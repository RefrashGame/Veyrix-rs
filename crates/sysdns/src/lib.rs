//! Замена DNS-серверов Windows (IPv4) на включённых адаптерах Ethernet и Wi-Fi — с резервной копией и откатом.
//!
//! Системные функции, а не netsh/PowerShell (их вывод локализован): GetAdaptersAddresses — адаптеры,
//! Get/SetInterfaceDnsSettings (Windows 10 2004+) — DNS адаптера, DnsFlushResolverCache — очистка кэша.
//! Пустой список серверов = «получать автоматически (DHCP)» — так откат возвращает и ручные, и автоматические.

use std::ffi::c_void;
use std::io;
use std::path::Path;

/// Адаптер и его DNS, заданный вручную (`""` — автоматически, DHCP).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    pub guid: String,
    pub name: String,
    pub manual_dns: String,
}

/// Состояние для окна и консоли.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub adapters: Vec<Adapter>,
    /// Есть резервная копия — DNS заменён программой и его можно вернуть.
    pub replaced: bool,
}

pub const YANDEX: [&str; 2] = ["77.88.8.8", "77.88.8.1"];

#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    d1: u32,
    d2: u16,
    d3: u16,
    d4: [u8; 8],
}

/// «{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}» → GUID.
fn parse_guid(s: &str) -> Option<Guid> {
    let parts: Vec<&str> = s.trim().trim_start_matches('{').trim_end_matches('}').split('-').collect();
    let [a, b, c, d, e] = parts.as_slice() else { return None };
    if [a.len(), b.len(), c.len(), d.len(), e.len()] != [8, 4, 4, 4, 12] {
        return None;
    }
    let tail = format!("{d}{e}");
    let mut d4 = [0u8; 8];
    for (i, byte) in d4.iter_mut().enumerate() {
        *byte = u8::from_str_radix(tail.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(Guid {
        d1: u32::from_str_radix(a, 16).ok()?,
        d2: u16::from_str_radix(b, 16).ok()?,
        d3: u16::from_str_radix(c, 16).ok()?,
        d4,
    })
}

/// Начало IP_ADAPTER_ADDRESSES_LH (iptypes.h, x64) — до OperStatus, остальное не нужно.
#[repr(C)]
struct AdapterAddresses {
    length: u32,
    if_index: u32,
    next: *const AdapterAddresses,
    adapter_name: *const u8,
    first_unicast: *const c_void,
    first_anycast: *const c_void,
    first_multicast: *const c_void,
    first_dns_server: *const c_void,
    dns_suffix: *const u16,
    description: *const u16,
    friendly_name: *const u16,
    physical_address: [u8; 8],
    physical_address_length: u32,
    flags: u32,
    mtu: u32,
    if_type: u32,
    oper_status: i32,
}

/// DNS_INTERFACE_SETTINGS (netioapi.h), версия 1.
#[repr(C)]
struct DnsInterfaceSettings {
    version: u32,
    flags: u64,
    domain: *mut u16,
    name_server: *mut u16,
    search_list: *mut u16,
    registration_enabled: u32,
    register_adapter_name: u32,
    enable_llmnr: u32,
    query_adapter_name: u32,
    profile_name_server: *mut u16,
}

const _: () = assert!(size_of::<DnsInterfaceSettings>() == 64);

const AF_INET: u32 = 2;
const GAA_SKIP_UNICAST_ANYCAST_MULTICAST: u32 = 0x1 | 0x2 | 0x4;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const ERROR_NO_DATA: u32 = 232;
const IF_TYPE_ETHERNET: u32 = 6;
const IF_TYPE_WIFI: u32 = 71;
const OPER_STATUS_UP: i32 = 1;
const DNS_SETTING_NAMESERVER: u64 = 0x0002;

#[link(name = "iphlpapi", kind = "raw-dylib")]
unsafe extern "system" {
    fn GetAdaptersAddresses(family: u32, flags: u32, reserved: *mut c_void, buf: *mut c_void, size: *mut u32) -> u32;
    fn GetInterfaceDnsSettings(interface: Guid, settings: *mut DnsInterfaceSettings) -> u32;
    fn SetInterfaceDnsSettings(interface: Guid, settings: *const DnsInterfaceSettings) -> u32;
    fn FreeInterfaceDnsSettings(settings: *mut DnsInterfaceSettings);
}

#[link(name = "dnsapi", kind = "raw-dylib")]
unsafe extern "system" {
    fn DnsFlushResolverCache() -> i32;
}

fn win_err(code: u32, what: &str) -> io::Error {
    let err = io::Error::from_raw_os_error(code as i32);
    io::Error::new(err.kind(), format!("{what}: {err}"))
}

/// UTF-16 строка с нулём → String.
///
/// # Safety
/// `p` — null или указатель на строку UTF-16 с нулём на конце.
unsafe fn wide_to_string(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    // SAFETY: строка заканчивается нулём (гарантия вызывающего).
    let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

/// Сетевой интерфейс с IPv4 — для диагностики (поиск VPN и туннелей).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub guid: String,
    pub name: String,
    pub description: String,
    /// IANA ifType: 6 — Ethernet, 71 — Wi-Fi, 23 — PPP, 53 — виртуальный, 131 — туннель.
    pub if_type: u32,
    pub up: bool,
}

pub const IF_TYPE_PPP: u32 = 23;

/// Все интерфейсы с IPv4.
pub fn interfaces() -> io::Result<Vec<Interface>> {
    let mut size = 16 * 1024u32;
    // Vec<u64> — выравнивание 8, как требуют структуры внутри буфера.
    let mut buf: Vec<u64> = Vec::new();
    for _ in 0..3 {
        buf = vec![0; size as usize / 8 + 1];
        // SAFETY: буфер на size байт, функция пишет не больше и сообщает нужный размер.
        let code = unsafe {
            GetAdaptersAddresses(AF_INET, GAA_SKIP_UNICAST_ANYCAST_MULTICAST, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut size)
        };
        match code {
            0 => break,
            ERROR_BUFFER_OVERFLOW => continue,
            ERROR_NO_DATA => return Ok(Vec::new()),
            other => return Err(win_err(other, "список адаптеров")),
        }
    }
    let mut out = Vec::new();
    let mut p = buf.as_ptr() as *const AdapterAddresses;
    while !p.is_null() {
        // SAFETY: список заполнен GetAdaptersAddresses и живёт, пока жив buf.
        let a = unsafe { &*p };
        // SAFETY: имя адаптера — ANSI-строка с нулём, имя и описание — UTF-16 с нулём.
        out.push(Interface {
            guid: unsafe { std::ffi::CStr::from_ptr(a.adapter_name.cast()) }.to_string_lossy().into_owned(),
            name: unsafe { wide_to_string(a.friendly_name) },
            description: unsafe { wide_to_string(a.description) },
            if_type: a.if_type,
            up: a.oper_status == OPER_STATUS_UP,
        });
        p = a.next;
    }
    Ok(out)
}

/// Включённые адаптеры Ethernet и Wi-Fi с IPv4 и их DNS, заданный вручную.
pub fn adapters() -> io::Result<Vec<Adapter>> {
    interfaces()?
        .into_iter()
        .filter(|i| i.up && matches!(i.if_type, IF_TYPE_ETHERNET | IF_TYPE_WIFI))
        .map(|i| Ok(Adapter { manual_dns: manual_dns(&i.guid)?, guid: i.guid, name: i.name }))
        .collect()
}

/// DNS адаптера, заданный вручную; `""` — автоматически (DHCP).
fn manual_dns(guid: &str) -> io::Result<String> {
    let id = parse_guid(guid).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("GUID «{guid}»")))?;
    // SAFETY: обнулённая структура допустима (указатели null); версию задаём до вызова.
    let mut settings: DnsInterfaceSettings = unsafe { std::mem::zeroed() };
    settings.version = 1;
    // SAFETY: структура наша; строки в ней выделяет функция и освобождает FreeInterfaceDnsSettings.
    let code = unsafe { GetInterfaceDnsSettings(id, &mut settings) };
    if code != 0 {
        return Err(win_err(code, "чтение DNS адаптера"));
    }
    // SAFETY: строку выделила GetInterfaceDnsSettings; освобождаем после копирования.
    let servers = unsafe { wide_to_string(settings.name_server) };
    unsafe { FreeInterfaceDnsSettings(&mut settings) };
    Ok(servers)
}

/// Задать DNS адаптера: серверы через запятую или `""` — вернуть автоматический (DHCP).
fn set_dns(guid: &str, servers: &str) -> io::Result<()> {
    let id = parse_guid(guid).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, format!("GUID «{guid}»")))?;
    let mut wide: Vec<u16> = servers.encode_utf16().chain([0]).collect();
    // SAFETY: обнулённая структура допустима; меняется только список серверов (флаг NAMESERVER).
    let mut settings: DnsInterfaceSettings = unsafe { std::mem::zeroed() };
    settings.version = 1;
    settings.flags = DNS_SETTING_NAMESERVER;
    settings.name_server = wide.as_mut_ptr();
    // SAFETY: строка живёт до конца вызова.
    let code = unsafe { SetInterfaceDnsSettings(id, &settings) };
    if code == 0 { Ok(()) } else { Err(win_err(code, "запись DNS адаптера")) }
}

/// Очистка кэша DNS Windows (как `ipconfig /flushdns`).
pub fn flush_cache() -> io::Result<()> {
    // SAFETY: функция без параметров.
    if unsafe { DnsFlushResolverCache() } != 0 { Ok(()) } else { Err(io::Error::other("кэш DNS не очищен")) }
}

/// Резервная копия: «GUID<TAB>имя<TAB>исходные серверы» по строке на адаптер.
fn to_backup(adapters: &[Adapter]) -> String {
    adapters.iter().map(|a| format!("{}\t{}\t{}\n", a.guid, a.name.replace(['\t', '\n'], " "), a.manual_dns)).collect()
}

fn from_backup(text: &str) -> Vec<Adapter> {
    text.lines()
        .filter_map(|l| {
            let mut f = l.splitn(3, '\t');
            let (guid, name, dns) = (f.next()?, f.next()?, f.next().unwrap_or(""));
            parse_guid(guid).map(|_| Adapter { guid: guid.into(), name: name.into(), manual_dns: dns.trim().into() })
        })
        .collect()
}

/// Добавляет в копию адаптеры, которых в ней нет: исходное значение уже сохранённых не перезаписывается.
fn merge_backup(saved: Vec<Adapter>, current: &[Adapter]) -> Vec<Adapter> {
    let mut all = saved;
    for a in current {
        if !all.iter().any(|s| s.guid.eq_ignore_ascii_case(&a.guid)) {
            all.push(a.clone());
        }
    }
    all
}

pub fn status(backup: &Path) -> io::Result<Status> {
    Ok(Status { adapters: adapters()?, replaced: backup.exists() })
}

/// Заменить DNS на `servers` на всех подходящих адаптерах. Сначала — резервная копия, потом — замена.
pub fn apply(servers: &[&str], backup: &Path) -> io::Result<Vec<Adapter>> {
    let current = adapters()?;
    if current.is_empty() {
        return Err(io::Error::other("нет включённых адаптеров Ethernet или Wi-Fi"));
    }
    let saved = std::fs::read_to_string(backup).map(|t| from_backup(&t)).unwrap_or_default();
    let merged = merge_backup(saved, &current);
    if let Some(dir) = backup.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Через временный файл: при сбое на середине записи старая копия не портится.
    let tmp = backup.with_extension("tmp");
    std::fs::write(&tmp, to_backup(&merged))?;
    std::fs::rename(&tmp, backup)?;

    let list = servers.join(",");
    let mut errors = Vec::new();
    for a in &current {
        if let Err(e) = set_dns(&a.guid, &list) {
            errors.push(format!("{}: {e}", a.name));
        }
    }
    let _ = flush_cache();
    if errors.is_empty() { adapters() } else { Err(io::Error::other(errors.join("; "))) }
}

/// Вернуть исходный DNS из резервной копии; копия удаляется, только если вернулось всё.
pub fn restore(backup: &Path) -> io::Result<usize> {
    let text = std::fs::read_to_string(backup)
        .map_err(|e| io::Error::new(e.kind(), "нет резервной копии: DNS не заменялся программой"))?;
    let saved = from_backup(&text);
    let present: Vec<String> = adapters()?.into_iter().map(|a| a.guid.to_ascii_lowercase()).collect();
    let mut errors = Vec::new();
    let mut restored = 0;
    for a in &saved {
        // Выключенный сейчас адаптер пропускается; копия сохранится, чтобы вернуть его позже.
        if !present.contains(&a.guid.to_ascii_lowercase()) {
            errors.push(format!("{}: адаптер сейчас выключен", a.name));
            continue;
        }
        match set_dns(&a.guid, &a.manual_dns) {
            Ok(()) => restored += 1,
            Err(e) => errors.push(format!("{}: {e}", a.name)),
        }
    }
    let _ = flush_cache();
    if errors.is_empty() {
        std::fs::remove_file(backup)?;
        Ok(restored)
    } else {
        Err(io::Error::other(format!("возвращено {restored}, не удалось: {}", errors.join("; "))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const G1: &str = "{4D36E972-E325-11CE-BFC1-08002BE10318}";
    const G2: &str = "{11111111-2222-3333-4444-555555555555}";

    #[test]
    fn guid_parsing() {
        let g = parse_guid(G1).unwrap();
        assert_eq!((g.d1, g.d2, g.d3), (0x4D36_E972, 0xE325, 0x11CE));
        assert_eq!(g.d4, [0xBF, 0xC1, 0x08, 0x00, 0x2B, 0xE1, 0x03, 0x18]);
        assert!(parse_guid("{4D36E972-E325}").is_none());
        assert!(parse_guid("{ZZZZZZZZ-E325-11CE-BFC1-08002BE10318}").is_none());
    }

    #[test]
    fn backup_roundtrip_keeps_dhcp_and_manual() {
        let list = vec![
            Adapter { guid: G1.into(), name: "Ethernet".into(), manual_dns: String::new() },
            Adapter { guid: G2.into(), name: "Wi-Fi\tдом".into(), manual_dns: "1.1.1.1,8.8.8.8".into() },
        ];
        let back = from_backup(&to_backup(&list));
        assert_eq!(back[0], list[0]);
        assert_eq!(back[1].manual_dns, "1.1.1.1,8.8.8.8");
        assert_eq!(back[1].name, "Wi-Fi дом");
        assert!(from_backup("мусор\nне\tGUID\t1.1.1.1\n").is_empty());
    }

    #[test]
    fn repeated_apply_never_overwrites_original() {
        let original = vec![Adapter { guid: G1.into(), name: "Ethernet".into(), manual_dns: String::new() }];
        // Второй запуск: на адаптере уже Яндекс, плюс включили Wi-Fi.
        let now = vec![
            Adapter { guid: G1.to_lowercase(), name: "Ethernet".into(), manual_dns: "77.88.8.8,77.88.8.1".into() },
            Adapter { guid: G2.into(), name: "Wi-Fi".into(), manual_dns: "9.9.9.9".into() },
        ];
        let merged = merge_backup(original, &now);
        assert_eq!(merged.len(), 2);
        assert_eq!(merged[0].manual_dns, ""); // исходный DHCP сохранён
        assert_eq!(merged[1].manual_dns, "9.9.9.9");
    }

    /// Только чтение: список адаптеров и их DNS на этой машине. Ничего не меняет.
    #[test]
    fn reading_adapters_does_not_fail() {
        let list = adapters().expect("GetAdaptersAddresses/GetInterfaceDnsSettings");
        for a in &list {
            assert!(parse_guid(&a.guid).is_some(), "{a:?}");
        }
    }
}
