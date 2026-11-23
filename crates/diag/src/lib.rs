//! Диагностика: всё, что мешает обходу или искажает автоподбор. Только чтение — ничего не меняет.
//!
//! Сбор (`snapshot`) — системные функции Windows; оценка (`evaluate`) — чистая функция, проверяется тестами.
//! Проверки и тексты — по Veyrix на C# (src/Veyrix.Core/Diagnostics.cs, NetworkEnvironment.cs).

use std::ffi::c_void;
use std::path::Path;
use std::time::Instant;

use vx_sysdns::Interface;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warning,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub level: Level,
    pub detail: String,
    /// Что сделать, если не в порядке.
    pub hint: Option<&'static str>,
}

/// Собранное о системе.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub admin: bool,
    pub missing_files: Vec<String>,
    /// `None` — не удалось узнать.
    pub bfe_running: Option<bool>,
    /// Служба драйвера WinDivert запущена (драйвер загружен).
    pub windivert_loaded: bool,
    /// Другие процессы (не этот), загрузившие WinDivert.dll.
    pub windivert_users: Vec<String>,
    pub vpn: Vec<String>,
    pub proxy: Option<String>,
    /// DoH-запрос к Cloudflare: время ответа в мс или ошибка.
    pub doh: Result<u128, String>,
}

impl Default for Snapshot {
    fn default() -> Self {
        Self {
            admin: false,
            missing_files: Vec::new(),
            bfe_running: None,
            windivert_loaded: false,
            windivert_users: Vec::new(),
            vpn: Vec::new(),
            proxy: None,
            doh: Err("не проверялся".into()),
        }
    }
}

// Ключевые слова в названии/описании адаптера, по которым узнаются VPN и туннели («Meta Tunnel» — TUN Clash Meta).
const VPN_MARKERS: [&str; 18] = [
    "vpn", "wireguard", "wintun", "tap-windows", "tap0901", "openvpn", "amnezia", "outline", "sing-tun", "clash", "mihomo",
    "warp", "meta tunnel", "dropweb", "v2ray", "xray", "hiddify", "nekoray",
];
// Системные туннели Windows, которые есть всегда и интернет-трафик не забирают.
const SYSTEM_TUNNELS: [&str; 5] = ["teredo", "6to4", "isatap", "ip-https", "loopback"];

/// Включённые VPN и туннели, забирающие маршрут.
pub fn find_vpn(interfaces: &[Interface]) -> Vec<String> {
    let has = |i: &Interface, m: &str| i.name.to_lowercase().contains(m) || i.description.to_lowercase().contains(m);
    let mut out: Vec<String> = interfaces
        .iter()
        .filter(|i| i.up && !SYSTEM_TUNNELS.iter().any(|t| has(i, t)))
        .filter(|i| i.if_type == vx_sysdns::IF_TYPE_PPP || VPN_MARKERS.iter().any(|m| has(i, m)))
        .map(|i| i.name.clone())
        .collect();
    out.dedup();
    out
}

pub fn evaluate(s: &Snapshot) -> Vec<Check> {
    let check = |name, level, detail: String, hint| Check { name, level, detail, hint };
    let list = |v: &[String]| v.join(", ");
    vec![
        if s.admin {
            check("Права администратора", Level::Ok, "Есть".into(), None)
        } else {
            check("Права администратора", Level::Failed, "Нет".into(),
                Some("Перехват пакетов работает только от администратора: перезапустите программу от его имени."))
        },
        if s.missing_files.is_empty() {
            check("Файлы WinDivert", Level::Ok, "На месте".into(), None)
        } else {
            check("Файлы WinDivert", Level::Failed, format!("Не найдены: {}", list(&s.missing_files)),
                Some("Скорее всего, их удалил антивирус. Добавьте папку программы в исключения и верните файлы."))
        },
        match s.bfe_running {
            Some(true) => check("Служба BFE", Level::Ok, "Работает".into(), None),
            Some(false) => check("Служба BFE", Level::Failed, "Не запущена".into(),
                Some("WinDivert работает через «Службу базовой фильтрации» (BFE). Включите её в services.msc.")),
            None => check("Служба BFE", Level::Warning, "Не удалось проверить".into(), None),
        },
        if s.windivert_users.is_empty() {
            check("Другие перехватчики трафика", Level::Ok, "Не найдены".into(), None)
        } else {
            check("Другие перехватчики трафика", Level::Failed, format!("WinDivert используют: {}", list(&s.windivert_users)),
                Some("Две программы, меняющие пакеты, мешают друг другу (например, zapret/winws или Veyrix на C#). Закройте их."))
        },
        if s.windivert_loaded && s.windivert_users.is_empty() {
            check("Драйвер WinDivert", Level::Warning, "Загружен, но другие программы им не пользуются".into(),
                Some("Обычно это нормально (драйвер остаётся после обходчиков). Если обход не стартует — перезагрузите компьютер."))
        } else {
            check("Драйвер WinDivert", Level::Ok, if s.windivert_loaded { "Загружен" } else { "Загрузится при старте" }.into(), None)
        },
        if s.vpn.is_empty() {
            check("VPN и туннели", Level::Ok, "Не активны".into(), None)
        } else {
            check("VPN и туннели", Level::Warning, format!("Активны: {}", list(&s.vpn)),
                Some("Трафик идёт через туннель, и обход к нему не применяется. Для автоподбора отключите VPN."))
        },
        match &s.proxy {
            None => check("Системный прокси", Level::Ok, "Не используется".into(), None),
            Some(p) => check("Системный прокси", Level::Warning, p.clone(),
                Some("Браузер ходит через прокси: обход и автоподбор могут вести себя иначе. Отключите прокси в параметрах Windows.")),
        },
        match &s.doh {
            Ok(ms) => check("DNS-over-HTTPS (Cloudflare)", Level::Ok, format!("Отвечает за {ms} мс"), None),
            Err(e) => check("DNS-over-HTTPS (Cloudflare)", Level::Warning, e.clone(),
                Some("DoH-сервер недоступен: выберите в настройках другой (Google, Quad9) или обычный DNS.")),
        },
    ]
}

/// Собирает сведения о системе. `engine_dir` — папка с WinDivert.dll и WinDivert64.sys.
pub fn snapshot(engine_dir: &Path) -> Snapshot {
    Snapshot { doh: doh_check(), ..local_snapshot(engine_dir) }
}

/// Всё, кроме сетевой проверки DoH.
fn local_snapshot(engine_dir: &Path) -> Snapshot {
    Snapshot {
        admin: is_admin(),
        missing_files: ["WinDivert.dll", "WinDivert64.sys"]
            .into_iter()
            .filter(|f| !engine_dir.join(f).exists())
            .map(String::from)
            .collect(),
        bfe_running: service_running("BFE"),
        windivert_loaded: ["WinDivert", "WinDivert14"].iter().any(|s| service_running(s) == Some(true)),
        windivert_users: windivert_users(),
        vpn: vx_sysdns::interfaces().map(|i| find_vpn(&i)).unwrap_or_default(),
        proxy: system_proxy(),
        doh: Err("не проверялся".into()),
    }
}

fn doh_check() -> Result<u128, String> {
    let started = Instant::now();
    let doh = vx_doh::Doh::new("cloudflare").map_err(|e| e.to_string())?;
    let query = vx_core::dns::build_query(0x4242, "example.com", vx_core::dns::TYPE_A);
    let answer = doh.query(&query).map_err(|e| e.to_string())?;
    if vx_core::dns::is_answer_to(&query, &answer) { Ok(started.elapsed().as_millis()) } else { Err("ответ не на тот запрос".into()) }
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn from_wide(buf: &[u16]) -> String {
    String::from_utf16_lossy(&buf[..buf.iter().position(|&c| c == 0).unwrap_or(buf.len())])
}

#[link(name = "shell32", kind = "raw-dylib")]
unsafe extern "system" {
    fn IsUserAnAdmin() -> i32;
}

fn is_admin() -> bool {
    // SAFETY: функция без параметров.
    unsafe { IsUserAnAdmin() != 0 }
}

#[repr(C)]
struct ServiceStatus {
    service_type: u32,
    current_state: u32,
    controls_accepted: u32,
    win32_exit_code: u32,
    service_exit_code: u32,
    check_point: u32,
    wait_hint: u32,
}

#[link(name = "advapi32", kind = "raw-dylib")]
unsafe extern "system" {
    fn OpenSCManagerW(machine: *const u16, database: *const u16, access: u32) -> *mut c_void;
    fn OpenServiceW(scm: *mut c_void, name: *const u16, access: u32) -> *mut c_void;
    fn QueryServiceStatus(service: *mut c_void, status: *mut ServiceStatus) -> i32;
    fn CloseServiceHandle(handle: *mut c_void) -> i32;
    fn RegGetValueW(key: isize, subkey: *const u16, value: *const u16, flags: u32, kind: *mut u32, data: *mut c_void, size: *mut u32) -> i32;
}

/// Запущена ли служба: `Some(false)` — нет такой или остановлена, `None` — нет доступа к диспетчеру служб.
fn service_running(name: &str) -> Option<bool> {
    const SC_MANAGER_CONNECT: u32 = 0x0001;
    const SERVICE_QUERY_STATUS: u32 = 0x0004;
    const SERVICE_RUNNING: u32 = 4;
    // SAFETY: null — локальный компьютер и база по умолчанию.
    let scm = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if scm.is_null() {
        return None;
    }
    let n = wide(name);
    // SAFETY: имя живёт до конца вызова; дескрипторы закрываются ниже.
    let svc = unsafe { OpenServiceW(scm, n.as_ptr(), SERVICE_QUERY_STATUS) };
    let running = if svc.is_null() {
        Some(false)
    } else {
        // SAFETY: структура наша, размер совпадает с SERVICE_STATUS.
        let mut st: ServiceStatus = unsafe { std::mem::zeroed() };
        let ok = unsafe { QueryServiceStatus(svc, &mut st) } != 0;
        unsafe { CloseServiceHandle(svc) };
        ok.then_some(st.current_state == SERVICE_RUNNING)
    };
    unsafe { CloseServiceHandle(scm) };
    running
}

/// Системный прокси текущего пользователя (как в параметрах Windows).
fn system_proxy() -> Option<String> {
    const HKEY_CURRENT_USER: isize = 0x8000_0001_u32 as i32 as isize;
    const RRF_RT_REG_DWORD: u32 = 0x10;
    const RRF_RT_REG_SZ: u32 = 0x02;
    let key = wide(r"Software\Microsoft\Windows\CurrentVersion\Internet Settings");
    let read_string = |value: &str| -> Option<String> {
        let mut buf = [0u16; 1024];
        let mut size = (buf.len() * 2) as u32;
        let v = wide(value);
        // SAFETY: буфер и его размер в байтах переданы.
        let code = unsafe {
            RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), v.as_ptr(), RRF_RT_REG_SZ, std::ptr::null_mut(), buf.as_mut_ptr().cast(), &mut size)
        };
        (code == 0).then(|| from_wide(&buf)).filter(|s| !s.is_empty())
    };
    let mut enabled = 0u32;
    let mut size = 4u32;
    let v = wide("ProxyEnable");
    // SAFETY: DWORD по указателю, размер 4.
    let code = unsafe {
        RegGetValueW(HKEY_CURRENT_USER, key.as_ptr(), v.as_ptr(), RRF_RT_REG_DWORD, std::ptr::null_mut(), (&raw mut enabled).cast(), &mut size)
    };
    if code == 0
        && enabled == 1
        && let Some(server) = read_string("ProxyServer")
    {
        return Some(server);
    }
    read_string("AutoConfigURL").map(|pac| format!("PAC: {pac}"))
}

#[repr(C)]
struct ProcessEntry {
    size: u32,
    usage: u32,
    pid: u32,
    heap_id: usize,
    module_id: u32,
    threads: u32,
    parent_pid: u32,
    priority: i32,
    flags: u32,
    exe: [u16; 260],
}

#[repr(C)]
struct ModuleEntry {
    size: u32,
    module_id: u32,
    pid: u32,
    global_usage: u32,
    process_usage: u32,
    base_addr: *mut u8,
    base_size: u32,
    module: *mut c_void,
    name: [u16; 256],
    path: [u16; 260],
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn CreateToolhelp32Snapshot(flags: u32, pid: u32) -> *mut c_void;
    fn Process32FirstW(snapshot: *mut c_void, entry: *mut ProcessEntry) -> i32;
    fn Process32NextW(snapshot: *mut c_void, entry: *mut ProcessEntry) -> i32;
    fn Module32FirstW(snapshot: *mut c_void, entry: *mut ModuleEntry) -> i32;
    fn Module32NextW(snapshot: *mut c_void, entry: *mut ModuleEntry) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

const INVALID_HANDLE: *mut c_void = -1isize as *mut c_void;

/// Процессы (кроме этого), загрузившие WinDivert.dll. Защищённые системные процессы недоступны — WinDivert они не используют.
fn windivert_users() -> Vec<String> {
    const TH32CS_SNAPPROCESS: u32 = 0x2;
    let own = std::process::id();
    let mut users = Vec::new();
    // SAFETY: снимок процессов закрывается в конце.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if snap == INVALID_HANDLE {
        return users;
    }
    // SAFETY: обнулённая структура допустима; размер задаётся перед первым вызовом, как требует API.
    let mut pe: ProcessEntry = unsafe { std::mem::zeroed() };
    pe.size = size_of::<ProcessEntry>() as u32;
    let mut more = unsafe { Process32FirstW(snap, &mut pe) } != 0;
    while more {
        if pe.pid != own && pe.pid != 0 && uses_windivert(pe.pid) {
            let name = from_wide(&pe.exe);
            if !users.contains(&name) {
                users.push(name);
            }
        }
        more = unsafe { Process32NextW(snap, &mut pe) } != 0;
    }
    unsafe { CloseHandle(snap) };
    users
}

fn uses_windivert(pid: u32) -> bool {
    const TH32CS_SNAPMODULE: u32 = 0x8;
    const TH32CS_SNAPMODULE32: u32 = 0x10;
    // SAFETY: снимок модулей закрывается в конце; недоступный процесс даёт INVALID_HANDLE.
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) };
    if snap == INVALID_HANDLE {
        return false;
    }
    // SAFETY: обнулённая структура допустима; размер задаётся перед первым вызовом.
    let mut me: ModuleEntry = unsafe { std::mem::zeroed() };
    me.size = size_of::<ModuleEntry>() as u32;
    let mut more = unsafe { Module32FirstW(snap, &mut me) } != 0;
    let mut found = false;
    while more && !found {
        found = from_wide(&me.name).eq_ignore_ascii_case("WinDivert.dll");
        more = unsafe { Module32NextW(snap, &mut me) } != 0;
    }
    unsafe { CloseHandle(snap) };
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, description: &str, if_type: u32, up: bool) -> Interface {
        Interface { guid: String::new(), name: name.into(), description: description.into(), if_type, up }
    }

    #[test]
    fn vpn_detection() {
        let list = [
            iface("Ethernet", "Realtek PCIe GbE", 6, true),
            iface("Meta", "Meta Tunnel", 53, true),
            iface("Teredo", "Teredo Tunneling Pseudo-Interface", 131, true),
            iface("WireGuard", "WireGuard Tunnel", 53, false), // выключен
            iface("Подключение", "WAN Miniport (PPPOE)", vx_sysdns::IF_TYPE_PPP, true),
        ];
        assert_eq!(find_vpn(&list), vec!["Meta".to_string(), "Подключение".to_string()]);
    }

    #[test]
    fn evaluate_flags_problems() {
        let bad = Snapshot {
            admin: false,
            missing_files: vec!["WinDivert64.sys".into()],
            bfe_running: Some(false),
            windivert_loaded: true,
            windivert_users: vec!["winws.exe".into()],
            vpn: vec!["Meta".into()],
            proxy: Some("127.0.0.1:8080".into()),
            doh: Err("нет ответа".into()),
        };
        let checks = evaluate(&bad);
        assert_eq!(checks.len(), 8);
        // При живом перехватчике драйвер «загружен» — это не отдельная проблема.
        assert!(checks.iter().all(|c| c.level != Level::Ok || c.name == "Драйвер WinDivert"));
        assert!(checks.iter().filter(|c| c.level != Level::Ok).all(|c| c.hint.is_some()));

        let good = Snapshot { admin: true, bfe_running: Some(true), doh: Ok(40), ..Snapshot::default() };
        assert!(evaluate(&good).iter().all(|c| c.level == Level::Ok), "{:?}", evaluate(&good));
    }

    /// Только чтение системы без сети: права, службы, процессы, адаптеры, реестр — сбор не падает.
    #[test]
    fn local_snapshot_reads_system() {
        let s = local_snapshot(Path::new(r"C:\нет-такой-папки"));
        assert!(s.bfe_running.is_some(), "диспетчер служб недоступен");
        assert_eq!(s.missing_files.len(), 2);
    }
}
