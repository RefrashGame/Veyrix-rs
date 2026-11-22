//! Тонкая обёртка над WinDivert.dll (драйвер перехвата пакетов basil00/WinDivert 2.x, LGPLv3).
//!
//! DLL загружается во время работы (LoadLibraryW), а не при старте процесса: без драйвера программа не падает
//! с системной ошибкой, а сообщает, чего не хватает. Драйвер WinDivert64.sys должен лежать рядом с DLL.

use std::ffi::{CString, c_void};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;

type Handle = *mut c_void;
const INVALID_HANDLE: Handle = -1isize as Handle;

pub const FLAG_SNIFF: u64 = 0x0001;
pub const FLAG_DROP: u64 = 0x0002;
const LAYER_NETWORK: u32 = 0;
const SHUTDOWN_BOTH: u32 = 3;

/// WINDIVERT_ADDRESS (80 байт): метка времени, битовые поля, данные слоя.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Address {
    pub timestamp: i64,
    bits: u32,
    reserved: u32,
    data: [u8; 64],
}

const _: () = assert!(size_of::<Address>() == 80);

impl Address {
    // Битовые поля MSVC — от младшего бита: Layer:8, Event:8, Sniffed, Outbound, Loopback, Impostor, IPv6, ...
    const OUTBOUND: u32 = 1 << 17;
    const LOOPBACK: u32 = 1 << 18;
    const IMPOSTOR: u32 = 1 << 19;
    const IPV6: u32 = 1 << 20;

    pub fn outbound(&self) -> bool {
        self.bits & Self::OUTBOUND != 0
    }
    /// Направление при отправке: `false` — пакет придёт программам этого компьютера как входящий
    /// (на том же интерфейсе, с которого был перехвачен исходный).
    pub fn set_outbound(&mut self, outbound: bool) {
        if outbound { self.bits |= Self::OUTBOUND } else { self.bits &= !Self::OUTBOUND }
    }
    pub fn loopback(&self) -> bool {
        self.bits & Self::LOOPBACK != 0
    }
    /// Пакет отправлен самим WinDivert (нашим или чужим обходчиком).
    pub fn impostor(&self) -> bool {
        self.bits & Self::IMPOSTOR != 0
    }
    pub fn ipv6(&self) -> bool {
        self.bits & Self::IPV6 != 0
    }
}

impl Default for Address {
    fn default() -> Self {
        Self { timestamp: 0, bits: 0, reserved: 0, data: [0; 64] }
    }
}

struct Api {
    open: unsafe extern "C" fn(*const i8, u32, i16, u64) -> Handle,
    recv: unsafe extern "C" fn(Handle, *mut c_void, u32, *mut u32, *mut Address) -> i32,
    send: unsafe extern "C" fn(Handle, *const c_void, u32, *mut u32, *const Address) -> i32,
    shutdown: unsafe extern "C" fn(Handle, u32) -> i32,
    close: unsafe extern "C" fn(Handle) -> i32,
    calc_checksums: unsafe extern "C" fn(*mut c_void, u32, *mut Address, u64) -> i32,
    compile_filter: unsafe extern "C" fn(*const i8, u32, *mut i8, u32, *mut *const i8, *mut u32) -> i32,
}

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
}

static API: OnceLock<Api> = OnceLock::new();

fn load(dll_dir: &Path) -> io::Result<&'static Api> {
    if let Some(api) = API.get() {
        return Ok(api);
    }
    let dll = dll_dir.join("WinDivert.dll");
    let path: Vec<u16> = dll.as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: путь — строка UTF-16 с нулём на конце. Библиотека не выгружается до конца процесса.
    let module = unsafe { LoadLibraryW(path.as_ptr()) };
    if module.is_null() {
        let err = io::Error::last_os_error();
        return Err(io::Error::new(err.kind(), format!("не загружается {}: {err}", dll.display())));
    }
    let sym = |name: &[u8]| -> io::Result<*mut c_void> {
        // SAFETY: имя — ASCII с нулём на конце.
        let p = unsafe { GetProcAddress(module, name.as_ptr()) };
        if p.is_null() {
            Err(io::Error::other(format!("в WinDivert.dll нет {}", String::from_utf8_lossy(&name[..name.len() - 1]))))
        } else {
            Ok(p)
        }
    };
    /// Адрес функции → указатель на функцию с сигнатурой из windivert.h 2.x (x64: одно соглашение о вызовах).
    unsafe fn cast<F: Copy>(p: *mut c_void) -> F {
        const { assert!(size_of::<F>() == size_of::<*mut c_void>()) };
        // SAFETY: вызывающий гарантирует, что F — указатель на функцию с верной сигнатурой.
        unsafe { std::mem::transmute_copy(&p) }
    }
    // SAFETY: имена и сигнатуры сверены с windivert.h.
    let api = unsafe {
        Api {
            open: cast(sym(b"WinDivertOpen\0")?),
            recv: cast(sym(b"WinDivertRecv\0")?),
            send: cast(sym(b"WinDivertSend\0")?),
            shutdown: cast(sym(b"WinDivertShutdown\0")?),
            close: cast(sym(b"WinDivertClose\0")?),
            calc_checksums: cast(sym(b"WinDivertHelperCalcChecksums\0")?),
            compile_filter: cast(sym(b"WinDivertHelperCompileFilter\0")?),
        }
    };
    Ok(API.get_or_init(|| api))
}

/// Проверяет синтаксис фильтра без драйвера и без перехвата (прав администратора не нужно).
pub fn check_filter(dll_dir: &Path, filter: &str) -> io::Result<()> {
    let api = load(dll_dir)?;
    let c = CString::new(filter).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "нулевой байт в фильтре"))?;
    let mut error: *const i8 = std::ptr::null();
    let mut pos = 0u32;
    // SAFETY: строка фильтра живёт до конца вызова; объект не нужен (null, 0).
    if unsafe { (api.compile_filter)(c.as_ptr(), LAYER_NETWORK, std::ptr::null_mut(), 0, &mut error, &mut pos) } != 0 {
        return Ok(());
    }
    // SAFETY: WinDivert возвращает статическую строку с ошибкой или null.
    let what = if error.is_null() { "?".into() } else { unsafe { std::ffi::CStr::from_ptr(error) }.to_string_lossy() };
    Err(io::Error::new(io::ErrorKind::InvalidInput, format!("фильтр WinDivert: {what} (позиция {pos})")))
}

/// Открытый перехват WinDivert. Закрывается при удалении — тогда весь трафик сразу идёт напрямую.
pub struct Divert {
    api: &'static Api,
    handle: Handle,
}

// SAFETY: дескриптор WinDivert потокобезопасен: recv/send/shutdown можно звать из разных потоков.
unsafe impl Send for Divert {}
unsafe impl Sync for Divert {}

impl Divert {
    /// Открывает перехват по фильтру WinDivert (например `outbound and tcp.DstPort == 443`).
    /// Нужны права администратора; при первом открытии Windows загружает драйвер WinDivert64.sys.
    pub fn open(dll_dir: &Path, filter: &str, priority: i16, flags: u64) -> io::Result<Self> {
        let api = load(dll_dir)?;
        let filter = CString::new(filter).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "нулевой байт в фильтре"))?;
        // SAFETY: filter живёт до конца вызова.
        let handle = unsafe { (api.open)(filter.as_ptr(), LAYER_NETWORK, priority, flags) };
        if handle == INVALID_HANDLE {
            return Err(explain(io::Error::last_os_error()));
        }
        Ok(Self { api, handle })
    }

    /// Ждёт следующий пакет. Ошибка после `shutdown` — сигнал завершать цикл.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Address)> {
        let mut len = 0u32;
        let mut addr = Address::default();
        // SAFETY: буфер и адрес принадлежат нам и живут до конца вызова.
        let ok = unsafe { (self.api.recv)(self.handle, buf.as_mut_ptr().cast(), buf.len() as u32, &mut len, &mut addr) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok((len as usize, addr)) }
    }

    /// Отправляет пакет дальше по сети (или вверх, если адрес входящий).
    pub fn send(&self, packet: &[u8], addr: &Address) -> io::Result<()> {
        // SAFETY: пакет и адрес только читаются.
        let ok = unsafe { (self.api.send)(self.handle, packet.as_ptr().cast(), packet.len() as u32, std::ptr::null_mut(), addr) };
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }

    /// Пересчитывает контрольные суммы IP/TCP/UDP после изменения пакета.
    pub fn calc_checksums(&self, packet: &mut [u8], addr: &mut Address) {
        // SAFETY: пакет и адрес принадлежат вызывающему.
        unsafe { (self.api.calc_checksums)(packet.as_mut_ptr().cast(), packet.len() as u32, addr, 0) };
    }

    /// Прерывает ожидающий `recv` из другого потока.
    pub fn shutdown(&self) -> io::Result<()> {
        // SAFETY: дескриптор открыт, пока жив self.
        if unsafe { (self.api.shutdown)(self.handle, SHUTDOWN_BOTH) } == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
    }
}

impl Drop for Divert {
    fn drop(&mut self) {
        // SAFETY: закрываем ровно один раз.
        unsafe { (self.api.close)(self.handle) };
    }
}

/// Коды ошибок WinDivertOpen из документации WinDivert — человеческими словами.
fn explain(err: io::Error) -> io::Error {
    let hint = match err.raw_os_error() {
        Some(2) => "не найден драйвер WinDivert64.sys рядом с WinDivert.dll",
        Some(5) => "нужны права администратора",
        Some(87) => "ошибка в фильтре WinDivert",
        Some(577) => "Windows не принимает подпись драйвера WinDivert",
        Some(654) => "загружена другая, несовместимая версия драйвера WinDivert (закройте другие обходчики)",
        Some(1275) => "драйвер заблокирован (антивирус или защита памяти Windows)",
        Some(1753) => "не запущена служба BFE (Base Filtering Engine)",
        _ => return err,
    };
    io::Error::new(err.kind(), format!("{hint} ({err})"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_flags() {
        let a = Address { bits: Address::OUTBOUND | Address::IPV6, ..Default::default() };
        assert!(a.outbound() && a.ipv6() && !a.loopback() && !a.impostor());
    }

    #[test]
    fn missing_dll_is_a_clear_error() {
        let err = load(Path::new(r"C:\нет-такой-папки")).err().unwrap();
        assert!(err.to_string().contains("WinDivert.dll"), "{err}");
    }
}
