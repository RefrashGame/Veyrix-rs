//! WebSocket (wss://host/apiws, подпротокол binary) и простой HTTPS GET через WinHTTP — встроенный в Windows клиент.

use std::ffi::c_void;
use std::io;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

type Hinternet = *mut c_void;

const ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;
const FLAG_SECURE: u32 = 0x0080_0000;
const QUERY_STATUS_CODE: u32 = 19;
const QUERY_FLAG_NUMBER: u32 = 0x2000_0000;
const OPTION_DISABLE_FEATURE: u32 = 63;
const DISABLE_REDIRECTS: u32 = 0x2;
const OPTION_UPGRADE_TO_WEB_SOCKET: u32 = 114;
const OPTION_RECEIVE_TIMEOUT: u32 = 7;
const WS_BINARY_MESSAGE: u32 = 0;
const WS_BINARY_FRAGMENT: u32 = 1;
const WS_CLOSE: u32 = 4;

#[link(name = "winhttp", kind = "raw-dylib")]
unsafe extern "system" {
    fn WinHttpOpen(agent: *const u16, access: u32, proxy: *const u16, bypass: *const u16, flags: u32) -> Hinternet;
    fn WinHttpSetTimeouts(h: Hinternet, resolve: i32, connect: i32, send: i32, receive: i32) -> i32;
    fn WinHttpSetOption(h: Hinternet, option: u32, buf: *const c_void, len: u32) -> i32;
    fn WinHttpConnect(session: Hinternet, server: *const u16, port: u16, reserved: u32) -> Hinternet;
    fn WinHttpOpenRequest(
        connect: Hinternet,
        verb: *const u16,
        path: *const u16,
        version: *const u16,
        referrer: *const u16,
        accept: *const *const u16,
        flags: u32,
    ) -> Hinternet;
    fn WinHttpSendRequest(r: Hinternet, headers: *const u16, headers_len: u32, opt: *const c_void, opt_len: u32, total: u32, ctx: usize) -> i32;
    fn WinHttpReceiveResponse(r: Hinternet, reserved: *mut c_void) -> i32;
    fn WinHttpQueryHeaders(r: Hinternet, level: u32, name: *const u16, buf: *mut c_void, len: *mut u32, index: *mut u32) -> i32;
    fn WinHttpReadData(r: Hinternet, buf: *mut c_void, to_read: u32, read: *mut u32) -> i32;
    fn WinHttpCloseHandle(h: Hinternet) -> i32;
    fn WinHttpWebSocketCompleteUpgrade(r: Hinternet, ctx: usize) -> Hinternet;
    fn WinHttpWebSocketSend(ws: Hinternet, kind: u32, buf: *const c_void, len: u32) -> u32;
    fn WinHttpWebSocketReceive(ws: Hinternet, buf: *mut c_void, len: u32, read: *mut u32, kind: *mut u32) -> u32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn last_error(what: &str) -> io::Error {
    let e = io::Error::last_os_error();
    io::Error::new(e.kind(), format!("{what}: {e}"))
}

struct Handle(Hinternet);

impl Drop for Handle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: дескриптор получен от WinHTTP и закрывается один раз.
            unsafe { WinHttpCloseHandle(self.0) };
        }
    }
}

// SAFETY: дескрипторы WinHTTP можно использовать из разных потоков.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

/// Общая сессия WinHTTP (браузерный User-Agent — как у веб-версии Telegram).
fn session() -> io::Result<Hinternet> {
    static SESSION: OnceLock<Handle> = OnceLock::new();
    if let Some(s) = SESSION.get() {
        return Ok(s.0);
    }
    let agent = wide("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36");
    // SAFETY: строка живёт до конца вызова.
    let h = unsafe { WinHttpOpen(agent.as_ptr(), ACCESS_TYPE_AUTOMATIC_PROXY, std::ptr::null(), std::ptr::null(), 0) };
    if h.is_null() {
        return Err(last_error("WinHTTP"));
    }
    Ok(SESSION.get_or_init(|| Handle(h)).0)
}

/// Запрос GET с ожиданием ответа; возвращает (соединение, запрос, код статуса).
fn get(host: &str, path: &str, timeout_ms: i32, headers: &str, websocket: bool) -> io::Result<(Handle, Handle, u32)> {
    let server = wide(host);
    // SAFETY: строка живёт до конца вызова.
    let connect = Handle(unsafe { WinHttpConnect(session()?, server.as_ptr(), 443, 0) });
    if connect.0.is_null() {
        return Err(last_error(host));
    }
    let (verb, path) = (wide("GET"), wide(path));
    // SAFETY: строки живут до конца вызова.
    let request = Handle(unsafe {
        WinHttpOpenRequest(connect.0, verb.as_ptr(), path.as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null(), FLAG_SECURE)
    });
    if request.0.is_null() {
        return Err(last_error(host));
    }
    let disable = DISABLE_REDIRECTS;
    // SAFETY: параметры — u32 по указателю; null для апгрейда до WebSocket — так требует WinHTTP.
    unsafe {
        WinHttpSetTimeouts(request.0, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
        WinHttpSetOption(request.0, OPTION_DISABLE_FEATURE, (&raw const disable).cast(), 4);
        if websocket && WinHttpSetOption(request.0, OPTION_UPGRADE_TO_WEB_SOCKET, std::ptr::null(), 0) == 0 {
            return Err(last_error("WebSocket"));
        }
    }
    let headers = wide(headers);
    // SAFETY: заголовки живут до конца вызова; длина u32::MAX — «до нуля».
    let sent = unsafe { WinHttpSendRequest(request.0, headers.as_ptr(), u32::MAX, std::ptr::null(), 0, 0, 0) };
    if sent == 0 || unsafe { WinHttpReceiveResponse(request.0, std::ptr::null_mut()) } == 0 {
        return Err(last_error(host));
    }
    let (mut status, mut size) = (0u32, 4u32);
    // SAFETY: буфер — u32, размер 4.
    unsafe {
        WinHttpQueryHeaders(request.0, QUERY_STATUS_CODE | QUERY_FLAG_NUMBER, std::ptr::null(), (&raw mut status).cast(), &mut size, std::ptr::null_mut());
    }
    Ok((connect, request, status))
}

/// Текст по HTTPS (для списка доменов Cloudflare).
pub fn https_get_text(url: &str, timeout_ms: i32) -> io::Result<String> {
    let rest = url.strip_prefix("https://").ok_or_else(|| io::Error::other("нужен https://"))?;
    let (host, path) = rest.split_once('/').map_or((rest, "/".to_string()), |(h, p)| (h, format!("/{p}")));
    let (_connect, request, status) = get(host, &path, timeout_ms, "", false)?;
    if status != 200 {
        return Err(io::Error::other(format!("HTTP {status}")));
    }
    let mut body = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let mut read = 0u32;
        // SAFETY: буфер наш, размер передан.
        if unsafe { WinHttpReadData(request.0, chunk.as_mut_ptr().cast(), chunk.len() as u32, &mut read) } == 0 {
            return Err(last_error("чтение ответа"));
        }
        if read == 0 || body.len() > 1 << 20 {
            break;
        }
        body.extend_from_slice(&chunk[..read as usize]);
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

#[derive(Debug)]
pub enum ConnectError {
    /// Вход ответил переадресацией — для этого DC он не работает.
    Redirect(u32),
    Failed(io::Error),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Redirect(code) => write!(f, "переадресация HTTP {code}"),
            Self::Failed(e) => write!(f, "{e}"),
        }
    }
}

/// Открытый WebSocket. `close()` из другого потока прерывает ожидающий `recv`.
pub struct WebSocket {
    ws: Hinternet,
    _connect: Handle,
    closed: AtomicBool,
}

// SAFETY: WinHTTP допускает одновременные send и receive из разных потоков; закрытие — один раз (AtomicBool).
unsafe impl Send for WebSocket {}
unsafe impl Sync for WebSocket {}

impl WebSocket {
    /// wss://host/apiws с заголовками веб-версии Telegram.
    pub fn connect(host: &str, timeout_ms: i32) -> Result<Self, ConnectError> {
        let headers = "Origin: https://web.telegram.org\r\nSec-WebSocket-Protocol: binary\r\n";
        let (connect, request, status) = get(host, "/apiws", timeout_ms, headers, true).map_err(ConnectError::Failed)?;
        if (300..400).contains(&status) {
            return Err(ConnectError::Redirect(status));
        }
        if status != 101 {
            return Err(ConnectError::Failed(io::Error::other(format!("HTTP {status} вместо 101"))));
        }
        // SAFETY: запрос получил 101; после апгрейда он больше не нужен (закрывается при выходе).
        let ws = unsafe { WinHttpWebSocketCompleteUpgrade(request.0, 0) };
        if ws.is_null() {
            return Err(ConnectError::Failed(last_error("апгрейд до WebSocket")));
        }
        // Соединение может молчать сколько угодно: без тайм-аута на приём.
        let infinite = 0u32;
        // SAFETY: параметр — u32 по указателю.
        unsafe { WinHttpSetOption(ws, OPTION_RECEIVE_TIMEOUT, (&raw const infinite).cast(), 4) };
        Ok(Self { ws, _connect: connect, closed: AtomicBool::new(false) })
    }

    pub fn send(&self, data: &[u8]) -> io::Result<()> {
        // SAFETY: буфер только читается.
        let code = unsafe { WinHttpWebSocketSend(self.ws, WS_BINARY_MESSAGE, data.as_ptr().cast(), data.len() as u32) };
        if code == 0 { Ok(()) } else { Err(io::Error::from_raw_os_error(code as i32)) }
    }

    /// Очередная порция данных; `Ok(0)` — сервер закрыл соединение.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let (mut read, mut kind) = (0u32, 0u32);
        // SAFETY: буфер наш, размер передан.
        let code = unsafe { WinHttpWebSocketReceive(self.ws, buf.as_mut_ptr().cast(), buf.len() as u32, &mut read, &mut kind) };
        match (code, kind) {
            (0, WS_BINARY_MESSAGE | WS_BINARY_FRAGMENT) => Ok(read as usize),
            (0, WS_CLOSE) => Ok(0),
            (0, _) => Ok(read as usize), // текстовые кадры Telegram не шлёт; передаём как есть
            (code, _) => Err(io::Error::from_raw_os_error(code as i32)),
        }
    }

    /// Закрыть сокет; ожидающий в другом потоке `recv` вернёт ошибку.
    pub fn close(&self) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            // SAFETY: закрываем ровно один раз.
            unsafe { WinHttpCloseHandle(self.ws) };
        }
    }
}

impl Drop for WebSocket {
    fn drop(&mut self) {
        self.close();
    }
}
