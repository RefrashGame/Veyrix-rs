//! DNS-over-HTTPS (RFC 8484, POST application/dns-message) через WinHTTP — HTTPS-клиент, встроенный в Windows.
//! Своих TLS-библиотек нет; сертификат сервера проверяет Windows.

use std::ffi::c_void;
use std::io;

type Hinternet = *mut c_void;

const ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;
const FLAG_SECURE: u32 = 0x0080_0000;
const QUERY_STATUS_CODE: u32 = 19;
const QUERY_FLAG_NUMBER: u32 = 0x2000_0000;

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
    fn WinHttpSendRequest(
        request: Hinternet,
        headers: *const u16,
        headers_len: u32,
        optional: *const c_void,
        optional_len: u32,
        total_len: u32,
        context: usize,
    ) -> i32;
    fn WinHttpReceiveResponse(request: Hinternet, reserved: *mut c_void) -> i32;
    fn WinHttpQueryHeaders(request: Hinternet, level: u32, name: *const u16, buf: *mut c_void, len: *mut u32, index: *mut u32) -> i32;
    fn WinHttpReadData(request: Hinternet, buf: *mut c_void, to_read: u32, read: *mut u32) -> i32;
    fn WinHttpCloseHandle(h: Hinternet) -> i32;
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain([0]).collect()
}

fn check(ok: i32, what: &str) -> io::Result<()> {
    if ok != 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    // Коды WinHTTP (12xxx) — самые частые словами.
    let hint = match err.raw_os_error() {
        Some(12002) => "сервер не ответил вовремя",
        Some(12007) => "не найден адрес сервера",
        Some(12029) | Some(12030) => "соединение не установлено или оборвано (возможно, DoH-сервер заблокирован)",
        Some(12175) => "ошибка проверки сертификата",
        _ => "",
    };
    Err(io::Error::new(err.kind(), format!("{what}: {hint} ({err})")))
}

/// Закрывает дескриптор WinHTTP при выходе из области видимости.
struct Handle(Hinternet);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: дескриптор получен от WinHTTP и закрывается один раз.
        unsafe { WinHttpCloseHandle(self.0) };
    }
}

/// Сервер DoH: адрес (IP, чтобы не нужен был обычный DNS для самого DoH), порт и путь.
pub fn provider(name: &str) -> io::Result<(String, u16, String)> {
    let preset = |host: &str| Ok((host.to_string(), 443, "/dns-query".to_string()));
    match name {
        "cloudflare" => preset("1.1.1.1"),
        "google" => preset("8.8.8.8"),
        "quad9" => preset("9.9.9.9"),
        url => {
            let rest = url.strip_prefix("https://").ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, format!("DoH: cloudflare, google, quad9 или https://… (а не «{url}»)"))
            })?;
            let (authority, path) = rest.split_once('/').map_or((rest, "/dns-query".to_string()), |(a, p)| (a, format!("/{p}")));
            let (host, port) = match authority.rsplit_once(':') {
                Some((h, p)) if !h.contains(':') => {
                    (h, p.parse().map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "DoH: неверный порт"))?)
                }
                _ => (authority, 443),
            };
            Ok((host.to_string(), port, path))
        }
    }
}

/// Клиент DoH. Соединение с сервером переиспользуется; можно звать из нескольких потоков.
pub struct Doh {
    // Порядок полей = порядок закрытия: сначала соединение, потом сессия.
    connect: Handle,
    _session: Handle,
    path: Vec<u16>,
    /// Имя или адрес сервера — запросы на него самого не перехватываются (иначе DoH ждал бы сам себя).
    pub host: String,
}

// SAFETY: дескрипторы сессии и соединения WinHTTP потокобезопасны; запросы открываются в каждом вызове свои.
unsafe impl Send for Doh {}
unsafe impl Sync for Doh {}

impl Doh {
    pub fn new(provider_name: &str) -> io::Result<Self> {
        let (host, port, path) = provider(provider_name)?;
        let agent = wide("Veyrix-rs");
        // SAFETY: строки UTF-16 с нулём живут до конца вызовов.
        let session = Handle(unsafe {
            WinHttpOpen(agent.as_ptr(), ACCESS_TYPE_AUTOMATIC_PROXY, std::ptr::null(), std::ptr::null(), 0)
        });
        if session.0.is_null() {
            check(0, "WinHTTP")?;
        }
        // Мс на разрешение, соединение, отправку, ответ: DNS не должен ждать долго — дальше запасной путь.
        // SAFETY: дескриптор сессии открыт.
        check(unsafe { WinHttpSetTimeouts(session.0, 2000, 2000, 2000, 3000) }, "WinHTTP")?;
        // HTTP/2: Quad9 и часть других DoH-серверов HTTP/1.1 не принимают (HTTP 505). Без поддержки — останется 1.1.
        let http2: u32 = 1; // WINHTTP_PROTOCOL_FLAG_HTTP2
        // SAFETY: параметр — u32 по указателю, длина 4.
        unsafe { WinHttpSetOption(session.0, 133 /* WINHTTP_OPTION_ENABLE_HTTP_PROTOCOL */, (&raw const http2).cast(), 4) };
        let server = wide(&host);
        // SAFETY: строка живёт до конца вызова.
        let connect = Handle(unsafe { WinHttpConnect(session.0, server.as_ptr(), port, 0) });
        if connect.0.is_null() {
            check(0, "DoH-сервер")?;
        }
        Ok(Self { connect, _session: session, path: wide(&path), host })
    }

    /// Отправляет DNS-запрос (сообщение без TCP-префикса длины) и возвращает DNS-ответ.
    pub fn query(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        let verb = wide("POST");
        // SAFETY: строки живут до конца вызова; accept-типы не нужны (null).
        let request = Handle(unsafe {
            WinHttpOpenRequest(self.connect.0, verb.as_ptr(), self.path.as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null(), FLAG_SECURE)
        });
        if request.0.is_null() {
            check(0, "DoH-запрос")?;
        }
        let headers = wide("Content-Type: application/dns-message\r\nAccept: application/dns-message\r\n");
        let len = message.len() as u32;
        // SAFETY: тело и заголовки живут до конца вызова; длина заголовков u32::MAX = «до нуля».
        check(
            unsafe { WinHttpSendRequest(request.0, headers.as_ptr(), u32::MAX, message.as_ptr().cast(), len, len, 0) },
            "DoH-запрос",
        )?;
        // SAFETY: запрос отправлен этим же дескриптором.
        check(unsafe { WinHttpReceiveResponse(request.0, std::ptr::null_mut()) }, "DoH-ответ")?;

        let (mut status, mut size) = (0u32, 4u32);
        // SAFETY: буфер — u32 размером 4 байта, как требует QUERY_FLAG_NUMBER.
        check(
            unsafe {
                WinHttpQueryHeaders(
                    request.0,
                    QUERY_STATUS_CODE | QUERY_FLAG_NUMBER,
                    std::ptr::null(),
                    (&raw mut status).cast(),
                    &mut size,
                    std::ptr::null_mut(),
                )
            },
            "DoH-ответ",
        )?;
        if status != 200 {
            return Err(io::Error::other(format!("DoH-сервер ответил HTTP {status}")));
        }

        let mut body = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            let mut read = 0u32;
            // SAFETY: буфер принадлежит нам, размер передан.
            check(unsafe { WinHttpReadData(request.0, chunk.as_mut_ptr().cast(), chunk.len() as u32, &mut read) }, "DoH-ответ")?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read as usize]);
            if body.len() > 65_535 {
                return Err(io::Error::other("DoH-ответ больше 64 КБ"));
            }
        }
        Ok(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn providers() {
        assert_eq!(provider("cloudflare").unwrap(), ("1.1.1.1".into(), 443, "/dns-query".into()));
        assert_eq!(provider("https://dns.example:8443/q").unwrap(), ("dns.example".into(), 8443, "/q".into()));
        assert_eq!(provider("https://dns.example").unwrap(), ("dns.example".into(), 443, "/dns-query".into()));
        assert!(provider("http://plain").is_err());
        assert!(provider("https://h:xx/").is_err());
    }
}
