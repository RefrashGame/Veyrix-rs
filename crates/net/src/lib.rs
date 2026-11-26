//! HTTPS через WinHTTP (встроен в Windows): запрос с телом и ответ потоком в любой `Write`.
//! Нужен окну для отчётов о проблемах (Telegram Bot API) и обновлений (GitHub). Переадресации WinHTTP
//! проходит сам (GitHub отдаёт файлы релизов через переадресацию на свой CDN). Сертификаты проверяет Windows.

use std::ffi::c_void;
use std::io::{self, Write};

type Hinternet = *mut c_void;

const ACCESS_TYPE_AUTOMATIC_PROXY: u32 = 4;
const FLAG_SECURE: u32 = 0x0080_0000;
const QUERY_STATUS_CODE: u32 = 19;
const QUERY_FLAG_NUMBER: u32 = 0x2000_0000;

#[link(name = "winhttp", kind = "raw-dylib")]
unsafe extern "system" {
    fn WinHttpOpen(agent: *const u16, access: u32, proxy: *const u16, bypass: *const u16, flags: u32) -> Hinternet;
    fn WinHttpSetTimeouts(h: Hinternet, resolve: i32, connect: i32, send: i32, receive: i32) -> i32;
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
    let hint = match err.raw_os_error() {
        Some(12002) => "сервер не ответил вовремя",
        Some(12007) => "не найден адрес сервера",
        Some(12029) | Some(12030) => "соединение не установлено или оборвано (сервер может блокироваться — включите обход)",
        Some(12175) => "ошибка проверки сертификата",
        _ => "",
    };
    Err(io::Error::new(err.kind(), format!("{what}: {hint} ({err})")))
}

struct Handle(Hinternet);

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: дескриптор получен от WinHTTP и закрывается один раз.
        unsafe { WinHttpCloseHandle(self.0) };
    }
}

/// Хост и путь из `https://host/path`.
fn split_url(url: &str) -> io::Result<(&str, String)> {
    let rest = url.strip_prefix("https://").ok_or_else(|| io::Error::other(format!("нужен https:// адрес: {url}")))?;
    Ok(rest.split_once('/').map_or((rest, "/".to_string()), |(h, p)| (h, format!("/{p}"))))
}

/// HTTPS-запрос. Тело ответа пишется в `out`, но не больше `max` байт. Возвращает код ответа HTTP.
pub fn request(method: &str, url: &str, headers: &str, body: &[u8], timeout_ms: i32, out: &mut dyn Write, max: usize) -> io::Result<u32> {
    let (host, path) = split_url(url)?;
    let agent = wide("Veyrix-rs");
    // SAFETY: строки UTF-16 с нулём живут до конца вызовов; результаты проверяются.
    let session = Handle(unsafe { WinHttpOpen(agent.as_ptr(), ACCESS_TYPE_AUTOMATIC_PROXY, std::ptr::null(), std::ptr::null(), 0) });
    if session.0.is_null() {
        check(0, "WinHTTP")?;
    }
    // SAFETY: дескриптор сессии открыт.
    check(unsafe { WinHttpSetTimeouts(session.0, timeout_ms, timeout_ms, timeout_ms, timeout_ms) }, "WinHTTP")?;
    let server = wide(host);
    // SAFETY: строка живёт до конца вызова.
    let connect = Handle(unsafe { WinHttpConnect(session.0, server.as_ptr(), 443, 0) });
    if connect.0.is_null() {
        check(0, host)?;
    }
    let (verb, path_w) = (wide(method), wide(&path));
    // SAFETY: строки живут до конца вызова.
    let req = Handle(unsafe {
        WinHttpOpenRequest(connect.0, verb.as_ptr(), path_w.as_ptr(), std::ptr::null(), std::ptr::null(), std::ptr::null(), FLAG_SECURE)
    });
    if req.0.is_null() {
        check(0, host)?;
    }
    let headers_w = wide(headers);
    let len = u32::try_from(body.len()).map_err(|_| io::Error::other("слишком большое тело запроса"))?;
    // SAFETY: тело и заголовки живут до конца вызова; длина заголовков u32::MAX — «до нуля».
    check(
        unsafe { WinHttpSendRequest(req.0, headers_w.as_ptr(), u32::MAX, body.as_ptr().cast(), len, len, 0) },
        host,
    )?;
    // SAFETY: запрос отправлен этим же дескриптором.
    check(unsafe { WinHttpReceiveResponse(req.0, std::ptr::null_mut()) }, host)?;
    let (mut status, mut size) = (0u32, 4u32);
    // SAFETY: буфер — u32 размером 4 байта, как требует QUERY_FLAG_NUMBER.
    check(
        unsafe {
            WinHttpQueryHeaders(req.0, QUERY_STATUS_CODE | QUERY_FLAG_NUMBER, std::ptr::null(), (&raw mut status).cast(), &mut size, std::ptr::null_mut())
        },
        host,
    )?;
    let mut chunk = vec![0u8; 64 * 1024];
    let mut total = 0usize;
    loop {
        let mut read = 0u32;
        // SAFETY: буфер наш, размер передан.
        check(unsafe { WinHttpReadData(req.0, chunk.as_mut_ptr().cast(), chunk.len() as u32, &mut read) }, host)?;
        if read == 0 {
            break;
        }
        total += read as usize;
        if total > max {
            return Err(io::Error::other(format!("ответ {host} больше {} МБ", max >> 20)));
        }
        out.write_all(&chunk[..read as usize])?;
    }
    Ok(status)
}

/// GET и ответ текстом (до 2 МБ); ошибка, если код не 200.
pub fn get_text(url: &str, headers: &str) -> io::Result<String> {
    let mut body = Vec::new();
    let status = request("GET", url, headers, &[], 15_000, &mut body, 2 << 20)?;
    if status != 200 {
        return Err(io::Error::other(format!("HTTP {status}")));
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

/// Тело `multipart/form-data`: текстовые поля и файлы (поле, имя файла, тип, данные). Возвращает (граница, тело).
pub fn multipart(fields: &[(&str, &str)], files: &[(&str, &str, &str, &[u8])]) -> (String, Vec<u8>) {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_nanos() as u64);
    let boundary = format!("veyrix{nanos:016x}");
    let mut body = Vec::new();
    for (name, value) in fields {
        body.extend(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n").as_bytes());
    }
    for (name, filename, mime, data) in files {
        body.extend(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {mime}\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(data);
        body.extend(b"\r\n");
    }
    body.extend(format!("--{boundary}--\r\n").as_bytes());
    (boundary, body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn urls() {
        assert_eq!(split_url("https://api.github.com/repos/a/b").unwrap(), ("api.github.com", "/repos/a/b".to_string()));
        assert_eq!(split_url("https://example.com").unwrap(), ("example.com", "/".to_string()));
        assert!(split_url("http://example.com/").is_err());
    }

    #[test]
    fn multipart_body() {
        let (b, body) = multipart(&[("chat_id", "42")], &[("p0", "a.png", "image/png", b"PNG")]);
        let text = String::from_utf8(body).unwrap();
        assert!(text.starts_with(&format!("--{b}\r\nContent-Disposition: form-data; name=\"chat_id\"\r\n\r\n42\r\n")));
        assert!(text.contains("name=\"p0\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\nPNG\r\n"));
        assert!(text.ends_with(&format!("--{b}--\r\n")));
    }
}
