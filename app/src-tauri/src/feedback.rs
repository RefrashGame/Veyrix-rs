//! «Сообщить о проблеме»: описание, скриншоты и Telegram для ответа уходят разработчику через Telegram-бота.
//! Токен бота и чат разработчика вшиваются при сборке (VEYRIX_FEEDBACK_TOKEN, VEYRIX_FEEDBACK_CHAT — секреты GitHub
//! Actions); в git их нет. shortcut: токен можно достать из exe — бот только пишет разработчику, худшее — спам ему;
//! при злоупотреблении токен меняется в @BotFather и выходит новая версия.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

const TOKEN: Option<&str> = option_env!("VEYRIX_FEEDBACK_TOKEN");
const CHAT: Option<&str> = option_env!("VEYRIX_FEEDBACK_CHAT");

const MAX_TEXT: usize = 3000;
const MAX_PHOTOS: usize = 6;
const MAX_PHOTO_BYTES: usize = 10 << 20;
/// Не чаще одного отчёта в минуту — защита от случайных повторов.
const PAUSE: Duration = Duration::from_secs(60);

static LAST: Mutex<Option<Instant>> = Mutex::new(None);

/// Отправка настроена в этой сборке.
pub fn configured() -> bool {
    TOKEN.is_some_and(|t| !t.is_empty()) && CHAT.is_some_and(|c| !c.is_empty())
}

#[derive(Debug, Deserialize)]
pub struct Photo {
    pub name: String,
    /// Содержимое файла в base64.
    pub data: String,
}

/// Проверка полей до отправки; возвращает картинки (имя, данные).
fn validate<'a>(description: &str, photos: &'a [Photo]) -> Result<Vec<(&'a str, Vec<u8>)>, String> {
    if description.trim().is_empty() {
        return Err("Опишите, что случилось".into());
    }
    if description.chars().count() > MAX_TEXT {
        return Err(format!("Описание длиннее {MAX_TEXT} символов — сократите"));
    }
    if photos.len() > MAX_PHOTOS {
        return Err(format!("Не больше {MAX_PHOTOS} снимков"));
    }
    photos
        .iter()
        .map(|p| {
            let data = base64_decode(&p.data).ok_or_else(|| format!("{}: не удалось прочитать файл", p.name))?;
            if data.len() > MAX_PHOTO_BYTES {
                return Err(format!("{}: больше 10 МБ", p.name));
            }
            Ok((p.name.as_str(), data))
        })
        .collect()
}

pub fn send(version: &str, description: &str, reply: &str, photos: &[Photo]) -> Result<(), String> {
    let images = validate(description, photos)?;
    let (Some(token), Some(chat)) = (TOKEN, CHAT) else {
        return Err("В этой сборке отправка отчётов не настроена".into());
    };
    if let Some(t) = *LAST.lock().map_err(|e| e.to_string())?
        && t.elapsed() < PAUSE
    {
        return Err("Отчёт уже отправлен — следующий можно через минуту".into());
    }

    let reply = match reply.trim() {
        "" => "—".to_string(),
        r if r.starts_with('@') => r.to_string(),
        r => format!("@{r}"),
    };
    let text = format!("🛠 Veyrix-rs {version}\nОтвет: {reply}\n\n{}", description.trim());
    call(token, "sendMessage", &[("chat_id", chat), ("text", &text)], &[])?;

    match images.as_slice() {
        [] => {}
        [(name, data)] => call(token, "sendPhoto", &[("chat_id", chat)], &[("photo", name, mime(name), data)])?,
        many => {
            let fields: Vec<String> = (0..many.len()).map(|i| format!("p{i}")).collect();
            let media: Vec<String> = fields.iter().map(|f| format!("{{\"type\":\"photo\",\"media\":\"attach://{f}\"}}")).collect();
            let media = format!("[{}]", media.join(","));
            let files: Vec<(&str, &str, &str, &[u8])> =
                many.iter().zip(&fields).map(|((name, data), field)| (field.as_str(), *name, mime(name), data.as_slice())).collect();
            call(token, "sendMediaGroup", &[("chat_id", chat), ("media", &media)], &files)?;
        }
    }
    *LAST.lock().map_err(|e| e.to_string())? = Some(Instant::now());
    Ok(())
}

fn mime(name: &str) -> &'static str {
    let lower = name.to_ascii_lowercase();
    if lower.ends_with(".jpg") || lower.ends_with(".jpeg") { "image/jpeg" } else { "image/png" }
}

/// Запрос к Bot API; ошибка — текстом Telegram.
fn call(token: &str, method: &str, fields: &[(&str, &str)], files: &[(&str, &str, &str, &[u8])]) -> Result<(), String> {
    let (boundary, body) = vx_net::multipart(fields, files);
    let headers = format!("Content-Type: multipart/form-data; boundary={boundary}\r\n");
    let mut answer = Vec::new();
    let url = format!("https://api.telegram.org/bot{token}/{method}");
    let status = vx_net::request("POST", &url, &headers, &body, 30_000, &mut answer, 1 << 20)
        .map_err(|e| format!("Telegram недоступен: {e}"))?;
    if status == 200 {
        return Ok(());
    }
    let reason = serde_json::from_slice::<serde_json::Value>(&answer)
        .ok()
        .and_then(|v| v["description"].as_str().map(str::to_string))
        .unwrap_or_else(|| format!("HTTP {status}"));
    Err(format!("Telegram не принял отчёт: {reason}"))
}

/// Base64 (стандартный алфавит, с `=` или без); `data:…;base64,` в начале пропускается.
fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let text = text.split_once(";base64,").map_or(text, |(_, b)| b);
    let mut out = Vec::with_capacity(text.len() * 3 / 4);
    let (mut acc, mut bits) = (0u32, 0u32);
    for c in text.bytes().filter(|c| !c.is_ascii_whitespace() && *c != b'=') {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64() {
        assert_eq!(base64_decode("SGVsbG8=").unwrap(), b"Hello");
        assert_eq!(base64_decode("data:image/png;base64,SGVsbG8gd29ybGQ").unwrap(), b"Hello world");
        assert_eq!(base64_decode("").unwrap(), b"");
        assert!(base64_decode("SGV*").is_none());
    }

    #[test]
    fn validation() {
        assert!(validate("  ", &[]).is_err());
        assert!(validate(&"я".repeat(MAX_TEXT + 1), &[]).is_err());
        let many: Vec<Photo> = (0..7).map(|i| Photo { name: format!("{i}.png"), data: String::new() }).collect();
        assert!(validate("текст", &many).is_err());
        let one = [Photo { name: "a.png".into(), data: "UE5H".into() }];
        assert_eq!(validate("текст", &one).unwrap(), vec![("a.png", b"PNG".to_vec())]);
    }
}
