//! Локальный MTProto-прокси для Telegram Desktop (127.0.0.1 + secret, ссылка tg://proxy).
//!
//! Протокол — по tg-ws-proxy (Flowseal, MIT) и Veyrix на C#; реализация своя. Шифрование — системная CNG,
//! HTTPS и WebSocket — системный WinHTTP: сторонних библиотек нет.

pub mod cloudflare;
pub mod crypto;
pub mod mtproto;
pub mod proxy;
pub mod selftest;
pub mod ws;

pub use proxy::{Proxy, Stats};
