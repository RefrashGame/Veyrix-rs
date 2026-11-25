//! Самопроверка: клиент с secret → локальный прокси → Telegram. Шлём req_pq_multi и ждём resPQ — первый обмен,
//! который делает Telegram Desktop. Ничего не меняет в системе.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::crypto::random;
use crate::mtproto::{ABRIDGED, Client};

const STEP_TIMEOUT: Duration = Duration::from_secs(15);
const REQ_PQ_MULTI: u32 = 0xbe7e_8ef1;
const RES_PQ: u32 = 0x0516_2463;

/// req_pq_multi через прокси на `port` к DC `dc`; время ответа или понятная ошибка.
pub fn req_pq(port: u16, secret: &[u8; 16], dc: i16) -> Result<Duration, String> {
    let started = Instant::now();
    let mut client = Client::new(secret, ABRIDGED, dc);
    let mut s = TcpStream::connect(("127.0.0.1", port)).map_err(|e| format!("прокси: {e}"))?;
    s.set_read_timeout(Some(STEP_TIMEOUT)).map_err(|e| e.to_string())?;
    s.write_all(&client.init).map_err(|e| e.to_string())?;

    let mut body = [0u8; 40];
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    body[8..16].copy_from_slice(&((now << 32) as i64).to_le_bytes()); // message_id
    body[16..20].copy_from_slice(&20i32.to_le_bytes());
    body[20..24].copy_from_slice(&REQ_PQ_MULTI.to_le_bytes());
    random(&mut body[24..40]); // nonce
    let mut packet = [&[(body.len() / 4) as u8][..], &body].concat();
    client.encrypt.apply(&mut packet);
    s.write_all(&packet).map_err(|e| e.to_string())?;

    let mut head = [0u8; 1];
    s.read_exact(&mut head).map_err(|e| format!("нет ответа: {e}"))?;
    client.decrypt.apply(&mut head);
    let mut reply = vec![0u8; usize::from(head[0]) * 4];
    s.read_exact(&mut reply).map_err(|e| format!("ответ оборван: {e}"))?;
    client.decrypt.apply(&mut reply);
    let constructor = reply.get(20..24).map(|b| u32::from_le_bytes(b.try_into().expect("4")));
    match constructor {
        Some(RES_PQ) => Ok(started.elapsed()),
        other => Err(format!("ответ не resPQ: {other:x?}")),
    }
}
