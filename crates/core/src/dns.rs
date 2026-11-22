//! DNS-сообщения (RFC 1035): вопрос из запроса, запрос для проверки, записи A/AAAA из ответа,
//! и IP/UDP-пакет ответа, который подставляется вместо ответа DNS провайдера.

use std::net::IpAddr;

use crate::packet::{Packet, Transport};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

/// Пропускает имя (метки или указатель сжатия), возвращает позицию после него.
fn skip_name(p: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *p.get(at)?;
        match len {
            0 => return Some(at + 1),
            l if l & 0xc0 == 0xc0 => return Some(at + 2),
            l => at += 1 + usize::from(l),
        }
    }
}

/// Имя (в нижнем регистре) и тип первого вопроса.
pub fn question(p: &[u8]) -> Option<(String, u16)> {
    if p.len() < 12 || be16(p, 4)? == 0 {
        return None;
    }
    let mut at = 12;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*p.get(at)?);
        if len == 0 {
            break;
        }
        if len & 0xc0 != 0 {
            return None; // сжатие в вопросе запроса не встречается
        }
        labels.push(String::from_utf8_lossy(p.get(at + 1..at + 1 + len)?).to_ascii_lowercase());
        at += 1 + len;
    }
    Some((labels.join("."), be16(p, at + 1)?))
}

/// Запрос с флагом рекурсии (для `vx doh`).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut p = id.to_be_bytes().to_vec();
    p.extend([0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // RD; один вопрос
    for label in name.trim_end_matches('.').split('.') {
        p.push(label.len() as u8);
        p.extend(label.as_bytes());
    }
    p.push(0);
    p.extend(qtype.to_be_bytes());
    p.extend([0, 1]); // класс IN
    p
}

/// Это ответ на этот запрос: флаг QR и тот же вопрос.
pub fn is_answer_to(query: &[u8], answer: &[u8]) -> bool {
    answer.len() >= 12 && answer[2] & 0x80 != 0 && question(query).is_some() && question(query) == question(answer)
}

/// Адреса из записей A и AAAA ответа.
pub fn addresses(p: &[u8]) -> Vec<IpAddr> {
    let parse = || -> Option<Vec<IpAddr>> {
        let (qd, an) = (be16(p, 4)?, be16(p, 6)?);
        let mut at = 12;
        for _ in 0..qd {
            at = skip_name(p, at)? + 4;
        }
        let mut out = Vec::new();
        for _ in 0..an {
            at = skip_name(p, at)?;
            let (kind, len) = (be16(p, at)?, usize::from(be16(p, at + 8)?));
            let data = p.get(at + 10..at + 10 + len)?;
            match (kind, len) {
                (TYPE_A, 4) => out.push(IpAddr::from(<[u8; 4]>::try_from(data).ok()?)),
                (TYPE_AAAA, 16) => out.push(IpAddr::from(<[u8; 16]>::try_from(data).ok()?)),
                _ => {}
            }
            at += 10 + len;
        }
        Some(out)
    };
    parse().unwrap_or_default()
}

/// IP/UDP-пакет ответа на перехваченный запрос: адреса и порты переставлены, внутри — `answer` с ID запроса.
/// Контрольные суммы считает вызывающий (WinDivert) уже для входящего направления.
pub fn reply_packet(query: &Packet, answer: &[u8]) -> Option<Vec<u8>> {
    let Transport::Udp(udp) = query.transport else { return None };
    let dns_id = query.payload.get(..2)?;
    let mut dns = answer.to_vec();
    dns.get_mut(..2)?.copy_from_slice(dns_id);

    let udp_len = 8 + dns.len();
    let mut p = match (query.src, query.dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            let total = 20 + udp_len;
            let mut h = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0x40, 0, 64, 17, 0, 0];
            h.extend(dst.octets());
            h.extend(src.octets());
            h
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            let mut h = vec![0x60, 0, 0, 0];
            h.extend((udp_len as u16).to_be_bytes());
            h.extend([17, 64]);
            h.extend(dst.octets());
            h.extend(src.octets());
            h
        }
        _ => return None,
    };
    p.extend(udp.dst_port.to_be_bytes());
    p.extend(udp.src_port.to_be_bytes());
    p.extend((udp_len as u16).to_be_bytes());
    p.extend([0, 0]);
    p.extend(dns);
    Some(p)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::parse;

    /// Ответ: вопрос из запроса + записи A и AAAA с указателем сжатия на имя (0xC00C).
    fn answer_for(query: &[u8]) -> Vec<u8> {
        let mut a = query.to_vec();
        a[2] = 0x81;
        a[3] = 0x80;
        a[7] = 2;
        a.extend([0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 215, 14]);
        a.extend([0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]);
        a.extend([0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0, 1, 0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46]);
        a
    }

    #[test]
    fn query_roundtrip_and_answer_addresses() {
        let q = build_query(0x1234, "Example.COM.", TYPE_A);
        assert_eq!(question(&q), Some(("example.com".into(), TYPE_A)));
        let a = answer_for(&q);
        assert!(is_answer_to(&q, &a));
        assert!(!is_answer_to(&q, &q)); // без флага QR — не ответ
        assert!(!is_answer_to(&q, &answer_for(&build_query(1, "other.com", TYPE_A))));
        assert_eq!(addresses(&a), vec![
            "93.184.215.14".parse::<IpAddr>().unwrap(),
            "2606:2800:220:1:248:1893:25c8:1946".parse().unwrap()
        ]);
        assert!(addresses(&a[..a.len() - 3]).is_empty()); // обрезанный ответ не роняет разбор
    }

    fn udp_packet(v6: bool, payload: &[u8]) -> Vec<u8> {
        let udp_len = 8 + payload.len();
        let mut p = if v6 {
            let mut h = vec![0x60, 0, 0, 0];
            h.extend((udp_len as u16).to_be_bytes());
            h.extend([17, 64]);
            h.extend([0xfd; 16]);
            h.extend([0xfe; 16]);
            h
        } else {
            let total = 20 + udp_len;
            vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 0, 0, 0, 128, 17, 0, 0, 192, 168, 1, 10, 192, 168, 1, 1]
        };
        p.extend(53001u16.to_be_bytes());
        p.extend(53u16.to_be_bytes());
        p.extend((udp_len as u16).to_be_bytes());
        p.extend([0, 0]);
        p.extend(payload);
        p
    }

    #[test]
    fn reply_packet_swaps_addresses_ports_and_keeps_query_id() {
        for v6 in [false, true] {
            let q = build_query(0xbeef, "youtube.com", TYPE_A);
            let query_bytes = udp_packet(v6, &q);
            let query = parse(&query_bytes).unwrap();
            let mut answer = answer_for(&q);
            answer[0] = 0; // DoH-серверы отвечают с ID 0
            answer[1] = 0;

            let reply_bytes = reply_packet(&query, &answer).unwrap();
            let reply = parse(&reply_bytes).expect("ответ — корректный пакет");
            assert_eq!((reply.src, reply.dst), (query.dst, query.src));
            let Transport::Udp(u) = reply.transport else { panic!() };
            assert_eq!((u.src_port, u.dst_port), (53, 53001));
            assert_eq!(&reply.payload[..2], &[0xbe, 0xef]);
            assert_eq!(&reply.payload[2..], &answer[2..]);
        }
    }
}
