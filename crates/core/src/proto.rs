//! Распознавание протоколов по первым байтам полезной нагрузки: по ним DPI решает, блокировать ли соединение.

use crate::packet::{Packet, Transport};

/// Что увидел разбор. Смещения — от начала полезной нагрузки: по ним этап 3 будет резать пакет.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto<'a> {
    /// TLS ClientHello с именем сайта (SNI).
    Tls { host: &'a str, host_offset: usize },
    /// HTTP-запрос с заголовком Host.
    Http { host: &'a str, host_offset: usize },
    /// QUIC Initial (HTTP/3): имя сайта внутри зашифровано ключом из самого пакета.
    Quic,
    /// Пакет определения IP голосового сервера Discord (74 байта).
    DiscordVoice,
    /// STUN (WebRTC, звонки).
    Stun,
}

pub fn classify<'a>(pkt: &Packet<'a>) -> Option<Proto<'a>> {
    let p = pkt.payload;
    match pkt.transport {
        Transport::Tcp(_) => tls_sni(p).or_else(|| http_host(p)),
        Transport::Udp(_) if is_quic_initial(p) => Some(Proto::Quic),
        Transport::Udp(_) if is_discord_ip_discovery(p) => Some(Proto::DiscordVoice),
        Transport::Udp(_) if is_stun(p) => Some(Proto::Stun),
        _ => None,
    }
}

fn be16(b: &[u8], at: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?)))
}

/// Имя сайта, если байты похожи на него (только ASCII-буквы, цифры, «.-_»).
fn hostname(s: &[u8]) -> Option<&str> {
    let ok = !s.is_empty() && s.len() <= 253 && s.iter().all(|c| c.is_ascii_alphanumeric() || b".-_".contains(c));
    ok.then(|| std::str::from_utf8(s).ok()).flatten()
}

/// Имя сайта из TLS ClientHello. Работает и на обрезанном ClientHello, если SNI успел попасть в этот сегмент.
pub fn tls_sni(p: &[u8]) -> Option<Proto<'_>> {
    // Запись TLS: тип 22 (handshake), версия 3.x; сообщение: тип 1 (ClientHello).
    if p.len() < 6 || p[0] != 0x16 || p[1] != 3 || p[5] != 1 {
        return None;
    }
    let mut at = 5 + 4 + 2 + 32; // заголовки записи и сообщения, версия, random
    at += 1 + usize::from(*p.get(at)?); // session id
    at += 2 + be16(p, at)?; // cipher suites
    at += 1 + usize::from(*p.get(at)?); // compression
    let ext_end = (at + 2 + be16(p, at)?).min(p.len());
    at += 2;
    while at + 4 <= ext_end {
        let (kind, len) = (be16(p, at)?, be16(p, at + 2)?);
        at += 4;
        if kind == 0 {
            // server_name: длина списка (2), тип имени (1, 0 = host), длина имени (2), имя.
            if p.get(at + 2) != Some(&0) {
                return None;
            }
            let name_len = be16(p, at + 3)?;
            let host_offset = at + 5;
            let name = p.get(host_offset..host_offset + name_len)?;
            return hostname(name).map(|host| Proto::Tls { host, host_offset });
        }
        at += len;
    }
    None
}

/// Хост из HTTP-запроса (без порта).
pub fn http_host(p: &[u8]) -> Option<Proto<'_>> {
    const METHODS: [&[u8]; 8] = [b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT "];
    if !METHODS.iter().any(|m| p.starts_with(m)) {
        return None;
    }
    let line = p.windows(7).position(|w| w.eq_ignore_ascii_case(b"\r\nhost:"))? + 7;
    let start = line + p[line..].iter().take_while(|c| **c == b' ' || **c == b'\t').count();
    let len = p[start..].iter().take_while(|c| !b"\r\n: ".contains(c)).count();
    let name = &p[start..start + len];
    hostname(name).map(|host| Proto::Http { host, host_offset: start })
}

/// QUIC Initial от клиента: длинный заголовок, известная версия, тип Initial; клиент обязан добивать до 1200 байт.
pub fn is_quic_initial(p: &[u8]) -> bool {
    if p.len() < 1200 || p[0] & 0xc0 != 0xc0 {
        return false;
    }
    let version = u32::from_be_bytes([p[1], p[2], p[3], p[4]]);
    let kind = (p[0] >> 4) & 0x03;
    match version {
        0x0000_0001 => kind == 0,                 // QUIC v1
        0x6b33_43cf => kind == 1,                 // QUIC v2 (RFC 9369): Initial = 0b01
        v if v >> 8 == 0x00ff_0000 => kind == 0, // черновики
        _ => false,
    }
}

/// Discord IP discovery: тип 0x0001, длина 70, всего 74 байта.
pub fn is_discord_ip_discovery(p: &[u8]) -> bool {
    p.len() == 74 && p[..4] == [0x00, 0x01, 0x00, 0x46]
}

/// STUN: первые два бита 0 и magic cookie 0x2112A442.
pub fn is_stun(p: &[u8]) -> bool {
    p.len() >= 20 && p[0] < 0x40 && p[4..8] == [0x21, 0x12, 0xa4, 0x42]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{TCP_ACK, TCP_PSH, parse, tests::ipv4_tcp};

    use crate::desync::fake_tls_hello as client_hello;

    #[test]
    fn sni_and_its_offset() {
        let hello = client_hello("www.youtube.com");
        let Some(Proto::Tls { host, host_offset }) = tls_sni(&hello) else { panic!() };
        assert_eq!(host, "www.youtube.com");
        assert_eq!(&hello[host_offset..host_offset + host.len()], b"www.youtube.com");
    }

    #[test]
    fn sni_from_truncated_hello_and_none_when_cut_before_it() {
        let mut hello = client_hello("discord.com");
        hello.extend([0u8; 300]); // будто дальше padding в следующем сегменте
        let host_end = hello.windows(11).position(|w| w == b"discord.com").unwrap() + 11;
        assert!(matches!(tls_sni(&hello[..host_end]), Some(Proto::Tls { host: "discord.com", .. })));
        assert_eq!(tls_sni(&hello[..host_end - 1]), None);
    }

    #[test]
    fn not_tls() {
        assert_eq!(tls_sni(b"\x17\x03\x03\x00\x10hello"), None); // application data
        assert_eq!(tls_sni(b""), None);
    }

    #[test]
    fn http_host_without_port_case_insensitive() {
        let req = b"GET / HTTP/1.1\r\nUser-Agent: x\r\nhOsT:  rutracker.org:8080\r\n\r\n";
        let Some(Proto::Http { host, host_offset }) = http_host(req) else { panic!() };
        assert_eq!(host, "rutracker.org");
        assert_eq!(&req[host_offset..host_offset + 13], b"rutracker.org");
        assert_eq!(http_host(b"HTTP/1.1 200 OK\r\nHost: a\r\n"), None);
    }

    #[test]
    fn quic_initial_v1_v2_and_short_header() {
        let mut p = vec![0u8; 1200];
        p[0] = 0xc3;
        p[1..5].copy_from_slice(&1u32.to_be_bytes());
        assert!(is_quic_initial(&p));
        p[0] = 0xd3; // v1 тип 1 = 0-RTT
        assert!(!is_quic_initial(&p));
        p[1..5].copy_from_slice(&0x6b33_43cfu32.to_be_bytes());
        assert!(is_quic_initial(&p)); // v2: тип 1 — Initial
        p[0] = 0x43; // короткий заголовок
        assert!(!is_quic_initial(&p));
        assert!(!is_quic_initial(&p[..1199]));
    }

    #[test]
    fn voice_and_stun() {
        let mut d = vec![0u8; 74];
        d[..4].copy_from_slice(&[0, 1, 0, 0x46]);
        assert!(is_discord_ip_discovery(&d));
        assert!(!is_discord_ip_discovery(&d[..73]));
        let mut s = vec![0u8; 20];
        s[..2].copy_from_slice(&[0x00, 0x01]);
        s[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        assert!(is_stun(&s));
    }

    #[test]
    fn classify_tcp_packet() {
        let p = ipv4_tcp(&client_hello("rr1---sn.googlevideo.com"), 443, TCP_PSH | TCP_ACK);
        let pkt = parse(&p).unwrap();
        assert!(matches!(classify(&pkt), Some(Proto::Tls { host: "rr1---sn.googlevideo.com", .. })));
    }
}
