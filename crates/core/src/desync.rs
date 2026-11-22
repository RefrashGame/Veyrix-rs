//! Приёмы обхода DPI: из одного перехваченного исходящего пакета — набор пакетов на отправку.
//!
//! DPI смотрит на первый пакет соединения (TLS ClientHello, HTTP-запрос, QUIC Initial) и по имени сайта решает,
//! блокировать ли. Приёмы мешают ему это имя прочитать, а серверу — нет:
//! - **разрезание** (split): запрос уходит несколькими TCP-сегментами, граница — посреди имени сайта;
//! - **перестановка** (disorder): сегменты уходят в обратном порядке, TCP сервера соберёт их сам;
//! - **фейк**: перед настоящим запросом — поддельный (с www.google.com), который DPI читает, а сервер отбрасывает
//!   (fooling: короткий TTL — не доходит до сервера; неверная контрольная сумма; неверный seq).
//!
//! Контрольные суммы считает вызывающий (WinDivert) уже после этого модуля; `Out::badsum` — испортить после подсчёта.

use crate::packet::{Packet, Transport, parse};
use crate::proto::{Proto, classify};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fooling {
    /// Фейк с этим TTL: умирает у провайдера, до сервера не доходит.
    Ttl(u8),
    /// Фейк с неверной TCP-контрольной суммой: сервер отбрасывает.
    BadSum,
    /// Фейк с seq/ack «из прошлого»: сервер отбрасывает.
    BadSeq,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitPos {
    /// Байт от начала полезной нагрузки.
    At(usize),
    /// Начало имени сайта.
    Host,
    /// Середина домена второго уровня (www.you|tube.com).
    MidSld,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicMode {
    /// Не трогать QUIC.
    Pass,
    /// Фейки перед QUIC Initial.
    Fake,
    /// Не пропускать QUIC: браузер перейдёт на обычный HTTPS (TCP), где работают остальные приёмы.
    Drop,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Strategy {
    pub fake: bool,
    pub split: Vec<SplitPos>,
    pub disorder: bool,
    pub fooling: Vec<Fooling>,
    /// Сколько раз отправить каждый фейк.
    pub repeats: u8,
    pub quic: QuicMode,
    /// Фейки перед голосом Discord (IP discovery, STUN). По умолчанию выключено: у владельца это ломало звонки.
    pub discord_voice: bool,
}

impl Default for Strategy {
    fn default() -> Self {
        Self {
            fake: true,
            split: vec![SplitPos::At(1), SplitPos::MidSld],
            disorder: true,
            fooling: vec![Fooling::BadSeq],
            repeats: 6,
            quic: QuicMode::Fake,
            discord_voice: false,
        }
    }
}

/// Пакет на отправку. Порядок в списке — порядок отправки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Out {
    pub data: Vec<u8>,
    /// Испортить TCP-контрольную сумму после её подсчёта (`corrupt_tcp_checksum`).
    pub badsum: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Отправить исходный пакет без изменений.
    Pass,
    /// Не отправлять.
    Drop,
    /// Отправить эти пакеты вместо исходного.
    Send(Vec<Out>),
}

pub fn apply(buf: &[u8], s: &Strategy) -> Action {
    let Some(pkt) = parse(buf) else { return Action::Pass };
    match (pkt.transport, classify(&pkt)) {
        (Transport::Tcp(_), Some(Proto::Tls { host, host_offset })) => Action::Send(tcp(buf, &pkt, host, host_offset, true, s)),
        (Transport::Tcp(_), Some(Proto::Http { host, host_offset })) => Action::Send(tcp(buf, &pkt, host, host_offset, false, s)),
        (Transport::Udp(_), Some(Proto::Quic)) => match s.quic {
            QuicMode::Pass => Action::Pass,
            QuicMode::Drop => Action::Drop,
            QuicMode::Fake => Action::Send(udp_with_fakes(buf, &pkt, s.repeats)),
        },
        (Transport::Udp(_), Some(Proto::DiscordVoice | Proto::Stun)) if s.discord_voice => {
            Action::Send(udp_with_fakes(buf, &pkt, s.repeats))
        }
        _ => Action::Pass,
    }
}

fn tcp(buf: &[u8], pkt: &Packet, host: &str, host_offset: usize, tls: bool, s: &Strategy) -> Vec<Out> {
    let len = pkt.payload.len();
    let mut cuts: Vec<usize> = s
        .split
        .iter()
        .map(|p| match p {
            SplitPos::At(n) => *n,
            SplitPos::Host => host_offset,
            SplitPos::MidSld => host_offset + mid_sld(host),
        })
        .filter(|&c| c > 0 && c < len)
        .collect();
    cuts.sort_unstable();
    cuts.dedup();

    let mut out = Vec::new();
    if s.fake {
        let fake = if tls { fake_tls_hello("www.google.com") } else { b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n".to_vec() };
        let (data, badsum) = fake_segment(buf, pkt, &fake, &s.fooling);
        out.extend(std::iter::repeat_n(Out { data, badsum }, usize::from(s.repeats.max(1))));
    }
    let bounds: Vec<usize> = std::iter::once(0).chain(cuts).chain(std::iter::once(len)).collect();
    let mut segments: Vec<Out> =
        bounds.windows(2).map(|w| Out { data: segment(buf, pkt, w[0], w[1]), badsum: false }).collect();
    if s.disorder {
        segments.reverse();
    }
    out.extend(segments);
    out
}

/// Смещение середины домена второго уровня внутри имени: «www.youtube.com» → 7 (www.you|tube).
pub fn mid_sld(host: &str) -> usize {
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return host.len() / 2;
    }
    let sld = labels[labels.len() - 2];
    let start = host.len() - labels[labels.len() - 1].len() - 1 - sld.len();
    start + (sld.len() / 2).max(1)
}

/// Записывает в заголовки длину пакета (IPv4 total length / IPv6 payload length; для UDP — длину UDP).
fn fix_lengths(p: &mut [u8], ip_header_len: usize, udp: bool) {
    let len = p.len();
    if p[0] >> 4 == 4 {
        p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    } else {
        p[4..6].copy_from_slice(&((len - 40) as u16).to_be_bytes());
    }
    if udp {
        p[ip_header_len + 4..ip_header_len + 6].copy_from_slice(&((len - ip_header_len) as u16).to_be_bytes());
    }
}

/// Кусок полезной нагрузки [from, to) отдельным TCP-сегментом с правильным seq.
fn segment(buf: &[u8], pkt: &Packet, from: usize, to: usize) -> Vec<u8> {
    let mut p = buf[..pkt.payload_offset].to_vec();
    p.extend_from_slice(&pkt.payload[from..to]);
    fix_lengths(&mut p, pkt.ip_header_len, false);
    let seq = pkt.tcp().expect("TCP").seq.wrapping_add(from as u32);
    let at = pkt.ip_header_len + 4;
    p[at..at + 4].copy_from_slice(&seq.to_be_bytes());
    p
}

fn fake_segment(buf: &[u8], pkt: &Packet, fake: &[u8], fooling: &[Fooling]) -> (Vec<u8>, bool) {
    let mut p = buf[..pkt.payload_offset].to_vec();
    p.extend_from_slice(fake);
    fix_lengths(&mut p, pkt.ip_header_len, false);
    let tcp = pkt.tcp().expect("TCP");
    let at = pkt.ip_header_len;
    let ttl_at = if p[0] >> 4 == 4 { 8 } else { 7 };
    let mut badsum = false;
    for f in fooling {
        match *f {
            Fooling::Ttl(ttl) => p[ttl_at] = ttl,
            Fooling::BadSum => badsum = true,
            Fooling::BadSeq => {
                // Как в zapret: seq и ack заведомо вне окна сервера.
                p[at + 4..at + 8].copy_from_slice(&tcp.seq.wrapping_sub(10_000).to_be_bytes());
                p[at + 8..at + 12].copy_from_slice(&tcp.ack.wrapping_sub(66_000).to_be_bytes());
            }
        }
    }
    (p, badsum)
}

/// Фейки (мусорный QUIC Initial на 1200 байт) и затем исходный UDP-пакет.
fn udp_with_fakes(buf: &[u8], pkt: &Packet, repeats: u8) -> Vec<Out> {
    let mut fake = buf[..pkt.payload_offset].to_vec();
    fake.extend(fake_quic_initial(u64::from(pkt.payload.len() as u32) ^ 0x9e37_79b9_7f4a_7c15));
    fix_lengths(&mut fake, pkt.ip_header_len, true);
    let mut out = vec![Out { data: fake, badsum: false }; usize::from(repeats.max(1))];
    out.push(Out { data: buf.to_vec(), badsum: false });
    out
}

/// Похожий на QUIC v1 Initial пакет со случайным содержимым: DPI видит начало QUIC, сервер не расшифрует и отбросит.
/// shortcut: содержимое не шифруется настоящим ключом Initial, поэтому имени сайта в нём нет; если DPI начнёт
/// требовать расшифровываемый фейк — собрать настоящий Initial (HKDF + AES-GCM, RFC 9001).
pub fn fake_quic_initial(seed: u64) -> Vec<u8> {
    let mut p = noise(seed, 1200);
    p[..6].copy_from_slice(&[0xc3, 0, 0, 0, 1, 8]); // длинный заголовок, Initial, v1, длина DCID 8
    p[14] = 0; // SCID пустой
    p[15] = 0; // без токена
    p
}

/// Псевдослучайные байты (xorshift64*): криптостойкость не нужна, нужно лишь непохожее на нули содержимое.
fn noise(mut x: u64, n: usize) -> Vec<u8> {
    x |= 1;
    (0..n)
        .map(|_| {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            (x.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 56) as u8
        })
        .collect()
}

/// Портит TCP-контрольную сумму уже посчитанного пакета (для fooling = badsum).
pub fn corrupt_tcp_checksum(p: &mut [u8]) {
    if let Some(Packet { ip_header_len, transport: Transport::Tcp(_), .. }) = parse(p) {
        p[ip_header_len + 16] ^= 0xff;
    }
}

/// TLS ClientHello с указанным SNI, добитый до 517 байт как у Chrome — фейк и тестовые данные.
pub fn fake_tls_hello(host: &str) -> Vec<u8> {
    let name = host.as_bytes();
    let mut ext = vec![0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]; // ec_point_formats
    ext.extend([0x00, 0x00]);
    ext.extend(((name.len() + 5) as u16).to_be_bytes());
    ext.extend(((name.len() + 3) as u16).to_be_bytes());
    ext.push(0);
    ext.extend((name.len() as u16).to_be_bytes());
    ext.extend(name);

    let mut body = vec![0x03, 0x03];
    body.extend([0x11; 32]); // random
    body.push(32);
    body.extend([0x22; 32]); // session id
    body.extend([0x00, 0x04, 0x13, 0x01, 0x13, 0x02]); // cipher suites
    body.extend([0x01, 0x00]); // compression
    let without_pad = 5 + 4 + body.len() + 2 + ext.len();
    if let Some(pad) = 517usize.checked_sub(without_pad + 4) {
        ext.extend([0x00, 0x15]);
        ext.extend((pad as u16).to_be_bytes());
        ext.extend(std::iter::repeat_n(0, pad));
    }
    body.extend((ext.len() as u16).to_be_bytes());
    body.extend(ext);

    let mut hs = vec![0x01, 0, (body.len() >> 8) as u8, body.len() as u8];
    hs.extend(body);
    let mut rec = vec![0x16, 0x03, 0x01];
    rec.extend((hs.len() as u16).to_be_bytes());
    rec.extend(hs);
    rec
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::{TCP_ACK, TCP_PSH, tests::ipv4_tcp};

    fn hello_packet(host: &str) -> Vec<u8> {
        ipv4_tcp(&fake_tls_hello(host), 443, TCP_PSH | TCP_ACK)
    }

    fn sent(a: Action) -> Vec<Out> {
        match a {
            Action::Send(v) => v,
            other => panic!("ожидалась отправка, а не {other:?}"),
        }
    }

    #[test]
    fn mid_sld_positions() {
        assert_eq!(mid_sld("www.youtube.com"), 7);
        assert_eq!(mid_sld("discord.com"), 3);
        assert_eq!(mid_sld("localhost"), 4);
        assert_eq!(mid_sld("x.ru"), 1);
    }

    #[test]
    fn fake_hello_is_parsed_back_and_padded() {
        let h = fake_tls_hello("www.google.com");
        assert_eq!(h.len(), 517);
        assert!(matches!(crate::proto::tls_sni(&h), Some(Proto::Tls { host: "www.google.com", .. })));
    }

    #[test]
    fn split_segments_reassemble_into_original_with_correct_seq() {
        let orig = hello_packet("www.youtube.com");
        let s = Strategy { fake: false, disorder: false, ..Strategy::default() };
        let outs = sent(apply(&orig, &s));
        assert_eq!(outs.len(), 3); // разрезы на 1 и посреди «youtube»

        let original = parse(&orig).unwrap();
        let mut joined = Vec::new();
        for o in &outs {
            let p = parse(&o.data).expect("сегмент — корректный пакет");
            assert_eq!(usize::from(u16::from_be_bytes([o.data[2], o.data[3]])), o.data.len());
            assert_eq!(p.tcp().unwrap().seq, original.tcp().unwrap().seq + joined.len() as u32);
            joined.extend_from_slice(p.payload);
        }
        assert_eq!(joined, original.payload);

        let Some(Proto::Tls { host_offset, .. }) = classify(&original) else { panic!() };
        assert_eq!(parse(&outs[1].data).unwrap().payload.len(), host_offset + 7 - 1); // граница — www.you|tube
    }

    #[test]
    fn disorder_sends_last_segment_first() {
        let orig = hello_packet("discord.com");
        let outs = sent(apply(&orig, &Strategy { fake: false, ..Strategy::default() }));
        let seqs: Vec<u32> = outs.iter().map(|o| parse(&o.data).unwrap().tcp().unwrap().seq).collect();
        assert!(seqs.windows(2).all(|w| w[0] > w[1]), "{seqs:?}");
    }

    #[test]
    fn fakes_go_first_with_fooling() {
        let orig = hello_packet("discord.com");
        let s = Strategy { fooling: vec![Fooling::Ttl(4), Fooling::BadSeq, Fooling::BadSum], repeats: 3, ..Strategy::default() };
        let outs = sent(apply(&orig, &s));
        let real_seq = parse(&orig).unwrap().tcp().unwrap().seq;
        for fake in &outs[..3] {
            let p = parse(&fake.data).unwrap();
            assert!(matches!(classify(&p), Some(Proto::Tls { host: "www.google.com", .. })));
            assert_eq!(p.ttl, 4);
            assert_eq!(p.tcp().unwrap().seq, real_seq.wrapping_sub(10_000));
            assert!(fake.badsum);
        }
        assert!(outs[3..].iter().all(|o| !o.badsum && parse(&o.data).unwrap().ttl == 64));
    }

    #[test]
    fn http_request_gets_fake_and_split() {
        let orig = ipv4_tcp(b"GET / HTTP/1.1\r\nHost: rutracker.org\r\n\r\n", 80, TCP_PSH | TCP_ACK);
        let outs = sent(apply(&orig, &Strategy { repeats: 1, ..Strategy::default() }));
        let fake = parse(&outs[0].data).unwrap();
        assert!(matches!(classify(&fake), Some(Proto::Http { host: "www.google.com", .. })));
        assert_eq!(outs.len(), 1 + 3);
    }

    #[test]
    fn other_tcp_data_passes_untouched() {
        let orig = ipv4_tcp(b"\x17\x03\x03\x00\x05hello", 443, TCP_PSH | TCP_ACK);
        assert_eq!(apply(&orig, &Strategy::default()), Action::Pass);
    }

    fn udp_v4(payload: &[u8], dst_port: u16) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 1, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1];
        p.extend(55555u16.to_be_bytes());
        p.extend(dst_port.to_be_bytes());
        p.extend(((8 + payload.len()) as u16).to_be_bytes());
        p.extend([0, 0]);
        p.extend(payload);
        p
    }

    #[test]
    fn quic_modes() {
        let mut initial = vec![0u8; 1250];
        initial[..5].copy_from_slice(&[0xc3, 0, 0, 0, 1]);
        let orig = udp_v4(&initial, 443);

        assert_eq!(apply(&orig, &Strategy { quic: QuicMode::Pass, ..Strategy::default() }), Action::Pass);
        assert_eq!(apply(&orig, &Strategy { quic: QuicMode::Drop, ..Strategy::default() }), Action::Drop);
        let outs = sent(apply(&orig, &Strategy { repeats: 2, ..Strategy::default() }));
        assert_eq!(outs.len(), 3);
        assert_eq!(outs[2].data, orig);
        let fake = parse(&outs[0].data).unwrap();
        assert_eq!(fake.payload.len(), 1200);
        assert_eq!(classify(&fake), Some(Proto::Quic));
        assert_eq!(u16::from_be_bytes([outs[0].data[24], outs[0].data[25]]), 8 + 1200); // длина UDP
    }

    #[test]
    fn discord_voice_is_untouched_unless_enabled() {
        let mut d = vec![0u8; 74];
        d[..4].copy_from_slice(&[0, 1, 0, 0x46]);
        let orig = udp_v4(&d, 50004);
        assert_eq!(apply(&orig, &Strategy::default()), Action::Pass);
        let outs = sent(apply(&orig, &Strategy { discord_voice: true, repeats: 2, ..Strategy::default() }));
        assert_eq!(outs.len(), 3);
        assert_eq!(outs.last().unwrap().data, orig);
    }

    #[test]
    fn badsum_flips_tcp_checksum_only() {
        let mut p = hello_packet("a.com");
        let before = p.clone();
        corrupt_tcp_checksum(&mut p);
        let diff: Vec<usize> = (0..p.len()).filter(|&i| p[i] != before[i]).collect();
        assert_eq!(diff, vec![20 + 16]);
    }
}
