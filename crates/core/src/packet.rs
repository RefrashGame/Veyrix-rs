//! Разбор IPv4/IPv6 и заголовков TCP/UDP. Ничего не копирует: полезная нагрузка — срез исходного буфера.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

const PROTO_TCP: u8 = 6;
const PROTO_UDP: u8 = 17;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub header_len: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp(TcpHeader),
    Udp(UdpHeader),
    /// Другой протокол или фрагмент IP без транспортного заголовка (номер протокола).
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// TTL (IPv4) или Hop Limit (IPv6).
    pub ttl: u8,
    /// Длина IP-заголовка вместе с расширениями IPv6: здесь начинается транспортный заголовок.
    pub ip_header_len: usize,
    pub transport: Transport,
    /// Смещение полезной нагрузки от начала пакета.
    pub payload_offset: usize,
    pub payload: &'a [u8],
}

impl Packet<'_> {
    pub fn tcp(&self) -> Option<&TcpHeader> {
        match &self.transport {
            Transport::Tcp(t) => Some(t),
            _ => None,
        }
    }
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// Разбирает IP-пакет. `None` — буфер не похож на корректный IPv4/IPv6.
pub fn parse(buf: &[u8]) -> Option<Packet<'_>> {
    let (src, dst, ttl, mut proto, mut off, end, fragment) = match buf.first()? >> 4 {
        4 => {
            let ihl = usize::from(buf[0] & 0x0f) * 4;
            let total = usize::from(be16(buf, 2)?);
            if ihl < 20 || total < ihl || total > buf.len() {
                return None;
            }
            let frag = be16(buf, 6)?;
            let src = Ipv4Addr::from(be32(buf, 12)?);
            let dst = Ipv4Addr::from(be32(buf, 16)?);
            // Транспортный заголовок есть только в первом фрагменте.
            (src.into(), dst.into(), buf[8], buf[9], ihl, total, frag & 0x1fff != 0)
        }
        6 => {
            let end = 40 + usize::from(be16(buf, 4)?);
            if buf.len() < 40 || end > buf.len() {
                return None;
            }
            let src = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).ok()?);
            let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).ok()?);
            (src.into(), dst.into(), buf[7], buf[6], 40, end, false)
        }
        _ => return None,
    };

    let mut fragment = fragment;
    if matches!(src, IpAddr::V6(_)) {
        // Расширения IPv6: hop-by-hop (0), routing (43), destination options (60), fragment (44).
        loop {
            match proto {
                0 | 43 | 60 => {
                    let len = (usize::from(*buf.get(off + 1)?) + 1) * 8;
                    proto = buf[off];
                    off += len;
                }
                44 => {
                    fragment |= be16(buf, off + 2)? & 0xfff8 != 0;
                    proto = *buf.get(off)?;
                    off += 8;
                }
                _ => break,
            }
            if off > end {
                return None;
            }
        }
    }

    let ip_header_len = off;
    let l4 = &buf[off..end];
    let (transport, header_len) = match proto {
        _ if fragment => (Transport::Other(proto), 0),
        PROTO_TCP => {
            let header_len = usize::from(*l4.get(12)? >> 4) * 4;
            if header_len < 20 || header_len > l4.len() {
                return None;
            }
            let tcp = TcpHeader {
                src_port: be16(l4, 0)?,
                dst_port: be16(l4, 2)?,
                seq: be32(l4, 4)?,
                ack: be32(l4, 8)?,
                flags: l4[13],
                header_len,
            };
            (Transport::Tcp(tcp), header_len)
        }
        PROTO_UDP => {
            if l4.len() < 8 {
                return None;
            }
            (Transport::Udp(UdpHeader { src_port: be16(l4, 0)?, dst_port: be16(l4, 2)? }), 8)
        }
        other => (Transport::Other(other), 0),
    };
    let payload_offset = off + header_len;
    Some(Packet { src, dst, ttl, ip_header_len, transport, payload_offset, payload: &buf[payload_offset..end] })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// IPv4-пакет TCP с заданной нагрузкой (контрольные суммы не нужны для разбора).
    pub fn ipv4_tcp(payload: &[u8], dst_port: u16, flags: u8) -> Vec<u8> {
        let total = 20 + 20 + payload.len();
        let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 1, 0x40, 0, 64, PROTO_TCP, 0, 0];
        p.extend([192, 168, 1, 10, 142, 250, 74, 46]);
        p.extend(50000u16.to_be_bytes());
        p.extend(dst_port.to_be_bytes());
        p.extend(1000u32.to_be_bytes());
        p.extend(2000u32.to_be_bytes());
        p.extend([0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend(payload);
        p
    }

    #[test]
    fn ipv4_tcp_is_parsed() {
        let p = ipv4_tcp(b"hello", 443, TCP_PSH | TCP_ACK);
        let pkt = parse(&p).unwrap();
        assert_eq!(pkt.dst, IpAddr::from([142, 250, 74, 46]));
        assert_eq!(pkt.ttl, 64);
        let tcp = pkt.tcp().unwrap();
        assert_eq!((tcp.src_port, tcp.dst_port, tcp.seq, tcp.ack), (50000, 443, 1000, 2000));
        assert_eq!(tcp.flags, TCP_PSH | TCP_ACK);
        assert_eq!(pkt.payload, b"hello");
        assert_eq!(pkt.payload_offset, 40);
    }

    #[test]
    fn ipv4_padding_after_total_length_is_ignored() {
        let mut p = ipv4_tcp(b"abc", 80, TCP_ACK);
        p.extend([0, 0, 0]); // Ethernet-добивка
        assert_eq!(parse(&p).unwrap().payload, b"abc");
    }

    #[test]
    fn non_first_ipv4_fragment_has_no_transport() {
        let mut p = ipv4_tcp(b"data", 443, TCP_ACK);
        p[6] = 0x00;
        p[7] = 0x10; // смещение фрагмента ≠ 0
        assert_eq!(parse(&p).unwrap().transport, Transport::Other(PROTO_TCP));
    }

    #[test]
    fn ipv6_udp_with_hop_by_hop_extension() {
        let payload = b"quic";
        let ext = [PROTO_UDP, 0, 0, 0, 0, 0, 0, 0]; // hop-by-hop, 8 байт
        let udp_len = 8 + payload.len();
        let mut p = vec![0x60, 0, 0, 0];
        p.extend(((ext.len() + udp_len) as u16).to_be_bytes());
        p.extend([0, 55]); // next = hop-by-hop, hop limit 55
        p.extend([0x20, 0x01, 0x0d, 0xb8].iter().chain(&[0u8; 11]).chain(&[1u8]));
        p.extend([0x26, 0x07, 0xf8, 0xb0].iter().chain(&[0u8; 11]).chain(&[2u8]));
        p.extend(ext);
        p.extend(51000u16.to_be_bytes());
        p.extend(443u16.to_be_bytes());
        p.extend((udp_len as u16).to_be_bytes());
        p.extend([0, 0]);
        p.extend(payload);

        let pkt = parse(&p).unwrap();
        assert_eq!(pkt.ttl, 55);
        assert_eq!(pkt.ip_header_len, 48);
        assert_eq!(pkt.transport, Transport::Udp(UdpHeader { src_port: 51000, dst_port: 443 }));
        assert_eq!(pkt.payload, payload);
    }

    #[test]
    fn garbage_is_rejected() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0x45, 0, 0, 10]).is_none());
        let mut p = ipv4_tcp(b"x", 443, TCP_ACK);
        p[32] = 0xf0; // длина TCP-заголовка 60 > остатка пакета
        assert!(parse(&p).is_none());
    }
}
