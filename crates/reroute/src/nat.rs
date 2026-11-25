//! Подмена адресов в пакетах (IPv4 + TCP) и таблица соединений режима «другой адрес Cloudflare».
//! Контрольные суммы после правки пересчитывает WinDivert (`calc_checksums`).

use std::collections::HashMap;
use std::net::Ipv4Addr;

/// Поля IPv4/TCP, которые меняет перенаправление. `None` — не IPv4+TCP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcp4 {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    ihl: usize,
}

impl Tcp4 {
    pub fn read(p: &[u8]) -> Option<Self> {
        if p.len() < 40 || p[0] >> 4 != 4 || p[9] != 6 {
            return None;
        }
        let ihl = usize::from(p[0] & 0x0f) * 4;
        if ihl < 20 || p.len() < ihl + 20 || u16::from_be_bytes([p[6], p[7]]) & 0x1fff != 0 {
            return None;
        }
        let ip = |at: usize| Ipv4Addr::new(p[at], p[at + 1], p[at + 2], p[at + 3]);
        let port = |at: usize| u16::from_be_bytes([p[at], p[at + 1]]);
        Some(Self { src: ip(12), dst: ip(16), src_port: port(ihl), dst_port: port(ihl + 2), flags: p[ihl + 13], ihl })
    }

    /// Записывает адреса и порты обратно в пакет.
    pub fn write(&self, p: &mut [u8]) {
        p[12..16].copy_from_slice(&self.src.octets());
        p[16..20].copy_from_slice(&self.dst.octets());
        p[self.ihl..self.ihl + 2].copy_from_slice(&self.src_port.to_be_bytes());
        p[self.ihl + 2..self.ihl + 4].copy_from_slice(&self.dst_port.to_be_bytes());
    }

    pub fn syn_only(&self) -> bool {
        self.flags & 0x12 == 0x02
    }
    pub fn syn_ack(&self) -> bool {
        self.flags & 0x12 == 0x12
    }
    pub fn rst(&self) -> bool {
        self.flags & 0x04 != 0
    }
    pub fn fin(&self) -> bool {
        self.flags & 0x01 != 0
    }
}

struct Flow {
    original: Ipv4Addr,
    replacement: Ipv4Addr,
    syn_ms: u64,
    answered: bool,
    last_ms: u64,
}

/// Соединения, у которых адрес сервера подменён: исходящие идут на замену, входящие возвращаются с исходным адресом —
/// программа (браузер, Discord) подмены не замечает.
#[derive(Default)]
pub struct Nat {
    /// Порт клиента → соединение (порт уникален для соединений одного компьютера).
    flows: HashMap<u16, Flow>,
}

const FLOW_IDLE_MS: u64 = 10 * 60 * 1000;
const FLOW_LIMIT: usize = 8192;

impl Nat {
    /// Исходящий пакет к `original`: куда его отправить на самом деле.
    pub fn outbound(&mut self, client_port: u16, original: Ipv4Addr, replacement: Ipv4Addr, syn: bool, now_ms: u64) -> Ipv4Addr {
        if self.flows.len() >= FLOW_LIMIT {
            self.flows.retain(|_, f| now_ms.saturating_sub(f.last_ms) < FLOW_IDLE_MS);
        }
        let flow = self.flows.entry(client_port).or_insert(Flow { original, replacement, syn_ms: now_ms, answered: false, last_ms: now_ms });
        if syn && flow.original != original {
            // Порт переиспользован для нового соединения.
            *flow = Flow { original, replacement, syn_ms: now_ms, answered: false, last_ms: now_ms };
        }
        flow.last_ms = now_ms;
        flow.replacement
    }

    /// Входящий пакет от `from`: исходный адрес, если это ответ по подменённому соединению.
    pub fn inbound(&mut self, client_port: u16, from: Ipv4Addr, syn_ack: bool, now_ms: u64) -> Option<Ipv4Addr> {
        let flow = self.flows.get_mut(&client_port).filter(|f| f.replacement == from)?;
        flow.answered |= syn_ack;
        flow.last_ms = now_ms;
        Some(flow.original)
    }

    /// Замены, которые не ответили на SYN дольше `timeout_ms`: их больше не использовать.
    pub fn dead_replacements(&mut self, now_ms: u64, timeout_ms: u64) -> Vec<Ipv4Addr> {
        let mut out = Vec::new();
        for f in self.flows.values_mut() {
            if !f.answered && now_ms.saturating_sub(f.syn_ms) >= timeout_ms {
                if !out.contains(&f.replacement) {
                    out.push(f.replacement);
                }
                f.answered = true; // сообщить один раз
            }
        }
        out
    }

    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: Ipv4Addr = Ipv4Addr::new(162, 159, 134, 232);
    const A: Ipv4Addr = Ipv4Addr::new(162, 159, 135, 232);

    fn packet(src: [u8; 4], dst: [u8; 4], sport: u16, dport: u16, flags: u8) -> Vec<u8> {
        let mut p = vec![0x45, 0, 0, 40, 0, 1, 0x40, 0, 64, 6, 0, 0];
        p.extend(src);
        p.extend(dst);
        p.extend(sport.to_be_bytes());
        p.extend(dport.to_be_bytes());
        p.extend([0, 0, 0, 1, 0, 0, 0, 0, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
        p
    }

    #[test]
    fn read_and_rewrite() {
        let mut p = packet([192, 168, 1, 5], S.octets(), 50000, 443, 0x02);
        let mut t = Tcp4::read(&p).unwrap();
        assert!(t.syn_only() && !t.syn_ack());
        assert_eq!((t.dst, t.dst_port), (S, 443));
        t.dst = A;
        t.dst_port = 8443;
        t.write(&mut p);
        let back = Tcp4::read(&p).unwrap();
        assert_eq!((back.src, back.dst, back.src_port, back.dst_port), (Ipv4Addr::new(192, 168, 1, 5), A, 50000, 8443));
        assert!(Tcp4::read(&p[..30]).is_none());
    }

    #[test]
    fn replies_come_back_with_the_original_address() {
        let mut nat = Nat::default();
        assert_eq!(nat.outbound(50000, S, A, true, 0), A);
        assert_eq!(nat.inbound(50000, A, true, 10), Some(S));
        assert_eq!(nat.inbound(50001, A, false, 10), None, "чужое соединение с тем же адресом не трогаем");
        assert!(nat.dead_replacements(5000, 2000).is_empty());
    }

    #[test]
    fn silent_replacement_is_reported_once() {
        let mut nat = Nat::default();
        nat.outbound(50000, S, A, true, 0);
        assert!(nat.dead_replacements(1000, 2000).is_empty());
        assert_eq!(nat.dead_replacements(2000, 2000), vec![A]);
        assert!(nat.dead_replacements(3000, 2000).is_empty());
    }
}
