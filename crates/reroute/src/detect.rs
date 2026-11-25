//! Обнаружение блокировки по IP: на SYN к порту 443 нет SYN-ACK дольше тайм-аута (пакеты до сервера не доходят).
//! RST от сервера — не блокировка (порт закрыт или сервер отказал). Заодно запоминаются адреса, которые отвечают:
//! из них берётся замена для режима «другой адрес Cloudflare».
//! Чистая логика: время — миллисекунды от вызывающего.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use crate::ranges::{common_prefix, is_cloudflare};

/// Сколько ждать SYN-ACK. Windows повторяет SYN примерно через 1 и 3 с — к повтору перенаправление уже готово.
pub const SYN_TIMEOUT_MS: u64 = 2000;
const PENDING_LIMIT: usize = 4096;
const GOOD_LIMIT: usize = 512;

#[derive(Default)]
pub struct SynWatch {
    /// (порт клиента, адрес сервера) → время первого SYN.
    pending: HashMap<(u16, Ipv4Addr), u64>,
    /// Адреса, ответившие SYN-ACK, → время последнего ответа.
    good: HashMap<Ipv4Addr, u64>,
}

impl SynWatch {
    /// Клиент отправил SYN. Повтор SYN не сдвигает время первого.
    pub fn syn(&mut self, client_port: u16, server: Ipv4Addr, now_ms: u64) {
        if self.pending.len() < PENDING_LIMIT {
            self.pending.entry((client_port, server)).or_insert(now_ms);
        }
    }

    /// Сервер ответил SYN-ACK.
    pub fn syn_ack(&mut self, client_port: u16, server: Ipv4Addr, now_ms: u64) {
        self.pending.remove(&(client_port, server));
        if self.good.len() >= GOOD_LIMIT
            && let Some(oldest) = self.good.iter().min_by_key(|(_, t)| **t).map(|(ip, _)| *ip)
        {
            self.good.remove(&oldest);
        }
        self.good.insert(server, now_ms);
    }

    /// Сервер ответил RST: он доступен, просто отказал.
    pub fn reset(&mut self, client_port: u16, server: Ipv4Addr) {
        self.pending.remove(&(client_port, server));
    }

    /// Адреса, где SYN остался без ответа дольше `SYN_TIMEOUT_MS`; без повторов.
    pub fn expired(&mut self, now_ms: u64) -> Vec<Ipv4Addr> {
        let mut out = Vec::new();
        self.pending.retain(|&(_, ip), &mut t| {
            if now_ms.saturating_sub(t) < SYN_TIMEOUT_MS {
                return true;
            }
            if !out.contains(&ip) {
                out.push(ip);
            }
            false
        });
        out
    }

    /// Ответивший адрес Cloudflare, ближайший к `blocked` (та же подсеть — скорее всего, та же служба сайта),
    /// кроме `exclude`.
    pub fn nearest_good(&self, blocked: Ipv4Addr, exclude: impl Fn(Ipv4Addr) -> bool) -> Option<Ipv4Addr> {
        self.good
            .keys()
            .copied()
            .filter(|&ip| ip != blocked && is_cloudflare(ip) && !exclude(ip))
            .max_by_key(|&ip| (common_prefix(ip, blocked), self.good[&ip]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BLOCKED: Ipv4Addr = Ipv4Addr::new(162, 159, 134, 232);
    const OK: Ipv4Addr = Ipv4Addr::new(162, 159, 135, 232);

    #[test]
    fn unanswered_syn_means_blocked() {
        let mut w = SynWatch::default();
        w.syn(50000, BLOCKED, 0);
        w.syn(50000, BLOCKED, 1000); // повтор SYN
        w.syn(50001, OK, 0);
        w.syn_ack(50001, OK, 50);
        assert!(w.expired(1500).is_empty());
        assert_eq!(w.expired(2000), vec![BLOCKED]);
        assert!(w.expired(9000).is_empty(), "итог — один раз");
    }

    #[test]
    fn reset_is_not_a_block() {
        let mut w = SynWatch::default();
        w.syn(50000, BLOCKED, 0);
        w.reset(50000, BLOCKED);
        assert!(w.expired(5000).is_empty());
    }

    #[test]
    fn replacement_is_the_closest_answering_cloudflare_address() {
        let mut w = SynWatch::default();
        w.syn_ack(1, Ipv4Addr::new(104, 16, 132, 229), 0);
        w.syn_ack(2, OK, 0);
        w.syn_ack(3, Ipv4Addr::new(142, 251, 152, 4), 0); // Google — не Cloudflare
        assert_eq!(w.nearest_good(BLOCKED, |_| false), Some(OK));
        assert_eq!(w.nearest_good(BLOCKED, |ip| ip == OK), Some(Ipv4Addr::new(104, 16, 132, 229)));
    }
}
