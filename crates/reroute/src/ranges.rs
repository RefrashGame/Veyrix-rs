//! Адреса Cloudflare (IPv4): сайт за Cloudflare отвечает на любом адресе этой сети — выбор по имени в TLS (SNI).
//! Список — https://www.cloudflare.com/ips-v4 (2026-11).

use std::net::Ipv4Addr;

const CLOUDFLARE: [(u32, u8); 15] = [
    (u32::from_be_bytes([173, 245, 48, 0]), 20),
    (u32::from_be_bytes([103, 21, 244, 0]), 22),
    (u32::from_be_bytes([103, 22, 200, 0]), 22),
    (u32::from_be_bytes([103, 31, 4, 0]), 22),
    (u32::from_be_bytes([141, 101, 64, 0]), 18),
    (u32::from_be_bytes([108, 162, 192, 0]), 18),
    (u32::from_be_bytes([190, 93, 240, 0]), 20),
    (u32::from_be_bytes([188, 114, 96, 0]), 20),
    (u32::from_be_bytes([197, 234, 240, 0]), 22),
    (u32::from_be_bytes([198, 41, 128, 0]), 17),
    (u32::from_be_bytes([162, 158, 0, 0]), 15),
    (u32::from_be_bytes([104, 16, 0, 0]), 13),
    (u32::from_be_bytes([104, 24, 0, 0]), 14),
    (u32::from_be_bytes([172, 64, 0, 0]), 13),
    (u32::from_be_bytes([131, 0, 72, 0]), 22),
];

pub fn is_cloudflare(ip: Ipv4Addr) -> bool {
    let ip = u32::from(ip);
    CLOUDFLARE.iter().any(|&(net, bits)| ip >> (32 - bits) == net >> (32 - bits))
}

/// Запасные адреса Cloudflare, если рабочих ещё не встречалось: адреса discord.com, проверенные на Билайне
/// (2026-11-25, Калининград), и общие адреса сети 104.16.0.0/13.
pub const SEEDS: [Ipv4Addr; 7] = [
    Ipv4Addr::new(162, 159, 135, 232),
    Ipv4Addr::new(162, 159, 136, 232),
    Ipv4Addr::new(162, 159, 137, 232),
    Ipv4Addr::new(162, 159, 138, 232),
    Ipv4Addr::new(162, 159, 128, 233),
    Ipv4Addr::new(104, 16, 132, 229),
    Ipv4Addr::new(104, 16, 133, 229),
];

/// Сколько старших бит совпадает: замена берётся как можно ближе к заблокированному адресу (та же подсеть сайта).
pub fn common_prefix(a: Ipv4Addr, b: Ipv4Addr) -> u32 {
    (u32::from(a) ^ u32::from(b)).leading_zeros()
}

/// Адрес из интернета: локальные, частные и служебные адреса не «блокируются», их не трогаем.
pub fn is_public(ip: Ipv4Addr) -> bool {
    !(ip.is_private() || ip.is_loopback() || ip.is_link_local() || ip.is_broadcast() || ip.is_multicast()
        || ip.is_unspecified() || ip.octets()[0] == 100 && ip.octets()[1] & 0xc0 == 64 // CGNAT 100.64.0.0/10
        || ip.octets()[0] == 198 && ip.octets()[1] & 0xfe == 18) // тестовая сеть и fake-ip VPN 198.18.0.0/15
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cloudflare_ranges() {
        assert!(is_cloudflare(Ipv4Addr::new(162, 159, 134, 232))); // media.discordapp.net
        assert!(is_cloudflare(Ipv4Addr::new(104, 23, 255, 255)));
        assert!(!is_cloudflare(Ipv4Addr::new(142, 251, 152, 4))); // youtube.com — Google
        assert!(SEEDS.iter().all(|&ip| is_cloudflare(ip)));
    }

    #[test]
    fn public_addresses() {
        assert!(is_public(Ipv4Addr::new(162, 159, 134, 232)));
        assert!(!is_public(Ipv4Addr::new(192, 168, 1, 5)));
        assert!(!is_public(Ipv4Addr::new(198, 18, 0, 51)));
        assert!(!is_public(Ipv4Addr::new(100, 72, 1, 1)));
    }

    #[test]
    fn prefix() {
        let a = Ipv4Addr::new(162, 159, 134, 232);
        assert!(common_prefix(a, Ipv4Addr::new(162, 159, 135, 232)) > common_prefix(a, Ipv4Addr::new(104, 16, 132, 229)));
    }
}
