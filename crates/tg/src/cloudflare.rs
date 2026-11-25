//! Резервный канал TgWsProxy (Flowseal, MIT): если веб-вход Telegram недоступен (блокировка по IP), тот же WebSocket
//! открывается на kws{DC}.<домен> — домены Flowseal за Cloudflare пересылают его в Telegram. Трафик MTProto
//! зашифрован Telegram; посредник видит IP и факт подключения, но не переписку.
//! Список доменов — как в upstream: закодирован сдвигом букв, обновляется из репозитория Flowseal.

use std::collections::HashMap;
use std::sync::Mutex;

pub const LIST_URL: &str = "https://raw.githubusercontent.com/Flowseal/tg-ws-proxy/main/.github/cfproxy-domains.txt";
const MIN_VALID: usize = 3;

// _CFPROXY_ENC из proxy/config.py upstream (Flowseal/tg-ws-proxy, коммит 2085861).
const ENCODED: [&str; 20] = [
    "virkgj.com", "vmmzovy.com", "mkuosckvso.com", "zaewayzmplad.com", "twdmbzcm.com",
    "awzwsldi.com", "clngqrflngqin.com", "tjacxbqtj.com", "bxaxtxmrw.com", "dmohrsgmohcrwb.com",
    "vwbmtmoi.com", "khgrre.com", "ulihssf.com", "tmhqsdqmfpmk.com", "xwuwoqbm.com",
    "orgcnunpj.com", "zhkuldz.com", "zypoljnslxa.com", "efabnxaowuzs.com", "zaftuzsftqdq.com",
];

/// _dd из upstream: у «xxx.com» буквы сдвигаются назад на число букв в имени, «.com» меняется на «.co.uk».
pub fn decode(s: &str) -> String {
    let Some(name) = s.strip_suffix(".com") else { return s.to_string() };
    let shift = name.chars().filter(char::is_ascii_alphabetic).count() as i32;
    let decoded: String = name
        .chars()
        .map(|c| {
            if !c.is_ascii_alphabetic() {
                return c;
            }
            let base = if c.is_ascii_lowercase() { b'a' } else { b'A' } as i32;
            (((c as i32 - base - shift) % 26 + 26) % 26 + base) as u8 as char
        })
        .collect();
    decoded + ".co.uk"
}

fn is_valid_domain(d: &str) -> bool {
    let labels: Vec<&str> = d.split('.').collect();
    !d.is_empty()
        && d.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty() && l.len() <= 63 && !l.starts_with('-') && !l.ends_with('-')
                && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        && labels.last().is_some_and(|t| t.len() >= 2 && t.chars().any(|c| c.is_ascii_alphabetic()))
}

/// Только корректные имена в нижнем регистре, без повторов.
pub fn normalize<I: IntoIterator<Item = String>>(domains: I) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for d in domains {
        let d = d.trim().to_ascii_lowercase();
        if is_valid_domain(&d) && !out.contains(&d) {
            out.push(d);
        }
    }
    out
}

pub fn default_domains() -> Vec<String> {
    normalize(ENCODED.iter().map(|s| decode(s)))
}

/// Строки cfproxy-domains.txt: закодированные домены, # — комментарии. `None` — меньше 3 корректных.
pub fn parse(text: &str) -> Option<Vec<String>> {
    let domains = normalize(text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')).map(decode));
    (domains.len() >= MIN_VALID).then_some(domains)
}

/// Выбор домена для DC (как balancer.py): сначала тот, что сработал последним, затем остальные вперемешку.
pub struct Balancer {
    state: Mutex<(Vec<String>, HashMap<i32, String>)>,
}

impl Default for Balancer {
    fn default() -> Self {
        Self { state: Mutex::new((default_domains(), HashMap::new())) }
    }
}

impl Balancer {
    pub fn domains(&self) -> Vec<String> {
        self.state.lock().map(|s| s.0.clone()).unwrap_or_default()
    }

    pub fn set_domains(&self, domains: Vec<String>) {
        if let Ok(mut s) = self.state.lock() {
            *s = (domains, HashMap::new());
        }
    }

    pub fn domains_for(&self, dc: i32) -> Vec<String> {
        let Ok(s) = self.state.lock() else { return Vec::new() };
        let current = s.1.get(&dc).filter(|d| s.0.contains(d)).cloned();
        let mut rest: Vec<String> = s.0.iter().filter(|d| Some(*d) != current.as_ref()).cloned().collect();
        shuffle(&mut rest);
        current.into_iter().chain(rest).collect()
    }

    pub fn worked(&self, dc: i32, domain: &str) {
        if let Ok(mut s) = self.state.lock() {
            s.1.insert(dc, domain.to_string());
        }
    }
}

fn shuffle(v: &mut [String]) {
    for i in (1..v.len()).rev() {
        let mut r = [0u8; 4];
        crate::crypto::random(&mut r);
        v.swap(i, u32::from_le_bytes(r) as usize % (i + 1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_reference_values() {
        // Сверено с Veyrix на C# (тот же алгоритм _dd).
        assert_eq!(decode("virkgj.com"), "pclead.co.uk");
        assert_eq!(decode("example.org"), "example.org");
        assert_eq!(default_domains().len(), 20);
        assert!(default_domains().iter().all(|d| d.ends_with(".co.uk")));
    }

    #[test]
    fn parse_needs_three_valid() {
        assert!(parse("# комментарий\nvirkgj.com\n").is_none());
        assert_eq!(parse("virkgj.com\nvmmzovy.com\n\nkhgrre.com\nbad domain\n").unwrap().len(), 3);
    }

    #[test]
    fn balancer_prefers_last_working() {
        let b = Balancer::default();
        b.set_domains(vec!["a.co.uk".into(), "b.co.uk".into(), "c.co.uk".into()]);
        b.worked(2, "c.co.uk");
        let list = b.domains_for(2);
        assert_eq!(list[0], "c.co.uk");
        assert_eq!(list.len(), 3);
        assert_eq!(b.domains_for(4).len(), 3);
    }
}
