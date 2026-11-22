//! Автоподбор и самовосстановление: для каждого сайта — свой приём; две неудачи подряд — следующий из списка.
//!
//! Успех соединения — TLS ServerHello от сервера; неудача — RST до ServerHello или тишина дольше тайм-аута.
//! Чистая логика без часов и сети: время передаётся в миллисекундах, чтобы всё проверялось тестами.

use std::collections::HashMap;
use std::net::IpAddr;

use crate::desync::{Fooling, SplitPos, Strategy};

/// Неудач подряд до смены приёма: одна — бывает и без DPI (сайт моргнул).
const FAILS_TO_SWITCH: u8 = 2;

/// Приёмы, которые перебирает автоподбор, по порядку. Первый — проверенный у владельца вариант по умолчанию.
pub fn presets() -> Vec<(&'static str, Strategy)> {
    let base = Strategy::default();
    vec![
        ("фейк badseq + перестановка", base.clone()),
        ("фейк TTL 4", Strategy { fooling: vec![Fooling::Ttl(4)], ..base.clone() }),
        ("фейк badsum, разрез по имени", Strategy { fooling: vec![Fooling::BadSum], split: vec![SplitPos::Host], ..base.clone() }),
        ("фейк ×11, три разреза", Strategy {
            fooling: vec![Fooling::BadSeq, Fooling::BadSum],
            repeats: 11,
            split: vec![SplitPos::At(1), SplitPos::Host, SplitPos::MidSld],
            ..base.clone()
        }),
        ("только разрезание", Strategy { fake: false, ..base }),
    ]
}

/// «Без приёмов» — для проверки самовосстановления: заблокированный сайт должен сам перейти на рабочий приём.
pub fn passthrough() -> Strategy {
    Strategy { fake: false, split: vec![], disorder: false, ..Strategy::default() }
}

/// Ключ сайта: домен второго уровня («rr1---sn-x.googlevideo.com» → «googlevideo.com»), чтобы поддомены учились вместе.
/// Для зон вида co.uk / com.ru — три метки.
pub fn site_key(host: &str) -> String {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    let take = match labels.as_slice() {
        [.., sld, tld] if tld.len() == 2 && ["co", "com", "net", "org", "gov", "ac"].contains(sld) => 3,
        _ => 2,
    };
    labels[labels.len().saturating_sub(take)..].join(".").to_ascii_lowercase()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Сайт заработал на этом приёме (сообщается один раз).
    Works { site: String, strategy: usize },
    /// Приём не сработал дважды — сайт переведён на следующий.
    Switched { site: String, from: usize, to: usize },
}

#[derive(Debug, Default)]
pub struct Tuner {
    count: usize,
    /// С какого приёма начинать новые сайты.
    start: usize,
    choice: HashMap<String, usize>,
    fails: HashMap<String, u8>,
    confirmed: HashMap<String, bool>,
}

impl Tuner {
    pub fn new(count: usize, start: usize) -> Self {
        Self { count, start, ..Self::default() }
    }

    pub fn choice(&self, site: &str) -> usize {
        self.choice.get(site).copied().unwrap_or(self.start)
    }

    /// Результат соединения, сделанного приёмом `strategy`. Результаты старых приёмов (сайт уже переключён) не считаются.
    pub fn report(&mut self, site: &str, strategy: usize, ok: bool) -> Option<Event> {
        let current = self.choice(site);
        if strategy != current {
            return None;
        }
        if ok {
            self.fails.remove(site);
            let first = !self.confirmed.insert(site.to_string(), true).unwrap_or(false);
            return first.then(|| Event::Works { site: site.to_string(), strategy });
        }
        let fails = self.fails.entry(site.to_string()).or_default();
        *fails += 1;
        if *fails < FAILS_TO_SWITCH {
            return None;
        }
        self.fails.remove(site);
        self.confirmed.remove(site);
        let to = (current + 1) % self.count.max(1);
        self.choice.insert(site.to_string(), to);
        Some(Event::Switched { site: site.to_string(), from: current, to })
    }

    /// Строки «сайт<TAB>название приёма» для файла; сохраняются только подтверждённые приёмы.
    pub fn save(&self, names: &[&str]) -> String {
        let mut lines: Vec<String> = self
            .confirmed
            .keys()
            .filter_map(|site| Some(format!("{site}\t{}", names.get(self.choice(site))?)))
            .collect();
        lines.sort();
        lines.join("\n") + "\n"
    }

    /// Загружает сохранённое; незнакомые названия приёмов (после обновления списка) пропускаются.
    pub fn load(&mut self, text: &str, names: &[&str]) {
        for (site, name) in text.lines().filter_map(|l| l.split_once('\t')) {
            if let Some(i) = names.iter().position(|n| *n == name.trim()) {
                self.choice.insert(site.trim().to_string(), i);
                self.confirmed.insert(site.trim().to_string(), true);
            }
        }
    }
}

/// Соединение: (адрес и порт клиента, адрес и порт сервера).
pub type Flow = (IpAddr, u16, IpAddr, u16);

struct Pending {
    site: String,
    strategy: usize,
    sent_ms: u64,
}

/// Ожидающие ответа соединения, к которым применён приём.
#[derive(Default)]
pub struct Tracker {
    pending: HashMap<Flow, Pending>,
}

impl Tracker {
    /// Отправлен ClientHello. Повтор (TCP перепослал) не сбрасывает время первого.
    pub fn sent(&mut self, flow: Flow, site: String, strategy: usize, now_ms: u64) {
        self.pending.entry(flow).or_insert(Pending { site, strategy, sent_ms: now_ms });
    }

    /// Ответ сервера: `ok` — ServerHello, иначе RST. `flow` — в направлении клиент → сервер.
    pub fn answered(&mut self, flow: Flow, ok: bool) -> Option<(String, usize, bool)> {
        self.pending.remove(&flow).map(|p| (p.site, p.strategy, ok))
    }

    /// Соединения без ответа дольше `timeout_ms` — неудачи.
    pub fn expired(&mut self, now_ms: u64, timeout_ms: u64) -> Vec<(String, usize)> {
        let mut out = Vec::new();
        self.pending.retain(|_, p| {
            let alive = now_ms.saturating_sub(p.sent_ms) < timeout_ms;
            if !alive {
                out.push((p.site.clone(), p.strategy));
            }
            alive
        });
        out
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn site_keys() {
        assert_eq!(site_key("rr1---sn-4g5e6nzs.googlevideo.com"), "googlevideo.com");
        assert_eq!(site_key("WWW.YouTube.com."), "youtube.com");
        assert_eq!(site_key("bbc.co.uk"), "bbc.co.uk");
        assert_eq!(site_key("news.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(site_key("localhost"), "localhost");
    }

    #[test]
    fn two_failures_switch_and_success_is_reported_once() {
        let mut t = Tuner::new(3, 0);
        assert_eq!(t.report("discord.com", 0, false), None); // одна неудача — ещё не повод
        assert_eq!(t.report("discord.com", 0, false), Some(Event::Switched { site: "discord.com".into(), from: 0, to: 1 }));
        assert_eq!(t.choice("discord.com"), 1);
        assert_eq!(t.report("discord.com", 0, false), None); // запоздалый результат старого приёма
        assert_eq!(t.report("discord.com", 1, true), Some(Event::Works { site: "discord.com".into(), strategy: 1 }));
        assert_eq!(t.report("discord.com", 1, true), None);
        assert_eq!(t.choice("youtube.com"), 0); // другие сайты не задеты
    }

    #[test]
    fn success_resets_failure_streak_and_list_wraps() {
        let mut t = Tuner::new(2, 1);
        t.report("a.com", 1, false);
        t.report("a.com", 1, true);
        assert_eq!(t.report("a.com", 1, false), None); // серия начата заново
        assert!(matches!(t.report("a.com", 1, false), Some(Event::Switched { to: 0, .. }))); // по кругу
    }

    #[test]
    fn save_and_load_keep_only_confirmed_sites() {
        let names = ["первый", "второй"];
        let mut t = Tuner::new(2, 0);
        t.report("a.com", 0, false);
        t.report("a.com", 0, false);
        t.report("a.com", 1, true);
        t.report("b.com", 0, false); // не подтверждён — не сохраняется
        let text = t.save(&names);
        assert_eq!(text, "a.com\tвторой\n");

        let mut loaded = Tuner::new(2, 0);
        loaded.load(&format!("{text}x.com\tудалённый приём\n"), &names);
        assert_eq!(loaded.choice("a.com"), 1);
        assert_eq!(loaded.choice("x.com"), 0);
    }

    #[test]
    fn tracker_answers_and_timeouts() {
        let flow = |port| -> Flow { ("192.168.1.10".parse().unwrap(), port, "1.2.3.4".parse().unwrap(), 443) };
        let mut tr = Tracker::default();
        tr.sent(flow(1), "a.com".into(), 0, 1000);
        tr.sent(flow(1), "a.com".into(), 0, 2500); // повтор ClientHello не продлевает ожидание
        tr.sent(flow(2), "b.com".into(), 3, 1000);
        assert_eq!(tr.answered(flow(2), true), Some(("b.com".into(), 3, true)));
        assert_eq!(tr.answered(flow(2), true), None);
        assert!(tr.expired(5999, 5000).is_empty());
        assert_eq!(tr.expired(6000, 5000), vec![("a.com".into(), 0)]);
        assert!(tr.is_empty());
    }

    #[test]
    fn presets_are_distinct() {
        let p = presets();
        for (i, a) in p.iter().enumerate() {
            assert!(p[i + 1..].iter().all(|b| a.1 != b.1 && a.0 != b.0), "повтор: {}", a.0);
        }
    }
}
