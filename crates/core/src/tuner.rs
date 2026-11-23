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

/// Столько данных от сервера — соединение точно не заморожено (ТСПУ замораживает после 16–20 КБ).
pub const SUCCESS_BYTES: u64 = 32 * 1024;

/// Разбор потока TLS-записей сервера по заголовкам (тип, версия, длина — открыты даже в зашифрованном TLS):
/// по нему видно, оборвался ли ответ посреди записи.
#[derive(Default)]
struct Records {
    /// Следующий ожидаемый seq; `None` — данных ещё не было.
    next_seq: Option<u32>,
    /// Сколько байт текущей записи ещё не пришло.
    need: usize,
    /// Начало заголовка записи, разрезанного между пакетами.
    header: Vec<u8>,
    /// Пакеты пришли не по порядку — границы записей больше не известны.
    lost: bool,
}

impl Records {
    fn feed(&mut self, seq: u32, mut payload: &[u8]) {
        if self.lost || payload.is_empty() {
            return;
        }
        let expected = *self.next_seq.get_or_insert(seq);
        // Разница seq с учётом переполнения: < 0 — повтор уже виденного, > 0 — пропуск (пакет обогнал предыдущий).
        let diff = seq.wrapping_sub(expected) as i32;
        if diff > 0 {
            self.lost = true;
            return;
        }
        let seen = diff.unsigned_abs() as usize;
        if seen >= payload.len() {
            return;
        }
        payload = &payload[seen..];
        self.next_seq = Some(expected.wrapping_add(payload.len() as u32));
        while !payload.is_empty() {
            if self.need > 0 {
                let take = self.need.min(payload.len());
                self.need -= take;
                payload = &payload[take..];
            } else {
                let take = (5 - self.header.len()).min(payload.len());
                self.header.extend_from_slice(&payload[..take]);
                payload = &payload[take..];
                if self.header.len() == 5 {
                    self.need = usize::from(u16::from_be_bytes([self.header[3], self.header[4]]));
                    self.header.clear();
                }
            }
        }
    }

    /// Ответ оборвался посреди записи (известно только при пакетах по порядку).
    fn incomplete(&self) -> bool {
        !self.lost && (self.need > 0 || !self.header.is_empty())
    }
}

struct Pending {
    site: String,
    strategy: usize,
    client_ms: u64,
    server_ms: Option<u64>,
    server_bytes: u64,
    records: Records,
}

impl Pending {
    /// Клиент ждёт: последним говорил он, а сервер ещё не ответил.
    fn client_waiting(&self) -> bool {
        self.server_ms.is_none_or(|s| self.client_ms > s)
    }
}

/// Соединения с приёмом, по которым ещё не ясно, открылся ли сайт.
///
/// Успех: от сервера ≥ `SUCCESS_BYTES`; закрытие сервером (FIN) на границе записи; тишина при законченном
/// обмене (все записи целы, клиент не ждёт). Неудача: RST до `SUCCESS_BYTES`; FIN посреди записи; тишина,
/// когда клиент ждёт ответа или запись оборвалась на середине — «замирание».
#[derive(Default)]
pub struct Tracker {
    pending: HashMap<Flow, Pending>,
}

/// Итог по соединению: сайт, номер приёма, успех.
pub type Verdict = (String, usize, bool);

impl Tracker {
    /// Отправлен ClientHello с приёмом. Повтор (TCP перепослал) ничего не меняет.
    pub fn sent(&mut self, flow: Flow, site: String, strategy: usize, now_ms: u64) {
        self.pending.entry(flow).or_insert(Pending {
            site,
            strategy,
            client_ms: now_ms,
            server_ms: None,
            server_bytes: 0,
            records: Records::default(),
        });
    }

    /// Клиент отправил данные по отслеживаемому соединению.
    pub fn client_data(&mut self, flow: Flow, now_ms: u64) {
        if let Some(p) = self.pending.get_mut(&flow) {
            p.client_ms = now_ms;
        }
    }

    /// Пакет сервера (`flow` — в направлении клиент → сервер). Возвращает итог, если он стал ясен.
    pub fn server_packet(&mut self, flow: Flow, seq: u32, payload: &[u8], rst: bool, fin: bool, now_ms: u64) -> Option<Verdict> {
        let p = self.pending.get_mut(&flow)?;
        if !payload.is_empty() {
            p.server_ms = Some(now_ms);
            p.server_bytes += payload.len() as u64;
            p.records.feed(seq, payload);
        }
        let ok = match () {
            _ if p.server_bytes >= SUCCESS_BYTES => true,
            _ if rst => false,
            _ if fin => p.server_bytes > 0 && !p.records.incomplete(),
            _ => return None,
        };
        let p = self.pending.remove(&flow)?;
        Some((p.site, p.strategy, ok))
    }

    /// Соединения, где `timeout_ms` ничего не происходит: неудача, если ответ ждут или он оборван, иначе успех.
    pub fn expired(&mut self, now_ms: u64, timeout_ms: u64) -> Vec<Verdict> {
        let mut out = Vec::new();
        self.pending.retain(|_, p| {
            let last = p.client_ms.max(p.server_ms.unwrap_or(0));
            if now_ms.saturating_sub(last) < timeout_ms {
                return true;
            }
            let stalled = p.client_waiting() || p.records.incomplete();
            out.push((p.site.clone(), p.strategy, !stalled));
            false
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

    fn flow(port: u16) -> Flow {
        ("192.168.1.10".parse().unwrap(), port, "1.2.3.4".parse().unwrap(), 443)
    }

    /// TLS-запись заданной длины тела (заголовок 23 03 03 + длина).
    fn record(len: usize) -> Vec<u8> {
        let mut r = vec![0x17, 0x03, 0x03, (len >> 8) as u8, len as u8];
        r.resize(5 + len, 0xaa);
        r
    }

    #[test]
    fn no_answer_is_a_failure() {
        let mut tr = Tracker::default();
        tr.sent(flow(1), "a.com".into(), 0, 1000);
        tr.sent(flow(1), "a.com".into(), 0, 2500); // повтор ClientHello не продлевает ожидание
        assert!(tr.expired(5999, 5000).is_empty());
        assert_eq!(tr.expired(6000, 5000), vec![("a.com".into(), 0, false)]);
        assert!(tr.is_empty());
    }

    #[test]
    fn freeze_in_the_middle_of_a_record_is_a_failure() {
        // Как ТСПУ: сервер начал большую запись (16 КБ), прислал 8 КБ — и тишина. Клиент ничего не ждёт сам.
        let mut tr = Tracker::default();
        tr.sent(flow(1), "youtube.com".into(), 0, 0);
        let rec = record(16_000);
        assert_eq!(tr.server_packet(flow(1), 100, &rec[..8_000], false, false, 100), None);
        assert_eq!(tr.expired(5_099, 5_000), vec![]);
        assert_eq!(tr.expired(5_100, 5_000), vec![("youtube.com".into(), 0, false)]);
    }

    #[test]
    fn small_complete_exchange_then_silence_is_a_success() {
        // Короткий ответ целыми записями, потом соединение просто простаивает (keep-alive).
        let mut tr = Tracker::default();
        tr.sent(flow(1), "a.com".into(), 2, 0);
        let mut data = record(90);
        data.extend(record(1_200));
        tr.server_packet(flow(1), 1, &data[..700], false, false, 50);
        tr.server_packet(flow(1), 701, &data[700..], false, false, 60);
        assert_eq!(tr.expired(6_000, 5_000), vec![("a.com".into(), 2, true)]);
    }

    #[test]
    fn client_waiting_without_answer_is_a_failure() {
        let mut tr = Tracker::default();
        tr.sent(flow(1), "a.com".into(), 0, 0);
        tr.server_packet(flow(1), 1, &record(100), false, false, 10);
        tr.client_data(flow(1), 20); // запрос после ответа на рукопожатие
        assert_eq!(tr.expired(5_020, 5_000), vec![("a.com".into(), 0, false)]);
    }

    #[test]
    fn rst_bytes_and_fin_decide_immediately() {
        let mut tr = Tracker::default();
        tr.sent(flow(1), "rst.com".into(), 0, 0);
        assert_eq!(tr.server_packet(flow(1), 1, &[], true, false, 5), Some(("rst.com".into(), 0, false)));

        tr.sent(flow(2), "big.com".into(), 1, 0);
        let big = record(40_000);
        assert_eq!(tr.server_packet(flow(2), 1, &big[..20_000], false, false, 5), None);
        assert_eq!(tr.server_packet(flow(2), 20_001, &big[20_000..], false, false, 6), Some(("big.com".into(), 1, true)));
        assert_eq!(tr.server_packet(flow(2), 1, &[], true, false, 7), None); // RST после решения не считается

        tr.sent(flow(3), "fin.com".into(), 0, 0);
        assert_eq!(tr.server_packet(flow(3), 1, &record(10), false, true, 5), Some(("fin.com".into(), 0, true)));
        tr.sent(flow(4), "cut.com".into(), 0, 0);
        assert_eq!(tr.server_packet(flow(4), 1, &record(1000)[..300], false, true, 5), Some(("cut.com".into(), 0, false)));
        assert!(tr.is_empty());
    }

    #[test]
    fn out_of_order_and_retransmits() {
        let mut r = Records::default();
        let rec = record(100);
        r.feed(1000, &rec[..50]);
        r.feed(1000, &rec[..50]); // повтор
        r.feed(1030, &rec[30..80]); // повтор с перекрытием — берётся только новое
        r.feed(1080, &rec[80..]);
        assert!(!r.incomplete());

        let mut gap = Records::default();
        gap.feed(1000, &rec[..10]);
        gap.feed(1050, &rec[50..]); // пропуск — границы записей потеряны, обрыв больше не утверждаем
        assert!(!gap.incomplete());
    }

    #[test]
    fn presets_are_distinct() {
        let p = presets();
        for (i, a) in p.iter().enumerate() {
            assert!(p[i + 1..].iter().all(|b| a.1 != b.1 && a.0 != b.0), "повтор: {}", a.0);
        }
    }
}
