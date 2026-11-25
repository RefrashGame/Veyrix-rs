//! Движок Veyrix-rs: перехват первых пакетов и приёмы обхода, DNS через DoH, автоподбор приёмов по сайтам.
//! Работает в окне (Tauri): события уходят в обработчик, счётчики — через `stats()`.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use vx_core::desync::corrupt_tcp_checksum;
use vx_core::dns;
use vx_core::packet::{TCP_FIN, TCP_RST};
use vx_core::tuner::{Tracker, Tuner, passthrough, presets, site_key};
use vx_core::{Action, Proto, QuicMode, Strategy, Transport, apply, classify, parse};
use vx_divert::{Divert, FLAG_SNIFF};
use vx_doh::Doh;

pub use vx_core;

#[derive(Debug, Clone)]
pub struct Config {
    /// Папка с WinDivert.dll и WinDivert64.sys.
    pub engine_dir: PathBuf,
    /// Папка данных: здесь `tuning.txt` автоподбора.
    pub data_dir: PathBuf,
    /// Приёмы без автоподбора; QUIC и голос Discord берутся отсюда и при автоподборе.
    pub strategy: Strategy,
    pub auto: bool,
    /// Автоподбор с чистого листа: все сайты начинают «без приёмов», сохранённый выбор не читается.
    pub auto_test: bool,
    /// DoH-сервер: cloudflare, google, quad9 или https://…; `None` — обычный DNS.
    pub doh: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Первое соединение с этим сайтом и сервером, к которому применён приём.
    Site { kind: &'static str, host: String, target: String },
    /// Автоподбор: сайт работает с этим приёмом.
    Works { site: String, strategy: String },
    /// Автоподбор: приём перестал работать, сайт переведён на следующий.
    Switched { site: String, from: String, to: String },
    /// Не отправлен пакет и т. п. — обход продолжается.
    Warning(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub changed: u64,
    pub passed: u64,
    pub dropped: u64,
    pub send_errors: u64,
    pub doh_ok: u64,
    pub doh_fallback: u64,
}

#[derive(Default)]
struct Counters {
    changed: AtomicU64,
    passed: AtomicU64,
    dropped: AtomicU64,
    send_errors: AtomicU64,
    doh_ok: AtomicU64,
    doh_fallback: AtomicU64,
}

pub type Sink = Arc<dyn Fn(Event) + Send + Sync>;

/// Активность сайта (ключ — домен 2-го уровня) для карты в окне.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiteStat {
    pub site: String,
    /// Соединений, первый пакет которых прошёл через обход (TLS/HTTP с именем сайта).
    pub connections: u64,
    /// DNS-запросов, на которые ответил DoH.
    pub dns: u64,
    /// Сколько мс назад было последнее соединение или DNS-запрос.
    pub idle_ms: u64,
    /// Приём последнего соединения из автоподбора; `None` — приём из настроек.
    pub strategy: Option<&'static str>,
}

/// Сколько сайтов помнить: при переполнении забывается самый давний.
const SITES_LIMIT: usize = 256;

#[derive(Default)]
struct SiteEntry {
    connections: u64,
    dns: u64,
    last_ms: u64,
    strategy: Option<&'static str>,
}

struct Sites {
    started: Instant,
    map: Mutex<HashMap<String, SiteEntry>>,
}

impl Sites {
    fn new() -> Self {
        Self { started: Instant::now(), map: Mutex::new(HashMap::new()) }
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn note(&self, host: &str, update: impl FnOnce(&mut SiteEntry)) {
        // Служебные имена (обратные запросы, имена без точки) — не сайты.
        if !host.contains('.') || host.ends_with(".arpa") || host.ends_with(".local") {
            return;
        }
        let site = site_key(host);
        let now = self.now_ms();
        let Ok(mut map) = self.map.lock() else { return };
        if !map.contains_key(&site)
            && map.len() >= SITES_LIMIT
            && let Some(oldest) = map.iter().min_by_key(|(_, e)| e.last_ms).map(|(k, _)| k.clone())
        {
            map.remove(&oldest);
        }
        let entry = map.entry(site).or_default();
        entry.last_ms = now;
        update(entry);
    }

    fn list(&self) -> Vec<SiteStat> {
        let now = self.now_ms();
        let Ok(map) = self.map.lock() else { return Vec::new() };
        map.iter()
            .map(|(site, e)| SiteStat {
                site: site.clone(),
                connections: e.connections,
                dns: e.dns,
                idle_ms: now.saturating_sub(e.last_ms),
                strategy: e.strategy,
            })
            .collect()
    }
}

/// Фильтр в ядре: только первые пакеты, которые приёмы меняют. Весь остальной трафик в программу не попадает.
pub fn run_filter(s: &Strategy) -> String {
    let mut parts = vec![
        "(tcp.DstPort == 443 and tcp.PayloadLength > 5 and tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x01)",
        "(tcp.DstPort == 80 and tcp.PayloadLength > 0)",
    ];
    if s.quic != QuicMode::Pass {
        parts.push("(udp.DstPort == 443 and udp.PayloadLength >= 1200)");
    }
    if s.discord_voice {
        parts.push(
            "(((udp.DstPort >= 19294 and udp.DstPort <= 19344) or (udp.DstPort >= 50000 and udp.DstPort <= 50100)) \
             and (udp.PayloadLength == 74 or (udp.PayloadLength >= 20 and udp.Payload32[1] == 0x2112A442)))",
        );
    }
    format!("outbound and !loopback and !impostor and ({})", parts.join(" or "))
}

/// Исходящие DNS-запросы (UDP 53). Ответы подставляет DoH.
const DNS_FILTER: &str = "outbound and !loopback and !impostor and udp.DstPort == 53";

/// Копии HTTPS-пакетов для оценки соединений с приёмом: данные и RST/FIN сервера, данные клиента.
/// shortcut: копируется весь HTTPS-трафик, хотя нужны лишь первые 32 КБ соединений с приёмом — лишняя нагрузка
/// на процессор при видео; если станет заметно — отключать наблюдение для решённых соединений иначе (WFP/ETW).
const WATCH_FILTER: &str = "!loopback and (\
    (inbound and tcp.SrcPort == 443 and (tcp.PayloadLength > 0 or tcp.Rst or tcp.Fin)) or \
    (outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0))";

/// Сколько тишины ждать, прежде чем подводить итог по соединению.
const ANSWER_TIMEOUT_MS: u64 = 5000;

/// Работающий обход. `stop()` или удаление останавливает перехват — драйвер сразу пускает трафик напрямую.
pub struct Engine {
    handles: Vec<Arc<Divert>>,
    main: Option<JoinHandle<()>>,
    counters: Arc<Counters>,
    sites: Arc<Sites>,
    /// Адрес DoH-сервера, если DoH включён.
    pub doh_server: Option<String>,
    /// Файл выбора автоподбора, если автоподбор включён.
    pub tuning_file: Option<PathBuf>,
}

impl Engine {
    /// Проверка без перехвата: фильтры WinDivert и DoH-сервер.
    pub fn check(config: &Config) -> Result<(), String> {
        for filter in [run_filter(&config.strategy).as_str(), DNS_FILTER, WATCH_FILTER] {
            vx_divert::check_filter(&config.engine_dir, filter).map_err(|e| e.to_string())?;
        }
        config.doh.as_deref().map(Doh::new).transpose().map_err(|e| e.to_string())?;
        Ok(())
    }

    pub fn start(config: Config, sink: Sink) -> Result<Self, String> {
        Self::check(&config)?;
        let counters = Arc::new(Counters::default());
        let sites = Arc::new(Sites::new());
        let main = Arc::new(Divert::open(&config.engine_dir, &run_filter(&config.strategy), 0, 0).map_err(|e| e.to_string())?);
        let mut handles = vec![Arc::clone(&main)];

        let mut doh_server = None;
        if let Some(provider) = &config.doh {
            let doh = Doh::new(provider).map_err(|e| e.to_string())?;
            doh_server = Some(doh.host.clone());
            handles.push(start_doh(&config.engine_dir, doh, Arc::clone(&counters), Arc::clone(&sites))?);
        }

        let auto = if config.auto || config.auto_test {
            let auto = Auto::start(&config, Arc::clone(&sink))?;
            handles.push(Arc::clone(&auto.watch));
            Some(auto)
        } else {
            None
        };
        let tuning_file = auto.as_ref().map(|a| a.file.clone());

        let (strategy, c, s) = (config.strategy.clone(), Arc::clone(&counters), Arc::clone(&sites));
        let main_thread = std::thread::spawn(move || packet_loop(&main, &strategy, auto.as_ref(), &c, &s, &sink));
        Ok(Self { handles, main: Some(main_thread), counters, sites, doh_server, tuning_file })
    }

    pub fn stats(&self) -> Stats {
        let c = &self.counters;
        let get = |a: &AtomicU64| a.load(Ordering::Relaxed);
        Stats {
            changed: get(&c.changed),
            passed: get(&c.passed),
            dropped: get(&c.dropped),
            send_errors: get(&c.send_errors),
            doh_ok: get(&c.doh_ok),
            doh_fallback: get(&c.doh_fallback),
        }
    }

    /// Сайты, которые обход видел с запуска.
    pub fn sites(&self) -> Vec<SiteStat> {
        self.sites.list()
    }

    /// Сколько времени работает обход.
    pub fn uptime(&self) -> Duration {
        self.sites.started.elapsed()
    }

    pub fn stop(mut self) -> Stats {
        self.shutdown();
        self.stats()
    }

    fn shutdown(&mut self) {
        for h in &self.handles {
            let _ = h.shutdown();
        }
        if let Some(t) = self.main.take() {
            let _ = t.join();
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn packet_loop(divert: &Divert, strategy: &Strategy, auto: Option<&Auto>, c: &Counters, sites: &Sites, sink: &Sink) {
    let mut seen: HashSet<String> = HashSet::new();
    let mut buf = vec![0u8; 0xffff];
    while let Ok((len, addr)) = divert.recv(&mut buf) {
        let packet = &buf[..len];
        let chosen = auto.and_then(|a| a.pick(packet).map(|i| (&a.strategies[i], a.names[i])));
        if let Some(host) = host_of(packet) {
            sites.note(&host, |e| {
                e.connections += 1;
                e.strategy = chosen.map(|(_, name)| name);
            });
        }
        let result = match apply(packet, chosen.map_or(strategy, |(s, _)| s)) {
            Action::Pass => {
                c.passed.fetch_add(1, Ordering::Relaxed);
                divert.send(packet, &addr)
            }
            Action::Drop => {
                c.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Action::Send(outs) => {
                c.changed.fetch_add(1, Ordering::Relaxed);
                if let Some(event) = describe(packet)
                    && let Event::Site { kind, host, target } = &event
                    && seen.insert(format!("{kind}{host}{target}"))
                {
                    sink(event);
                }
                outs.into_iter().try_for_each(|mut out| {
                    let mut a = addr;
                    divert.calc_checksums(&mut out.data, &mut a);
                    if out.badsum {
                        corrupt_tcp_checksum(&mut out.data);
                    }
                    divert.send(&out.data, &a)
                })
            }
        };
        if let Err(e) = result
            && c.send_errors.fetch_add(1, Ordering::Relaxed) < 3
        {
            sink(Event::Warning(format!("Не отправлен пакет: {e}")));
        }
    }
}

/// Имя сайта из первого пакета TLS или HTTP.
fn host_of(packet: &[u8]) -> Option<String> {
    match classify(&parse(packet)?)? {
        Proto::Tls { host, .. } | Proto::Http { host, .. } if !host.is_empty() => Some(host.to_string()),
        _ => None,
    }
}

/// Событие «сайт» для журнала.
fn describe(packet: &[u8]) -> Option<Event> {
    let pkt = parse(packet)?;
    let (kind, host) = match classify(&pkt)? {
        Proto::Tls { host, .. } => ("TLS", host),
        Proto::Http { host, .. } => ("HTTP", host),
        Proto::Quic => ("QUIC", ""),
        Proto::DiscordVoice => ("ГОЛОС", "Discord"),
        Proto::Stun => ("STUN", ""),
    };
    let port = match pkt.transport {
        Transport::Tcp(t) => t.dst_port,
        Transport::Udp(u) => u.dst_port,
        Transport::Other(_) => 0,
    };
    Some(Event::Site { kind, host: host.to_string(), target: format!("{}:{port}", pkt.dst) })
}

/// Автоподбор: приём для сайта выбирает `Tuner`; копии HTTPS-пакетов и тайм-ауты сообщают, сработал ли он.
struct Auto {
    strategies: Vec<Strategy>,
    names: Vec<&'static str>,
    state: Arc<Mutex<(Tuner, Tracker)>>,
    watch: Arc<Divert>,
    file: PathBuf,
    started: Instant,
}

impl Auto {
    fn start(config: &Config, sink: Sink) -> Result<Self, String> {
        let mut list = presets();
        if config.auto_test {
            list.insert(0, ("без приёмов", passthrough()));
        }
        // QUIC и голос Discord — общие настройки, автоподбор меняет только приёмы для TLS.
        let global = &config.strategy;
        let strategies: Vec<Strategy> = list
            .iter()
            .map(|(_, s)| Strategy { quic: global.quic, discord_voice: global.discord_voice, ..s.clone() })
            .collect();
        let names: Vec<&'static str> = list.iter().map(|(n, _)| *n).collect();
        let file = config.data_dir.join("tuning.txt");
        let mut tuner = Tuner::new(names.len(), 0);
        if !config.auto_test
            && let Ok(text) = std::fs::read_to_string(&file)
        {
            tuner.load(&text, &names);
        }
        let state = Arc::new(Mutex::new((tuner, Tracker::default())));
        let watch = Arc::new(Divert::open(&config.engine_dir, WATCH_FILTER, 0, FLAG_SNIFF).map_err(|e| e.to_string())?);
        let auto = Self { strategies, names: names.clone(), state, watch, file, started: Instant::now() };
        auto.spawn_watchers(names, sink);
        Ok(auto)
    }

    fn now_ms(started: Instant) -> u64 {
        started.elapsed().as_millis() as u64
    }

    /// Приём для исходящего ClientHello; соединение запоминается до итога.
    fn pick(&self, packet: &[u8]) -> Option<usize> {
        let pkt = parse(packet)?;
        let (Transport::Tcp(tcp), Some(Proto::Tls { host, .. })) = (pkt.transport, classify(&pkt)) else { return None };
        let site = site_key(host);
        let mut state = self.state.lock().ok()?;
        let choice = state.0.choice(&site);
        state.1.sent((pkt.src, tcp.src_port, pkt.dst, tcp.dst_port), site, choice, Self::now_ms(self.started));
        Some(choice)
    }

    /// Поток копий пакетов и поток тайм-аутов.
    fn spawn_watchers(&self, names: Vec<&'static str>, sink: Sink) {
        let file = self.file.clone();
        let report = Arc::new(move |state: &mut (Tuner, Tracker), site: String, strategy: usize, ok: bool| {
            let Some(event) = state.0.report(&site, strategy, ok) else { return };
            sink(match event {
                vx_core::tuner::Event::Works { site, strategy } => Event::Works { site, strategy: names[strategy].into() },
                vx_core::tuner::Event::Switched { site, from, to } => {
                    Event::Switched { site, from: names[from].into(), to: names[to].into() }
                }
            });
            // Ошибка записи не мешает обходу: выбор просто не сохранится до следующего запуска.
            let _ = std::fs::create_dir_all(file.parent().unwrap_or(&file))
                .and_then(|_| std::fs::write(&file, state.0.save(&names)));
        });

        // Все отметки времени — от одного `started`, что и в `pick`: трекер сравнивает, кто говорил последним.
        let started = self.started;
        let (watch, state, rep) = (Arc::clone(&self.watch), Arc::clone(&self.state), Arc::clone(&report));
        std::thread::spawn(move || {
            let mut buf = vec![0u8; 0xffff];
            while let Ok((len, addr)) = watch.recv(&mut buf) {
                let Some(pkt) = parse(&buf[..len]) else { continue };
                let Transport::Tcp(tcp) = pkt.transport else { continue };
                let Ok(mut s) = state.lock() else { break };
                let now = Self::now_ms(started);
                if addr.outbound() {
                    s.1.client_data((pkt.src, tcp.src_port, pkt.dst, tcp.dst_port), now);
                    continue;
                }
                let flow = (pkt.dst, tcp.dst_port, pkt.src, tcp.src_port);
                let (rst, fin) = (tcp.flags & TCP_RST != 0, tcp.flags & TCP_FIN != 0);
                if let Some((site, strategy, ok)) = s.1.server_packet(flow, tcp.seq, pkt.payload, rst, fin, now) {
                    rep(&mut s, site, strategy, ok);
                }
            }
        });

        // Поток тайм-аутов живёт, пока жив перехват копий: после остановки он выходит на следующем тике.
        let (state, watch) = (Arc::clone(&self.state), Arc::downgrade(&self.watch));
        std::thread::spawn(move || {
            while watch.strong_count() > 0 {
                std::thread::sleep(Duration::from_secs(1));
                let Ok(mut s) = state.lock() else { break };
                for (site, strategy, ok) in s.1.expired(Self::now_ms(started), ANSWER_TIMEOUT_MS) {
                    report(&mut s, site, strategy, ok);
                }
            }
        });
    }
}

/// Перехват DNS: запрос → DoH → ответ подставляется входящим пакетом. Если DoH не ответил или ответил не тем —
/// исходный запрос отправляется дальше без изменений, и сайт откроется через обычный DNS, как без программы.
fn start_doh(dir: &Path, doh: Doh, c: Arc<Counters>, sites: Arc<Sites>) -> Result<Arc<Divert>, String> {
    let divert = Arc::new(Divert::open(dir, DNS_FILTER, 0, 0).map_err(|e| e.to_string())?);
    let doh = Arc::new(doh);
    let (tx, rx) = std::sync::mpsc::channel::<(Vec<u8>, vx_divert::Address)>();
    let rx = Arc::new(Mutex::new(rx));

    // Несколько запросов параллельно: один медленный ответ не задерживает остальные.
    for _ in 0..8 {
        let (divert, doh, c, rx, sites) =
            (Arc::clone(&divert), Arc::clone(&doh), Arc::clone(&c), Arc::clone(&rx), Arc::clone(&sites));
        std::thread::spawn(move || {
            while let Ok((packet, addr)) = rx.lock().map_err(|_| ()).and_then(|r| r.recv().map_err(|_| ())) {
                if let Some((name, mut reply)) = resolve(&doh, &packet) {
                    sites.note(&name, |e| e.dns += 1);
                    let mut a = addr;
                    a.set_outbound(false);
                    divert.calc_checksums(&mut reply, &mut a);
                    if divert.send(&reply, &a).is_ok() {
                        c.doh_ok.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                }
                c.doh_fallback.fetch_add(1, Ordering::Relaxed);
                let _ = divert.send(&packet, &addr);
            }
        });
    }

    let reader = Arc::clone(&divert);
    std::thread::spawn(move || {
        let mut buf = vec![0u8; 0xffff];
        while let Ok((len, addr)) = reader.recv(&mut buf) {
            if tx.send((buf[..len].to_vec(), addr)).is_err() {
                break;
            }
        }
    });
    Ok(divert)
}

/// Имя из запроса и ответный пакет из DoH или `None`, если запрос к самому DoH-серверу, DoH не ответил
/// или ответил не на то.
fn resolve(doh: &Doh, packet: &[u8]) -> Option<(String, Vec<u8>)> {
    let pkt = parse(packet)?;
    let (name, _) = dns::question(pkt.payload)?;
    if name == doh.host {
        return None;
    }
    let answer = doh.query(pkt.payload).ok()?;
    let reply = dns::is_answer_to(pkt.payload, &answer).then(|| dns::reply_packet(&pkt, &answer)).flatten()?;
    Some((name, reply))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filter_skips_quic_and_voice_when_not_needed() {
        let base = run_filter(&Strategy { quic: QuicMode::Pass, ..Strategy::default() });
        assert!(!base.contains("udp"));
        assert!(run_filter(&Strategy { discord_voice: true, ..Strategy::default() }).contains("50000"));
    }

    #[test]
    fn sites_group_by_domain_and_skip_service_names() {
        let sites = Sites::new();
        sites.note("rr1---sn-x.googlevideo.com", |e| e.connections += 1);
        sites.note("www.googlevideo.com", |e| e.dns += 1);
        sites.note("1.0.0.127.in-addr.arpa", |e| e.dns += 1);
        sites.note("wpad", |e| e.dns += 1);
        let list = sites.list();
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].site.as_str(), list[0].connections, list[0].dns), ("googlevideo.com", 1, 1));
    }

    #[test]
    fn sites_forget_the_oldest_when_full() {
        let sites = Sites::new();
        for i in 0..=SITES_LIMIT {
            sites.note(&format!("site{i}.com"), |e| e.connections += 1);
        }
        assert_eq!(sites.list().len(), SITES_LIMIT);
    }

    #[test]
    fn describe_names_site_and_server() {
        let hello = vx_core::desync::fake_tls_hello("discord.com");
        let total = 40 + hello.len();
        let mut p = vec![0x45, 0, (total >> 8) as u8, total as u8, 0, 1, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, 2, 162, 159, 128, 233];
        p.extend(50000u16.to_be_bytes());
        p.extend(443u16.to_be_bytes());
        p.extend([0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0xff, 0xff, 0, 0, 0, 0]);
        p.extend(hello);
        assert_eq!(
            describe(&p),
            Some(Event::Site { kind: "TLS", host: "discord.com".into(), target: "162.159.128.233:443".into() })
        );
    }
}
