//! Обход блокировки по IP: когда до адреса не доходят даже пакеты подключения (SYN без ответа), приёмы против DPI
//! бесполезны — соединение надо увести на другой путь. Три режима, выбор — в настройках:
//!
//! - **Cloudflare** — локально, без посредников: адрес Cloudflare заменяется другим адресом Cloudflare, который
//!   отвечает (сайт выбирается по имени в TLS). Подменяются адреса в пакетах; программа этого не замечает.
//! - **Свой прокси** — соединение уходит через SOCKS5-прокси пользователя.
//! - **WARP** — то же через Cloudflare WARP в режиме прокси (127.0.0.1:40000); WARP ставит сам пользователь.
//!
//! Для прокси соединение перехватывается и разворачивается на локальный приёмник (как streamdump в примерах
//! WinDivert): пакеты к заблокированному адресу приходят приёмнику как входящие, ответы — обратно программе.
//! Перенаправляются только заблокированные адреса (IPv4, порт 443); остальной трафик идёт как обычно.
//! shortcut: IPv6 и порты кроме 443 не перенаправляются; список заблокированных живёт до остановки обхода.

pub mod detect;
pub mod nat;
pub mod ranges;
pub mod socks;

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vx_divert::{Divert, FLAG_SNIFF};

use detect::{SYN_TIMEOUT_MS, SynWatch};
use nat::{Nat, Tcp4};
use ranges::{SEEDS, is_cloudflare, is_public};
pub use socks::Proxy;

/// Адрес Cloudflare WARP в режиме прокси (`warp-cli mode proxy`).
pub const WARP_PROXY: &str = "127.0.0.1:40000";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    Cloudflare,
    Proxy(Proxy),
    Warp,
}

impl Mode {
    fn proxy(&self) -> Option<Proxy> {
        match self {
            Mode::Cloudflare => None,
            Mode::Proxy(p) => Some(p.clone()),
            Mode::Warp => Some(Proxy { addr: WARP_PROXY.parse().expect("адрес WARP"), login: None }),
        }
    }

    fn label(&self) -> String {
        match self {
            Mode::Cloudflare => "другой адрес Cloudflare".into(),
            Mode::Proxy(p) => format!("прокси {}", p.addr),
            Mode::Warp => "Cloudflare WARP".into(),
        }
    }
}

/// Сообщение для журнала.
pub type Log = Arc<dyn Fn(String) + Send + Sync>;

#[derive(Debug, Default)]
pub struct Stats {
    /// Адресов, признанных заблокированными и перенаправленных.
    pub blocked: AtomicU64,
    /// Соединений, ушедших в обход.
    pub rerouted: AtomicU64,
}

/// Копии SYN к 443 и ответов на них — для обнаружения блокировки. Высший приоритет: видит пакеты до подмены.
const DETECT_FILTER: &str = "ip and tcp and !loopback and \
    ((outbound and tcp.DstPort == 443 and tcp.Syn and !tcp.Ack) or (inbound and tcp.SrcPort == 443 and (tcp.Syn or tcp.Rst)))";
const DETECT_PRIORITY: i16 = 400;
/// Подмена: раньше приёмов обхода (приоритет 0), чтобы приёмы применялись уже к новому адресу.
const REWRITE_PRIORITY: i16 = 200;
/// Больше адресов фильтр WinDivert не вместит.
const BLOCKED_LIMIT: usize = 64;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Одновременных подключений к прокси на один адрес — больше бывает только при петле.
const LOOP_LIMIT: usize = 16;

#[derive(Clone, Copy)]
enum Kind {
    Cloudflare,
    Relay { port: u16 },
}

struct State {
    dll_dir: PathBuf,
    kind: Kind,
    started: Instant,
    watch: SynWatch,
    nat: Nat,
    /// Заблокированные адреса (в порядке обнаружения).
    blocked: Vec<Ipv4Addr>,
    /// Режим Cloudflare: заблокированный адрес → замена.
    replacement: HashMap<Ipv4Addr, Ipv4Addr>,
    /// Замены, которые сами не ответили.
    dead: HashSet<Ipv4Addr>,
    /// Адреса, о которых уже сказано, что заменить их нельзя.
    skipped: HashSet<Ipv4Addr>,
    rewriter: Option<Arc<Divert>>,
}

impl State {
    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// Ответивший адрес Cloudflare рядом с `blocked`, иначе запасной.
    fn pick_replacement(&self, blocked: Ipv4Addr) -> Option<Ipv4Addr> {
        let unusable = |ip: Ipv4Addr| ip == blocked || self.blocked.contains(&ip) || self.dead.contains(&ip);
        self.watch.nearest_good(blocked, unusable).or_else(|| SEEDS.iter().copied().find(|&ip| !unusable(ip)))
    }

    fn filter(&self) -> Option<String> {
        if self.blocked.is_empty() {
            return None;
        }
        let any = |field: &str, ips: &mut dyn Iterator<Item = Ipv4Addr>| {
            ips.map(|ip| format!("{field} == {ip}")).collect::<Vec<_>>().join(" or ")
        };
        let to_blocked = format!("(outbound and tcp.DstPort == 443 and ({}))", any("ip.DstAddr", &mut self.blocked.iter().copied()));
        let back = match self.kind {
            Kind::Cloudflare => {
                let mut repl: Vec<Ipv4Addr> = self.replacement.values().copied().collect();
                repl.sort();
                repl.dedup();
                format!("(inbound and tcp.SrcPort == 443 and ({}))", any("ip.SrcAddr", &mut repl.into_iter()))
            }
            Kind::Relay { port } => format!("(outbound and tcp.SrcPort == {port})"),
        };
        Some(format!("ip and tcp and !loopback and ({to_blocked} or {back})"))
    }
}

/// Работающий обход блокировки по IP. `stop()` или удаление — всё снова идёт напрямую.
pub struct Reroute {
    state: Arc<Mutex<State>>,
    detector: Arc<Divert>,
    stop: Arc<AtomicBool>,
    relay_port: Option<u16>,
    stats: Arc<Stats>,
}

impl Reroute {
    pub fn start(dll_dir: &Path, mode: Mode, log: Log) -> Result<Self, String> {
        let proxy = mode.proxy();
        if let Some(p) = &proxy {
            TcpStream::connect_timeout(&p.addr, Duration::from_secs(2)).map_err(|e| match mode {
                Mode::Warp => format!(
                    "Cloudflare WARP не отвечает на {WARP_PROXY} ({e}). Установите WARP, включите режим прокси \
                     (warp-cli mode proxy) и подключитесь (warp-cli connect)."
                ),
                _ => format!("Прокси {} не отвечает: {e}", p.addr),
            })?;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let stats = Arc::new(Stats::default());

        let (kind, relay_port) = match &proxy {
            None => (Kind::Cloudflare, None),
            Some(p) => {
                let port = start_relay(p.clone(), Arc::clone(&stop), Arc::clone(&log))?;
                (Kind::Relay { port }, Some(port))
            }
        };
        let detector = Arc::new(
            Divert::open(dll_dir, DETECT_FILTER, DETECT_PRIORITY, FLAG_SNIFF).map_err(|e| format!("обход по IP: {e}"))?,
        );
        let state = Arc::new(Mutex::new(State {
            dll_dir: dll_dir.to_path_buf(),
            kind,
            started: Instant::now(),
            watch: SynWatch::default(),
            nat: Nat::default(),
            blocked: Vec::new(),
            replacement: HashMap::new(),
            dead: HashSet::new(),
            skipped: HashSet::new(),
            rewriter: None,
        }));

        let (d, s) = (Arc::clone(&detector), Arc::clone(&state));
        std::thread::spawn(move || detect_loop(&d, &s));

        let (s, st, sp, label) = (Arc::clone(&state), Arc::clone(&stats), Arc::clone(&stop), mode.label());
        std::thread::spawn(move || {
            while !sp.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(250));
                tick(&s, &st, &label, &log);
            }
        });

        Ok(Self { state, detector, stop, relay_port, stats })
    }

    pub fn stats(&self) -> (u64, u64) {
        (self.stats.blocked.load(Ordering::Relaxed), self.stats.rerouted.load(Ordering::Relaxed))
    }

    pub fn stop(self) {}
}

impl Drop for Reroute {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.detector.shutdown();
        if let Some(r) = self.state.lock().ok().and_then(|mut s| s.rewriter.take()) {
            let _ = r.shutdown();
        }
        if let Some(port) = self.relay_port {
            // Будим приёмник, ждущий в accept.
            let _ = TcpStream::connect_timeout(&SocketAddr::from(([127, 0, 0, 1], port)), Duration::from_millis(200));
        }
    }
}

fn detect_loop(divert: &Divert, state: &Mutex<State>) {
    let mut buf = vec![0u8; 0xffff];
    while let Ok((len, addr)) = divert.recv(&mut buf) {
        let Some(t) = Tcp4::read(&buf[..len]) else { continue };
        let Ok(mut s) = state.lock() else { break };
        let now = s.now_ms();
        if addr.outbound() {
            if t.syn_only() && is_public(t.dst) {
                s.watch.syn(t.src_port, t.dst, now);
            }
        } else if t.syn_ack() {
            s.watch.syn_ack(t.dst_port, t.src, now);
        } else if t.rst() {
            s.watch.reset(t.dst_port, t.src);
        }
    }
}

/// Раз в 250 мс: новые заблокированные адреса и замолчавшие замены → новый фильтр подмены.
fn tick(state: &Arc<Mutex<State>>, stats: &Arc<Stats>, label: &str, log: &Log) {
    let Ok(mut s) = state.lock() else { return };
    let now = s.now_ms();
    let mut changed = false;

    for dead in s.nat.dead_replacements(now, SYN_TIMEOUT_MS) {
        if s.dead.insert(dead) {
            log(format!("Замена {dead} тоже не отвечает — беру другую"));
        }
        let affected: Vec<Ipv4Addr> = s.replacement.iter().filter(|(_, r)| **r == dead).map(|(b, _)| *b).collect();
        for blocked in affected {
            match s.pick_replacement(blocked) {
                Some(r) => {
                    s.replacement.insert(blocked, r);
                }
                None => {
                    s.replacement.remove(&blocked);
                    s.blocked.retain(|ip| *ip != blocked);
                    log(format!("Для {blocked} не осталось рабочих адресов Cloudflare"));
                }
            }
            changed = true;
        }
    }

    for ip in s.watch.expired(now) {
        if s.blocked.contains(&ip) || s.skipped.contains(&ip) || s.dead.contains(&ip) || s.replacement.values().any(|r| *r == ip) {
            continue;
        }
        if s.blocked.len() >= BLOCKED_LIMIT {
            if s.skipped.insert(ip) {
                log(format!("{ip} не отвечает, но список обхода по IP полон ({BLOCKED_LIMIT} адресов) — перезапустите обход"));
            }
            continue;
        }
        match s.kind {
            Kind::Cloudflare if !is_cloudflare(ip) => {
                if s.skipped.insert(ip) {
                    log(format!(
                        "{ip} не отвечает (похоже на блокировку по IP), но это не Cloudflare — заменить адрес нельзя. \
                         Для таких сайтов выберите в настройках свой прокси или WARP."
                    ));
                }
            }
            Kind::Cloudflare => match s.pick_replacement(ip) {
                Some(r) => {
                    s.blocked.push(ip);
                    s.replacement.insert(ip, r);
                    log(format!("{ip} не отвечает (блокировка по IP) → соединения идут на {r} (тоже Cloudflare)"));
                    changed = true;
                }
                None => {
                    if s.skipped.insert(ip) {
                        log(format!("{ip} не отвечает, а рабочей замены в сети Cloudflare не нашлось"));
                    }
                }
            },
            Kind::Relay { .. } => {
                s.blocked.push(ip);
                log(format!("{ip} не отвечает (блокировка по IP) → соединения идут через {label}"));
                changed = true;
            }
        }
    }

    if changed {
        stats.blocked.store(s.blocked.len() as u64, Ordering::Relaxed);
        reopen_rewriter(&mut s, state, stats, log);
    }
}

/// Новый фильтр — новый перехват; старый закрывается после открытия нового, чтобы не было окна без подмены.
fn reopen_rewriter(s: &mut State, state: &Arc<Mutex<State>>, stats: &Arc<Stats>, log: &Log) {
    let old = s.rewriter.take();
    if let Some(filter) = s.filter() {
        match Divert::open(&s.dll_dir, &filter, REWRITE_PRIORITY, 0) {
            Ok(d) => {
                let d = Arc::new(d);
                s.rewriter = Some(Arc::clone(&d));
                let (kind, state, stats) = (s.kind, Arc::clone(state), Arc::clone(stats));
                // Поток выходит после shutdown своего перехвата (новый фильтр или остановка).
                std::thread::spawn(move || rewrite_loop(&d, kind, &state, &stats));
            }
            Err(e) => log(format!("Обход по IP: не открылся перехват ({e})")),
        }
    }
    if let Some(old) = old {
        let _ = old.shutdown();
    }
}

fn rewrite_loop(divert: &Divert, kind: Kind, state: &Mutex<State>, stats: &Stats) {
    let mut buf = vec![0u8; 0xffff];
    while let Ok((len, mut addr)) = divert.recv(&mut buf) {
        let packet = &mut buf[..len];
        if let Some(mut t) = Tcp4::read(packet) {
            let Ok(mut s) = state.lock() else { break };
            let now = s.now_ms();
            match kind {
                Kind::Cloudflare => {
                    if addr.outbound() {
                        if let Some(r) = s.replacement.get(&t.dst).copied() {
                            if t.syn_only() {
                                stats.rerouted.fetch_add(1, Ordering::Relaxed);
                            }
                            t.dst = s.nat.outbound(t.src_port, t.dst, r, t.syn_only(), now);
                        }
                    } else if let Some(original) = s.nat.inbound(t.dst_port, t.src, t.syn_ack(), now) {
                        t.src = original;
                    }
                }
                Kind::Relay { port } => {
                    // Только исходящие: пакеты программы → приёмнику, ответы приёмника → программе, оба как входящие.
                    if t.src_port == port {
                        (t.src, t.dst) = (t.dst, t.src);
                        t.src_port = 443;
                    } else {
                        if t.syn_only() {
                            stats.rerouted.fetch_add(1, Ordering::Relaxed);
                        }
                        (t.src, t.dst) = (t.dst, t.src);
                        t.dst_port = port;
                    }
                    addr.set_outbound(false);
                }
            }
            drop(s);
            t.write(packet);
            divert.calc_checksums(packet, &mut addr);
        }
        let _ = divert.send(packet, &addr);
    }
}

/// Приёмник развёрнутых соединений: адрес «собеседника» — заблокированный сервер, порт назначения всегда 443.
fn start_relay(proxy: Proxy, stop: Arc<AtomicBool>, log: Log) -> Result<u16, String> {
    let listener = TcpListener::bind("0.0.0.0:0").map_err(|e| format!("обход по IP: приёмник не открылся ({e})"))?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    let reported = Arc::new(AtomicBool::new(false));
    let looped = Arc::new(AtomicBool::new(false));
    // Подключения к прокси, ещё не получившие ответа, по адресам. Если прокси работает на этом же компьютере и сам
    // ходит к заблокированному адресу напрямую, его соединение снова попадает сюда — петля; её останавливает предел.
    let connecting: Arc<Mutex<HashMap<SocketAddrV4, usize>>> = Arc::default();
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            let Ok(client) = conn else { continue };
            let Ok(SocketAddr::V4(peer)) = client.peer_addr() else { continue };
            let target = SocketAddrV4::new(*peer.ip(), 443);
            {
                let Ok(mut c) = connecting.lock() else { break };
                let n = c.entry(target).or_default();
                if *n >= LOOP_LIMIT {
                    if !looped.swap(true, Ordering::Relaxed) {
                        log(format!(
                            "Похоже на петлю: прокси {} сам подключается к {target} через этот компьютер. \
                             Нужен прокси на другом компьютере или WARP.",
                            proxy.addr
                        ));
                    }
                    continue;
                }
                *n += 1;
            }
            let (proxy, log, reported, connecting) =
                (proxy.clone(), Arc::clone(&log), Arc::clone(&reported), Arc::clone(&connecting));
            std::thread::spawn(move || {
                let upstream = proxy.connect(target, CONNECT_TIMEOUT);
                if let Ok(mut c) = connecting.lock()
                    && let Some(n) = c.get_mut(&target)
                {
                    *n = n.saturating_sub(1);
                }
                match upstream {
                    Ok(upstream) => bridge(client, upstream),
                    Err(e) => {
                        if !reported.swap(true, Ordering::Relaxed) {
                            log(format!("Через прокси {} не удалось соединиться с {target}: {e}", proxy.addr));
                        }
                    }
                }
            });
        }
    });
    Ok(port)
}

fn bridge(a: TcpStream, b: TcpStream) {
    let _ = a.set_nodelay(true);
    let (Ok(mut a2), Ok(mut b2)) = (a.try_clone(), b.try_clone()) else { return };
    let (mut a, mut b) = (a, b);
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a2, &mut b2);
        let _ = b2.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut b, &mut a);
    let _ = a.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(kind: Kind) -> State {
        State {
            dll_dir: PathBuf::new(),
            kind,
            started: Instant::now(),
            watch: SynWatch::default(),
            nat: Nat::default(),
            blocked: Vec::new(),
            replacement: HashMap::new(),
            dead: HashSet::new(),
            skipped: HashSet::new(),
            rewriter: None,
        }
    }

    #[test]
    fn filters() {
        let mut s = state(Kind::Cloudflare);
        assert_eq!(s.filter(), None);
        let b = Ipv4Addr::new(162, 159, 134, 232);
        s.blocked.push(b);
        s.replacement.insert(b, Ipv4Addr::new(162, 159, 135, 232));
        let f = s.filter().unwrap();
        assert!(f.contains("ip.DstAddr == 162.159.134.232") && f.contains("ip.SrcAddr == 162.159.135.232"), "{f}");

        let mut r = state(Kind::Relay { port: 50123 });
        r.blocked.push(b);
        assert!(r.filter().unwrap().contains("tcp.SrcPort == 50123"));
    }

    #[test]
    fn replacement_skips_blocked_and_dead_addresses() {
        let mut s = state(Kind::Cloudflare);
        let b = Ipv4Addr::new(162, 159, 134, 232);
        assert_eq!(s.pick_replacement(b), Some(SEEDS[0]));
        s.dead.insert(SEEDS[0]);
        s.blocked.push(SEEDS[1]);
        assert_eq!(s.pick_replacement(b), Some(SEEDS[2]));
    }

    #[test]
    fn modes() {
        assert_eq!(Mode::Warp.proxy().unwrap().addr, WARP_PROXY.parse().unwrap());
        assert_eq!(Mode::Cloudflare.proxy(), None);
    }
}
