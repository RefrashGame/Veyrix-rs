//! Локальный MTProto-прокси: 127.0.0.1:порт, поток на соединение.
//!
//! Маршрут к Telegram (как в Veyrix на C#): WebSocket-вход веб-версии (kws2/kws4.web.telegram.org); если он не ответил
//! за секунду — параллельно резерв через Cloudflare, побеждает первый; иначе прямой TCP на адрес DC.
//! После неудачи прямой вход пропускается: 30 с, 1 мин, 2 мин … до 10 мин.

use std::collections::{HashMap, HashSet};
use std::io::{self, Read, Write};
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use crate::cloudflare::{self, Balancer};
use crate::mtproto::{Ciphers, INIT_LEN, PacketSplitter, dc_address, parse_handshake, parse_secret, relay_init, ws_domains};
use crate::ws::{ConnectError, WebSocket};

pub type Log = Arc<dyn Fn(String) + Send + Sync>;

const MAX_CONNECTIONS: usize = 200;
const BUFFER: usize = 64 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WS_TIMEOUT_MS: i32 = 10_000;
const CLOUDFLARE_TIMEOUT_MS: i32 = 8_000;
// shortcut: upstream перебирает все ~20 доменов по очереди; мы пробуем 8 одновременно (рабочий + 7 случайных) —
// ответ за секунды, а не минуты, ценой 8 TLS-рукопожатий на соединение в резервном режиме.
const CLOUDFLARE_ATTEMPTS: usize = 8;
const WS_HEAD_START: Duration = Duration::from_secs(1);
const FAIL_COOLDOWN: Duration = Duration::from_secs(30);
const MAX_COOLDOWN: Duration = Duration::from_secs(600);
const CLOUDFLARE_REFRESH: Duration = Duration::from_secs(3600);
/// DC, у которых есть WebSocket-вход веб-версии (DefaultDcIps в Veyrix на C#: 2 и 4).
const DIRECT_WS_DCS: [i32; 2] = [2, 4];

#[derive(Default)]
pub struct Stats {
    pub active: AtomicUsize,
    pub up: AtomicU64,
    pub down: AtomicU64,
    pub via_ws: AtomicU64,
    pub via_cloudflare: AtomicU64,
    pub via_tcp: AtomicU64,
    pub bad_handshakes: AtomicU64,
}

#[derive(Debug, Clone, Copy)]
pub struct Options {
    /// Прямой WebSocket-вход веб-версии Telegram.
    pub direct_ws: bool,
    /// Резерв через Cloudflare-домены Flowseal.
    pub cloudflare: bool,
    /// Прямой TCP к серверам Telegram (выключается только для проверки других путей).
    pub direct_tcp: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self { direct_ws: true, cloudflare: true, direct_tcp: true }
    }
}

type Target = (i32, bool);

struct Shared {
    secret: [u8; 16],
    options: Options,
    balancer: Balancer,
    stats: Arc<Stats>,
    log: Log,
    /// Пауза прямого входа после неудач: до какого времени и сколько неудач подряд.
    pause: Mutex<HashMap<Target, (Instant, u32)>>,
    /// DC, где все входы отвечают переадресацией — дальше без прямого WebSocket.
    redirected: Mutex<HashSet<Target>>,
    stop: AtomicBool,
}

pub struct Proxy {
    shared: Arc<Shared>,
    addr: SocketAddr,
    accept: Option<JoinHandle<()>>,
}

impl Proxy {
    /// Слушает только 127.0.0.1 (порт 0 — любой свободный). Ошибка — порт занят или secret неверный.
    pub fn start(port: u16, secret_hex: &str, options: Options, log: Log) -> io::Result<Self> {
        let secret = parse_secret(secret_hex).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "secret — 32 hex-символа"))?;
        let listener = TcpListener::bind(("127.0.0.1", port))?;
        let addr = listener.local_addr()?;
        let shared = Arc::new(Shared {
            secret,
            options,
            balancer: Balancer::default(),
            stats: Arc::new(Stats::default()),
            log,
            pause: Mutex::new(HashMap::new()),
            redirected: Mutex::new(HashSet::new()),
            stop: AtomicBool::new(false),
        });
        if options.cloudflare {
            let sh = Arc::clone(&shared);
            std::thread::spawn(move || refresh_cloudflare(&sh));
        }
        let sh = Arc::clone(&shared);
        let accept = std::thread::spawn(move || accept_loop(listener, &sh));
        (shared.log)(format!(
            "Telegram-прокси запущен: 127.0.0.1:{}; прямой вход: {}; резерв через Cloudflare: {}",
            addr.port(),
            if options.direct_ws { "DC 2, 4" } else { "выключен" },
            if options.cloudflare { "включён" } else { "выключен" },
        ));
        Ok(Self { shared, addr, accept: Some(accept) })
    }

    pub fn port(&self) -> u16 {
        self.addr.port()
    }

    pub fn stats(&self) -> Arc<Stats> {
        Arc::clone(&self.shared.stats)
    }

    /// Перестаёт принимать новые соединения. Открытые закроются, когда Telegram их оборвёт.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        if self.shared.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = TcpStream::connect_timeout(&self.addr, Duration::from_secs(1)); // разбудить accept
        if let Some(t) = self.accept.take() {
            let _ = t.join();
        }
        (self.shared.log)("Telegram-прокси остановлен".into());
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn accept_loop(listener: TcpListener, sh: &Arc<Shared>) {
    for client in listener.incoming() {
        if sh.stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(client) = client else { continue };
        if sh.stats.active.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            continue; // соединение закроется при выходе из области видимости
        }
        sh.stats.active.fetch_add(1, Ordering::Relaxed);
        let sh = Arc::clone(sh);
        std::thread::spawn(move || {
            let _ = serve(&sh, client); // обрыв соединения для прокси — норма
            sh.stats.active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn refresh_cloudflare(sh: &Shared) {
    while !sh.stop.load(Ordering::SeqCst) {
        let url = format!("{}?{:08x}", cloudflare::LIST_URL, rand_u32()); // мимо кэша GitHub, как в upstream
        match crate::ws::https_get_text(&url, 15_000).map(|t| cloudflare::parse(&t)) {
            Ok(Some(fresh)) if fresh != sh.balancer.domains() => {
                (sh.log)(format!("Telegram: список доменов Cloudflare обновлён: {}", fresh.len()));
                sh.balancer.set_domains(fresh);
            }
            _ => {} // остаётся текущий список
        }
        let until = Instant::now() + CLOUDFLARE_REFRESH;
        while Instant::now() < until && !sh.stop.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    crate::crypto::random(&mut b);
    u32::from_le_bytes(b)
}

fn serve(sh: &Arc<Shared>, mut client: TcpStream) -> io::Result<()> {
    client.set_nodelay(true)?;
    client.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let mut init = [0u8; INIT_LEN];
    client.read_exact(&mut init)?;
    client.set_read_timeout(None)?;

    let Some(hs) = parse_handshake(&init, &sh.secret) else {
        if sh.stats.bad_handshakes.fetch_add(1, Ordering::Relaxed) == 0 {
            (sh.log)("Telegram: подключение с неверным ключом — в Telegram указан другой secret. Подключите Telegram заново.".into());
        }
        return Ok(());
    };
    let relay = relay_init(hs.protocol, hs.dc, hs.media);
    let ciphers = Ciphers::new(&hs, &sh.secret, &relay);

    match route(sh, (hs.dc, hs.media)) {
        Some(Remote::Ws(ws, via_cloudflare)) => {
            let counter = if via_cloudflare { &sh.stats.via_cloudflare } else { &sh.stats.via_ws };
            counter.fetch_add(1, Ordering::Relaxed);
            ws.send(&relay)?;
            bridge_ws(sh, client, ws, ciphers, PacketSplitter::new(hs.protocol))
        }
        Some(Remote::Tcp(mut remote)) => {
            sh.stats.via_tcp.fetch_add(1, Ordering::Relaxed);
            remote.write_all(&relay)?;
            bridge_tcp(sh, client, remote, ciphers)
        }
        None => {
            (sh.log)(format!("Telegram DC{}: нет ни веб-входа, ни резерва, ни прямого подключения", hs.dc));
            Ok(())
        }
    }
}

enum Remote {
    /// WebSocket; `true` — через Cloudflare.
    Ws(WebSocket, bool),
    Tcp(TcpStream),
}

/// Прямой путь (веб-вход для DC 2/4, иначе TCP к DC), а через секунду без ответа — параллельно Cloudflare;
/// первое удачное подключение побеждает, опоздавшее закрывается само (некому отдать результат).
/// Для DC 2/4 последний шанс — прямой TCP.
fn route(sh: &Arc<Shared>, target: Target) -> Option<Remote> {
    let ws_dc = sh.options.direct_ws && DIRECT_WS_DCS.contains(&target.0);
    let (tx, rx) = mpsc::channel::<Option<Remote>>();
    let mut pending = 0;
    if (ws_dc && direct_allowed(sh, target)) || (!ws_dc && sh.options.direct_tcp) {
        pending += 1;
        let (tx, worker) = (tx.clone(), Arc::clone(sh));
        std::thread::spawn(move || {
            let remote = if ws_dc { try_direct(&worker, target).map(|ws| Remote::Ws(ws, false)) } else { try_tcp(target.0) };
            let _ = tx.send(remote);
        });
        let wait = if sh.options.cloudflare { WS_HEAD_START } else { Duration::from_secs(60) };
        match rx.recv_timeout(wait) {
            Ok(Some(remote)) => return Some(remote),
            Ok(None) => pending -= 1,
            Err(_) => {}
        }
    }
    if sh.options.cloudflare {
        pending += 1;
        let (tx, worker) = (tx.clone(), Arc::clone(sh));
        std::thread::spawn(move || {
            let _ = tx.send(try_cloudflare(&worker, target.0).map(|ws| Remote::Ws(ws, true)));
        });
    }
    drop(tx);
    while pending > 0 {
        match rx.recv() {
            Ok(Some(remote)) => return Some(remote),
            Ok(None) => pending -= 1,
            Err(_) => break,
        }
    }
    if ws_dc && sh.options.direct_tcp { try_tcp(target.0) } else { None }
}

fn try_tcp(dc: i32) -> Option<Remote> {
    let stream = TcpStream::connect_timeout(&SocketAddr::from((dc_address(dc)?, 443)), CONNECT_TIMEOUT).ok()?;
    let _ = stream.set_nodelay(true);
    Some(Remote::Tcp(stream))
}

fn direct_allowed(sh: &Shared, target: Target) -> bool {
    !sh.redirected.lock().is_ok_and(|r| r.contains(&target))
        && !sh.pause.lock().is_ok_and(|p| p.get(&target).is_some_and(|(until, _)| Instant::now() < *until))
}

fn try_direct(sh: &Shared, target: Target) -> Option<WebSocket> {
    let domains = ws_domains(target.0, target.1);
    let mut redirects = 0;
    for domain in &domains {
        match WebSocket::connect(domain, WS_TIMEOUT_MS) {
            Ok(ws) => {
                if let Ok(mut p) = sh.pause.lock() {
                    p.remove(&target);
                }
                return Some(ws);
            }
            Err(ConnectError::Redirect(_)) => redirects += 1,
            Err(ConnectError::Failed(_)) => {}
        }
    }
    let label = format!("DC{}{}", target.0, if target.1 { " (медиа)" } else { "" });
    if redirects == domains.len() {
        if let Ok(mut r) = sh.redirected.lock() {
            r.insert(target);
        }
        (sh.log)(format!("Telegram {label}: веб-вход отвечает переадресацией — дальше без него"));
    } else if let Ok(mut p) = sh.pause.lock() {
        // Пауза растёт с каждой неудачей подряд: 30 с, 1 мин, 2 мин … 10 мин.
        let streak = p.get(&target).map_or(1, |(_, s)| s + 1);
        let pause = (FAIL_COOLDOWN * 2u32.pow((streak - 1).min(10))).min(MAX_COOLDOWN);
        p.insert(target, (Instant::now() + pause, streak));
        if streak == 1 {
            let via = if sh.options.cloudflare { " — соединения идут через Cloudflare" } else { "" };
            (sh.log)(format!("Telegram {label}: веб-вход не отвечает{via}"));
        }
    }
    None
}

/// kws{DC}.<домен>: сработавший для DC и случайные — одновременно, побеждает первый ответивший
/// (по очереди мёртвые домены задерживали Telegram на 8 с каждый).
fn try_cloudflare(sh: &Shared, dc: i32) -> Option<WebSocket> {
    let dc = if dc == 203 { 2 } else { dc };
    let (tx, rx) = mpsc::channel();
    for domain in sh.balancer.domains_for(dc).into_iter().take(CLOUDFLARE_ATTEMPTS) {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let ws = WebSocket::connect(&format!("kws{dc}.{domain}"), CLOUDFLARE_TIMEOUT_MS).ok();
            let _ = tx.send((domain, ws));
        });
    }
    drop(tx);
    for (domain, ws) in rx {
        if let Some(ws) = ws {
            sh.balancer.worked(dc, &domain);
            return Some(ws);
        }
    }
    (sh.log)(format!("Telegram DC{dc}: резерв через Cloudflare не ответил ({CLOUDFLARE_ATTEMPTS} домена)"));
    None
}

/// Клиент ⇄ WebSocket с перешифрованием; к Telegram — по одному пакету MTProto на кадр.
fn bridge_ws(sh: &Arc<Shared>, mut client: TcpStream, ws: WebSocket, c: Ciphers, mut splitter: PacketSplitter) -> io::Result<()> {
    let Ciphers { mut from_client, mut to_client, mut to_telegram, mut from_telegram } = c;
    let ws = Arc::new(ws);
    let (ws_down, mut client_down, stats) = (Arc::clone(&ws), client.try_clone()?, Arc::clone(&sh.stats));
    let down = std::thread::spawn(move || {
        let mut buf = vec![0u8; BUFFER];
        while let Ok(n) = ws_down.recv(&mut buf) {
            if n == 0 {
                break;
            }
            stats.down.fetch_add(n as u64, Ordering::Relaxed);
            from_telegram.apply(&mut buf[..n]);
            to_client.apply(&mut buf[..n]);
            if client_down.write_all(&buf[..n]).is_err() {
                break;
            }
        }
        let _ = client_down.shutdown(Shutdown::Both);
    });

    let mut buf = vec![0u8; BUFFER];
    'up: while let Ok(n) = client.read(&mut buf) {
        if n == 0 {
            break;
        }
        sh.stats.up.fetch_add(n as u64, Ordering::Relaxed);
        let data = &mut buf[..n];
        from_client.apply(data);
        let plain = data.to_vec();
        to_telegram.apply(data);
        for part in splitter.split(data, &plain) {
            if ws.send(&part).is_err() {
                break 'up;
            }
        }
    }
    if let Some(tail) = splitter.flush() {
        let _ = ws.send(&tail);
    }
    ws.close(); // прерывает приём во втором потоке
    let _ = down.join();
    let _ = client.shutdown(Shutdown::Both);
    Ok(())
}

fn bridge_tcp(sh: &Arc<Shared>, client: TcpStream, remote: TcpStream, c: Ciphers) -> io::Result<()> {
    let Ciphers { from_client, to_client, to_telegram, from_telegram } = c;
    let (client2, remote2, stats) = (client.try_clone()?, remote.try_clone()?, Arc::clone(&sh.stats));
    let down = std::thread::spawn(move || pipe(remote2, client2, from_telegram, to_client, &stats.down));
    pipe(client, remote, from_client, to_telegram, &sh.stats.up);
    let _ = down.join();
    Ok(())
}

/// Перешифровка в одну сторону; когда сторона закрылась — закрываем обе, чтобы встречный поток тоже завершился.
fn pipe(mut from: TcpStream, mut to: TcpStream, mut decrypt: crate::crypto::AesCtr, mut encrypt: crate::crypto::AesCtr, counter: &AtomicU64) {
    let mut buf = vec![0u8; BUFFER];
    while let Ok(n) = from.read(&mut buf) {
        if n == 0 {
            break;
        }
        counter.fetch_add(n as u64, Ordering::Relaxed);
        decrypt.apply(&mut buf[..n]);
        encrypt.apply(&mut buf[..n]);
        if to.write_all(&buf[..n]).is_err() {
            break;
        }
    }
    let _ = from.shutdown(Shutdown::Both);
    let _ = to.shutdown(Shutdown::Both);
}
