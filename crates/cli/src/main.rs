//! vx — консольный Veyrix-rs.
//!
//! vx sniff [--seconds N] [--engine ПАПКА]
//!     Наблюдение: какие сайты открываются (TLS SNI, HTTP Host), QUIC и голос Discord.
//!     Режим копии (WinDivert SNIFF): пакеты идут как обычно, программа их не задерживает и не меняет.
//!
//! vx run [приёмы] [--seconds N] [--engine ПАПКА]
//!     Обход: первые пакеты соединений (TLS ClientHello, HTTP-запрос, QUIC Initial) заменяются приёмами.
//!     --split 1,midsld        где резать запрос: число байт, host (начало имени), midsld (середина домена), none
//!     --no-disorder           слать куски по порядку (по умолчанию — в обратном)
//!     --no-fake               без фейкового запроса перед настоящим
//!     --fooling badseq        как фейк не дойдёт до сервера: badseq, badsum, ttl=N (через запятую)
//!     --repeats 6             сколько раз отправить фейк
//!     --quic fake             QUIC (HTTP/3): fake, drop (браузер уйдёт на TCP), pass
//!     --discord-voice         фейки перед голосом Discord (по умолчанию голос не трогается)
//!     --check                 только проверить параметры и фильтр, без перехвата
//!     --auto                  автоподбор: свой приём для каждого сайта, при сбоях — следующий (--split/--fooling
//!                             и т. п. тогда не действуют); выбор хранится в data\tuning.txt рядом с vx.exe
//!     --auto-test             то же, но все сайты начинают «без приёмов» и файл не читается — проверка, что
//!                             заблокированный сайт сам переходит на рабочий приём
//!     --doh cloudflare        DNS через DNS-over-HTTPS: cloudflare, google, quad9 или https://…; если DoH не ответил —
//!                             запрос уходит обычному DNS как раньше
//!
//! vx sysdns status | set | restore
//!     DNS Windows: показать; заменить на Яндекс (77.88.8.8, 77.88.8.1) с резервной копией в data\dns-backup.txt;
//!     вернуть исходный. Каждый раз очищается кэш DNS. Меняет системную настройку — нужен администратор.
//!
//! vx doh ИМЯ [--doh cloudflare]
//!     Проверка DoH без перехвата: адреса сайта через DNS-over-HTTPS.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vx_core::dns;
use vx_core::{Fooling, Proto, QuicMode, SplitPos, Strategy, Transport, classify, parse};
use vx_divert::{Divert, FLAG_SNIFF};
use vx_doh::Doh;
use vx_engine::{Config, Engine, Event as EngineEvent};

/// Только исходящие пакеты с данными на порты, которые разбираем; в ядре, чтобы не копировать весь трафик.
const SNIFF_FILTER: &str = "outbound and !loopback and !impostor and (\
    (tcp.PayloadLength > 0 and (tcp.DstPort == 443 or tcp.DstPort == 80)) or \
    udp.DstPort == 443 or (udp.DstPort >= 19294 and udp.DstPort <= 19344) or \
    (udp.DstPort >= 50000 and udp.DstPort <= 50100))";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("sniff") => sniff(&args[1..]),
        Some("run") => run(&args[1..]),
        Some("doh") => doh_test(&args[1..]),
        Some("sysdns") => sysdns(&args[1..]),
        _ => {
            eprintln!("Использование: vx sniff | vx run [приёмы] — подробности в docs/DEVELOPMENT.md");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Ошибка: {e}");
            ExitCode::FAILURE
        }
    }
}

fn option(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

/// Папка с WinDivert: --engine, иначе `engine` рядом с vx.exe, иначе сама папка vx.exe.
fn engine_dir(args: &[String]) -> std::io::Result<PathBuf> {
    if let Some(dir) = option(args, "--engine") {
        return Ok(dir.into());
    }
    let exe_dir = std::env::current_exe()?.parent().map(PathBuf::from).unwrap_or_default();
    let nested = exe_dir.join("engine");
    Ok(if nested.join("WinDivert.dll").exists() { nested } else { exe_dir })
}

fn seconds(args: &[String]) -> Result<Option<u64>, String> {
    option(args, "--seconds").map(|s| s.parse::<u64>().map_err(|_| format!("--seconds: не число «{s}»"))).transpose()
}

/// Остановить перехват через N секунд (иначе — до Ctrl+C; при выходе драйвер сразу пускает трафик напрямую).
fn stop_after(divert: &Arc<Divert>, seconds: Option<u64>) -> String {
    match seconds {
        Some(s) => {
            let d = Arc::clone(divert);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(s));
                let _ = d.shutdown();
            });
            format!("{s} с")
        }
        None => "остановка — Ctrl+C".into(),
    }
}

fn sniff(args: &[String]) -> Result<(), String> {
    let seconds = seconds(args)?;
    let dir = engine_dir(args).map_err(|e| e.to_string())?;
    let divert = Arc::new(Divert::open(&dir, SNIFF_FILTER, 0, FLAG_SNIFF).map_err(|e| e.to_string())?);
    println!("Наблюдение запущено (пакеты не меняются), {}.", stop_after(&divert, seconds));

    let started = Instant::now();
    let mut seen: HashSet<(&'static str, String, IpAddr)> = HashSet::new();
    let (mut packets, mut recognized) = (0u64, 0u64);
    let mut buf = vec![0u8; 0xffff];
    while let Ok((len, _addr)) = divert.recv(&mut buf) {
        packets += 1;
        let Some(pkt) = parse(&buf[..len]) else { continue };
        let Some(proto) = classify(&pkt) else { continue };
        recognized += 1;
        let port = match pkt.transport {
            Transport::Tcp(t) => t.dst_port,
            Transport::Udp(u) => u.dst_port,
            Transport::Other(_) => 0,
        };
        let (kind, what) = match proto {
            Proto::Tls { host, .. } => ("TLS ", host.to_string()),
            Proto::Http { host, .. } => ("HTTP", host.to_string()),
            Proto::Quic => ("QUIC", String::new()),
            Proto::DiscordVoice => ("ГОЛОС", "Discord IP discovery".into()),
            Proto::Stun => ("STUN", String::new()),
        };
        // Повторы (тот же протокол, сайт и сервер) не печатаем — журнал остаётся читаемым.
        if seen.insert((kind, what.clone(), pkt.dst)) {
            println!("{:>7.1} с  {kind:<5} {:<40} {what}", started.elapsed().as_secs_f32(), format!("{}:{port}", pkt.dst));
        }
    }
    println!("Готово: пакетов {packets}, распознано {recognized}, разных записей {}.", seen.len());
    Ok(())
}

fn parse_strategy(args: &[String]) -> Result<Strategy, String> {
    let mut s = Strategy::default();
    if let Some(list) = option(args, "--split") {
        s.split = list
            .split(',')
            .filter(|p| *p != "none")
            .map(|p| match p {
                "host" => Ok(SplitPos::Host),
                "midsld" => Ok(SplitPos::MidSld),
                n => n.parse().map(SplitPos::At).map_err(|_| format!("--split: непонятная позиция «{n}»")),
            })
            .collect::<Result<_, _>>()?;
    }
    if let Some(list) = option(args, "--fooling") {
        s.fooling = list
            .split(',')
            .map(|f| match f {
                "badseq" => Ok(Fooling::BadSeq),
                "badsum" => Ok(Fooling::BadSum),
                f => f
                    .strip_prefix("ttl=")
                    .and_then(|n| n.parse().ok())
                    .map(Fooling::Ttl)
                    .ok_or_else(|| format!("--fooling: непонятный способ «{f}» (badseq, badsum, ttl=N)")),
            })
            .collect::<Result<_, _>>()?;
    }
    if let Some(n) = option(args, "--repeats") {
        s.repeats = n.parse().map_err(|_| format!("--repeats: не число «{n}»"))?;
    }
    if let Some(q) = option(args, "--quic") {
        s.quic = match q.as_str() {
            "fake" => QuicMode::Fake,
            "drop" => QuicMode::Drop,
            "pass" => QuicMode::Pass,
            _ => return Err(format!("--quic: fake, drop или pass, а не «{q}»")),
        };
    }
    s.fake = !args.iter().any(|a| a == "--no-fake");
    s.disorder = !args.iter().any(|a| a == "--no-disorder");
    s.discord_voice = args.iter().any(|a| a == "--discord-voice");
    Ok(s)
}

fn run(args: &[String]) -> Result<(), String> {
    let config = Config {
        engine_dir: engine_dir(args).map_err(|e| e.to_string())?,
        data_dir: std::env::current_exe().map_err(|e| e.to_string())?.with_file_name("data"),
        strategy: parse_strategy(args)?,
        auto: args.iter().any(|a| a == "--auto"),
        auto_test: args.iter().any(|a| a == "--auto-test"),
        doh: option(args, "--doh"),
    };
    let seconds = seconds(args)?;
    if args.iter().any(|a| a == "--check") {
        Engine::check(&config)?;
        println!("Фильтр и приёмы в порядке: {:?}", config.strategy);
        return Ok(());
    }

    let started = Instant::now();
    let sink: vx_engine::Sink = Arc::new(move |event| {
        let t = started.elapsed().as_secs_f32();
        match event {
            EngineEvent::Site { kind, host, target } => println!("{t:>7.1} с  {kind:<5} {host:<35} → {target}"),
            EngineEvent::Works { site, strategy } => println!("  {site}: работает с «{strategy}»"),
            EngineEvent::Switched { site, from, to } => println!("  {site}: не открывается с «{from}» → пробую «{to}»"),
            EngineEvent::Warning(text) => eprintln!("{text}"),
        }
    });
    let strategy = config.strategy.clone();
    let engine = Engine::start(config, sink)?;
    println!("Обход запущен, {}.", seconds.map_or("остановка — Ctrl+C".into(), |s| format!("{s} с")));
    println!("Приёмы: {strategy:?}");
    if let Some(server) = &engine.doh_server {
        println!("DNS: через DoH {server}, при сбое — обычный DNS.");
    }
    if let Some(file) = &engine.tuning_file {
        println!("Автоподбор: для каждого сайта свой приём, при сбоях — следующий; выбор хранится в {}.", file.display());
    }

    // Без --seconds работает до Ctrl+C: процесс завершается, драйвер сам пускает трафик напрямую.
    match seconds {
        Some(s) => std::thread::sleep(Duration::from_secs(s)),
        None => loop {
            std::thread::sleep(Duration::from_secs(3600));
        },
    }
    let s = engine.stop();
    println!("Готово: изменено {}, пропущено {}, отброшено QUIC {}, ошибок отправки {}.", s.changed, s.passed, s.dropped, s.send_errors);
    if s.doh_ok + s.doh_fallback > 0 {
        println!("DNS: через DoH {}, обычным DNS (DoH не ответил) {}.", s.doh_ok, s.doh_fallback);
    }
    Ok(())
}

fn sysdns(args: &[String]) -> Result<(), String> {
    let backup = std::env::current_exe().map_err(|e| e.to_string())?.with_file_name("data").join("dns-backup.txt");
    let show = |list: &[vx_sysdns::Adapter]| {
        for a in list {
            let dns = if a.manual_dns.is_empty() { "автоматически (DHCP)" } else { &a.manual_dns };
            println!("  {:<30} {dns}", a.name);
        }
    };
    match args.first().map(String::as_str) {
        Some("status") | None => {
            let s = vx_sysdns::status(&backup).map_err(|e| e.to_string())?;
            show(&s.adapters);
            println!("{}", if s.replaced { "DNS заменён программой — вернуть: vx sysdns restore" } else { "DNS программой не менялся." });
        }
        Some("set") => {
            let list = vx_sysdns::apply(&vx_sysdns::YANDEX, &backup).map_err(|e| e.to_string())?;
            show(&list);
            println!("DNS заменён на {}, кэш очищен. Исходный сохранён в {}.", vx_sysdns::YANDEX.join(", "), backup.display());
        }
        Some("restore") => {
            let n = vx_sysdns::restore(&backup).map_err(|e| e.to_string())?;
            println!("Исходный DNS возвращён на адаптерах: {n}, кэш очищен.");
        }
        Some(other) => return Err(format!("vx sysdns: status, set или restore, а не «{other}»")),
    }
    Ok(())
}

fn doh_test(args: &[String]) -> Result<(), String> {
    let name = args.first().filter(|a| !a.starts_with("--")).ok_or("Использование: vx doh ИМЯ [--doh cloudflare]")?;
    let provider = option(args, "--doh").unwrap_or_else(|| "cloudflare".into());
    let doh = Doh::new(&provider).map_err(|e| e.to_string())?;
    for (kind, qtype) in [("A", dns::TYPE_A), ("AAAA", dns::TYPE_AAAA)] {
        let query = dns::build_query(0x5678, name, qtype);
        let started = Instant::now();
        let answer = doh.query(&query).map_err(|e| e.to_string())?;
        if !dns::is_answer_to(&query, &answer) {
            return Err(format!("{provider}: ответ не на этот запрос"));
        }
        let list: Vec<String> = dns::addresses(&answer).iter().map(ToString::to_string).collect();
        println!("{kind:<4} {name} через {} за {} мс: {}", doh.host, started.elapsed().as_millis(),
            if list.is_empty() { "нет записей".into() } else { list.join(", ") });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn strategy_from_arguments() {
        let s = parse_strategy(&args("--split 2,host --fooling ttl=5,badsum --repeats 3 --quic drop --no-disorder --discord-voice")).unwrap();
        assert_eq!(s.split, vec![SplitPos::At(2), SplitPos::Host]);
        assert_eq!(s.fooling, vec![Fooling::Ttl(5), Fooling::BadSum]);
        assert_eq!((s.repeats, s.quic, s.disorder, s.fake, s.discord_voice), (3, QuicMode::Drop, false, true, true));
        assert_eq!(parse_strategy(&args("--split none")).unwrap().split, vec![]);
        assert!(parse_strategy(&args("--fooling ttl=x")).is_err());
    }
}
