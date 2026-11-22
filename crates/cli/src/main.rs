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

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vx_core::desync::corrupt_tcp_checksum;
use vx_core::{Action, Fooling, Proto, QuicMode, SplitPos, Strategy, Transport, apply, classify, parse};
use vx_divert::{Divert, FLAG_SNIFF};

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

/// Фильтр в ядре: только первые пакеты, которые приёмы меняют. Весь остальной трафик в программу не попадает.
fn run_filter(s: &Strategy) -> String {
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

fn run(args: &[String]) -> Result<(), String> {
    let strategy = parse_strategy(args)?;
    let seconds = seconds(args)?;
    let dir = engine_dir(args).map_err(|e| e.to_string())?;
    let filter = run_filter(&strategy);
    vx_divert::check_filter(&dir, &filter).map_err(|e| e.to_string())?;
    if args.iter().any(|a| a == "--check") {
        println!("Фильтр и приёмы в порядке: {strategy:?}");
        return Ok(());
    }
    let divert = Arc::new(Divert::open(&dir, &filter, 0, 0).map_err(|e| e.to_string())?);
    println!("Обход запущен, {}.", stop_after(&divert, seconds));
    println!("Приёмы: {strategy:?}");

    let started = Instant::now();
    let mut seen: HashSet<String> = HashSet::new();
    let (mut changed, mut passed, mut dropped, mut send_errors) = (0u64, 0u64, 0u64, 0u64);
    let mut buf = vec![0u8; 0xffff];
    while let Ok((len, addr)) = divert.recv(&mut buf) {
        let packet = &buf[..len];
        let result = match apply(packet, &strategy) {
            Action::Pass => {
                passed += 1;
                divert.send(packet, &addr)
            }
            Action::Drop => {
                dropped += 1;
                Ok(())
            }
            Action::Send(outs) => {
                changed += 1;
                if let Some(label) = describe(packet).filter(|l| seen.insert(l.clone())) {
                    println!("{:>7.1} с  {label}", started.elapsed().as_secs_f32());
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
        if let Err(e) = result {
            send_errors += 1;
            if send_errors <= 3 {
                eprintln!("Не отправлен пакет: {e}");
            }
        }
    }
    println!("Готово: изменено {changed}, пропущено {passed}, отброшено QUIC {dropped}, ошибок отправки {send_errors}.");
    Ok(())
}

/// «TLS  youtube.com → 142.250.74.46:443» для журнала.
fn describe(packet: &[u8]) -> Option<String> {
    let pkt = parse(packet)?;
    let (kind, host) = match classify(&pkt)? {
        Proto::Tls { host, .. } => ("TLS ", host),
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
    Some(format!("{kind:<5} {host:<35} → {}:{port}", pkt.dst))
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

    #[test]
    fn filter_skips_quic_and_voice_when_not_needed() {
        let base = run_filter(&Strategy { quic: QuicMode::Pass, ..Strategy::default() });
        assert!(!base.contains("udp"));
        assert!(run_filter(&Strategy { discord_voice: true, ..Strategy::default() }).contains("50000"));
    }
}
