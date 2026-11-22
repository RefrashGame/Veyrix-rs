//! vx — консольный Veyrix-rs.
//!
//! vx sniff [--seconds N] [--engine ПАПКА]
//!     Наблюдение: какие сайты открываются (TLS SNI, HTTP Host), QUIC и голос Discord.
//!     Режим копии (WinDivert SNIFF): пакеты идут как обычно, программа их не задерживает и не меняет.

use std::collections::HashSet;
use std::net::IpAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vx_core::{Proto, Transport, classify, parse};
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
        _ => {
            eprintln!("Использование: vx sniff [--seconds N] [--engine ПАПКА с WinDivert.dll и WinDivert64.sys]");
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

fn sniff(args: &[String]) -> Result<(), String> {
    let seconds = match option(args, "--seconds") {
        Some(s) => Some(s.parse::<u64>().map_err(|_| format!("--seconds: не число «{s}»"))?),
        None => None,
    };
    let dir = engine_dir(args).map_err(|e| e.to_string())?;
    let divert = Arc::new(Divert::open(&dir, SNIFF_FILTER, 0, FLAG_SNIFF).map_err(|e| e.to_string())?);
    println!("Наблюдение запущено (пакеты не меняются){}.", match seconds {
        Some(s) => format!(", {s} с"),
        None => ", остановка — Ctrl+C".into(),
    });

    if let Some(s) = seconds {
        let d = Arc::clone(&divert);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(s));
            let _ = d.shutdown();
        });
    }

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
