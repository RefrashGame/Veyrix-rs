//! Окно Veyrix-rs: команды для интерфейса поверх `vx-engine` и события журнала.

use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::webview::PageLoadEvent;
use tauri::{AppHandle, Emitter, State};
use tauri_plugin_opener::OpenerExt;
use vx_engine::vx_core::{QuicMode, Strategy};
use vx_engine::{Config, Engine, Event, Stats};

/// Настройки из окна; хранятся в data\settings.json рядом с exe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct Settings {
    /// Автоподбор приёма для каждого сайта.
    auto: bool,
    /// QUIC (HTTP/3): fake, drop, pass.
    quic: String,
    /// DoH-сервер: off, cloudflare, google, quad9 или https://…
    doh: String,
    /// Фейки перед голосом Discord.
    discord_voice: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self { auto: true, quic: "fake".into(), doh: "off".into(), discord_voice: false }
    }
}

impl Settings {
    fn config(&self, dirs: &Dirs) -> Result<Config, String> {
        let quic = match self.quic.as_str() {
            "fake" => QuicMode::Fake,
            "drop" => QuicMode::Drop,
            "pass" => QuicMode::Pass,
            other => return Err(format!("QUIC: неизвестный режим «{other}»")),
        };
        Ok(Config {
            engine_dir: dirs.engine.clone(),
            data_dir: dirs.data.clone(),
            strategy: Strategy { quic, discord_voice: self.discord_voice, ..Strategy::default() },
            auto: self.auto,
            auto_test: false,
            doh: (self.doh != "off").then(|| self.doh.clone()),
        })
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct Status {
    running: bool,
    stats: StatsDto,
    doh_server: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct StatsDto {
    changed: u64,
    passed: u64,
    dropped: u64,
    send_errors: u64,
    doh_ok: u64,
    doh_fallback: u64,
}

impl From<Stats> for StatsDto {
    fn from(s: Stats) -> Self {
        Self {
            changed: s.changed,
            passed: s.passed,
            dropped: s.dropped,
            send_errors: s.send_errors,
            doh_ok: s.doh_ok,
            doh_fallback: s.doh_fallback,
        }
    }
}

/// Запись журнала для окна: вид и текст (время ставит окно при получении).
#[derive(Debug, Clone, Serialize)]
struct LogEntry {
    kind: &'static str,
    text: String,
}

fn log_entry(event: Event) -> LogEntry {
    match event {
        Event::Site { kind, host, target } => {
            LogEntry { kind: "site", text: format!("{kind} {} → {target}", if host.is_empty() { "—" } else { &host }) }
        }
        Event::Works { site, strategy } => LogEntry { kind: "works", text: format!("{site}: работает с «{strategy}»") },
        Event::Switched { site, from, to } => {
            LogEntry { kind: "switched", text: format!("{site}: не открывается с «{from}» → пробую «{to}»") }
        }
        Event::Warning(text) => LogEntry { kind: "warning", text },
    }
}

/// Папки рядом с exe: `engine` (WinDivert, если есть) и `data`.
struct Dirs {
    engine: PathBuf,
    data: PathBuf,
}

impl Dirs {
    fn near_exe() -> Self {
        let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(PathBuf::from)).unwrap_or_default();
        let nested = exe_dir.join("engine");
        let engine = if nested.join("WinDivert.dll").exists() { nested } else { exe_dir.clone() };
        Self { engine, data: exe_dir.join("data") }
    }

    fn dns_backup(&self) -> PathBuf {
        self.data.join("dns-backup.txt")
    }

    fn settings_file(&self) -> PathBuf {
        self.data.join("settings.json")
    }
}

struct AppState {
    dirs: Dirs,
    engine: Mutex<Option<Engine>>,
}

impl AppState {
    fn status(&self) -> Status {
        let engine = self.engine.lock().unwrap_or_else(|e| e.into_inner());
        Status {
            running: engine.is_some(),
            stats: engine.as_ref().map(|e| e.stats().into()).unwrap_or_default(),
            doh_server: engine.as_ref().and_then(|e| e.doh_server.clone()),
        }
    }
}

#[tauri::command]
fn load_settings(state: State<AppState>) -> Settings {
    std::fs::read_to_string(state.dirs.settings_file())
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

#[tauri::command]
fn save_settings(state: State<AppState>, settings: Settings) -> Result<(), String> {
    settings.config(&state.dirs)?; // не сохраняем то, с чем движок не запустится
    std::fs::create_dir_all(&state.dirs.data).map_err(|e| e.to_string())?;
    let json = serde_json::to_string_pretty(&settings).map_err(|e| e.to_string())?;
    std::fs::write(state.dirs.settings_file(), json).map_err(|e| e.to_string())
}

#[tauri::command]
fn engine_start(app: AppHandle, state: State<AppState>, settings: Settings) -> Result<Status, String> {
    let config = settings.config(&state.dirs)?;
    {
        let mut slot = state.engine.lock().map_err(|e| e.to_string())?;
        if slot.is_none() {
            let sink: vx_engine::Sink = std::sync::Arc::new(move |event| {
                let _ = app.emit("vx-event", log_entry(event));
            });
            *slot = Some(Engine::start(config, sink)?);
        }
    }
    Ok(state.status())
}

#[tauri::command]
fn engine_stop(state: State<AppState>) -> Status {
    let engine = state.engine.lock().unwrap_or_else(|e| e.into_inner()).take();
    let last = engine.map(Engine::stop).map(StatsDto::from).unwrap_or_default();
    Status { running: false, stats: last, doh_server: None }
}

#[tauri::command]
fn engine_status(state: State<AppState>) -> Status {
    state.status()
}

/// DNS Windows для окна: адаптеры и заменён ли DNS программой.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct SysDns {
    adapters: Vec<AdapterDns>,
    replaced: bool,
    servers: [&'static str; 2],
}

#[derive(Debug, Clone, Serialize)]
struct AdapterDns {
    name: String,
    /// Пусто — автоматически (DHCP).
    dns: String,
}

fn sysdns_dto(status: vx_sysdns::Status) -> SysDns {
    SysDns {
        adapters: status.adapters.into_iter().map(|a| AdapterDns { name: a.name, dns: a.manual_dns }).collect(),
        replaced: status.replaced,
        servers: vx_sysdns::YANDEX,
    }
}

#[tauri::command]
fn sysdns_status(state: State<AppState>) -> Result<SysDns, String> {
    vx_sysdns::status(&state.dirs.dns_backup()).map(sysdns_dto).map_err(|e| e.to_string())
}

/// Меняет системную настройку: окно спрашивает подтверждение до вызова.
#[tauri::command]
fn sysdns_apply(state: State<AppState>) -> Result<SysDns, String> {
    let backup = state.dirs.dns_backup();
    vx_sysdns::apply(&vx_sysdns::YANDEX, &backup).map_err(|e| e.to_string())?;
    sysdns_status(state)
}

#[tauri::command]
fn sysdns_restore(state: State<AppState>) -> Result<SysDns, String> {
    vx_sysdns::restore(&state.dirs.dns_backup()).map_err(|e| e.to_string())?;
    sysdns_status(state)
}

fn external_navigation_plugin<R: tauri::Runtime>() -> tauri::plugin::TauriPlugin<R> {
    tauri::plugin::Builder::<R>::new("external-navigation")
        .on_navigation(|webview, url| {
            let internal = url.scheme() == "tauri"
                || matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "tauri.localhost" | "::1"));
            if internal {
                return true;
            }
            if matches!(url.scheme(), "http" | "https" | "mailto" | "tel") {
                let _ = webview.opener().open_url(url.as_str(), None::<&str>);
                return false;
            }
            true
        })
        .build()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    use tauri_plugin_log::{Target, TargetKind};
    tauri::Builder::default()
        .plugin(
            tauri_plugin_log::Builder::new()
                .targets([Target::new(TargetKind::Stdout), Target::new(TargetKind::LogDir { file_name: None })])
                .build(),
        )
        .plugin(tauri_plugin_opener::init())
        .plugin(external_navigation_plugin())
        .manage(AppState { dirs: Dirs::near_exe(), engine: Mutex::new(None) })
        .invoke_handler(tauri::generate_handler![
            load_settings,
            save_settings,
            engine_start,
            engine_stop,
            engine_status,
            sysdns_status,
            sysdns_apply,
            sysdns_restore
        ])
        .on_page_load(|webview, payload| {
            if webview.label() == "main" && matches!(payload.event(), PageLoadEvent::Finished) {
                let _ = webview.window().show();
            }
        })
        .run(tauri::generate_context!())
        .expect("не запустилось окно Veyrix");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_json_roundtrip_and_validation() {
        let dirs = Dirs { engine: "e".into(), data: "d".into() };
        let s: Settings = serde_json::from_str(r#"{"quic":"drop","doh":"quad9"}"#).unwrap();
        assert_eq!(s, Settings { quic: "drop".into(), doh: "quad9".into(), ..Settings::default() });
        let c = s.config(&dirs).unwrap();
        assert_eq!((c.strategy.quic, c.doh.as_deref(), c.auto), (QuicMode::Drop, Some("quad9"), true));
        assert_eq!(Settings::default().config(&dirs).unwrap().doh, None);
        assert!(Settings { quic: "x".into(), ..Settings::default() }.config(&dirs).is_err());
    }
}
