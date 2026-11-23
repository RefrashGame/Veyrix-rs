//! Окно Veyrix-rs: команды для интерфейса поверх `vx-engine` и события журнала.

use std::path::PathBuf;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use tauri::webview::PageLoadEvent;
use tauri::{AppHandle, Emitter, Manager, State};
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
    /// Запуск из автозапуска: окно не показывается, обход стартует сам.
    autostart: bool,
}

fn read_settings(dirs: &Dirs) -> Settings {
    std::fs::read_to_string(dirs.settings_file()).ok().and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
}

/// Запуск обхода — общий для кнопки, трея и автозапуска. Окну сообщается новое состояние (`vx-status`).
fn start_engine(app: &AppHandle, state: &AppState, settings: &Settings) -> Result<Status, String> {
    let config = settings.config(&state.dirs)?;
    {
        let mut slot = state.engine.lock().map_err(|e| e.to_string())?;
        if slot.is_none() {
            let events = app.clone();
            let sink: vx_engine::Sink = std::sync::Arc::new(move |event| {
                let _ = events.emit("vx-event", log_entry(event));
            });
            *slot = Some(Engine::start(config, sink)?);
        }
    }
    let status = state.status();
    let _ = app.emit("vx-status", &status);
    Ok(status)
}

fn stop_engine(app: &AppHandle, state: &AppState) -> Status {
    let engine = state.engine.lock().unwrap_or_else(|e| e.into_inner()).take();
    let last = engine.map(Engine::stop).map(StatsDto::from).unwrap_or_default();
    let status = Status { running: false, stats: last, doh_server: None };
    let _ = app.emit("vx-status", &status);
    status
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
    read_settings(&state.dirs)
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
    start_engine(&app, &state, &settings)
}

#[tauri::command]
fn engine_stop(app: AppHandle, state: State<AppState>) -> Status {
    stop_engine(&app, &state)
}

#[derive(Debug, Clone, Serialize)]
struct CheckDto {
    name: &'static str,
    level: &'static str,
    detail: String,
    hint: Option<&'static str>,
}

/// Диагностика — в отдельном потоке (`async`): проверка DoH идёт до нескольких секунд, окно не должно замирать.
#[tauri::command(async)]
fn diagnostics(state: State<AppState>) -> Vec<CheckDto> {
    vx_diag::evaluate(&vx_diag::snapshot(&state.dirs.engine))
        .into_iter()
        .map(|c| CheckDto {
            name: c.name,
            level: match c.level {
                vx_diag::Level::Ok => "ok",
                vx_diag::Level::Warning => "warning",
                vx_diag::Level::Failed => "failed",
            },
            detail: c.detail,
            hint: c.hint,
        })
        .collect()
}

/// Автозапуск — задача Планировщика с наивысшими правами: ключ Run не запускает программы, которым нужен
/// администратор. Имя отличается от задачи Veyrix на C# («Veyrix»), чтобы они не мешали друг другу.
const AUTOSTART_TASK: &str = "Veyrix-rs";
const AUTOSTART_ARG: &str = "--autostart";

fn schtasks(args: &[&str]) -> Result<(), String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("schtasks.exe")
        .args(args)
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        // Вывод schtasks — в кодировке консоли; для сообщения хватит кода выхода и текста как есть.
        Err(format!("schtasks: код {}: {}", out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stderr).trim()))
    }
}

#[tauri::command(async)]
fn autostart_status() -> bool {
    schtasks(&["/Query", "/TN", AUTOSTART_TASK]).is_ok()
}

/// Включает или выключает автозапуск при входе в Windows (через 10 с — успевает подняться сеть).
#[tauri::command(async)]
fn autostart_set(enabled: bool) -> Result<bool, String> {
    if enabled {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let run = format!("\"{}\" {AUTOSTART_ARG}", exe.display());
        schtasks(&["/Create", "/TN", AUTOSTART_TASK, "/TR", &run, "/SC", "ONLOGON", "/RL", "HIGHEST", "/DELAY", "0000:10", "/F"])?;
    } else if autostart_status() {
        schtasks(&["/Delete", "/TN", AUTOSTART_TASK, "/F"])?;
    }
    Ok(autostart_status())
}

fn show_window(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

/// Значок в трее: левый клик — окно; меню — открыть, запустить/остановить обход, выход.
fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
    let open = MenuItem::with_id(app, "open", "Открыть Veyrix", true, None::<&str>)?;
    let toggle = MenuItem::with_id(app, "toggle", "Запустить / остановить обход", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выход", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &toggle, &quit])?;
    let mut tray = TrayIconBuilder::with_id("main").tooltip("Veyrix").menu(&menu).show_menu_on_left_click(false);
    if let Some(icon) = app.default_window_icon() {
        tray = tray.icon(icon.clone());
    }
    tray.on_menu_event(|app, event| {
        let state = app.state::<AppState>();
        match event.id.as_ref() {
            "open" => show_window(app),
            "toggle" => {
                let running = state.engine.lock().map(|e| e.is_some()).unwrap_or(false);
                if running {
                    stop_engine(app, &state);
                } else if let Err(e) = start_engine(app, &state, &read_settings(&state.dirs)) {
                    let _ = app.emit("vx-event", LogEntry { kind: "warning", text: e });
                    show_window(app);
                }
            }
            "quit" => {
                stop_engine(app, &state);
                app.exit(0);
            }
            _ => {}
        }
    })
    .on_tray_icon_event(|tray, event| {
        if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
            show_window(tray.app_handle());
        }
    })
    .build(app)?;
    Ok(())
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
        .manage(AppState {
            dirs: Dirs::near_exe(),
            engine: Mutex::new(None),
            autostart: std::env::args().any(|a| a == AUTOSTART_ARG),
        })
        .invoke_handler(tauri::generate_handler![
            load_settings,
            save_settings,
            engine_start,
            engine_stop,
            engine_status,
            sysdns_status,
            sysdns_apply,
            sysdns_restore,
            diagnostics,
            autostart_status,
            autostart_set
        ])
        .setup(|app| {
            build_tray(app)?;
            let state = app.state::<AppState>();
            if state.autostart {
                // При входе в Windows: обход с сохранёнными настройками, окно скрыто (значок в трее).
                if let Err(e) = start_engine(app.handle(), &state, &read_settings(&state.dirs)) {
                    log::error!("автозапуск обхода: {e}");
                    show_window(app.handle());
                }
            }
            Ok(())
        })
        .on_window_event(|window, event| {
            // Крестик прячет окно в трей: обход продолжает работать. Выход — из меню значка.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .on_page_load(|webview, payload| {
            let autostart = webview.app_handle().state::<AppState>().autostart;
            if webview.label() == "main" && matches!(payload.event(), PageLoadEvent::Finished) && !autostart {
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
