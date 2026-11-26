//! Встроенный Cloudflare WARP без официального клиента: две открытые программы без изменений рядом с Veyrix
//! (`engine\warp\`): wgcf (MIT) регистрирует бесплатный аккаунт WARP и пишет профиль WireGuard, wireproxy (ISC)
//! поднимает по этому профилю WireGuard в обычном процессе (без драйвера) и даёт локальный SOCKS5 на 127.0.0.1.
//! Через этот SOCKS5 обход по IP (`vx-reroute`, режим WARP) отправляет соединения к заблокированным адресам.
//! wireproxy живёт в job object с «убить при закрытии»: при любом завершении Veyrix (выход, установщик, сбой)
//! Windows закрывает дескриптор job и завершает wireproxy — иначе он держал файл и мешал обновлению.

use std::ffi::c_void;
use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Порт SOCKS5 встроенного WARP (не 40000 официального клиента — чтобы не спорить с ним за порт).
pub const PORT: u16 = 40100;

pub fn proxy_addr() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], PORT))
}

const PROFILE: &str = "wgcf-profile.conf";
const ACCOUNT: &str = "wgcf-account.toml";
const CONFIG: &str = "wireproxy.conf";
const LOG: &str = "wireproxy.log";

pub struct Warp {
    /// Папка с wgcf.exe и wireproxy.exe.
    bin: PathBuf,
    /// Папка данных WARP: аккаунт, профиль, настройки wireproxy.
    data: PathBuf,
}

/// Запущенный wireproxy; удаление останавливает процесс.
pub struct Process {
    child: Child,
    // Закрытие дескриптора (в том числе системой при падении Veyrix) завершает wireproxy.
    _job: Option<Job>,
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Process {
    /// Процесс ещё работает.
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}

/// Job object Windows с JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
struct Job(*mut c_void);

// SAFETY: дескриптор job — обычный HANDLE ядра, его можно закрывать из любого потока.
unsafe impl Send for Job {}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: дескриптор наш, закрывается один раз.
        unsafe { CloseHandle(self.0) };
    }
}

#[repr(C)]
#[derive(Default)]
struct BasicLimit {
    per_process_user_time: i64,
    per_job_user_time: i64,
    limit_flags: u32,
    min_working_set: usize,
    max_working_set: usize,
    active_process_limit: u32,
    affinity: usize,
    priority_class: u32,
    scheduling_class: u32,
}

/// JOBOBJECT_EXTENDED_LIMIT_INFORMATION.
#[repr(C)]
#[derive(Default)]
struct ExtendedLimit {
    basic: BasicLimit,
    io: [u64; 6],
    process_memory_limit: usize,
    job_memory_limit: usize,
    peak_process_memory: usize,
    peak_job_memory: usize,
}

const _: () = assert!(size_of::<ExtendedLimit>() == 144);

#[link(name = "kernel32", kind = "raw-dylib")]
unsafe extern "system" {
    fn CreateJobObjectW(attributes: *mut c_void, name: *const u16) -> *mut c_void;
    fn SetInformationJobObject(job: *mut c_void, class: u32, info: *const c_void, len: u32) -> i32;
    fn AssignProcessToJobObject(job: *mut c_void, process: *mut c_void) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}

/// Привязывает процесс к новому job, который завершит его при закрытии. `None` — не вышло (тогда wireproxy
/// остановится только при обычном выходе из Veyrix).
fn kill_on_close(child: &Child) -> Option<Job> {
    const EXTENDED_LIMIT_INFORMATION: u32 = 9;
    const KILL_ON_JOB_CLOSE: u32 = 0x2000;
    // SAFETY: без атрибутов и имени; результат проверяется.
    let job = unsafe { CreateJobObjectW(std::ptr::null_mut(), std::ptr::null()) };
    if job.is_null() {
        return None;
    }
    let job = Job(job);
    let mut info = ExtendedLimit::default();
    info.basic.limit_flags = KILL_ON_JOB_CLOSE;
    // SAFETY: структура нужного размера живёт до конца вызова; дескриптор процесса принадлежит `child`.
    let ok = unsafe {
        SetInformationJobObject(job.0, EXTENDED_LIMIT_INFORMATION, (&raw const info).cast(), size_of::<ExtendedLimit>() as u32) != 0
            && AssignProcessToJobObject(job.0, child.as_raw_handle()) != 0
    };
    ok.then_some(job)
}

impl Warp {
    pub fn new(bin: PathBuf, data: PathBuf) -> Self {
        Self { bin, data }
    }

    /// Программы WARP есть рядом с Veyrix.
    pub fn installed(&self) -> bool {
        self.bin.join("wgcf.exe").exists() && self.bin.join("wireproxy.exe").exists()
    }

    /// Аккаунт зарегистрирован и профиль WireGuard создан.
    pub fn registered(&self) -> bool {
        self.data.join(PROFILE).exists()
    }

    /// Регистрация бесплатного аккаунта WARP и профиль WireGuard. Вызывать только после согласия пользователя
    /// с условиями Cloudflare: `--accept-tos` принимает их от его имени.
    pub fn register(&self) -> Result<(), String> {
        if !self.installed() {
            return Err(format!("Нет программ WARP в {}", self.bin.display()));
        }
        std::fs::create_dir_all(&self.data).map_err(|e| e.to_string())?;
        if !self.data.join(ACCOUNT).exists() {
            run(&self.bin.join("wgcf.exe"), &["register", "--accept-tos"], &self.data)
                .map_err(|e| format!("Регистрация WARP: {e}"))?;
        }
        run(&self.bin.join("wgcf.exe"), &["generate"], &self.data).map_err(|e| format!("Профиль WARP: {e}"))?;
        if self.registered() { Ok(()) } else { Err("wgcf не создал профиль WireGuard".into()) }
    }

    /// Запускает wireproxy и ждёт, пока SOCKS5 начнёт принимать подключения.
    pub fn start(&self) -> Result<Process, String> {
        if !self.installed() {
            return Err(format!("Нет программ WARP в {}", self.bin.display()));
        }
        if !self.registered() {
            return Err("WARP не зарегистрирован: нажмите «Зарегистрировать» во вкладке WARP".into());
        }
        // Порт занят — остался wireproxy от прошлого запуска (до привязки к job); он держит файлы и мешает обновлению.
        if TcpStream::connect_timeout(&proxy_addr(), Duration::from_millis(300)).is_ok() {
            let mut kill = Command::new("taskkill.exe");
            kill.args(["/F", "/IM", "wireproxy.exe"]);
            hide_window(&mut kill);
            let _ = kill.output();
            std::thread::sleep(Duration::from_millis(500));
        }
        let config = self.data.join(CONFIG);
        std::fs::write(&config, wireproxy_config(&self.data.join(PROFILE), PORT)).map_err(|e| e.to_string())?;
        let mut cmd = Command::new(self.bin.join("wireproxy.exe"));
        cmd.arg("-c").arg(&config).current_dir(&self.data);
        // Журнал wireproxy (рукопожатие WireGuard, ошибки) — для разбора, если WARP не отвечает.
        if let Ok(log) = std::fs::File::create(self.data.join(LOG))
            && let Ok(err) = log.try_clone()
        {
            cmd.stdout(log).stderr(err);
        }
        hide_window(&mut cmd);
        let child = cmd.spawn().map_err(|e| format!("wireproxy не запустился: {e}"))?;
        let job = kill_on_close(&child);
        let mut process = Process { child, _job: job };
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(8) {
            if TcpStream::connect_timeout(&proxy_addr(), Duration::from_millis(300)).is_ok() {
                return Ok(process);
            }
            if !process.alive() {
                return Err("wireproxy завершился сразу после запуска — профиль WARP повреждён? Зарегистрируйте заново".into());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        Err(format!("wireproxy не открыл 127.0.0.1:{PORT} за 8 с"))
    }
}

/// Проверка через SOCKS5: страница трассировки Cloudflare показывает, идёт ли трафик через WARP.
/// Возвращает (warp: on/off/plus, IP выхода).
pub fn check() -> Result<(String, String), String> {
    // Первое рукопожатие WireGuard после запуска может не успеть — несколько попыток.
    let mut last = String::new();
    for _ in 0..3 {
        match trace_once() {
            // Любой ответ HTTP пришёл через туннель — WARP работает. Трассировку Cloudflare отдаёт не всегда
            // (адресам WARP www.cloudflare.com может ответить 403) — тогда адрес выхода неизвестен.
            Ok(body) if body.starts_with("HTTP/") => {
                return Ok(parse_trace(&body).unwrap_or_else(|| ("on".into(), String::new())));
            }
            Ok(body) => last = format!("WARP: непонятный ответ «{}»", body.lines().next().unwrap_or("").trim()),
            Err(e) => last = e,
        }
    }
    Err(format!("{last}. Журнал WARP — data\\warp\\wireproxy.log"))
}

/// Один запрос трассировки через SOCKS5 WARP; весь ответ (заголовки и тело).
fn trace_once() -> Result<String, String> {
    let proxy = vx_reroute::Proxy { addr: proxy_addr(), login: None };
    // www.cloudflare.com по HTTP: трассировка отдаётся без TLS и без перенаправления на HTTPS.
    let target = SocketAddrV4::new(Ipv4Addr::new(104, 16, 132, 229), 80);
    let mut s = proxy.connect(target, Duration::from_secs(10)).map_err(|e| format!("WARP не отвечает: {e}"))?;
    s.set_read_timeout(Some(Duration::from_secs(10))).map_err(|e| e.to_string())?;
    s.write_all(b"GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nUser-Agent: Veyrix\r\nConnection: close\r\n\r\n")
        .map_err(|e| e.to_string())?;
    let mut body = Vec::new();
    // Ответ мог прийти целиком и без закрытия соединения — тогда тайм-аут чтения не ошибка.
    if let Err(e) = s.read_to_end(&mut body)
        && body.is_empty()
    {
        return Err(format!("WARP: нет ответа ({e})"));
    }
    Ok(String::from_utf8_lossy(&body).into_owned())
}

fn parse_trace(text: &str) -> Option<(String, String)> {
    let field = |key: &str| text.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim().to_string());
    Some((field("warp=")?, field("ip=")?))
}

/// Настройки wireproxy: профиль WireGuard от wgcf и SOCKS5 только на 127.0.0.1.
fn wireproxy_config(profile: &Path, port: u16) -> String {
    // Прямые слеши: парсер настроек wireproxy не обязан понимать обратные.
    let profile = profile.display().to_string().replace('\\', "/");
    format!("WGConfig = {profile}\n\n[Socks5]\nBindAddress = 127.0.0.1:{port}\n")
}

fn hide_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

fn run(exe: &Path, args: &[&str], dir: &Path) -> Result<(), String> {
    let mut cmd = Command::new(exe);
    cmd.args(args).current_dir(dir);
    hide_window(&mut cmd);
    let out = cmd.output().map_err(|e| e.to_string())?;
    if out.status.success() {
        Ok(())
    } else {
        let text = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr }).into_owned();
        Err(explain(&text))
    }
}

/// Вывод wgcf при ошибке — длинный стек вызовов Go; оставляем суть и подсказку.
fn explain(output: &str) -> String {
    let core = output.split(" attached stack trace").next().unwrap_or(output);
    let core = core.rsplit("Get \"").next().map_or(core, |rest| rest.split("\":").nth(1).unwrap_or(rest)).trim();
    let core = core.trim_end_matches(" (1)").trim();
    let network = ["deadline exceeded", "handshake", "timeout", "connection", "no such host"];
    if network.iter().any(|w| core.contains(w)) {
        format!(
            "нет связи с сервером регистрации WARP (api.cloudflareclient.com): {core}. Выключите VPN, \
             включите обход в Veyrix (сервер может блокироваться провайдером) и нажмите ещё раз"
        )
    } else {
        core.lines().next().unwrap_or(core).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_uses_forward_slashes_and_loopback() {
        let c = wireproxy_config(Path::new(r"C:\Users\u\AppData\Local\Veyrix-rs\data\warp\wgcf-profile.conf"), PORT);
        assert_eq!(
            c,
            "WGConfig = C:/Users/u/AppData/Local/Veyrix-rs/data/warp/wgcf-profile.conf\n\n[Socks5]\nBindAddress = 127.0.0.1:40100\n"
        );
    }

    #[test]
    fn trace() {
        let body = "HTTP/1.1 200 OK\r\n\r\nfl=1\nh=www.cloudflare.com\nip=104.28.1.2\nts=1\nwarp=on\ngateway=off\n";
        assert_eq!(parse_trace(body), Some(("on".into(), "104.28.1.2".into())));
        assert_eq!(parse_trace("nothing"), None);
    }

    #[test]
    fn job_kills_child_when_closed() {
        let mut cmd = Command::new("ping.exe");
        cmd.args(["-n", "30", "127.0.0.1"]).stdout(std::process::Stdio::null());
        hide_window(&mut cmd);
        let mut child = cmd.spawn().unwrap();
        let job = kill_on_close(&child).expect("job object");
        drop(job);
        let started = Instant::now();
        while child.try_wait().unwrap().is_none() {
            assert!(started.elapsed() < Duration::from_secs(5), "процесс пережил закрытие job");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[test]
    fn wgcf_errors_are_short() {
        let out = "2026/11/26 19:06:45 Using config file: wgcf-account.toml\n2026/11/26 19:06:55 Get \
                   \"https://api.cloudflareclient.com/v0a5641/reg/69e1\": WARP TLS handshake: context deadline exceeded (1) \
                   attached stack trace\n  -- stack trace:\n  | github.com/ViRb3/wgcf/v2/cmd/generate.generateProfile";
        let e = explain(out);
        assert!(e.starts_with("нет связи с сервером регистрации WARP"), "{e}");
        assert!(e.contains("WARP TLS handshake: context deadline exceeded") && !e.contains("stack"), "{e}");
        assert_eq!(explain("Error: something odd\nmore"), "Error: something odd");
    }

    #[test]
    fn not_installed() {
        let w = Warp::new(PathBuf::from(r"C:\нет"), PathBuf::from(r"C:\нет\data"));
        assert!(!w.installed() && !w.registered());
        assert!(w.register().is_err() && w.start().is_err());
    }
}
