//! Обновление с GitHub Releases: новая версия ищется через API GitHub, установщик скачивается со страницы релиза,
//! сверяется с SHA256SUMS.txt того же релиза и запускается — дальше обычный мастер установки (настройки в `data\`
//! сохраняются). Бета-версии получают и бета-обновления, стабильные — только стабильные.

use std::cmp::Ordering;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::Value;

const REPO: &str = "RefrashGame/Veyrix-rs";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Update {
    pub version: String,
    pub notes: String,
    pub page: String,
    pub setup_name: String,
    pub setup_url: String,
    pub sums_url: String,
    pub size: u64,
}

pub fn check(current: &str) -> Result<Option<Update>, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases?per_page=20");
    let text = vx_net::get_text(&url, "Accept: application/vnd.github+json\r\n").map_err(|e| format!("GitHub недоступен: {e}"))?;
    let releases: Value = serde_json::from_str(&text).map_err(|e| format!("GitHub: непонятный ответ ({e})"))?;
    Ok(pick(current, &releases))
}

/// Самый новый подходящий релиз новее `current`, у которого есть установщик и SHA256SUMS.txt.
fn pick(current: &str, releases: &Value) -> Option<Update> {
    let beta = current.contains('-');
    releases
        .as_array()?
        .iter()
        .filter_map(|r| {
            if r["draft"].as_bool().unwrap_or(true) || (r["prerelease"].as_bool().unwrap_or(false) && !beta) {
                return None;
            }
            let version = r["tag_name"].as_str()?.trim_start_matches('v').to_string();
            if compare(&version, current)? != Ordering::Greater {
                return None;
            }
            let asset = |name: &str| r["assets"].as_array()?.iter().find(|a| a["name"].as_str() == Some(name));
            let setup_name = format!("Veyrix-rs-{version}-x64-setup.exe");
            let setup = asset(&setup_name)?;
            let sums = asset("SHA256SUMS.txt")?;
            Some(Update {
                notes: r["body"].as_str().unwrap_or("").to_string(),
                page: r["html_url"].as_str().unwrap_or("").to_string(),
                setup_url: setup["browser_download_url"].as_str()?.to_string(),
                sums_url: sums["browser_download_url"].as_str()?.to_string(),
                size: setup["size"].as_u64().unwrap_or(0),
                setup_name,
                version,
            })
        })
        .max_by(|a, b| compare(&a.version, &b.version).unwrap_or(Ordering::Equal))
}

/// Сравнение версий «X.Y.Z» и «X.Y.Z-суффикс»: версия без суффикса новее той же с суффиксом.
fn compare(a: &str, b: &str) -> Option<Ordering> {
    fn parse(v: &str) -> Option<([u64; 3], Option<&str>)> {
        let (core, pre) = v.split_once('-').map_or((v, None), |(c, p)| (c, Some(p)));
        let mut n = core.split('.').map(|x| x.parse::<u64>().ok());
        Some(([n.next()??, n.next()??, n.next()??], pre))
    }
    let (a, b) = (parse(a)?, parse(b)?);
    Some(a.0.cmp(&b.0).then(match (a.1, b.1) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => x.cmp(y),
    }))
}

/// Скачивает установщик, сверяет SHA256 и запускает его. Адреса принимаются только из релизов этого репозитория.
pub fn install(u: &Update) -> Result<PathBuf, String> {
    let prefix = format!("https://github.com/{REPO}/releases/download/");
    if !u.setup_url.starts_with(&prefix) || !u.sums_url.starts_with(&prefix) || u.setup_name.contains(['/', '\\']) {
        return Err("Обновление: чужой адрес файла".into());
    }
    let sums = vx_net::get_text(&u.sums_url, "").map_err(|e| format!("Не скачался SHA256SUMS.txt: {e}"))?;
    let expected = sums
        .lines()
        .find_map(|l| l.split_once("  ").filter(|(_, name)| name.trim() == u.setup_name).map(|(h, _)| h.trim().to_ascii_lowercase()))
        .ok_or("В SHA256SUMS.txt нет хеша установщика")?;
    let mut data = Vec::new();
    let status = vx_net::request("GET", &u.setup_url, "", &[], 60_000, &mut data, 200 << 20)
        .map_err(|e| format!("Не скачался установщик: {e}"))?;
    if status != 200 {
        return Err(format!("Не скачался установщик: HTTP {status}"));
    }
    let actual: String = vx_tg::crypto::sha256(&[&data]).iter().map(|b| format!("{b:02x}")).collect();
    if actual != expected {
        return Err("Установщик скачался с ошибкой: SHA256 не совпадает. Попробуйте ещё раз".into());
    }
    let dir = std::env::temp_dir().join("Veyrix-rs-update");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(&u.setup_name);
    std::fs::write(&path, &data).map_err(|e| e.to_string())?;
    std::process::Command::new(&path).spawn().map_err(|e| format!("Установщик не запустился: {e}"))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions() {
        assert_eq!(compare("0.2.2-beta", "0.2.1-beta"), Some(Ordering::Greater));
        assert_eq!(compare("0.2.0", "0.2.0-beta"), Some(Ordering::Greater));
        assert_eq!(compare("0.10.0", "0.9.9"), Some(Ordering::Greater));
        assert_eq!(compare("0.1.0", "0.1.0"), Some(Ordering::Equal));
        assert_eq!(compare("x", "0.1.0"), None);
    }

    fn release(tag: &str, pre: bool, setup: bool) -> Value {
        let v = tag.trim_start_matches('v');
        let url = |n: &str| format!("https://github.com/{REPO}/releases/download/{tag}/{n}");
        let mut assets = vec![serde_json::json!({"name": "SHA256SUMS.txt", "browser_download_url": url("SHA256SUMS.txt")})];
        if setup {
            let n = format!("Veyrix-rs-{v}-x64-setup.exe");
            assets.push(serde_json::json!({"name": n, "browser_download_url": url(&n), "size": 10}));
        }
        serde_json::json!({"tag_name": tag, "draft": false, "prerelease": pre, "html_url": "p", "body": "b", "assets": assets})
    }

    #[test]
    fn picks_newest_suitable_release() {
        let list = Value::Array(vec![
            release("v0.3.0-beta", true, true),
            release("v0.2.2-beta", true, true),
            release("v0.2.0-beta", true, false),
            release("v0.1.0", false, false),
        ]);
        assert_eq!(pick("0.2.1-beta", &list).unwrap().version, "0.3.0-beta");
        assert_eq!(pick("0.3.0-beta", &list), None);
        // Стабильная версия не получает бета-обновлений.
        assert_eq!(pick("0.1.0", &list), None);
        let u = pick("0.2.1-beta", &Value::Array(vec![release("v0.2.2-beta", true, true)])).unwrap();
        assert_eq!(u.setup_name, "Veyrix-rs-0.2.2-beta-x64-setup.exe");
    }

    #[test]
    fn foreign_urls_are_refused() {
        let mut u = pick("0.2.1-beta", &Value::Array(vec![release("v0.2.2-beta", true, true)])).unwrap();
        u.setup_url = "https://evil.example/x.exe".into();
        assert!(install(&u).unwrap_err().contains("чужой адрес"));
    }
}
