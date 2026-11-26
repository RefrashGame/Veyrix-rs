# Сторонние компоненты

Движок (`crates/*`) — без внешних Rust-зависимостей; код написан заново, код zapret не используется.
Интерфейс (`app/`) создан шаблоном create-tauri-ui и использует пакеты npm/crates.io ниже (полный список и
версии — `app/bun.lock`, `app/src-tauri/Cargo.lock`); все с разрешительными лицензиями.

| Компонент | Лицензия | Правообладатель | Как используется |
|---|---|---|---|
| create-tauri-ui 1.2.1 (шаблон `app/`) | MIT | agmmnn | Сгенерированный каркас интерфейса, правится как свой код |
| Tauri 2 (`tauri`, `@tauri-apps/api`, `@tauri-apps/cli`, плагины log, opener и single-instance) | Apache-2.0 или MIT | Tauri Programme | Оболочка окна и связь интерфейса с Rust |
| React 19, Vite 8, Tailwind CSS 4, shadcn 4, Base UI | MIT | Meta; VoidZero; Tailwind Labs; shadcn; MUI | Интерфейс |
| lucide-react | ISC | Lucide Contributors | Значки |
| tg-ws-proxy (Flowseal), коммит 2085861 | MIT | Flowseal, 2026 | Протокол Telegram-прокси и резервный канал Cloudflare перенесены по нему (реализация своя, `crates/tg`): список доменов `_CFPROXY_ENC` и декодер `_dd`, адреса DC, загрузка `cfproxy-domains.txt` |
| WinDivert 2.x (`WinDivert.dll`, `WinDivert64.sys`) | LGPLv3 или GPLv2 (на выбор) | basil00 | Без изменений, DLL загружается во время работы (`crates/divert`). В пакет релиза кладётся 2.2.2 с официального релиза (в `release.yml` архив, DLL и драйвер сверяются по хешам) в `engine\`, текст лицензии — `licenses\WinDivert-LICENSE.txt`; исходники — https://github.com/basil00/WinDivert |
| wgcf 2.3.1 (`wgcf.exe`) | MIT | ViRb3 | Без изменений, отдельная программа в `engine\warp\`: регистрирует бесплатный аккаунт Cloudflare WARP и пишет профиль WireGuard (`crates/warp`). Скачивается `tools/fetch-warp.ps1` с официального релиза, SHA256 сверяется; лицензия — `licenses\wgcf-LICENSE.txt`; исходники — https://github.com/ViRb3/wgcf |
| wireproxy 1.1.3 (`wireproxy.exe`) | ISC | Tsz Fung Wong (windtf) | Без изменений, отдельная программа в `engine\warp\`: WireGuard без драйвера и SOCKS5 на 127.0.0.1 для режима «Через WARP». Скачивается так же; лицензия — `licenses\wireproxy-LICENSE.txt`; исходники — https://github.com/windtf/wireproxy (внутри — wireguard-go, MIT, и gVisor, Apache-2.0) |
