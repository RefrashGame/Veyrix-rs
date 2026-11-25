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
| WinDivert 2.x (`WinDivert.dll`, `WinDivert64.sys`) | LGPLv3 или GPLv2 (на выбор) | basil00 | Без изменений, DLL загружается во время работы (`crates/divert`); при распространении — приложить текст LGPLv3 и ссылку на исходники https://github.com/basil00/WinDivert |
