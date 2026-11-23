# Разработка

## Сборка и тесты

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets
cargo build --release -p vx
```

## WinDivert

`WinDivert.dll` и `WinDivert64.sys` (WinDivert 2.x, подписанный драйвер) в git не хранятся. `vx` ищет их
в `--engine ПАПКА`, затем в `engine\` рядом с `vx.exe`, затем рядом с `vx.exe`. Для разработки — из Veyrix:

```powershell
$e = "target\debug\engine"; New-Item -ItemType Directory -Force $e
# WinDivert 2.2 (x64) — https://github.com/basil00/WinDivert/releases: из архива взять x64\WinDivert.dll и x64\WinDivert64.sys
Copy-Item путь\к\WinDivert-2.2.x-A\x64\WinDivert.dll, путь\к\WinDivert-2.2.x-A\x64\WinDivert64.sys $e
```

## Проверка перехвата (от администратора)

```powershell
target\debug\vx.exe sniff --seconds 15
```

Откройте сайты в браузере — в консоли появятся TLS/HTTP-имена. Режим копии: трафик не меняется.
Если включён VPN с fake-ip (Clash, dropweb), адреса будут вида 198.18.x.x — для проверки обхода VPN выключите.

## Обход (от администратора, VPN и Veyrix/zapret выключены)

```powershell
target\release\vx.exe run --check          # только проверить параметры, без перехвата
target\release\vx.exe run                  # по умолчанию: фейк (badseq) ×6 + разрезание 1,midsld в обратном порядке, QUIC — фейк
```

Перехватываются только первые пакеты соединений (ClientHello, HTTP-запрос, QUIC Initial); остальной трафик
в программу не попадает. Ctrl+C или закрытие окна — драйвер сразу пускает всё напрямую.
Параметры приёмов — в начале `crates/cli/src/main.rs` (`--split`, `--fooling`, `--repeats`, `--quic`,
`--no-fake`, `--no-disorder`, `--discord-voice`).

## Окно (Tauri)

Интерфейс — `app/` (React + shadcn, bun), нативная часть — `app/src-tauri` (крейт `veyrix`, участник workspace,
ходит в `vx-engine`). Окно просит права администратора при запуске (манифест `app/src-tauri/veyrix.manifest` —
только ASCII, иначе Windows не запускает exe с ошибкой 14001).

```powershell
cd app
bun install                          # один раз
bun run tauri dev                    # разработка; терминал — от администратора
bun run tauri build --no-bundle      # target\release\veyrix.exe с встроенным интерфейсом
```

WinDivert для окна ищется так же, как для `vx`: `engine\` рядом с `veyrix.exe`, иначе рядом с ним.
Настройки окна — `data\settings.json` рядом с exe. Версии Tauri в `app/src-tauri/Cargo.toml` и `app/package.json`
должны совпадать по major.minor (`tauri build` проверяет).

## Автоподбор

```powershell
target\release\vx.exe run --auto --doh cloudflare   # свой приём для каждого сайта, при сбоях — следующий
target\release\vx.exe run --auto-test               # все сайты начинают «без приёмов»: видно, как заблокированные переключаются
```

В консоли: «сайт: работает с «приём»» и «сайт: не открывается с «A» → пробую «B»». Выбор — `data\tuning.txt`
рядом с `vx.exe` (`--auto-test` его не читает, но перезаписывает).

## Диагностика, трей, автозапуск

```powershell
target\release\vx.exe diag     # права, WinDivert, служба BFE, другие перехватчики, VPN, прокси, DoH — только чтение
```

В окне: вкладка «Диагностика». Крестик прячет окно в трей (обход работает), выход — из меню значка.
«Запускать вместе с Windows» создаёт задачу Планировщика `Veyrix-rs` (наивысшие права, при входе, задержка 10 с,
аргумент `--autostart`: окно скрыто, обход стартует с `data\settings.json`); выключение удаляет задачу.
Значки — `bunx tauri icon путь\к\логотипу-1024px-или-больше.png` в `app/` (мобильные папки `icons/android` и `icons/ios` не нужны).

## DNS Windows (от администратора)

```powershell
target\release\vx.exe sysdns status    # адаптеры и их DNS — только чтение
target\release\vx.exe sysdns set       # Яндекс 77.88.8.8 / 77.88.8.1 + очистка кэша; исходный — в data\dns-backup.txt
target\release\vx.exe sysdns restore   # вернуть исходный (ручной или DHCP) + очистка кэша
```

То же — кнопками в окне: «Настройки» → «DNS Windows». Системная настройка действует и без программы.

## DNS-over-HTTPS

```powershell
target\release\vx.exe doh youtube.com --doh quad9   # проверка DoH без перехвата, прав администратора не нужно
target\release\vx.exe run --doh cloudflare          # обход + DNS через DoH (cloudflare, google, quad9, https://…)
```

Системные настройки DNS не меняются: запросы на UDP 53 перехватываются, ответ от DoH подставляется входящим
пакетом. Если DoH не ответил (≈ 3 с) — исходный запрос уходит обычному DNS. Проверка подмены: `nslookup сайт`
во время работы — адреса должны совпасть с `vx doh сайт`.
