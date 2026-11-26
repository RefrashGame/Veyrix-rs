# Разработка

Программа — одно окно `veyrix.exe` (Tauri). Консольная версия `vx` удалена 2026-11-25; всё проверяется в окне.

## Сборка и тесты

```powershell
cargo test --workspace
cargo clippy --workspace --all-targets
cd app
bun install                          # один раз
bun run tauri dev                    # разработка; терминал — от администратора
bun run tauri build --no-bundle      # target\release\veyrix.exe с встроенным интерфейсом
```

Интерфейс — `app/` (React + shadcn, bun), нативная часть — `app/src-tauri` (крейт `veyrix`, участник workspace,
ходит в `vx-engine`). Окно просит права администратора при запуске (манифест `app/src-tauri/veyrix.manifest` —
только ASCII, иначе Windows не запускает exe с ошибкой 14001). Версии Tauri в `app/src-tauri/Cargo.toml` и
`app/package.json` должны совпадать по major.minor (`tauri build` проверяет).

## WinDivert

`WinDivert.dll` и `WinDivert64.sys` (WinDivert 2.x, подписанный драйвер) в git не хранятся. Окно ищет их в `engine\`
рядом с `veyrix.exe`, иначе рядом с ним:

```powershell
$e = "target\release\engine"; New-Item -ItemType Directory -Force $e
# WinDivert 2.2 (x64) — https://github.com/basil00/WinDivert/releases: из архива взять x64\WinDivert.dll и x64\WinDivert64.sys
Copy-Item путь\к\WinDivert-2.2.x-A\x64\WinDivert.dll, путь\к\WinDivert-2.2.x-A\x64\WinDivert64.sys $e
```

Microsoft Defender может удалить официальный архив WinDivert («Misleading:Win32/Malgent») — тогда нужна папка
в исключениях Defender (решает владелец компьютера). В релиз WinDivert кладёт `release.yml`.

## Обход и автоподбор

Перехватываются только первые пакеты соединений (ClientHello, HTTP-запрос, QUIC Initial); остальной трафик
в программу не попадает. «Остановить» — драйвер сразу пускает всё напрямую. Приёмы — `crates/core/src/desync.rs`,
список автоподбора — `tuner::presets` (`crates/core/src/tuner.rs`); выбор автоподбора — `data\tuning.txt` рядом
с exe, события — во вкладке «Журнал» («сайт: работает с «приём»», «не открывается с «A» → пробую «B»»).
Настройки окна — `data\settings.json` рядом с exe.

## DNS-over-HTTPS

Системные настройки DNS не меняются: запросы на UDP 53 перехватываются, ответ от DoH подставляется входящим
пакетом. Если DoH не ответил (≈ 3 с) — исходный запрос уходит обычному DNS. Проверка: `nslookup сайт 192.0.2.1`
(несуществующий сервер) при включённом DoH всё равно получает адреса.

## Блокировка по IP

Крейт `vx-reroute`, режим — «Настройки» → «Если сайт заблокирован по IP-адресу» (`ipBlock`: off, cloudflare,
proxy, warp; адрес прокси — `ipProxy`). События — в «Журнале» с меткой «обход по IP». Для proxy и warp при
запуске обхода ставится правило брандмауэра «Veyrix-rs: обход блокировки по IP», при остановке удаляется.
WARP встроен (крейт `vx-warp`, вкладка «WARP»): `engine\warp\wgcf.exe` регистрирует аккаунт и пишет профиль
WireGuard в `data\warp\`, `engine\warp\wireproxy.exe` по нему даёт SOCKS5 на 127.0.0.1:40100; Veyrix запускает его
перед обходом в режиме WARP и останавливает при выходе. Программы в git не хранятся: `toolsetch-warp.ps1 -Dest
app\src-tauri\engine\warp` скачивает их с официальных релизов и сверяет SHA256 (так же делает `release.yml`);
для запуска из `targetelease` скопируйте папку в `targetelease\engine\warp`.
Проверка без настоящей блокировки: отдельным перехватом WinDivert (приоритет ниже 200) выбрасывать исходящие
SYN к выбранному адресу — через ~3 с соединения пойдут в обход. Прокси для проверки должен ходить к адресу
не с этого компьютера (иначе петля), а VPN с fake-ip (dropweb) искажает результат — проверять без него.

## Telegram-прокси

Вкладка «Telegram». Secret создаётся при первом запуске и хранится в `data\settings.json`.

## Диагностика, трей, автозапуск

Вкладка «Диагностика»: права, WinDivert, служба BFE, другие перехватчики, VPN, прокси, DoH — только чтение.
Крестик прячет окно в трей (обход работает), выход — из меню значка.
«Запускать вместе с Windows» создаёт задачу Планировщика `Veyrix-rs` (наивысшие права, при входе, задержка 10 с,
аргумент `--autostart`: окно скрыто, обход стартует с `data\settings.json`); выключение удаляет задачу.
Значки — `bunx tauri icon путь\к\логотипу-1024px-или-больше.png` в `app/` (мобильные папки `icons/android` и `icons/ios` не нужны).

## DNS Windows (от администратора)

Страница «DNS Windows»: замена на Яндекс 77.88.8.8 / 77.88.8.1 с очисткой кэша; исходный — в `data\dns-backup.txt`,
«Вернуть исходный DNS» восстанавливает ручной или DHCP. Системная настройка действует и без программы.

## Релиз

Тег `vX.Y.Z` (версии в `Cargo.toml`, `app/package.json`, `app/src-tauri/tauri.conf.json` совпадают с тегом,
описание — `docs/releases/vX.Y.Z.md`) → `release.yml` собирает установщик NSIS, архив zip и черновик релиза;
публикация — вручную. Установщик локально (WinDivert и `WinDivert-LICENSE.txt` — в `app\src-tauri\engine\`;
отдельная папка сборки, если запущенный Veyrix держит файлы в `target\release`):

```powershell
cd app
$env:CARGO_TARGET_DIR = "..\target\nsis"; bun run tauri build --config src-tauri/tauri.nsis.conf.json
# → target\nsis\release\bundle\nsis\Veyrix-rs_<версия>_x64-setup.exe
```

Установщик (`tauri.nsis.conf.json`): для текущего пользователя (без прав администратора, `%LOCALAPPDATA%\Veyrix-rs`),
русский, LZMA. При первой сборке Tauri сам скачивает NSIS со своей страницы релизов и сверяет хеш.
