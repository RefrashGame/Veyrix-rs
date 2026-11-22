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
Copy-Item D:\Project\NetPulse\engines\zapret\bin\WinDivert.dll, D:\Project\NetPulse\engines\zapret\bin\WinDivert64.sys $e
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
