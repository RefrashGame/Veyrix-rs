# Veyrix-rs

Обход DPI-блокировок на этом компьютере, без своего сервера. Rust, перехват пакетов через драйвер WinDivert.
Этапы — `docs/PLAN.md`, сборка — `docs/DEVELOPMENT.md`. Лицензия — GPL-3.0 (`LICENSE`),
сторонние компоненты — `THIRD-PARTY-LICENSES.md`.

Окно (этап 6): `target\release\veyrix.exe` — старт/стоп, журнал, настройки. Консоль: `vx sniff` — наблюдение; `vx run` — обход (фейки, разрезание, перестановка, QUIC);
`--auto` — свой приём для каждого сайта с самовосстановлением; `--doh` — DNS через DNS-over-HTTPS.
