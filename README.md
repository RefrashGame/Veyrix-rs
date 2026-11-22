# Veyrix-rs

Обход DPI-блокировок на этом компьютере, без своего сервера. Rust, перехват пакетов через драйвер WinDivert.
Личный проект. Этапы — `docs/PLAN.md`, сборка — `docs/DEVELOPMENT.md`.

Сейчас (этап 4): `vx sniff` — наблюдение; `vx run` — обход (фейки, разрезание, перестановка, QUIC);
`--doh` — DNS через DNS-over-HTTPS; `vx doh сайт` — проверка DoH.
