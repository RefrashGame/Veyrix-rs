@echo off
rem Veyrix-rs: sbor svedenij dlya razbora problemy. Tolko chtenie: nichego ne menyaet v sisteme.
chcp 65001 >nul
setlocal EnableExtensions
title Veyrix-rs — проверка

echo.
echo  Veyrix-rs — проверка YouTube и Discord
echo  Файл ничего не меняет в системе: только читает настройки и пробует открыть сайты.
echo.
echo  Запустите его ДВА раза:
echo    1) когда обход в Veyrix ВЫКЛЮЧЕН  — введите: off
echo    2) когда обход в Veyrix ВКЛЮЧЁН   — введите: on
echo.
set "MODE="
set /p "MODE=Обход сейчас включён или выключен (on/off): "
if /i not "%MODE%"=="on" if /i not "%MODE%"=="off" set "MODE=unknown"

rem Nastoyashchij Rabochij stol (mozhet byt v OneDrive); esli ne udalos - papka etogo fajla.
set "DESK="
for /f "usebackq delims=" %%D in (`powershell -NoProfile -Command "[Environment]::GetFolderPath('Desktop')"`) do set "DESK=%%D"
if not defined DESK set "DESK=%~dp0"
if not exist "%DESK%\" set "DESK=%~dp0"
set "OUT=%DESK%\veyrix-check-%MODE%.txt"
echo.
echo  Собираю сведения, это займёт 1-3 минуты...

> "%OUT%" (
  echo ===== Veyrix-rs проверка, обход: %MODE% =====
  echo Дата: %DATE% %TIME%
  ver
)

call :section "Права администратора"
net session >nul 2>&1 && (echo да>>"%OUT%") || (echo нет>>"%OUT%")

call :section "Другие обходчики: процессы"
tasklist /fo table 2>nul | findstr /i "winws goodbyedpi zapret veyrix dpi spoofdpi byedpi warp clash v2ray xray hiddify nekoray amnezia outline" >>"%OUT%" || echo не найдены>>"%OUT%"

call :section "Параметры запущенных обходчиков (zapret, GoodbyeDPI)"
powershell -NoProfile -Command "Get-CimInstance Win32_Process | Where-Object { $_.Name -match 'winws|goodbyedpi' } | ForEach-Object { $_.Name + ': ' + $_.CommandLine }" >>"%OUT%" 2>&1

call :section "Другие обходчики: службы"
for %%S in (zapret winws1 winws2 GoodbyeDPI WinDivert WinDivert14 Monkey) do (
  sc query %%S >nul 2>&1 && (echo --- %%S & sc query %%S | findstr /i "STATE") >>"%OUT%"
)

call :section "Драйверы WinDivert"
sc query type= driver state= all 2>nul | findstr /i /c:"divert" >>"%OUT%" || echo не найдены>>"%OUT%"

call :section "Прокси"
netsh winhttp show proxy >>"%OUT%" 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable >>"%OUT%" 2>&1
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer >>"%OUT%" 2>nul

call :section "DNS-серверы адаптеров"
powershell -NoProfile -Command "Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object ServerAddresses | ForEach-Object { '{0}: {1}' -f $_.InterfaceAlias, ($_.ServerAddresses -join ', ') }" >>"%OUT%" 2>&1

call :section "DNS: системный против 1.1.1.1 и 77.88.8.8 (разные адреса = подмена DNS)"
for %%H in (www.youtube.com googlevideo.com discord.com gateway.discord.gg cdn.discordapp.com media.discordapp.net) do (
  echo --- %%H>>"%OUT%"
  powershell -NoProfile -Command "foreach ($s in @('', '1.1.1.1', '77.88.8.8')) { try { $a = if ($s) { Resolve-DnsName %%H -Server $s -Type A -DnsOnly -QuickTimeout -ErrorAction Stop } else { Resolve-DnsName %%H -Type A -DnsOnly -QuickTimeout -ErrorAction Stop }; '{0,-10} {1}' -f ($(if ($s) { $s } else { 'системный' })), (($a | Where-Object IPAddress).IPAddress -join ' ') } catch { '{0,-10} ошибка: {1}' -f ($(if ($s) { $s } else { 'системный' })), $_.Exception.Message } }" >>"%OUT%" 2>&1
)

call :section "HTTPS: код, время соединения, TLS, всего, сколько байт пришло"
echo (замирание после 16-20 КБ или «000» при таймауте — признак блокировки DPI)>>"%OUT%"
for %%U in (
  https://ya.ru/
  https://www.youtube.com/
  https://i.ytimg.com/vi/dQw4w9WgXcQ/hqdefault.jpg
  https://redirector.googlevideo.com/
  https://discord.com/
  https://discord.com/api/v9/gateway
  https://gateway.discord.gg/
  https://cdn.discordapp.com/
  https://media.discordapp.net/
  https://dl.discordapp.net/
  https://updates.discord.com/
) do (
  curl.exe -s -o nul --max-time 15 -w "%%{http_code}  conn=%%{time_connect}s  tls=%%{time_appconnect}s  total=%%{time_total}s  bytes=%%{size_download}  %%{url_effective}\n" "%%U" >>"%OUT%" 2>&1
)

>>"%OUT%" echo (QUIC/HTTP3 curl Windows не умеет — проверяется только TCP)

echo.>>"%OUT%"
echo ===== конец =====>>"%OUT%"

echo.
if not exist "%OUT%" (echo  Не удалось записать отчёт: %OUT% & pause & exit /b 1)
echo  Готово. Файл: %OUT%
start "" explorer /select,"%OUT%"
echo  Отправьте его (и второй файл после повторного запуска) разработчику.
echo  В файле нет паролей и личных данных — только настройки сети и результаты проверки сайтов.
echo.
pause
exit /b 0

:section
>>"%OUT%" echo.
>>"%OUT%" echo ===== %~1 =====
exit /b 0
