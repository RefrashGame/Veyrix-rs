# Скачивает программы встроенного WARP для Veyrix-rs и сверяет SHA256 (хеши — со страниц релизов на GitHub).
# wgcf (MIT, ViRb3/wgcf) — регистрация WARP; wireproxy (ISC, windtf/wireproxy) — WireGuard без драйвера + SOCKS5.
# Запуск: .\tools\fetch-warp.ps1 -Dest app\src-tauri\engine\warp
param([Parameter(Mandatory = $true)][string]$Dest)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$wgcf = @{
    Url     = 'https://github.com/ViRb3/wgcf/releases/download/v2.3.1/wgcf_2.3.1_windows_amd64.exe'
    Sha     = 'e222fd9443d7cb3264d825a3e86967797fc9c938507c5d93e3cc21e4aed11dcc'
    License = 'https://raw.githubusercontent.com/ViRb3/wgcf/v2.3.1/LICENSE'
}
$wireproxy = @{
    Url     = 'https://github.com/windtf/wireproxy/releases/download/v1.1.3/wireproxy_windows_amd64.tar.gz'
    Sha     = 'bce041ea9fe0f8a3351301dcbe29cdf6a523bb25cf9c62f17ebb5699a8051d0f'
    License = 'https://raw.githubusercontent.com/windtf/wireproxy/v1.1.3/LICENSE'
}

function Get-Checked($item, $path) {
    Invoke-WebRequest -Uri $item.Url -OutFile $path -UseBasicParsing
    $hash = (Get-FileHash $path -Algorithm SHA256).Hash.ToLower()
    if ($hash -ne $item.Sha) { throw "$($item.Url): SHA256 $hash не совпадает с ожидаемым $($item.Sha)" }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("veyrix-warp-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force $tmp, $Dest | Out-Null
try {
    Get-Checked $wgcf (Join-Path $tmp 'wgcf.exe')
    Get-Checked $wireproxy (Join-Path $tmp 'wireproxy.tar.gz')
    tar -xzf (Join-Path $tmp 'wireproxy.tar.gz') -C $tmp
    if ($LASTEXITCODE) { throw "tar: код $LASTEXITCODE" }
    Copy-Item (Join-Path $tmp 'wgcf.exe'), (Join-Path $tmp 'wireproxy.exe') $Dest -Force
    Invoke-WebRequest -Uri $wgcf.License -OutFile (Join-Path $Dest 'wgcf-LICENSE.txt') -UseBasicParsing
    Invoke-WebRequest -Uri $wireproxy.License -OutFile (Join-Path $Dest 'wireproxy-LICENSE.txt') -UseBasicParsing
    Get-ChildItem $Dest | ForEach-Object { "{0,10}  {1}" -f $_.Length, $_.Name }
    "Готово: $Dest"
} finally {
    Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
