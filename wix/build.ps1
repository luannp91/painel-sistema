<#
.SYNOPSIS
  Compila o painel-sistema e empacota como .msi via WiX Toolset.

.DESCRIPTION
  Requer:
    - cargo (Rust)
    - WiX Toolset v3 (candle.exe + light.exe no PATH)

.EXAMPLE
  .\wix\build.ps1
#>

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$version = (Select-String -Path "$root\Cargo.toml" -Pattern '^version = "(.+)"').Matches.Groups[1].Value

Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Painel do Sistema — Build" -ForegroundColor Cyan
Write-Host "  Versão: $version" -ForegroundColor Cyan
Write-Host "═══════════════════════════════════════════════" -ForegroundColor Cyan

# 1. Compila o release
Write-Host "`n[1/3] Compilando release..." -ForegroundColor Yellow
Push-Location $root
cargo build --release
Pop-Location

$exePath = "$root\target\release\painel-sistema.exe"
if (-not (Test-Path $exePath)) {
    Write-Host "ERRO: executável não encontrado em $exePath" -ForegroundColor Red
    exit 1
}

# 2. Verifica WiX
Write-Host "`n[2/3] Verificando WiX Toolset..." -ForegroundColor Yellow
$candle = Get-Command candle.exe -ErrorAction SilentlyContinue
$light = Get-Command light.exe -ErrorAction SilentlyContinue

if (-not $candle -or -not $light) {
    Write-Host "ERRO: WiX Toolset não está no PATH." -ForegroundColor Red
    Write-Host "Instale em https://wixtoolset.org/releases/ e adicione o bin/ ao PATH." -ForegroundColor Red
    exit 1
}

# 3. Compila o .msi
Write-Host "`n[3/3] Gerando instalador .msi..." -ForegroundColor Yellow
$wixDir = "$root\wix"
$buildDir = "$wixDir\target"
New-Item -ItemType Directory -Path $buildDir -Force | Out-Null

Push-Location $wixDir
candle.exe -nologo -out "$buildDir\main.wixobj" main.wxs
light.exe -nologo -ext WixUIExtension -ext WixUtilExtension `
    -out "$buildDir\PainelSistema-$version.msi" `
    "$buildDir\main.wixobj"
Pop-Location

$msiPath = "$buildDir\PainelSistema-$version.msi"
if (Test-Path $msiPath) {
    $sizeMB = [math]::Round((Get-Item $msiPath).Length / 1MB, 2)
    Write-Host "`n✅ Instalador gerado com sucesso!" -ForegroundColor Green
    Write-Host "   Arquivo: $msiPath" -ForegroundColor Green
    Write-Host "   Tamanho: $sizeMB MB" -ForegroundColor Green
} else {
    Write-Host "ERRO: falha ao gerar o .msi" -ForegroundColor Red
    exit 1
}
