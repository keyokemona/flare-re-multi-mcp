<#
.SYNOPSIS
    Instalador Automatizado 1-Comando para Windows (FlareVM e Windows 10/11 Padrão).
.DESCRIPTION
    Verifica Python 3.11+, instala dependências, baixa ferramentas portáteis ausentes
    (FLOSS, CAPA, capa-rules, Detect It Easy, Radare2 + r2ghidra) em ~/.flare-re-mcp/tools,
    configura ~/.gemini/config/mcp_config.json e aquece o cache de regras CAPA.
#>
param(
    [switch]$DownloadMissingTools = $true
)

$ErrorActionPreference = "Stop"
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "============================================================================" -ForegroundColor Cyan
Write-Host " [flare-re-mcp] Instalador Automatizado para Windows (FlareVM & Standard)" -ForegroundColor Cyan
Write-Host "============================================================================" -ForegroundColor Cyan

if (-not (Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Python não encontrado no PATH. Tentando instalar via winget..." -ForegroundColor Yellow
    winget install -e --id Python.Python.3.11 --accept-package-agreements --accept-source-agreements
}

$ArgsList = @("$RepoRoot\install.py")
if ($DownloadMissingTools) {
    $ArgsList += "--download-missing"
}

& python @ArgsList

Write-Host "`n[OK] Ambiente pronto! Execute 'agy' na raiz do projeto para iniciar." -ForegroundColor Green
