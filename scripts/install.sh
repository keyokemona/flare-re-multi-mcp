#!/usr/bin/env bash
# ============================================================================
# [flare-re-mcp] Instalador Automatizado 1-Comando para Linux / REMnux / Kali / WSL2
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "============================================================================"
echo " [flare-re-mcp] Instalador Automatizado para Linux (Ubuntu/Kali/REMnux/WSL2)"
echo "============================================================================"

if command -v apt-get >/dev/null 2>&1; then
    echo "[*] Detectado gerenciador APT (Debian/Ubuntu/Kali/REMnux). Verificando pacotes base..."
    sudo apt-get update -y || true
    sudo apt-get install -y python3 python3-pip python3-venv git curl unzip radare2 rizin openjdk-21-jdk-headless || true
elif command -v pacman >/dev/null 2>&1; then
    echo "[*] Detectado gerenciador Pacman (Arch Linux). Verificando pacotes base..."
    sudo pacman -Sy --noconfirm python python-pip git curl unzip radare2 rizin jdk21-openjdk || true
elif command -v dnf >/dev/null 2>&1; then
    echo "[*] Detectado gerenciador DNF (Fedora/RHEL). Verificando pacotes base..."
    sudo dnf install -y python3 python3-pip git curl unzip radare2 rizin java-21-openjdk-headless || true
fi

python3 "${REPO_ROOT}/install.py" --download-missing

echo ""
echo "[OK] Ambiente pronto! Basta abrir o 'agy' na pasta ${REPO_ROOT} para começar."
