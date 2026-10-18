# 🚀 Diretório `scripts/` — Instaladores Automatizados Multi-Plataforma

Este diretório contém os scripts de *bootstrap* de comando único para configurar o **`flare-re-mcp`** automaticamente tanto no **FlareVM** quanto em máquinas **Windows 10/11 padrão**, **Linux (Ubuntu, Debian, Kali, REMnux, Arch, Fedora, WSL2)** e ambientes **Docker**.

---

## 📄 Scripts Disponíveis

| Script | Sistema Operacional | O que Faz Automaticamente |
| :--- | :--- | :--- |
| **[`install.ps1`](./install.ps1)** | **Windows** (FlareVM ou Windows 10/11 Limpo) | Verifica o Python 3.11+, instala o pacote `flare-re-mcp` + `yara-python`, baixa automaticamente em `~/.flare-re-mcp/tools` quaisquer ferramentas portáteis ausentes (*FLOSS*, *CAPA*, *capa-rules v9.4.0*, *Detect It Easy*, *Radare2 + r2ghidra*), configura `~/.radare2rc` e `~/.rizinrc`, registra todos os servidores em `~/.gemini/config/mcp_config.json` e pré-aquece o cache `.pkl` do CAPA. |
| **[`install.sh`](./install.sh)** | **Linux / WSL2** (Ubuntu, Kali, REMnux, Arch, Fedora) | Instala dependências nativas (`python3`, `radare2`, `rizin`, `openjdk-21-jdk-headless`) via `apt`/`pacman`/`dnf`, baixa as releases Linux do *FLOSS*, *CAPA* e *capa-rules v9.4.0* em `~/.flare-re-mcp/tools` e configura automaticamente `~/.gemini/config/mcp_config.json`. |

---

## ⚡ Como Executar

### No Windows (PowerShell):
```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\install.ps1
```

### No Linux / WSL2 / macOS:
```bash
chmod +x ./scripts/install.sh && ./scripts/install.sh
```

### Diretamente via Python (Qualquer OS):
```bash
python install.py --download-missing
```
