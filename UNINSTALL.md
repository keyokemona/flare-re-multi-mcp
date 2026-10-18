# 🧹 Manual de Desinstalação Completa (Zero Resíduos) — `flare-re-mcp`

Este documento descreve como remover **100% dos componentes, servidores MCP, caches forenses, bancos do Ghidra, variáveis de ambiente, ferramentas portáteis e pacotes Python** instalados pela suíte **`flare-re-mcp`**, garantindo que não reste absolutamente nenhum resquício no sistema hospedeiro ou máquina virtual (Windows / FlareVM / Linux).

---

## ⚡ Opção 1 — Desinstalação Automatizada em 1 Comando (Recomendado)

O repositório inclui o desinstalador automatizado **[`uninstall.py`](./uninstall.py)**, que executa toda a limpeza em 5 etapas auditáveis:

### Desinstalação Padrão (Preserva seus relatórios em `./reports/`):
```powershell
python uninstall.py
```

### Desinstalação Total (`--full-purge` — Remove absolutamente tudo, incluindo variáveis de ambiente e dependências):
```powershell
python uninstall.py --full-purge
```

**O que o `uninstall.py` remove automaticamente:**
1. **Servidores MCP no Antigravity CLI (`~/.gemini/config/mcp_config.json`)**:
   - Remove as entradas `die-mcp`, `floss-mcp`, `capa-mcp`, `rizin-mcp`, `radare2-mcp`, `ghidra-mcp`, `unpacker-mcp` e `threat-intel-mcp` sem afetar outros servidores MCP pessoais que você utilize.
2. **Caches, Snapshots e Bancos de Dados Locais**:
   - Remove `.analysis_cache/` (incluindo `_capa_ruleset_cache.pkl`, `_last_update_check.json`, snapshots JSON e arquivos descompactados).
   - Remove `ghidra_projects/` (bancos `.gpr` e `.rep` do PyGhidra Headless).
   - Remove `~/.flare-re-mcp/` (diretório de ferramentas portáteis baixadas pelo `install.py --download-missing`).
3. **Arquivos de Configuração de Decompiladores**:
   - Remove `~/.radare2rc` e `~/.rizinrc`.
4. **Variáveis de Ambiente de Usuário (`--purge-env` / `--full-purge`)**:
   - Remove `CAPA_RULES_PATH`, `RIZIN_SLEIGH_PATH` e `GHIDRA_INSTALL_DIR` do escopo `User`.
5. **Pacote Python e Dependências (`--purge-python-deps` / `--full-purge`)**:
   - Executa `pip uninstall -y flare-re-mcp rzpipe r2pipe yara-python`.

---

## 🛠️ Opção 2 — Passo a Passo Manual (Windows PowerShell & Linux Bash)

Caso deseje auditar ou executar cada etapa manualmente:

### 1. Restaurar o Backup Original do `mcp_config.json`
* **Windows (PowerShell)**:
  ```powershell
  Copy-Item "$env:USERPROFILE\.gemini\config\mcp_config.json.bak" "$env:USERPROFILE\.gemini\config\mcp_config.json" -Force
  Remove-Item "$env:USERPROFILE\.gemini\config\mcp_config.json.bak" -Force
  ```
* **Linux (Bash)**:
  ```bash
  cp ~/.gemini/config/mcp_config.json.bak ~/.gemini/config/mcp_config.json
  rm -f ~/.gemini/config/mcp_config.json.bak
  ```

### 2. Remover Caches, Projetos Ghidra e Ferramentas Portáteis
* **Windows (PowerShell)**:
  ```powershell
  Remove-Item -Recurse -Force .\.analysis_cache, .\ghidra_projects, "$env:USERPROFILE\.flare-re-mcp", "$env:USERPROFILE\.radare2rc", "$env:USERPROFILE\.rizinrc" -ErrorAction SilentlyContinue
  ```
* **Linux (Bash)**:
  ```bash
  rm -rf ./.analysis_cache ./ghidra_projects ~/.flare-re-mcp ~/.radare2rc ~/.rizinrc
  ```

### 3. Desinstalar Pacotes Python
```bash
python -m pip uninstall -y flare-re-mcp rzpipe r2pipe yara-python
```

### 4. Remover Containers e Imagens Docker (Caso tenha utilizado Docker)
```bash
docker compose down --rmi all --volumes --remove-orphans
```

### 5. Remover a Pasta do Projeto
Após salvar quaisquer relatórios desejados de `./reports/`, basta excluir a pasta raiz do repositório:
```powershell
# Windows:
cd ..
Remove-Item -Recurse -Force .\flare-re-mcp
```
