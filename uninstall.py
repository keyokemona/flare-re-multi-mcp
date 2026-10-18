#!/usr/bin/env python3
"""Complete Zero-Residue Uninstaller for `flare-re-mcp` (`flare-re-uninstall`).
Cleans up:
  1. MCP server entries registered in `~/.gemini/config/mcp_config.json`
  2. All analysis caches (`.analysis_cache/`), persistent Ghidra databases (`ghidra_projects/`),
     and portable downloaded tools (`~/.flare-re-mcp/`)
  3. Configuration files `~/.radare2rc` and `~/.rizinrc`
  4. User environment variables (`CAPA_RULES_PATH`, `RIZIN_SLEIGH_PATH`, `GHIDRA_INSTALL_DIR`) if `--purge-env`
  5. Editable package `flare-re-mcp` (and optionally MCP Python dependencies if `--purge-python-deps`)
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from typing import List

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
USER_HOME = os.path.expanduser("~")
IS_WINDOWS = os.name == "nt"

SUITE_MCP_SERVERS = [
    "die-mcp",
    "floss-mcp",
    "capa-mcp",
    "rizin-mcp",
    "radare2-mcp",
    "ghidra-mcp",
    "unpacker-mcp",
    "threat-intel-mcp",
]


def _banner(msg: str) -> None:
    print(f"\n{'=' * 76}\n[flare-re-mcp UNINSTALLER] {msg}\n{'=' * 76}")


def step_1_clean_mcp_config(remove_ms_learn: bool = False) -> None:
    _banner("Passo 1/5: Removendo Servidores MCP de `~/.gemini/config/mcp_config.json`")
    mcp_cfg_path = os.path.join(USER_HOME, ".gemini", "config", "mcp_config.json")
    if not os.path.isfile(mcp_cfg_path):
        print("  [i] Arquivo mcp_config.json não encontrado. Nada a remover.")
        return

    try:
        with open(mcp_cfg_path, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        servers = cfg.get("mcpServers", {})
        removed = []
        target_keys = list(SUITE_MCP_SERVERS) + (["ms-learn"] if remove_ms_learn else [])
        for k in target_keys:
            if k in servers:
                del servers[k]
                removed.append(k)
        with open(mcp_cfg_path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        print(f"  [OK] Removidos {len(removed)} servidores do mcp_config.json: {', '.join(removed) or 'nenhum'}")
    except Exception as exc:
        print(f"  [!] Erro ao limpar mcp_config.json: {exc}")


def step_2_remove_caches_and_portable_tools(remove_reports: bool = False) -> None:
    _banner("Passo 2/5: Removendo Caches SHA-256, Projetos Ghidra e Ferramentas Portáteis")
    dirs_to_remove: List[str] = [
        os.path.join(PROJECT_ROOT, ".analysis_cache"),
        os.path.join(PROJECT_ROOT, "ghidra_projects"),
        os.path.join(PROJECT_ROOT, "src", "flare_re_mcp.egg-info"),
        os.path.join(PROJECT_ROOT, "src", "flare_re_mcp", "__pycache__"),
        os.path.join(USER_HOME, ".flare-re-mcp"),
    ]
    if remove_reports:
        dirs_to_remove.append(os.path.join(PROJECT_ROOT, "reports"))

    for d in dirs_to_remove:
        if os.path.exists(d):
            try:
                shutil.rmtree(d, ignore_errors=True)
                print(f"  [OK] Diretório removido: {d}")
            except Exception as exc:
                print(f"  [!] Aviso ao remover {d}: {exc}")
        else:
            print(f"  [i] Já ausente: {d}")


def step_3_remove_rc_configs() -> None:
    _banner("Passo 3/5: Limpando Arquivos `~/.radare2rc` e `~/.rizinrc`")
    for rc_name in [".radare2rc", ".rizinrc"]:
        rc_path = os.path.join(USER_HOME, rc_name)
        if os.path.isfile(rc_path):
            try:
                os.remove(rc_path)
                print(f"  [OK] Removido: {rc_path}")
            except Exception as exc:
                print(f"  [!] Aviso ao remover {rc_path}: {exc}")


def step_4_clean_environment_variables(purge_env: bool = False) -> None:
    _banner("Passo 4/5: Limpando Variáveis de Ambiente de Usuário")
    if not purge_env:
        print("  [i] Pulo de variáveis de ambiente do SO (passe `--purge-env` para removê-las do registro do usuário).")
        return
    if IS_WINDOWS:
        for var in ["CAPA_RULES_PATH", "RIZIN_SLEIGH_PATH", "GHIDRA_INSTALL_DIR"]:
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", f"[Environment]::SetEnvironmentVariable('{var}', $null, 'User')"],
                check=False,
            )
            print(f"  [OK] Variável de usuário removida: {var}")


def step_5_uninstall_python_packages(purge_deps: bool = False) -> None:
    _banner("Passo 5/5: Desinstalando Pacote Python `flare-re-mcp`")
    subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", "flare-re-mcp"], check=False)
    print("  [OK] Pacote `flare-re-mcp` desinstalado do ambiente Python.")

    if purge_deps:
        deps = ["rzpipe", "r2pipe", "yara-python"]
        subprocess.run([sys.executable, "-m", "pip", "uninstall", "-y", *deps], check=False)
        print(f"  [OK] Dependências extras removidas: {', '.join(deps)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Desinstalador Completo Zero-Resíduos do flare-re-mcp")
    parser.add_argument("--remove-reports", action="store_true", help="Remove também a pasta ./reports/")
    parser.add_argument("--purge-env", action="store_true", help="Remove variáveis de ambiente de usuário criadas")
    parser.add_argument("--purge-python-deps", action="store_true", help="Desinstala também rzpipe, r2pipe e yara-python")
    parser.add_argument("--full-purge", action="store_true", help="Executa limpeza total (caches + env + pacotes Python)")
    args = parser.parse_args()

    step_1_clean_mcp_config()
    step_2_remove_caches_and_portable_tools(remove_reports=args.remove_reports or args.full_purge)
    step_3_remove_rc_configs()
    step_4_clean_environment_variables(purge_env=args.purge_env or args.full_purge)
    step_5_uninstall_python_packages(purge_deps=args.purge_python_deps or args.full_purge)

    _banner("DESINSTALAÇÃO CONCLUÍDA — SISTEMA LIMPO E SEM RESQUÍCIOS!")


if __name__ == "__main__":
    main()
