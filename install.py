#!/usr/bin/env python3
"""Universal Automated Installer & Cross-Platform Bootstrapper for `flare-re-mcp`.
Supports:
  - Windows (FlareVM & Standard Windows 10/11 across Python 3.11, 3.12, 3.13, 3.14+)
  - Linux (Ubuntu, Debian, Kali, REMnux, Fedora, Arch, WSL2)
  - Docker Containers

What it does automatically in one command (`python install.py --download-missing`):
  1. Installs Python dependencies (`pip install --prefer-binary -e .`), plus binary wheels for
     `JPype1` + `pyghidra` (`--no-deps` so Python 3.14+ uses `JPype1>=1.7.1` wheel without C++ build)
     and `yara-python` / `yara-x` (`--only-binary=:all:` so it never fails compiling C/C++ wheels).
  2. Discovers existing RE tools (`diec`, `floss`, `capa`, `capa-rules`, `upx`, `rizin` + `rz-ghidra`,
     `radare2` + `r2ghidra`, `ghidra`) and downloads ALL missing official portable GitHub releases
     into `~/.flare-re-mcp/tools/` when `--download-missing` is specified.
  3. Configures `~/.radare2rc` and `~/.rizinrc` (UTF-8 without BOM) with `r2ghidra` and `rz-ghidra` Sleigh paths.
  4. Automatically configures `~/.gemini/config/mcp_config.json` for Antigravity CLI (`agy`) while preserving
     any existing user MCP servers (with automatic `.bak` backup).
  5. Pre-compiles the 997 CAPA rules into `.analysis_cache/_capa_ruleset_cache.pkl` (<0.12s load time).
"""

import argparse
import datetime
import json
import os
import platform
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path
from typing import Any, Dict

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
SRC_DIR = os.path.join(PROJECT_ROOT, "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

IS_WINDOWS = os.name == "nt"
IS_LINUX = sys.platform.startswith("linux")
USER_HOME = os.path.expanduser("~")
PORTABLE_TOOLS_DIR = os.path.join(USER_HOME, ".flare-re-mcp", "tools")

# Official Portable Release URLs for Non-FlareVM Windows & Linux Bootstrap
PORTABLE_RELEASES = {
    "capa_rules": {
        "all": "https://github.com/mandiant/capa-rules/archive/refs/tags/v9.4.0.zip",
    },
    "floss": {
        "windows": "https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-windows.zip",
        "linux": "https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip",
    },
    "capa": {
        "windows": "https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-windows.zip",
        "linux": "https://github.com/mandiant/capa/releases/download/v9.4.0/capa-v9.4.0-linux.zip",
    },
    "die": {
        "windows": "https://github.com/horsicq/DIE-engine/releases/download/3.10/die_win64_portable_3.10_x64.zip",
    },
    "upx": {
        "windows": "https://github.com/upx/upx/releases/download/v4.2.4/upx-4.2.4-win64.zip",
    },
    "radare2": {
        "windows": "https://github.com/radareorg/radare2/releases/download/6.2.4/radare2-6.2.4-w64.zip",
    },
    "r2ghidra": {
        "windows": "https://github.com/radareorg/r2ghidra/releases/download/6.2.4/r2ghidra-6.2.4-w64.zip",
    },
    "r2ghidra_sleigh": {
        "windows": "https://github.com/radareorg/r2ghidra/releases/download/6.2.4/r2ghidra_sleigh-6.2.4.zip",
    },
    "cutter_rizin": {
        "windows": "https://github.com/rizinorg/cutter/releases/download/v2.5.0/Cutter-v2.5.0-Windows-x86_64.zip",
    },
    "ghidra": {
        "all": "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip",
    },
}


def _banner(msg: str) -> None:
    print(f"\n{'=' * 76}\n[flare-re-mcp] {msg}\n{'=' * 76}")


def _download_and_extract_zip(url: str, dest_dir: str) -> bool:
    os.makedirs(dest_dir, exist_ok=True)
    tmp_zip = os.path.join(dest_dir, "_download_tmp.zip")
    try:
        print(f"  -> Baixando: {url}")
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (flare-re-mcp-installer)"})
        with urllib.request.urlopen(req, timeout=600) as resp, open(tmp_zip, "wb") as out_f:
            shutil.copyfileobj(resp, out_f)
        print(f"  -> Extraindo em: {dest_dir}")
        with zipfile.ZipFile(tmp_zip, "r") as zf:
            zf.extractall(dest_dir)
        os.remove(tmp_zip)
        return True
    except Exception as exc:
        print(f"  [!] Aviso ao baixar {url}: {exc}")
        if os.path.exists(tmp_zip):
            try:
                os.remove(tmp_zip)
            except Exception:
                pass
        return False


def step_1_install_python_packages() -> None:
    _banner("Passo 1/5: Instalando Pacote Python `flare-re-mcp` e Dependências (100% Prebuilt Wheels)")

    # 1. Core pure-Python / universal wheel dependencies + editable package
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "--prefer-binary", "-e", PROJECT_ROOT],
        check=False,
    )

    # 2. PyGhidra + JPype1:
    # pyghidra 3.1.0 pins `Jpype1==1.5.2`, which lacks a cp314 wheel on Python 3.14+, whereas `JPype1>=1.7.1`
    # provides pre-compiled binary wheels (`cp310`..`cp314`) on Windows/Linux.
    # By installing `JPype1` with `--only-binary=:all:` and `pyghidra` with `--no-deps`, we never trigger a C++ build!
    print("  -> Instalando wheel binária pré-compilada do JPype1 + PyGhidra...")
    jpype_res = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--only-binary=:all:", "JPype1>=1.5.2", "packaging"],
        check=False,
    )
    if jpype_res.returncode == 0:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--no-deps", "pyghidra>=3.0.0"],
            check=False,
        )
    else:
        print("  [!] Aviso: Wheel binária do JPype1 não disponível para esta arquitetura; ghidra-mcp usará modo Headless CLI se necessário.")

    # 3. YARA Engine:
    # Try pre-compiled `yara-python` wheel first (`cp39`..`cp313`). If running on Python 3.14+ where `yara-python`
    # does not yet publish a wheel, install `yara-x` (VirusTotal's official Rust YARA engine with universal `abi3` wheel).
    print("  -> Instalando motor YARA (wheel binária pré-compilada sem necessidade de compilador C++)...")
    yara_res = subprocess.run(
        [sys.executable, "-m", "pip", "install", "--only-binary=:all:", "yara-python"],
        capture_output=True,
        text=True,
    )
    if yara_res.returncode == 0:
        print("  [OK] `yara-python` instalado via wheel binária pré-compilada.")
    else:
        print("  -> `yara-python` não possui wheel pré-compilada para esta versão do Python; instalando `yara-x` (universal abi3 wheel)...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "--only-binary=:all:", "yara-x"],
            check=False,
        )


def step_2_discover_or_bootstrap_tools(download_missing: bool = False, skip_ghidra_download: bool = False) -> Dict[str, Any]:
    _banner("Passo 2/5: Verificando e Baixando Ferramentas de Engenharia Reversa")
    os.makedirs(PORTABLE_TOOLS_DIR, exist_ok=True)
    os_key = "windows" if IS_WINDOWS else ("linux" if IS_LINUX else "other")

    import importlib
    import flare_re_mcp.common as common

    importlib.reload(common)

    # 1. Bootstrap capa-rules if missing
    if not os.path.isdir(common.CAPA_RULES_DIR) and download_missing:
        rules_target = os.path.join(PORTABLE_TOOLS_DIR, "capa")
        if _download_and_extract_zip(PORTABLE_RELEASES["capa_rules"]["all"], rules_target):
            extracted = os.path.join(rules_target, "capa-rules-9.4.0")
            final_rules = os.path.join(rules_target, "rules")
            if os.path.isdir(extracted):
                if os.path.isdir(final_rules):
                    shutil.rmtree(final_rules, ignore_errors=True)
                shutil.move(extracted, final_rules)

    # 2. Bootstrap FLOSS if missing
    if not os.path.isfile(common.FLOSS_BIN) and download_missing and os_key in PORTABLE_RELEASES["floss"]:
        floss_dir = os.path.join(PORTABLE_TOOLS_DIR, "floss")
        if _download_and_extract_zip(PORTABLE_RELEASES["floss"][os_key], floss_dir) and not IS_WINDOWS:
            floss_bin = os.path.join(floss_dir, "floss")
            if os.path.isfile(floss_bin):
                os.chmod(floss_bin, 0o755)

    # 3. Bootstrap CAPA CLI if missing
    if not os.path.isfile(common.CAPA_BIN) and download_missing and os_key in PORTABLE_RELEASES["capa"]:
        capa_dir = os.path.join(PORTABLE_TOOLS_DIR, "capa")
        if _download_and_extract_zip(PORTABLE_RELEASES["capa"][os_key], capa_dir) and not IS_WINDOWS:
            capa_bin = os.path.join(capa_dir, "capa")
            if os.path.isfile(capa_bin):
                os.chmod(capa_bin, 0o755)

    # 4. Bootstrap DIE if missing on Windows
    if not os.path.isfile(common.DIEC_BIN) and download_missing and os_key in PORTABLE_RELEASES["die"]:
        die_dir = os.path.join(PORTABLE_TOOLS_DIR, "die")
        _download_and_extract_zip(PORTABLE_RELEASES["die"][os_key], die_dir)

    # 5. Bootstrap UPX if missing on Windows
    if not os.path.isfile(common.UPX_BIN) and download_missing and os_key in PORTABLE_RELEASES["upx"]:
        upx_extract = os.path.join(PORTABLE_TOOLS_DIR, "upx_extract")
        if _download_and_extract_zip(PORTABLE_RELEASES["upx"][os_key], upx_extract):
            upx_dir = os.path.join(PORTABLE_TOOLS_DIR, "upx")
            os.makedirs(upx_dir, exist_ok=True)
            for root, _, files in os.walk(upx_extract):
                for fn in files:
                    if fn.lower() == "upx.exe":
                        shutil.copy2(os.path.join(root, fn), os.path.join(upx_dir, "upx.exe"))
            shutil.rmtree(upx_extract, ignore_errors=True)

    # 6. Bootstrap Radare2 + r2ghidra + r2ghidra_sleigh on Windows if missing
    if (not os.path.isfile(common.R2_BIN) or not os.path.isdir(common.R2_SLEIGH_DIR)) and download_missing and IS_WINDOWS:
        target_r2 = os.path.join(PORTABLE_TOOLS_DIR, "radare2")
        if not os.path.isfile(common.R2_BIN):
            r2_base = os.path.join(PORTABLE_TOOLS_DIR, "radare2_extract")
            if _download_and_extract_zip(PORTABLE_RELEASES["radare2"]["windows"], r2_base):
                sub = os.path.join(r2_base, "radare2-6.2.4-w64")
                if os.path.isdir(sub):
                    if os.path.isdir(target_r2):
                        shutil.rmtree(target_r2, ignore_errors=True)
                    shutil.move(sub, target_r2)
                shutil.rmtree(r2_base, ignore_errors=True)

        plugins_dst = os.path.join(target_r2, "lib", "plugins") if os.path.isdir(target_r2) else os.path.join(os.path.dirname(os.path.dirname(common.R2_BIN)), "lib", "plugins")
        os.makedirs(plugins_dst, exist_ok=True)

        # Download core_r2ghidra.dll
        r2g_base = os.path.join(PORTABLE_TOOLS_DIR, "r2ghidra_extract")
        if _download_and_extract_zip(PORTABLE_RELEASES["r2ghidra"]["windows"], r2g_base):
            for root, _, files in os.walk(r2g_base):
                for fn in files:
                    if fn.endswith(".dll"):
                        shutil.copy2(os.path.join(root, fn), os.path.join(plugins_dst, fn))
            shutil.rmtree(r2g_base, ignore_errors=True)

        # Download r2ghidra_sleigh-6.2.4.zip
        sleigh_dst = os.path.join(plugins_dst, "r2ghidra_sleigh")
        if not os.path.isdir(sleigh_dst):
            sleigh_base = os.path.join(PORTABLE_TOOLS_DIR, "r2ghidra_sleigh_extract")
            if _download_and_extract_zip(PORTABLE_RELEASES["r2ghidra_sleigh"]["windows"], sleigh_base):
                sub_sleigh = os.path.join(sleigh_base, "r2ghidra_sleigh-6.2.4")
                if os.path.isdir(sub_sleigh):
                    shutil.move(sub_sleigh, sleigh_dst)
                shutil.rmtree(sleigh_base, ignore_errors=True)

    # 7. Bootstrap Rizin + rz_ghidra_sleigh (via official Cutter portable bundle) on Windows if missing
    if (not os.path.isfile(common.RIZIN_BIN) or not os.path.isdir(common.RIZIN_SLEIGH_DIR)) and download_missing and IS_WINDOWS:
        rz_extract = os.path.join(PORTABLE_TOOLS_DIR, "rizin_extract")
        if _download_and_extract_zip(PORTABLE_RELEASES["cutter_rizin"]["windows"], rz_extract):
            sub_cutter = os.path.join(rz_extract, "Cutter-v2.5.0-Windows-x86_64")
            target_rz = os.path.join(PORTABLE_TOOLS_DIR, "rizin")
            if os.path.isdir(sub_cutter):
                if os.path.isdir(target_rz):
                    shutil.rmtree(target_rz, ignore_errors=True)
                shutil.move(sub_cutter, target_rz)
            shutil.rmtree(rz_extract, ignore_errors=True)

    # 8. Bootstrap Ghidra 12.1.4 if missing
    if not os.path.isdir(common.GHIDRA_INSTALL_DIR) and download_missing and not skip_ghidra_download:
        ghidra_base = os.path.join(PORTABLE_TOOLS_DIR, "ghidra")
        _download_and_extract_zip(PORTABLE_RELEASES["ghidra"]["all"], ghidra_base)

    importlib.reload(common)

    status = {
        "os_platform": f"{platform.system()} {platform.release()} ({platform.machine()})",
        "python_version": sys.version.split()[0],
        "environment_type": (
            "FlareVM (Windows)"
            if (IS_WINDOWS and os.path.isdir(r"C:\Tools\capa"))
            else ("Windows Standard" if IS_WINDOWS else "Linux / Container")
        ),
        "tools": {
            "diec": {"path": common.DIEC_BIN, "installed": os.path.isfile(common.DIEC_BIN)},
            "floss": {"path": common.FLOSS_BIN, "installed": os.path.isfile(common.FLOSS_BIN)},
            "capa": {"path": common.CAPA_BIN, "installed": os.path.isfile(common.CAPA_BIN)},
            "capa_rules": {"path": common.CAPA_RULES_DIR, "installed": os.path.isdir(common.CAPA_RULES_DIR)},
            "upx": {"path": common.UPX_BIN, "installed": os.path.isfile(common.UPX_BIN)},
            "rizin": {"path": common.RIZIN_BIN, "installed": os.path.isfile(common.RIZIN_BIN)},
            "rz_ghidra_sleigh": {"path": common.RIZIN_SLEIGH_DIR, "installed": os.path.isdir(common.RIZIN_SLEIGH_DIR)},
            "radare2": {"path": common.R2_BIN, "installed": os.path.isfile(common.R2_BIN)},
            "r2ghidra_sleigh": {"path": common.R2_SLEIGH_DIR, "installed": os.path.isdir(common.R2_SLEIGH_DIR)},
            "ghidra": {"path": common.GHIDRA_INSTALL_DIR, "installed": os.path.isdir(common.GHIDRA_INSTALL_DIR)},
        },
    }
    for tname, tinfo in status["tools"].items():
        badge = "[OK]" if tinfo["installed"] else "[AUSENTE - use --download-missing]"
        print(f"  {badge:34s} {tname:18s} -> {tinfo['path']}")
    return status


def step_3_configure_rc_files() -> None:
    _banner("Passo 3/5: Configurando ~/.radare2rc e ~/.rizinrc (UTF-8 sem BOM)")
    import flare_re_mcp.common as common

    if common.R2_SLEIGH_DIR and os.path.isdir(common.R2_SLEIGH_DIR):
        r2rc = os.path.join(USER_HOME, ".radare2rc")
        with open(r2rc, "wb") as f:
            f.write(f"e r2ghidra.sleighhome={common.R2_SLEIGH_DIR}\n".encode("utf-8"))
        print(f"  [OK] Configurado: {r2rc}")

    if common.RIZIN_SLEIGH_DIR and os.path.isdir(common.RIZIN_SLEIGH_DIR):
        rzrc = os.path.join(USER_HOME, ".rizinrc")
        with open(rzrc, "wb") as f:
            f.write(f"e ghidra.sleighhome={common.RIZIN_SLEIGH_DIR}\n".encode("utf-8"))
        print(f"  [OK] Configurado: {rzrc}")


def step_4_configure_mcp_config() -> str:
    _banner("Passo 4/5: Configurando Automaticamente `~/.gemini/config/mcp_config.json`")
    import flare_re_mcp.common as common

    gemini_cfg_dir = os.path.join(USER_HOME, ".gemini", "config")
    os.makedirs(gemini_cfg_dir, exist_ok=True)
    mcp_cfg_path = os.path.join(gemini_cfg_dir, "mcp_config.json")

    existing_cfg: Dict[str, Any] = {"mcpServers": {}}
    if os.path.isfile(mcp_cfg_path):
        try:
            with open(mcp_cfg_path, "r", encoding="utf-8") as f:
                existing_cfg = json.load(f)
            bak_path = f"{mcp_cfg_path}.bak"
            shutil.copy2(mcp_cfg_path, bak_path)
            print(f"  [OK] Backup criado em: {bak_path}")
        except Exception:
            existing_cfg = {"mcpServers": {}}

    servers = existing_cfg.setdefault("mcpServers", {})
    py_exe = sys.executable

    # Ensure ms-learn is registered
    servers.setdefault(
        "ms-learn",
        {
            "type": "http",
            "url": "https://learn.microsoft.com/api/mcp",
        },
    )

    # Register all 8 local flare-re-mcp servers dynamically using current Python & discovered paths
    base_env = {"PYTHONPATH": SRC_DIR}
    servers["die-mcp"] = {
        "command": py_exe,
        "args": ["-m", "flare_re_mcp.die_server"],
        "env": dict(base_env),
    }
    servers["floss-mcp"] = {
        "command": py_exe,
        "args": ["-m", "flare_re_mcp.floss_server"],
        "env": dict(base_env),
    }
    servers["capa-mcp"] = {
        "command": py_exe,
        "args": ["-m", "flare_re_mcp.capa_server"],
        "env": {
            **base_env,
            "CAPA_RULES_PATH": common.CAPA_RULES_DIR,
            "GHIDRA_INSTALL_DIR": common.GHIDRA_INSTALL_DIR,
        },
    }
    servers["rizin-mcp"] = {
        "command": py_exe,
        "args": ["-m", "flare_re_mcp.rizin_server"],
        "env": {
            **base_env,
            "CAPA_RULES_PATH": common.CAPA_RULES_DIR,
            "RIZIN_SLEIGH_PATH": common.RIZIN_SLEIGH_DIR,
        },
    }
    servers["radare2-mcp"] = {
        "command": py_exe,
        "args": ["-m", "flare_re_mcp.radare2_server"],
        "env": dict(base_env),
    }
    servers["ghidra-mcp"] = {
        "command": py_exe,
        "args": ["-m", "flare_re_mcp.ghidra_server"],
        "env": {
            **base_env,
            "GHIDRA_INSTALL_DIR": common.GHIDRA_INSTALL_DIR,
        },
    }
    servers["unpacker-mcp"] = {
        "command": py_exe,
        "args": ["-m", "flare_re_mcp.unpacker_server"],
        "env": dict(base_env),
    }
    servers["threat-intel-mcp"] = {
        "command": py_exe,
        "args": ["-m", "flare_re_mcp.threat_intel_server"],
        "env": dict(base_env),
    }

    with open(mcp_cfg_path, "w", encoding="utf-8") as f:
        json.dump(existing_cfg, f, ensure_ascii=False, indent=2)

    print(f"  [OK] {len(servers)} servidores MCP registrados em: {mcp_cfg_path}")
    return mcp_cfg_path


def step_5_prewarm_capa_cache() -> None:
    _banner("Passo 5/5: Pré-Compilando Cache Binário `.pkl` das Regras CAPA")
    try:
        import importlib
        import flare_re_mcp.common as common

        importlib.reload(common)
        t0 = datetime.datetime.now()
        rs = common.get_cached_capa_ruleset()
        elapsed = (datetime.datetime.now() - t0).total_seconds()
        rules_count = len(getattr(rs, "rules", {}))
        print(f"  [OK] {rules_count} regras CAPA prontas em cache ({elapsed:.2f}s)!")
    except Exception as exc:
        print(f"  [!] Aviso ao pré-aquecer regras CAPA: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Instalador Automatizado Universal do flare-re-mcp")
    parser.add_argument(
        "--download-missing",
        action="store_true",
        help="Baixa automaticamente todas as ferramentas portáteis oficiais ausentes (FLOSS, CAPA, capa-rules, DIE, UPX, Radare2+r2ghidra, Rizin/Cutter+rz-ghidra e Ghidra 12.1.4)",
    )
    parser.add_argument(
        "--skip-ghidra-download",
        action="store_true",
        help="Pula apenas o download do arquivo portátil do Ghidra (~543 MB) caso queira instalá-lo separadamente",
    )
    parser.add_argument(
        "--skip-pip",
        action="store_true",
        help="Pula a etapa de pip install (útil para apenas reconfigurar o mcp_config.json)",
    )
    args = parser.parse_args()

    if not args.skip_pip:
        step_1_install_python_packages()
    step_2_discover_or_bootstrap_tools(
        download_missing=args.download_missing,
        skip_ghidra_download=args.skip_ghidra_download,
    )
    step_3_configure_rc_files()
    mcp_path = step_4_configure_mcp_config()
    step_5_prewarm_capa_cache()

    _banner("INSTALAÇÃO CONCLUÍDA COM SUCESSO!")
    print(f"  • Arquivo MCP configurado: {mcp_path}")
    print(f"  • Diretório do projeto   : {PROJECT_ROOT}")
    print("  • Próximo passo          : Basta executar `agy` nesta pasta e pedir a análise de qualquer binário!")


if __name__ == "__main__":
    main()
