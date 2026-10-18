"""Non-Blocking Startup Version Checker & Auto-Updater (`flare-re-update`).
Runs automatically on `agy` session startup (via `.agents/hooks.json` and `orchestrator_qa.py` with a 12-hour
cooldown cache so startup is never delayed) or manually via `flare-re-update` / `python -m flare_re_mcp.auto_updater`.

Strategy selected by user:
  - Fast non-blocking check on startup
  - Automatic lightweight updates (Python packages, CAPA `.pkl` ruleset cache, STIX verification)
  - Dedicated `flare-re-update --update-all` command for heavy binary releases
"""

import argparse
import datetime
import importlib.metadata
import json
import os
import subprocess
import sys
import time
import urllib.request
from typing import Any, Dict, Optional

from flare_re_mcp.common import (
    ANALYSIS_CACHE_DIR,
    CAPA_BIN,
    CAPA_RULES_DIR,
    DIEC_BIN,
    FLOSS_BIN,
    GHIDRA_INSTALL_DIR,
    PROJECT_ROOT,
    R2_BIN,
    RIZIN_BIN,
    get_cached_capa_ruleset,
)
from flare_re_mcp.unpacker_server import UPX_BIN

UPDATE_STATE_FILE = os.path.join(ANALYSIS_CACHE_DIR, "_last_update_check.json")
CHECK_COOLDOWN_SECONDS = 12 * 3600  # 12 hours

GITHUB_REPOS = {
    "capa-rules": "mandiant/capa-rules",
    "capa": "mandiant/capa",
    "floss": "mandiant/flare-floss",
    "radare2": "radareorg/radare2",
    "rizin": "rizinorg/rizin",
}


def _get_cmd_version(cmd_args: list[str]) -> str:
    if not cmd_args or not cmd_args[0] or not os.path.isfile(cmd_args[0]):
        return "not_installed"
    try:
        r = subprocess.run(cmd_args, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=5)
        out = (r.stdout or r.stderr or "").strip()
        return out.splitlines()[0] if out else "installed"
    except Exception:
        return "installed"


def _get_pkg_version(pkg_name: str) -> str:
    try:
        return importlib.metadata.version(pkg_name)
    except Exception:
        return "not_installed"


def _fetch_github_latest_tag(repo: str, timeout: int = 3) -> Optional[str]:
    url = f"https://api.github.com/repos/{repo}/releases/latest"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "flare-re-mcp-updater"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            return data.get("tag_name")
    except Exception:
        return None


def check_all_components(check_remote: bool = True, force: bool = False) -> Dict[str, Any]:
    """Inspect local versions of all tools, Python libraries, and STIX datasets, and optionally check upstream tags."""
    now_ts = time.time()
    if not force and os.path.isfile(UPDATE_STATE_FILE):
        try:
            with open(UPDATE_STATE_FILE, "r", encoding="utf-8") as f:
                cached = json.load(f)
            if now_ts - float(cached.get("checked_at_epoch", 0)) < CHECK_COOLDOWN_SECONDS:
                cached["from_cooldown_cache"] = True
                return cached
        except Exception:
            pass

    local_python_pkgs = {
        "flare-re-mcp": _get_pkg_version("flare-re-mcp"),
        "flare-capa": _get_pkg_version("flare-capa"),
        "pefile": _get_pkg_version("pefile"),
        "yara-python": _get_pkg_version("yara-python"),
        "rzpipe": _get_pkg_version("rzpipe"),
        "r2pipe": _get_pkg_version("r2pipe"),
        "pyghidra": _get_pkg_version("pyghidra"),
    }

    local_cli_tools = {
        "diec": _get_cmd_version([DIEC_BIN, "--version"]),
        "floss": _get_cmd_version([FLOSS_BIN, "--version"]),
        "capa": _get_cmd_version([CAPA_BIN, "--version"]),
        "rizin": _get_cmd_version([RIZIN_BIN, "-v"]),
        "radare2": _get_cmd_version([R2_BIN, "-v"]),
        "upx": _get_cmd_version([UPX_BIN, "--version"]),
        "ghidra_dir": os.path.basename(GHIDRA_INSTALL_DIR) if os.path.isdir(GHIDRA_INSTALL_DIR) else "not_installed",
        "capa_rules_dir": CAPA_RULES_DIR if os.path.isdir(CAPA_RULES_DIR) else "not_installed",
    }

    stix_path = os.path.expanduser(r"~\.mitre-mcp-server\data\v20.0\enterprise-attack.json")
    mitre_stix_status = "v20.0 (Enterprise/Mobile/ICS)" if os.path.isfile(stix_path) else "external_or_custom"

    upstream_latest: Dict[str, Optional[str]] = {}
    if check_remote:
        for name, repo in GITHUB_REPOS.items():
            upstream_latest[name] = _fetch_github_latest_tag(repo, timeout=3)

    report = {
        "status": "up_to_date",
        "checked_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "checked_at_epoch": now_ts,
        "from_cooldown_cache": False,
        "mitre_attack_stix_version": mitre_stix_status,
        "python_packages": local_python_pkgs,
        "native_cli_tools": local_cli_tools,
        "upstream_latest_releases": upstream_latest,
    }
    try:
        with open(UPDATE_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return report


def run_auto_update(update_heavy_binaries: bool = False) -> Dict[str, Any]:
    """Perform automatic lightweight updates (pip dependencies + CAPA ruleset `.pkl` cache rebuild)
    and optionally bootstrap/update portable binary tools via `install.py --download-missing`.
    """
    actions = []
    # 1. Lightweight pip editable refresh
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "-q", "-e", PROJECT_ROOT],
        check=False,
    )
    actions.append("Synchronized `flare-re-mcp` editable package metadata.")

    # 2. Rebuild CAPA .pkl ruleset cache if rules folder was modified more recently than cache
    cache_pkl = os.path.join(ANALYSIS_CACHE_DIR, "_capa_ruleset_cache.pkl")
    if os.path.isdir(CAPA_RULES_DIR):
        get_cached_capa_ruleset()
        actions.append(f"Verified CAPA `.pkl` binary ruleset cache ({cache_pkl}).")

    # 3. Heavy binaries update if requested
    if update_heavy_binaries:
        installer_script = os.path.join(PROJECT_ROOT, "install.py")
        if os.path.isfile(installer_script):
            subprocess.run([sys.executable, installer_script, "--download-missing", "--skip-pip"], check=False)
            actions.append("Executed full portable binary & MCP config update (`install.py --download-missing`).")

    status = check_all_components(check_remote=True, force=True)
    status["update_actions_performed"] = actions
    return status


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Flare-RE-MCP Startup Version Checker & Auto-Updater")
    parser.add_argument("--startup-hook", action="store_true", help="Fast non-blocking check for `agy` startup hook")
    parser.add_argument("--force-check", "--status", dest="force_check", action="store_true", help="Bypass 12-hour cooldown cache and check upstream")
    parser.add_argument("--update-all", action="store_true", help="Update Python packages, rules, and missing binaries")
    args = parser.parse_args()

    if args.update_all:
        res = run_auto_update(update_heavy_binaries=True)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return

    if args.startup_hook:
        res = check_all_components(check_remote=False, force=False)
        # Keep startup hook output ultra-concise
        print(
            f"[flare-re-mcp auto-check] OK | MITRE ATT&CK {res.get('mitre_attack_stix_version')} | "
            f"CAPA {res['python_packages'].get('flare-capa')} | FLOSS {res['native_cli_tools'].get('floss')}"
        )
        return

    res = check_all_components(check_remote=True, force=args.force_check)
    print(json.dumps(res, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
