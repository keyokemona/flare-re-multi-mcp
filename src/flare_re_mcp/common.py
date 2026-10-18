"""Shared utilities, FlareVM tool path discovery, SHA-256 artifact cache,
REA-inspired Evidence Ledger, and MITRE ATT&CK / Microsoft Learn cross-enrichment.
"""

import contextlib
import datetime
import hashlib
import json
import os
import pickle
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import glob
import platform

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
ANALYSIS_CACHE_DIR = os.path.join(PROJECT_ROOT, ".analysis_cache")
REPORTS_DIR = os.path.join(PROJECT_ROOT, "reports")
USER_PORTABLE_TOOLS_DIR = os.path.join(os.path.expanduser("~"), ".flare-re-mcp", "tools")
os.makedirs(ANALYSIS_CACHE_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

IS_WINDOWS = os.name == "nt"
EXE_EXT = ".exe" if IS_WINDOWS else ""


def _first_existing_path(candidates: List[Optional[str]], expect_dir: bool = False) -> str:
    """Return the first existing file or directory from a prioritized list of candidate paths."""
    for cand in candidates:
        if not cand:
            continue
        expanded = os.path.expandvars(os.path.expanduser(cand))
        if "*" in expanded:
            matches = sorted(glob.glob(expanded), reverse=True)
            for m in matches:
                if (expect_dir and os.path.isdir(m)) or (not expect_dir and os.path.isfile(m)):
                    return os.path.abspath(m)
        else:
            if (expect_dir and os.path.isdir(expanded)) or (not expect_dir and os.path.isfile(expanded)):
                return os.path.abspath(expanded)
    # Fallback to first non-empty candidate so callers still see expected default path
    for cand in candidates:
        if cand and "*" not in cand:
            return cand
    return ""


# --- Cross-Platform (FlareVM + Standard Windows + Linux/REMnux/Kali/Docker) Tool Discovery ---
DIE_DIR = _first_existing_path(
    [
        os.environ.get("DIE_DIR"),
        r"C:\Tools\die" if IS_WINDOWS else None,
        os.path.join(USER_PORTABLE_TOOLS_DIR, "die"),
        "/opt/die" if not IS_WINDOWS else None,
        "/usr/local/bin" if not IS_WINDOWS else None,
    ],
    expect_dir=True,
)
DIEC_BIN = _first_existing_path(
    [
        os.environ.get("DIEC_BIN"),
        shutil.which("diec"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "die", f"diec{EXE_EXT}"),
        os.path.join(DIE_DIR, f"diec{EXE_EXT}") if DIE_DIR else None,
        r"C:\Tools\die\diec.exe" if IS_WINDOWS else "/usr/bin/diec",
    ]
)

FLOSS_BIN = _first_existing_path(
    [
        os.environ.get("FLOSS_BIN"),
        shutil.which("floss"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "floss", f"floss{EXE_EXT}"),
        r"C:\Tools\FLOSS\floss.exe" if IS_WINDOWS else "/usr/local/bin/floss",
        "/usr/bin/floss" if not IS_WINDOWS else None,
    ]
)

CAPA_BIN = _first_existing_path(
    [
        os.environ.get("CAPA_BIN"),
        shutil.which("capa"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "capa", f"capa{EXE_EXT}"),
        r"C:\Tools\capa\capa.exe" if IS_WINDOWS else "/usr/local/bin/capa",
        "/usr/bin/capa" if not IS_WINDOWS else None,
    ]
)

CAPA_RULES_DIR = _first_existing_path(
    [
        os.environ.get("CAPA_RULES_PATH"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "capa", "rules"),
        r"C:\Tools\capa\rules" if IS_WINDOWS else None,
        os.path.join(PROJECT_ROOT, "rules"),
        "/opt/capa-rules" if not IS_WINDOWS else None,
        "/usr/share/capa-rules" if not IS_WINDOWS else None,
    ],
    expect_dir=True,
)

CUTTER_DIR = _first_existing_path(
    [
        os.environ.get("CUTTER_DIR"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "rizin"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "rizin", "bin"),
        r"C:\Tools\Cutter\Cutter-v2.5.0-Windows-x86_64" if IS_WINDOWS else None,
        r"C:\Tools\Cutter\Cutter-*" if IS_WINDOWS else None,
        "/usr/local/bin" if not IS_WINDOWS else None,
        "/usr/bin" if not IS_WINDOWS else None,
    ],
    expect_dir=True,
)

RIZIN_BIN = _first_existing_path(
    [
        os.environ.get("RIZIN_BIN"),
        shutil.which("rizin"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "rizin", f"rizin{EXE_EXT}"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "rizin", "bin", f"rizin{EXE_EXT}"),
        os.path.join(CUTTER_DIR, f"rizin{EXE_EXT}") if CUTTER_DIR else None,
        r"C:\Tools\Cutter\Cutter-v2.5.0-Windows-x86_64\rizin.exe" if IS_WINDOWS else "/usr/bin/rizin",
        "/usr/local/bin/rizin" if not IS_WINDOWS else None,
    ]
)

RIZIN_SLEIGH_DIR = _first_existing_path(
    [
        os.environ.get("RIZIN_SLEIGH_PATH"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "rizin", "lib", "rizin", "plugins", "rz_ghidra_sleigh"),
        os.path.join(CUTTER_DIR, "lib", "rizin", "plugins", "rz_ghidra_sleigh") if CUTTER_DIR else None,
        r"C:\Tools\Cutter\Cutter-v2.5.0-Windows-x86_64\lib\rizin\plugins\rz_ghidra_sleigh" if IS_WINDOWS else None,
        "/usr/lib/x86_64-linux-gnu/rizin/plugins/rz_ghidra_sleigh" if not IS_WINDOWS else None,
        "/usr/local/lib/rizin/plugins/rz_ghidra_sleigh" if not IS_WINDOWS else None,
        "/usr/share/rizin/rz_ghidra_sleigh" if not IS_WINDOWS else None,
    ],
    expect_dir=True,
)

R2_DIR = _first_existing_path(
    [
        os.environ.get("R2_DIR"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "radare2", "bin"),
        r"C:\Tools\radare2\radare2-6.2.4-w64\bin" if IS_WINDOWS else None,
        r"C:\Tools\radare2\radare2-*\bin" if IS_WINDOWS else None,
        "/usr/local/bin" if not IS_WINDOWS else None,
        "/usr/bin" if not IS_WINDOWS else None,
    ],
    expect_dir=True,
)

R2_BIN = _first_existing_path(
    [
        os.environ.get("R2_BIN"),
        shutil.which("radare2"),
        shutil.which("r2"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "radare2", "bin", f"radare2{EXE_EXT}"),
        os.path.join(R2_DIR, f"radare2{EXE_EXT}") if R2_DIR else None,
        r"C:\Tools\radare2\radare2-6.2.4-w64\bin\radare2.exe" if IS_WINDOWS else "/usr/bin/radare2",
        "/usr/local/bin/radare2" if not IS_WINDOWS else None,
    ]
)

R2_SLEIGH_DIR = _first_existing_path(
    [
        os.environ.get("R2_SLEIGH_PATH"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "radare2", "lib", "plugins", "r2ghidra_sleigh"),
        r"C:\Tools\radare2\radare2-6.2.4-w64\lib\plugins\r2ghidra_sleigh" if IS_WINDOWS else None,
        r"C:\Tools\radare2\radare2-*\lib\plugins\r2ghidra_sleigh" if IS_WINDOWS else None,
        os.path.expanduser("~/.local/share/radare2/plugins/r2ghidra_sleigh"),
        "/usr/local/lib/radare2/last/r2ghidra_sleigh" if not IS_WINDOWS else None,
        "/usr/share/radare2/plugins/r2ghidra_sleigh" if not IS_WINDOWS else None,
    ],
    expect_dir=True,
)

UPX_BIN = _first_existing_path(
    [
        os.environ.get("UPX_BIN"),
        shutil.which("upx"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "upx", f"upx{EXE_EXT}"),
        r"C:\Tools\UniExtract\UniExtract\bin\upx.exe" if IS_WINDOWS else None,
        r"C:\Tools\Explorer Suite\Extensions\CFF Explorer\UPX Utility\upx.exe" if IS_WINDOWS else None,
        r"C:\Tools\upx\upx.exe" if IS_WINDOWS else "/usr/bin/upx",
        "/usr/local/bin/upx" if not IS_WINDOWS else None,
    ]
)

GHIDRA_INSTALL_DIR = _first_existing_path(
    [
        os.environ.get("GHIDRA_INSTALL_DIR") if os.path.isdir(os.environ.get("GHIDRA_INSTALL_DIR", "")) else None,
        os.path.join(USER_PORTABLE_TOOLS_DIR, "ghidra", "ghidra_12.1.4_PUBLIC"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "ghidra", "ghidra_*_PUBLIC"),
        r"C:\ProgramData\chocolatey\lib\ghidra\tools\ghidra_12.1.4_PUBLIC" if IS_WINDOWS else None,
        r"C:\ProgramData\chocolatey\lib\ghidra\tools\ghidra_*_PUBLIC" if IS_WINDOWS else None,
        r"C:\Tools\ghidra\ghidra_*_PUBLIC" if IS_WINDOWS else None,
        "/opt/ghidra" if not IS_WINDOWS else None,
        "/opt/ghidra_*" if not IS_WINDOWS else None,
        "/usr/share/ghidra" if not IS_WINDOWS else None,
    ],
    expect_dir=True,
)
if GHIDRA_INSTALL_DIR and os.path.isdir(GHIDRA_INSTALL_DIR):
    os.environ["GHIDRA_INSTALL_DIR"] = GHIDRA_INSTALL_DIR

# Ensure discovered tool directories are present on process PATH
for _tool_dir in [
    DIE_DIR,
    CUTTER_DIR,
    R2_DIR,
    os.path.dirname(DIEC_BIN) if DIEC_BIN else "",
    os.path.dirname(CAPA_BIN) if CAPA_BIN else "",
    os.path.dirname(FLOSS_BIN) if FLOSS_BIN else "",
    os.path.dirname(RIZIN_BIN) if RIZIN_BIN else "",
    os.path.dirname(R2_BIN) if R2_BIN else "",
    os.path.dirname(UPX_BIN) if UPX_BIN else "",
]:
    if _tool_dir and os.path.isdir(_tool_dir) and _tool_dir not in os.environ.get("PATH", ""):
        os.environ["PATH"] = _tool_dir + os.pathsep + os.environ.get("PATH", "")


SAVED_CONSOLE_FD: Optional[int] = None


def log_info(server_tag: str, msg: str) -> None:
    """Write clean diagnostic logs to stderr without corrupting MCP stdio JSON-RPC frames."""
    formatted = f"[{server_tag}] {msg}\n"
    if SAVED_CONSOLE_FD is not None:
        try:
            os.write(SAVED_CONSOLE_FD, formatted.encode("utf-8", errors="ignore"))
            return
        except Exception:
            pass
    try:
        sys.stderr.write(formatted)
        sys.stderr.flush()
    except Exception:
        pass


@contextlib.contextmanager
def suppress_stderr():
    """Suppress C-level, JVM, and pipe stderr noise while preserving SAVED_CONSOLE_FD for log_info."""
    global SAVED_CONSOLE_FD
    saved_stderr_fd = None
    devnull = None
    try:
        stderr_fd = sys.stderr.fileno()
        saved_stderr_fd = os.dup(stderr_fd)
        SAVED_CONSOLE_FD = saved_stderr_fd
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, stderr_fd)
    except Exception:
        pass

    try:
        yield
    finally:
        try:
            if saved_stderr_fd is not None:
                os.dup2(saved_stderr_fd, sys.stderr.fileno())
                os.close(saved_stderr_fd)
            if devnull is not None:
                os.close(devnull)
            SAVED_CONSOLE_FD = None
        except Exception:
            pass


def resolve_binary_path(user_path: str) -> str:
    """Validate and resolve a binary file path on the FlareVM system.
    If FLARE_MCP_STRICT_BASE_DIR is set, confines access to that directory.
    """
    if not user_path or not user_path.strip():
        raise ValueError("Empty file_path provided.")
    cleaned = user_path.strip().strip('"').strip("'")
    if os.path.isabs(cleaned):
        target_path = os.path.abspath(cleaned)
    else:
        target_path = os.path.abspath(os.path.join(os.getcwd(), cleaned))

    strict_base = os.environ.get("FLARE_MCP_STRICT_BASE_DIR")
    if strict_base:
        base_abs = os.path.abspath(strict_base)
        try:
            inside = os.path.commonpath([target_path, base_abs]) == base_abs
        except ValueError:
            inside = False
        if not inside:
            raise ValueError(f"Access denied: path '{user_path}' is outside allowed base directory '{base_abs}'.")

    if not os.path.exists(target_path):
        raise FileNotFoundError(f"File not found: '{target_path}'")
    if not os.path.isfile(target_path):
        raise ValueError(f"Path is not a regular file: '{target_path}'")
    return target_path


def sanitize_symbol_or_address(identifier: str) -> str:
    """Sanitize address or symbol name to prevent command injection in Rizin/radare2 commands."""
    cleaned = identifier.strip()
    if not re.match(r"^[a-zA-Z0-9_\.\+\-:]+$", cleaned):
        raise ValueError(
            f"Security Alert: Invalid or potentially dangerous characters in address/symbol name: '{identifier}'"
        )
    return cleaned


def get_file_hashes(file_path: str) -> Dict[str, Any]:
    """Compute MD5, SHA-1, SHA-256, and file size in a single streaming pass."""
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            size += len(chunk)
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {
        "file_path": file_path,
        "file_name": os.path.basename(file_path),
        "size_bytes": size,
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def get_sample_cache_dir(file_path: str) -> Tuple[str, Dict[str, Any]]:
    """Return the per-sample cache directory (.analysis_cache/<sha256>) and file hashes."""
    hashes = get_file_hashes(file_path)
    sample_dir = os.path.join(ANALYSIS_CACHE_DIR, hashes["sha256"])
    os.makedirs(sample_dir, exist_ok=True)
    meta_file = os.path.join(sample_dir, "sample_meta.json")
    if not os.path.exists(meta_file):
        try:
            with open(meta_file, "w", encoding="utf-8") as f:
                json.dump(hashes, f, ensure_ascii=False, indent=2)
        except Exception:
            pass
    return sample_dir, hashes


def save_tool_snapshot(file_path: str, tool_name: str, payload: Dict[str, Any]) -> str:
    """Persist structured output from a tool (die, floss, capa, rizin, radare2, ghidra) to SHA-256 disk cache."""
    sample_dir, hashes = get_sample_cache_dir(file_path)
    snapshot_path = os.path.join(sample_dir, f"{tool_name}.json")
    enriched = dict(payload)
    enriched.setdefault("sample_hashes", hashes)
    enriched["snapshot_timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with open(snapshot_path, "w", encoding="utf-8") as f:
        json.dump(enriched, f, ensure_ascii=False, indent=2)
    return snapshot_path


def load_tool_snapshot(file_path: str, tool_name: str) -> Optional[Dict[str, Any]]:
    """Load cached tool output if available for the binary's SHA-256."""
    sample_dir, _ = get_sample_cache_dir(file_path)
    snapshot_path = os.path.join(sample_dir, f"{tool_name}.json")
    if not os.path.exists(snapshot_path):
        return None
    try:
        with open(snapshot_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["cached"] = True
        return data
    except Exception:
        return None


def list_available_snapshots(file_path: str) -> Dict[str, Any]:
    """List all cached tool snapshots and investigation ledger entries for a given binary."""
    sample_dir, hashes = get_sample_cache_dir(file_path)
    snapshots = {}
    for tool in ["die", "floss", "capa", "capa_rizin", "capa_ghidra", "rizin", "radare2", "ghidra", "ledger"]:
        p = os.path.join(sample_dir, f"{tool}.json")
        if os.path.exists(p):
            snapshots[tool] = p
    return {
        "sample": hashes,
        "cache_dir": sample_dir,
        "available_snapshots": snapshots,
    }


# --- REA-Inspired Evidence Ledger (Observations, Inferences, Residual Unknowns) ---

def update_evidence_ledger(
    file_path: str,
    source_tool: str,
    observations: Optional[List[Dict[str, Any]]] = None,
    inferences: Optional[List[Dict[str, Any]]] = None,
    residual_unknowns: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Append verified observations, inferences, and residual unknowns (inspired by morluto/rea)
    to the per-binary investigation ledger on disk.
    """
    sample_dir, hashes = get_sample_cache_dir(file_path)
    ledger_path = os.path.join(sample_dir, "ledger.json")
    ledger: Dict[str, Any] = {
        "sample": hashes,
        "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "verified_observations": [],
        "inferences": [],
        "residual_unknowns": [],
    }
    if os.path.exists(ledger_path):
        try:
            with open(ledger_path, "r", encoding="utf-8") as f:
                ledger = json.load(f)
        except Exception:
            pass

    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    for obs in observations or []:
        entry = {"timestamp": now, "source_tool": source_tool, **obs}
        if entry not in ledger["verified_observations"]:
            ledger["verified_observations"].append(entry)

    for inf in inferences or []:
        entry = {"timestamp": now, "source_tool": source_tool, **inf}
        if entry not in ledger["inferences"]:
            ledger["inferences"].append(entry)

    for unk in residual_unknowns or []:
        entry = {"timestamp": now, "source_tool": source_tool, **unk}
        if entry not in ledger["residual_unknowns"]:
            ledger["residual_unknowns"].append(entry)

    ledger["updated_at"] = now
    try:
        with open(ledger_path, "w", encoding="utf-8") as f:
            json.dump(ledger, f, ensure_ascii=False, indent=2)
    except Exception:
        pass
    return ledger


# --- High-Signal Windows API & MITRE ATT&CK Cross-Correlation Catalog ---

SUSPICIOUS_WIN32_APIS: Dict[str, Dict[str, str]] = {
    # Process Injection & Memory Manipulation
    "VirtualAlloc": {"category": "Memory Allocation / Unpacking", "attack_id": "T1055", "ms_learn_query": "VirtualAlloc function memoryapi.h Win32"},
    "VirtualAllocEx": {"category": "Process Injection", "attack_id": "T1055", "ms_learn_query": "VirtualAllocEx function memoryapi.h Win32"},
    "VirtualProtect": {"category": "Memory Protection / RWX", "attack_id": "T1055", "ms_learn_query": "VirtualProtect function memoryapi.h Win32"},
    "VirtualProtectEx": {"category": "Process Injection", "attack_id": "T1055", "ms_learn_query": "VirtualProtectEx function memoryapi.h Win32"},
    "WriteProcessMemory": {"category": "Process Injection", "attack_id": "T1055", "ms_learn_query": "WriteProcessMemory function memoryapi.h Win32"},
    "ReadProcessMemory": {"category": "Process Memory Access / Credential Dumping", "attack_id": "T1003.001", "ms_learn_query": "ReadProcessMemory function memoryapi.h Win32"},
    "CreateRemoteThread": {"category": "Process Injection", "attack_id": "T1055", "ms_learn_query": "CreateRemoteThread function processthreadsapi.h Win32"},
    "CreateRemoteThreadEx": {"category": "Process Injection", "attack_id": "T1055", "ms_learn_query": "CreateRemoteThreadEx function processthreadsapi.h Win32"},
    "NtCreateThreadEx": {"category": "Process Injection (Native API)", "attack_id": "T1055", "ms_learn_query": "NtCreateThreadEx ZwCreateThreadEx Windows Native API"},
    "QueueUserAPC": {"category": "APC Injection", "attack_id": "T1055.004", "ms_learn_query": "QueueUserAPC function processthreadsapi.h Win32"},
    "NtUnmapViewOfSection": {"category": "Process Hollowing", "attack_id": "T1055.012", "ms_learn_query": "ZwUnmapViewOfSection NtUnmapViewOfSection wdm.h"},
    "SetThreadContext": {"category": "Process Hollowing / Thread Execution Hijacking", "attack_id": "T1055.003", "ms_learn_query": "SetThreadContext function processthreadsapi.h Win32"},
    # Dynamic API Resolution & Loader
    "LoadLibraryA": {"category": "Dynamic DLL Loading", "attack_id": "T1129", "ms_learn_query": "LoadLibraryA function libloaderapi.h Win32"},
    "LoadLibraryW": {"category": "Dynamic DLL Loading", "attack_id": "T1129", "ms_learn_query": "LoadLibraryW function libloaderapi.h Win32"},
    "LoadLibraryExA": {"category": "Dynamic DLL Loading", "attack_id": "T1129", "ms_learn_query": "LoadLibraryExA function libloaderapi.h Win32"},
    "LoadLibraryExW": {"category": "Dynamic DLL Loading", "attack_id": "T1129", "ms_learn_query": "LoadLibraryExW function libloaderapi.h Win32"},
    "GetProcAddress": {"category": "Dynamic API Resolution", "attack_id": "T1106", "ms_learn_query": "GetProcAddress function libloaderapi.h Win32"},
    "LdrLoadDll": {"category": "Native Dynamic DLL Loading", "attack_id": "T1129", "ms_learn_query": "LdrLoadDll ntdll Windows Native API"},
    # Anti-Analysis & Defense Evasion
    "IsDebuggerPresent": {"category": "Anti-Debug", "attack_id": "T1622", "ms_learn_query": "IsDebuggerPresent function debugapi.h Win32"},
    "CheckRemoteDebuggerPresent": {"category": "Anti-Debug", "attack_id": "T1622", "ms_learn_query": "CheckRemoteDebuggerPresent function debugapi.h Win32"},
    "NtQueryInformationProcess": {"category": "Anti-Debug / Process Discovery", "attack_id": "T1622", "ms_learn_query": "NtQueryInformationProcess winternl.h Win32"},
    "OutputDebugStringA": {"category": "Anti-Debug / Debug Output", "attack_id": "T1622", "ms_learn_query": "OutputDebugStringA function debugapi.h Win32"},
    "GetTickCount": {"category": "Timing / Sandbox Evasion", "attack_id": "T1497.003", "ms_learn_query": "GetTickCount function sysinfoapi.h Win32"},
    "QueryPerformanceCounter": {"category": "Timing / Sandbox Evasion", "attack_id": "T1497.003", "ms_learn_query": "QueryPerformanceCounter function profileapi.h Win32"},
    # Privilege & Token Manipulation
    "AdjustTokenPrivileges": {"category": "Access Token Manipulation", "attack_id": "T1134", "ms_learn_query": "AdjustTokenPrivileges function securitybaseapi.h Win32"},
    "OpenProcessToken": {"category": "Access Token Manipulation", "attack_id": "T1134", "ms_learn_query": "OpenProcessToken function processthreadsapi.h Win32"},
    "LookupPrivilegeValueA": {"category": "Access Token Manipulation", "attack_id": "T1134", "ms_learn_query": "LookupPrivilegeValueA function winbase.h Win32"},
    "LookupPrivilegeValueW": {"category": "Access Token Manipulation", "attack_id": "T1134", "ms_learn_query": "LookupPrivilegeValueW function winbase.h Win32"},
    "ImpersonateLoggedOnUser": {"category": "Token Impersonation", "attack_id": "T1134.001", "ms_learn_query": "ImpersonateLoggedOnUser function securitybaseapi.h Win32"},
    "DuplicateTokenEx": {"category": "Token Duplication", "attack_id": "T1134.001", "ms_learn_query": "DuplicateTokenEx function securitybaseapi.h Win32"},
    # Execution & Process Creation
    "CreateProcessA": {"category": "Process Creation", "attack_id": "T1106", "ms_learn_query": "CreateProcessA function processthreadsapi.h Win32"},
    "CreateProcessW": {"category": "Process Creation", "attack_id": "T1106", "ms_learn_query": "CreateProcessW function processthreadsapi.h Win32"},
    "ShellExecuteA": {"category": "Command/Process Execution", "attack_id": "T1106", "ms_learn_query": "ShellExecuteA function shellapi.h Win32"},
    "ShellExecuteW": {"category": "Command/Process Execution", "attack_id": "T1106", "ms_learn_query": "ShellExecuteW function shellapi.h Win32"},
    "WinExec": {"category": "Process Execution", "attack_id": "T1106", "ms_learn_query": "WinExec function winbase.h Win32"},
    # Persistence & Registry / Services
    "RegSetValueExA": {"category": "Registry Modification / Persistence", "attack_id": "T1112", "ms_learn_query": "RegSetValueExA function winreg.h Win32"},
    "RegSetValueExW": {"category": "Registry Modification / Persistence", "attack_id": "T1112", "ms_learn_query": "RegSetValueExW function winreg.h Win32"},
    "RegCreateKeyExA": {"category": "Registry Modification", "attack_id": "T1112", "ms_learn_query": "RegCreateKeyExA function winreg.h Win32"},
    "RegCreateKeyExW": {"category": "Registry Modification", "attack_id": "T1112", "ms_learn_query": "RegCreateKeyExW function winreg.h Win32"},
    "CreateServiceA": {"category": "Service Persistence", "attack_id": "T1543.003", "ms_learn_query": "CreateServiceA function winsvc.h Win32"},
    "CreateServiceW": {"category": "Service Persistence", "attack_id": "T1543.003", "ms_learn_query": "CreateServiceW function winsvc.h Win32"},
    # Cryptography & Ransomware/Obfuscation
    "CryptAcquireContextA": {"category": "CryptoAPI", "attack_id": "T1027", "ms_learn_query": "CryptAcquireContextA function wincrypt.h Win32"},
    "CryptAcquireContextW": {"category": "CryptoAPI", "attack_id": "T1027", "ms_learn_query": "CryptAcquireContextW function wincrypt.h Win32"},
    "CryptEncrypt": {"category": "CryptoAPI Encryption", "attack_id": "T1486", "ms_learn_query": "CryptEncrypt function wincrypt.h Win32"},
    "CryptDecrypt": {"category": "CryptoAPI Decryption", "attack_id": "T1140", "ms_learn_query": "CryptDecrypt function wincrypt.h Win32"},
    "BCryptEncrypt": {"category": "CNG Encryption", "attack_id": "T1486", "ms_learn_query": "BCryptEncrypt function bcrypt.h Win32"},
    "BCryptDecrypt": {"category": "CNG Decryption", "attack_id": "T1140", "ms_learn_query": "BCryptDecrypt function bcrypt.h Win32"},
    # Networking & C2
    "InternetOpenA": {"category": "WinINet HTTP/C2", "attack_id": "T1071.001", "ms_learn_query": "InternetOpenA function wininet.h Win32"},
    "InternetOpenW": {"category": "WinINet HTTP/C2", "attack_id": "T1071.001", "ms_learn_query": "InternetOpenW function wininet.h Win32"},
    "InternetOpenUrlA": {"category": "WinINet URL Download", "attack_id": "T1105", "ms_learn_query": "InternetOpenUrlA function wininet.h Win32"},
    "InternetOpenUrlW": {"category": "WinINet URL Download", "attack_id": "T1105", "ms_learn_query": "InternetOpenUrlW function wininet.h Win32"},
    "HttpSendRequestA": {"category": "WinINet HTTP Request", "attack_id": "T1071.001", "ms_learn_query": "HttpSendRequestA function wininet.h Win32"},
    "HttpSendRequestW": {"category": "WinINet HTTP Request", "attack_id": "T1071.001", "ms_learn_query": "HttpSendRequestW function wininet.h Win32"},
    "WinHttpOpen": {"category": "WinHTTP C2", "attack_id": "T1071.001", "ms_learn_query": "WinHttpOpen function winhttp.h Win32"},
    "URLDownloadToFileA": {"category": "URLMon File Download", "attack_id": "T1105", "ms_learn_query": "URLDownloadToFile function urlmon.h Win32"},
    "URLDownloadToFileW": {"category": "URLMon File Download", "attack_id": "T1105", "ms_learn_query": "URLDownloadToFile function urlmon.h Win32"},
    "WSAStartup": {"category": "Winsock Networking", "attack_id": "T1095", "ms_learn_query": "WSAStartup function winsock2.h Win32"},
    "WSASocketA": {"category": "Winsock Raw Socket", "attack_id": "T1095", "ms_learn_query": "WSASocketA function winsock2.h Win32"},
    "WSASocketW": {"category": "Winsock Raw Socket", "attack_id": "T1095", "ms_learn_query": "WSASocketW function winsock2.h Win32"},
    # Embedded Resource & Payload Extraction
    "FindResourceA": {"category": "Resource Payload Extraction", "attack_id": "T1027.009", "ms_learn_query": "FindResourceA function winbase.h Win32"},
    "FindResourceW": {"category": "Resource Payload Extraction", "attack_id": "T1027.009", "ms_learn_query": "FindResourceW function libloaderapi.h Win32"},
    "LoadResource": {"category": "Resource Payload Extraction", "attack_id": "T1027.009", "ms_learn_query": "LoadResource function libloaderapi.h Win32"},
    "LockResource": {"category": "Resource Payload Extraction", "attack_id": "T1027.009", "ms_learn_query": "LockResource function libloaderapi.h Win32"},
}


def classify_imports_for_mcp_enrichment(import_names: List[str]) -> Dict[str, Any]:
    """Match a list of imported function names against high-signal Windows APIs and generate
    ready-to-execute queries for the `ms-learn` and `mitre-attack` MCP servers.
    """
    matched_apis = []
    seen = set()
    attack_ids = set()
    ms_learn_queries = []

    for raw_name in import_names:
        if not raw_name:
            continue
        clean = raw_name.split(".")[-1].split("_")[-1]
        for api_name, meta in SUSPICIOUS_WIN32_APIS.items():
            if clean.lower() == api_name.lower() and api_name not in seen:
                seen.add(api_name)
                attack_ids.add(meta["attack_id"])
                matched_apis.append({
                    "api": api_name,
                    "raw_symbol": raw_name,
                    "category": meta["category"],
                    "related_attack_id": meta["attack_id"],
                    "ms_learn_query": meta["ms_learn_query"],
                })
                ms_learn_queries.append({
                    "server": "ms-learn",
                    "tool": "microsoft_docs_search",
                    "arguments": {"query": meta["ms_learn_query"]},
                })

    mitre_queries = [
        {
            "server": "mitre-attack",
            "tool": "get_technique_by_id",
            "arguments": {"technique_id": tid, "domain": "enterprise", "include_description": True},
        }
        for tid in sorted(attack_ids)
    ]

    return {
        "suspicious_api_count": len(matched_apis),
        "suspicious_apis": matched_apis,
        "recommended_ms_learn_mcp_calls": ms_learn_queries[:15],
        "recommended_mitre_attack_mcp_calls": mitre_queries,
    }


_SHARED_CAPA_RULESET: Any = None


def get_cached_capa_ruleset() -> Any:
    """Return CAPA RuleSet using an in-memory singleton backed by a fast disk pickle cache
    in `.analysis_cache/_capa_ruleset_cache.pkl` so cold-start rule loading takes ~0.12s instead of ~3.5s.
    """
    global _SHARED_CAPA_RULESET
    if _SHARED_CAPA_RULESET is not None:
        return _SHARED_CAPA_RULESET

    import capa.rules

    cache_pkl = os.path.join(ANALYSIS_CACHE_DIR, "_capa_ruleset_cache.pkl")
    if os.path.exists(cache_pkl):
        try:
            with open(cache_pkl, "rb") as f:
                loaded = pickle.load(f)
            if len(getattr(loaded, "rules", {})) > 0:
                _SHARED_CAPA_RULESET = loaded
                return _SHARED_CAPA_RULESET
        except Exception:
            pass

    rules_dir = CAPA_RULES_DIR
    if not os.path.isdir(rules_dir):
        rules_dir = _first_existing_path(
            [
                os.environ.get("CAPA_RULES_PATH"),
                os.path.join(USER_PORTABLE_TOOLS_DIR, "capa", "rules"),
                r"C:\Tools\capa\rules" if IS_WINDOWS else None,
                os.path.join(PROJECT_ROOT, "rules"),
                "/opt/capa-rules" if not IS_WINDOWS else None,
                "/usr/share/capa-rules" if not IS_WINDOWS else None,
            ],
            expect_dir=True,
        )
    if not os.path.exists(rules_dir):
        raise FileNotFoundError(f"Cannot find capa-rules directory: {rules_dir}")

    rule_paths = []
    for root, _, files in os.walk(rules_dir):
        if ".github" in root or ".git" in root:
            continue
        for fn in files:
            if fn.endswith((".yml", ".yaml")):
                rule_paths.append(Path(os.path.join(root, fn)))

    if hasattr(capa.rules, "get_rules"):
        _SHARED_CAPA_RULESET = capa.rules.get_rules(rule_paths)
    else:
        _SHARED_CAPA_RULESET = capa.rules.RuleSet([capa.rules.Rule.from_yaml_file(str(p)) for p in rule_paths])

    try:
        with open(cache_pkl, "wb") as f:
            pickle.dump(_SHARED_CAPA_RULESET, f, protocol=pickle.HIGHEST_PROTOCOL)
    except Exception:
        pass
    return _SHARED_CAPA_RULESET


def sanitize_markdown_report_formatting(markdown_content: str) -> str:
    """Sanitize and normalize Markdown report formatting according to DevSecOps & CommonMark standards:
    1. Ensure every code block (especially ```mermaid ... ```) ends with an explicit newline (\\n) before closing ```.
    2. Ensure at least two newlines (\\n\\n) exist after any code block closure before dividers (---) or headings (##).
    3. Ensure at least two newlines (\\n\\n) exist between dividers (---) and headings (##).
    4. In Mermaid node formatting, ensure directory paths with backslashes (ex: %TEMP%\\caminho\\) have double backslashes (\\\\).
    5. Normalize invisible whitespace (\\u00A0, \\u202F, \\u2007, \\u200B, \\uFEFF, etc.) to standard ASCII spaces.
    """
    if not markdown_content:
        return markdown_content

    # Step A: Normalize Unicode whitespace globally (Rule 4)
    for ws in ("\u00a0", "\u202f", "\u2007", "\u2000", "\u2001", "\u2002", "\u2003", "\u2004", "\u2005", "\u2006", "\u2008", "\u2009", "\u200a", "\u205f", "\u3000"):
        markdown_content = markdown_content.replace(ws, " ")
    for zw in ("\u200b", "\u200c", "\u200d", "\ufeff"):
        markdown_content = markdown_content.replace(zw, "")

    # Step B: Separate any accidentally joined code block delimiters on the same line
    # e.g.: `...child_process.exec"]```---## 4. Engenharia`
    # 1. Non-newline character immediately before closing ```
    markdown_content = re.sub(r'([^\n\r`])(```+)', r'\1\n\2', markdown_content)

    # 2. ``` followed immediately by --- or ##
    markdown_content = re.sub(r'(```+)[ \t]*(?:---|\n---)[ \t]*(?:##|#|\n##|\n#)', r'\1\n\n---\n\n##', markdown_content)
    markdown_content = re.sub(r'(```+)[ \t]*(?:---|\n---)', r'\1\n\n---', markdown_content)
    markdown_content = re.sub(r'(```+)[ \t]*(\n*#{1,6}\s+)', r'\1\n\n\2', markdown_content)

    # 3. Divider (---) separated from a subsequent heading by at least two newlines (\n\n)
    markdown_content = re.sub(r'(---)[ \t]*(\n*#{1,6}\s+)', r'\1\n\n\2', markdown_content)

    # Step C: Sanitize Mermaid code blocks specifically
    def _clean_mermaid_block(match: re.Match) -> str:
        header = match.group(1)
        body = match.group(2)
        footer = match.group(3)

        # 1. Strip non-breaking and zero-width spaces in indentation and labels
        for ws in ("\u00a0", "\u202f", "\u2007", "\u2000", "\u2001", "\u2002", "\u2003", "\u2004", "\u2005", "\u2006", "\u2008", "\u2009", "\u200a", "\u205f", "\u3000"):
            body = body.replace(ws, " ")
        for zw in ("\u200b", "\u200c", "\u200d", "\ufeff"):
            body = body.replace(zw, "")

        # 2. Repair previously damaged labels where closing quotes were eaten (e.g. `\#quot;]` or `\\#quot;]` -> `\\"]`)
        body = re.sub(r'\\*#quot;\s*([\]\)\}])', r'\\"]', body)
        body = re.sub(r'(?<![A-Za-z0-9_])#quot;\s*([\]\)\}])', r'"]', body)

        # 3. Normalize edge labels with quotes: `A -- "text" --> B` -> `A -->|text| B`
        def _fix_edge_quotes(m: re.Match) -> str:
            edge_text = m.group(2).strip()
            if (edge_text.startswith('"') and edge_text.endswith('"')) or (edge_text.startswith("'") and edge_text.endswith("'")):
                edge_text = edge_text[1:-1]
            edge_text = edge_text.replace('"', '#quot;')
            return f"-->|{edge_text}|"

        body = re.sub(r'(--|-->)\s*\"([^\"]+)\"\s*(-->|-->|\s*>\s*)', _fix_edge_quotes, body)

        # 4. Process line by line to sanitize node labels
        lines = body.splitlines()
        cleaned_lines = []

        for line in lines:
            line_str = line

            # Match node declarations with quotes: `A["content"]`, `B{"content"}`, `C("content")`, `D(["content"])`, etc.
            def _clean_node_label(m: re.Match) -> str:
                prefix = m.group(1)
                content = m.group(2)
                suffix = m.group(3)

                # Rule 3: Ensure directory paths with backslashes have double backslashes (\\)
                # If there are forward slashes at the end of Windows paths from a previous run (e.g. `HyperSuiteSmartPack/`),
                # restore them to Windows backslash format `HyperSuiteSmartPack\\` (excluding URLs like https://.../kqq/)
                if not re.search(r'https?://[^\s"]+/$', content):
                    if re.search(r'(?:%[A-Za-z0-9_]+%|[A-Za-z]:|\\)', content):
                        content = re.sub(r'([A-Za-z0-9_%-]+)/$', r'\1\\\\', content)

                # Escape lone backslashes that are not already part of a double backslash:
                # (?<!\\)\\(?!\\) matches any single backslash not preceded or followed by another backslash
                content = re.sub(r'(?<!\\)\\(?!\\)', r'\\\\', content)

                # Ensure trailing backslash before closing quote is always doubled:
                # If content ends with an odd number of backslashes, add one to ensure it is escaped
                trailing_count = 0
                for ch in reversed(content):
                    if ch == '\\':
                        trailing_count += 1
                    else:
                        break
                if trailing_count > 0 and trailing_count % 2 != 0:
                    content += '\\'

                # Inside content: replace any raw unescaped quotes with #quot;
                content = re.sub(r'(?<!\\)\"', '#quot;', content)

                # Replace unescaped angle brackets like <timestamp> with &lt;timestamp&gt;
                content = re.sub(r'<(?!\/?(?:br|b|i|u|span)\b)([^>]+)>', r'&lt;\1&gt;', content)

                return f"{prefix}{content}{suffix}"

            line_str = re.sub(
                r'([A-Za-z0-9_]+\s*(?:\[\"|\(\"|\{\")|\[\(\"|\[\[\"|\(\[\")(.*?)(\"\]|\"\}|\"\)|\"\)\]|\"\]\]|\"\)\])',
                _clean_node_label,
                line_str
            )

            # Check for unquoted node labels with parentheses, colons, or special characters:
            # e.g. `A[Inno Setup Exec(): Dispara]` -> `A["Inno Setup Exec(): Dispara"]`
            def _quote_unquoted_square(m: re.Match) -> str:
                node_id = m.group(1)
                raw_content = m.group(2)
                if raw_content.startswith('"') and raw_content.endswith('"'):
                    return m.group(0)
                if any(c in raw_content for c in "():/\\%\""):
                    safe_content = raw_content.replace('"', '#quot;')
                    safe_content = re.sub(r'(?<!\\)\\(?!\\)', r'\\\\', safe_content)
                    return f'{node_id}["{safe_content}"]'
                return m.group(0)

            line_str = re.sub(r'([A-Za-z0-9_]+)\[([^\]\n]+)\]', _quote_unquoted_square, line_str)

            cleaned_lines.append(line_str)

        body = "\n".join(cleaned_lines)

        # Split concatenated statements after a closing node bracket on the same line
        body = re.sub(r'(\"\s*[\]\)\}])\s+([A-Za-z0-9_]+\s*(?:-->|---|-\.-|==>))', r"\1\n    \2", body)

        # Rule 1: Ensure Mermaid block always ends with an explicit newline (\n) before closing ```
        body_trimmed = body.rstrip()
        return f"{header}{body_trimmed}\n{footer}\n"

    # Apply Mermaid block cleaning
    markdown_content = re.sub(
        r"(```mermaid[ \t]*\r?\n)(.*?)(```)",
        _clean_mermaid_block,
        markdown_content,
        flags=re.DOTALL,
    )

    # Rule 1 (General): Ensure EVERY code block ends with \n before ```
    def _ensure_code_block_ending(m: re.Match) -> str:
        code_header = m.group(1)
        code_body = m.group(2)
        code_footer = m.group(3)
        code_body_clean = code_body.rstrip()
        return f"{code_header}{code_body_clean}\n{code_footer}"

    markdown_content = re.sub(
        r"(```[a-zA-Z0-9_-]*[ \t]*\r?\n)(.*?)(```)",
        _ensure_code_block_ending,
        markdown_content,
        flags=re.DOTALL,
    )

    # Rule 2: Ensure that after closing of any code block (```) there are at least two newlines (\n\n)
    # before dividers (---) or headings (## / #)
    markdown_content = re.sub(r'(```+)\s*(?:---|\n---)\s*(?:##|#|\n##|\n#)', r'\1\n\n---\n\n##', markdown_content)
    markdown_content = re.sub(r'(```+)\s*(?:---|\n---)', r'\1\n\n---', markdown_content)
    markdown_content = re.sub(r'(```+)\s*(\n*#{1,6}\s+)', r'\1\n\n\2', markdown_content)
    markdown_content = re.sub(r'(---)\s*(\n*#{1,6}\s+)', r'\1\n\n\2', markdown_content)

    return markdown_content


def sanitize_mermaid_syntax(markdown_content: str) -> str:
    """Wrapper for backward compatibility that runs full Markdown report sanitization."""
    return sanitize_markdown_report_formatting(markdown_content)


def export_markdown_report(file_path: str, markdown_content: str, custom_timestamp: Optional[str] = None) -> str:
    """Save a copy of the static analysis report into `./reports/<YYYY-MM-DD_HH-MM-SS>_<filename>_<sha256[:12]>.md`."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    markdown_content = sanitize_mermaid_syntax(markdown_content)
    hashes = get_file_hashes(file_path)
    ts = custom_timestamp or datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", hashes["file_name"])
    short_hash = hashes["sha256"][:12]
    report_filename = f"{ts}_{safe_name}_{short_hash}.md"
    out_path = os.path.join(REPORTS_DIR, report_filename)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(markdown_content)
    return out_path


