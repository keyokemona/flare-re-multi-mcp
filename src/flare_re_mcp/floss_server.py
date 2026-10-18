"""Mandiant FLOSS String & Obfuscation Analysis MCP Server (`floss-mcp`).
Extracts static, stack, tight, language-specific (Go/Rust), and decoded strings via `floss -j`,
normalizes function/PC addresses to hex for immediate cross-querying in Ghidra/Rizin/radare2,
classifies IOCs (URLs, IPs, Registry keys, File paths, Commands, Win32 APIs),
and supports async background jobs + SHA-256 disk caching.
"""

import concurrent.futures
import json
import os
import re
import subprocess
import threading
import time
import traceback
from typing import Any, Dict, List, Optional
import uuid

from mcp.server import MCPServer

from flare_re_mcp.common import (
    FLOSS_BIN,
    classify_imports_for_mcp_enrichment,
    get_file_hashes,
    load_tool_snapshot,
    log_info,
    resolve_binary_path,
    save_tool_snapshot,
    update_evidence_ledger,
)

SERVER_TAG = "floss-mcp"
server = MCPServer("floss-analyzer")

FLOSS_JOBS: Dict[str, Dict[str, Any]] = {}
FLOSS_JOBS_LOCK = threading.Lock()
FLOSS_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="floss-job")

_IOC_PATTERNS = {
    "url": re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE),
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"),
    "registry": re.compile(
        r"\b(?:HKEY_LOCAL_MACHINE|HKLM|HKEY_CURRENT_USER|HKCU|HKEY_CLASSES_ROOT|HKCR|HKEY_USERS|HKU|SOFTWARE\\Microsoft\\Windows\\CurrentVersion)[\\A-Za-z0-9_\-\.\s]*",
        re.IGNORECASE,
    ),
    "windows_path": re.compile(r"\b(?:[A-Za-z]:\\|\\\\[A-Za-z0-9_\.\-]+\\)[A-Za-z0-9_\\\-\.\s]{3,}", re.IGNORECASE),
    "command_shell": re.compile(
        r"\b(?:cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?|mshta(?:\.exe)?|rundll32(?:\.exe)?|regsvr32(?:\.exe)?|schtasks(?:\.exe)?|vssadmin(?:\.exe)?|bcdedit(?:\.exe)?)\b.*",
        re.IGNORECASE,
    ),
    "pdb_path": re.compile(r"[^\s\"'<>]+\.pdb\b", re.IGNORECASE),
}


def _normalize_floss_item(item: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(item)
    for addr_field in ("function", "program_counter", "decoding_routine", "decoded_at", "address", "offset"):
        val = out.get(addr_field)
        if isinstance(val, int) and val > 0:
            out[f"{addr_field}_hex"] = hex(val)
    return out


def _extract_iocs_from_strings(all_strings: List[str]) -> Dict[str, Any]:
    iocs: Dict[str, List[str]] = {k: [] for k in _IOC_PATTERNS}
    seen: Dict[str, set] = {k: set() for k in _IOC_PATTERNS}

    for s in all_strings:
        if not s or len(s) < 4:
            continue
        for cat, pat in _IOC_PATTERNS.items():
            for match in pat.findall(s):
                m_clean = match.strip()
                if m_clean and m_clean not in seen[cat]:
                    seen[cat].add(m_clean)
                    if len(iocs[cat]) < 100:
                        iocs[cat].append(m_clean)

    api_enrichment = classify_imports_for_mcp_enrichment(all_strings)
    return {
        "iocs_by_category": iocs,
        "total_ioc_matches": sum(len(v) for v in iocs.values()),
        "referenced_win32_apis_and_mitre": api_enrichment,
    }


def _execute_floss_job(safe_path: str, min_length: int, include_static: bool) -> Dict[str, Any]:
    t0 = time.time()
    cmd = [FLOSS_BIN, "-q", "-j", "-n", str(max(3, int(min_length)))]
    if not include_static:
        cmd.extend(["--only", "stack", "tight", "decoded"])
    cmd.extend(["--", safe_path])

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )
    raw = proc.stdout or ""
    brace_idx = raw.find("{")
    if brace_idx == -1:
        # If the sample is ELF or non-PE, FLOSS string emulation fails. Fall back to static strings.
        err_msg = (proc.stderr or raw).strip()
        if "supports the following formats" in err_msg or include_static:
            fallback_cmd = [FLOSS_BIN, "-q", "-j", "-n", str(max(3, int(min_length))), "--only", "static", "--", safe_path]
            proc_fb = subprocess.run(
                fallback_cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=600,
            )
            raw = proc_fb.stdout or ""
            brace_idx = raw.find("{")

    if brace_idx == -1:
        raise RuntimeError(f"FLOSS failed to produce JSON output: {(proc.stderr or raw).strip()}")

    data = json.loads(raw[brace_idx:])
    strings_section = data.get("strings", {})

    decoded_strings = [_normalize_floss_item(x) for x in strings_section.get("decoded_strings", [])]
    stack_strings = [_normalize_floss_item(x) for x in strings_section.get("stack_strings", [])]
    tight_strings = [_normalize_floss_item(x) for x in strings_section.get("tight_strings", [])]
    language_strings = [_normalize_floss_item(x) for x in strings_section.get("language_strings", [])]
    static_strings = [_normalize_floss_item(x) for x in strings_section.get("static_strings", [])]

    # Convert decoding function score keys to hex so they can be directly passed to Ghidra/Rizin/r2
    raw_scores = data.get("analysis", {}).get("functions", {}).get("decoding_function_scores", {})
    decoding_candidates = []
    for func_addr_str, score_info in raw_scores.items():
        try:
            addr_int = int(func_addr_str)
            addr_hex = hex(addr_int)
        except ValueError:
            addr_hex = func_addr_str
        decoding_candidates.append({
            "function_address": addr_hex,
            "score": score_info.get("score"),
            "xrefs_to": score_info.get("xrefs_to"),
        })
    decoding_candidates.sort(key=lambda x: x.get("score") or 0.0, reverse=True)

    all_text_values = [
        x.get("string", "")
        for group in (decoded_strings, stack_strings, tight_strings, language_strings, static_strings)
        for x in group
        if x.get("string")
    ]
    ioc_summary = _extract_iocs_from_strings(all_text_values)

    t1 = time.time()
    payload = {
        "status": "success",
        "cached": False,
        "tool": "Mandiant FLOSS",
        "file_path": safe_path,
        "elapsed_seconds": round(t1 - t0, 2),
        "metadata": data.get("metadata", {}),
        "counts": {
            "decoded_strings": len(decoded_strings),
            "stack_strings": len(stack_strings),
            "tight_strings": len(tight_strings),
            "language_strings": len(language_strings),
            "static_strings": len(static_strings),
            "top_decoding_function_candidates": len(decoding_candidates),
        },
        "top_decoding_function_candidates": decoding_candidates[:30],
        "decoded_strings": decoded_strings,
        "stack_strings": stack_strings,
        "tight_strings": tight_strings,
        "language_strings": language_strings[:200],
        "static_strings_sample": static_strings[:200],
        "static_strings_all": static_strings,
        "ioc_and_api_enrichment": ioc_summary,
    }
    save_tool_snapshot(safe_path, "floss" if include_static else "floss_no_static", payload)

    # Record high-signal observations in the REA Evidence Ledger
    obs = []
    if decoded_strings:
        obs.append({
            "category": "FLOSS_Decoded_Strings",
            "count": len(decoded_strings),
            "sample": [d.get("string") for d in decoded_strings[:10]],
        })
    if stack_strings:
        obs.append({
            "category": "FLOSS_Stack_Strings",
            "count": len(stack_strings),
            "sample": [s.get("string") for s in stack_strings[:10]],
        })
    if decoding_candidates:
        obs.append({
            "category": "FLOSS_Decoding_Function_Candidates",
            "top_functions": decoding_candidates[:5],
        })
    update_evidence_ledger(safe_path, SERVER_TAG, observations=obs)

    # Return compact response without dumping thousands of static strings at once
    compact = dict(payload)
    compact.pop("static_strings_all", None)
    return compact


@server.tool(
    name="floss_extract_strings",
    description=(
        "Extract obfuscated strings (decoded_strings, stack_strings, tight_strings, language_strings) "
        "and static strings using Mandiant FLOSS, plus candidate decoding function addresses in hex "
        "(ready to decompile in Ghidra/Rizin/radare2) and IOC/Win32 API classification. "
        "Supports synchronous execution (`wait=True`) or background job (`wait=False`)."
    ),
)
def floss_extract_strings(
    file_path: str,
    min_length: int = 4,
    include_static: bool = True,
    force_reanalysis: bool = False,
    wait: bool = True,
) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        if not force_reanalysis:
            cached = load_tool_snapshot(safe_path, "floss")
            if cached:
                cached.pop("static_strings_all", None)
                return json.dumps(cached, ensure_ascii=False, indent=2)

        if wait:
            result = _execute_floss_job(safe_path, min_length=min_length, include_static=include_static)
            return json.dumps(result, ensure_ascii=False, indent=2)

        with FLOSS_JOBS_LOCK:
            existing = FLOSS_JOBS.get(safe_path)
            if existing is not None and not existing["future"].done():
                return json.dumps({
                    "status": "started",
                    "job_id": existing["job_id"],
                    "message": f"FLOSS job already running. Poll floss_get_job_status('{existing['job_id']}').",
                }, ensure_ascii=False, indent=2)

            job_id = uuid.uuid4().hex[:16]
            future = FLOSS_EXECUTOR.submit(_execute_floss_job, safe_path, min_length, include_static)
            entry = {"job_id": job_id, "future": future, "started_at": time.time(), "file_path": safe_path}
            FLOSS_JOBS[safe_path] = entry
            FLOSS_JOBS[job_id] = entry

        return json.dumps({
            "status": "started",
            "job_id": job_id,
            "message": f"FLOSS extraction started in background. Poll floss_get_job_status('{job_id}').",
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="floss_get_job_status",
    description="Poll the status of a background FLOSS extraction job started with wait=False.",
)
def floss_get_job_status(job_id: str) -> str:
    with FLOSS_JOBS_LOCK:
        job = FLOSS_JOBS.get(job_id)
    if job is None:
        return json.dumps({"status": "error", "message": f"Unknown job_id: '{job_id}'."}, ensure_ascii=False)
    future = job["future"]
    if not future.done():
        return json.dumps({
            "status": "running",
            "job_id": job_id,
            "elapsed_seconds": round(time.time() - job["started_at"], 1),
        }, ensure_ascii=False, indent=2)
    exc = future.exception()
    if exc is not None:
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        return json.dumps({"status": "error", "job_id": job_id, "message": str(exc), "traceback": tb}, ensure_ascii=False, indent=2)
    return json.dumps(future.result(), ensure_ascii=False, indent=2)


@server.tool(
    name="floss_get_obfuscated_strings_and_decoders",
    description=(
        "Return only high-signal obfuscated strings (`decoded_strings`, `stack_strings`, `tight_strings`) "
        "and the top candidate decoding functions (with hex addresses and FLARE scores) for immediate "
        "cross-decompilation in Ghidra, Rizin, or radare2."
    ),
)
def floss_get_obfuscated_strings_and_decoders(file_path: str) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        cached = load_tool_snapshot(safe_path, "floss")
        if not cached:
            cached = _execute_floss_job(safe_path, min_length=4, include_static=False)
        return json.dumps({
            "status": "success",
            "file_path": safe_path,
            "counts": cached.get("counts"),
            "top_decoding_function_candidates": cached.get("top_decoding_function_candidates", []),
            "decoded_strings": cached.get("decoded_strings", []),
            "stack_strings": cached.get("stack_strings", []),
            "tight_strings": cached.get("tight_strings", []),
            "ioc_and_api_enrichment": cached.get("ioc_and_api_enrichment", {}),
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="floss_search_strings",
    description=(
        "Search across all FLOSS string categories (decoded, stack, tight, language, static) "
        "using a keyword or regular expression."
    ),
)
def floss_search_strings(
    file_path: str,
    query: str = "",
    category: str = "all",
    use_regex: bool = False,
    limit: int = 100,
) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        cached = load_tool_snapshot(safe_path, "floss")
        if not cached:
            _execute_floss_job(safe_path, min_length=4, include_static=True)
            cached = load_tool_snapshot(safe_path, "floss") or {}

        cat = category.lower().strip()
        buckets = {
            "decoded": cached.get("decoded_strings", []),
            "stack": cached.get("stack_strings", []),
            "tight": cached.get("tight_strings", []),
            "language": cached.get("language_strings", []),
            "static": cached.get("static_strings_all") or cached.get("static_strings_sample", []),
        }
        selected = buckets if cat == "all" else {cat: buckets.get(cat, [])}

        pattern = re.compile(query, re.IGNORECASE) if (query and use_regex) else None
        q_lower = query.lower().strip()

        matches = []
        for b_name, items in selected.items():
            for item in items:
                s_val = item.get("string", "")
                if not query:
                    matched = True
                elif pattern:
                    matched = bool(pattern.search(s_val))
                else:
                    matched = q_lower in s_val.lower()
                if matched:
                    matches.append({"category": b_name, **item})
                    if len(matches) >= max(1, int(limit)):
                        break
            if len(matches) >= max(1, int(limit)):
                break

        return json.dumps({
            "status": "success",
            "file_path": safe_path,
            "query": query,
            "category": category,
            "returned_count": len(matches),
            "matches": matches,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


def main():
    server.run()


if __name__ == "__main__":
    main()
