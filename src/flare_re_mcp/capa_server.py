"""Mandiant CAPA Capability & MITRE ATT&CK / MBC MCP Server (`capa-mcp`).
Supports three backends:
  1. `vivisect` / `auto` (via standalone `capa.exe -j`)
  2. `ghidra` (via `capa -b ghidra` + `GHIDRA_INSTALL_DIR` / PyGhidra)
  3. `rizin` (via ultra-fast `RizinFeatureExtractor` from `rizin-mcp`)
Also includes `capa_bulk_analyze` (inspired by `capa/scripts/bulk-process.py`),
`capa_inspect_rule_matches` (instruction/basic-block feature drilldown),
and `capa_correlate_mitre_and_apis` (direct bridge to `mitre-attack` & `ms-learn` MCP servers).
"""

import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import threading
import time
import traceback
from typing import Any, Dict, List, Optional
import uuid

import capa.main
import capa.rules
from mcp.server import MCPServer
import rzpipe

from flare_re_mcp.common import (
    CAPA_BIN,
    CAPA_RULES_DIR,
    GHIDRA_INSTALL_DIR,
    RIZIN_SLEIGH_DIR,
    classify_imports_for_mcp_enrichment,
    get_cached_capa_ruleset,
    load_tool_snapshot,
    log_info,
    resolve_binary_path,
    save_tool_snapshot,
    suppress_stderr,
    update_evidence_ledger,
)
from flare_re_mcp.rz_extractor import RizinFeatureExtractor

SERVER_TAG = "capa-mcp"
server = MCPServer("capa-analyzer")

CAPA_JOBS: Dict[str, Dict[str, Any]] = {}
CAPA_JOBS_LOCK = threading.Lock()
CAPA_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="capa-mcp-job")


def _get_ruleset() -> capa.rules.RuleSet:
    return get_cached_capa_ruleset()


def _confidence_hint(meta: Dict[str, Any]) -> str:
    has_tags = bool(meta.get("attack")) or bool(meta.get("mbc"))
    is_generic = not has_tags and not meta.get("namespace", "")
    return "behavioral" if has_tags else ("generic-library" if is_generic else "unclassified")


def _extract_features_from_node(node: Any, out_apis: set, out_strings: set, out_Addrs: set) -> None:
    if not isinstance(node, dict):
        return
    for loc in node.get("locations", []) or []:
        if isinstance(loc, dict) and isinstance(loc.get("value"), int):
            out_Addrs.add(hex(loc["value"]))
    feat = node.get("node", {})
    if isinstance(feat, dict) and feat.get("type") == "feature":
        f_inner = feat.get("feature", {})
        if isinstance(f_inner, dict):
            f_type = f_inner.get("type")
            if f_type == "api" and f_inner.get("api"):
                out_apis.add(f_inner["api"])
            elif f_type in ("string", "substring") and f_inner.get("string"):
                out_strings.add(f_inner["string"])
    for child in node.get("children", []) or []:
        _extract_features_from_node(child, out_apis, out_strings, out_Addrs)


def _parse_capa_json_document(doc: Dict[str, Any], safe_path: str, backend_used: str, elapsed: float) -> Dict[str, Any]:
    rules_dict = doc.get("rules", {})
    capabilities = []
    attack_tactics: Dict[str, List[Dict[str, Any]]] = {}
    mbc_objectives: Dict[str, List[Dict[str, Any]]] = {}
    unique_attack_ids = set()
    matched_apis: set = set()
    matched_strings: set = set()
    function_to_capabilities: Dict[str, List[str]] = {}

    for rule_name, rdata in rules_dict.items():
        meta = rdata.get("meta", {})
        if meta.get("lib", False):
            continue

        addresses = []
        rule_apis: set = set()
        rule_strings: set = set()
        rule_insn_addrs: set = set()

        for match_pair in rdata.get("matches", []) or []:
            if isinstance(match_pair, list) and len(match_pair) >= 1:
                loc = match_pair[0]
                if isinstance(loc, dict) and isinstance(loc.get("value"), int):
                    addr_hex = hex(loc["value"])
                    addresses.append(addr_hex)
                    function_to_capabilities.setdefault(addr_hex, []).append(rule_name)
                if len(match_pair) >= 2:
                    _extract_features_from_node(match_pair[1], rule_apis, rule_strings, rule_insn_addrs)

        matched_apis.update(rule_apis)
        matched_strings.update(rule_strings)

        attacks = meta.get("attack", []) or []
        for att in attacks:
            if isinstance(att, dict):
                tactic = att.get("tactic", "UNKNOWN")
                tid = att.get("id", "")
                if tid:
                    unique_attack_ids.add(tid)
                attack_tactics.setdefault(tactic, []).append({
                    "id": tid,
                    "technique": att.get("technique"),
                    "subtechnique": att.get("subtechnique"),
                    "rule": rule_name,
                    "addresses": addresses[:10],
                })

        mbcs = meta.get("mbc", []) or []
        for m in mbcs:
            if isinstance(m, dict):
                obj = m.get("objective", "UNKNOWN")
                mbc_objectives.setdefault(obj, []).append({
                    "id": m.get("id"),
                    "behavior": m.get("behavior"),
                    "method": m.get("method"),
                    "rule": rule_name,
                    "addresses": addresses[:10],
                })

        capabilities.append({
            "rule": rule_name,
            "namespace": meta.get("namespace", ""),
            "scopes": meta.get("scopes", {}),
            "attack": attacks,
            "mbc": mbcs,
            "confidence_hint": _confidence_hint(meta),
            "matched_addresses": addresses[:15],
            "total_matches": len(addresses),
            "matched_apis": sorted(rule_apis)[:20],
            "matched_strings": sorted(rule_strings)[:20],
            "sample_instruction_addresses": sorted(rule_insn_addrs)[:15],
            "rule_source": rdata.get("source", ""),
        })

    api_mcp_enrichment = classify_imports_for_mcp_enrichment(list(matched_apis))
    mitre_mcp_calls = []
    for tid in sorted(unique_attack_ids):
        mitre_mcp_calls.extend([
            {"server": "mitre-attack", "tool": "get_technique_by_id", "arguments": {"technique_id": tid}},
            {"server": "mitre-attack", "tool": "get_mitigations_mitigating_technique", "arguments": {"technique_id": tid}},
            {"server": "mitre-attack", "tool": "get_datacomponents_detecting_technique", "arguments": {"technique_id": tid}},
        ])

    return {
        "status": "success",
        "cached": False,
        "tool": "Mandiant CAPA",
        "backend": backend_used,
        "file_path": safe_path,
        "elapsed_seconds": round(elapsed, 2),
        "meta": doc.get("meta", {}).get("sample", {}),
        "total_capabilities": len(capabilities),
        "attack_tactics_matrix": attack_tactics,
        "mbc_objectives_matrix": mbc_objectives,
        "function_capability_map": function_to_capabilities,
        "capabilities": capabilities,
        "cross_mcp_enrichment": {
            "unique_attack_technique_ids": sorted(unique_attack_ids),
            "recommended_mitre_attack_mcp_calls": mitre_mcp_calls[:30],
            "win32_api_enrichment": api_mcp_enrichment,
        },
    }


def _run_capa_cli_backend(safe_path: str, backend: str) -> Dict[str, Any]:
    t0 = time.time()
    env = os.environ.copy()
    env["GHIDRA_INSTALL_DIR"] = GHIDRA_INSTALL_DIR

    cmd = [CAPA_BIN, "-q", "-j"]
    if os.path.isdir(CAPA_RULES_DIR):
        cmd.extend(["-r", CAPA_RULES_DIR])
    if backend and backend not in ("auto", "default"):
        cmd.extend(["-b", backend])
    cmd.append(safe_path)

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=900,
    )
    raw = proc.stdout or ""
    brace_idx = raw.find("{")
    if brace_idx == -1:
        raise RuntimeError(f"capa CLI ({backend}) failed: {(proc.stderr or raw).strip()}")

    doc = json.loads(raw[brace_idx:])
    elapsed = time.time() - t0
    return _parse_capa_json_document(doc, safe_path, backend_used=backend, elapsed=elapsed)


def _run_capa_rizin_backend(safe_path: str) -> Dict[str, Any]:
    t0 = time.time()
    rules = _get_ruleset()
    with suppress_stderr():
        rz = rzpipe.open(safe_path, flags=["-e", "bin.cache=true"])
        try:
            if os.path.exists(RIZIN_SLEIGH_DIR):
                rz.cmd(f"e ghidra.sleighhome={RIZIN_SLEIGH_DIR}")
            rz.cmd("e log.level=0")
            rz.cmd("aaa")
            extractor = RizinFeatureExtractor(rz, path=Path(safe_path), max_functions=0)
            capa_res = capa.main.find_capabilities(rules, extractor)
        finally:
            try:
                rz.quit()
            except Exception:
                pass

    rules_matches = getattr(capa_res, "matches", None) or getattr(capa_res, "rules", None) or (
        capa_res[0] if isinstance(capa_res, tuple) and capa_res else capa_res if isinstance(capa_res, dict) else {}
    )
    capabilities = []
    attack_tactics: Dict[str, List[Dict[str, Any]]] = {}
    mbc_objectives: Dict[str, List[Dict[str, Any]]] = {}
    unique_attack_ids = set()
    function_to_capabilities: Dict[str, List[str]] = {}

    for rule_name, rule_matches in rules_matches.items():
        rule = rules[rule_name]
        meta = rule.meta
        if meta.get("lib", False):
            continue

        addresses = []
        locs = getattr(rule_matches, "locations", None) or (
            rule_matches if isinstance(rule_matches, (tuple, list)) else rule_matches.get("locations", [])
        )
        for match_item in locs:
            addr_val = match_item[0] if isinstance(match_item, tuple) and match_item else match_item
            v = getattr(addr_val, "value", addr_val)
            if isinstance(v, int):
                addr_hex = hex(v)
                addresses.append(addr_hex)
                function_to_capabilities.setdefault(addr_hex, []).append(rule_name)

        for att in meta.get("attack", []) or []:
            if isinstance(att, dict):
                tactic = att.get("tactic", "UNKNOWN")
                tid = att.get("id", "")
                if tid:
                    unique_attack_ids.add(tid)
                attack_tactics.setdefault(tactic, []).append({
                    "id": tid,
                    "technique": att.get("technique"),
                    "subtechnique": att.get("subtechnique"),
                    "rule": rule_name,
                    "addresses": addresses[:10],
                })

        for m in meta.get("mbc", []) or []:
            if isinstance(m, dict):
                obj = m.get("objective", "UNKNOWN")
                mbc_objectives.setdefault(obj, []).append({
                    "id": m.get("id"),
                    "behavior": m.get("behavior"),
                    "method": m.get("method"),
                    "rule": rule_name,
                    "addresses": addresses[:10],
                })

        capabilities.append({
            "rule": rule_name,
            "namespace": meta.get("namespace", ""),
            "scopes": meta.get("scopes", {}),
            "attack": meta.get("attack", []),
            "mbc": meta.get("mbc", []),
            "confidence_hint": _confidence_hint(meta),
            "matched_addresses": addresses[:15],
            "total_matches": len(addresses),
            "rule_source": getattr(rule, "definition", ""),
        })

    elapsed = time.time() - t0
    return {
        "status": "success",
        "cached": False,
        "tool": "Mandiant CAPA (RizinFeatureExtractor)",
        "backend": "rizin",
        "file_path": safe_path,
        "elapsed_seconds": round(elapsed, 2),
        "total_capabilities": len(capabilities),
        "attack_tactics_matrix": attack_tactics,
        "mbc_objectives_matrix": mbc_objectives,
        "function_capability_map": function_to_capabilities,
        "capabilities": capabilities,
        "cross_mcp_enrichment": {
            "unique_attack_technique_ids": sorted(unique_attack_ids),
            "recommended_mitre_attack_mcp_calls": [
                {"server": "mitre-attack", "tool": "get_technique_by_id", "arguments": {"technique_id": tid}}
                for tid in sorted(unique_attack_ids)
            ],
        },
    }


def _execute_capa_job(safe_path: str, backend: str) -> Dict[str, Any]:
    snap_key = "capa" if backend in ("auto", "vivisect") else f"capa_{backend}"
    if backend == "rizin":
        payload = _run_capa_rizin_backend(safe_path)
    else:
        payload = _run_capa_cli_backend(safe_path, backend=backend)

    save_tool_snapshot(safe_path, snap_key, payload)
    # Also save as default `capa` snapshot if none exists yet
    if not load_tool_snapshot(safe_path, "capa"):
        save_tool_snapshot(safe_path, "capa", payload)

    obs = []
    for cap in payload.get("capabilities", []):
        if cap.get("confidence_hint") == "behavioral":
            obs.append({
                "category": "CAPA_Behavioral_Capability",
                "rule": cap.get("rule"),
                "namespace": cap.get("namespace"),
                "attack": cap.get("attack"),
                "mbc": cap.get("mbc"),
                "addresses": cap.get("matched_addresses"),
            })
    update_evidence_ledger(safe_path, SERVER_TAG, observations=obs)
    return payload


@server.tool(
    name="capa_analyze_binary",
    description=(
        "Run Mandiant CAPA capability detection on a binary. "
        "Supports `backend='vivisect'` (default standalone capa), `backend='rizin'` (ultra-fast RizinFeatureExtractor), "
        "or `backend='ghidra'` (PyGhidra headless backend via GHIDRA_INSTALL_DIR). "
        "Returns matched capabilities, function-to-capability address map, MITRE ATT&CK & MBC matrices, "
        "and ready-to-call queries for the `mitre-attack` and `ms-learn` MCP servers."
    ),
)
def capa_analyze_binary(
    file_path: str,
    backend: str = "vivisect",
    force_reanalysis: bool = False,
    wait: bool = True,
) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        backend_norm = backend.lower().strip()
        if backend_norm not in ("vivisect", "auto", "rizin", "ghidra", "dotnet"):
            backend_norm = "vivisect"

        snap_key = "capa" if backend_norm in ("auto", "vivisect") else f"capa_{backend_norm}"
        if not force_reanalysis:
            cached = load_tool_snapshot(safe_path, snap_key)
            if cached:
                compact = dict(cached)
                for c in compact.get("capabilities", []):
                    c.pop("rule_source", None)
                return json.dumps(compact, ensure_ascii=False, indent=2)

        if wait:
            res = _execute_capa_job(safe_path, backend=backend_norm)
            compact = dict(res)
            for c in compact.get("capabilities", []):
                c.pop("rule_source", None)
            return json.dumps(compact, ensure_ascii=False, indent=2)

        job_key = f"{safe_path}::{backend_norm}"
        with CAPA_JOBS_LOCK:
            existing = CAPA_JOBS.get(job_key)
            if existing is not None and not existing["future"].done():
                return json.dumps({
                    "status": "started",
                    "job_id": existing["job_id"],
                    "backend": backend_norm,
                    "message": f"CAPA job already running. Poll capa_get_job_status('{existing['job_id']}').",
                }, ensure_ascii=False, indent=2)

            job_id = uuid.uuid4().hex[:16]
            future = CAPA_EXECUTOR.submit(_execute_capa_job, safe_path, backend_norm)
            entry = {"job_id": job_id, "future": future, "started_at": time.time(), "backend": backend_norm}
            CAPA_JOBS[job_key] = entry
            CAPA_JOBS[job_id] = entry

        return json.dumps({
            "status": "started",
            "job_id": job_id,
            "backend": backend_norm,
            "message": f"CAPA ({backend_norm}) started in background. Poll capa_get_job_status('{job_id}').",
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="capa_get_job_status",
    description="Poll the status of a background CAPA analysis job started with wait=False.",
)
def capa_get_job_status(job_id: str) -> str:
    with CAPA_JOBS_LOCK:
        job = CAPA_JOBS.get(job_id)
    if job is None:
        return json.dumps({"status": "error", "message": f"Unknown job_id: '{job_id}'."}, ensure_ascii=False)
    future = job["future"]
    if not future.done():
        return json.dumps({
            "status": "running",
            "job_id": job_id,
            "backend": job.get("backend"),
            "elapsed_seconds": round(time.time() - job["started_at"], 1),
        }, ensure_ascii=False, indent=2)
    exc = future.exception()
    if exc is not None:
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        return json.dumps({"status": "error", "job_id": job_id, "message": str(exc), "traceback": tb}, ensure_ascii=False, indent=2)
    res = dict(future.result())
    for c in res.get("capabilities", []):
        c.pop("rule_source", None)
    return json.dumps(res, ensure_ascii=False, indent=2)


@server.tool(
    name="capa_inspect_rule_matches",
    description=(
        "Drill down into a specific CAPA rule (or keyword filter) for a binary, returning exact function addresses, "
        "instruction addresses, matched Win32 APIs, strings, and the raw YAML rule source so those functions "
        "can be immediately decompiled in Ghidra, Rizin, or radare2."
    ),
)
def capa_inspect_rule_matches(file_path: str, rule_filter: str = "", include_yaml_source: bool = True) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        cached = (
            load_tool_snapshot(safe_path, "capa")
            or load_tool_snapshot(safe_path, "capa_ghidra")
            or load_tool_snapshot(safe_path, "capa_rizin")
        )
        if not cached:
            cached = _execute_capa_job(safe_path, backend="vivisect")

        q = rule_filter.lower().strip()
        matched = []
        for cap in cached.get("capabilities", []):
            rname = cap.get("rule", "")
            ns = cap.get("namespace", "")
            if not q or q in rname.lower() or q in ns.lower():
                item = dict(cap)
                if not include_yaml_source:
                    item.pop("rule_source", None)
                matched.append(item)

        return json.dumps({
            "status": "success",
            "file_path": safe_path,
            "rule_filter": rule_filter,
            "matched_count": len(matched),
            "rules": matched,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="capa_correlate_mitre_and_apis",
    description=(
        "Extract all MITRE ATT&CK techniques, MBC behaviors, and Windows APIs identified by CAPA for a binary, "
        "enriching them with local STIX data and generating structured calls for the `mitre-attack` and `ms-learn` MCP servers."
    ),
)
def capa_correlate_mitre_and_apis(file_path: str) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        cached = (
            load_tool_snapshot(safe_path, "capa")
            or load_tool_snapshot(safe_path, "capa_ghidra")
            or load_tool_snapshot(safe_path, "capa_rizin")
        )
        if not cached:
            cached = _execute_capa_job(safe_path, backend="vivisect")

        return json.dumps({
            "status": "success",
            "file_path": safe_path,
            "attack_tactics_matrix": cached.get("attack_tactics_matrix", {}),
            "mbc_objectives_matrix": cached.get("mbc_objectives_matrix", {}),
            "function_capability_map": cached.get("function_capability_map", {}),
            "cross_mcp_enrichment": cached.get("cross_mcp_enrichment", {}),
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="capa_bulk_analyze",
    description=(
        "[Inspired by capa/scripts/bulk-process.py] Run batch CAPA capability triage across multiple binaries "
        "in a directory (or semicolon-separated file list) and produce a comparative capability & MITRE ATT&CK summary."
    ),
)
def capa_bulk_analyze(
    directory_or_files: str,
    backend: str = "rizin",
    max_files: int = 10,
) -> str:
    try:
        targets: List[str] = []
        if ";" in directory_or_files:
            for part in directory_or_files.split(";"):
                if part.strip():
                    targets.append(resolve_binary_path(part.strip()))
        else:
            p = os.path.abspath(directory_or_files.strip().strip('"'))
            if os.path.isfile(p):
                targets.append(p)
            elif os.path.isdir(p):
                for entry in sorted(os.listdir(p)):
                    full = os.path.join(p, entry)
                    if os.path.isfile(full) and entry.lower().endswith((".exe", ".dll", ".sys", ".bin", ".elf", ".sc")):
                        targets.append(full)
                        if len(targets) >= max(1, int(max_files)):
                            break
            else:
                raise FileNotFoundError(f"Directory or file not found: '{directory_or_files}'")

        results = []
        shared_attack_techniques: Dict[str, List[str]] = {}
        for t in targets[: max(1, int(max_files))]:
            try:
                snap = load_tool_snapshot(t, "capa") or load_tool_snapshot(t, f"capa_{backend}")
                if not snap:
                    snap = _execute_capa_job(t, backend=backend)
                t_name = os.path.basename(t)
                att_ids = snap.get("cross_mcp_enrichment", {}).get("unique_attack_technique_ids", [])
                for aid in att_ids:
                    shared_attack_techniques.setdefault(aid, []).append(t_name)
                results.append({
                    "file_name": t_name,
                    "file_path": t,
                    "total_capabilities": snap.get("total_capabilities", 0),
                    "attack_technique_ids": att_ids,
                    "top_behavioral_rules": [
                        c["rule"] for c in snap.get("capabilities", []) if c.get("confidence_hint") == "behavioral"
                    ][:20],
                })
            except Exception as inner_e:
                results.append({"file_path": t, "status": "error", "error": str(inner_e)})

        return json.dumps({
            "status": "success",
            "analyzed_count": len(results),
            "backend": backend,
            "shared_attack_techniques_across_samples": shared_attack_techniques,
            "samples": results,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


def main():
    server.run()


if __name__ == "__main__":
    main()
