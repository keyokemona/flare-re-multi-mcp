"""Rizin & RzGhidra Static Analysis MCP Server (`rizin-mcp`).
Built on kd992102/rizin-mcp with FlareVM auto-configuration (Cutter 2.5.0 Rizin + RzGhidra Sleigh + capa-rules),
enhanced with morluto/rea composite function dossiers, Evidence Ledger, and MITRE ATT&CK / MS-Learn cross-enrichment.
"""

import base64
import concurrent.futures
import json
import os
from pathlib import Path
import re
import threading
import time
import traceback
from typing import Any, Dict, List, Optional
import uuid

import capa.main
import capa.rules
from mcp.server import MCPServer
import pefile
import rzpipe

from flare_re_mcp.common import (
    CAPA_RULES_DIR,
    RIZIN_SLEIGH_DIR,
    classify_imports_for_mcp_enrichment,
    get_cached_capa_ruleset,
    get_file_hashes,
    load_tool_snapshot,
    log_info,
    resolve_binary_path,
    sanitize_symbol_or_address,
    save_tool_snapshot,
    suppress_stderr,
    update_evidence_ledger,
)
from flare_re_mcp.rz_extractor import RizinFeatureExtractor

SERVER_TAG = "rizin-mcp"
server = MCPServer("rizin-analyzer")

CURRENT_RZ: Optional[rzpipe.open] = None
CURRENT_FILE_PATH: Optional[str] = None

CAPA_JOBS: Dict[str, Dict[str, Any]] = {}
CAPA_JOBS_LOCK = threading.Lock()
CAPA_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="rizin-capa-job")


def _parse_rizin_numeric(raw: str) -> Optional[int]:
    if raw is None:
        return None
    value = raw.strip().splitlines()[0].strip() if raw.strip() else ""
    if not value:
        return None
    try:
        return int(value, 16) if value.lower().startswith("0x") else int(value, 0)
    except ValueError:
        return None


def resolve_seek_target(rz, target: str) -> int:
    safe_target = sanitize_symbol_or_address(target)
    resolved: Optional[int] = None

    try:
        eval_raw = rz.cmd(f"%v {safe_target}") or rz.cmd(f"?v {safe_target}")
        candidate = _parse_rizin_numeric(eval_raw)
        if candidate:
            resolved = candidate
    except Exception:
        pass

    if resolved is None:
        try:
            imports_raw = rz.cmd("iij")
            imports = json.loads(imports_raw) if imports_raw else []
        except Exception:
            imports = []

        target_lower = safe_target.lower()
        for imp in imports:
            name = str(imp.get("name", ""))
            if not name:
                continue
            candidates = {name.lower()}
            if "_" in name:
                candidates.add(name.split("_")[-1].lower())
            if "." in name:
                candidates.add(name.split(".")[-1].lower())
            if target_lower in candidates:
                addr = imp.get("plt") or imp.get("vaddr")
                if addr:
                    resolved = addr
                    break

    if resolved is None:
        raise ValueError(f"Symbol/address not found: '{target}'")

    rz.cmd(f"s {hex(resolved)}")
    current_raw = rz.cmd("s")
    current_addr = _parse_rizin_numeric(current_raw)
    if current_addr != resolved:
        got = current_raw.strip() if current_raw else "<no output>"
        raise ValueError(f"Seek verification failed for '{target}' (expected 0x{resolved:x}, got '{got}')")
    return resolved


def get_capa_ruleset() -> capa.rules.RuleSet:
    return get_cached_capa_ruleset()


def _confidence_hint_for_meta(meta: Dict[str, Any]) -> str:
    has_tags = bool(meta.get("attack")) or bool(meta.get("mbc"))
    is_generic_lib = not has_tags and not meta.get("namespace", "")
    return "behavioral" if has_tags else ("generic-library" if is_generic_lib else "unclassified")


def _summarize_capability_confidence(capabilities) -> Dict[str, int]:
    behavioral_count = sum(1 for c in capabilities if c.get("confidence_hint") == "behavioral")
    generic_library_count = sum(1 for c in capabilities if c.get("confidence_hint") == "generic-library")
    unclassified_count = len(capabilities) - behavioral_count - generic_library_count
    return {
        "behavioral_count": behavioral_count,
        "generic_library_count": generic_library_count,
        "unclassified_count": unclassified_count,
    }


@server.tool(
    name="open_and_analyze",
    description=(
        "Open and automatically analyze a binary file with Rizin + RzGhidra Sleigh configured. "
        "When auto_dossier=True (default), also auto-decompiles priority functions (main/entry0/non-thunk user functions) in one turn."
    ),
)
def open_and_analyze(file_path: str, analyze_level: str = "aaa", auto_dossier: bool = True) -> str:
    global CURRENT_RZ, CURRENT_FILE_PATH
    try:
        safe_path = resolve_binary_path(file_path)
        filename = os.path.basename(safe_path)
        log_info(SERVER_TAG, f"Loading binary file: {filename}")

        if CURRENT_RZ is not None:
            try:
                CURRENT_RZ.quit()
            except Exception:
                pass
            CURRENT_RZ = None
            CURRENT_FILE_PATH = None

        t0 = time.time()
        level = analyze_level if analyze_level in ["a", "aa", "aaa", "aaaa"] else "aaa"

        auto_dossiers = []
        with suppress_stderr():
            rz = rzpipe.open(safe_path, flags=["-e", "bin.cache=true"])
            if os.path.exists(RIZIN_SLEIGH_DIR):
                rz.cmd(f"e ghidra.sleighhome={RIZIN_SLEIGH_DIR}")
            rz.cmd("e log.level=0")
            rz.cmd(level)

            info = json.loads(rz.cmd("iIj") or "{}")
            funcs = json.loads(rz.cmd("aflj") or "[]")
            imports = json.loads(rz.cmd("iij") or "[]")

            if auto_dossier and funcs:
                priority = []
                for f in funcs:
                    fname = str(f.get("name", ""))
                    if fname in ("main", "sym._main", "entry0") or (
                        fname.startswith("fcn.") and int(f.get("size", 0) or 0) >= 24
                    ):
                        priority.append(f)
                for f in priority[:6]:
                    off = f.get("offset")
                    if off is None:
                        continue
                    rz.cmd(f"s {hex(off)}")
                    c_code = (rz.cmd("pdg") or "").strip()
                    asm_code = (rz.cmd("pdf") or "").strip()
                    auto_dossiers.append({
                        "name": f.get("name"),
                        "address": hex(off),
                        "size": f.get("size"),
                        "rz_ghidra_decompiled_c": c_code,
                        "disassembly": asm_code[:4000],
                    })

        t1 = time.time()
        CURRENT_RZ = rz
        CURRENT_FILE_PATH = safe_path

        import_names = [imp.get("name", "") for imp in imports if imp.get("name")]
        enrichment = classify_imports_for_mcp_enrichment(import_names)

        payload = {
            "status": "success",
            "message": f"Successfully loaded and analyzed file: {filename}",
            "file_path": safe_path,
            "analysis_seconds": round(t1 - t0, 2),
            "architecture": info.get("arch"),
            "format": info.get("bintype"),
            "bits": info.get("bits"),
            "endian": info.get("endian"),
            "total_functions": len(funcs),
            "total_imports": len(imports),
            "win32_api_and_mitre_enrichment": enrichment,
            "auto_triage_dossiers": auto_dossiers,
        }
        save_tool_snapshot(safe_path, "rizin", payload)
        return json.dumps(payload, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Analysis failed: {str(e)}"}, ensure_ascii=False)


def _run_capa_analysis_job(rz, target_path: str) -> Dict[str, Any]:
    t0 = time.time()
    rules = get_capa_ruleset()

    with suppress_stderr():
        extractor = RizinFeatureExtractor(
            rz, path=Path(target_path), max_functions=0, log_callback=lambda m: log_info(SERVER_TAG, m)
        )
        capa_res = capa.main.find_capabilities(rules, extractor)

    result_capabilities = []
    rules_matches = getattr(capa_res, "matches", None) or getattr(capa_res, "rules", None) or (
        capa_res[0] if isinstance(capa_res, tuple) and capa_res else capa_res if isinstance(capa_res, dict) else {}
    )

    attack_ids = set()
    for rule_name, rule_matches in rules_matches.items():
        rule = rules[rule_name]
        meta = rule.meta

        addresses = []
        locs = getattr(rule_matches, "locations", None) or (
            rule_matches if isinstance(rule_matches, (tuple, list)) else rule_matches.get("locations", [])
        )
        for match_item in locs:
            addr_val = match_item[0] if isinstance(match_item, tuple) and match_item else match_item
            if hasattr(addr_val, "value"):
                v = addr_val.value
                if isinstance(v, int):
                    addresses.append(hex(v))
                elif v is not None and "Result object" not in str(v):
                    addresses.append(str(v))
            elif isinstance(addr_val, int):
                addresses.append(hex(addr_val))
            elif isinstance(addr_val, str) and "Result object" not in addr_val:
                addresses.append(addr_val)

        for att in meta.get("attack", []) or []:
            if isinstance(att, dict) and att.get("id"):
                attack_ids.add(att["id"])

        result_capabilities.append({
            "rule": rule_name,
            "namespace": meta.get("namespace", ""),
            "scopes": meta.get("scopes", []),
            "attack": meta.get("attack", []),
            "mbc": meta.get("mbc", []),
            "confidence_hint": _confidence_hint_for_meta(meta),
            "matched_addresses": addresses[:10],
            "total_matches": len(addresses),
        })

    t1 = time.time()
    response_payload = {
        "status": "success",
        "cached": False,
        "mode": "Rizin Feature Extractor (Full Mode)",
        "file_path": target_path,
        "elapsed_seconds": round(t1 - t0, 2),
        "total_capabilities": len(result_capabilities),
        "summary": _summarize_capability_confidence(result_capabilities),
        "capabilities": result_capabilities,
        "recommended_mitre_attack_mcp_calls": [
            {"server": "mitre-attack", "tool": "get_technique_by_id", "arguments": {"technique_id": tid}}
            for tid in sorted(attack_ids)
        ],
    }
    save_tool_snapshot(target_path, "capa_rizin", response_payload)
    return response_payload


@server.tool(
    name="run_capa_analysis",
    description=(
        "[Ultra-fast Rizin Extractor Mode] Use the pre-analyzed Rizin session from open_and_analyze "
        "to match capa-rules and identify capabilities + MITRE ATT&CK / MBC mappings."
    ),
)
def run_capa_analysis(force_reanalysis: bool = False) -> str:
    if CURRENT_RZ is None or not CURRENT_FILE_PATH:
        return json.dumps({"status": "error", "message": "No file open. Call open_and_analyze first."}, ensure_ascii=False)

    target_path = CURRENT_FILE_PATH
    filename = os.path.basename(target_path)

    if not force_reanalysis:
        cached = load_tool_snapshot(target_path, "capa_rizin")
        if cached:
            return json.dumps(cached, ensure_ascii=False, indent=2)

    with CAPA_JOBS_LOCK:
        existing = CAPA_JOBS.get(target_path)
        if existing is not None and not existing["future"].done():
            elapsed = time.time() - existing["started_at"]
            return json.dumps({
                "status": "started",
                "job_id": existing["job_id"],
                "cached": False,
                "message": f"capa analysis for '{filename}' is already running ({elapsed:.0f}s). Poll get_capa_status('{existing['job_id']}').",
            }, ensure_ascii=False, indent=2)

        job_id = uuid.uuid4().hex[:16]
        future = CAPA_EXECUTOR.submit(_run_capa_analysis_job, CURRENT_RZ, target_path)
        job_entry = {"job_id": job_id, "future": future, "started_at": time.time(), "target_path": target_path}
        CAPA_JOBS[target_path] = job_entry
        CAPA_JOBS[job_id] = job_entry

    return json.dumps({
        "status": "started",
        "job_id": job_id,
        "cached": False,
        "message": f"capa analysis started in background for '{filename}'. Poll get_capa_status('{job_id}').",
    }, ensure_ascii=False, indent=2)


@server.tool(
    name="get_capa_status",
    description="Poll the status of a background Rizin capa analysis job started by run_capa_analysis.",
)
def get_capa_status(job_id: str) -> str:
    with CAPA_JOBS_LOCK:
        job = CAPA_JOBS.get(job_id)
    if job is None:
        return json.dumps({"status": "error", "message": f"Unknown job_id: '{job_id}'."}, ensure_ascii=False)

    future = job["future"]
    if not future.done():
        elapsed = time.time() - job["started_at"]
        return json.dumps({
            "status": "running",
            "job_id": job_id,
            "elapsed_seconds": round(elapsed, 1),
            "message": "capa analysis is still running.",
        }, ensure_ascii=False, indent=2)

    exc = future.exception()
    if exc is not None:
        tb = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
        return json.dumps({"status": "error", "job_id": job_id, "message": str(exc), "traceback": tb}, ensure_ascii=False, indent=2)

    result = dict(future.result())
    result["job_id"] = job_id
    return json.dumps(result, ensure_ascii=False, indent=2)


@server.tool(
    name="list_functions",
    description="List all functions identified in the current Rizin session, optionally filtered by keyword or hex address.",
)
def list_functions(filter_keyword: str = "", limit: int = 200) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "Call open_and_analyze first."})
    try:
        with suppress_stderr():
            funcs = json.loads(CURRENT_RZ.cmd("aflj") or "[]")
        filter_lower = filter_keyword.lower().strip()
        result = []
        for f in funcs:
            name = f.get("name", "")
            addr = hex(f.get("offset", 0))
            if not filter_lower or filter_lower in name.lower() or filter_lower in addr.lower():
                result.append({
                    "name": name,
                    "address": addr,
                    "size": f.get("size", 0),
                    "nargs": f.get("nargs", 0),
                    "nlocals": f.get("nlocals", 0),
                })
        return json.dumps({
            "status": "success",
            "total_matched": len(result),
            "functions": result[: max(1, int(limit))],
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def _split_ghidra_warnings(c_code: str):
    if not c_code:
        return c_code, []
    code_lines = []
    warnings = []
    for line in c_code.splitlines():
        if line.strip().startswith("// WARNING:"):
            warnings.append(line.strip()[len("// WARNING:") :].strip())
        else:
            code_lines.append(line)
    return "\n".join(code_lines), warnings


@server.tool(
    name="decompile_function",
    description="Use the RzGhidra decompiler (`pdg`) to decompile a function or memory address into clean C pseudocode.",
)
def decompile_function(address_or_name: str) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "Call open_and_analyze first."})
    try:
        safe_target = sanitize_symbol_or_address(address_or_name)
        with suppress_stderr():
            CURRENT_RZ.cmd(f"s {safe_target}")
            CURRENT_RZ.cmd("af")
            c_code = CURRENT_RZ.cmd("pdg")
        clean_code, warnings = _split_ghidra_warnings(c_code)
        return json.dumps({
            "status": "success" if clean_code.strip() else "warning",
            "target": address_or_name,
            "code": clean_code,
            "warnings": warnings,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="disassemble_function",
    description="Get the assembly disassembly (`pdf`) for a specified function or address.",
)
def disassemble_function(address_or_name: str) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "Call open_and_analyze first."})
    try:
        safe_target = sanitize_symbol_or_address(address_or_name)
        with suppress_stderr():
            CURRENT_RZ.cmd(f"s {safe_target}")
            asm_code = CURRENT_RZ.cmd("pdf")
        return json.dumps({"status": "success", "target": address_or_name, "disassembly": asm_code}, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="get_binary_info",
    description="Get architectural info, headers, sections, imports sample, and exports count from the current Rizin session.",
)
def get_binary_info() -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "Call open_and_analyze first."})
    try:
        with suppress_stderr():
            info = json.loads(CURRENT_RZ.cmd("iIj") or "{}")
            imports = json.loads(CURRENT_RZ.cmd("iij") or "[]")
            sections = json.loads(CURRENT_RZ.cmd("iSj") or "[]")
            exports = json.loads(CURRENT_RZ.cmd("iEj") or "[]")
        return json.dumps({
            "status": "success",
            "info": info,
            "sections_count": len(sections),
            "imports_count": len(imports),
            "exports_count": len(exports),
            "imports_sample": imports[:25],
            "sections": sections,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="search_imports",
    description="Search the import table by function name and/or DLL keyword, returning structured JSON plus MS-Learn/MITRE enrichment.",
)
def search_imports(query: str = "", dll: str = "") -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "Call open_and_analyze first."})
    try:
        with suppress_stderr():
            imports = json.loads(CURRENT_RZ.cmd("iij") or "[]")
        query_lower = query.lower().strip()
        dll_lower = dll.lower().strip()
        results = []
        names = []
        for imp in imports:
            name = imp.get("name", "")
            libname = imp.get("libname", "")
            if query_lower and query_lower not in name.lower():
                continue
            if dll_lower and dll_lower not in libname.lower():
                continue
            addr = imp.get("plt") or imp.get("vaddr") or 0
            results.append({"name": name, "libname": libname, "vaddr": hex(addr)})
            names.append(name)
        return json.dumps({
            "status": "success",
            "count": len(results),
            "imports": results,
            "mcp_enrichment": classify_imports_for_mcp_enrichment(names),
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="search_strings",
    description="Search for readable strings in the binary (`izj`), filtered by keyword.",
)
def search_strings(query: str = "", limit: int = 100) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "Call open_and_analyze first."})
    try:
        with suppress_stderr():
            strings = json.loads(CURRENT_RZ.cmd("izj") or "[]")
        query_lower = query.lower().strip()
        matched = []
        for s in strings:
            val = s.get("string", "")
            if not query_lower or query_lower in val.lower():
                matched.append({"address": hex(s.get("vaddr", 0)), "type": s.get("type"), "string": val})
        return json.dumps({
            "status": "success",
            "total_matched": len(matched),
            "strings": matched[: max(1, int(limit))],
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="get_xrefs",
    description="Find cross-references (Xrefs) to/from a specified function or address (`afxj`/`axtj`/`axfj`).",
)
def get_xrefs(address_or_name: str = "", xref_type: str = "ALL", limit: int = 100) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "Call open_and_analyze first."})
    try:
        with suppress_stderr():
            if address_or_name:
                resolve_seek_target(CURRENT_RZ, address_or_name)
                raw = CURRENT_RZ.cmd("afxj")
                if not raw or raw.strip() in ["", "[]"] or "ERROR" in raw:
                    t_list = json.loads(CURRENT_RZ.cmd("axtj") or "[]")
                    f_list = json.loads(CURRENT_RZ.cmd("axfj") or "[]")
                    items = t_list + f_list
                else:
                    items = json.loads(raw)
            else:
                items = json.loads(CURRENT_RZ.cmd("axlj") or "[]")

        type_filter = xref_type.strip().upper()
        xrefs = []
        for item in items:
            f_val = item.get("from")
            t_val = item.get("to")
            x_type = str(item.get("type", "UNKNOWN")).upper()
            if type_filter != "ALL" and x_type != type_filter:
                continue
            xrefs.append({
                "type": x_type,
                "from": hex(f_val) if isinstance(f_val, int) else str(f_val),
                "to": hex(t_val) if isinstance(t_val, int) else str(t_val),
            })
            if len(xrefs) >= limit:
                break
        return json.dumps({
            "status": "success",
            "target": address_or_name or "ALL",
            "count": len(xrefs),
            "xrefs": xrefs,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def _function_containing_address(rz, addr: int) -> Optional[Dict[str, Any]]:
    try:
        raw = rz.cmd(f"afij @ {addr}")
        info = json.loads(raw) if raw and "ERROR" not in raw else []
    except Exception:
        info = []
    if isinstance(info, list) and info:
        f = info[0]
        return {"name": f.get("name"), "address": hex(f.get("offset", 0))}
    return None


@server.tool(
    name="find_import_callers",
    description="Given an imported API name, list every call site that references it and resolve the containing function.",
)
def find_import_callers(import_name: str) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "Call open_and_analyze first."})
    try:
        with suppress_stderr():
            target_addr = resolve_seek_target(CURRENT_RZ, import_name)
            axt_items = json.loads(CURRENT_RZ.cmd(f"axtj @ {target_addr}") or "[]")
            call_sites = []
            for item in axt_items:
                from_addr = item.get("from")
                if from_addr is None:
                    continue
                call_sites.append({
                    "call_site": hex(from_addr) if isinstance(from_addr, int) else str(from_addr),
                    "in_function": _function_containing_address(CURRENT_RZ, from_addr) if isinstance(from_addr, int) else None,
                })
        return json.dumps({
            "status": "success",
            "import_name": import_name,
            "target_address": hex(target_addr),
            "count": len(call_sites),
            "call_sites": call_sites,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="analyze_function_dossier",
    description=(
        "[REA-Inspired Composite Tool] Produce a complete single-call dossier for a function or address: "
        "RzGhidra decompiled C code (`pdg`), assembly (`pdf`), callers (`axtj`), callees (`axfj`), "
        "matched CAPA capabilities at this address, and suspicious Win32 API calls."
    ),
)
def analyze_function_dossier(address_or_name: str) -> str:
    if CURRENT_RZ is None or not CURRENT_FILE_PATH:
        return json.dumps({"status": "error", "message": "Call open_and_analyze first."})
    try:
        with suppress_stderr():
            resolved = resolve_seek_target(CURRENT_RZ, address_or_name)
            CURRENT_RZ.cmd(f"s {hex(resolved)}")
            CURRENT_RZ.cmd("af")
            c_code = CURRENT_RZ.cmd("pdg")
            asm_code = CURRENT_RZ.cmd("pdf")
            callers = json.loads(CURRENT_RZ.cmd(f"axtj @ {resolved}") or "[]")
            callees = json.loads(CURRENT_RZ.cmd(f"axfj @ {resolved}") or "[]")
            finfo = json.loads(CURRENT_RZ.cmd(f"afij @ {resolved}") or "[]")

        clean_code, warnings = _split_ghidra_warnings(c_code)

        # Cross-check cached capa results for this function address
        matched_capa = []
        for snap_name in ["capa", "capa_rizin", "capa_ghidra"]:
            snap = load_tool_snapshot(CURRENT_FILE_PATH, snap_name)
            if snap and "capabilities" in snap:
                for cap in snap["capabilities"]:
                    if hex(resolved).lower() in [str(a).lower() for a in cap.get("matched_addresses", [])]:
                        matched_capa.append(cap)

        return json.dumps({
            "status": "success",
            "target": address_or_name,
            "resolved_address": hex(resolved),
            "function_metadata": finfo[0] if finfo else {},
            "decompiled_c": clean_code,
            "decompiler_warnings": warnings,
            "callers_count": len(callers),
            "callers": callers[:30],
            "callees_count": len(callees),
            "callees": callees[:50],
            "matched_capa_capabilities": matched_capa,
            "disassembly_preview": "\n".join((asm_code or "").splitlines()[:120]),
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="record_investigation_evidence",
    description=(
        "[REA-Inspired Evidence Ledger] Record verified observations, analyst inferences, or residual unknowns "
        "in the persistent per-binary ledger (.analysis_cache/<sha256>/ledger.json)."
    ),
)
def record_investigation_evidence(
    observation: str = "",
    inference: str = "",
    residual_unknown: str = "",
    address: str = "",
    file_path: str = "",
) -> str:
    target = file_path or CURRENT_FILE_PATH
    if not target:
        return json.dumps({"status": "error", "message": "Provide file_path or call open_and_analyze first."})
    safe_path = resolve_binary_path(target)
    obs = [{"address": address, "detail": observation}] if observation else None
    inf = [{"address": address, "hypothesis": inference}] if inference else None
    unk = [{"address": address, "unknown": residual_unknown}] if residual_unknown else None
    ledger = update_evidence_ledger(safe_path, SERVER_TAG, observations=obs, inferences=inf, residual_unknowns=unk)
    return json.dumps({"status": "success", "ledger": ledger}, ensure_ascii=False, indent=2)


def _rizin_command_denial_reason(command: str) -> Optional[str]:
    if not command:
        return None
    for sub in re.split(r"[;\n]+", command):
        sub = sub.strip()
        if not sub:
            continue
        if sub.startswith("!"):
            return f"Shell-escape commands are blocked: '{sub}'"
        head_match = re.match(r"^([A-Za-z][A-Za-z0-9+]*)", sub)
        head = head_match.group(1) if head_match else ""
        if head and head[0] in ("w", "o"):
            return f"Write/open commands ('{head}') are blocked in read-only mode."
    return None


@server.tool(
    name="execute_rizin_command",
    description="[Read-only] Execute custom commands in Rizin (e.g., `px 64 @ 0x140001000`, `iSj`). Supports pagination via offset/limit.",
)
def execute_rizin_command(command: str, offset: int = 0, limit: int = 20000) -> str:
    if CURRENT_RZ is None:
        return json.dumps({"status": "error", "message": "Call open_and_analyze first."})
    denial = _rizin_command_denial_reason(command)
    if denial:
        return json.dumps({"status": "error", "message": denial}, ensure_ascii=False)
    try:
        offset = max(0, int(offset))
        limit = max(1, int(limit))
        with suppress_stderr():
            output = CURRENT_RZ.cmd(command) or ""
        total = len(output)
        chunk = output[offset : offset + limit]
        next_offset = offset + len(chunk)
        truncated = next_offset < total
        return json.dumps({
            "status": "success",
            "command": command,
            "output": chunk,
            "total_length": total,
            "truncated": truncated,
            "next_offset": next_offset if truncated else None,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="close_file",
    description="Close the currently opened binary file and Rizin session.",
)
def close_file() -> str:
    global CURRENT_RZ, CURRENT_FILE_PATH
    if CURRENT_RZ is None:
        return json.dumps({"status": "info", "message": "No file currently open."})
    try:
        with suppress_stderr():
            CURRENT_RZ.quit()
        CURRENT_RZ = None
        CURRENT_FILE_PATH = None
        return json.dumps({"status": "success", "message": "Closed Rizin session."})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def main():
    server.run()


if __name__ == "__main__":
    main()
