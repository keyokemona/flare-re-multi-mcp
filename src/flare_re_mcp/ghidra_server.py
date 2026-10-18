"""Ghidra 12.1.4 & PyGhidra Headless MCP Server (`ghidra-mcp`) + Cross-Tool Synthesizer.
Integrates:
  - PyGhidra 3.1.0 native JVM bridge (`GHIDRA_INSTALL_DIR`) with persistent per-SHA-256 Ghidra projects
  - Batch & single-function decompilation via `ghidra.app.decompiler.DecompInterface` (inspired by `bethington/ghidra-mcp`)
  - `capa_explorer.py` style CAPA-to-Ghidra function annotation & cross-decompilation
  - `morluto/rea` style multi-tool evidence synthesis across DIE, FLOSS, CAPA, Rizin, radare2, Ghidra, MITRE ATT&CK, and MS-Learn.
"""

import json
import os
import time
from typing import Any, Dict, List, Optional

from mcp.server import MCPServer

from flare_re_mcp.common import (
    GHIDRA_INSTALL_DIR,
    classify_imports_for_mcp_enrichment,
    get_sample_cache_dir,
    list_available_snapshots,
    load_tool_snapshot,
    log_info,
    resolve_binary_path,
    save_tool_snapshot,
    suppress_stderr,
    update_evidence_ledger,
)

SERVER_TAG = "ghidra-mcp"
server = MCPServer("ghidra-analyzer")

# Persistent in-memory PyGhidra session state
CURRENT_CTX = None
CURRENT_FLAT_API = None
CURRENT_PROGRAM = None
CURRENT_DECOMP = None
CURRENT_FILE_PATH: Optional[str] = None


def _ensure_pyghidra_started():
    os.environ["GHIDRA_INSTALL_DIR"] = GHIDRA_INSTALL_DIR
    import pyghidra

    if not pyghidra.started():
        log_info(SERVER_TAG, f"Starting PyGhidra headless JVM from {GHIDRA_INSTALL_DIR}...")
        with suppress_stderr():
            pyghidra.start()
    return pyghidra


def _close_current_session():
    global CURRENT_CTX, CURRENT_FLAT_API, CURRENT_PROGRAM, CURRENT_DECOMP, CURRENT_FILE_PATH
    if CURRENT_DECOMP is not None:
        try:
            CURRENT_DECOMP.dispose()
        except Exception:
            pass
        CURRENT_DECOMP = None
    if CURRENT_CTX is not None:
        try:
            CURRENT_CTX.__exit__(None, None, None)
        except Exception:
            pass
        CURRENT_CTX = None
    CURRENT_FLAT_API = None
    CURRENT_PROGRAM = None
    CURRENT_FILE_PATH = None


def _resolve_ghidra_function(program, target: str):
    """Resolve a function in Ghidra by hex address, entry point, or symbol name."""
    fm = program.getFunctionManager()
    cleaned = target.strip()

    # 1. Try parsing as hex/int address and match against Ghidra image base
    try:
        addr_int = int(cleaned, 16) if cleaned.lower().startswith("0x") else int(cleaned, 16)
        addr_obj = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_int)
        func = fm.getFunctionAt(addr_obj) or fm.getFunctionContaining(addr_obj)
        if func is not None:
            return func
    except Exception:
        pass

    # 2. Search by function name (exact or substring)
    for func in fm.getFunctions(True):
        if func.getName().lower() == cleaned.lower():
            return func
    for func in fm.getFunctions(True):
        if cleaned.lower() in func.getName().lower():
            return func
    return None


@server.tool(
    name="ghidra_open_and_analyze",
    description=(
        "Start PyGhidra (if not already running), import/open the binary in a persistent Ghidra project "
        "cached under `ghidra_projects/<sha256>`, run Ghidra auto-analysis, initialize `DecompInterface`, "
        "and when `auto_decompile_top=True` (default), automatically decompile `entry`/`main`/top user functions in one turn."
    ),
)
def ghidra_open_and_analyze(
    file_path: str,
    analyze: bool = True,
    auto_decompile_top: bool = True,
    force_reanalysis: bool = False,
) -> str:
    global CURRENT_CTX, CURRENT_FLAT_API, CURRENT_PROGRAM, CURRENT_DECOMP, CURRENT_FILE_PATH
    try:
        safe_path = resolve_binary_path(file_path)
        if CURRENT_PROGRAM is not None and CURRENT_FILE_PATH == safe_path and not force_reanalysis:
            cached = load_tool_snapshot(safe_path, "ghidra")
            if cached:
                return json.dumps(cached, ensure_ascii=False, indent=2)

        _close_current_session()
        t0 = time.time()

        from flare_re_mcp.common import PROJECT_ROOT
        sample_dir, hashes = get_sample_cache_dir(safe_path)
        proj_dir = os.path.join(PROJECT_ROOT, "ghidra_projects", hashes["sha256"])
        os.makedirs(proj_dir, exist_ok=True)
        for stale_lock in ("FlareMCP.lock", "FlareMCP.lock~"):
            lock_path = os.path.join(proj_dir, stale_lock)
            if os.path.exists(lock_path):
                try:
                    os.remove(lock_path)
                except Exception:
                    # Another live process (e.g. active MCP server) holds the lock
                    if not force_reanalysis:
                        cached = load_tool_snapshot(safe_path, "ghidra")
                        if cached:
                            return json.dumps(cached, ensure_ascii=False, indent=2)

        pyghidra = _ensure_pyghidra_started()
        auto_decompiled = []
        with suppress_stderr():
            try:
                ctx = pyghidra.open_program(
                    safe_path,
                    project_location=proj_dir,
                    project_name="FlareMCP",
                    analyze=analyze,
                    nested_project_location=False,
                )
                flat_api = ctx.__enter__()
            except Exception as lock_exc:
                if "LockException" in str(lock_exc):
                    if not force_reanalysis:
                        cached = load_tool_snapshot(safe_path, "ghidra")
                        if cached:
                            return json.dumps(cached, ensure_ascii=False, indent=2)
                    ctx = pyghidra.open_program(
                        safe_path,
                        project_location=proj_dir,
                        project_name=f"FlareMCP_{os.getpid()}",
                        analyze=analyze,
                        nested_project_location=False,
                    )
                    flat_api = ctx.__enter__()
                else:
                    raise
            program = flat_api.getCurrentProgram()

            from ghidra.app.decompiler import DecompInterface
            from ghidra.util.task import ConsoleTaskMonitor

            decomp = DecompInterface()
            decomp.openProgram(program)

            fm = program.getFunctionManager()
            funcs_count = 0
            external_funcs = []
            priority_funcs = []
            for f in fm.getFunctions(True):
                funcs_count += 1
                if not f.isThunk() and not f.isExternal():
                    fname = f.getName()
                    fsize = int(f.getBody().getNumAddresses())
                    if fname in ("entry", "main", "WinMain", "wmain", "DllMain") or (
                        fname.startswith("FUN_") and fsize >= 24
                    ):
                        priority_funcs.append(f)
            for ext_f in fm.getExternalFunctions():
                external_funcs.append(ext_f.getName())

            if auto_decompile_top and priority_funcs:
                monitor = ConsoleTaskMonitor()
                for pf in priority_funcs[:6]:
                    dec_res = decomp.decompileFunction(pf, 30, monitor)
                    c_code = ""
                    if dec_res and dec_res.decompileCompleted() and dec_res.getDecompiledFunction():
                        c_code = str(dec_res.getDecompiledFunction().getC())
                    called = [
                        {"name": cf.getName(), "address": f"0x{cf.getEntryPoint().getOffset():x}"}
                        for cf in pf.getCalledFunctions(monitor)
                    ]
                    auto_decompiled.append({
                        "function_name": pf.getName(),
                        "entry_point": f"0x{pf.getEntryPoint().getOffset():x}",
                        "size": int(pf.getBody().getNumAddresses()),
                        "signature": str(pf.getPrototypeString(False, False)),
                        "called_functions": called[:30],
                        "decompiled_c": c_code,
                    })

        CURRENT_CTX = ctx
        CURRENT_FLAT_API = flat_api
        CURRENT_PROGRAM = program
        CURRENT_DECOMP = decomp
        CURRENT_FILE_PATH = safe_path

        t1 = time.time()
        enrichment = classify_imports_for_mcp_enrichment(external_funcs)

        payload = {
            "status": "success",
            "tool": "Ghidra 12.1.4 (PyGhidra 3.1.0)",
            "file_path": safe_path,
            "ghidra_project_dir": proj_dir,
            "analysis_seconds": round(t1 - t0, 2),
            "program_name": program.getName(),
            "language_id": str(program.getLanguageID()),
            "compiler_spec": str(program.getCompilerSpec().getCompilerSpecID()),
            "image_base": hex(program.getImageBase().getOffset()),
            "total_functions": funcs_count,
            "external_imports_count": len(external_funcs),
            "win32_api_and_mitre_enrichment": enrichment,
            "auto_triage_decompiled": auto_decompiled,
        }
        save_tool_snapshot(safe_path, "ghidra", payload)
        return json.dumps(payload, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="ghidra_list_functions",
    description="List functions in the active Ghidra program with signature, calling convention, parameter count, and size.",
)
def ghidra_list_functions(
    filter_keyword: str = "",
    include_thunks_and_externals: bool = False,
    limit: int = 200,
) -> str:
    if CURRENT_PROGRAM is None:
        return json.dumps({"status": "error", "message": "Call ghidra_open_and_analyze first."})
    try:
        fm = CURRENT_PROGRAM.getFunctionManager()
        q = filter_keyword.lower().strip()
        out = []
        for f in fm.getFunctions(True):
            if not include_thunks_and_externals and (f.isThunk() or f.isExternal()):
                continue
            name = f.getName()
            addr = f"0x{f.getEntryPoint().getOffset():x}"
            sig = f.getPrototypeString(False, False)
            if not q or q in name.lower() or q in addr.lower() or q in sig.lower():
                out.append({
                    "name": name,
                    "address": addr,
                    "size": int(f.getBody().getNumAddresses()),
                    "signature": sig,
                    "calling_convention": str(f.getCallingConventionName()),
                    "parameter_count": int(f.getParameterCount()),
                    "is_thunk": bool(f.isThunk()),
                })
                if len(out) >= max(1, int(limit)):
                    break
        return json.dumps({
            "status": "success",
            "returned_count": len(out),
            "functions": out,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="ghidra_decompile_functions",
    description=(
        "[Batch & Single Decompiler - inspired by bethington/ghidra-mcp] Decompile one or multiple functions "
        "(pass semicolon-separated addresses or names, e.g. `0x140001000;entry`) using Ghidra's native "
        "`DecompInterface`, returning C pseudocode, function signature, called functions, and calling functions."
    ),
)
def ghidra_decompile_functions(targets: str, timeout_seconds: int = 60) -> str:
    if CURRENT_PROGRAM is None or CURRENT_DECOMP is None:
        return json.dumps({"status": "error", "message": "Call ghidra_open_and_analyze first."})
    try:
        from ghidra.util.task import ConsoleTaskMonitor

        monitor = ConsoleTaskMonitor()
        target_list = [t.strip() for t in targets.split(";") if t.strip()]
        results = []

        for t in target_list:
            func = _resolve_ghidra_function(CURRENT_PROGRAM, t)
            if func is None:
                results.append({"target": t, "status": "not_found", "message": f"Function '{t}' not found in Ghidra."})
                continue

            with suppress_stderr():
                dec_res = CURRENT_DECOMP.decompileFunction(func, int(timeout_seconds), monitor)

            c_code = ""
            if dec_res and dec_res.decompileCompleted() and dec_res.getDecompiledFunction():
                c_code = str(dec_res.getDecompiledFunction().getC())

            called = [
                {"name": cf.getName(), "address": f"0x{cf.getEntryPoint().getOffset():x}"}
                for cf in func.getCalledFunctions(monitor)
            ]
            callers = [
                {"name": cr.getName(), "address": f"0x{cr.getEntryPoint().getOffset():x}"}
                for cr in func.getCallingFunctions(monitor)
            ]

            results.append({
                "target": t,
                "status": "success" if c_code else "warning",
                "function_name": func.getName(),
                "entry_point": f"0x{func.getEntryPoint().getOffset():x}",
                "signature": str(func.getPrototypeString(False, False)),
                "calling_convention": str(func.getCallingConventionName()),
                "called_functions": called[:50],
                "calling_functions": callers[:50],
                "decompiled_c": c_code,
            })

        return json.dumps({
            "status": "success",
            "decompiled_count": len(results),
            "results": results,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="ghidra_get_xrefs",
    description="Query Ghidra's ReferenceManager for all cross-references TO and FROM a target address or function name.",
)
def ghidra_get_xrefs(address_or_name: str, limit: int = 100) -> str:
    if CURRENT_PROGRAM is None:
        return json.dumps({"status": "error", "message": "Call ghidra_open_and_analyze first."})
    try:
        fm = CURRENT_PROGRAM.getFunctionManager()
        rm = CURRENT_PROGRAM.getReferenceManager()

        func = _resolve_ghidra_function(CURRENT_PROGRAM, address_or_name)
        if func is not None:
            addr_obj = func.getEntryPoint()
        else:
            cleaned = address_or_name.strip()
            addr_int = int(cleaned, 16) if cleaned.lower().startswith("0x") else int(cleaned, 16)
            addr_obj = CURRENT_PROGRAM.getAddressFactory().getDefaultAddressSpace().getAddress(addr_int)

        refs_to = []
        for ref in rm.getReferencesTo(addr_obj):
            from_addr = ref.getFromAddress()
            containing = fm.getFunctionContaining(from_addr)
            refs_to.append({
                "from_address": f"0x{from_addr.getOffset():x}",
                "from_function": containing.getName() if containing else None,
                "type": str(ref.getReferenceType()),
            })
            if len(refs_to) >= max(1, int(limit)):
                break

        refs_from = []
        for ref in rm.getReferencesFrom(addr_obj):
            to_addr = ref.getToAddress()
            containing = fm.getFunctionContaining(to_addr)
            refs_from.append({
                "to_address": f"0x{to_addr.getOffset():x}",
                "to_function": containing.getName() if containing else None,
                "type": str(ref.getReferenceType()),
            })
            if len(refs_from) >= max(1, int(limit)):
                break

        return json.dumps({
            "status": "success",
            "target": address_or_name,
            "resolved_address": f"0x{addr_obj.getOffset():x}",
            "references_to_count": len(refs_to),
            "references_to": refs_to,
            "references_from_count": len(refs_from),
            "references_from": refs_from,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="ghidra_annotate_with_capa",
    description=(
        "[Inspired by capa/ghidra/plugin/capa_explorer.py] Cross-reference CAPA capability matches onto "
        "Ghidra functions, automatically decompiling the top behavioral functions in Ghidra so you can inspect "
        "the exact C pseudocode implementing each MITRE ATT&CK / MBC capability."
    ),
)
def ghidra_annotate_with_capa(
    file_path: str = "",
    decompile_top_n_functions: int = 5,
) -> str:
    try:
        target_path = resolve_binary_path(file_path or CURRENT_FILE_PATH or "")
        if CURRENT_PROGRAM is None or CURRENT_FILE_PATH != target_path:
            ghidra_open_and_analyze(target_path, analyze=True)

        capa_snap = (
            load_tool_snapshot(target_path, "capa")
            or load_tool_snapshot(target_path, "capa_ghidra")
            or load_tool_snapshot(target_path, "capa_rizin")
        )
        if not capa_snap:
            from flare_re_mcp.capa_server import _execute_capa_job

            capa_snap = _execute_capa_job(target_path, backend="vivisect")

        func_cap_map = capa_snap.get("function_capability_map", {})
        annotated_functions = []
        for addr_hex, rules in func_cap_map.items():
            func = _resolve_ghidra_function(CURRENT_PROGRAM, addr_hex)
            annotated_functions.append({
                "address": addr_hex,
                "ghidra_function_name": func.getName() if func else None,
                "ghidra_signature": str(func.getPrototypeString(False, False)) if func else None,
                "matched_capa_rules": rules,
                "rule_count": len(rules),
            })

        annotated_functions.sort(key=lambda x: x["rule_count"], reverse=True)

        decompiled_highlights = []
        if decompile_top_n_functions > 0 and annotated_functions:
            top_addrs = ";".join(x["address"] for x in annotated_functions[: int(decompile_top_n_functions)])
            dec_raw = json.loads(ghidra_decompile_functions(top_addrs))
            decompiled_highlights = dec_raw.get("results", [])

        return json.dumps({
            "status": "success",
            "file_path": target_path,
            "total_annotated_functions": len(annotated_functions),
            "annotated_functions": annotated_functions,
            "top_behavioral_functions_decompiled": decompiled_highlights,
            "attack_tactics_matrix": capa_snap.get("attack_tactics_matrix", {}),
            "mbc_objectives_matrix": capa_snap.get("mbc_objectives_matrix", {}),
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="ghidra_synthesize_multi_tool_report",
    description=(
        "[Master REA Cross-Tool Synthesizer] Fuse cached/live static analysis results from all FlareVM tools "
        "(Detect It Easy, FLOSS, CAPA, Rizin, radare2, Ghidra, and the REA Evidence Ledger) for a binary, "
        "automatically running any missing fast triage passes and producing a unified threat intelligence & "
        "reverse-engineering dossier with prioritized `mitre-attack` and `ms-learn` MCP queries."
    ),
)
def ghidra_synthesize_multi_tool_report(
    file_path: str,
    auto_run_missing_triage: bool = True,
) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        die_snap = load_tool_snapshot(safe_path, "die")
        if not die_snap and auto_run_missing_triage:
            from flare_re_mcp.die_server import die_scan_binary

            die_snap = json.loads(die_scan_binary(safe_path))

        floss_snap = load_tool_snapshot(safe_path, "floss")
        if not floss_snap and auto_run_missing_triage:
            from flare_re_mcp.floss_server import _execute_floss_job

            floss_snap = _execute_floss_job(safe_path, min_length=4, include_static=False)

        capa_snap = (
            load_tool_snapshot(safe_path, "capa")
            or load_tool_snapshot(safe_path, "capa_ghidra")
            or load_tool_snapshot(safe_path, "capa_rizin")
        )
        if not capa_snap and auto_run_missing_triage:
            from flare_re_mcp.capa_server import _execute_capa_job

            capa_snap = _execute_capa_job(safe_path, backend="vivisect")

        rizin_snap = load_tool_snapshot(safe_path, "rizin")
        r2_snap = load_tool_snapshot(safe_path, "radare2")
        ghidra_snap = load_tool_snapshot(safe_path, "ghidra")
        ledger_snap = load_tool_snapshot(safe_path, "ledger")

        # Cross-correlate high-priority functions across CAPA and FLOSS
        capa_funcs = set((capa_snap or {}).get("function_capability_map", {}).keys())
        floss_decoders = {
            c["function_address"]: c
            for c in (floss_snap or {}).get("top_decoding_function_candidates", [])
            if c.get("function_address")
        }
        high_priority_functions = []
        for addr in sorted(capa_funcs | set(floss_decoders.keys())):
            high_priority_functions.append({
                "address": addr,
                "capa_rules": (capa_snap or {}).get("function_capability_map", {}).get(addr, []),
                "floss_decoder_score": floss_decoders.get(addr, {}).get("score"),
            })

        return json.dumps({
            "status": "success",
            "file_path": safe_path,
            "available_snapshots": list_available_snapshots(safe_path),
            "triage_die": {
                "detects": (die_snap or {}).get("die_detections", {}).get("detects", []),
                "packing_indicators": (die_snap or {}).get("pe_analysis", {}).get("packing_indicators", {}),
                "imphash": (die_snap or {}).get("pe_analysis", {}).get("imphash"),
                "compile_timestamp_utc": (die_snap or {}).get("pe_analysis", {}).get("compile_timestamp_utc"),
            },
            "obfuscation_floss": {
                "counts": (floss_snap or {}).get("counts", {}),
                "decoded_strings": (floss_snap or {}).get("decoded_strings", [])[:30],
                "stack_strings": (floss_snap or {}).get("stack_strings", [])[:30],
                "top_decoding_functions": (floss_snap or {}).get("top_decoding_function_candidates", [])[:10],
                "iocs": (floss_snap or {}).get("ioc_and_api_enrichment", {}).get("iocs_by_category", {}),
            },
            "capabilities_capa": {
                "total_capabilities": (capa_snap or {}).get("total_capabilities", 0),
                "attack_tactics_matrix": (capa_snap or {}).get("attack_tactics_matrix", {}),
                "mbc_objectives_matrix": (capa_snap or {}).get("mbc_objectives_matrix", {}),
            },
            "cross_correlated_priority_functions": high_priority_functions[:30],
            "disassemblers_status": {
                "rizin_analyzed": rizin_snap is not None,
                "radare2_analyzed": r2_snap is not None,
                "ghidra_analyzed": ghidra_snap is not None,
            },
            "rea_evidence_ledger": ledger_snap or {},
            "recommended_mcp_cross_queries": {
                "mitre_attack_mcp": (capa_snap or {}).get("cross_mcp_enrichment", {}).get("recommended_mitre_attack_mcp_calls", []),
                "ms_learn_mcp": (die_snap or {}).get("pe_analysis", {}).get("win32_api_and_mitre_enrichment", {}).get("recommended_ms_learn_mcp_calls", []),
            },
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="ghidra_close_program",
    description="Close the active Ghidra program and save project state.",
)
def ghidra_close_program() -> str:
    _close_current_session()
    return json.dumps({"status": "success", "message": "Closed Ghidra program session."})


def main():
    server.run()


if __name__ == "__main__":
    main()
