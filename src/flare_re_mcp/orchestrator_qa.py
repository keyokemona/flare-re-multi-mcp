"""DevSecOps, Information Security & Software Engineering Orchestrator QA & Queue Engine.
Ensures 100% completion, data integrity, hybrid unpacking check, Threat Intelligence OSINT lookup,
detection validation (YARA + ATT&CK Navigator), scenario-based execution time telemetry, and
standardized report archival (`./reports/<timestamp>_<filename>_<sha256>.md`) across all MCP servers:
  - `die-mcp`, `unpacker-mcp`, `floss-mcp`, `capa-mcp`, `rizin-mcp`, `radare2-mcp`, `ghidra-mcp`,
    `threat-intel-mcp`, `mitre-attack`, and `ms-learn`.
"""

import argparse
import concurrent.futures
import datetime
import glob
import json
import os
import re
import sys
import time
from typing import Any, Dict, List, Optional

from flare_re_mcp.auto_updater import check_all_components
from flare_re_mcp.common import (
    PROJECT_ROOT,
    REPORTS_DIR,
    export_markdown_report,
    get_cached_capa_ruleset,
    get_sample_cache_dir,
    load_tool_snapshot,
    resolve_binary_path,
)


def prewarm_parallel_static_queue(file_path: str, run_ghidra: bool = False) -> Dict[str, Any]:
    """Execute the fast native & OSINT analysis stages concurrently in a background ThreadPoolExecutor:
      - Startup component version check (12h cached cooldown)
      - `die-mcp` (structural triage & entropy)
      - `unpacker-mcp` (hybrid packer detection & automatic unpacking if `auto_supported`)
      - `threat-intel-mcp` (MalwareBazaar, ThreatFox, URLhaus, VirusTotal hash lookup)
      - `floss-mcp` (static, stack, tight & decoded strings)
      - `capa-mcp` (1,385 cached `.pkl` rules via Rizin extractor)
      - `rizin-mcp` (`rz-ghidra` auto-dossiers)
      - `radare2-mcp` (`r2ghidra` auto-dossiers)
    """
    safe_path = resolve_binary_path(file_path)
    t0 = time.time()

    # Non-blocking startup component health check
    update_check = check_all_components(check_remote=False, force=False)

    # Pre-warm CAPA ruleset pickle cache first so worker threads don't race on initial load
    try:
        get_cached_capa_ruleset()
    except Exception:
        pass

    from flare_re_mcp.capa_server import capa_analyze_binary
    from flare_re_mcp.die_server import die_scan_binary
    from flare_re_mcp.floss_server import floss_extract_strings
    from flare_re_mcp.radare2_server import r2_close_file, r2_open_and_analyze
    from flare_re_mcp.rizin_server import close_file as rz_close_file, open_and_analyze as rz_open_and_analyze
    from flare_re_mcp.threat_intel_server import ti_lookup_binary_reputation
    from flare_re_mcp.unpacker_server import unpack_auto_decompress, unpack_inspect_and_detect

    def _task_die() -> Dict[str, Any]:
        t = time.time()
        res = json.loads(die_scan_binary(safe_path, deep_scan=True))
        return {"status": res.get("status", "unknown"), "elapsed_s": round(time.time() - t, 2)}

    def _task_unpacker() -> Dict[str, Any]:
        t = time.time()
        res = json.loads(unpack_inspect_and_detect(safe_path))
        strat = res.get("unpack_strategy")
        unpacked_path = None
        if strat == "auto_supported":
            dec = json.loads(unpack_auto_decompress(safe_path, allow_header_repair=True))
            unpacked_path = dec.get("unpacked_file_path")
        return {
            "status": res.get("status", "unknown"),
            "unpack_strategy": strat,
            "unpacked_file_path": unpacked_path,
            "elapsed_s": round(time.time() - t, 2),
        }

    def _task_threat_intel() -> Dict[str, Any]:
        t = time.time()
        res = json.loads(ti_lookup_binary_reputation(safe_path))
        return {
            "status": res.get("status", "unknown"),
            "reputation_verdict": res.get("reputation_verdict"),
            "elapsed_s": round(time.time() - t, 2),
        }

    def _task_floss() -> Dict[str, Any]:
        t = time.time()
        res = json.loads(floss_extract_strings(safe_path, min_length=4, include_static=True, wait=True))
        return {"status": res.get("status", "unknown"), "elapsed_s": round(time.time() - t, 2)}

    def _task_capa() -> Dict[str, Any]:
        t = time.time()
        res = json.loads(capa_analyze_binary(safe_path, backend="rizin", wait=True))
        return {
            "status": res.get("status", "unknown"),
            "capabilities": res.get("total_capabilities", 0),
            "elapsed_s": round(time.time() - t, 2),
        }

    def _task_rizin() -> Dict[str, Any]:
        t = time.time()
        res = json.loads(rz_open_and_analyze(safe_path, analyze_level="aaa", auto_dossier=True))
        rz_close_file()
        return {
            "status": res.get("status", "unknown"),
            "dossiers": len(res.get("auto_triage_dossiers", [])),
            "elapsed_s": round(time.time() - t, 2),
        }

    def _task_radare2() -> Dict[str, Any]:
        t = time.time()
        res = json.loads(r2_open_and_analyze(safe_path, analyze_level="aaa", auto_dossier=True))
        r2_close_file()
        return {
            "status": res.get("status", "unknown"),
            "dossiers": len(res.get("auto_triage_dossiers", [])),
            "elapsed_s": round(time.time() - t, 2),
        }

    stage_results: Dict[str, Any] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=7, thread_name_prefix="secops-queue") as pool:
        futures = {
            "die-mcp": pool.submit(_task_die),
            "unpacker-mcp": pool.submit(_task_unpacker),
            "threat-intel-mcp": pool.submit(_task_threat_intel),
            "floss-mcp": pool.submit(_task_floss),
            "capa-mcp": pool.submit(_task_capa),
            "rizin-mcp": pool.submit(_task_rizin),
            "radare2-mcp": pool.submit(_task_radare2),
        }
        for name, fut in futures.items():
            try:
                stage_results[name] = fut.result(timeout=180)
            except Exception as exc:
                stage_results[name] = {"status": "error", "error": str(exc)}

    if run_ghidra:
        from flare_re_mcp.ghidra_server import ghidra_close_program, ghidra_open_and_analyze

        tg = time.time()
        gres = json.loads(ghidra_open_and_analyze(safe_path, analyze=True, auto_decompile_top=True))
        ghidra_close_program()
        stage_results["ghidra-mcp"] = {
            "status": gres.get("status", "unknown"),
            "decompiled": len(gres.get("auto_triage_decompiled", [])),
            "elapsed_s": round(time.time() - tg, 2),
        }

    return {
        "status": "success",
        "file_path": safe_path,
        "startup_component_check": update_check.get("status", "up_to_date"),
        "total_wall_clock_seconds": round(time.time() - t0, 2),
        "stages": stage_results,
    }


def estimate_analysis_time_by_scenario(
    die_snap: Optional[Dict[str, Any]],
    floss_snap: Optional[Dict[str, Any]],
    capa_snap: Optional[Dict[str, Any]],
    unpack_snap: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Classify the analyzed binary into its technical complexity scenario and provide realistic
    execution time benchmarks across the most common malware reverse engineering scenarios.
    """
    is_packed = bool((unpack_snap or {}).get("is_packed_or_wrapped"))
    unpack_strat = (unpack_snap or {}).get("unpack_strategy", "not_packed")
    decoded_count = int((floss_snap or {}).get("counts", {}).get("decoded_strings", 0) or 0)
    stack_count = int((floss_snap or {}).get("counts", {}).get("stack_strings", 0) or 0)

    caps_text = json.dumps((capa_snap or {}).get("capabilities", [])).lower()
    has_anti_debug = any(k in caps_text for k in ["anti-debug", "debugger", "t1622", "t1497"])
    has_anti_disasm = any(k in caps_text for k in ["anti-disassembly", "opaque", "control-flow"])
    has_defense_evasion = any(k in caps_text for k in ["defense-evasion", "t1070", "t1027", "self-delete", "xor"])

    detected_scenarios = []
    if is_packed:
        detected_scenarios.append(f"Packing / Compression ({unpack_strat})")
    if has_defense_evasion or decoded_count > 0 or stack_count > 0:
        detected_scenarios.append("Defense Evasion / String Obfuscation")
    if has_anti_debug:
        detected_scenarios.append("Anti-Debugging / Sandbox Evasion (Timing)")
    if has_anti_disasm:
        detected_scenarios.append("Anti-Disassembly / Control-Flow Obfuscation")
    if not detected_scenarios:
        detected_scenarios.append("Clean Native Binary (Unpacked C/C++)")

    return {
        "detected_sample_scenarios": detected_scenarios,
        "scenario_time_benchmarks": {
            "1_clean_unpacked_native_binary": {
                "description": "Binários PE/ELF nativos sem packer (Droppers, Downloaders, Utilitários C/C++)",
                "parallel_prewarm_queue_time": "~4s – 7s",
                "ghidra_headless_and_threat_intel_time": "~12s – 25s",
                "total_end_to_end_analysis_time": "~20s – 35s",
            },
            "2_packed_standard_or_tampered_wrapper": {
                "description": "Binários comprimidos com UPX, UPX adulterado, PyInstaller ou PE/XOR embutido em recursos (.rsrc)",
                "unpacker_decompression_time": "~2s – 6s (`unpacker-mcp` automático + reparo de cabeçalho)",
                "reanalysis_of_unpacked_payload_time": "~20s – 35s",
                "total_end_to_end_analysis_time": "~25s – 45s",
            },
            "3_defense_evasion_and_string_obfuscation": {
                "description": "Binários com Stack Strings, Tight Strings, XOR/RC4 loop, API Hashing (`GetProcAddress`) e Auto-Deleção (`T1070.004`)",
                "floss_emulation_and_capa_time": "~8s – 18s",
                "triple_decompilation_and_xref_time": "~18s – 30s",
                "total_end_to_end_analysis_time": "~30s – 50s",
            },
            "4_anti_debugging_and_sandbox_evasion": {
                "description": "Binários com `IsDebuggerPresent`, `NtQueryInformationProcess`, `TLS Callbacks`, `RDTSC`/`Sleep`/`ping` timing checks",
                "tls_and_anti_debug_capa_inspection_time": "~8s – 15s",
                "ghidra_and_ms_learn_flag_verification_time": "~20s – 35s",
                "total_end_to_end_analysis_time": "~35s – 55s",
            },
            "5_anti_disassembly_or_custom_packer": {
                "description": "Binários com predicados opacos, junk bytes, saltos no meio de instruções ou Packers Customizados/VMProtect",
                "oep_landmark_and_stub_analysis_time": "~10s – 20s",
                "custom_python_unpacker_or_deep_cfg_time": "~45s – 90s (caso o usuário opte por gerar unpacker customizado)",
                "total_end_to_end_analysis_time": "~55s – 110s",
            },
        },
    }


def audit_execution_queue(
    file_path: str,
    artifact_report_path: Optional[str] = None,
    sync_to_reports_dir: bool = True,
) -> Dict[str, Any]:
    """Run the DevSecOps & SecOps Quality Gate Audit for a binary analysis.
    Verifies every tool snapshot (including `unpacker-mcp` and `threat-intel-mcp`), Evidence Ledger integrity,
    YARA rule compilation & matching, MITRE ATT&CK Navigator layer validity, and exports/verifies `./reports/`.
    """
    safe_path = resolve_binary_path(file_path)
    sample_dir, hashes = get_sample_cache_dir(safe_path)

    die_snap = load_tool_snapshot(safe_path, "die")
    unpack_snap = load_tool_snapshot(safe_path, "unpacker_inspect")
    ti_snap = load_tool_snapshot(safe_path, "threat_intel")
    floss_snap = load_tool_snapshot(safe_path, "floss")
    capa_snap = (
        load_tool_snapshot(safe_path, "capa_rizin")
        or load_tool_snapshot(safe_path, "capa")
        or load_tool_snapshot(safe_path, "capa_ghidra")
    )
    rizin_snap = load_tool_snapshot(safe_path, "rizin")
    r2_snap = load_tool_snapshot(safe_path, "radare2")
    ghidra_snap = load_tool_snapshot(safe_path, "ghidra")
    ledger_snap = load_tool_snapshot(safe_path, "ledger")

    checks: Dict[str, Dict[str, Any]] = {}

    # 1. DIE + Unpacker Check
    checks["1_die_and_unpacker_triage"] = {
        "passed": bool(die_snap and die_snap.get("status") == "success"),
        "imphash": (die_snap or {}).get("pe_analysis", {}).get("imphash"),
        "sections_count": len((die_snap or {}).get("pe_analysis", {}).get("sections", [])),
        "packed": (unpack_snap or {}).get("is_packed_or_wrapped", False),
        "unpack_strategy": (unpack_snap or {}).get("unpack_strategy", "not_packed"),
    }

    # 2. FLOSS Check
    checks["2_floss_strings"] = {
        "passed": bool(floss_snap and floss_snap.get("status") == "success"),
        "counts": (floss_snap or {}).get("counts", {}),
        "ioc_categories": list(
            ((floss_snap or {}).get("ioc_and_api_enrichment", {}).get("iocs_by_category", {}) or {}).keys()
        ),
    }

    # 3. CAPA Check
    checks["3_capa_capabilities"] = {
        "passed": bool(capa_snap and capa_snap.get("status") == "success"),
        "backend": (capa_snap or {}).get("backend"),
        "total_capabilities": (capa_snap or {}).get("total_capabilities", 0),
        "tactics": list(((capa_snap or {}).get("attack_tactics_matrix", {}) or {}).keys()),
    }

    # 4. Rizin + RzGhidra Check
    checks["4_rizin_re"] = {
        "passed": bool(rizin_snap and rizin_snap.get("status") == "success"),
        "total_functions": (rizin_snap or {}).get("total_functions", 0),
        "auto_triage_dossiers": len((rizin_snap or {}).get("auto_triage_dossiers", [])),
    }

    # 5. Radare2 + r2ghidra Check
    checks["5_radare2_re"] = {
        "passed": bool(r2_snap and r2_snap.get("status") == "success"),
        "total_functions": (r2_snap or {}).get("total_functions", 0),
        "auto_triage_dossiers": len((r2_snap or {}).get("auto_triage_dossiers", [])),
    }

    # 6. Ghidra + PyGhidra Check
    ghidra_proj_dir = os.path.join(PROJECT_ROOT, "ghidra_projects", hashes["sha256"])
    checks["6_ghidra_decompiler"] = {
        "passed": bool(ghidra_snap and ghidra_snap.get("status") == "success"),
        "total_functions": (ghidra_snap or {}).get("total_functions", 0),
        "project_persisted": os.path.isdir(ghidra_proj_dir),
    }

    # 7. REA Evidence Ledger & Threat Intel OSINT Check
    obs_list = (ledger_snap or {}).get("verified_observations", [])
    inf_list = (ledger_snap or {}).get("inferences", [])
    unk_list = (ledger_snap or {}).get("residual_unknowns", [])
    checks["7_rea_evidence_ledger_and_threat_intel"] = {
        "passed": bool(ledger_snap and len(obs_list) > 0),
        "verified_observations_count": len(obs_list),
        "inferences_count": len(inf_list),
        "residual_unknowns_count": len(unk_list),
        "threat_intel_checked": bool(ti_snap and ti_snap.get("status") == "success"),
        "reputation_verdict": (ti_snap or {}).get("reputation_verdict", "NOT_YET_QUERIED"),
    }

    # 8. Detection Engineering (Navigator Layer + YARA Rule) & Report Export Check
    nav_path = os.path.join(sample_dir, "attack_navigator_layer.json")
    yar_files = glob.glob(os.path.join(sample_dir, "*.yar"))
    yara_valid = False
    yara_matches = []
    if yar_files:
        try:
            import yara

            rule_obj = yara.compile(filepath=yar_files[0])
            matches = rule_obj.match(safe_path)
            yara_valid = len(matches) > 0
            yara_matches = [m.rule for m in matches]
        except ImportError:
            try:
                import yara_x

                with open(yar_files[0], "r", encoding="utf-8") as yf:
                    rules_src = yf.read()
                rules = yara_x.compile(rules_src)
                with open(safe_path, "rb") as bf:
                    scan_res = rules.scan(bf.read())
                yara_matches = [m.identifier for m in scan_res.matching_rules]
                yara_valid = len(yara_matches) > 0
            except Exception as exc:
                yara_matches = [f"error: {exc}"]
        except Exception as exc:
            yara_matches = [f"error: {exc}"]

    from flare_re_mcp.common import sanitize_markdown_report_formatting, sanitize_mermaid_syntax

    if artifact_report_path and os.path.exists(artifact_report_path):
        try:
            with open(artifact_report_path, "r", encoding="utf-8") as rf:
                orig_art = rf.read()
            cleaned_art = sanitize_markdown_report_formatting(orig_art)
            if cleaned_art != orig_art:
                with open(artifact_report_path, "w", encoding="utf-8") as wf:
                    wf.write(cleaned_art)
        except Exception:
            pass

    exported_reports = glob.glob(os.path.join(REPORTS_DIR, f"*{hashes['file_name']}*.md")) + glob.glob(
        os.path.join(REPORTS_DIR, f"*{hashes['sha256'][:12]}*.md")
    )
    if sync_to_reports_dir and artifact_report_path and os.path.exists(artifact_report_path) and not exported_reports:
        with open(artifact_report_path, "r", encoding="utf-8") as rf:
            content = rf.read()
        new_report = export_markdown_report(safe_path, content)
        exported_reports = [new_report]

    for rep_file in sorted(set(exported_reports)):
        if os.path.isfile(rep_file):
            try:
                with open(rep_file, "r", encoding="utf-8") as rf:
                    orig_rep = rf.read()
                cleaned_rep = sanitize_markdown_report_formatting(orig_rep)
                if cleaned_rep != orig_rep:
                    with open(rep_file, "w", encoding="utf-8") as wf:
                        wf.write(cleaned_rep)
            except Exception:
                pass

    checks["8_deliverables_and_reports"] = {
        "passed": bool(os.path.exists(nav_path) and yara_valid and len(exported_reports) > 0),
        "attack_navigator_layer": nav_path if os.path.exists(nav_path) else None,
        "yara_rule_file": yar_files[0] if yar_files else None,
        "yara_validated": yara_valid,
        "yara_matched_rules": yara_matches,
        "reports_dir_files": sorted(set(exported_reports)),
    }

    all_passed = all(c.get("passed", False) for c in checks.values())
    missing_stages = [k for k, v in checks.items() if not v.get("passed", False)]
    time_estimates = estimate_analysis_time_by_scenario(die_snap, floss_snap, capa_snap, unpack_snap)

    return {
        "overall_quality_gate": "PASSED" if all_passed else "INCOMPLETE",
        "all_checks_passed": all_passed,
        "missing_or_failed_stages": missing_stages,
        "sample": hashes,
        "cache_directory": sample_dir,
        "quality_gate_checks": checks,
        "analysis_time_estimation_by_scenario": time_estimates,
    }


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="DevSecOps & SecOps Static Analysis Orchestrator QA Engine")
    parser.add_argument("file_path", help="Path to the target binary analyzed")
    parser.add_argument("--prewarm", action="store_true", help="Run parallel fast pre-warming queue first")
    parser.add_argument("--include-ghidra", action="store_true", help="Include Ghidra in prewarm pass")
    parser.add_argument("--artifact-report", default="", help="Path to markdown report artifact to sync into ./reports/")
    args = parser.parse_args()

    out: Dict[str, Any] = {}
    if args.prewarm:
        out["prewarm"] = prewarm_parallel_static_queue(args.file_path, run_ghidra=args.include_ghidra)
    out["audit"] = audit_execution_queue(
        args.file_path,
        artifact_report_path=args.artifact_report or None,
        sync_to_reports_dir=True,
    )
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
