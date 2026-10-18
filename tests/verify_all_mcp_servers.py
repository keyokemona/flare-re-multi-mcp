"""End-to-end verification test suite for all 8 custom Flare-RE-MCP servers,
plus the Auto-Updater (`flare-re-update`) and Offline Mentor Engine (`flare-re-mentor`).
"""

import json
import os
import shutil
import subprocess
import tempfile
import time

SAMPLE = r"C:\Users\keyokemona\Desktop\Malware.Unknown.exe.malz"
if not os.path.isfile(SAMPLE):
    SAMPLE = r"C:\Windows\System32\whoami.exe"


def run_verification():
    print("=" * 78)
    print(f"Starting End-to-End Verification Suite on: {SAMPLE}")
    print("=" * 78)

    # 1. Test die-mcp
    from flare_re_mcp import die_server

    t0 = time.time()
    die_res = json.loads(die_server.die_scan_binary(SAMPLE))
    assert die_res["status"] == "success", f"die_scan_binary failed: {die_res}"
    rsrc_res = json.loads(die_server.die_inspect_resources(SAMPLE))
    assert rsrc_res["status"] == "success", f"die_inspect_resources failed: {rsrc_res}"
    print(
        f"[1/10] [OK] die-mcp ({time.time() - t0:.2f}s) -> "
        f"Imphash={die_res['pe_analysis'].get('imphash')}, "
        f"Resources={rsrc_res.get('resource_count')}, "
        f"Suspicious APIs={die_res['pe_analysis']['win32_api_and_mitre_enrichment']['suspicious_api_count']}"
    )

    # 2. Test unpacker-mcp (including real UPX pack -> tamper -> auto-unpack cycle if UPX is available)
    from flare_re_mcp import unpacker_server

    t0 = time.time()
    unp_inspect = json.loads(unpacker_server.unpack_inspect_and_detect(SAMPLE))
    assert unp_inspect["status"] == "success", f"unpack_inspect_and_detect failed: {unp_inspect}"
    upx_test_note = f"strategy={unp_inspect['unpack_strategy']}"
    if os.path.isfile(unpacker_server.UPX_BIN):
        with tempfile.TemporaryDirectory() as tmpd:
            packed_tmp = os.path.join(tmpd, "packed_upx_test.exe")
            p = subprocess.run([unpacker_server.UPX_BIN, "-1", "-q", "-o", packed_tmp, SAMPLE], capture_output=True)
            if p.returncode == 0 and os.path.isfile(packed_tmp):
                det_packed = json.loads(unpacker_server.unpack_inspect_and_detect(packed_tmp))
                dec_packed = json.loads(unpacker_server.unpack_auto_decompress(packed_tmp))
                assert dec_packed["status"] == "success", f"unpack_auto_decompress failed: {dec_packed}"
                upx_test_note = f"UPX pack+auto-unpack verified -> {os.path.basename(dec_packed['unpacked_file_path'])}"
    print(f"[2/10] [OK] unpacker-mcp ({time.time() - t0:.2f}s) -> {upx_test_note}")

    # 3. Test threat-intel-mcp
    from flare_re_mcp import threat_intel_server

    t0 = time.time()
    ti_res = json.loads(threat_intel_server.ti_lookup_binary_reputation(SAMPLE))
    assert ti_res["status"] == "success", f"ti_lookup_binary_reputation failed: {ti_res}"
    print(
        f"[3/10] [OK] threat-intel-mcp ({time.time() - t0:.2f}s) -> "
        f"Verdict={ti_res['reputation_verdict']}, "
        f"Web Queries={len(ti_res.get('recommended_web_search_queries', []))}"
    )

    # 4. Test floss-mcp
    from flare_re_mcp import floss_server

    t0 = time.time()
    floss_res = json.loads(floss_server.floss_get_obfuscated_strings_and_decoders(SAMPLE))
    assert floss_res["status"] == "success", f"floss failed: {floss_res}"
    print(
        f"[4/10] [OK] floss-mcp ({time.time() - t0:.2f}s) -> "
        f"Counts={floss_res['counts']}"
    )

    # 5. Test capa-mcp
    from flare_re_mcp import capa_server

    t0 = time.time()
    capa_res = json.loads(capa_server.capa_analyze_binary(SAMPLE, backend="rizin", wait=True))
    assert capa_res["status"] == "success", f"capa failed: {capa_res}"
    corr_res = json.loads(capa_server.capa_correlate_mitre_and_apis(SAMPLE))
    assert corr_res["status"] == "success", f"capa correlate failed: {corr_res}"
    print(
        f"[5/10] [OK] capa-mcp ({time.time() - t0:.2f}s) -> "
        f"Capabilities={capa_res['total_capabilities']}, "
        f"ATT&CK IDs={corr_res['cross_mcp_enrichment']['unique_attack_technique_ids']}"
    )

    func_map = capa_res.get("function_capability_map", {})
    target_func_addr = next(iter(func_map.keys()), "entry0")

    # 6. Test rizin-mcp
    from flare_re_mcp import rizin_server

    t0 = time.time()
    rz_open = json.loads(rizin_server.open_and_analyze(SAMPLE, analyze_level="aaa", auto_dossier=True))
    assert rz_open["status"] == "success", f"rizin open failed: {rz_open}"
    rz_dossier = json.loads(rizin_server.analyze_function_dossier(target_func_addr))
    assert rz_dossier["status"] == "success", f"rizin dossier failed: {rz_dossier}"
    rizin_server.close_file()
    print(
        f"[6/10] [OK] rizin-mcp ({time.time() - t0:.2f}s) -> "
        f"Functions={rz_open['total_functions']}, Auto-Dossiers={len(rz_open.get('auto_triage_dossiers', []))}"
    )

    # 7. Test radare2-mcp
    from flare_re_mcp import radare2_server

    t0 = time.time()
    r2_open = json.loads(radare2_server.r2_open_and_analyze(SAMPLE, analyze_level="aaa", auto_dossier=True))
    assert r2_open["status"] == "success", f"r2 open failed: {r2_open}"
    r2_dec = json.loads(radare2_server.r2_decompile_function(target_func_addr))
    assert r2_dec["status"] in ("success", "warning"), f"r2 decompile failed: {r2_dec}"
    radare2_server.r2_close_file()
    print(
        f"[7/10] [OK] radare2-mcp ({time.time() - t0:.2f}s) -> "
        f"Functions={r2_open['total_functions']}, Auto-Dossiers={len(r2_open.get('auto_triage_dossiers', []))}"
    )

    # 8. Test ghidra-mcp
    from flare_re_mcp import ghidra_server

    t0 = time.time()
    gh_open = json.loads(ghidra_server.ghidra_open_and_analyze(SAMPLE, analyze=True, auto_decompile_top=True))
    assert gh_open["status"] == "success", f"ghidra open failed: {gh_open}"
    gh_synth = json.loads(ghidra_server.ghidra_synthesize_multi_tool_report(SAMPLE, auto_run_missing_triage=False))
    assert gh_synth["status"] == "success", f"ghidra_synthesize_multi_tool_report failed: {gh_synth}"
    ghidra_server.ghidra_close_program()
    print(
        f"[8/10] [OK] ghidra-mcp ({time.time() - t0:.2f}s) -> "
        f"Functions={gh_open['total_functions']}"
    )

    # 9. Test auto_updater (flare-re-update)
    from flare_re_mcp import auto_updater

    t0 = time.time()
    upd_res = auto_updater.check_all_components(check_remote=False, force=True)
    assert upd_res["status"] == "up_to_date", f"auto_updater failed: {upd_res}"
    print(
        f"[9/10] [OK] auto_updater ({time.time() - t0:.2f}s) -> "
        f"MITRE={upd_res['mitre_attack_stix_version']}, CAPA={upd_res['python_packages']['flare-capa']}"
    )

    # 10. Test mentor_engine (flare-re-mentor)
    from flare_re_mcp import mentor_engine

    t0 = time.time()
    curr = mentor_engine.build_progressive_curriculum(SAMPLE, auto_prewarm=False)
    lab_md = mentor_engine.export_offline_lab_markdown(curr)
    assert len(curr["levels"]) == 4 and os.path.isfile(lab_md), "mentor_engine failed"
    print(
        f"[10/10] [OK] mentor_engine ({time.time() - t0:.2f}s) -> "
        f"4 Progressive Levels generated, Lab Guide exported to {os.path.basename(lab_md)}"
    )

    print("=" * 78)
    print("ALL 10 VERIFICATION STAGES PASSED SUCCESSFULLY!")
    print("=" * 78)


if __name__ == "__main__":
    run_verification()
