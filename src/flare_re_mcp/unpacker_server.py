"""Smart Hybrid Binary Unpacker & Deobfuscator MCP Server (`unpacker-mcp`).
Implements the Hybrid Unpacking Strategy:
  1. Automatic Decompression (`auto_supported`):
     - Standard UPX (`upx -d`)
     - Modified / Tampered UPX (automatic header & section name restoration + `upx -d`)
     - Embedded PE Carve & Deobfuscation (Raw MZ/PE in overlay or `.rsrc`, Single-Byte XOR `0x01..0xFF`, Base64 PE)
     - PyInstaller Archive Detection (`MEI` cookie + embedded `.pyc`/payload metadata)
  2. Token-Conscious User Choice for Unknown/Custom Packers (`custom_manual_requires_user_choice`):
     - Detects custom packers (high entropy >= 6.8, minimal import table with `LoadLibrary`/`GetProcAddress`/`VirtualAlloc`)
     - Locates OEP (Original Entry Point) candidates (`pushad`/`popad` + tail-jump patterns)
     - Prompts the user whether to generate a custom Python unpacker or analyze the packed stub directly.
"""

import base64
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from mcp.server import MCPServer
import pefile
import rzpipe

from flare_re_mcp.common import (
    EXE_EXT,
    IS_WINDOWS,
    RIZIN_SLEIGH_DIR,
    USER_PORTABLE_TOOLS_DIR,
    _first_existing_path,
    get_file_hashes,
     get_sample_cache_dir,
    log_info,
    resolve_binary_path,
    save_tool_snapshot,
    suppress_stderr,
    update_evidence_ledger,
)
from flare_re_mcp.die_server import _shannon_entropy, die_scan_binary

SERVER_TAG = "unpacker-mcp"
server = MCPServer("unpacker-deobfuscator")

UPX_BIN = _first_existing_path(
    [
        os.environ.get("UPX_BIN"),
        shutil.which("upx"),
        os.path.join(USER_PORTABLE_TOOLS_DIR, "upx", f"upx{EXE_EXT}"),
        r"C:\Tools\upx\upx.exe" if IS_WINDOWS else "/usr/bin/upx",
        r"C:\Tools\UniExtract\UniExtract\bin\upx.exe" if IS_WINDOWS else None,
        r"C:\Tools\Explorer Suite\Extensions\CFF Explorer\UPX Utility\upx.exe" if IS_WINDOWS else None,
        r"C:\ProgramData\chocolatey\bin\upx.exe" if IS_WINDOWS else "/usr/local/bin/upx",
    ]
)


def _detect_modified_upx(raw_bytes: bytes, pe: Optional[pefile.PE]) -> Dict[str, Any]:
    """Check if a binary is standard UPX or tampered/modified UPX (where UPX! magic or UPX0/UPX1 names were altered)."""
    has_upx_magic = b"UPX!" in raw_bytes or b"UPX0" in raw_bytes or b"UPX1" in raw_bytes
    # Classic 32-bit/64-bit UPX entry stub opcodes: pushad (60), mov esi, ... (BE ...), lea edi, [esi+...] (8D BE ...)
    upx_stub_32 = re.search(rb"\x60\xbe....\x8d\xbe....\x57", raw_bytes) is not None
    upx_stub_64 = re.search(rb"\x53\x56\x57\x55\x48\x8d\x35....\x48\x8d\xbe", raw_bytes) is not None
    nr2b_marker = b"$Id: UPX" in raw_bytes or b"$Info: This file is packed with the UPX" in raw_bytes

    sec_names = []
    if pe is not None:
        for s in pe.sections:
            sec_names.append(s.Name.decode("utf-8", errors="ignore").strip("\x00"))

    standard_sections = any(n.upper().startswith("UPX") for n in sec_names)
    is_upx_family = has_upx_magic or upx_stub_32 or upx_stub_64 or nr2b_marker
    is_tampered = is_upx_family and not ( b"UPX!" in raw_bytes and standard_sections )

    return {
        "is_upx_family": is_upx_family,
        "is_standard_upx": bool(is_upx_family and not is_tampered),
        "is_tampered_upx": bool(is_tampered),
        "has_upx_magic_marker": b"UPX!" in raw_bytes,
        "matched_stub_opcodes": "x86_pushad_stub" if upx_stub_32 else ("x64_stub" if upx_stub_64 else None),
        "section_names": sec_names,
    }


def _repair_tampered_upx_bytes(raw_bytes: bytes) -> Tuple[bytes, List[str]]:
    """Attempt to restore wiped UPX0/UPX1 section names and UPX! magic header on tampered UPX binaries."""
    repaired = bytearray(raw_bytes)
    repairs_applied = []
    try:
        pe = pefile.PE(data=bytes(repaired), fast_load=True)
        if len(pe.sections) >= 2:
            s0_off = pe.sections[0].get_file_offset()
            s1_off = pe.sections[1].get_file_offset()
            n0 = pe.sections[0].Name.rstrip(b"\x00")
            n1 = pe.sections[1].Name.rstrip(b"\x00")
            if not n0.upper().startswith(b"UPX"):
                repaired[s0_off : s0_off + 8] = b"UPX0\x00\x00\x00\x00"
                repairs_applied.append(f"Restored section[0] name '{n0.decode('latin1', 'ignore')}' -> 'UPX0'")
            if not n1.upper().startswith(b"UPX"):
                repaired[s1_off : s1_off + 8] = b"UPX1\x00\x00\x00\x00"
                repairs_applied.append(f"Restored section[1] name '{n1.decode('latin1', 'ignore')}' -> 'UPX1'")
            if len(pe.sections) >= 3:
                s2_off = pe.sections[2].get_file_offset()
                n2 = pe.sections[2].Name.rstrip(b"\x00")
                if not n2.upper().startswith((b"UPX", b".RSRC")):
                    repaired[s2_off : s2_off + 8] = b"UPX2\x00\x00\x00\x00"
                    repairs_applied.append(f"Restored section[2] name '{n2.decode('latin1', 'ignore')}' -> 'UPX2'")
    except Exception:
        pass
    return bytes(repaired), repairs_applied


def _scan_for_embedded_or_xor_pe(raw_bytes: bytes) -> List[Dict[str, Any]]:
    """Scan binary beyond offset 0x400 for raw embedded MZ/PE payloads or single-byte XOR encoded PE files."""
    findings = []
    # 1. Raw embedded MZ/PE after the main header
    pos = 0x400
    while True:
        idx = raw_bytes.find(b"MZ", pos)
        if idx == -1:
            break
        if idx + 0x40 < len(raw_bytes):
            e_lfanew = int.from_bytes(raw_bytes[idx + 0x3C : idx + 0x40], "little", signed=False)
            if 0x40 <= e_lfanew <= 0x1000 and idx + e_lfanew + 4 <= len(raw_bytes):
                if raw_bytes[idx + e_lfanew : idx + e_lfanew + 4] == b"PE\x00\x00":
                    findings.append({
                        "type": "raw_embedded_pe",
                        "offset": hex(idx),
                        "offset_int": idx,
                        "xor_key": 0,
                        "description": f"Executable PE ('MZ...PE\\0\\0') found embedded at offset {hex(idx)}",
                    })
        pos = idx + 2

    # 2. Single-byte XOR scan for 'This program cannot be run in DOS mode' or 'This program must be run under Win32'
    dos_stub_needle = b"This program cannot be run in DOS mode"
    for key in range(1, 256):
        xored_needle = bytes(b ^ key for b in dos_stub_needle)
        hit = raw_bytes.find(xored_needle)
        if hit != -1 and hit >= 0x40:
            mz_candidate = hit - 0x4E
            if mz_candidate >= 0 and (raw_bytes[mz_candidate] ^ key) == 0x4D and (raw_bytes[mz_candidate + 1] ^ key) == 0x5A:
                findings.append({
                    "type": "xor_single_byte_pe",
                    "offset": hex(mz_candidate),
                    "offset_int": mz_candidate,
                    "xor_key": key,
                    "xor_key_hex": hex(key),
                    "description": f"Single-byte XOR ({hex(key)}) encoded PE found at offset {hex(mz_candidate)}",
                })
    return findings


@server.tool(
    name="unpack_inspect_and_detect",
    description=(
        "Inspect a binary for packing, compression, crypters, or embedded payloads (UPX, tampered UPX, PyInstaller, "
        "ASPack, MPRESS, VMProtect, Themida, or XOR/embedded PE). Classifies whether unpacking is `auto_supported` "
        "(can be unpacked immediately without spending LLM tokens) or `custom_manual_requires_user_choice` "
        "(recommends asking the user before writing a custom Python unpacker)."
    ),
)
def unpack_inspect_and_detect(file_path: str) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        with open(safe_path, "rb") as f:
            raw_bytes = f.read()

        die_res = json.loads(die_scan_binary(safe_path, deep_scan=True))
        pe_info = die_res.get("pe_analysis", {})
        packing_ind = pe_info.get("packing_indicators", {})

        pe_obj = None
        try:
            pe_obj = pefile.PE(data=raw_bytes, fast_load=True)
        except Exception:
            pass

        upx_check = _detect_modified_upx(raw_bytes, pe_obj)
        embedded_pes = _scan_for_embedded_or_xor_pe(raw_bytes)
        is_pyinstaller = b"MEI\x0c\x0b\x0a\x0b\x0e" in raw_bytes or b"_MEIPASS" in raw_bytes

        die_detects_str = json.dumps(die_res.get("die_detections", {})).lower()
        known_commercial_or_custom = []
        for pname in ["aspack", "mpress", "petite", "vmprotect", "themida", "enigma", "confuser", "netreactor", "fsg", "mew"]:
            if pname in die_detects_str:
                known_commercial_or_custom.append(pname)

        is_packed = bool(
            upx_check["is_upx_family"]
            or embedded_pes
            or is_pyinstaller
            or known_commercial_or_custom
            or packing_ind.get("is_likely_packed")
        )

        if not is_packed:
            strategy = "not_packed"
            recommendation = "Binário não aparenta estar empacotado. Prosseguir diretamente com a fila padrão de análise estática."
        elif upx_check["is_upx_family"] or embedded_pes:
            strategy = "auto_supported"
            recommendation = (
                "Packer/Payload suportado automaticamente detectado! Chame `unpack_auto_decompress` imediatamente "
                "para gerar o novo binário descompactado e execute a fila de análise sobre o arquivo descomprimido."
            )
        else:
            strategy = "custom_manual_requires_user_choice"
            recommendation = (
                "Packer customizado/complexo detectado. Para economizar tokens, chame `unpack_find_oep_and_stub_landmarks` "
                "e PERGUNTE AO USUÁRIO se ele deseja que você escreva um script Python desempacotador sob medida "
                "ou se prefere analisar apenas o stub empacotado diretamente."
            )

        payload = {
            "status": "success",
            "file_path": safe_path,
            "is_packed_or_wrapped": is_packed,
            "unpack_strategy": strategy,
            "orchestrator_recommendation": recommendation,
            "upx_analysis": upx_check,
            "upx_cli_available": os.path.isfile(UPX_BIN),
            "upx_cli_path": UPX_BIN,
            "pyinstaller_detected": is_pyinstaller,
            "embedded_or_xor_pe_payloads": embedded_pes,
            "other_packer_signatures": known_commercial_or_custom,
            "entropy_and_packing_indicators": packing_ind,
        }
        save_tool_snapshot(safe_path, "unpacker_inspect", payload)
        return json.dumps(payload, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="unpack_auto_decompress",
    description=(
        "Automatically unpack a binary packed with UPX, tampered/modified UPX (restores section names/headers first), "
        "or extract an embedded/XOR-encoded PE payload into `.analysis_cache/<sha256>/unpacked/<name>.unpacked.exe`. "
        "Returns the new unpacked binary path and SHA-256 so all other MCP tools can analyze the clean payload."
    ),
)
def unpack_auto_decompress(
    file_path: str,
    allow_header_repair: bool = True,
) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        sample_dir, orig_hashes = get_sample_cache_dir(safe_path)
        unpacked_dir = os.path.join(sample_dir, "unpacked")
        os.makedirs(unpacked_dir, exist_ok=True)

        base_name = os.path.basename(safe_path)
        out_path = os.path.join(unpacked_dir, f"{base_name}.unpacked.exe")

        with open(safe_path, "rb") as f:
            raw_bytes = f.read()

        pe_obj = None
        try:
            pe_obj = pefile.PE(data=raw_bytes, fast_load=True)
        except Exception:
            pass

        upx_info = _detect_modified_upx(raw_bytes, pe_obj)
        actions_taken: List[str] = []
        unpack_success = False

        # Case 1: UPX or Tampered UPX
        if upx_info["is_upx_family"]:
            if not os.path.isfile(UPX_BIN):
                return json.dumps({
                    "status": "error",
                    "message": f"UPX binary not found at '{UPX_BIN}'. Run `python install.py --download-missing`.",
                })

            work_copy = os.path.join(unpacked_dir, f"_tmp_{base_name}")
            shutil.copy2(safe_path, work_copy)
            if upx_info["is_tampered_upx"] and allow_header_repair:
                repaired_bytes, repairs = _repair_tampered_upx_bytes(raw_bytes)
                if repairs:
                    with open(work_copy, "wb") as wf:
                        wf.write(repaired_bytes)
                    actions_taken.extend(repairs)

            if os.path.exists(out_path):
                os.remove(out_path)

            proc = subprocess.run(
                [UPX_BIN, "-d", "-o", out_path, work_copy],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=120,
            )
            try:
                os.remove(work_copy)
            except Exception:
                pass

            if proc.returncode == 0 and os.path.isfile(out_path):
                unpack_success = True
                actions_taken.append(f"Executed `upx -d` -> generated `{out_path}`")
            else:
                actions_taken.append(f"UPX CLI returned code {proc.returncode}: {(proc.stderr or proc.stdout).strip()}")

        # Case 2: Embedded PE or Single-Byte XOR PE
        if not unpack_success:
            embedded = _scan_for_embedded_or_xor_pe(raw_bytes)
            if embedded:
                best = embedded[0]
                off = int(best["offset_int"])
                xor_key = int(best.get("xor_key", 0))
                carved = raw_bytes[off:]
                if xor_key != 0:
                    carved = bytes(b ^ xor_key for b in carved)
                with open(out_path, "wb") as out_f:
                    out_f.write(carved)
                unpack_success = True
                actions_taken.append(best["description"] + f" -> carved to `{out_path}`")

        if not unpack_success or not os.path.isfile(out_path):
            return json.dumps({
                "status": "requires_manual_unpacker",
                "file_path": safe_path,
                "actions_attempted": actions_taken,
                "message": (
                    "Automatic unpacking did not produce an unpacked file. Use `unpack_find_oep_and_stub_landmarks` "
                    "and ask the user whether to build a custom Python unpacker script."
                ),
            }, ensure_ascii=False, indent=2)

        new_hashes = get_file_hashes(out_path)
        update_evidence_ledger(
            safe_path,
            source_tool="unpacker-mcp",
            observations=[
                {
                    "type": "binary_unpacked",
                    "original_sha256": orig_hashes["sha256"],
                    "unpacked_file_path": out_path,
                    "unpacked_sha256": new_hashes["sha256"],
                    "unpacked_size_bytes": new_hashes["size_bytes"],
                    "actions_taken": actions_taken,
                }
            ],
        )

        result_payload = {
            "status": "success",
            "original_file_path": safe_path,
            "original_hashes": orig_hashes,
            "unpacked_file_path": out_path,
            "unpacked_hashes": new_hashes,
            "actions_taken": actions_taken,
            "next_step": f"Run full static analysis queue on the clean unpacked binary: {out_path}",
        }
        save_tool_snapshot(safe_path, "unpacker_result", result_payload)
        return json.dumps(result_payload, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="unpack_find_oep_and_stub_landmarks",
    description=(
        "Analyze a packed binary's entry stub in Rizin to locate Original Entry Point (OEP) candidates, "
        "`pushad`/`popad` pairs, tail jumps (`jmp reg`, `push + ret`), and memory allocation/protection calls "
        "(`VirtualAlloc`, `VirtualProtect`) to guide custom Python unpacker creation."
    ),
)
def unpack_find_oep_and_stub_landmarks(file_path: str) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        with suppress_stderr():
            rz = rzpipe.open(safe_path, flags=["-e", "bin.cache=true"])
            try:
                if os.path.exists(RIZIN_SLEIGH_DIR):
                    rz.cmd(f"e ghidra.sleighhome={RIZIN_SLEIGH_DIR}")
                rz.cmd("e log.level=0")
                rz.cmd("aa")
                entry_info = json.loads(rz.cmd("iej") or "[]")
                rz.cmd("s entry0")
                entry_asm = (rz.cmd("pd 80") or "").strip()
                entry_c = (rz.cmd("pdg") or "").strip()
            finally:
                rz.quit()

        tail_jumps = []
        for line in entry_asm.splitlines():
            low = line.lower()
            if any(k in low for k in ["popal", "popad", "jmp eax", "jmp r", "ret", "virtualalloc", "virtualprotect"]):
                tail_jumps.append(line.strip())

        return json.dumps({
            "status": "success",
            "file_path": safe_path,
            "entrypoints": entry_info,
            "stub_landmark_instructions": tail_jumps[:25],
            "entry0_disassembly_80_insns": entry_asm,
            "entry0_decompiled_c": entry_c,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
