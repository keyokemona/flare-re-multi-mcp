"""Detect It Easy (DIE) & PE Triage MCP Server (`die-mcp`).
Provides fast initial binary triage, compiler/packer/protector detection via `diec`,
PE section entropy & RWX anomaly detection, `.rsrc` magic-mismatch inspection,
and cross-enrichment recommendations for `mitre-attack` and `ms-learn` MCP servers.
"""

import base64
import datetime
import hashlib
import json
import math
import subprocess
from typing import Any, Dict, List, Optional

from mcp.server import MCPServer
import pefile

from flare_re_mcp.common import (
    DIEC_BIN,
    classify_imports_for_mcp_enrichment,
    get_file_hashes,
    load_tool_snapshot,
    log_info,
    resolve_binary_path,
    save_tool_snapshot,
    update_evidence_ledger,
)

SERVER_TAG = "die-mcp"
server = MCPServer("die-analyzer")

_MAGIC_SIGNATURES = [
    (b"MZ", "PE/EXE"),
    (b"\x7fELF", "ELF"),
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"BM", "BMP"),
    (b"PK\x03\x04", "ZIP"),
    (b"Rar!\x1a\x07", "RAR"),
    (b"7z\xbc\xaf'\x1c", "7Z"),
    (b"%PDF", "PDF"),
    (b"\x00\x00\x01\x00", "ICO"),
    (b"\x00\x00\x02\x00", "CUR"),
    (b"<?xml", "XML"),
    (b"\xef\xbb\xbf<?xml", "XML"),
]
_CODE_LIKE_RESOURCE_TYPES = {"RT_RCDATA", "RT_ANICURSOR", "RT_ANIICON", "RT_HTML", "RT_DLGINCLUDE"}


def _shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / length
            ent -= p * math.log2(p)
    return round(ent, 4)


def _detect_magic(data: bytes) -> str:
    for sig, name in _MAGIC_SIGNATURES:
        if data.startswith(sig):
            return name
    return "UNKNOWN"


def _resource_type_mismatch(type_name: str, detected_magic: str) -> Optional[str]:
    if detected_magic in ("PE/EXE", "ELF") and type_name not in _CODE_LIKE_RESOURCE_TYPES:
        return (
            f"Resource declared as '{type_name}' but content starts with {detected_magic} header - "
            "possible embedded/disguised executable payload (MITRE ATT&CK T1027.009)."
        )
    if type_name == "RT_BITMAP" and detected_magic not in ("BMP", "UNKNOWN"):
        return f"Resource declared as RT_BITMAP but content looks like {detected_magic}, not BMP."
    if type_name in ("RT_ICON", "RT_GROUP_ICON") and detected_magic in ("PE/EXE", "ELF", "ZIP", "RAR", "7Z", "PDF"):
        return f"Resource declared as '{type_name}' but content looks like {detected_magic}."
    return None


def _run_diec_json(safe_path: str, heuristic: bool = True, deep: bool = True) -> Dict[str, Any]:
    cmd = [DIEC_BIN, "-j"]
    if heuristic:
        cmd.append("--heuristicscan")
    if deep:
        cmd.append("--deepscan")
    cmd.append(safe_path)

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    raw = proc.stdout or ""
    # Strip any leading warning lines before JSON object
    brace_idx = raw.find("{")
    if brace_idx != -1:
        raw_json = raw[brace_idx:]
        try:
            return json.loads(raw_json)
        except Exception:
            pass
    return {"raw_output": raw.strip(), "stderr": (proc.stderr or "").strip()}


def _analyze_pe_details(safe_path: str) -> Dict[str, Any]:
    try:
        pe = pefile.PE(safe_path, fast_load=False)
    except Exception as e:
        return {"is_pe": False, "note": str(e)}

    try:
        imphash = pe.get_imphash()
    except Exception:
        imphash = None

    ts = getattr(pe.FILE_HEADER, "TimeDateStamp", 0)
    try:
        compile_time = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).isoformat()
    except Exception:
        compile_time = str(ts)

    sections_info = []
    packed_or_high_entropy_sections = []
    rwx_sections = []
    for sec in pe.sections:
        name = sec.Name.decode("utf-8", errors="replace").rstrip("\x00")
        raw_data = sec.get_data()
        entropy = _shannon_entropy(raw_data)
        chars = sec.Characteristics
        is_r = bool(chars & 0x40000000)
        is_w = bool(chars & 0x80000000)
        is_x = bool(chars & 0x20000000)
        perms = f"{'R' if is_r else '-'}{'W' if is_w else '-'}{'X' if is_x else '-'}"
        sec_entry = {
            "name": name,
            "virtual_address": hex(sec.VirtualAddress),
            "virtual_size": sec.Misc_VirtualSize,
            "raw_size": sec.SizeOfRawData,
            "entropy": entropy,
            "permissions": perms,
            "high_entropy": entropy >= 6.8,
            "is_rwx": is_r and is_w and is_x,
            "raw_zero_virtual_nonzero": sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0,
        }
        sections_info.append(sec_entry)
        if sec_entry["high_entropy"] or sec_entry["raw_zero_virtual_nonzero"]:
            packed_or_high_entropy_sections.append(name)
        if sec_entry["is_rwx"]:
            rwx_sections.append(name)

    imported_apis: List[str] = []
    imported_dlls: List[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode("utf-8", errors="replace") if entry.dll else ""
            if dll_name:
                imported_dlls.append(dll_name)
            for imp in entry.imports:
                if imp.name:
                    imported_apis.append(imp.name.decode("utf-8", errors="replace"))

    exports_list: List[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports_list.append(exp.name.decode("utf-8", errors="replace"))

    tls_callbacks: List[str] = []
    if hasattr(pe, "DIRECTORY_ENTRY_TLS") and pe.DIRECTORY_ENTRY_TLS:
        cb_rva = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        if cb_rva:
            tls_callbacks.append(hex(cb_rva))

    overlay_offset = pe.get_overlay_data_start_offset()
    overlay_size = 0
    overlay_entropy = 0.0
    if overlay_offset is not None:
        overlay_bytes = pe.get_overlay() or b""
        overlay_size = len(overlay_bytes)
        overlay_entropy = _shannon_entropy(overlay_bytes)

    pe.close()

    mcp_enrichment = classify_imports_for_mcp_enrichment(imported_apis)

    return {
        "is_pe": True,
        "machine": hex(pe.FILE_HEADER.Machine),
        "compile_timestamp_utc": compile_time,
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "entry_point_rva": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "entry_point_va": hex(pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "imphash": imphash,
        "imported_dlls": imported_dlls,
        "total_imports": len(imported_apis),
        "total_exports": len(exports_list),
        "exports_sample": exports_list[:30],
        "tls_callbacks": tls_callbacks,
        "overlay": {
            "present": overlay_offset is not None and overlay_size > 0,
            "offset": hex(overlay_offset) if overlay_offset is not None else None,
            "size": overlay_size,
            "entropy": overlay_entropy,
        },
        "sections": sections_info,
        "packing_indicators": {
            "likely_packed": bool(packed_or_high_entropy_sections or rwx_sections or len(imported_apis) < 5),
            "high_entropy_or_virtual_only_sections": packed_or_high_entropy_sections,
            "rwx_sections": rwx_sections,
            "very_few_imports": len(imported_apis) < 5,
        },
        "win32_api_and_mitre_enrichment": mcp_enrichment,
    }


@server.tool(
    name="die_scan_binary",
    description=(
        "Run Detect It Easy (diec) with heuristic and deep scan plus comprehensive PE/ELF header, "
        "section entropy, RWX permission, TLS callback, overlay, and suspicious Win32 API triage. "
        "Results are cached by SHA-256 and automatically populate the shared REA Evidence Ledger "
        "plus recommended queries for the `mitre-attack` and `ms-learn` MCP servers."
    ),
)
def die_scan_binary(
    file_path: str,
    heuristic_scan: bool = True,
    deep_scan: bool = True,
    force_rescan: bool = False,
) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        if not force_rescan:
            cached = load_tool_snapshot(safe_path, "die")
            if cached:
                return json.dumps(cached, ensure_ascii=False, indent=2)

        log_info(SERVER_TAG, f"Scanning {safe_path} with Detect It Easy (diec)...")
        hashes = get_file_hashes(safe_path)
        with open(safe_path, "rb") as f:
            whole_entropy = _shannon_entropy(f.read())

        die_output = _run_diec_json(safe_path, heuristic=heuristic_scan, deep=deep_scan)
        pe_details = _analyze_pe_details(safe_path)

        # Build REA-style observations and residual unknowns
        observations = []
        unknowns = []
        detects = die_output.get("detects", [])
        for d in detects:
            ft = d.get("filetype")
            for val in d.get("values", []):
                observations.append({
                    "category": f"DIE_{val.get('type', 'Detection')}",
                    "filetype": ft,
                    "detail": val.get("string") or val.get("name"),
                })

        if pe_details.get("is_pe"):
            packing = pe_details.get("packing_indicators", {})
            if packing.get("likely_packed"):
                unknowns.append({
                    "issue": "Binary exhibits packing/obfuscation indicators (high entropy, RWX sections, or minimal import table).",
                    "sections": packing.get("high_entropy_or_virtual_only_sections"),
                    "rwx_sections": packing.get("rwx_sections"),
                    "recommended_next_step": "Run `floss_extract_strings` for stack/decoded strings and `capa_analyze_binary` to check for packer/anti-analysis rules.",
                })

        payload = {
            "status": "success",
            "cached": False,
            "tool": "Detect It Easy (diec) + PE Triage",
            "sample": {**hashes, "overall_entropy": whole_entropy},
            "die_detections": die_output,
            "pe_analysis": pe_details,
        }
        save_tool_snapshot(safe_path, "die", payload)
        update_evidence_ledger(safe_path, SERVER_TAG, observations=observations, residual_unknowns=unknowns)
        return json.dumps(payload, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


@server.tool(
    name="die_check_packing_and_entropy",
    description="Quickly inspect binary section entropies, RWX permissions, overlay data, and DIE packer signatures to determine if a sample is packed or obfuscated.",
)
def die_check_packing_and_entropy(file_path: str) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        cached = load_tool_snapshot(safe_path, "die")
        if not cached:
            raw = die_scan_binary(safe_path)
            cached = json.loads(raw)

        pe_info = cached.get("pe_analysis", {})
        return json.dumps({
            "status": "success",
            "sample": cached.get("sample"),
            "die_detections": cached.get("die_detections"),
            "packing_indicators": pe_info.get("packing_indicators"),
            "sections": pe_info.get("sections"),
            "overlay": pe_info.get("overlay"),
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False, indent=2)


def _iter_pe_resources(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return
    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if res_type.name is not None:
            type_name = str(res_type.name)
        else:
            type_id = res_type.struct.Id
            type_name = pefile.RESOURCE_TYPE.get(type_id, str(type_id))

        if not hasattr(res_type, "directory"):
            continue
        for res_id_entry in res_type.directory.entries:
            res_id = str(res_id_entry.name) if res_id_entry.name is not None else str(res_id_entry.struct.Id)
            if not hasattr(res_id_entry, "directory"):
                continue
            for res_lang_entry in res_id_entry.directory.entries:
                lang_id = getattr(res_lang_entry.data, "lang", None)
                data_rva = res_lang_entry.data.struct.OffsetToData
                size = res_lang_entry.data.struct.Size
                yield type_name, res_id, lang_id, data_rva, size


@server.tool(
    name="die_inspect_resources",
    description=(
        "Inspect all PE resource (.rsrc) entries, computing per-resource entropy, SHA-256, magic bytes, "
        "and flagging type-content mismatches (e.g. an embedded MZ/PE executable disguised inside RT_ICON/RT_BITMAP)."
    ),
)
def die_inspect_resources(file_path: str) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        pe = pefile.PE(safe_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Cannot parse PE resources: {e}"}, ensure_ascii=False)

    try:
        resources = []
        mismatches = []
        for type_name, res_id, lang_id, data_rva, size in _iter_pe_resources(pe):
            try:
                raw = pe.get_data(data_rva, size)
            except Exception:
                raw = b""
            magic = _detect_magic(raw)
            mismatch = _resource_type_mismatch(type_name, magic)
            entropy = _shannon_entropy(raw)
            entry = {
                "type": type_name,
                "id": res_id,
                "lang": lang_id,
                "size": size,
                "va": hex(pe.OPTIONAL_HEADER.ImageBase + data_rva),
                "rva": hex(data_rva),
                "entropy": entropy,
                "sha256": hashlib.sha256(raw).hexdigest() if raw else None,
                "preview_hex": raw[:32].hex(),
                "detected_magic": magic,
                "type_content_mismatch": mismatch is not None,
                "mismatch_note": mismatch,
            }
            resources.append(entry)
            if mismatch:
                mismatches.append(entry)

        if mismatches:
            update_evidence_ledger(
                safe_path,
                SERVER_TAG,
                observations=[
                    {
                        "category": "Disguised_PE_Resource",
                        "detail": m["mismatch_note"],
                        "resource_type": m["type"],
                        "resource_id": m["id"],
                        "va": m["va"],
                    }
                    for m in mismatches
                ],
            )

        return json.dumps({
            "status": "success",
            "file_path": safe_path,
            "resource_count": len(resources),
            "suspicious_mismatch_count": len(mismatches),
            "resources": resources,
        }, ensure_ascii=False, indent=2)
    finally:
        try:
            pe.close()
        except Exception:
            pass


@server.tool(
    name="die_extract_resource",
    description=(
        "Extract a specific PE resource by type and ID, returning base64 bytes, SHA-256, and optionally "
        "saving the extracted payload to disk so it can be analyzed by DIE, FLOSS, CAPA, Rizin, radare2, or Ghidra."
    ),
)
def die_extract_resource(
    file_path: str,
    res_type: str,
    res_id: str,
    save_to_disk: bool = False,
    max_base64_bytes: int = 65536,
) -> str:
    try:
        safe_path = resolve_binary_path(file_path)
        pe = pefile.PE(safe_path, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Cannot parse PE resources: {e}"}, ensure_ascii=False)

    try:
        for type_name, r_id, lang_id, data_rva, size in _iter_pe_resources(pe):
            if type_name != res_type or r_id != res_id:
                continue
            raw = pe.get_data(data_rva, size)
            sha256 = hashlib.sha256(raw).hexdigest()
            saved_path = None
            if save_to_disk:
                from flare_re_mcp.common import get_sample_cache_dir

                sample_dir, _ = get_sample_cache_dir(safe_path)
                saved_path = f"{sample_dir}\\extracted_rsrc_{type_name}_{r_id}_{sha256[:8]}.bin"
                with open(saved_path, "wb") as out_f:
                    out_f.write(raw)

            chunk = raw[: max(1, int(max_base64_bytes))]
            return json.dumps({
                "status": "success",
                "type": type_name,
                "id": r_id,
                "lang": lang_id,
                "total_size": len(raw),
                "sha256": sha256,
                "entropy": _shannon_entropy(raw),
                "detected_magic": _detect_magic(raw),
                "saved_file_path": saved_path,
                "truncated_base64": len(raw) > len(chunk),
                "data_base64": base64.b64encode(chunk).decode("ascii"),
            }, ensure_ascii=False, indent=2)

        return json.dumps({
            "status": "error",
            "message": f"Resource not found: type='{res_type}', id='{res_id}'",
        }, ensure_ascii=False)
    finally:
        try:
            pe.close()
        except Exception:
            pass


def main():
    server.run()


if __name__ == "__main__":
    main()
