"""radare2 & r2ghidra Static Analysis MCP Server (`radare2-mcp`).
Combines radareorg/radare2-mcp tool design with kd992102/rizin-mcp session management,
pre-configured for FlareVM (`C:\\Tools\\radare2\\radare2-6.2.4-w64\\bin` + `core_r2ghidra.dll` + `r2ghidra_sleigh`).
"""

import json
import os
import re
import time
from typing import Any, Dict, List, Optional

from mcp.server import MCPServer
import r2pipe

from flare_re_mcp.common import (
    R2_BIN,
    R2_SLEIGH_DIR,
    classify_imports_for_mcp_enrichment,
    log_info,
    resolve_binary_path,
    sanitize_symbol_or_address,
    save_tool_snapshot,
    suppress_stderr,
)

SERVER_TAG = "radare2-mcp"
server = MCPServer("radare2-analyzer")

CURRENT_R2: Optional[Any] = None
CURRENT_FILE_PATH: Optional[str] = None


def _parse_r2_numeric(raw: str) -> Optional[int]:
    if raw is None:
        return None
    val = raw.strip().splitlines()[0].strip() if raw.strip() else ""
    if not val:
        return None
    try:
        return int(val, 16) if val.lower().startswith("0x") else int(val, 0)
    except ValueError:
        return None


def _resolve_r2_target(r2, target: str) -> int:
    safe_target = sanitize_symbol_or_address(target)
    resolved: Optional[int] = None

    try:
        eval_raw = r2.cmd(f"?v {safe_target}")
        cand = _parse_r2_numeric(eval_raw)
        if cand:
            resolved = cand
    except Exception:
        pass

    if resolved is None:
        try:
            imports = json.loads(r2.cmd("iij") or "[]")
        except Exception:
            imports = []
        t_low = safe_target.lower()
        for imp in imports:
            name = str(imp.get("name", ""))
            if not name:
                continue
            cands = {name.lower()}
            if "_" in name:
                cands.add(name.split("_")[-1].lower())
            if "." in name:
                cands.add(name.split(".")[-1].lower())
            if t_low in cands:
                addr = imp.get("plt") or imp.get("vaddr")
                if addr:
                    resolved = addr
                    break

    if resolved is None:
        raise ValueError(f"Symbol/address not found in radare2: '{target}'")

    r2.cmd(f"s {hex(resolved)}")
    return resolved


@server.tool(
    name="r2_open_and_analyze",
    description=(
        "Open and analyze a binary file using radare2 (`r2pipe`) with `bin.relocs.apply=true` "
        "and the `r2ghidra` native decompiler pre-configured. When auto_dossier=True (default), "
        "automatically decompiles priority functions (main/entry0/non-thunk user functions) in one turn."
    ),
)
def r2_open_and_analyze(file_path: str, analyze_level: str = "aaa", auto_dossier: bool = True) -> str:
    global CURRENT_R2, CURRENT_FILE_PATH
    try:
        safe_path = resolve_binary_path(file_path)
        if CURRENT_R2 is not None:
            try:
                CURRENT_R2.quit()
            except Exception:
                pass
            CURRENT_R2 = None
            CURRENT_FILE_PATH = None

        t0 = time.time()
        level = analyze_level if analyze_level in ["a", "aa", "aaa", "aaaa"] else "aaa"

        auto_dossiers = []
        with suppress_stderr():
            r2 = r2pipe.open(safe_path, flags=["-2", "-e", "bin.relocs.apply=true", "-e", "bin.cache=true"], radare2home=os.path.dirname(R2_BIN))
            if os.path.isdir(R2_SLEIGH_DIR):
                r2.cmd(f"e r2ghidra.sleighhome={R2_SLEIGH_DIR}")
            r2.cmd("e scr.color=0")
            r2.cmd(level)

            info = json.loads(r2.cmd("iIj") or "{}")
            funcs = json.loads(r2.cmd("aflj") or "[]")
            imports = json.loads(r2.cmd("iij") or "[]")
            entrypoints = json.loads(r2.cmd("iej") or "[]")

            if auto_dossier and funcs:
                priority = []
                for f in funcs:
                    fname = str(f.get("name", ""))
                    fsize = int(f.get("size") or f.get("realsz") or 0)
                    if fname in ("main", "sym._main", "entry0") or (
                        fname.startswith("fcn.") and fsize >= 24
                    ):
                        priority.append(f)
                for f in priority[:6]:
                    off = f.get("addr") if f.get("addr") is not None else f.get("offset")
                    if off is None:
                        continue
                    r2.cmd(f"s {hex(off)}")
                    c_code = (r2.cmd("pdg") or "").strip()
                    asm_code = (r2.cmd("pdf") or "").strip()
                    auto_dossiers.append({
                        "name": f.get("name"),
                        "address": hex(off),
                        "size": f.get("size") or f.get("realsz"),
                        "r2ghidra_decompiled_c": c_code,
                        "disassembly": asm_code[:4000],
                    })

        t1 = time.time()
        CURRENT_R2 = r2
        CURRENT_FILE_PATH = safe_path

        imp_names = [imp.get("name", "") for imp in imports if imp.get("name")]
        enrichment = classify_imports_for_mcp_enrichment(imp_names)

        payload = {
            "status": "success",
            "tool": "radare2 + r2ghidra",
            "file_path": safe_path,
            "analysis_seconds": round(t1 - t0, 2),
            "architecture": info.get("arch"),
            "format": info.get("bintype"),
            "bits": info.get("bits"),
            "endian": info.get("endian"),
            "entrypoints": entrypoints,
            "total_functions": len(funcs),
            "total_imports": len(imports),
            "win32_api_and_mitre_enrichment": enrichment,
            "auto_triage_dossiers": auto_dossiers,
        }
        save_tool_snapshot(safe_path, "radare2", payload)
        return json.dumps(payload, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)}, ensure_ascii=False)


@server.tool(
    name="r2_decompile_function",
    description="Decompile a function or address into C pseudocode using `r2ghidra` (`pdg`) inside radare2.",
)
def r2_decompile_function(address_or_name: str) -> str:
    if CURRENT_R2 is None:
        return json.dumps({"status": "error", "message": "Call r2_open_and_analyze first."})
    try:
        safe_target = sanitize_symbol_or_address(address_or_name)
        with suppress_stderr():
            CURRENT_R2.cmd(f"s {safe_target}")
            CURRENT_R2.cmd("af")
            c_code = CURRENT_R2.cmd("pdg")
        return json.dumps({
            "status": "success" if (c_code and c_code.strip()) else "warning",
            "target": address_or_name,
            "decompiler": "r2ghidra (pdg)",
            "code": c_code or "",
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="r2_disassemble_function",
    description="Disassemble a function or address (`pdf`) in radare2.",
)
def r2_disassemble_function(address_or_name: str) -> str:
    if CURRENT_R2 is None:
        return json.dumps({"status": "error", "message": "Call r2_open_and_analyze first."})
    try:
        safe_target = sanitize_symbol_or_address(address_or_name)
        with suppress_stderr():
            CURRENT_R2.cmd(f"s {safe_target}")
            asm = CURRENT_R2.cmd("pdf")
        return json.dumps({"status": "success", "target": address_or_name, "disassembly": asm}, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="r2_list_functions",
    description="List functions (`aflj`) in radare2, optionally filtered by keyword or address.",
)
def r2_list_functions(filter_keyword: str = "", limit: int = 200) -> str:
    if CURRENT_R2 is None:
        return json.dumps({"status": "error", "message": "Call r2_open_and_analyze first."})
    try:
        with suppress_stderr():
            funcs = json.loads(CURRENT_R2.cmd("aflj") or "[]")
        q = filter_keyword.lower().strip()
        out = []
        for f in funcs:
            name = f.get("name", "")
            addr = hex(f.get("offset", 0))
            if not q or q in name.lower() or q in addr.lower():
                out.append({
                    "name": name,
                    "address": addr,
                    "size": f.get("size", 0),
                    "cc": f.get("cc", 0),
                    "nbbs": f.get("nbbs", 0),
                    "nargs": f.get("nargs", 0),
                })
        return json.dumps({
            "status": "success",
            "total_matched": len(out),
            "functions": out[: max(1, int(limit))],
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="r2_list_imports_and_exports",
    description="List imports (`iij`), exports (`iEj`), and sections (`iSj`) in radare2 with keyword filter.",
)
def r2_list_imports_and_exports(query: str = "") -> str:
    if CURRENT_R2 is None:
        return json.dumps({"status": "error", "message": "Call r2_open_and_analyze first."})
    try:
        with suppress_stderr():
            imports = json.loads(CURRENT_R2.cmd("iij") or "[]")
            exports = json.loads(CURRENT_R2.cmd("iEj") or "[]")
            sections = json.loads(CURRENT_R2.cmd("iSj") or "[]")
        q = query.lower().strip()
        filt_imp = [i for i in imports if not q or q in str(i.get("name", "")).lower() or q in str(i.get("libname", "")).lower()]
        filt_exp = [e for e in exports if not q or q in str(e.get("name", "")).lower()]
        return json.dumps({
            "status": "success",
            "imports_count": len(filt_imp),
            "imports": filt_imp[:200],
            "exports_count": len(filt_exp),
            "exports": filt_exp[:100],
            "sections": sections,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="r2_get_xrefs",
    description="Get cross-references (`axtj` callers / `axfj` callees) for a target symbol or address in radare2.",
)
def r2_get_xrefs(address_or_name: str, limit: int = 100) -> str:
    if CURRENT_R2 is None:
        return json.dumps({"status": "error", "message": "Call r2_open_and_analyze first."})
    try:
        with suppress_stderr():
            target_addr = _resolve_r2_target(CURRENT_R2, address_or_name)
            to_refs = json.loads(CURRENT_R2.cmd(f"axtj @ {target_addr}") or "[]")
            from_refs = json.loads(CURRENT_R2.cmd(f"axfj @ {target_addr}") or "[]")
        return json.dumps({
            "status": "success",
            "target": address_or_name,
            "resolved_address": hex(target_addr),
            "xrefs_to_target": to_refs[: max(1, int(limit))],
            "xrefs_from_target": from_refs[: max(1, int(limit))],
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="r2_get_call_graph",
    description="Get the function call-graph (`agcj`) in radare2, optionally scoped to a specific function.",
)
def r2_get_call_graph(address_or_name: str = "") -> str:
    if CURRENT_R2 is None:
        return json.dumps({"status": "error", "message": "Call r2_open_and_analyze first."})
    try:
        with suppress_stderr():
            if address_or_name:
                target_addr = _resolve_r2_target(CURRENT_R2, address_or_name)
                cg = json.loads(CURRENT_R2.cmd(f"agcj @ {target_addr}") or "[]")
            else:
                cg = json.loads(CURRENT_R2.cmd("agcj") or "[]")
        return json.dumps({
            "status": "success",
            "target": address_or_name or "GLOBAL",
            "call_graph": cg[:200],
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="r2_calculate",
    description="[Inspired by radare2-mcp] Evaluate a 64-bit math, hex, or symbol expression using radare2's `?v` evaluator.",
)
def r2_calculate(expression: str) -> str:
    if CURRENT_R2 is None:
        return json.dumps({"status": "error", "message": "Call r2_open_and_analyze first."})
    if any(c in expression for c in (";", "\n", "!", "`")):
        return json.dumps({"status": "error", "message": "Disallowed characters in expression."})
    try:
        with suppress_stderr():
            hex_val = (CURRENT_R2.cmd(f"?v {expression}") or "").strip()
        num = _parse_r2_numeric(hex_val)
        return json.dumps({
            "status": "success",
            "expression": expression,
            "hex": hex(num) if num is not None else hex_val,
            "decimal": num,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def _r2_denial_reason(command: str) -> Optional[str]:
    for sub in re.split(r"[;\n]+", command or ""):
        sub = sub.strip()
        if not sub:
            continue
        if sub.startswith("!"):
            return f"Shell-escape blocked: '{sub}'"
        head_match = re.match(r"^([A-Za-z][A-Za-z0-9+]*)", sub)
        head = head_match.group(1) if head_match else ""
        if head and head[0] in ("w", "o"):
            return f"Write/open command blocked in read-only mode: '{sub}'"
    return None


@server.tool(
    name="r2_execute_command",
    description="[Read-only] Execute a custom radare2 command with pagination (`offset`, `limit`).",
)
def r2_execute_command(command: str, offset: int = 0, limit: int = 20000) -> str:
    if CURRENT_R2 is None:
        return json.dumps({"status": "error", "message": "Call r2_open_and_analyze first."})
    denial = _r2_denial_reason(command)
    if denial:
        return json.dumps({"status": "error", "message": denial})
    try:
        with suppress_stderr():
            out = CURRENT_R2.cmd(command) or ""
        offset = max(0, int(offset))
        limit = max(1, int(limit))
        chunk = out[offset : offset + limit]
        next_off = offset + len(chunk)
        trunc = next_off < len(out)
        return json.dumps({
            "status": "success",
            "command": command,
            "output": chunk,
            "total_length": len(out),
            "truncated": trunc,
            "next_offset": next_off if trunc else None,
        }, ensure_ascii=False, indent=2)
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@server.tool(
    name="r2_close_file",
    description="Close the active radare2 session.",
)
def r2_close_file() -> str:
    global CURRENT_R2, CURRENT_FILE_PATH
    if CURRENT_R2 is None:
        return json.dumps({"status": "info", "message": "No file open."})
    try:
        with suppress_stderr():
            CURRENT_R2.quit()
        CURRENT_R2 = None
        CURRENT_FILE_PATH = None
        return json.dumps({"status": "success", "message": "Closed radare2 session."})
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


def main():
    server.run()


if __name__ == "__main__":
    main()
