---
name: flare-static-analysis
description: >-
  Guided multi-tool static binary and malware analysis workflow on FlareVM.
  Activates when analyzing PE/ELF/shellcode binaries by dynamically crossing
  Detect It Easy (die-mcp), Mandiant FLOSS (floss-mcp), Mandiant CAPA (capa-mcp),
  Rizin/RzGhidra (rizin-mcp), radare2/r2ghidra (radare2-mcp), Ghidra/PyGhidra (ghidra-mcp),
  MITRE ATT&CK (mitre-attack), and Microsoft Learn Win32/NTAPI Docs (ms-learn).
---

# FlareVM Multi-Tool Static Analysis Workflow

Use this skill whenever the user asks to analyze, triage, reverse engineer, or inspect a binary/malware sample on FlareVM.

## 1. Fast Triage & Packing Assessment (`die-mcp` + `floss-mcp`)
1. **Detect It Easy & PE Triage (`die-mcp`)**:
   - Call `die_scan_binary(file_path)` to identify file format, compiler, linker, protector/packer, Imphash, compile timestamp, section entropies, RWX anomalies, TLS callbacks, overlay, and suspicious Win32 APIs.
   - Call `die_inspect_resources(file_path)` on PE binaries to check `.rsrc` entries for magic-byte mismatches (e.g., embedded MZ/PE executables disguised inside `RT_ICON` or `RT_RCDATA`). If found, extract with `die_extract_resource(..., save_to_disk=True)` and analyze the extracted payload recursively.
2. **Obfuscated Strings & Candidate Decoders (`floss-mcp`)**:
   - Call `floss_get_obfuscated_strings_and_decoders(file_path)` (or `floss_extract_strings`) to recover `decoded_strings`, `stack_strings`, `tight_strings`, extracted IOCs (URLs, IPs, Registry keys, file paths, commands), and the hex addresses of the highest-scoring candidate decoding functions (`top_decoding_function_candidates`).

## 2. Behavioral Capability Mapping (`capa-mcp`)
1. Call `capa_analyze_binary(file_path, backend="vivisect" | "rizin" | "ghidra")` to map binary capabilities to **MITRE ATT&CK** tactics/techniques and **MBC (Malware Behavior Catalog)** objectives.
2. Use `capa_inspect_rule_matches(file_path, rule_filter=...)` to obtain the exact function addresses (`matched_addresses`), instruction addresses, and matched API/string features for high-risk capabilities.

## 3. Cross-Tool Disassembly & Decompilation (`rizin-mcp`, `radare2-mcp`, `ghidra-mcp`)
Cross-verify the candidate function addresses surfaced by **CAPA** (`function_capability_map`) and **FLOSS** (`top_decoding_function_candidates`):
1. **Fast Interactive Decompilation & Dossiers (`rizin-mcp` & `radare2-mcp`)**:
   - In `rizin-mcp`: Call `open_and_analyze(file_path)` followed by `analyze_function_dossier(address_or_name)` or `decompile_function(address_or_name)` (uses `rz-ghidra` `pdg`) and `find_import_callers(import_name)`.
   - In `radare2-mcp`: Call `r2_open_and_analyze(file_path)` followed by `r2_decompile_function(address_or_name)` (uses `r2ghidra` `pdg` with `bin.relocs.apply=true`), `r2_get_xrefs`, and `r2_get_call_graph`.
2. **Deep Type-Recovered Decompilation & Synthesis (`ghidra-mcp`)**:
   - Call `ghidra_annotate_with_capa(file_path, decompile_top_n_functions=5)` to map CAPA rules directly onto Ghidra's `FunctionManager` and batch-decompile the top behavioral functions via `DecompInterface`.
   - Call `ghidra_synthesize_multi_tool_report(file_path)` to fuse all cached snapshots (`die`, `floss`, `capa`, `rizin`, `radare2`, `ghidra`, and the REA Evidence Ledger) into a single correlated dossier.

## 4. Threat Intelligence & API Grounding (`mitre-attack` + `ms-learn`)
Never stop at raw tool output — enrich findings using the system's knowledge MCP servers:
1. **`mitre-attack` MCP Server**:
   - For every MITRE ATT&CK technique ID returned in `recommended_mitre_attack_mcp_calls` (e.g., `T1055`, `T1134`, `T1027`):
     - Call `get_technique_by_id(technique_id=...)`
     - Call `get_procedure_examples_by_technique(technique_id=...)` or `get_groups_using_technique(technique_id=...)` to correlate threat actor/malware procedures
     - Call `get_mitigations_mitigating_technique(technique_id=...)` and `get_datacomponents_detecting_technique(technique_id=...)` for defensive detection & response engineering.
2. **`ms-learn` MCP Server**:
   - For suspicious or undocumented Windows APIs/structures surfaced in `recommended_ms_learn_mcp_calls` (e.g., `VirtualAllocEx`, `WriteProcessMemory`, `AdjustTokenPrivileges`, `NtQueryInformationProcess`):
     - Call `microsoft_docs_search(query=...)` and `microsoft_docs_fetch(url=...)` to verify exact parameter flags, return codes, and security implications from official Microsoft documentation.

## 5. REA Evidence Discipline
Maintain strict separation between:
- **Verified Observations**: Concrete facts backed by tool output and addresses (`0x...`).
- **Inferences**: Analytical conclusions linking multiple observations (e.g., "Function `0x140001200` decodes a C2 URL via XOR and passes it to `WinHttpOpen`").
- **Residual Unknowns**: Unresolved questions (e.g., indirect jumps, packed overlays, external config files), recorded via `record_investigation_evidence`.

## 6. Orquestração DevSecOps, Fila Paralela e Quality Gate (`secops-orchestrator`)
Para máxima velocidade (2x–4x mais rápido) e garantia de 100% de integridade:
1. **Pré-Aquecimento Paralelo (`orchestrator_qa.py --prewarm`)**:
   - Execute `python -m flare_re_mcp.orchestrator_qa "<file_path>" --prewarm` para disparar `die-mcp`, `floss-mcp`, `capa-mcp` (com cache `.pkl`), `rizin-mcp` (`auto_dossier=True`) e `radare2-mcp` (`auto_dossier=True`) simultaneamente em `ThreadPoolExecutor` (~4–6s).
2. **Despacho Paralelo de Sub-Agentes (`invoke_subagent`)**:
   - Utilize `secops-orchestrator` coordenando `triage-capa-worker`, `re-disasm-worker` e `ghidra-intel-worker` em paralelo (ver [secops-orchestrator/SKILL.md](file:///C:/Users/keyokemona/agy_dir/.agents/skills/secops-orchestrator/SKILL.md)).
3. **Auditoria de 8 Estágios, Sintaxe Mermaid e Arquivamento em `./reports/`**:
   - Nos diagramas ```` ```mermaid ````, jamais utilize `\"` dentro de rótulos `["..."]` (substitua por `#quot;`, ex.: `Del /f /q #quot;%s#quot;`), evite *non-breaking spaces* (`\u00A0`) no recuo e mantenha cada transição `-->` em uma linha separada.
   - Exporte o relatório final em `./reports/<YYYY-MM-DD_HH-MM-SS>_<nome_do_arquivo>_<sha256[:12]>.md` e valide todos os 8 estágios com `python -m flare_re_mcp.orchestrator_qa "<file_path>"`.


