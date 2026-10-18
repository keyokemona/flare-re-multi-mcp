"""Offline & Agentic Interactive Reverse Engineering Mentor (`flare-re-mentor`).
Designed for two scenarios:
  1. Inside Antigravity CLI (`agy`): Generates structured progressive hints (Levels 1 to 4) for the
     `static-analysis-mentor` skill so the AI guides the analyst Socratically without spoiling the final report.
  2. 100% Offline Terminal Mode (`flare-re-mentor <binary>`): Works without internet, without `agy`, and with
     ZERO LLM token consumption (ideal when weekly tokens are exhausted or in air-gapped forensic labs).
"""

import argparse
import datetime
import json
import os
import re
import sys
from typing import Any, Dict, List

from flare_re_mcp.common import (
    REPORTS_DIR,
     get_file_hashes,
    load_tool_snapshot,
    resolve_binary_path,
)
from flare_re_mcp.orchestrator_qa import prewarm_parallel_static_queue


def build_progressive_curriculum(file_path: str, auto_prewarm: bool = True) -> Dict[str, Any]:
    """Build a 4-level progressive hands-on reverse engineering curriculum tailored to the target binary
    without revealing spoilers upfront.
    """
    safe_path = resolve_binary_path(file_path)
    die_snap = load_tool_snapshot(safe_path, "die")
    floss_snap = load_tool_snapshot(safe_path, "floss")
    capa_snap = load_tool_snapshot(safe_path, "capa_rizin") or load_tool_snapshot(safe_path, "capa")
    rizin_snap = load_tool_snapshot(safe_path, "rizin")

    if auto_prewarm and not (die_snap and floss_snap and capa_snap and rizin_snap):
        prewarm_parallel_static_queue(safe_path, run_ghidra=False)
        die_snap = load_tool_snapshot(safe_path, "die") or {}
        floss_snap = load_tool_snapshot(safe_path, "floss") or {}
        capa_snap = load_tool_snapshot(safe_path, "capa_rizin") or load_tool_snapshot(safe_path, "capa") or {}
        rizin_snap = load_tool_snapshot(safe_path, "rizin") or {}

    hashes = get_file_hashes(safe_path)
    pe_info = (die_snap or {}).get("pe_analysis", {})
    sections = pe_info.get("sections", [])
    packing = pe_info.get("packing_indicators", {})
    susp_apis = pe_info.get("win32_api_and_mitre_enrichment", {}).get("suspicious_apis", [])

    iocs = (floss_snap or {}).get("ioc_and_api_enrichment", {}).get("iocs_by_category", {})
    stack_strs = (floss_snap or {}).get("stack_strings", [])
    decoded_strs = (floss_snap or {}).get("decoded_strings", [])

    caps = (capa_snap or {}).get("capabilities", [])
    func_map = (capa_snap or {}).get("function_capability_map", {})
    priority_addrs = sorted(func_map.keys())
    dossiers = (rizin_snap or {}).get("auto_triage_dossiers", [])
    main_addr = priority_addrs[0] if priority_addrs else (dossiers[0]["address"] if dossiers else "entry0")

    levels = [
        {
            "level": 1,
            "title": "Nível 1 — Triagem Estrutural, Compilador, Seções e Detecção de Packing",
            "objective": (
                "Identificar a arquitetura do binário, o compilador utilizado, o Imphash e avaliar se o executável "
                "está comprimido/ofuscado (packed) observando a entropia das seções PE."
            ),
            "terminal_commands_to_run_manually": [
                f'diec -j -d "{safe_path}"',
                f'rizin -q -c "iI; iS" "{safe_path}"',
            ],
            "guiding_questions": [
                f"1. O arquivo possui {len(sections)} seções PE. Alguma seção apresenta entropia acima de 6.8 ou permissão RWX?",
                "2. Qual é o subsistema (Console vs GUI), arquitetura (32-bit vs 64-bit) e compilador apontado pelo DIE?",
                "3. Há algum caminho de debug PDB (`RSDS`) visível nos diretórios de dados?",
            ],
            "progressive_hint": (
                f"Olhe para a entropia máxima ({round(max((s.get('entropy', 0.0) for s in sections), default=0.0), 4)}) e para a tabela de Importação: "
                f"foram detectadas {len(susp_apis)} APIs críticas já visíveis na IAT."
            ),
            "spoiler_solution": {
                "imphash": pe_info.get("imphash"),
                "is_likely_packed": packing.get("is_likely_packed"),
                "sections_summary": [
                    {"name": s.get("name"), "entropy": s.get("entropy"), "rwx": s.get("is_rwx")} for s in sections
                ],
            },
        },
        {
            "level": 2,
            "title": "Nível 2 — Extração de Strings (Estáticas, Stack & Decoded) e Caça a IOCs",
            "objective": (
                "Recuperar indicadores de comprometimento (URLs, IPs, caminhos de arquivo, comandos de shell) "
                "e identificar se o autor escondeu strings na pilha (stack strings) ou em rotinas XOR/RC4."
            ),
            "terminal_commands_to_run_manually": [
                f'floss "{safe_path}"',
                f'floss -j "{safe_path}" > floss_out.json',
            ],
            "guiding_questions": [
                f"1. O FLOSS encontrou {len(stack_strs)} stack string(s) e {len(decoded_strs)} decoded string(s). Quais categorias de IOCs ({', '.join(iocs.keys()) or 'nenhuma'}) aparecem nas strings UTF-16LE (wide)?",
                "2. Existe alguma URL de download de 2º estágio ou comando `cmd.exe` / `ping` embutido?",
                "3. O que o caminho do arquivo `.pdb` revela sobre a origem ou projeto do artefato?",
            ],
            "progressive_hint": (
                f"Preste atenção especial às strings UTF-16LE (Wide): há {len(iocs.get('url', []))} URL(s), "
                f"{len(iocs.get('windows_path', []))} caminho(s) do Windows e {len(iocs.get('command_shell', []))} comando(s) de shell."
            ),
            "spoiler_solution": {
                "iocs_by_category": iocs,
                "stack_strings": stack_strs[:10],
                "decoded_strings": decoded_strs[:10],
            },
        },
        {
            "level": 3,
            "title": "Nível 3 — Mapeamento Comportamental (CAPA) e Localização da Função Principal",
            "objective": (
                "Cruzar as capacidades comportamentais detectadas pelo Mandiant CAPA com os endereços virtuais "
                "das funções para descobrir exatamente qual função implementa a lógica maliciosa."
            ),
            "terminal_commands_to_run_manually": [
                f'capa -vv "{safe_path}"',
                f'rizin -q -c "aaa; afl" "{safe_path}"',
            ],
            "guiding_questions": [
                f"1. O CAPA detectou {len(caps)} capacidades comportamentais. Em qual endereço virtual (`0x...`) se concentram os matches principais?",
                f"2. Quais APIs da Win32 (`{', '.join(a['api'] for a in susp_apis[:6])}`) são chamadas dentro dessa função?",
            ],
            "progressive_hint": (
                f"Concentre sua inspeção no endereço `{main_addr}`. Use o comando `s {main_addr}; pdg; pdf` no Rizin ou Radare2!"
            ),
            "spoiler_solution": {
                "priority_function_addresses": priority_addrs,
                "matched_capabilities": [
                    {"rule": c.get("rule"), "addresses": c.get("matched_addresses")} for c in caps
                ],
            },
        },
        {
            "level": 4,
            "title": "Nível 4 — Decompilação C (`rz-ghidra` / `r2ghidra`), Fluxo de Decisão e Engenharia de Detecção (YARA)",
            "objective": (
                "Analisar o código C decompilado e os opcodes Assembly da função principal, compreender todos os ramos "
                "condicionais (`if/else`), traduzir as flags hexadecimais passadas às APIs da Microsoft e escrever uma regra YARA."
            ),
            "terminal_commands_to_run_manually": [
                f'rizin -q -c "aaa; s {main_addr}; pdg; pdf" "{safe_path}"',
                f'radare2 -2 -q -c "e bin.relocs.apply=true; aaa; s {main_addr}; pdg" "{safe_path}"',
            ],
            "guiding_questions": [
                f"1. Na função `{main_addr}`, qual valor de retorno define se o programa segue pelo caminho de sucesso (`== 0`) ou pelo caminho de falha (`!= 0`)?",
                "2. Quais constantes hexadecimais (flags `dwFlags` ou `dwCreationFlags`) são empilhadas (`push`) antes das chamadas de rede e criação de processo?",
                "3. Quais 3 strings + sequência de opcodes tornam uma regra YARA altamente resiliente para este binário?",
            ],
            "progressive_hint": (
                "Compare a saída do `pdg` no Rizin com o `pdg` no Radare2 em "
                f"`{main_addr}`: observe o teste `if (iVar1 != 0)` após o download e veja como o caminho de erro invoca `CreateProcessW` com `0x08000000` (`CREATE_NO_WINDOW`)."
            ),
            "spoiler_solution": {
                "decompiled_dossiers_preview": dossiers[:2],
            },
        },
    ]

    return {
        "status": "success",
        "mode": "Interactive Static Analysis Mentor & Offline Lab Generator",
        "sample": hashes,
        "levels": levels,
    }


def export_offline_lab_markdown(curriculum: Dict[str, Any]) -> str:
    """Export a self-contained, spoiler-free interactive Markdown workbook (with collapsible `<details>` hints
    and solutions) to `./reports/LAB_MENTOR_<filename>_<sha256[:12]>.md`.
    """
    sample = curriculum["sample"]
    ts = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", sample["file_name"])
    out_path = os.path.join(REPORTS_DIR, f"LAB_MENTOR_{ts}_{safe_name}_{sample['sha256'][:12]}.md")

    lines = [
        f"# 🎓 Laboratório Guiado de Análise Estática (Modo Mentor Offline) — `{sample['file_name']}`\n",
        "> **Objetivo deste Guia**: Permitir que você treine e conduza a análise estática completa passo a passo diretamente no seu terminal (sem depender de tokens de IA ou conexão com a internet). As dicas e o gabarito estão recolhidos em blocos expansíveis para não entregar spoilers antes da sua investigação.\n",
        f"- **Arquivo Alvo**: `{sample['file_path']}`",
        f"- **SHA-256**: `{sample['sha256']}`",
        f"- **Tamanho**: `{sample['size_bytes']}` bytes\n",
        "---\n",
    ]

    for lvl in curriculum["levels"]:
        lines.append(f"## {lvl['title']}\n")
        lines.append(f"**🎯 Objetivo**: {lvl['objective']}\n")
        lines.append("### 💻 Comandos para Executar no Seu Terminal\n```powershell")
        for cmd in lvl["terminal_commands_to_run_manually"]:
            lines.append(cmd)
        lines.append("```\n")
        lines.append("### 🧠 Perguntas de Investigação")
        for q in lvl["guiding_questions"]:
            lines.append(f"- {q}")
        lines.append("\n<details>\n<summary>💡 <b>Clique aqui para ver uma Pista (Sem Spoiler Total)</b></summary>\n")
        lines.append(f"\n> {lvl['progressive_hint']}\n")
        lines.append("</details>\n")
        lines.append("<details>\n<summary>✅ <b>Clique aqui para conferir o Gabarito Técnico deste Nível</b></summary>\n\n```json")
        lines.append(json.dumps(lvl["spoiler_solution"], ensure_ascii=False, indent=2))
        lines.append("```\n</details>\n\n---\n")

    content = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(content)
    return out_path


def run_interactive_cli_session(curriculum: Dict[str, Any]) -> None:
    sample = curriculum["sample"]
    print("=" * 78)
    print(f" 🎓 FLARE-RE-MENTOR (Modo 100% Offline & Zero-Tokens) — {sample['file_name']}")
    print(f" SHA-256: {sample['sha256']}")
    print("=" * 78)
    for lvl in curriculum["levels"]:
        print(f"\n>>> {lvl['title']}")
        print(f"Objetivo: {lvl['objective']}\n")
        print("Comandos sugeridos para você rodar em outro terminal:")
        for c in lvl["terminal_commands_to_run_manually"]:
            print(f"  $ {c}")
        print("\nPerguntas para responder:")
        for q in lvl["guiding_questions"]:
            print(f"  {q}")
        try:
            ans = input("\n[Enter = Ver Pista | 'g' = Ver Gabarito | 'q' = Sair]: ").strip().lower()
        except EOFError:
            break
        if ans == "q":
            break
        print(f"\n  [PISTA]: {lvl['progressive_hint']}")
        if ans == "g":
            print(f"  [GABARITO]: {json.dumps(lvl['spoiler_solution'], ensure_ascii=False, indent=2)}")


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Flare-RE-Mentor: Interactive & Offline Reverse Engineering Tutor")
    parser.add_argument("file_path", help="Path to the binary sample to study")
    parser.add_argument("--level", type=int, choices=[1, 2, 3, 4], help="Show only a specific progressive level (1-4)")
    parser.add_argument("--show-hint", action="store_true", help="Include the progressive hint for the selected level")
    parser.add_argument("--show-solution", action="store_true", help="Include the spoiler solution for the selected level")
    parser.add_argument("--export-lab-guide", action="store_true", help="Export a self-paced Markdown workbook with collapsible hints to ./reports/")
    parser.add_argument("--interactive", action="store_true", help="Launch interactive step-by-step terminal session")
    parser.add_argument("--json-hints", action="store_true", help="Output structured JSON curriculum for agentic mentor skill")
    args = parser.parse_args()

    curriculum = build_progressive_curriculum(args.file_path, auto_prewarm=True)

    if args.export_lab_guide:
        lab_path = export_offline_lab_markdown(curriculum)
        curriculum["exported_lab_guide_path"] = lab_path

    if args.interactive:
        run_interactive_cli_session(curriculum)
        return

    if args.level:
        lvl = curriculum["levels"][args.level - 1]
        out = {
            "level": lvl["level"],
            "title": lvl["title"],
            "objective": lvl["objective"],
            "terminal_commands_to_run_manually": lvl["terminal_commands_to_run_manually"],
            "guiding_questions": lvl["guiding_questions"],
        }
        if args.show_hint:
            out["progressive_hint"] = lvl["progressive_hint"]
        if args.show_solution:
            out["spoiler_solution"] = lvl["spoiler_solution"]
        if args.export_lab_guide:
            out["exported_lab_guide_path"] = curriculum.get("exported_lab_guide_path")
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return

    print(json.dumps(curriculum, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
