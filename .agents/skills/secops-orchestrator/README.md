# 🛡️ Skill `secops-orchestrator` — Orquestrador DevSecOps & SecOps de Sub-Agentes

Esta pasta contém a skill **[`SKILL.md`](./SKILL.md)** que define o comportamento do **Orquestrador Principal (`secops-orchestrator`)** — atuando como um Especialista Principal em Segurança da Informação, DevSecOps e Engenharia de Software.

---

## 🎯 Responsabilidades do Orquestrador

1. **Coordenação de Sub-Agentes Especializados (*Fan-Out / Fan-In*)**:
   - **`triage-capa-worker`**: Executa `die-mcp` + `floss-mcp` + `capa-mcp`.
   - **`re-disasm-worker`**: Executa `rizin-mcp` + `radare2-mcp` + atualização do `ledger.json`.
   - **`ghidra-intel-worker`**: Executa `ghidra-mcp` + `mitre-attack` + `ms-learn`.
2. **Aceleração por Pré-Aquecimento Paralelo (`--prewarm`)**:
   - Dispara os 5 servidores nativos mais rápidos em paralelo via `ThreadPoolExecutor` (`python -m flare_re_mcp.orchestrator_qa "<binario>" --prewarm`), concluindo toda a triagem e os dossiês `rz-ghidra` e `r2ghidra` em **~5 segundos** enquanto o Ghidra e os servidores de Threat Intel rodam em paralelo.
3. **Quality Gate Determinístico de 8 Estágios**:
   - Exige aprovação integral (`"overall_quality_gate": "PASSED"`) nos 8 estágios auditados por [`orchestrator_qa.py`](../../../src/flare_re_mcp/orchestrator_qa.py), incluindo compilação e validação de regras YARA com `yara-python`, camada do ATT&CK Navigator e arquivamento padronizado em [`reports/`](../../../reports/).

---

## 🛠️ Como Customizar os Sub-Agentes

Se desejar adicionar um 4º sub-agente especializado (ex.: `yara-sigma-detection-worker` focado exclusivamente em regras Sigma, YARA e Suricata), basta:
1. Adicionar sua especificação em [`SKILL.md`](./SKILL.md) para que seja registrado via `define_subagent`.
2. Incluir a verificação do novo artefato na função `audit_execution_queue()` em [`src/flare_re_mcp/orchestrator_qa.py`](../../../src/flare_re_mcp/orchestrator_qa.py).
