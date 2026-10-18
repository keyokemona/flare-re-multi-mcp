# 🔬 Skill `flare-static-analysis` — Metodologia de Análise Estática Multi-MCP

Esta pasta contém a skill **[`SKILL.md`](./SKILL.md)** responsável por guiar o agente através do fluxo técnico de análise estática cruzada nos 8 servidores MCP do ambiente FlareVM.

---

## 🎯 O que esta Skill Ensina ao Agente

1. **Fase 1 — Triagem Estrutural e Avaliação de Packing (`die-mcp` + `floss-mcp`)**:
   - Identificação de compilador, *Imphash*, entropia por seção, flags RWX, inspeção de recursos `.rsrc` em busca de binários ocultos e extração de strings estáticas, *stack strings*, *tight strings* e *decoded strings*.
2. **Fase 2 — Mapeamento de Capacidades Comportamentais (`capa-mcp`)**:
   - Correlação das funções do binário com táticas/técnicas **MITRE ATT&CK** e objetivos **MBC (Malware Behavior Catalog)** nos backends `rizin`, `vivisect` ou `ghidra`.
3. **Fase 3 — Disassembly e Decompilação Tripla (`rizin-mcp`, `radare2-mcp`, `ghidra-mcp`)**:
   - Confronto direto do código C gerado por `rz-ghidra` (`pdg`), `r2ghidra` (`pdg` com `bin.relocs.apply=true`) e `DecompInterface` nativo do Ghidra (`PyGhidra`), incluindo verificação de opcodes exatos e referências cruzadas (XREFs).
4. **Fase 4 — Enriquecimento de Threat Intelligence e Documentação Win32 (`mitre-attack` + `ms-learn`)**:
   - Consulta de descrições oficiais, mitigações (`Mxxxx`) e componentes de dados de detecção no `mitre-attack` e validação de protótipos, flags hexadecimais e valores de retorno (`HRESULT`) no `ms-learn`.
5. **Fase 5 — Disciplina de Evidências Forenses (`REA Evidence Ledger`)**:
   - Registro obrigatório de *Verified Observations*, *Inferences* e *Residual Unknowns* em `.analysis_cache/<sha256>/ledger.json`.
6. **Fase 6 — Integração com o Orquestrador DevSecOps (`secops-orchestrator`)**:
   - Uso do pré-aquecimento paralelo e auditoria final com [`orchestrator_qa.py`](../../../src/flare_re_mcp/orchestrator_qa.py).

---

## 🛠️ Como Customizar

Para adicionar novas etapas analíticas (por exemplo, análise específica de binários .NET, Go ou Rust), edite o arquivo [`SKILL.md`](./SKILL.md) mantendo o cabeçalho YAML (`name: flare-static-analysis`).
