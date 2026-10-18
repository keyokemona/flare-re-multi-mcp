# 📚 Diretório `reference/` — Repositórios de Referência e Base Arquitetural

Este diretório armazena clones locais de referência estudados durante o desenvolvimento da suíte **`flare-re-mcp`** para garantir fidelidade técnica e aproveitamento das melhores práticas da comunidade de engenharia reversa assistida por IA.

---

## 🏛️ Repositórios Estudados e Como Foram Integrados

| Repositório / Projeto | Papel na Arquitetura do `flare-re-mcp` | Onde Foi Aplicado |
| :--- | :--- | :--- |
| **[`kd992102/rizin-mcp`](./rizin-mcp/)** | Base direta para o gerenciamento de sessão `rzpipe`, sanitização de alvos, isolamento de `stderr` C-level (`suppress_stderr`) e extração rápida de features para o CAPA (`RizinFeatureExtractor`). | [`src/flare_re_mcp/rizin_server.py`](../src/flare_re_mcp/rizin_server.py)<br/>[`src/flare_re_mcp/rz_extractor.py`](../src/flare_re_mcp/rz_extractor.py)<br/>[`src/flare_re_mcp/common.py`](../src/flare_re_mcp/common.py) |
| **[`morluto/rea`](https://github.com/morluto/rea)** | Inspirou os dossiês compostos de funções (`analyze_function_dossier`), o cache de snapshots por SHA-256 e o **REA Evidence Ledger** (`verified_observations`, `inferences`, `residual_unknowns`). | [`src/flare_re_mcp/common.py`](../src/flare_re_mcp/common.py)<br/>[`src/flare_re_mcp/rizin_server.py`](../src/flare_re_mcp/rizin_server.py)<br/>[`src/flare_re_mcp/ghidra_server.py`](../src/flare_re_mcp/ghidra_server.py) |
| **[`radareorg/radare2-mcp`](https://github.com/radareorg/radare2-mcp)** | Inspirou o conjunto de ferramentas expostas pelo `radare2-mcp` (`r2_decompile_function` via `r2ghidra`, `r2_get_call_graph`, `r2_get_xrefs`, `r2_calculate`). | [`src/flare_re_mcp/radare2_server.py`](../src/flare_re_mcp/radare2_server.py) |
| **[`bethington/ghidra-mcp`](https://github.com/bethington/ghidra-mcp)** | Inspirou a decompilação em lote separada por `;` (`ghidra_decompile_functions`) e a navegação de referências cruzadas via `ReferenceManager`. | [`src/flare_re_mcp/ghidra_server.py`](../src/flare_re_mcp/ghidra_server.py) |
| **[`mandiant/capa`](https://github.com/mandiant/capa)** | Inspirou o `capa_bulk_analyze` (`scripts/bulk-process.py`) e o `ghidra_annotate_with_capa` (`capa/ghidra/plugin/capa_explorer.py`). | [`src/flare_re_mcp/capa_server.py`](../src/flare_re_mcp/capa_server.py)<br/>[`src/flare_re_mcp/ghidra_server.py`](../src/flare_re_mcp/ghidra_server.py) |

---

## 💡 Nota para Backup no GitHub

O subdiretório `reference/rizin-mcp/` é um clone do repositório upstream `kd992102/rizin-mcp`. No arquivo [`.gitignore`](../.gitignore) da raiz, `reference/rizin-mcp/` está configurado para ser ignorado por padrão (evitando problemas de submódulo Git aninhado ao fazer `git push`), mantendo este [`reference/README.md`](./README.md) versionado com toda a documentação de referência.
