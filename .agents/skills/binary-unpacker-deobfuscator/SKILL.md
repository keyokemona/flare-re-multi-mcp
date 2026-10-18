---
name: binary-unpacker-deobfuscator
description: >-
  Fluxo especializado de Desempacotamento Híbrido (unpacker-mcp) e Threat Intelligence OSINT (threat-intel-mcp).
  Detecta packers (UPX, UPX adulterado, PyInstaller, ASPack, VMProtect, PE/XOR embutido), descompacta automaticamente
  wrappers suportados para reanálise limpa, ou pergunta ao usuário antes de criar unpackers manuais em Python.
---

# 🔓 Desempacotamento Híbrido (`unpacker-mcp`) & Threat Intelligence OSINT (`threat-intel-mcp`)

## 1. Fluxo do Sub-Agente `unpacker-deobfuscator-worker` (`unpacker-mcp`)

Sempre que a triagem inicial (`die-mcp` ou `unpack_inspect_and_detect`) indicar que o binário está comprimido/ofuscado (`is_packed_or_wrapped == true`):

1. **Caso A — Packer Suportado Automaticamente (`unpack_strategy == "auto_supported"`)**:
   - Exemplos: **UPX padrão**, **UPX modificado/adulterado** (nomes de seção `UPX0`/`UPX1` apagados), **PE embutido em Overlay/Recurso** ou **PE codificado com XOR de 1 byte**.
   - Chame imediatamente `unpack_auto_decompress(file_path)` no servidor `unpacker-mcp`.
   - O servidor gerará o novo executável limpo em `.analysis_cache/<sha256>/unpacked/<nome>.unpacked.exe`.
   - **Redirecionamento Automático da Fila**: Todos os demais agentes (`floss-mcp`, `capa-mcp`, `rizin-mcp`, `radare2-mcp`, `ghidra-mcp`) devem ser executados sobre o **novo binário descompactado** (`unpacked_file_path`), registrando tanto o hash do wrapper original quanto o hash do payload descompactado!

2. **Caso B — Packer Customizado / Comercial Complexo (`unpack_strategy == "custom_manual_requires_user_choice"`)**:
   - Chame `unpack_find_oep_and_stub_landmarks(file_path)` para identificar candidatos a *Original Entry Point (OEP)* (`pushad`/`popad` + `jmp reg` / `ret`).
   - **Economia Consciente de Tokens**: Pergunte ao usuário (via `ask_question`) se ele deseja que você escreva e execute um script Python desempacotador customizado para extrair o payload ou se prefere seguir apenas com a análise estática do stub empacotado + Threat Intelligence.

---

## 2. Fluxo do Sub-Agente `threat-intel-osint-worker` (`threat-intel-mcp`)

Em toda análise estática:
1. Chame `ti_lookup_binary_reputation(file_path)` e `ti_lookup_iocs(file_path)` no servidor `threat-intel-mcp`.
   - Consulta **MalwareBazaar**, **ThreatFox**, **URLhaus** e **VirusTotal v3** (se `VT_API_KEY` estiver presente) **estritamente por hash/IOC** (nunca enviando o arquivo binário para fora da máquina).
2. Caso o hash SHA-256 seja inédito nos repositórios ou haja artefatos únicos (como nome de arquivo `.pdb`, `Imphash` ou domínios C2), utilize `search_web` com as queries retornadas em `recommended_web_search_queries` para verificar se o artefato já foi documentado publicamente em relatórios de Threat Intelligence.
