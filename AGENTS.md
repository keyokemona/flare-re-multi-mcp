# Diretrizes do Workspace `flare-re-mcp` (Orquestrador DevSecOps, Unpacker, Threat Intel & Mentor)

Sempre que o usuário interagir neste workspace, siga rigorosamente os fluxos abaixo:

1. **Verificação Automática de Componentes (`auto_updater.py`)**:
   - Na inicialização da sessão (via `.agents/hooks.json` ou no início da fila do `orchestrator_qa.py`), o sistema verifica de forma não-bloqueante se os pacotes Python, regras CAPA (`.pkl`), base STIX do MITRE ATT&CK (`v20.0`) e binários nativos estão atualizados.

2. **Modo Aprendizado / Mentor Socrático (`static-analysis-mentor`)**:
   - Se o usuário usar palavras-chave como `/treino`, `/mentor`, `modo aprendizado`, `me dê pistas`, `ensine a analisar` ou pedir para não entregar a resposta pronta, ative imediatamente a skill [`static-analysis-mentor`](file:///C:/Users/keyokemona/agy_dir/.agents/skills/static-analysis-mentor/SKILL.md) e utilize [`mentor_engine.py`](file:///C:/Users/keyokemona/agy_dir/src/flare_re_mcp/mentor_engine.py) para guiar o analista em **4 Níveis Progressivos** (sem spoilers iniciais).

3. **Análise Estática Completa & Orquestrador DevSecOps (`secops-orchestrator`)**:
   - Utilize as skills [`secops-orchestrator`](file:///C:/Users/keyokemona/agy_dir/.agents/skills/secops-orchestrator/SKILL.md), [`flare-static-analysis`](file:///C:/Users/keyokemona/agy_dir/.agents/skills/flare-static-analysis/SKILL.md) e [`binary-unpacker-deobfuscator`](file:///C:/Users/keyokemona/agy_dir/.agents/skills/binary-unpacker-deobfuscator/SKILL.md).
   - **Desempacotamento Híbrido (`unpacker-mcp` / `unpacker-deobfuscator-worker`)**:
     - Se `unpack_inspect_and_detect` detectar um packer suportado automaticamente (`UPX`, `UPX adulterado`, `PE/XOR embutido`), execute `unpack_auto_decompress` para gerar o binário limpo (`.unpacked.exe`) e conduza a análise completa sobre o novo binário descompactado.
     - Se detectar um packer customizado/desconhecido (`custom_manual_requires_user_choice`), consulte o usuário antes de criar um desempacotador manual em Python (economizando tokens).
   - **Threat Intelligence OSINT (`threat-intel-mcp` / `threat-intel-osint-worker`)**:
     - Execute `ti_lookup_binary_reputation` e `ti_lookup_iocs` (consultando MalwareBazaar, ThreatFox, URLhaus e VirusTotal v3 estritamente por Hash/IOC, sem jamais fazer upload do arquivo binário) e complemente com buscas web OSINT (`search_web`).

4. **Quality Gate Obrigatório de 8 Estágios, Sintaxe Mermaid e Cópia em `./reports/`**:
   - **Formatação de Markdown e Sintaxe Mermaid nos Relatórios**:
     - **Fechamento Explícito de Code Blocks**: Todo bloco de código (especialmente ```` ```mermaid ````) deve terminar sempre com uma quebra de linha explícita (`\n`) antes do fechamento triplo de crases (```` ``` ````).
     - **Espaçamento Pós-Bloco**: Após o fechamento de qualquer code block, devem existir pelo menos duas quebras de linha (`\n\n`) antes de divisores (`---`) ou novos cabeçalhos (`##`), bem como entre divisores e novos cabeçalhos.
     - **Caminhos com Contrabarras Windows**: Caminhos de diretório contendo contrabarras (ex.: `%TEMP%\\caminho\\`) devem ter as barras devidamente escapadas como dupla barra (`\\`) para evitar conflitos de escape léxico no Mermaid.
     - **Aspas e Delimitadores Internos**: **Nunca** utilize aspas escapadas com barra invertida (`\"`) dentro de rótulos de nós `["..."]` (utilize sempre a entidade HTML **`#quot;`**, ex.: `Del /f /q #quot;%s#quot;`, ou aspas simples `'...'`).
     - **Arestas com Rótulos**: Utilize sempre a sintaxe padrão de pipe `-->|rótulo|` (ex.: `R -->|task.e| S`) em vez de `-- "rótulo" -->`.
     - **Normalização de Espaços**: Nunca utilize *non-breaking spaces* (`\u00A0`) ou caracteres invisíveis; use sempre espaços ASCII padrão (`\x20`) e coloque cada aresta (`A --> B`) em sua própria linha.
   - Salve o relatório final em `./reports/<YYYY-MM-DD_HH-MM-SS>_<nome_do_arquivo>_<sha256[:12]>.md`.
   - Ao final, execute `python -m flare_re_mcp.orchestrator_qa "<binario>" --artifact-report "<caminho_do_artifact_md>"` (que sanitiza e repara automaticamente blocos Mermaid e Markdown via `common.sanitize_markdown_report_formatting`) e valide `"overall_quality_gate": "PASSED"`.

