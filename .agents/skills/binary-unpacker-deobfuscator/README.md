# 🔓 Skill `binary-unpacker-deobfuscator` — Desempacotamento Híbrido & Threat Intelligence OSINT

Esta pasta contém a skill **[`SKILL.md`](./SKILL.md)** que coordena dois recursos avançados da suíte **`flare-re-mcp`**:

1. **Desempacotamento e Deofuscação Híbrida (`unpacker-mcp` / sub-agente `unpacker-deobfuscator-worker`)**:
   - Descompacta automaticamente wrappers conhecidos (**UPX**, **UPX com cabeçalho adulterado** via restauração automática de `UPX0`/`UPX1`, e **PEs embutidos ou cifrados com XOR**) gerando um novo arquivo `.unpacked.exe` e redirecionando toda a fila de engenharia reversa para o binário limpo.
   - Em packers customizados/desconhecidos, localiza candidatos a *Original Entry Point (OEP)* e consulta o usuário antes de tentar criar um desempacotador manual (protegendo o consumo de tokens do analista).
2. **Threat Intelligence & Reputação OSINT (`threat-intel-mcp` / sub-agente `threat-intel-osint-worker`)**:
   - Consulta **MalwareBazaar**, **ThreatFox**, **URLhaus** e **VirusTotal v3** estritamente por hashes (`SHA-256`, `MD5`, `Imphash`) e IOCs, sem jamais fazer upload da amostra.
