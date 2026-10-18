# 🧠 Diretório `.agents/skills/` — Catálogo de Skills Operacionais

Este diretório contém as **4 Skills** que ensinam ao agente Antigravity procedimentos avançados de engenharia reversa, desempacotamento híbrido, Threat Intelligence OSINT, coordenação de sub-agentes paralelos, validação DevSecOps e mentoria socrática.

---

## 📋 Skills Disponíveis

| Nome da Skill | Papel Principal | Arquivos |
| :--- | :--- | :--- |
| **[`secops-orchestrator`](./secops-orchestrator/)** | **Orquestrador Principal ("Funcionário Especialista")** em Segurança da Informação, DevSecOps e Engenharia de Software. Gerencia a fila de execução paralela (`orchestrator_qa.py --prewarm`), despacha os sub-agentes especializados e audita o Quality Gate de 8 estágios. | [SKILL.md](./secops-orchestrator/SKILL.md)<br/>[README.md](./secops-orchestrator/README.md) |
| **[`flare-static-analysis`](./flare-static-analysis/)** | **Metodologia Técnica de Análise Estática Multi-Ferramenta**. Define como cruzar *Detect It Easy*, *FLOSS*, *CAPA*, *Rizin/RzGhidra*, *Radare2/r2ghidra*, *Ghidra/PyGhidra*, *MITRE ATT&CK v20.0* e *Microsoft Learn* mantendo a disciplina do *REA Evidence Ledger*. | [SKILL.md](./flare-static-analysis/SKILL.md)<br/>[README.md](./flare-static-analysis/README.md) |
| **[`binary-unpacker-deobfuscator`](./binary-unpacker-deobfuscator/)** | **Desempacotamento Híbrido & Threat Intelligence OSINT**. Coordena o `unpacker-mcp` (descompactação automática de UPX, UPX adulterado, PE/XOR embutido ou busca de OEP com confirmação do usuário) e o `threat-intel-mcp` (MalwareBazaar, ThreatFox, URLhaus e VirusTotal v3 sem upload de amostra). | [SKILL.md](./binary-unpacker-deobfuscator/SKILL.md)<br/>[README.md](./binary-unpacker-deobfuscator/README.md) |
| **[`static-analysis-mentor`](./static-analysis-mentor/)** | **Módulo de Aprendizado Prático & Mentoria Socrática**. Ativado por `/treino`, `/mentor` ou `me dê pistas`, guiando o analista passo a passo em 4 níveis progressivos (com suporte ao CLI 100% offline `flare-re-mentor` sem consumo de tokens). | [SKILL.md](./static-analysis-mentor/SKILL.md)<br/>[README.md](./static-analysis-mentor/README.md) |
