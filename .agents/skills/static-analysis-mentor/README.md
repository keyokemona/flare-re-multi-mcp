# 🎓 Skill `static-analysis-mentor` — Módulo de Aprendizado Prático e Mentoria Offline/Agêntica

Esta pasta contém a skill **[`SKILL.md`](./SKILL.md)** que transforma o agente em um **Instrutor Sêior de Engenharia Reversa**, guiando o analista por pistas progressivas em vez de entregar o relatório pronto.

---

## 🎯 Duplo Modo de Operação (Agêntico + 100% Offline Zero-Tokens)

1. **No Chat do Antigravity CLI (`agy`)**:
   - Basta digitar:
     > *"/treino Quero analisar o binário `C:\caminho\amostra.exe` passo a passo, me dê pistas!"*
   - O agente utiliza [`mentor_engine.py`](../../../src/flare_re_mcp/mentor_engine.py) em background e conduz você por **4 Níveis Progressivos** (Triagem PE → Strings/IOCs → Capacidades CAPA → Decompilação C/Assembly & YARA), ensinando os comandos reais de terminal de cada ferramenta.
2. **No Terminal 100% Offline (`flare-re-mentor` — Sem Consumo de Tokens)**:
   - Ideal para ambientes *air-gapped* (isolados de rede) ou quando sua franquia semanal de tokens estiver esgotada:
     ```powershell
     # Sessão interativa passo a passo no terminal:
     python -m flare_re_mcp.mentor_engine "C:\caminho\amostra.exe" --interactive

     # Gerar caderno de laboratório Markdown com dicas e gabaritos recolhíveis (<details>):
     python -m flare_re_mcp.mentor_engine "C:\caminho\amostra.exe" --export-lab-guide
     ```
