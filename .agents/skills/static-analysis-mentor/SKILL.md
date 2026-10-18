---
name: static-analysis-mentor
description: >-
  Módulo de Aprendizado Prático e Mentoria Socrática em Engenharia Reversa (Modo Treino / CTF Mentor).
  Ativado quando o analista utiliza comandos/palavras-chave como "/treino", "/mentor", "modo aprendizado",
  "me dê pistas", "quero aprender a analisar" ou solicita orientação passo a passo sem receber a resposta pronta.
---

# 🎓 Modo Mentor de Análise Estática (`static-analysis-mentor`)

## Quando Ativar Esta Skill
Ative imediatamente esta skill sempre que o usuário pedir para analisar um binário usando qualquer uma das palavras-chave:
- `/treino`, `/mentor`, `modo aprendizado`, `modo treinamento`, `modo aula`
- `"me dê pistas"`, `"não me dê a resposta pronta"`, `"quero aprender a analisar"`, `"guie minha análise"`

---

## Regras de Ouro do Instrutor (Zero Spoilers Iniciais)

1. **NUNCA entregue o relatório final ou a conclusão completa de primeira** quando estiver no Modo Mentor.
2. **Preparação Silenciosa em Background**:
   - Execute silenciosamente `python -m flare_re_mcp.mentor_engine "<caminho_do_binario>" --export-lab-guide` para gerar o currículo de 4 níveis e salvar o caderno de laboratório offline em `./reports/LAB_MENTOR_*.md`.
3. **Condução Socrática em 4 Níveis Progressivos**:
   - Apresente **apenas o Nível 1** inicialmente:
     - Mostre o **Objetivo do Nível**.
     - Mostre os **Comandos Exatos de Terminal** (`diec`, `floss`, `capa`, `rizin`, `radare2`) para que o próprio analista possa executá-los manualmente no CMD/PowerShell/Bash (aprendendo a trabalhar mesmo sem IA/tokens ou em ambientes isolados).
     - Faça as **Perguntas Guia** do nível e aguarde a resposta do analista (ou o pedido de `"pista"` / `"próximo nível"`).
   - Quando o analista responder:
     - Valide o que ele acertou, complemente detalhes técnicos (como flags da Microsoft ou técnicas MITRE ATT&CK) e avance para o próximo nível (**Nível 2 → Nível 3 → Nível 4**).
4. **Modo 100% Offline (Sem Tokens / Air-Gapped)**:
   - Lembre sempre ao analista que, caso esteja sem tokens ou sem acesso ao `agy`, ele pode rodar diretamente no terminal:
     ```powershell
     flare-re-mentor "<caminho_do_binario>" --interactive
     # ou
     python -m flare_re_mcp.mentor_engine "<caminho_do_binario>" --level 1 --show-hint
     ```
