# 🤖 Diretório `.agents/` — Customizações do Ecossistema Antigravity CLI

Este diretório armazena as **customizações específicas do projeto (Workspace Customizations)** descobertas automaticamente pelo **Antigravity CLI (`agy`)** sempre que uma sessão é iniciada neste repositório.

---

## 🔍 Como Funciona a Descoberta Automática

De acordo com a arquitetura do Antigravity Customization System:
1. Ao iniciar o `agy` em qualquer subpasta do projeto, o agente percorre a árvore de diretórios até a raiz e localiza `.agents/` e o arquivo [`AGENTS.md`](../AGENTS.md).
2. As **Skills** dentro de [`.agents/skills/`](./skills/) utilizam *Progressive Disclosure*: seus nomes e descrições ficam sempre disponíveis no prompt de sistema do agente, e suas instruções completas (`SKILL.md`) são ativadas sob demanda assim que uma tarefa de análise estática ou engenharia reversa é solicitada.

---

## 📂 Estrutura Interna

| Caminho | Propósito | Documentação |
| :--- | :--- | :--- |
| **[`skills/`](./skills/)** | Contém as skills operacionais do workspace (`flare-static-analysis` e `secops-orchestrator`). | [.agents/skills/README.md](./skills/README.md) |
| **[`skills/flare-static-analysis/`](./skills/flare-static-analysis/)** | Runbook completo de análise estática multi-MCP em 6 fases. | [README.md](./skills/flare-static-analysis/README.md) \| [SKILL.md](./skills/flare-static-analysis/SKILL.md) |
| **[`skills/secops-orchestrator/`](./skills/secops-orchestrator/)** | Orquestrador DevSecOps & SecOps de Sub-Agentes Paralelos e Quality Gate de 8 estágios. | [README.md](./skills/secops-orchestrator/README.md) \| [SKILL.md](./skills/secops-orchestrator/SKILL.md) |

---

## 🛠️ Como Expandir as Customizações deste Workspace

* **Adicionar uma Nova Skill**: Crie uma pasta `.agents/skills/<nome-da-skill>/` contendo um arquivo `SKILL.md` com cabeçalho YAML (`name` e `description`) e um `README.md` documentando seu propósito.
* **Adicionar Regras Sempre Ativas**: Edite o arquivo [`AGENTS.md`](../AGENTS.md) na raiz do projeto ou adicione arquivos `.md` em `.agents/rules/`.
