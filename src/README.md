# 📦 Diretório `src/` — Camada de Código-Fonte (`src-layout`)

Este diretório segue o padrão moderno de empacotamento Python **`src-layout`** (recomendado pela *Python Packaging Authority - PyPA* e PEP 517/621).

---

## 🎯 Por que utilizamos o `src-layout`?

1. **Isolamento de Importação**: Garante que os servidores MCP (`die-mcp`, `floss-mcp`, `capa-mcp`, `rizin-mcp`, `radare2-mcp`, `ghidra-mcp`) e a suíte de testes importem o pacote instalado `flare_re_mcp` de forma determinística, evitando conflitos com pastas locais do diretório de trabalho.
2. **Instalação Editável (`pip install -e .`)**: Permite que desenvolvedores editem qualquer módulo dentro de [`src/flare_re_mcp/`](./flare_re_mcp/) e vejam as alterações refletidas imediatamente nos binários CLI e servidores MCP registrados no Antigravity CLI (`agy`), sem necessidade de reinstalar o pacote.

---

## 📂 Estrutura Interna

| Caminho | Descrição | Documentação |
| :--- | :--- | :--- |
| **[`flare_re_mcp/`](./flare_re_mcp/)** | Pacote principal contendo os 6 servidores MCP, utilitários compartilhados, extrator Rizin-CAPA e o orquestrador de Quality Gate DevSecOps. | [src/flare_re_mcp/README.md](./flare_re_mcp/README.md) |
| **`flare_re_mcp.egg-info/`** | Metadados gerados automaticamente pelo `setuptools` durante `pip install -e .` (incluso no `.gitignore`). | — |

---

## 🛠️ Como Desenvolver e Testar Alterações

```powershell
# Na raiz do repositório:
pip install -e .

# Verificar se todos os módulos compilam sem erros de sintaxe:
python -m py_compile src\flare_re_mcp\*.py

# Executar a suíte de verificação dos servidores MCP:
python tests\verify_all_mcp_servers.py
```
