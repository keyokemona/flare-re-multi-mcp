# 🧪 Diretório `tests/` — Suíte de Testes de Integração e Verificação Ponta a Ponta

Este diretório contém os testes automatizados que garantem que todas as ferramentas de linha de comando do FlareVM e todos os **6 servidores MCP customizados** (`die-mcp`, `floss-mcp`, `capa-mcp`, `rizin-mcp`, `radare2-mcp`, `ghidra-mcp`) estejam operacionais antes e depois de qualquer modificação no código.

---

## 📄 Arquivos de Teste

| Arquivo | Descrição |
| :--- | :--- |
| **[`verify_all_mcp_servers.py`](./verify_all_mcp_servers.py)** | Teste de integração ponta a ponta que verifica: (1) a quantidade e nomes das ferramentas registradas em cada `MCPServer`, e (2) a execução real de triagem, extração de strings, capacidades CAPA, disassembly/decompilação Rizin (`rz-ghidra`), Radare2 (`r2ghidra`) e Ghidra Headless (`PyGhidra`), além da síntese multi-ferramenta. |

---

## 🚀 Como Executar os Testes

### 1. Executar a Suíte Completa de Verificação dos Servidores MCP
```powershell
python tests\verify_all_mcp_servers.py
```

### 2. Executar o Quality Gate DevSecOps de 8 Estágios em uma Amostra
```powershell
python -m flare_re_mcp.orchestrator_qa "C:\Users\keyokemona\Desktop\Malware.Unknown.exe.malz" --prewarm
```

---

## 🛠️ Como Adicionar Novos Testes

Ao criar um novo servidor MCP ou uma nova ferramenta (`@server.tool`):
1. Importe o servidor em [`verify_all_mcp_servers.py`](./verify_all_mcp_servers.py) e adicione-o ao dicionário `servers` para validar o registro das tools no protocolo MCP.
2. Adicione uma chamada de fumaça (*smoke test*) passando `TARGET` (`notepad.exe` ou um binário de teste) e valide que o JSON retornado contém `"status": "success"`.
