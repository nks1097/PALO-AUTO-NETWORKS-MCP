#!/usr/bin/env python3
"""
Palo Alto Networks MCP Server - Bridge Stdio nativo para Antigravity IDE.
Suporta perfeitamente 'server/discover', 'initialize', 'tools/list' e 'tools/call'.
Silencia stderr para garantir indicador 100% verde e sem alertas falsos na IDE.
"""

import asyncio
import json
import os
import sys
from pathlib import Path

# Configurações de ambiente silenciosas
os.environ["PYTHONIOENCODING"] = "utf-8"
os.environ["FASTMCP_SHOW_SERVER_BANNER"] = "false"
os.environ["FASTMCP_LOG_LEVEL"] = "CRITICAL"

# Redireciona stderr para arquivo de log local para não poluir o Antigravity IDE com erros falsos
LOG_DIR = Path(__file__).resolve().parent / "logs"
LOG_DIR.mkdir(exist_ok=True)
sys.stderr = open(LOG_DIR / "paloalto_bridge.log", "a", encoding="utf-8")

# Adiciona o src ao path do Python
SRC_DIR = Path(__file__).resolve().parent / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

# Importa as ferramentas e o registro oficial do Palo Alto MCP
import paloalto_mcp.tools  # noqa: F401
from paloalto_mcp.registry import REGISTERED_TOOLS
from paloalto_mcp.server import initialize_mcp_server

# Pré-carrega o servidor e ferramentas FastMCP para obter os schemas de entrada
_mcp_instance = initialize_mcp_server()
_fastmcp_tools = {t.name: t for t in _mcp_instance._tool_manager.list_tools()}


def build_tools_list() -> list:
    """Retorna a lista das 100 ferramentas no formato padrão JSON-RPC da especificação MCP."""
    tools = []
    for name, reg in REGISTERED_TOOLS.items():
        fm_tool = _fastmcp_tools.get(name)
        schema = fm_tool.parameters if (fm_tool and hasattr(fm_tool, "parameters") and fm_tool.parameters) else {
            "type": "object",
            "properties": {},
            "required": []
        }
        tools.append({
            "name": name,
            "description": f"[{reg.metadata.category.upper()}] {reg.metadata.description}",
            "inputSchema": schema,
        })
    return tools


def write_response(payload: dict):
    """Envia uma resposta JSON-RPC delimitada por quebra de linha no stdout."""
    line = json.dumps(payload, ensure_ascii=False)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


async def execute_tool_async(tool_name: str, arguments: dict) -> dict:
    """Executa a ferramenta assíncrona correspondente e formata o resultado."""
    reg = REGISTERED_TOOLS.get(tool_name)
    if not reg:
        return {
            "content": [{"type": "text", "text": f"Ferramenta '{tool_name}' não encontrada."}],
            "isError": True,
        }

    try:
        handler = reg.handler
        if asyncio.iscoroutinefunction(handler):
            result = await handler(**arguments)
        else:
            result = handler(**arguments)

        data_to_dump = result.model_dump() if hasattr(result, "model_dump") else result
        text_out = json.dumps(data_to_dump, ensure_ascii=False, indent=2)

        return {
            "content": [{"type": "text", "text": text_out}],
            "isError": getattr(result, "success", True) is False,
        }
    except Exception as exc:
        return {
            "content": [{"type": "text", "text": f"Erro na execução da ferramenta {tool_name}: {str(exc)}"}],
            "isError": True,
        }


def main():
    """Loop principal síncrono no stdin (compatível com Windows pipes)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        for raw_line in sys.stdin:
            raw_line = raw_line.strip()
            if not raw_line:
                continue

            try:
                msg = json.loads(raw_line)
            except json.JSONDecodeError:
                continue

            method = msg.get("method", "")
            msg_id = msg.get("id")

            # 1. Antigravity Discovery proprietário
            if method == "server/discover":
                write_response({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "serverInfo": {
                            "name": "paloalto",
                            "version": "1.0.0",
                        },
                        "capabilities": {
                            "tools": {"listChanged": False},
                        },
                    },
                })
                continue

            # 2. Inicialização MCP padrão
            if method == "initialize":
                write_response({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {
                            "tools": {"listChanged": False},
                        },
                        "serverInfo": {
                            "name": "paloalto",
                            "version": "1.0.0",
                        },
                    },
                })
                continue

            # 3. Notificações MCP (sem id)
            if method == "notifications/initialized":
                continue

            # 4. Ping
            if method == "ping":
                write_response({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {},
                })
                continue

            # 5. Listagem das 100 ferramentas
            if method == "tools/list":
                write_response({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": {
                        "tools": build_tools_list(),
                    },
                })
                continue

            # 6. Execução de ferramentas
            if method == "tools/call":
                params = msg.get("params", {})
                tool_name = params.get("name", "")
                arguments = params.get("arguments", {})
                call_result = loop.run_until_complete(execute_tool_async(tool_name, arguments))
                write_response({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "result": call_result,
                })
                continue

            # Métodos desconhecidos
            if msg_id is not None:
                write_response({
                    "jsonrpc": "2.0",
                    "id": msg_id,
                    "error": {
                        "code": -32601,
                        "message": f"Método não suportado: {method}",
                    },
                })

    except (KeyboardInterrupt, BrokenPipeError, EOFError):
        pass
    finally:
        loop.close()


if __name__ == "__main__":
    main()
