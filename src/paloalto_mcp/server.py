"""
Servidor MCP principal para Palo Alto Networks (PAN-OS / Panorama).
Registra as 100 ferramentas no FastMCP e valida a contagem estrita no startup.
Opcionalmente expõe endpoints HTTP /health, /ready e /metrics via FastAPI.
"""

from typing import Any, Dict

from fastapi import FastAPI
from mcp.server.fastmcp import FastMCP

# Garante importação e registro de todas as 100 ferramentas
from . import tools  # noqa: F401
from .config import settings
from .logging import logger, setup_logging
from .registry import (
    EXPECTED_TOOL_COUNT,
    REGISTERED_TOOLS,
    get_registry_stats,
    validate_registry,
)

# Inicializa FastMCP oficial
mcp = FastMCP(
    name="Palo Alto Networks MCP",
    instructions="Servidor MCP corporativo para administração defensiva, observabilidade e automação do Palo Alto Networks PAN-OS e Panorama.",
)


def initialize_mcp_server() -> FastMCP:
    """Valida o registro e adiciona as 100 ferramentas ao FastMCP."""
    validate_registry()

    for name, reg in REGISTERED_TOOLS.items():
        mcp.add_tool(
            reg.handler,
            name=reg.metadata.name,
            description=f"[{reg.metadata.category.upper()}] {reg.metadata.description}",
        )

    logger.info(
        "mcp_server_initialized",
        expected=EXPECTED_TOOL_COUNT,
        registered=len(REGISTERED_TOOLS),
        stats=get_registry_stats(),
    )
    return mcp


# Criação da aplicação FastAPI para observabilidade e healthchecks
app = FastAPI(
    title="Palo Alto Networks MCP Server",
    description="MCP Server com 100 ferramentas para administração e observabilidade do PAN-OS e Panorama.",
    version="1.0.0",
)


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Endpoint de saúde do servidor sem expor nenhum segredo."""
    return {
        "status": "healthy",
        "service": "paloalto-mcp",
        "tools_count": len(REGISTERED_TOOLS),
        "target_host": settings.panos_host.split("@")[-1],  # Sanitizado
        "ssl_verify": settings.panos_verify_ssl,
        "write_allowed": settings.allow_write_operations,
        "commit_allowed": settings.allow_commit,
    }


@app.get("/ready")
async def readiness_check() -> Dict[str, Any]:
    """Endpoint de prontidão verificando o registro de 100 ferramentas."""
    is_ready = len(REGISTERED_TOOLS) == EXPECTED_TOOL_COUNT
    return {
        "ready": is_ready,
        "tools_registered": len(REGISTERED_TOOLS),
        "expected_tools": EXPECTED_TOOL_COUNT,
    }


@app.get("/metrics")
async def metrics() -> Dict[str, Any]:
    """Métricas operacionais do servidor MCP."""
    stats = get_registry_stats()
    return {
        "mcp_tools_total": stats["total"],
        "mcp_tools_read": stats["read"],
        "mcp_tools_write": stats["write"],
        "mcp_tools_delete": stats["delete"],
        "mcp_tools_commit": stats["commit"],
        "mcp_tools_diagnostic": stats["diagnostic"],
        "mcp_tools_destructive": stats["destructive"],
        "mcp_tools_panorama": stats["panorama"],
        "mcp_tools_firewall": stats["firewall"],
    }


def main():
    """Ponto de entrada de execução do servidor MCP via stdio."""
    setup_logging(settings.log_level)
    server = initialize_mcp_server()
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
