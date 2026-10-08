"""
Palo Alto Networks MCP Server - 100 Ferramentas para Administração e Observabilidade.
"""

from .registry import EXPECTED_TOOL_COUNT, REGISTERED_TOOLS, get_registry_stats
from .server import initialize_mcp_server, mcp

__version__ = "1.0.0"
__all__ = ["mcp", "initialize_mcp_server", "REGISTERED_TOOLS", "EXPECTED_TOOL_COUNT", "get_registry_stats"]
