"""
Importação e inicialização automática de todas as 100 ferramentas MCP.
"""

from . import config, diagnostics, ha, logs, network, objects, panorama, policies, system, vpn

__all__ = [
    "system",
    "config",
    "objects",
    "policies",
    "network",
    "vpn",
    "logs",
    "ha",
    "panorama",
    "diagnostics",
]
