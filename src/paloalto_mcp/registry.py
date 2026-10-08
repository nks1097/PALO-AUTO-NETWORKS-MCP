"""
Registro central de ferramentas MCP do Palo Alto Networks.
Garante a validação estrita de exatamente 100 ferramentas, seus metadados e permissões RBAC.
"""

from typing import Callable, Dict

from pydantic import BaseModel

from .security.permissions import Permission

EXPECTED_TOOL_COUNT = 100


class ToolMetadata(BaseModel):
    name: str
    category: str
    permission: Permission
    destructive: bool = False
    supports_dry_run: bool = False
    is_panorama: bool = False
    description: str


class ToolRegistration:
    def __init__(self, metadata: ToolMetadata, handler: Callable):
        self.metadata = metadata
        self.handler = handler


# Dicionário de ferramentas registradas
REGISTERED_TOOLS: Dict[str, ToolRegistration] = {}


def register_tool(
    name: str,
    category: str,
    permission: Permission,
    description: str,
    destructive: bool = False,
    supports_dry_run: bool = False,
    is_panorama: bool = False,
):
    """Decorator para registro de ferramentas com metadados e validação estrita."""
    def decorator(func: Callable):
        if name in REGISTERED_TOOLS:
            raise ValueError(f"Ferramenta duplicada detectada no registro: {name}")

        meta = ToolMetadata(
            name=name,
            category=category,
            permission=permission,
            destructive=destructive,
            supports_dry_run=supports_dry_run,
            is_panorama=is_panorama,
            description=description,
        )
        REGISTERED_TOOLS[name] = ToolRegistration(metadata=meta, handler=func)
        return func

    return decorator


def validate_registry() -> None:
    """
    Valida se exatamente 100 ferramentas estão registradas.
    Falha imediatamente no startup se a contagem for diferente.
    """
    count = len(REGISTERED_TOOLS)
    if count != EXPECTED_TOOL_COUNT:
        raise RuntimeError(
            f"FALHA NO STARTUP DO SERVIDOR MCP: Esperado exatamente {EXPECTED_TOOL_COUNT} ferramentas registradas, "
            f"mas foram encontradas {count}."
        )


def get_registry_stats() -> Dict[str, int]:
    """Retorna métricas e estatísticas das 100 ferramentas registradas."""
    stats = {
        "total": len(REGISTERED_TOOLS),
        "read": 0,
        "write": 0,
        "delete": 0,
        "commit": 0,
        "diagnostic": 0,
        "destructive": 0,
        "supports_dry_run": 0,
        "panorama": 0,
        "firewall": 0,
    }

    for reg in REGISTERED_TOOLS.values():
        perm = reg.metadata.permission
        if perm == Permission.READ:
            stats["read"] += 1
        elif perm == Permission.WRITE:
            stats["write"] += 1
        elif perm == Permission.DELETE:
            stats["delete"] += 1
        elif perm == Permission.COMMIT:
            stats["commit"] += 1
        elif perm == Permission.DIAGNOSTIC:
            stats["diagnostic"] += 1

        if reg.metadata.destructive:
            stats["destructive"] += 1
        if reg.metadata.supports_dry_run:
            stats["supports_dry_run"] += 1
        if reg.metadata.is_panorama:
            stats["panorama"] += 1
        else:
            stats["firewall"] += 1

    return stats
