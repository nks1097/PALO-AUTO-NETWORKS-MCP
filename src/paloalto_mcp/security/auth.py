"""
Gestão de correlação, identificação de sessão e auditoria de operações MCP.
"""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..logging import logger


def generate_correlation_id() -> str:
    """Gera um identificador de correlação único para rastreamento de requisições."""
    return str(uuid.uuid4())


def audit_log(
    tool: str,
    operation: str,
    device: Optional[str],
    target_object: Optional[str],
    dry_run: bool,
    success: bool,
    correlation_id: str,
    user: str = "mcp_ai_agent",
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """
    Registra trilha de auditoria estruturada em conformidade com o Requisito 19.
    Nunca registra dados sensíveis ou segredos.
    """
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool,
        "user": user,
        "device": device or "default",
        "operation": operation,
        "object": target_object or "none",
        "dry_run": dry_run,
        "success": success,
        "correlation_id": correlation_id,
    }
    if extra:
        event["extra"] = extra

    logger.info("mcp_audit_event", **event)
