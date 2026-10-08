"""
Configuração de logs estruturados e sanitização de dados sensíveis.
Garante que credenciais, chaves de API e tokens nunca apareçam nos logs.
"""

import logging
import re
import sys
from typing import Any, MutableMapping

import structlog

# Padrões para mascarar dados sensíveis nos logs
SENSITIVE_PATTERNS = [
    (re.compile(r"(key=)[^&\s'\"]+", re.IGNORECASE), r"\1[REDACTED_API_KEY]"),
    (re.compile(r"(password=)[^&\s'\"]+", re.IGNORECASE), r"\1[REDACTED_PASSWORD]"),
    (re.compile(r"(X-PAN-KEY:\s*)[^\r\n]+", re.IGNORECASE), r"\1[REDACTED_PAN_KEY]"),
    (re.compile(r"(LUFRPT[0-9A-Za-z+/=]+)", re.IGNORECASE), r"[REDACTED_TOKEN]"),
]


def redact_sensitive_data(message: str) -> str:
    """Substitui ocorrências de chaves, senhas e tokens por texto ofuscado."""
    for pattern, repl in SENSITIVE_PATTERNS:
        message = pattern.sub(repl, message)
    return message


def sanitize_processor(
    logger: Any, method_name: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    """Processador structlog que sanitiza strings sensíveis em qualquer campo."""
    for k, v in list(event_dict.items()):
        if isinstance(v, str):
            event_dict[k] = redact_sensitive_data(v)
    return event_dict


def setup_logging(log_level: str = "INFO") -> None:
    """Configura o logger padrão do sistema e structlog."""
    level = getattr(logging, log_level.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        level=level,
    )

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            sanitize_processor,
            structlog.dev.ConsoleRenderer()
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        cache_logger_on_first_use=True,
    )


# Inicializa configuração padrão apontando para sys.stderr
setup_logging()
logger = structlog.get_logger("paloalto_mcp")
