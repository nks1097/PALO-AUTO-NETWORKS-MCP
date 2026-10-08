"""
Exportação consolidada do módulo de segurança.
"""

from .auth import audit_log, generate_correlation_id
from .permissions import Permission, enforce_authorization
from .sanitizer import ALLOWED_DIAGNOSTIC_COMMANDS, sanitize_object_name, sanitize_xpath, validate_diagnostic_command
from .secrets import sanitize_secrets_dict

__all__ = [
    "generate_correlation_id",
    "audit_log",
    "Permission",
    "enforce_authorization",
    "sanitize_object_name",
    "sanitize_xpath",
    "validate_diagnostic_command",
    "ALLOWED_DIAGNOSTIC_COMMANDS",
    "sanitize_secrets_dict",
]
