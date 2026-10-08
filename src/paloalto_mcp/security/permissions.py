"""
Controle de Acesso Baseado em Função (RBAC) e checagens de autorização para ferramentas MCP.
"""

from enum import Enum

from ..config import settings
from ..exceptions import PaloAltoAuthorizationError


class Permission(str, Enum):
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    COMMIT = "commit"
    DIAGNOSTIC = "diagnostic"
    ADMIN = "admin"


def enforce_authorization(
    permission: Permission,
    destructive: bool = False,
    confirmed: bool = False,
    dry_run: bool = False,
) -> None:
    """
    Valida se a operação é permitida com base na configuração do ambiente e confirmação do usuário.
    """
    # Operações em dry-run nunca alteram o firewall, portanto são seguras
    if dry_run:
        return

    # Bloqueio de escrita se ALLOW_WRITE_OPERATIONS estiver desativado
    if permission in (Permission.WRITE, Permission.DELETE):
        if not settings.allow_write_operations:
            raise PaloAltoAuthorizationError(
                "Operações de escrita/modificação estão desabilitadas no servidor (ALLOW_WRITE_OPERATIONS=false)."
            )

    # Bloqueio de commit se ALLOW_COMMIT estiver desativado
    if permission == Permission.COMMIT:
        if not settings.allow_commit:
            raise PaloAltoAuthorizationError(
                "Operações de commit estão desabilitadas no servidor (ALLOW_COMMIT=false)."
            )

    # Validação de confirmação explícita para ações destrutivas (delete, commit, reboot, reset)
    if destructive and settings.mcp_require_confirmation and not confirmed:
        raise PaloAltoAuthorizationError(
            "Esta é uma operação destrutiva e requer confirmação explícita. Passe o parâmetro 'confirm=true' para prosseguir.",
            details={"code": "CONFIRMATION_REQUIRED", "permission": permission.value}
        )
