"""
Hierarquia de exceções personalizadas para o servidor MCP Palo Alto Networks.
"""

from typing import Any, Dict, Optional


class PaloAltoError(Exception):
    """Exceção base para todas as operações do Palo Alto MCP."""

    def __init__(self, message: str, code: str = "PANOS_ERROR", details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.message = message
        self.code = code
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "details": self.details,
        }


class PaloAltoAuthenticationError(PaloAltoError):
    """Falha de autenticação (API Key inválida, credenciais incorretas)."""

    def __init__(self, message: str = "Falha na autenticação com o PAN-OS", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="AUTHENTICATION_FAILED", details=details)


class PaloAltoAuthorizationError(PaloAltoError):
    """Permissão negada (operação requer nível mais alto ou confirmação)."""

    def __init__(self, message: str = "Operação não autorizada pelas políticas de segurança", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="AUTHORIZATION_DENIED", details=details)


class PaloAltoAPIError(PaloAltoError):
    """Erro retornado pela API do PAN-OS (XML ou REST)."""

    def __init__(self, message: str, code: str = "PANOS_API_ERROR", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code=code, details=details)


class PaloAltoTimeoutError(PaloAltoError):
    """Timeout de comunicação com o firewall ou Panorama."""

    def __init__(self, message: str = "Tempo limite excedido na comunicação com o firewall", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="TIMEOUT_ERROR", details=details)


class PaloAltoValidationError(PaloAltoError):
    """Erro de validação de dados de entrada, parâmetros ou limites."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="VALIDATION_ERROR", details=details)


class PaloAltoCommitError(PaloAltoError):
    """Falha durante validação ou execução de commit."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="COMMIT_FAILED", details=details)


class PaloAltoNotFoundError(PaloAltoError):
    """Objeto, política, interface ou recurso não encontrado."""

    def __init__(self, message: str = "Recurso não encontrado no PAN-OS", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="RESOURCE_NOT_FOUND", details=details)


class PaloAltoConflictError(PaloAltoError):
    """Conflito de estado ou objeto já existente (ex: endereço duplicado)."""

    def __init__(self, message: str = "Conflito na operação: objeto já existente ou em uso", details: Optional[Dict[str, Any]] = None):
        super().__init__(message, code="CONFLICT_ERROR", details=details)
