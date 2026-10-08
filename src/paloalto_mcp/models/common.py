"""
Modelos de dados comuns e estrutura padronizada de respostas MCP.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: Optional[Dict[str, Any]] = None


class WarningDetail(BaseModel):
    code: str
    message: str


class DryRunResult(BaseModel):
    dry_run: bool = True
    operation: str
    target_object: str
    endpoint: str
    parameters: Dict[str, Any]
    risk_level: str
    predicted_changes: Dict[str, Any]
    message: str = "Simulação executada com sucesso. Nenhuma alteração foi enviada ao firewall."


class MCPResponse(BaseModel):
    """
    Estrutura padronizada de resposta para todas as ferramentas MCP.
    Garante consistência e previsibilidade para clientes de IA.
    """
    success: bool
    tool: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    device: Optional[str] = None
    data: Optional[Any] = None
    warnings: List[WarningDetail] = Field(default_factory=list)
    errors: List[ErrorDetail] = Field(default_factory=list)

    @classmethod
    def ok(cls, tool: str, data: Any, device: Optional[str] = None, warnings: Optional[List[WarningDetail]] = None) -> "MCPResponse":
        return cls(
            success=True,
            tool=tool,
            device=device,
            data=data,
            warnings=warnings or [],
            errors=[],
        )

    @classmethod
    def fail(cls, tool: str, message: str, code: str = "ERROR", device: Optional[str] = None, details: Optional[Dict[str, Any]] = None) -> "MCPResponse":
        return cls(
            success=False,
            tool=tool,
            device=device,
            data=None,
            warnings=[],
            errors=[ErrorDetail(code=code, message=message, details=details)],
        )


class PaginationParams(BaseModel):
    limit: int = Field(default=100, ge=1, le=1000, description="Quantidade máxima de registros (1 a 1000)")
    offset: int = Field(default=0, ge=0, description="Deslocamento para paginação")
