"""
Cliente de comunicação com a REST API do PAN-OS (/restapi/v10.2/).
Suporta operações completas de CRUD para objetos de rede, serviços e políticas.
"""

from typing import Any, Dict, Optional

from ..exceptions import (
    PaloAltoAPIError,
    PaloAltoAuthenticationError,
    PaloAltoConflictError,
    PaloAltoNotFoundError,
)
from .base import BaseClient


class PanosRestClient(BaseClient):
    """Implementa as operações REST do PAN-OS."""

    def __init__(self, *args, version: str = "v10.2", **kwargs):
        super().__init__(*args, **kwargs)
        self.rest_version = version

    @property
    def rest_base(self) -> str:
        return f"{self.base_url}/restapi/{self.rest_version}"

    def _headers(self) -> Dict[str, str]:
        if not self.api_key:
            raise PaloAltoAuthenticationError("PANOS_API_KEY não configurada para requisição REST.")
        return {
            "X-PAN-KEY": self.api_key,
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def get_objects(
        self,
        endpoint: str,
        location: str = "vsys",
        vsys: str = "vsys1",
        name: Optional[str] = None,
    ) -> Any:
        """Consulta lista de objetos ou um objeto específico por nome."""
        url = f"{self.rest_base}/{endpoint}"
        params: Dict[str, Any] = {"location": location}
        if location == "vsys":
            params["vsys"] = vsys
        if name:
            params["name"] = name

        resp = await self.execute_request("GET", url, params=params, headers=self._headers())
        if resp.status_code == 404:
            raise PaloAltoNotFoundError(f"Objeto '{name or endpoint}' não encontrado.")
        if resp.status_code == 403:
            raise PaloAltoAuthenticationError("Acesso não autorizado na REST API.")

        data = resp.json()
        if data.get("@status") == "error":
            raise PaloAltoAPIError(data.get("message", "Erro retornado pela REST API"))

        result = data.get("result", {})
        if "entry" in result:
            return result["entry"]
        return result

    async def create_object(
        self,
        endpoint: str,
        payload: Dict[str, Any],
        location: str = "vsys",
        vsys: str = "vsys1",
        name: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cria um novo objeto ou regra via POST."""
        url = f"{self.rest_base}/{endpoint}"
        params: Dict[str, Any] = {"location": location}
        if location == "vsys":
            params["vsys"] = vsys
        if name:
            params["name"] = name

        body = {"entry": [payload] if isinstance(payload, dict) and "@name" in payload else payload}
        resp = await self.execute_request("POST", url, params=params, headers=self._headers(), json=body)

        if resp.status_code in (409, 400) and "already exists" in resp.text.lower():
            raise PaloAltoConflictError(f"Objeto '{name}' já existe no PAN-OS.")

        data = resp.json()
        if data.get("@status") == "error":
            raise PaloAltoAPIError(data.get("message", "Erro ao criar objeto"))
        return data

    async def update_object(
        self,
        endpoint: str,
        name: str,
        payload: Dict[str, Any],
        location: str = "vsys",
        vsys: str = "vsys1",
    ) -> Dict[str, Any]:
        """Atualiza um objeto ou regra existente via PUT."""
        url = f"{self.rest_base}/{endpoint}"
        params: Dict[str, Any] = {"location": location, "name": name}
        if location == "vsys":
            params["vsys"] = vsys

        body = {"entry": [payload] if isinstance(payload, dict) and "@name" in payload else payload}
        resp = await self.execute_request("PUT", url, params=params, headers=self._headers(), json=body)

        if resp.status_code == 404:
            raise PaloAltoNotFoundError(f"Objeto '{name}' não encontrado para atualização.")

        data = resp.json()
        if data.get("@status") == "error":
            raise PaloAltoAPIError(data.get("message", f"Erro ao atualizar objeto {name}"))
        return data

    async def delete_object(
        self,
        endpoint: str,
        name: str,
        location: str = "vsys",
        vsys: str = "vsys1",
    ) -> Dict[str, Any]:
        """Exclui um objeto ou regra existente via DELETE."""
        url = f"{self.rest_base}/{endpoint}"
        params: Dict[str, Any] = {"location": location, "name": name}
        if location == "vsys":
            params["vsys"] = vsys

        resp = await self.execute_request("DELETE", url, params=params, headers=self._headers())
        if resp.status_code == 404:
            raise PaloAltoNotFoundError(f"Objeto '{name}' não encontrado para exclusão.")

        data = resp.json()
        if data.get("@status") == "error":
            raise PaloAltoAPIError(data.get("message", f"Erro ao excluir objeto {name}"))
        return data
