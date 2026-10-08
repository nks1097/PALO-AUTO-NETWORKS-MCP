"""
Cliente base assíncrono para comunicação HTTP/HTTPS com o PAN-OS e Panorama.
"""

import xml.etree.ElementTree as ET
from typing import Any, Dict, Optional

import httpx

from ..config import settings
from ..exceptions import (
    PaloAltoAPIError,
    PaloAltoAuthenticationError,
    PaloAltoError,
    PaloAltoTimeoutError,
)
from ..logging import logger
from .retry import panos_retry


class BaseClient:
    """Cliente base gerenciador de sessões e requisições HTTP."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
        timeout: Optional[int] = None,
    ):
        self.base_url = (base_url or settings.panos_host).rstrip("/")
        self.api_key = api_key or settings.panos_api_key
        self.verify_ssl = settings.panos_verify_ssl if verify_ssl is None else verify_ssl
        self.timeout = timeout or settings.panos_timeout

        if not self.verify_ssl:
            logger.warning(
                "panos_tls_warning",
                message="Verificação SSL/TLS está desativada! Adequado apenas para ambiente de laboratório/teste.",
            )

        self._client: Optional[httpx.AsyncClient] = None

    async def get_client(self) -> httpx.AsyncClient:
        """Retorna uma instância reutilizável do AsyncClient com connection pooling vinculada ao event loop ativo."""
        import asyncio
        current_loop = asyncio.get_running_loop()
        if (
            self._client is None
            or self._client.is_closed
            or getattr(self, "_client_loop", None) is not current_loop
        ):
            self._client_loop = current_loop
            self._client = httpx.AsyncClient(
                verify=self.verify_ssl,
                timeout=httpx.Timeout(self.timeout, connect=settings.panos_connect_timeout),
                headers={"User-Agent": "PaloAlto-MCP-Server/1.0"},
            )
        return self._client

    async def close(self) -> None:
        """Encerra a sessão HTTP."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    @panos_retry
    async def execute_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
    ) -> httpx.Response:
        """Executa a requisição HTTP com retry automático para falhas transitórias."""
        client = await self.get_client()
        try:
            response = await client.request(
                method=method,
                url=url,
                params=params,
                headers=headers,
                json=json,
                data=data,
            )
            return response
        except httpx.TimeoutException as exc:
            raise PaloAltoTimeoutError(f"Timeout na requisição para {url}: {exc}") from exc
        except httpx.HTTPError as exc:
            raise PaloAltoError(f"Erro de transporte HTTP para {url}: {exc}") from exc

    def parse_xml_response(self, text: str) -> Dict[str, Any]:
        """Faz o parsing seguro do XML retornado pela API XML do PAN-OS."""
        try:
            root = ET.fromstring(text)
        except ET.ParseError as e:
            raise PaloAltoAPIError(f"Falha ao interpretar resposta XML do PAN-OS: {e}")

        status = root.attrib.get("status", "")
        code = root.attrib.get("code", "")

        if status == "error":
            # Extrair mensagem de erro
            msg_node = root.find(".//msg")
            err_msg = ""
            if msg_node is not None:
                lines = [line.text for line in msg_node.findall(".//line") if line.text]
                err_msg = " | ".join(lines) if lines else (msg_node.text or "Erro desconhecido")
            else:
                err_msg = text[:300]

            if "Invalid credentials" in err_msg or "Unauthorized" in err_msg or code == "403":
                raise PaloAltoAuthenticationError(f"Falha de autenticação no PAN-OS: {err_msg}")

            raise PaloAltoAPIError(f"Erro na API XML do PAN-OS: {err_msg}", code=f"PANOS_XML_{code or 'ERR'}")

        # Função recursiva para converter nós XML em dicionário
        def xml_to_dict(node: ET.Element) -> Any:
            children = list(node)
            if not children:
                return node.text or ""

            # Se todos os filhos tiverem a tag 'entry', tratar como lista
            if all(child.tag == "entry" for child in children):
                entries = []
                for child in children:
                    entry_dict = xml_to_dict(child)
                    if isinstance(entry_dict, dict):
                        if "name" in child.attrib:
                            entry_dict["@name"] = child.attrib["name"]
                    elif isinstance(entry_dict, str):
                        entry_dict = {"@name": child.attrib.get("name", ""), "value": entry_dict}
                    entries.append(entry_dict)
                return entries

            # Se todos os filhos tiverem a tag 'member', tratar como lista de membros
            if all(child.tag == "member" for child in children):
                return [child.text or "" for child in children]

            res: Dict[str, Any] = {}
            for child in children:
                tag = child.tag
                child_val = xml_to_dict(child)
                if tag in res:
                    if not isinstance(res[tag], list):
                        res[tag] = [res[tag]]
                    res[tag].append(child_val)
                else:
                    res[tag] = child_val
            return res

        result_node = root.find("result")
        if result_node is not None:
            return {"status": status, "result": xml_to_dict(result_node)}
        return {"status": status, "result": {}}
