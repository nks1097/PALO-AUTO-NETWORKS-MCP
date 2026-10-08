"""
Cliente de comunicação com a API XML do PAN-OS.
Responsável por comandos operacionais, queries XPath, visualização de candidate/running config e commits.
"""

from typing import Any, Dict, Optional

from ..exceptions import PaloAltoAuthenticationError, PaloAltoValidationError
from ..security.sanitizer import sanitize_xpath
from .base import BaseClient


class PanosXmlClient(BaseClient):
    """Implementa as operações da PAN-OS XML API (/api/)."""

    async def op_command(self, cmd_xml: str) -> Dict[str, Any]:
        """
        Executa um comando operacional via XML API.
        Exemplo: <show><system><info></info></system></show>
        """
        if not self.api_key:
            raise PaloAltoAuthenticationError("PANOS_API_KEY não foi configurada.")

        url = f"{self.base_url}/api/"
        params = {
            "type": "op",
            "cmd": cmd_xml,
            "key": self.api_key,
        }

        resp = await self.execute_request("GET", url, params=params)
        return self.parse_xml_response(resp.text)

    async def get_config(self, xpath: str) -> Dict[str, Any]:
        """Consulta configuração em um determinado caminho XPath."""
        clean_xpath = sanitize_xpath(xpath)
        url = f"{self.base_url}/api/"
        params = {
            "type": "config",
            "action": "get",
            "xpath": clean_xpath,
            "key": self.api_key,
        }
        resp = await self.execute_request("GET", url, params=params)
        return self.parse_xml_response(resp.text)

    async def show_candidate_config(self, xpath: str = "/config") -> Dict[str, Any]:
        """Consulta configuração candidata (candidate config)."""
        clean_xpath = sanitize_xpath(xpath)
        url = f"{self.base_url}/api/"
        params = {
            "type": "config",
            "action": "show",
            "xpath": clean_xpath,
            "key": self.api_key,
        }
        resp = await self.execute_request("GET", url, params=params)
        return self.parse_xml_response(resp.text)

    async def set_config(self, xpath: str, element_xml: str) -> Dict[str, Any]:
        """Adiciona ou mescla configuração em um determinado XPath."""
        clean_xpath = sanitize_xpath(xpath)
        url = f"{self.base_url}/api/"
        params = {
            "type": "config",
            "action": "set",
            "xpath": clean_xpath,
            "element": element_xml,
            "key": self.api_key,
        }
        resp = await self.execute_request("POST", url, params=params)
        return self.parse_xml_response(resp.text)

    async def edit_config(self, xpath: str, element_xml: str) -> Dict[str, Any]:
        """Substitui configuração existente em um determinado XPath."""
        clean_xpath = sanitize_xpath(xpath)
        url = f"{self.base_url}/api/"
        params = {
            "type": "config",
            "action": "edit",
            "xpath": clean_xpath,
            "element": element_xml,
            "key": self.api_key,
        }
        resp = await self.execute_request("POST", url, params=params)
        return self.parse_xml_response(resp.text)

    async def delete_config(self, xpath: str) -> Dict[str, Any]:
        """Exclui configuração em um determinado XPath."""
        clean_xpath = sanitize_xpath(xpath)
        url = f"{self.base_url}/api/"
        params = {
            "type": "config",
            "action": "delete",
            "xpath": clean_xpath,
            "key": self.api_key,
        }
        resp = await self.execute_request("POST", url, params=params)
        return self.parse_xml_response(resp.text)

    async def commit_config(self, description: Optional[str] = None) -> Dict[str, Any]:
        """Dispara um commit de configuração no PAN-OS."""
        cmd = "<commit></commit>"
        if description:
            desc_clean = description.replace("<", "").replace(">", "").strip()
            cmd = f"<commit><description>{desc_clean}</description></commit>"

        url = f"{self.base_url}/api/"
        params = {
            "type": "commit",
            "cmd": cmd,
            "key": self.api_key,
        }
        resp = await self.execute_request("POST", url, params=params)
        return self.parse_xml_response(resp.text)

    async def query_logs(
        self,
        log_type: str,
        query: Optional[str] = None,
        nlogs: int = 50,
        skip: int = 0,
    ) -> Dict[str, Any]:
        """Consulta logs estruturados (traffic, threat, system, config, url, auth)."""
        valid_log_types = {"traffic", "threat", "system", "config", "url", "data", "auth"}
        if log_type not in valid_log_types:
            raise PaloAltoValidationError(f"Tipo de log inválido: {log_type}. Tipos válidos: {valid_log_types}")

        url = f"{self.base_url}/api/"
        params = {
            "type": "log",
            "log-type": log_type,
            "nlogs": min(max(1, nlogs), 1000),
            "skip": max(0, skip),
            "key": self.api_key,
        }
        if query:
            params["query"] = query

        resp = await self.execute_request("GET", url, params=params)
        return self.parse_xml_response(resp.text)
