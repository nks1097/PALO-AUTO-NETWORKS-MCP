"""
Cliente unificado Palo Alto Networks (PAN-OS XML + REST + Panorama).
Implementa pooling, cache leve com TTL, normalização e tratamento de versões.
"""

import time
from typing import Any, Dict, Optional

from .panorama import PanoramaClient
from .rest_api import PanosRestClient
from .xml_api import PanosXmlClient


class PaloAltoClient:
    """Cliente unificado e inteligente para PAN-OS e Panorama."""

    def __init__(
        self,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        verify_ssl: Optional[bool] = None,
    ):
        self.xml = PanosXmlClient(base_url, api_key, verify_ssl)
        self.rest = PanosRestClient(base_url, api_key, verify_ssl)
        self.panorama = PanoramaClient()
        self._cache: Dict[str, Any] = {}
        self._cache_ttl: Dict[str, float] = {}

    async def close(self) -> None:
        await self.xml.close()
        await self.rest.close()
        await self.panorama.close()

    def _get_from_cache(self, key: str) -> Optional[Any]:
        if key in self._cache and time.time() < self._cache_ttl.get(key, 0):
            return self._cache[key]
        return None

    def _set_cache(self, key: str, value: Any, ttl_seconds: float = 60.0) -> None:
        self._cache[key] = value
        self._cache_ttl[key] = time.time() + ttl_seconds

    async def get_system_info(self, force_refresh: bool = False) -> Dict[str, Any]:
        """Obtém dados de 'show system info' com cache inteligente."""
        cache_key = "system_info"
        if not force_refresh:
            cached = self._get_from_cache(cache_key)
            if cached:
                return cached

        res = await self.xml.op_command("<show><system><info></info></system></show>")
        sys_info = res.get("result", {}).get("system", {})
        self._set_cache(cache_key, sys_info, ttl_seconds=120)
        return sys_info


# Instância global padrão do cliente
client = PaloAltoClient()

__all__ = ["PaloAltoClient", "PanosXmlClient", "PanosRestClient", "PanoramaClient", "client"]
