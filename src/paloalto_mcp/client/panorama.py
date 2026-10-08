"""
Cliente para operações específicas do Panorama (Gerenciamento centralizado de firewalls).
"""

from typing import Any, Dict, List, Optional

from ..config import settings
from .xml_api import PanosXmlClient


class PanoramaClient(PanosXmlClient):
    """Cliente especializado para gerenciamento centralizado com Panorama."""

    def __init__(self, *args, **kwargs):
        super().__init__(
            base_url=settings.panorama_host or settings.panos_host,
            api_key=settings.panorama_api_key or settings.panos_api_key,
            *args,
            **kwargs,
        )

    async def list_device_groups(self) -> List[Dict[str, Any]]:
        """Lista os Device Groups configurados no Panorama."""
        xpath = "/config/devices/entry[@name='localhost.localdomain']/device-group"
        try:
            res = await self.get_config(xpath)
            groups = res.get("result", {}).get("entry", [])
            if isinstance(groups, dict):
                return [groups]
            return groups if isinstance(groups, list) else []
        except Exception:
            return []

    async def get_device_group(self, name: str) -> Optional[Dict[str, Any]]:
        """Consulta um Device Group específico pelo nome."""
        xpath = f"/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='{name}']"
        res = await self.get_config(xpath)
        entry = res.get("result", {}).get("entry")
        if isinstance(entry, list) and entry:
            return entry[0]
        return entry if isinstance(entry, dict) else None

    async def list_managed_devices(self) -> List[Dict[str, Any]]:
        """Lista os firewalls gerenciados conectados ao Panorama."""
        try:
            res = await self.op_command("<show><devices><all></all></devices></show>")
            devices = res.get("result", {}).get("devices", {}).get("entry", [])
            if isinstance(devices, dict):
                return [devices]
            return devices if isinstance(devices, list) else []
        except Exception:
            # Fallback se executado diretamente em firewall local
            return []

    async def list_templates(self) -> List[Dict[str, Any]]:
        """Lista os Templates de configuração do Panorama."""
        xpath = "/config/devices/entry[@name='localhost.localdomain']/template"
        try:
            res = await self.get_config(xpath)
            templates = res.get("result", {}).get("entry", [])
            if isinstance(templates, dict):
                return [templates]
            return templates if isinstance(templates, list) else []
        except Exception:
            return []

    async def list_template_stacks(self) -> List[Dict[str, Any]]:
        """Lista as Template Stacks configuradas no Panorama."""
        xpath = "/config/devices/entry[@name='localhost.localdomain']/template-stack"
        try:
            res = await self.get_config(xpath)
            stacks = res.get("result", {}).get("entry", [])
            if isinstance(stacks, dict):
                return [stacks]
            return stacks if isinstance(stacks, list) else []
        except Exception:
            return []
