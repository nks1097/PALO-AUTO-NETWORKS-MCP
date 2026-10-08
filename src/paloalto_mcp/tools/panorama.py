"""
Ferramentas MCP do Grupo J: PANORAMA (Ferramentas 93 a 97).
Permite administrar e inspecionar Device Groups, Templates, Template Stacks e firewalls gerenciados pelo Panorama.
"""

from typing import Optional

from ..client import client
from ..exceptions import PaloAltoNotFoundError
from ..models.common import MCPResponse
from ..registry import register_tool
from ..security.auth import audit_log, generate_correlation_id
from ..security.permissions import Permission, enforce_authorization
from ..security.sanitizer import sanitize_object_name


@register_tool(
    name="panorama_list_device_groups",
    category="ha_panorama_diagnostics",
    permission=Permission.READ,
    is_panorama=True,
    description="Lista todos os Device Groups configurados no Panorama para gerenciamento em lote de políticas.",
)
async def panorama_list_device_groups(device: Optional[str] = None) -> MCPResponse:
    """Lista os Device Groups do Panorama."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        groups = await client.panorama.list_device_groups()
        audit_log("panorama_list_device_groups", "list", device, "device_groups", False, True, cid)
        return MCPResponse.ok("panorama_list_device_groups", data={"total": len(groups), "device_groups": groups}, device=device)
    except Exception as e:
        audit_log("panorama_list_device_groups", "list", device, "device_groups", False, False, cid)
        return MCPResponse.fail("panorama_list_device_groups", str(e), device=device)


@register_tool(
    name="panorama_get_device_group",
    category="ha_panorama_diagnostics",
    permission=Permission.READ,
    is_panorama=True,
    description="Consulta a definição, dispositivos membros e hierarquia de um Device Group específico no Panorama.",
)
async def panorama_get_device_group(name: str, device: Optional[str] = None) -> MCPResponse:
    """Consulta detalhes de um Device Group no Panorama por nome."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        dg = await client.panorama.get_device_group(clean_name)
        if not dg:
            raise PaloAltoNotFoundError(f"Device Group '{clean_name}' não encontrado no Panorama.")
        audit_log("panorama_get_device_group", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panorama_get_device_group", data=dg, device=device)
    except Exception as e:
        audit_log("panorama_get_device_group", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panorama_get_device_group", str(e), device=device)


@register_tool(
    name="panorama_list_devices",
    category="ha_panorama_diagnostics",
    permission=Permission.READ,
    is_panorama=True,
    description="Lista todos os firewalls registrados e gerenciados centralmente pelo Panorama.",
)
async def panorama_list_devices(device: Optional[str] = None) -> MCPResponse:
    """Lista dispositivos gerenciados pelo Panorama."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        devices = await client.panorama.list_managed_devices()
        audit_log("panorama_list_devices", "list", device, "managed_devices", False, True, cid)
        return MCPResponse.ok("panorama_list_devices", data={"total": len(devices), "devices": devices}, device=device)
    except Exception as e:
        audit_log("panorama_list_devices", "list", device, "managed_devices", False, False, cid)
        return MCPResponse.fail("panorama_list_devices", str(e), device=device)


@register_tool(
    name="panorama_list_templates",
    category="ha_panorama_diagnostics",
    permission=Permission.READ,
    is_panorama=True,
    description="Lista os Templates de configuração de rede e dispositivos do Panorama.",
)
async def panorama_list_templates(device: Optional[str] = None) -> MCPResponse:
    """Lista Templates do Panorama."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        templates = await client.panorama.list_templates()
        audit_log("panorama_list_templates", "list", device, "templates", False, True, cid)
        return MCPResponse.ok("panorama_list_templates", data={"total": len(templates), "templates": templates}, device=device)
    except Exception as e:
        audit_log("panorama_list_templates", "list", device, "templates", False, False, cid)
        return MCPResponse.fail("panorama_list_templates", str(e), device=device)


@register_tool(
    name="panorama_list_template_stacks",
    category="ha_panorama_diagnostics",
    permission=Permission.READ,
    is_panorama=True,
    description="Lista as Template Stacks (pilhas de templates com ordem de sobreposição) do Panorama.",
)
async def panorama_list_template_stacks(device: Optional[str] = None) -> MCPResponse:
    """Lista Template Stacks do Panorama."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        stacks = await client.panorama.list_template_stacks()
        audit_log("panorama_list_template_stacks", "list", device, "template_stacks", False, True, cid)
        return MCPResponse.ok("panorama_list_template_stacks", data={"total": len(stacks), "template_stacks": stacks}, device=device)
    except Exception as e:
        audit_log("panorama_list_template_stacks", "list", device, "template_stacks", False, False, cid)
        return MCPResponse.fail("panorama_list_template_stacks", str(e), device=device)
