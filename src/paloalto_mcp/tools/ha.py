"""
Ferramentas MCP do Grupo J: ALTA DISPONIBILIDADE - HA (Ferramentas 91 e 92).
Permite monitorar o status do cluster HA, sincronização de configurações e conectividade com o peer.
"""

from typing import Optional

from ..client import client
from ..models.common import MCPResponse
from ..registry import register_tool
from ..security.auth import audit_log, generate_correlation_id
from ..security.permissions import Permission, enforce_authorization


@register_tool(
    name="panos_get_ha_status",
    category="ha_panorama_diagnostics",
    permission=Permission.READ,
    description="Consulta o status de Alta Disponibilidade (HA): active/passive, sincronização de estado e versão.",
)
async def panos_get_ha_status(device: Optional[str] = None) -> MCPResponse:
    """Consulta o status geral do cluster de alta disponibilidade (HA)."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><high-availability><state></state></high-availability></show>")
        data = res.get("result", {})
        audit_log("panos_get_ha_status", "get", device, "ha_state", False, True, cid)
        return MCPResponse.ok("panos_get_ha_status", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_ha_status", "get", device, "ha_state", False, False, cid)
        return MCPResponse.fail("panos_get_ha_status", str(e), device=device)


@register_tool(
    name="panos_get_ha_peer_status",
    category="ha_panorama_diagnostics",
    permission=Permission.READ,
    description="Consulta o status de conectividade, heartbeat e compatibilidade do nó peer no cluster HA.",
)
async def panos_get_ha_peer_status(device: Optional[str] = None) -> MCPResponse:
    """Consulta detalhes específicos do nó peer de HA."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><high-availability><all></all></high-availability></show>")
        ha_all = res.get("result", {}).get("group", {})
        peer_info = ha_all.get("peer-info", {}) if isinstance(ha_all, dict) else {}
        audit_log("panos_get_ha_peer_status", "get", device, "ha_peer", False, True, cid)
        return MCPResponse.ok("panos_get_ha_peer_status", data=peer_info or ha_all, device=device)
    except Exception as e:
        audit_log("panos_get_ha_peer_status", "get", device, "ha_peer", False, False, cid)
        return MCPResponse.fail("panos_get_ha_peer_status", str(e), device=device)
