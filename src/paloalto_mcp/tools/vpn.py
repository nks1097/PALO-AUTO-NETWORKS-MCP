"""
Ferramentas MCP do Grupo H: VPN / GLOBALPROTECT (Ferramentas 71 a 80).
Permite listar e diagnosticar túneis IPSec, IKE Gateways, portais e usuários GlobalProtect,
além de executar testes seguros de conectividade e negociação de túneis.
"""

from typing import Optional

from ..client import client
from ..models.common import MCPResponse
from ..registry import register_tool
from ..security.auth import audit_log, generate_correlation_id
from ..security.permissions import Permission, enforce_authorization
from ..security.sanitizer import sanitize_object_name


@register_tool(
    name="panos_list_ipsec_tunnels",
    category="vpn",
    permission=Permission.READ,
    description="Lista todos os túneis IPSec VPN configurados e seus estados atuais de SA (Fase 2).",
)
async def panos_list_ipsec_tunnels(device: Optional[str] = None) -> MCPResponse:
    """Lista todos os túneis IPSec configurados e ativos."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><vpn><flow></flow></vpn></show>")
        data = res.get("result", {})
        audit_log("panos_list_ipsec_tunnels", "list", device, "ipsec_tunnels", False, True, cid)
        return MCPResponse.ok("panos_list_ipsec_tunnels", data=data, device=device)
    except Exception as e:
        audit_log("panos_list_ipsec_tunnels", "list", device, "ipsec_tunnels", False, False, cid)
        return MCPResponse.fail("panos_list_ipsec_tunnels", str(e), device=device)


@register_tool(
    name="panos_get_ipsec_tunnel",
    category="vpn",
    permission=Permission.READ,
    description="Consulta o status detalhado, contadores de pacotes e parâmetros de criptografia de um túnel IPSec.",
)
async def panos_get_ipsec_tunnel(name: str, device: Optional[str] = None) -> MCPResponse:
    """Consulta detalhes de um túnel IPSec específico."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        cmd = f"<show><vpn><ipsec-sa><tunnel>{clean_name}</tunnel></ipsec-sa></vpn></show>"
        res = await client.xml.op_command(cmd)
        data = res.get("result", {})
        audit_log("panos_get_ipsec_tunnel", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_get_ipsec_tunnel", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_ipsec_tunnel", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_get_ipsec_tunnel", str(e), device=device)


@register_tool(
    name="panos_list_ike_gateways",
    category="vpn",
    permission=Permission.READ,
    description="Lista todos os IKE Gateways configurados e suas associações de segurança de Fase 1 (IKEv1 / IKEv2).",
)
async def panos_list_ike_gateways(device: Optional[str] = None) -> MCPResponse:
    """Lista todos os IKE Gateways configurados."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><vpn><ike-sa></ike-sa></vpn></show>")
        data = res.get("result", {})
        audit_log("panos_list_ike_gateways", "list", device, "ike_gateways", False, True, cid)
        return MCPResponse.ok("panos_list_ike_gateways", data=data, device=device)
    except Exception as e:
        audit_log("panos_list_ike_gateways", "list", device, "ike_gateways", False, False, cid)
        return MCPResponse.fail("panos_list_ike_gateways", str(e), device=device)


@register_tool(
    name="panos_get_ike_gateway",
    category="vpn",
    permission=Permission.READ,
    description="Consulta o status de negociação, algoritmos propostos e IP do peer de um IKE Gateway específico.",
)
async def panos_get_ike_gateway(name: str, device: Optional[str] = None) -> MCPResponse:
    """Consulta detalhes de um IKE Gateway específico."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        cmd = f"<show><vpn><ike-sa><gateway>{clean_name}</gateway></ike-sa></vpn></show>"
        res = await client.xml.op_command(cmd)
        data = res.get("result", {})
        audit_log("panos_get_ike_gateway", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_get_ike_gateway", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_ike_gateway", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_get_ike_gateway", str(e), device=device)


@register_tool(
    name="panos_get_globalprotect_status",
    category="vpn",
    permission=Permission.READ,
    description="Consulta o status operacional geral dos portais e gateways do GlobalProtect.",
)
async def panos_get_globalprotect_status(device: Optional[str] = None) -> MCPResponse:
    """Consulta o status operacional do GlobalProtect."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><global-protect-gateway><gateway></gateway></global-protect-gateway></show>")
        data = res.get("result", {})
        audit_log("panos_get_globalprotect_status", "get", device, "gp_status", False, True, cid)
        return MCPResponse.ok("panos_get_globalprotect_status", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_globalprotect_status", "get", device, "gp_status", False, False, cid)
        return MCPResponse.fail("panos_get_globalprotect_status", str(e), device=device)


@register_tool(
    name="panos_list_globalprotect_users",
    category="vpn",
    permission=Permission.READ,
    description="Lista os usuários conectados remotamente via GlobalProtect, incluindo IP alocado e tempo de login.",
)
async def panos_list_globalprotect_users(
    gateway: Optional[str] = None,
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista usuários conectados no GlobalProtect."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        cmd = "<show><global-protect-gateway><current-user></current-user></global-protect-gateway></show>"
        if gateway:
            gw_clean = sanitize_object_name(gateway)
            cmd = f"<show><global-protect-gateway><current-user><gateway>{gw_clean}</gateway></current-user></global-protect-gateway></show>"
        res = await client.xml.op_command(cmd)
        data = res.get("result", {})
        audit_log("panos_list_globalprotect_users", "list", device, gateway or "all", False, True, cid)
        return MCPResponse.ok("panos_list_globalprotect_users", data=data, device=device)
    except Exception as e:
        audit_log("panos_list_globalprotect_users", "list", device, gateway or "all", False, False, cid)
        return MCPResponse.fail("panos_list_globalprotect_users", str(e), device=device)


@register_tool(
    name="panos_list_globalprotect_gateways",
    category="vpn",
    permission=Permission.READ,
    description="Lista os GlobalProtect Gateways configurados e suas configurações de pool de endereços IP.",
)
async def panos_list_globalprotect_gateways(device: Optional[str] = None) -> MCPResponse:
    """Lista os Gateways GlobalProtect configurados."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><global-protect-gateway><statistics></statistics></global-protect-gateway></show>")
        data = res.get("result", {})
        audit_log("panos_list_globalprotect_gateways", "list", device, "gp_gateways", False, True, cid)
        return MCPResponse.ok("panos_list_globalprotect_gateways", data=data, device=device)
    except Exception as e:
        audit_log("panos_list_globalprotect_gateways", "list", device, "gp_gateways", False, False, cid)
        return MCPResponse.fail("panos_list_globalprotect_gateways", str(e), device=device)


@register_tool(
    name="panos_get_vpn_statistics",
    category="vpn",
    permission=Permission.READ,
    description="Retorna estatísticas consolidadas de VPN: túneis ativos, caídos, IKE SAs e contagem de usuários remotos.",
)
async def panos_get_vpn_statistics(device: Optional[str] = None) -> MCPResponse:
    """Retorna métricas consolidadas de VPN para observabilidade e AI."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        flow_res = await client.xml.op_command("<show><vpn><flow></flow></vpn></show>")
        flow_data = flow_res.get("result", {})

        stats = {
            "total_ipsec_tunnels": 0,
            "active_tunnels": 0,
            "down_tunnels": 0,
            "flow_info": flow_data,
        }

        # Extração de contagens se presentes
        entries = flow_data.get("IPSec", {}).get("entry", [])
        if isinstance(entries, dict):
            entries = [entries]
        if isinstance(entries, list):
            stats["total_ipsec_tunnels"] = len(entries)
            stats["active_tunnels"] = sum(1 for e in entries if e.get("state") in ("active", "up"))
            stats["down_tunnels"] = stats["total_ipsec_tunnels"] - stats["active_tunnels"]

        audit_log("panos_get_vpn_statistics", "get", device, "vpn_stats", False, True, cid)
        return MCPResponse.ok("panos_get_vpn_statistics", data=stats, device=device)
    except Exception as e:
        audit_log("panos_get_vpn_statistics", "get", device, "vpn_stats", False, False, cid)
        return MCPResponse.fail("panos_get_vpn_statistics", str(e), device=device)


@register_tool(
    name="panos_test_ipsec_tunnel",
    category="vpn",
    permission=Permission.DIAGNOSTIC,
    description="Executa teste diagnóstico de negociação e verificação de integridade de um túnel IPSec.",
)
async def panos_test_ipsec_tunnel(name: str, device: Optional[str] = None) -> MCPResponse:
    """Testa a negociação de SA de um túnel IPSec."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.DIAGNOSTIC)
        cmd = f"<test><vpn><ipsec-sa><tunnel>{clean_name}</tunnel></ipsec-sa></vpn></test>"
        res = await client.xml.op_command(cmd)
        data = res.get("result", {})
        audit_log("panos_test_ipsec_tunnel", "test", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_test_ipsec_tunnel", data=data, device=device)
    except Exception as e:
        audit_log("panos_test_ipsec_tunnel", "test", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_test_ipsec_tunnel", str(e), device=device)


@register_tool(
    name="panos_test_ike_gateway",
    category="vpn",
    permission=Permission.DIAGNOSTIC,
    description="Executa teste diagnóstico de negociação e handshake IKE Fase 1 de um gateway específico.",
)
async def panos_test_ike_gateway(name: str, device: Optional[str] = None) -> MCPResponse:
    """Testa o handshake IKE Fase 1 de um gateway."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.DIAGNOSTIC)
        cmd = f"<test><vpn><ike-sa><gateway>{clean_name}</gateway></ike-sa></vpn></test>"
        res = await client.xml.op_command(cmd)
        data = res.get("result", {})
        audit_log("panos_test_ike_gateway", "test", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_test_ike_gateway", data=data, device=device)
    except Exception as e:
        audit_log("panos_test_ike_gateway", "test", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_test_ike_gateway", str(e), device=device)
