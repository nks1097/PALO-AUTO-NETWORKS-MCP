"""
Ferramentas MCP do Grupo G: NETWORK (Ferramentas 61 a 70).
Permite inspecionar interfaces de rede, zonas de segurança, roteadores virtuais,
tabela de rotas, tabela ARP, tabela MAC e contadores de tráfego de interface.
"""

from typing import Optional

from ..client import client
from ..models.common import MCPResponse
from ..registry import register_tool
from ..security.auth import audit_log, generate_correlation_id
from ..security.permissions import Permission, enforce_authorization
from ..security.sanitizer import sanitize_object_name


@register_tool(
    name="panos_list_interfaces",
    category="network",
    permission=Permission.READ,
    description="Lista todas as interfaces físicas e lógicas configuradas (ethernet, vlan, loopback, tunnel).",
)
async def panos_list_interfaces(device: Optional[str] = None) -> MCPResponse:
    """Lista todas as interfaces do firewall."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><interface>all</interface></show>")
        data = res.get("result", {})
        audit_log("panos_list_interfaces", "list", device, "interface_all", False, True, cid)
        return MCPResponse.ok("panos_list_interfaces", data=data, device=device)
    except Exception as e:
        audit_log("panos_list_interfaces", "list", device, "interface_all", False, False, cid)
        return MCPResponse.fail("panos_list_interfaces", str(e), device=device)


@register_tool(
    name="panos_get_interface",
    category="network",
    permission=Permission.READ,
    description="Consulta o status operacional, IP, MTU, duplex e estatísticas de uma interface específica.",
)
async def panos_get_interface(name: str, device: Optional[str] = None) -> MCPResponse:
    """Consulta detalhes de uma interface específica."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        cmd = f"<show><interface>{clean_name}</interface></show>"
        res = await client.xml.op_command(cmd)
        data = res.get("result", {})
        audit_log("panos_get_interface", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_get_interface", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_interface", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_get_interface", str(e), device=device)


@register_tool(
    name="panos_list_zones",
    category="network",
    permission=Permission.READ,
    description="Lista as Security Zones (zonas de segurança) e interfaces associadas a cada uma.",
)
async def panos_list_zones(
    vsys: str = "vsys1",
    location: str = "vsys",
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista as Security Zones configuradas."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Network/Zones", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])
        audit_log("panos_list_zones", "list", device, "Network/Zones", False, True, cid)
        return MCPResponse.ok("panos_list_zones", data={"total": len(items), "zones": items}, device=device)
    except Exception as e:
        audit_log("panos_list_zones", "list", device, "Network/Zones", False, False, cid)
        return MCPResponse.fail("panos_list_zones", str(e), device=device)


@register_tool(
    name="panos_get_zone",
    category="network",
    permission=Permission.READ,
    description="Consulta os detalhes, tipo de rede e perfis de proteção de uma zona de segurança específica.",
)
async def panos_get_zone(
    name: str,
    vsys: str = "vsys1",
    location: str = "vsys",
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta detalhes de uma zona de segurança por nome."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        data = await client.rest.get_objects("Network/Zones", location=location, vsys=vsys, name=clean_name)
        audit_log("panos_get_zone", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_get_zone", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_zone", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_get_zone", str(e), device=device)


@register_tool(
    name="panos_list_virtual_routers",
    category="network",
    permission=Permission.READ,
    description="Lista os Virtual Routers (VRs) e instâncias de roteamento configuradas no firewall.",
)
async def panos_list_virtual_routers(
    location: str = "vsys",
    vsys: str = "vsys1",
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista os Virtual Routers configurados."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Network/VirtualRouters", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])
        audit_log("panos_list_virtual_routers", "list", device, "Network/VirtualRouters", False, True, cid)
        return MCPResponse.ok("panos_list_virtual_routers", data={"total": len(items), "virtual_routers": items}, device=device)
    except Exception as e:
        audit_log("panos_list_virtual_routers", "list", device, "Network/VirtualRouters", False, False, cid)
        return MCPResponse.fail("panos_list_virtual_routers", str(e), device=device)


@register_tool(
    name="panos_get_virtual_router",
    category="network",
    permission=Permission.READ,
    description="Consulta as interfaces, protocolos dinâmicos (OSPF, BGP) e rotas estáticas de um Virtual Router.",
)
async def panos_get_virtual_router(
    name: str,
    location: str = "vsys",
    vsys: str = "vsys1",
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta detalhes de um Virtual Router por nome."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        data = await client.rest.get_objects("Network/VirtualRouters", location=location, vsys=vsys, name=clean_name)
        audit_log("panos_get_virtual_router", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_get_virtual_router", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_virtual_router", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_get_virtual_router", str(e), device=device)


@register_tool(
    name="panos_get_routing_table",
    category="network",
    permission=Permission.READ,
    description="Consulta a tabela de roteamento ativa do kernel (FIB/RIB) com prefixos, gateways e flags.",
)
async def panos_get_routing_table(
    virtual_router: Optional[str] = None,
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta a tabela de roteamento ativa."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        cmd = "<show><routing><route></route></routing></show>"
        if virtual_router:
            vr_clean = sanitize_object_name(virtual_router)
            cmd = f"<show><routing><route><virtual-router>{vr_clean}</virtual-router></route></routing></show>"
        res = await client.xml.op_command(cmd)
        data = res.get("result", {})
        audit_log("panos_get_routing_table", "get", device, "routing_table", False, True, cid)
        return MCPResponse.ok("panos_get_routing_table", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_routing_table", "get", device, "routing_table", False, False, cid)
        return MCPResponse.fail("panos_get_routing_table", str(e), device=device)


@register_tool(
    name="panos_get_arp_table",
    category="network",
    permission=Permission.READ,
    description="Consulta a tabela ARP ativa com associações de IP para MAC address e interfaces.",
)
async def panos_get_arp_table(
    interface: Optional[str] = None,
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta a tabela ARP do firewall."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        cmd = "<show><arp><entry name='all'/></arp></show>"
        if interface:
            if_clean = sanitize_object_name(interface)
            cmd = f"<show><arp><entry name='{if_clean}'/></arp></show>"
        res = await client.xml.op_command(cmd)
        data = res.get("result", {})
        audit_log("panos_get_arp_table", "get", device, "arp_table", False, True, cid)
        return MCPResponse.ok("panos_get_arp_table", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_arp_table", "get", device, "arp_table", False, False, cid)
        return MCPResponse.fail("panos_get_arp_table", str(e), device=device)


@register_tool(
    name="panos_get_mac_table",
    category="network",
    permission=Permission.READ,
    description="Consulta a tabela de endereços MAC aprendidos em interfaces Layer 2 e VLANs.",
)
async def panos_get_mac_table(
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta a tabela MAC do firewall."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><mac><all></all></mac></show>")
        data = res.get("result", {})
        audit_log("panos_get_mac_table", "get", device, "mac_table", False, True, cid)
        return MCPResponse.ok("panos_get_mac_table", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_mac_table", "get", device, "mac_table", False, False, cid)
        return MCPResponse.fail("panos_get_mac_table", str(e), device=device)


@register_tool(
    name="panos_get_interface_counters",
    category="network",
    permission=Permission.READ,
    description="Consulta contadores estatísticos detalhados de pacotes, bytes, drops e erros por interface.",
)
async def panos_get_interface_counters(
    name: Optional[str] = None,
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta contadores e métricas de tráfego das interfaces."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        if name:
            if_clean = sanitize_object_name(name)
            cmd = f"<show><counter><interface>{if_clean}</interface></counter></show>"
        else:
            cmd = "<show><counter><interface>all</interface></counter></show>"
        res = await client.xml.op_command(cmd)
        data = res.get("result", {})
        audit_log("panos_get_interface_counters", "get", device, name or "all", False, True, cid)
        return MCPResponse.ok("panos_get_interface_counters", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_interface_counters", "get", device, name or "all", False, False, cid)
        return MCPResponse.fail("panos_get_interface_counters", str(e), device=device)
