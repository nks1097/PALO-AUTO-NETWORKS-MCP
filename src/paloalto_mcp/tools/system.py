"""
Ferramentas MCP do Grupo A: SYSTEM / DEVICE (Ferramentas 1 a 10).
Permite consultar informações gerais, recursos de hardware, versões, licenças e saúde do firewall.
"""

from typing import Optional

from ..client import client
from ..models.common import MCPResponse
from ..registry import register_tool
from ..security.auth import audit_log, generate_correlation_id
from ..security.permissions import Permission, enforce_authorization


@register_tool(
    name="panos_get_system_info",
    category="system",
    permission=Permission.READ,
    description="Obtém informações gerais do firewall Palo Alto: hostname, serial, versão PAN-OS, modelo e uptime.",
)
async def panos_get_system_info(device: Optional[str] = None) -> MCPResponse:
    """Obtém informações gerais do firewall Palo Alto."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        data = await client.get_system_info()
        audit_log("panos_get_system_info", "read", device, "system_info", False, True, cid)
        return MCPResponse.ok(
            tool="panos_get_system_info",
            device=data.get("hostname", device),
            data=data,
        )
    except Exception as e:
        audit_log("panos_get_system_info", "read", device, "system_info", False, False, cid)
        return MCPResponse.fail("panos_get_system_info", str(e), device=device)


@register_tool(
    name="panos_get_system_state",
    category="system",
    permission=Permission.READ,
    description="Consulta o estado operacional detalhado dos subsistemas e variáveis de ambiente do PAN-OS.",
)
async def panos_get_system_state(filter_key: Optional[str] = None, device: Optional[str] = None) -> MCPResponse:
    """Consulta o estado operacional do sistema."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        cmd = "<show><system><state></state></system></show>"
        if filter_key:
            cmd = f"<show><system><state><filter>{filter_key}</filter></state></system></show>"
        res = await client.xml.op_command(cmd)
        data = res.get("result", {})
        audit_log("panos_get_system_state", "read", device, "system_state", False, True, cid)
        return MCPResponse.ok("panos_get_system_state", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_system_state", "read", device, "system_state", False, False, cid)
        return MCPResponse.fail("panos_get_system_state", str(e), device=device)


@register_tool(
    name="panos_get_system_resources",
    category="system",
    permission=Permission.READ,
    description="Consulta a utilização de recursos do sistema: CPU do management plane, dataplane e memória RAM.",
)
async def panos_get_system_resources(device: Optional[str] = None) -> MCPResponse:
    """Consulta a utilização de recursos de CPU e memória do firewall."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><system><resources></resources></system></show>")
        data = res.get("result", {})
        audit_log("panos_get_system_resources", "read", device, "resources", False, True, cid)
        return MCPResponse.ok("panos_get_system_resources", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_system_resources", "read", device, "resources", False, False, cid)
        return MCPResponse.fail("panos_get_system_resources", str(e), device=device)


@register_tool(
    name="panos_get_system_version",
    category="system",
    permission=Permission.READ,
    description="Obtém exclusivamente a versão do software PAN-OS e versões de assinaturas antivírus e ameaças.",
)
async def panos_get_system_version(device: Optional[str] = None) -> MCPResponse:
    """Obtém versões instaladas de software e conteúdo de segurança."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        info = await client.get_system_info()
        data = {
            "sw_version": info.get("sw-version") or info.get("sw_version"),
            "app_version": info.get("app-version") or info.get("app_version"),
            "threat_version": info.get("threat-version") or info.get("threat_version"),
            "av_version": info.get("av-version") or info.get("av_version"),
            "wildfire_version": info.get("wildfire-version") or info.get("wildfire_version"),
            "url_version": info.get("url-filtering-version") or info.get("url_filtering_version"),
        }
        audit_log("panos_get_system_version", "read", device, "version", False, True, cid)
        return MCPResponse.ok("panos_get_system_version", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_system_version", "read", device, "version", False, False, cid)
        return MCPResponse.fail("panos_get_system_version", str(e), device=device)


@register_tool(
    name="panos_get_system_uptime",
    category="system",
    permission=Permission.READ,
    description="Consulta o tempo de atividade contínuo (uptime) e horário oficial do firewall.",
)
async def panos_get_system_uptime(device: Optional[str] = None) -> MCPResponse:
    """Consulta o tempo de atividade (uptime) do firewall."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        info = await client.get_system_info()
        data = {
            "uptime": info.get("uptime"),
            "system_time": info.get("time"),
        }
        audit_log("panos_get_system_uptime", "read", device, "uptime", False, True, cid)
        return MCPResponse.ok("panos_get_system_uptime", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_system_uptime", "read", device, "uptime", False, False, cid)
        return MCPResponse.fail("panos_get_system_uptime", str(e), device=device)


@register_tool(
    name="panos_get_system_license",
    category="system",
    permission=Permission.READ,
    description="Consulta as licenças ativas, recursos contratados e datas de expiração no equipamento.",
)
async def panos_get_system_license(device: Optional[str] = None) -> MCPResponse:
    """Consulta licenças instaladas no firewall."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<request><license><info></info></license></request>")
        data = res.get("result", {})
        audit_log("panos_get_system_license", "read", device, "licenses", False, True, cid)
        return MCPResponse.ok("panos_get_system_license", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_system_license", "read", device, "licenses", False, False, cid)
        return MCPResponse.fail("panos_get_system_license", str(e), device=device)


@register_tool(
    name="panos_get_system_software",
    category="system",
    permission=Permission.READ,
    description="Lista versões de software PAN-OS disponíveis para download, instaladas e ativas.",
)
async def panos_get_system_software(device: Optional[str] = None) -> MCPResponse:
    """Lista versões de software PAN-OS disponíveis e instaladas."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<request><system><software><status></status></software></system></request>")
        data = res.get("result", {})
        audit_log("panos_get_system_software", "read", device, "software", False, True, cid)
        return MCPResponse.ok("panos_get_system_software", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_system_software", "read", device, "software", False, False, cid)
        return MCPResponse.fail("panos_get_system_software", str(e), device=device)


@register_tool(
    name="panos_get_system_disk_usage",
    category="system",
    permission=Permission.READ,
    description="Consulta o espaço livre, utilizado e pontos de montagem das partições de disco do firewall.",
)
async def panos_get_system_disk_usage(device: Optional[str] = None) -> MCPResponse:
    """Consulta utilização de espaço em disco no firewall."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><system><disk-space></disk-space></system></show>")
        data = res.get("result", {})
        audit_log("panos_get_system_disk_usage", "read", device, "disk", False, True, cid)
        return MCPResponse.ok("panos_get_system_disk_usage", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_system_disk_usage", "read", device, "disk", False, False, cid)
        return MCPResponse.fail("panos_get_system_disk_usage", str(e), device=device)


@register_tool(
    name="panos_get_system_services",
    category="system",
    permission=Permission.READ,
    description="Consulta o status dos daemons e serviços do sistema (management plane, dataplane, logging).",
)
async def panos_get_system_services(device: Optional[str] = None) -> MCPResponse:
    """Consulta o estado dos serviços e processos internos do PAN-OS."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><system><services></services></system></show>")
        data = res.get("result", {})
        audit_log("panos_get_system_services", "read", device, "services", False, True, cid)
        return MCPResponse.ok("panos_get_system_services", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_system_services", "read", device, "services", False, False, cid)
        return MCPResponse.fail("panos_get_system_services", str(e), device=device)


@register_tool(
    name="panos_get_system_info_extended",
    category="system",
    permission=Permission.READ,
    description="Retorna um diagnóstico completo e estendido consolidando informações de hardware, SO, rede e licenças.",
)
async def panos_get_system_info_extended(device: Optional[str] = None) -> MCPResponse:
    """Retorna diagnóstico completo consolidado do sistema."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        sys_info = await client.get_system_info(force_refresh=True)
        extended = {
            "system": sys_info,
            "management_ip": sys_info.get("ip-address") or sys_info.get("ip_address"),
            "model": sys_info.get("model"),
            "serial": sys_info.get("serial"),
            "sw_version": sys_info.get("sw-version") or sys_info.get("sw_version"),
            "uptime": sys_info.get("uptime"),
            "ha_enabled": sys_info.get("ha-state") is not None,
            "multi_vsys": sys_info.get("multi-vsys") == "on",
            "cloud_mode": sys_info.get("cloud-mode"),
        }
        audit_log("panos_get_system_info_extended", "read", device, "extended_info", False, True, cid)
        return MCPResponse.ok("panos_get_system_info_extended", data=extended, device=device)
    except Exception as e:
        audit_log("panos_get_system_info_extended", "read", device, "extended_info", False, False, cid)
        return MCPResponse.fail("panos_get_system_info_extended", str(e), device=device)
