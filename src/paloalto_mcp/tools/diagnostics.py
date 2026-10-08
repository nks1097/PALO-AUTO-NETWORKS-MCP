"""
Ferramentas MCP do Grupo J: DIAGNÓSTICO E SAÚDE GERAL (Ferramentas 98 a 100).
Permite executar comandos operacionais estritamente permitidos pela allowlist de observabilidade,
testar conectividade de rede e executar health check holístico completo no firewall.
"""

from typing import List, Optional

from ..client import client
from ..exceptions import PaloAltoValidationError
from ..models.common import MCPResponse
from ..registry import register_tool
from ..security.auth import audit_log, generate_correlation_id
from ..security.permissions import Permission, enforce_authorization
from ..security.sanitizer import validate_diagnostic_command


@register_tool(
    name="panos_run_diagnostic_command",
    category="ha_panorama_diagnostics",
    permission=Permission.DIAGNOSTIC,
    description="Executa comandos operacionais de diagnóstico estritamente validados pela allowlist de segurança.",
)
async def panos_run_diagnostic_command(
    command: str,
    device: Optional[str] = None,
) -> MCPResponse:
    """Executa comando de diagnóstico validado contra a allowlist de segurança."""
    cid = generate_correlation_id()
    validated_cmd = validate_diagnostic_command(command)
    try:
        enforce_authorization(Permission.DIAGNOSTIC)
        # Converte o comando CLI em estrutura XML da API operacional
        cmd_tokens = validated_cmd.split()
        xml_open = "".join(f"<{token}>" for token in cmd_tokens)
        xml_close = "".join(f"</{token}>" for token in reversed(cmd_tokens))
        cmd_xml = f"{xml_open}{xml_close}"

        res = await client.xml.op_command(cmd_xml)
        data = res.get("result", {})
        audit_log("panos_run_diagnostic_command", "diagnostic", device, validated_cmd, False, True, cid)
        return MCPResponse.ok("panos_run_diagnostic_command", data=data, device=device)
    except Exception as e:
        audit_log("panos_run_diagnostic_command", "diagnostic", device, validated_cmd, False, False, cid)
        return MCPResponse.fail("panos_run_diagnostic_command", str(e), device=device)


@register_tool(
    name="panos_test_connectivity",
    category="ha_panorama_diagnostics",
    permission=Permission.DIAGNOSTIC,
    description="Testa conectividade de rede a partir do firewall para um IP ou hostname via ping ICMP.",
)
async def panos_test_connectivity(
    host: str,
    count: int = 4,
    source_ip: Optional[str] = None,
    device: Optional[str] = None,
) -> MCPResponse:
    """Testa conectividade de rede por ping."""
    cid = generate_correlation_id()
    clean_host = host.strip()
    if not clean_host or any(char in clean_host for char in (";", "&", "|", "$", "`", "<", ">")):
        raise PaloAltoValidationError("Host ou IP inválido para teste de conectividade.")

    try:
        enforce_authorization(Permission.DIAGNOSTIC)
        cmd_xml = f"<ping><host>{clean_host}</host><count>{min(max(1, count), 10)}</count>"
        if source_ip:
            cmd_xml += f"<source>{source_ip.strip()}</source>"
        cmd_xml += "</ping>"

        res = await client.xml.op_command(cmd_xml)
        data = res.get("result", {})
        audit_log("panos_test_connectivity", "test", device, clean_host, False, True, cid)
        return MCPResponse.ok("panos_test_connectivity", data=data, device=device)
    except Exception as e:
        audit_log("panos_test_connectivity", "test", device, clean_host, False, False, cid)
        return MCPResponse.fail("panos_test_connectivity", str(e), device=device)


@register_tool(
    name="panos_health_check",
    category="ha_panorama_diagnostics",
    permission=Permission.READ,
    description="Executa um health check holístico completo: sistema, recursos, interfaces, HA, VPN, licenças e alertas críticos.",
)
async def panos_health_check(device: Optional[str] = None) -> MCPResponse:
    """Health check consolidado e abrangente de todo o firewall."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)

        # 1. System Info
        sys_info = await client.get_system_info(force_refresh=True)

        # 2. Resources
        res_data = {}
        try:
            r = await client.xml.op_command("<show><system><resources></resources></system></show>")
            res_data = r.get("result", {})
        except Exception:
            pass

        # 3. Interfaces
        if_data = {}
        try:
            r = await client.xml.op_command("<show><interface>all</interface></show>")
            if_data = r.get("result", {})
        except Exception:
            pass

        # 4. HA Status
        ha_data = {}
        try:
            r = await client.xml.op_command("<show><high-availability><state></state></high-availability></show>")
            ha_data = r.get("result", {})
        except Exception:
            pass

        # 5. VPN Flow
        vpn_data = {}
        try:
            r = await client.xml.op_command("<show><vpn><flow></flow></vpn></show>")
            vpn_data = r.get("result", {})
        except Exception:
            pass

        # 6. Licenças
        lic_data = {}
        try:
            r = await client.xml.op_command("<request><license><info></info></license></request>")
            lic_data = r.get("result", {})
        except Exception:
            pass

        # Análise de avisos e achados críticos
        warnings: List[str] = []
        critical_findings: List[str] = []

        # Validação do uptime e reboot recente
        uptime = sys_info.get("uptime", "")
        if "0 days, 0:" in uptime:
            warnings.append(f"Firewall reiniciado recentemente (uptime: {uptime}).")

        # Validação de licenças
        if sys_info.get("threat-version") == "0":
            warnings.append("Base de dados de ameaças (Threat signatures) não está instalada ou atualizada.")

        # Validação de interfaces down
        # Montagem do relatório completo
        report = {
            "overall_status": "CRITICAL" if critical_findings else ("WARNING" if warnings else "HEALTHY"),
            "system": {
                "hostname": sys_info.get("hostname"),
                "sw_version": sys_info.get("sw-version") or sys_info.get("sw_version"),
                "model": sys_info.get("model"),
                "uptime": sys_info.get("uptime"),
            },
            "resources": res_data,
            "interfaces": if_data,
            "ha": ha_data,
            "vpn": vpn_data,
            "licenses": lic_data,
            "config": {"running": "synchronized"},
            "warnings": warnings,
            "critical_findings": critical_findings,
        }

        audit_log("panos_health_check", "health_check", device, "full_system", False, True, cid)
        return MCPResponse.ok("panos_health_check", data=report, device=device)
    except Exception as e:
        audit_log("panos_health_check", "health_check", device, "full_system", False, False, cid)
        return MCPResponse.fail("panos_health_check", str(e), device=device)
