"""
Ferramentas MCP do Grupo I: LOGS / SESSIONS (Ferramentas 81 a 90).
Permite consultar logs estruturados de tráfego, ameaças, sistema, auditoria de configuração,
URL e autenticação, além de inspecionar sessões ativas do firewall e top aplicações.
"""

from typing import Optional

from ..client import client
from ..exceptions import PaloAltoValidationError
from ..models.common import MCPResponse
from ..registry import register_tool
from ..security.auth import audit_log, generate_correlation_id
from ..security.permissions import Permission, enforce_authorization


def _build_log_filter(
    source: Optional[str] = None,
    destination: Optional[str] = None,
    application: Optional[str] = None,
    action: Optional[str] = None,
    rule: Optional[str] = None,
    query: Optional[str] = None,
) -> Optional[str]:
    """Constrói de forma segura a query de filtro do PAN-OS a partir de parâmetros estruturados."""
    clauses = []
    if query:
        clauses.append(f"({query})")
    if source:
        clauses.append(f"(addr.src in {source})")
    if destination:
        clauses.append(f"(addr.dst in {destination})")
    if application:
        clauses.append(f"(app eq {application})")
    if action:
        clauses.append(f"(action eq {action})")
    if rule:
        clauses.append(f"(rule eq '{rule}')")

    return " and ".join(clauses) if clauses else None


@register_tool(
    name="panos_query_traffic_logs",
    category="logs_sessions",
    permission=Permission.READ,
    description="Pesquisa logs de tráfego (Traffic Logs) com filtros estruturados por IP, aplicação, regra ou ação.",
)
async def panos_query_traffic_logs(
    source: Optional[str] = None,
    destination: Optional[str] = None,
    application: Optional[str] = None,
    action: Optional[str] = None,
    rule: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Pesquisa logs de tráfego no PAN-OS."""
    cid = generate_correlation_id()
    if limit > 1000:
        raise PaloAltoValidationError("Limite máximo permitido para busca de logs é 1000 registros.")

    q = _build_log_filter(source, destination, application, action, rule, query)
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.query_logs("traffic", query=q, nlogs=limit, skip=offset)
        data = res.get("result", {})
        audit_log("panos_query_traffic_logs", "query", device, "traffic_logs", False, True, cid)
        return MCPResponse.ok("panos_query_traffic_logs", data=data, device=device)
    except Exception as e:
        audit_log("panos_query_traffic_logs", "query", device, "traffic_logs", False, False, cid)
        return MCPResponse.fail("panos_query_traffic_logs", str(e), device=device)


@register_tool(
    name="panos_query_threat_logs",
    category="logs_sessions",
    permission=Permission.READ,
    description="Pesquisa logs de ameaças (Threat Logs), incluindo antivírus, vulnerabilidades, spyware e exploits.",
)
async def panos_query_threat_logs(
    source: Optional[str] = None,
    destination: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Pesquisa logs de ameaças detectadas."""
    cid = generate_correlation_id()
    if limit > 1000:
        raise PaloAltoValidationError("Limite máximo permitido é 1000 registros.")

    q = _build_log_filter(source=source, destination=destination, query=query)
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.query_logs("threat", query=q, nlogs=limit, skip=offset)
        data = res.get("result", {})
        audit_log("panos_query_threat_logs", "query", device, "threat_logs", False, True, cid)
        return MCPResponse.ok("panos_query_threat_logs", data=data, device=device)
    except Exception as e:
        audit_log("panos_query_threat_logs", "query", device, "threat_logs", False, False, cid)
        return MCPResponse.fail("panos_query_threat_logs", str(e), device=device)


@register_tool(
    name="panos_query_system_logs",
    category="logs_sessions",
    permission=Permission.READ,
    description="Pesquisa logs de eventos do sistema operacional (falhas, alertas de hardware, interfaces, HA).",
)
async def panos_query_system_logs(
    query: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Pesquisa logs de sistema."""
    cid = generate_correlation_id()
    if limit > 1000:
        raise PaloAltoValidationError("Limite máximo permitido é 1000 registros.")
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.query_logs("system", query=query, nlogs=limit, skip=offset)
        data = res.get("result", {})
        audit_log("panos_query_system_logs", "query", device, "system_logs", False, True, cid)
        return MCPResponse.ok("panos_query_system_logs", data=data, device=device)
    except Exception as e:
        audit_log("panos_query_system_logs", "query", device, "system_logs", False, False, cid)
        return MCPResponse.fail("panos_query_system_logs", str(e), device=device)


@register_tool(
    name="panos_query_config_logs",
    category="logs_sessions",
    permission=Permission.READ,
    description="Pesquisa logs de auditoria de alterações de configuração realizadas por administradores.",
)
async def panos_query_config_logs(
    admin: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Pesquisa logs de auditoria de configuração."""
    cid = generate_correlation_id()
    if limit > 1000:
        raise PaloAltoValidationError("Limite máximo permitido é 1000 registros.")

    clauses = []
    if query:
        clauses.append(f"({query})")
    if admin:
        clauses.append(f"(admin eq '{admin}')")
    q = " and ".join(clauses) if clauses else None

    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.query_logs("config", query=q, nlogs=limit, skip=offset)
        data = res.get("result", {})
        audit_log("panos_query_config_logs", "query", device, "config_logs", False, True, cid)
        return MCPResponse.ok("panos_query_config_logs", data=data, device=device)
    except Exception as e:
        audit_log("panos_query_config_logs", "query", device, "config_logs", False, False, cid)
        return MCPResponse.fail("panos_query_config_logs", str(e), device=device)


@register_tool(
    name="panos_query_url_logs",
    category="logs_sessions",
    permission=Permission.READ,
    description="Pesquisa logs de filtragem de URL e acessos web efetuados na rede.",
)
async def panos_query_url_logs(
    source: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Pesquisa logs de filtragem de URL."""
    cid = generate_correlation_id()
    if limit > 1000:
        raise PaloAltoValidationError("Limite máximo permitido é 1000 registros.")

    q = _build_log_filter(source=source, query=query)
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.query_logs("url", query=q, nlogs=limit, skip=offset)
        data = res.get("result", {})
        audit_log("panos_query_url_logs", "query", device, "url_logs", False, True, cid)
        return MCPResponse.ok("panos_query_url_logs", data=data, device=device)
    except Exception as e:
        audit_log("panos_query_url_logs", "query", device, "url_logs", False, False, cid)
        return MCPResponse.fail("panos_query_url_logs", str(e), device=device)


@register_tool(
    name="panos_query_auth_logs",
    category="logs_sessions",
    permission=Permission.READ,
    description="Pesquisa logs de eventos de autenticação de usuários e serviços (GlobalProtect, Captive Portal).",
)
async def panos_query_auth_logs(
    user: Optional[str] = None,
    query: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Pesquisa logs de autenticação."""
    cid = generate_correlation_id()
    if limit > 1000:
        raise PaloAltoValidationError("Limite máximo permitido é 1000 registros.")

    clauses = []
    if query:
        clauses.append(f"({query})")
    if user:
        clauses.append(f"(user eq '{user}')")
    q = " and ".join(clauses) if clauses else None

    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.query_logs("auth", query=q, nlogs=limit, skip=offset)
        data = res.get("result", {})
        audit_log("panos_query_auth_logs", "query", device, "auth_logs", False, True, cid)
        return MCPResponse.ok("panos_query_auth_logs", data=data, device=device)
    except Exception as e:
        audit_log("panos_query_auth_logs", "query", device, "auth_logs", False, False, cid)
        return MCPResponse.fail("panos_query_auth_logs", str(e), device=device)


@register_tool(
    name="panos_get_active_sessions",
    category="logs_sessions",
    permission=Permission.READ,
    description="Consulta as sessões de rede ativas que estão fluindo no dataplane do firewall.",
)
async def panos_get_active_sessions(device: Optional[str] = None) -> MCPResponse:
    """Consulta sessões ativas no dataplane."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><session><all></all></session></show>")
        data = res.get("result", {})
        audit_log("panos_get_active_sessions", "get", device, "sessions_all", False, True, cid)
        return MCPResponse.ok("panos_get_active_sessions", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_active_sessions", "get", device, "sessions_all", False, False, cid)
        return MCPResponse.fail("panos_get_active_sessions", str(e), device=device)


@register_tool(
    name="panos_find_sessions",
    category="logs_sessions",
    permission=Permission.READ,
    description="Pesquisa sessões ativas com filtros por IP de origem/destino, portas ou protocolo de transporte.",
)
async def panos_find_sessions(
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    source_port: Optional[int] = None,
    destination_port: Optional[int] = None,
    protocol: Optional[str] = None,
    device: Optional[str] = None,
) -> MCPResponse:
    """Pesquisa sessões com filtros específicos."""
    cid = generate_correlation_id()
    filter_elements = []
    if source_ip:
        filter_elements.append(f"<source>{source_ip}</source>")
    if destination_ip:
        filter_elements.append(f"<destination>{destination_ip}</destination>")
    if source_port:
        filter_elements.append(f"<source-port>{source_port}</source-port>")
    if destination_port:
        filter_elements.append(f"<destination-port>{destination_port}</destination-port>")
    if protocol:
        filter_elements.append(f"<protocol>{protocol}</protocol>")

    filter_xml = "".join(filter_elements)
    cmd = f"<show><session><all><filter>{filter_xml}</filter></all></session></show>" if filter_xml else "<show><session><all></all></session></show>"

    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command(cmd)
        data = res.get("result", {})
        audit_log("panos_find_sessions", "find", device, "sessions_filter", False, True, cid)
        return MCPResponse.ok("panos_find_sessions", data=data, device=device)
    except Exception as e:
        audit_log("panos_find_sessions", "find", device, "sessions_filter", False, False, cid)
        return MCPResponse.fail("panos_find_sessions", str(e), device=device)


@register_tool(
    name="panos_get_session_statistics",
    category="logs_sessions",
    permission=Permission.READ,
    description="Consulta estatísticas gerais de sessões: contagem de ativas, máxima suportada, taxa por segundo e throughput.",
)
async def panos_get_session_statistics(device: Optional[str] = None) -> MCPResponse:
    """Consulta estatísticas de capacidade e uso da tabela de sessões."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><session><info></info></session></show>")
        data = res.get("result", {})
        audit_log("panos_get_session_statistics", "get", device, "session_info", False, True, cid)
        return MCPResponse.ok("panos_get_session_statistics", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_session_statistics", "get", device, "session_info", False, False, cid)
        return MCPResponse.fail("panos_get_session_statistics", str(e), device=device)


@register_tool(
    name="panos_get_top_applications",
    category="logs_sessions",
    permission=Permission.READ,
    description="Identifica as aplicações com maior consumo de largura de banda e número de conexões (ACC Analytics).",
)
async def panos_get_top_applications(device: Optional[str] = None) -> MCPResponse:
    """Consulta as principais aplicações em tráfego."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><session><meter></meter></session></show>")
        data = res.get("result", {})
        audit_log("panos_get_top_applications", "get", device, "top_apps", False, True, cid)
        return MCPResponse.ok("panos_get_top_applications", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_top_applications", "get", device, "top_apps", False, False, cid)
        return MCPResponse.fail("panos_get_top_applications", str(e), device=device)
