"""
Ferramentas MCP dos Grupos E e F: POLÍTICAS DE SEGURANÇA E NAT/OUTRAS POLÍTICAS (Ferramentas 41 a 60).
Permite listar, consultar, criar, atualizar, mover, habilitar/desabilitar, buscar e auditar regras de segurança,
bem como administrar regras de NAT, PBF, Decryption, Autenticação e QoS.
"""

from typing import Any, Dict, List, Optional

from ..client import client
from ..exceptions import PaloAltoNotFoundError, PaloAltoValidationError
from ..models.common import DryRunResult, MCPResponse
from ..registry import register_tool
from ..security.auth import audit_log, generate_correlation_id
from ..security.permissions import Permission, enforce_authorization
from ..security.sanitizer import sanitize_object_name

# ============================================================================
# GRUPO E — SECURITY POLICY (41-50)
# ============================================================================

@register_tool(
    name="panos_list_security_rules",
    category="security_policy",
    permission=Permission.READ,
    description="Lista as regras de segurança (Security Rules) configuradas no firewall com filtros de paginação.",
)
async def panos_list_security_rules(
    vsys: str = "vsys1",
    location: str = "vsys",
    limit: int = 100,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista regras de política de segurança."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Policies/SecurityRules", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])
        paginated = items[offset : offset + limit]
        audit_log("panos_list_security_rules", "list", device, "Policies/SecurityRules", False, True, cid)
        return MCPResponse.ok("panos_list_security_rules", data={"total": len(items), "rules": paginated}, device=device)
    except Exception as e:
        audit_log("panos_list_security_rules", "list", device, "Policies/SecurityRules", False, False, cid)
        return MCPResponse.fail("panos_list_security_rules", str(e), device=device)


@register_tool(
    name="panos_get_security_rule",
    category="security_policy",
    permission=Permission.READ,
    description="Consulta todos os parâmetros e detalhes de uma regra de segurança específica por nome.",
)
async def panos_get_security_rule(
    name: str,
    vsys: str = "vsys1",
    location: str = "vsys",
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta detalhes de uma regra de segurança pelo nome."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        data = await client.rest.get_objects("Policies/SecurityRules", location=location, vsys=vsys, name=clean_name)
        audit_log("panos_get_security_rule", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_get_security_rule", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_security_rule", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_get_security_rule", str(e), device=device)


@register_tool(
    name="panos_create_security_rule",
    category="security_policy",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Cria uma nova regra de política de segurança com suporte a zonas, IPs, apps, serviços e perfis. Suporta dry_run.",
)
async def panos_create_security_rule(
    name: str,
    from_zones: List[str],
    to_zones: List[str],
    source: List[str],
    destination: List[str],
    application: Optional[List[str]] = None,
    service: Optional[List[str]] = None,
    category: Optional[List[str]] = None,
    action: str = "allow",
    description: Optional[str] = None,
    disabled: bool = False,
    profile_setting: Optional[Dict[str, Any]] = None,
    tags: Optional[List[str]] = None,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Cria uma regra de segurança completa."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    action_clean = action.lower().strip()
    if action_clean not in ("allow", "deny", "drop", "reset-client", "reset-server", "reset-both"):
        raise PaloAltoValidationError(f"Ação inválida: {action}. Use allow, deny, drop, reset-client, reset-server ou reset-both.")

    payload: Dict[str, Any] = {
        "@name": clean_name,
        "from": {"member": from_zones},
        "to": {"member": to_zones},
        "source": {"member": source},
        "destination": {"member": destination},
        "source-user": {"member": ["any"]},
        "category": {"member": category or ["any"]},
        "application": {"member": application or ["any"]},
        "service": {"member": service or ["application-default"]},
        "action": action_clean,
        "disabled": "yes" if disabled else "no",
        "log-start": "no",
        "log-end": "yes",
    }
    if description:
        payload["description"] = description
    if profile_setting:
        payload["profile-setting"] = profile_setting
    if tags:
        payload["tag"] = {"member": tags}

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="CREATE_SECURITY_RULE",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Policies/SecurityRules",
                parameters=payload,
                risk_level="MEDIUM",
                predicted_changes={"action": "create_rule", "name": clean_name, "rule_action": action_clean},
            )
            audit_log("panos_create_security_rule", "create", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_create_security_rule", data=sim.model_dump(), device=device)

        res = await client.rest.create_object("Policies/SecurityRules", payload=payload, location=location, vsys=vsys, name=clean_name)
        audit_log("panos_create_security_rule", "create", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_create_security_rule", data=res, device=device)
    except Exception as e:
        audit_log("panos_create_security_rule", "create", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_create_security_rule", str(e), device=device)


@register_tool(
    name="panos_update_security_rule",
    category="security_policy",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Atualiza zonas, endereços, aplicações ou ação de uma regra de segurança existente. Suporta dry_run.",
)
async def panos_update_security_rule(
    name: str,
    from_zones: Optional[List[str]] = None,
    to_zones: Optional[List[str]] = None,
    source: Optional[List[str]] = None,
    destination: Optional[List[str]] = None,
    application: Optional[List[str]] = None,
    service: Optional[List[str]] = None,
    category: Optional[List[str]] = None,
    action: Optional[str] = None,
    description: Optional[str] = None,
    disabled: Optional[bool] = None,
    profile_setting: Optional[Dict[str, Any]] = None,
    tags: Optional[List[str]] = None,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Atualiza uma regra de segurança existente."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    payload: Dict[str, Any] = {"@name": clean_name}

    if from_zones:
        payload["from"] = {"member": from_zones}
    if to_zones:
        payload["to"] = {"member": to_zones}
    if source:
        payload["source"] = {"member": source}
    if destination:
        payload["destination"] = {"member": destination}
    if application:
        payload["application"] = {"member": application}
    if service:
        payload["service"] = {"member": service}
    if category:
        payload["category"] = {"member": category}
    if action:
        payload["action"] = action.lower().strip()
    if disabled is not None:
        payload["disabled"] = "yes" if disabled else "no"
    if description:
        payload["description"] = description
    if profile_setting:
        payload["profile-setting"] = profile_setting
    if tags:
        payload["tag"] = {"member": tags}

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="UPDATE_SECURITY_RULE",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Policies/SecurityRules",
                parameters=payload,
                risk_level="MEDIUM",
                predicted_changes={"action": "update_rule", "name": clean_name},
            )
            audit_log("panos_update_security_rule", "update", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_update_security_rule", data=sim.model_dump(), device=device)

        res = await client.rest.update_object("Policies/SecurityRules", name=clean_name, payload=payload, location=location, vsys=vsys)
        audit_log("panos_update_security_rule", "update", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_update_security_rule", data=res, device=device)
    except Exception as e:
        audit_log("panos_update_security_rule", "update", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_update_security_rule", str(e), device=device)


@register_tool(
    name="panos_delete_security_rule",
    category="security_policy",
    permission=Permission.DELETE,
    destructive=True,
    supports_dry_run=True,
    description="Exclui uma regra de política de segurança do firewall. Requer confirm=true.",
)
async def panos_delete_security_rule(
    name: str,
    confirm: bool = False,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Exclui uma regra de segurança com confirmação obrigatória."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.DELETE, destructive=True, confirmed=confirm, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="DELETE_SECURITY_RULE",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Policies/SecurityRules",
                parameters={"name": clean_name, "confirm": confirm},
                risk_level="HIGH",
                predicted_changes={"action": "delete_rule", "name": clean_name},
            )
            audit_log("panos_delete_security_rule", "delete", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_delete_security_rule", data=sim.model_dump(), device=device)

        res = await client.rest.delete_object("Policies/SecurityRules", name=clean_name, location=location, vsys=vsys)
        audit_log("panos_delete_security_rule", "delete", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_delete_security_rule", data=res, device=device)
    except Exception as e:
        audit_log("panos_delete_security_rule", "delete", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_delete_security_rule", str(e), device=device)


@register_tool(
    name="panos_move_security_rule",
    category="security_policy",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Muda a ordem de prioridade de uma regra de segurança (top, bottom, before, after). Suporta dry_run.",
)
async def panos_move_security_rule(
    name: str,
    where: str,
    dst: Optional[str] = None,
    vsys: str = "vsys1",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Move uma regra de segurança para alterar a ordem de avaliação."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    where_clean = where.lower().strip()
    if where_clean not in ("top", "bottom", "before", "after"):
        raise PaloAltoValidationError("Posição inválida. Use 'top', 'bottom', 'before' ou 'after'.")

    xpath = f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{vsys}']/rulebase/security/rules/entry[@name='{clean_name}']"
    params: Dict[str, Any] = {"type": "config", "action": "move", "xpath": xpath, "where": where_clean}
    if dst:
        params["dst"] = sanitize_object_name(dst)

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="MOVE_SECURITY_RULE",
                target_object=clean_name,
                endpoint="/api/?type=config&action=move",
                parameters=params,
                risk_level="MEDIUM",
                predicted_changes={"action": "reorder_rule", "name": clean_name, "where": where_clean, "relative_to": dst},
            )
            audit_log("panos_move_security_rule", "move", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_move_security_rule", data=sim.model_dump(), device=device)

        url = f"{client.xml.base_url}/api/"
        params["key"] = client.xml.api_key
        resp = await client.xml.execute_request("POST", url, params=params)
        res = client.xml.parse_xml_response(resp.text)
        audit_log("panos_move_security_rule", "move", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_move_security_rule", data=res, device=device)
    except Exception as e:
        audit_log("panos_move_security_rule", "move", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_move_security_rule", str(e), device=device)


@register_tool(
    name="panos_enable_security_rule",
    category="security_policy",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Habilita uma regra de segurança desativada. Suporta dry_run.",
)
async def panos_enable_security_rule(
    name: str,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Habilita uma regra de segurança."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="ENABLE_SECURITY_RULE",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Policies/SecurityRules",
                parameters={"name": clean_name, "disabled": "no"},
                risk_level="MEDIUM",
                predicted_changes={"action": "enable_rule", "name": clean_name},
            )
            audit_log("panos_enable_security_rule", "enable", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_enable_security_rule", data=sim.model_dump(), device=device)

        res = await client.rest.update_object("Policies/SecurityRules", name=clean_name, payload={"@name": clean_name, "disabled": "no"}, location=location, vsys=vsys)
        audit_log("panos_enable_security_rule", "enable", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_enable_security_rule", data=res, device=device)
    except Exception as e:
        audit_log("panos_enable_security_rule", "enable", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_enable_security_rule", str(e), device=device)


@register_tool(
    name="panos_disable_security_rule",
    category="security_policy",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Desabilita temporariamente uma regra de segurança sem excluí-la. Suporta dry_run.",
)
async def panos_disable_security_rule(
    name: str,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Desabilita uma regra de segurança."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="DISABLE_SECURITY_RULE",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Policies/SecurityRules",
                parameters={"name": clean_name, "disabled": "yes"},
                risk_level="MEDIUM",
                predicted_changes={"action": "disable_rule", "name": clean_name},
            )
            audit_log("panos_disable_security_rule", "disable", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_disable_security_rule", data=sim.model_dump(), device=device)

        res = await client.rest.update_object("Policies/SecurityRules", name=clean_name, payload={"@name": clean_name, "disabled": "yes"}, location=location, vsys=vsys)
        audit_log("panos_disable_security_rule", "disable", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_disable_security_rule", data=res, device=device)
    except Exception as e:
        audit_log("panos_disable_security_rule", "disable", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_disable_security_rule", str(e), device=device)


@register_tool(
    name="panos_find_security_rule",
    category="security_policy",
    permission=Permission.READ,
    description="Pesquisa regras de segurança por critérios: zona de origem/destino, IP, aplicação, serviço ou ação.",
)
async def panos_find_security_rule(
    from_zone: Optional[str] = None,
    to_zone: Optional[str] = None,
    source_ip: Optional[str] = None,
    dest_ip: Optional[str] = None,
    application: Optional[str] = None,
    action: Optional[str] = None,
    vsys: str = "vsys1",
    location: str = "vsys",
    device: Optional[str] = None,
) -> MCPResponse:
    """Pesquisa inteligente de regras de segurança com filtros estruturados."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Policies/SecurityRules", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])

        matched = []
        for rule in items:
            # Filtro por from_zone
            if from_zone:
                rzones = rule.get("from", {}).get("member", [])
                if "any" not in rzones and from_zone not in rzones:
                    continue
            # Filtro por to_zone
            if to_zone:
                tzones = rule.get("to", {}).get("member", [])
                if "any" not in tzones and to_zone not in tzones:
                    continue
            # Filtro por source_ip
            if source_ip:
                srcs = rule.get("source", {}).get("member", [])
                if "any" not in srcs and source_ip not in srcs:
                    continue
            # Filtro por dest_ip
            if dest_ip:
                dsts = rule.get("destination", {}).get("member", [])
                if "any" not in dsts and dest_ip not in dsts:
                    continue
            # Filtro por application
            if application:
                apps = rule.get("application", {}).get("member", [])
                if "any" not in apps and application not in apps:
                    continue
            # Filtro por action
            if action:
                if rule.get("action", "").lower() != action.lower():
                    continue

            matched.append(rule)

        audit_log("panos_find_security_rule", "find", device, "Policies/SecurityRules", False, True, cid)
        return MCPResponse.ok("panos_find_security_rule", data={"matched_count": len(matched), "rules": matched}, device=device)
    except Exception as e:
        audit_log("panos_find_security_rule", "find", device, "Policies/SecurityRules", False, False, cid)
        return MCPResponse.fail("panos_find_security_rule", str(e), device=device)


@register_tool(
    name="panos_analyze_security_rule",
    category="security_policy",
    permission=Permission.READ,
    description="Analisa a postura de segurança de uma regra: identifica shadowing, source/dest any, ausência de profile e risco.",
)
async def panos_analyze_security_rule(
    name: str,
    vsys: str = "vsys1",
    location: str = "vsys",
    device: Optional[str] = None,
) -> MCPResponse:
    """Auditoria e análise de conformidade de uma regra de segurança para IA."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        rule_data = await client.rest.get_objects("Policies/SecurityRules", location=location, vsys=vsys, name=clean_name)
        if isinstance(rule_data, list) and rule_data:
            rule = rule_data[0]
        elif isinstance(rule_data, dict):
            rule = rule_data
        else:
            raise PaloAltoNotFoundError(f"Regra '{clean_name}' não encontrada.")

        srcs = rule.get("source", {}).get("member", [])
        dsts = rule.get("destination", {}).get("member", [])
        apps = rule.get("application", {}).get("member", [])
        services = rule.get("service", {}).get("member", [])
        action = rule.get("action", "allow")
        profiles = rule.get("profile-setting")

        src_any = "any" in srcs
        dst_any = "any" in dsts
        app_any = "any" in apps
        srv_any = "any" in services

        permissive_reasons = []
        recommendations = []
        risk_score = 0

        if action == "allow":
            if src_any and dst_any:
                permissive_reasons.append("Origem e Destino definidos como 'any'")
                risk_score += 40
            elif src_any or dst_any:
                permissive_reasons.append("Origem ou Destino indefinido ('any')")
                risk_score += 20

            if app_any:
                permissive_reasons.append("Aplicação definida como 'any' (App-ID não aproveitado)")
                recommendations.append("Especifique aplicações conhecidas ao invés de 'any'")
                risk_score += 25

            if srv_any:
                permissive_reasons.append("Serviço definido como 'any' (portas irrestritas)")
                recommendations.append("Utilize 'application-default' ou objetos de serviço específicos")
                risk_score += 15

            if not profiles:
                permissive_reasons.append("Nenhum Security Profile associado (Antivirus, Vulnerability, Anti-Spyware)")
                recommendations.append("Associe um grupo de Security Profiles para inspecionar conteúdo de segurança")
                risk_score += 30

        risk_level = "LOW"
        if risk_score >= 70:
            risk_level = "CRITICAL"
        elif risk_score >= 40:
            risk_level = "HIGH"
        elif risk_score >= 20:
            risk_level = "MEDIUM"

        analysis = {
            "rule_name": clean_name,
            "action": action,
            "disabled": rule.get("disabled") == "yes",
            "source_any": src_any,
            "destination_any": dst_any,
            "application_any": app_any,
            "service_any": srv_any,
            "has_security_profile": profiles is not None,
            "is_overly_permissive": len(permissive_reasons) > 0,
            "permissive_reasons": permissive_reasons,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "recommendations": recommendations,
        }

        audit_log("panos_analyze_security_rule", "analyze", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_analyze_security_rule", data=analysis, device=device)
    except Exception as e:
        audit_log("panos_analyze_security_rule", "analyze", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_analyze_security_rule", str(e), device=device)


# ============================================================================
# GRUPO F — NAT / OUTRAS POLÍTICAS (51-60)
# ============================================================================

@register_tool(
    name="panos_list_nat_rules",
    category="nat_policy",
    permission=Permission.READ,
    description="Lista todas as políticas de tradução de endereço de rede (NAT Rules) configuradas no PAN-OS.",
)
async def panos_list_nat_rules(
    vsys: str = "vsys1",
    location: str = "vsys",
    limit: int = 100,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista NAT Rules configuradas."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Policies/NatRules", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])
        paginated = items[offset : offset + limit]
        audit_log("panos_list_nat_rules", "list", device, "Policies/NatRules", False, True, cid)
        return MCPResponse.ok("panos_list_nat_rules", data={"total": len(items), "rules": paginated}, device=device)
    except Exception as e:
        audit_log("panos_list_nat_rules", "list", device, "Policies/NatRules", False, False, cid)
        return MCPResponse.fail("panos_list_nat_rules", str(e), device=device)


@register_tool(
    name="panos_get_nat_rule",
    category="nat_policy",
    permission=Permission.READ,
    description="Consulta os detalhes de uma regra NAT específica pelo nome (origem, destino e tradução).",
)
async def panos_get_nat_rule(
    name: str,
    vsys: str = "vsys1",
    location: str = "vsys",
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta detalhes de uma NAT Rule por nome."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        data = await client.rest.get_objects("Policies/NatRules", location=location, vsys=vsys, name=clean_name)
        audit_log("panos_get_nat_rule", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_get_nat_rule", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_nat_rule", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_get_nat_rule", str(e), device=device)


@register_tool(
    name="panos_create_nat_rule",
    category="nat_policy",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Cria uma nova regra NAT (Source NAT, Destination NAT ou DIPP). Suporta dry_run.",
)
async def panos_create_nat_rule(
    name: str,
    from_zones: List[str],
    to_zones: List[str],
    source: List[str],
    destination: List[str],
    service: str = "any",
    source_translation: Optional[Dict[str, Any]] = None,
    destination_translation: Optional[Dict[str, Any]] = None,
    description: Optional[str] = None,
    disabled: bool = False,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Cria uma NAT Rule."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    payload: Dict[str, Any] = {
        "@name": clean_name,
        "from": {"member": from_zones},
        "to": {"member": to_zones},
        "source": {"member": source},
        "destination": {"member": destination},
        "service": service,
        "disabled": "yes" if disabled else "no",
    }
    if source_translation:
        payload["source-translation"] = source_translation
    if destination_translation:
        payload["destination-translation"] = destination_translation
    if description:
        payload["description"] = description

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="CREATE_NAT_RULE",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Policies/NatRules",
                parameters=payload,
                risk_level="MEDIUM",
                predicted_changes={"action": "create_nat_rule", "name": clean_name},
            )
            audit_log("panos_create_nat_rule", "create", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_create_nat_rule", data=sim.model_dump(), device=device)

        res = await client.rest.create_object("Policies/NatRules", payload=payload, location=location, vsys=vsys, name=clean_name)
        audit_log("panos_create_nat_rule", "create", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_create_nat_rule", data=res, device=device)
    except Exception as e:
        audit_log("panos_create_nat_rule", "create", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_create_nat_rule", str(e), device=device)


@register_tool(
    name="panos_update_nat_rule",
    category="nat_policy",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Atualiza configurações de tradução ou zonas de uma regra NAT existente. Suporta dry_run.",
)
async def panos_update_nat_rule(
    name: str,
    from_zones: Optional[List[str]] = None,
    to_zones: Optional[List[str]] = None,
    source: Optional[List[str]] = None,
    destination: Optional[List[str]] = None,
    service: Optional[str] = None,
    source_translation: Optional[Dict[str, Any]] = None,
    destination_translation: Optional[Dict[str, Any]] = None,
    description: Optional[str] = None,
    disabled: Optional[bool] = None,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Atualiza uma NAT Rule existente."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    payload: Dict[str, Any] = {"@name": clean_name}
    if from_zones:
        payload["from"] = {"member": from_zones}
    if to_zones:
        payload["to"] = {"member": to_zones}
    if source:
        payload["source"] = {"member": source}
    if destination:
        payload["destination"] = {"member": destination}
    if service:
        payload["service"] = service
    if source_translation:
        payload["source-translation"] = source_translation
    if destination_translation:
        payload["destination-translation"] = destination_translation
    if disabled is not None:
        payload["disabled"] = "yes" if disabled else "no"
    if description:
        payload["description"] = description

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="UPDATE_NAT_RULE",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Policies/NatRules",
                parameters=payload,
                risk_level="MEDIUM",
                predicted_changes={"action": "update_nat_rule", "name": clean_name},
            )
            audit_log("panos_update_nat_rule", "update", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_update_nat_rule", data=sim.model_dump(), device=device)

        res = await client.rest.update_object("Policies/NatRules", name=clean_name, payload=payload, location=location, vsys=vsys)
        audit_log("panos_update_nat_rule", "update", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_update_nat_rule", data=res, device=device)
    except Exception as e:
        audit_log("panos_update_nat_rule", "update", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_update_nat_rule", str(e), device=device)


@register_tool(
    name="panos_delete_nat_rule",
    category="nat_policy",
    permission=Permission.DELETE,
    destructive=True,
    supports_dry_run=True,
    description="Exclui uma regra NAT do firewall. Requer confirm=true.",
)
async def panos_delete_nat_rule(
    name: str,
    confirm: bool = False,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Exclui uma NAT Rule com confirmação obrigatória."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.DELETE, destructive=True, confirmed=confirm, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="DELETE_NAT_RULE",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Policies/NatRules",
                parameters={"name": clean_name, "confirm": confirm},
                risk_level="HIGH",
                predicted_changes={"action": "delete_nat_rule", "name": clean_name},
            )
            audit_log("panos_delete_nat_rule", "delete", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_delete_nat_rule", data=sim.model_dump(), device=device)

        res = await client.rest.delete_object("Policies/NatRules", name=clean_name, location=location, vsys=vsys)
        audit_log("panos_delete_nat_rule", "delete", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_delete_nat_rule", data=res, device=device)
    except Exception as e:
        audit_log("panos_delete_nat_rule", "delete", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_delete_nat_rule", str(e), device=device)


@register_tool(
    name="panos_list_pbf_rules",
    category="nat_policy",
    permission=Permission.READ,
    description="Lista todas as regras de redirecionamento de política (Policy Based Forwarding - PBF).",
)
async def panos_list_pbf_rules(
    vsys: str = "vsys1",
    location: str = "vsys",
    limit: int = 100,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista regras PBF."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Policies/PolicyBasedForwardingRules", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])
        paginated = items[offset : offset + limit]
        audit_log("panos_list_pbf_rules", "list", device, "Policies/PbfRules", False, True, cid)
        return MCPResponse.ok("panos_list_pbf_rules", data={"total": len(items), "rules": paginated}, device=device)
    except Exception as e:
        audit_log("panos_list_pbf_rules", "list", device, "Policies/PbfRules", False, False, cid)
        return MCPResponse.fail("panos_list_pbf_rules", str(e), device=device)


@register_tool(
    name="panos_get_pbf_rule",
    category="nat_policy",
    permission=Permission.READ,
    description="Consulta detalhes e interface de saída de uma regra PBF específica por nome.",
)
async def panos_get_pbf_rule(
    name: str,
    vsys: str = "vsys1",
    location: str = "vsys",
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta detalhes de uma regra PBF por nome."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        data = await client.rest.get_objects("Policies/PolicyBasedForwardingRules", location=location, vsys=vsys, name=clean_name)
        audit_log("panos_get_pbf_rule", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_get_pbf_rule", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_pbf_rule", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_get_pbf_rule", str(e), device=device)


@register_tool(
    name="panos_list_decryption_rules",
    category="nat_policy",
    permission=Permission.READ,
    description="Lista as políticas de descriptografia SSL (Decryption Policies) configuradas no firewall.",
)
async def panos_list_decryption_rules(
    vsys: str = "vsys1",
    location: str = "vsys",
    limit: int = 100,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista Decryption Policies."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Policies/DecryptionRules", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])
        paginated = items[offset : offset + limit]
        audit_log("panos_list_decryption_rules", "list", device, "Policies/DecryptionRules", False, True, cid)
        return MCPResponse.ok("panos_list_decryption_rules", data={"total": len(items), "rules": paginated}, device=device)
    except Exception as e:
        audit_log("panos_list_decryption_rules", "list", device, "Policies/DecryptionRules", False, False, cid)
        return MCPResponse.fail("panos_list_decryption_rules", str(e), device=device)


@register_tool(
    name="panos_list_authentication_rules",
    category="nat_policy",
    permission=Permission.READ,
    description="Lista as políticas de autenticação e captive portal (Authentication Policies).",
)
async def panos_list_authentication_rules(
    vsys: str = "vsys1",
    location: str = "vsys",
    limit: int = 100,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista Authentication Policies."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Policies/AuthenticationRules", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])
        paginated = items[offset : offset + limit]
        audit_log("panos_list_authentication_rules", "list", device, "Policies/AuthenticationRules", False, True, cid)
        return MCPResponse.ok("panos_list_authentication_rules", data={"total": len(items), "rules": paginated}, device=device)
    except Exception as e:
        audit_log("panos_list_authentication_rules", "list", device, "Policies/AuthenticationRules", False, False, cid)
        return MCPResponse.fail("panos_list_authentication_rules", str(e), device=device)


@register_tool(
    name="panos_list_qos_rules",
    category="nat_policy",
    permission=Permission.READ,
    description="Lista as políticas de qualidade de serviço (QoS Policies) e limitação de tráfego configuradas.",
)
async def panos_list_qos_rules(
    vsys: str = "vsys1",
    location: str = "vsys",
    limit: int = 100,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista QoS Policies."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Policies/QoSRules", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])
        paginated = items[offset : offset + limit]
        audit_log("panos_list_qos_rules", "list", device, "Policies/QoSRules", False, True, cid)
        return MCPResponse.ok("panos_list_qos_rules", data={"total": len(items), "rules": paginated}, device=device)
    except Exception as e:
        audit_log("panos_list_qos_rules", "list", device, "Policies/QoSRules", False, False, cid)
        return MCPResponse.fail("panos_list_qos_rules", str(e), device=device)
