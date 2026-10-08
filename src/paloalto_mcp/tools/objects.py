"""
Ferramentas MCP dos Grupos C e D: OBJETOS DE ENDEREÇO E SERVIÇO (Ferramentas 21 a 40).
Permite listar, consultar, criar, atualizar e excluir objetos e grupos de endereços e portas/serviços.
"""

from typing import Any, Dict, List, Optional

from ..client import client
from ..exceptions import PaloAltoValidationError
from ..models.common import DryRunResult, MCPResponse
from ..registry import register_tool
from ..security.auth import audit_log, generate_correlation_id
from ..security.permissions import Permission, enforce_authorization
from ..security.sanitizer import sanitize_object_name

# ============================================================================
# GRUPO C — ADDRESS OBJECTS (21-30)
# ============================================================================

@register_tool(
    name="panos_list_address_objects",
    category="address_objects",
    permission=Permission.READ,
    description="Lista todos os objetos de endereço (Address Objects) configurados no vsys ou shared.",
)
async def panos_list_address_objects(
    vsys: str = "vsys1",
    location: str = "vsys",
    limit: int = 100,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista Address Objects configurados."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Objects/Addresses", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])
        paginated = items[offset : offset + limit]
        audit_log("panos_list_address_objects", "list", device, "Objects/Addresses", False, True, cid)
        return MCPResponse.ok("panos_list_address_objects", data={"total": len(items), "objects": paginated}, device=device)
    except Exception as e:
        audit_log("panos_list_address_objects", "list", device, "Objects/Addresses", False, False, cid)
        return MCPResponse.fail("panos_list_address_objects", str(e), device=device)


@register_tool(
    name="panos_get_address_object",
    category="address_objects",
    permission=Permission.READ,
    description="Consulta detalhes de um objeto de endereço específico pelo seu nome.",
)
async def panos_get_address_object(
    name: str,
    vsys: str = "vsys1",
    location: str = "vsys",
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta detalhes de um Address Object por nome."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        data = await client.rest.get_objects("Objects/Addresses", location=location, vsys=vsys, name=clean_name)
        audit_log("panos_get_address_object", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_get_address_object", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_address_object", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_get_address_object", str(e), device=device)


@register_tool(
    name="panos_create_address_object",
    category="address_objects",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Cria um novo objeto de endereço (ip-netmask, ip-range, fqdn ou ip-wildcard). Suporta dry_run.",
)
async def panos_create_address_object(
    name: str,
    value: str,
    type: str = "ip-netmask",
    description: Optional[str] = None,
    tags: Optional[List[str]] = None,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Cria um Address Object com checagem de idempotência."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    if type not in ("ip-netmask", "ip-range", "fqdn", "ip-wildcard"):
        raise PaloAltoValidationError("Tipo inválido. Use: ip-netmask, ip-range, fqdn ou ip-wildcard.")

    payload: Dict[str, Any] = {"@name": clean_name, type: value}
    if description:
        payload["description"] = description
    if tags:
        payload["tag"] = {"member": tags}

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="CREATE_ADDRESS_OBJECT",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Objects/Addresses",
                parameters=payload,
                risk_level="LOW",
                predicted_changes={"action": "create", "name": clean_name, "value": value, "type": type},
            )
            audit_log("panos_create_address_object", "create", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_create_address_object", data=sim.model_dump(), device=device)

        res = await client.rest.create_object("Objects/Addresses", payload=payload, location=location, vsys=vsys, name=clean_name)
        audit_log("panos_create_address_object", "create", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_create_address_object", data=res, device=device)
    except Exception as e:
        audit_log("panos_create_address_object", "create", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_create_address_object", str(e), device=device)


@register_tool(
    name="panos_update_address_object",
    category="address_objects",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Atualiza as propriedades de um objeto de endereço existente. Suporta dry_run.",
)
async def panos_update_address_object(
    name: str,
    value: str,
    type: str = "ip-netmask",
    description: Optional[str] = None,
    tags: Optional[List[str]] = None,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Atualiza um Address Object existente."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    payload: Dict[str, Any] = {"@name": clean_name, type: value}
    if description:
        payload["description"] = description
    if tags:
        payload["tag"] = {"member": tags}

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="UPDATE_ADDRESS_OBJECT",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Objects/Addresses",
                parameters=payload,
                risk_level="MEDIUM",
                predicted_changes={"action": "update", "name": clean_name, "new_value": value},
            )
            audit_log("panos_update_address_object", "update", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_update_address_object", data=sim.model_dump(), device=device)

        res = await client.rest.update_object("Objects/Addresses", name=clean_name, payload=payload, location=location, vsys=vsys)
        audit_log("panos_update_address_object", "update", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_update_address_object", data=res, device=device)
    except Exception as e:
        audit_log("panos_update_address_object", "update", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_update_address_object", str(e), device=device)


@register_tool(
    name="panos_delete_address_object",
    category="address_objects",
    permission=Permission.DELETE,
    destructive=True,
    supports_dry_run=True,
    description="Exclui um objeto de endereço do PAN-OS. Requer confirm=true.",
)
async def panos_delete_address_object(
    name: str,
    confirm: bool = False,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Exclui um Address Object com confirmação obrigatória."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.DELETE, destructive=True, confirmed=confirm, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="DELETE_ADDRESS_OBJECT",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Objects/Addresses",
                parameters={"name": clean_name, "confirm": confirm},
                risk_level="HIGH",
                predicted_changes={"action": "delete", "name": clean_name},
            )
            audit_log("panos_delete_address_object", "delete", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_delete_address_object", data=sim.model_dump(), device=device)

        res = await client.rest.delete_object("Objects/Addresses", name=clean_name, location=location, vsys=vsys)
        audit_log("panos_delete_address_object", "delete", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_delete_address_object", data=res, device=device)
    except Exception as e:
        audit_log("panos_delete_address_object", "delete", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_delete_address_object", str(e), device=device)


@register_tool(
    name="panos_list_address_groups",
    category="address_objects",
    permission=Permission.READ,
    description="Lista todos os grupos de endereços (estáticos ou dinâmicos) configurados no PAN-OS.",
)
async def panos_list_address_groups(
    vsys: str = "vsys1",
    location: str = "vsys",
    limit: int = 100,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista Address Groups configurados."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Objects/AddressGroups", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])
        paginated = items[offset : offset + limit]
        audit_log("panos_list_address_groups", "list", device, "Objects/AddressGroups", False, True, cid)
        return MCPResponse.ok("panos_list_address_groups", data={"total": len(items), "groups": paginated}, device=device)
    except Exception as e:
        audit_log("panos_list_address_groups", "list", device, "Objects/AddressGroups", False, False, cid)
        return MCPResponse.fail("panos_list_address_groups", str(e), device=device)


@register_tool(
    name="panos_get_address_group",
    category="address_objects",
    permission=Permission.READ,
    description="Consulta a definição e membros de um grupo de endereços específico pelo nome.",
)
async def panos_get_address_group(
    name: str,
    vsys: str = "vsys1",
    location: str = "vsys",
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta detalhes de um Address Group por nome."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        data = await client.rest.get_objects("Objects/AddressGroups", location=location, vsys=vsys, name=clean_name)
        audit_log("panos_get_address_group", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_get_address_group", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_address_group", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_get_address_group", str(e), device=device)


@register_tool(
    name="panos_create_address_group",
    category="address_objects",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Cria um novo grupo de endereços (estático com membros ou dinâmico com filtro de tags). Suporta dry_run.",
)
async def panos_create_address_group(
    name: str,
    members: Optional[List[str]] = None,
    dynamic_filter: Optional[str] = None,
    description: Optional[str] = None,
    tags: Optional[List[str]] = None,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Cria um Address Group estático ou dinâmico."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    payload: Dict[str, Any] = {"@name": clean_name}
    if members:
        payload["static"] = {"member": members}
    elif dynamic_filter:
        payload["dynamic"] = {"filter": dynamic_filter}
    else:
        raise PaloAltoValidationError("Deve ser fornecida uma lista de 'members' estáticos ou 'dynamic_filter'.")

    if description:
        payload["description"] = description
    if tags:
        payload["tag"] = {"member": tags}

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="CREATE_ADDRESS_GROUP",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Objects/AddressGroups",
                parameters=payload,
                risk_level="LOW",
                predicted_changes={"action": "create_group", "name": clean_name},
            )
            audit_log("panos_create_address_group", "create", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_create_address_group", data=sim.model_dump(), device=device)

        res = await client.rest.create_object("Objects/AddressGroups", payload=payload, location=location, vsys=vsys, name=clean_name)
        audit_log("panos_create_address_group", "create", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_create_address_group", data=res, device=device)
    except Exception as e:
        audit_log("panos_create_address_group", "create", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_create_address_group", str(e), device=device)


@register_tool(
    name="panos_update_address_group",
    category="address_objects",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Atualiza os membros ou filtros dinâmicos de um grupo de endereços existente. Suporta dry_run.",
)
async def panos_update_address_group(
    name: str,
    members: Optional[List[str]] = None,
    dynamic_filter: Optional[str] = None,
    description: Optional[str] = None,
    tags: Optional[List[str]] = None,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Atualiza um Address Group existente."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    payload: Dict[str, Any] = {"@name": clean_name}
    if members:
        payload["static"] = {"member": members}
    elif dynamic_filter:
        payload["dynamic"] = {"filter": dynamic_filter}
    if description:
        payload["description"] = description
    if tags:
        payload["tag"] = {"member": tags}

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="UPDATE_ADDRESS_GROUP",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Objects/AddressGroups",
                parameters=payload,
                risk_level="MEDIUM",
                predicted_changes={"action": "update_group", "name": clean_name},
            )
            audit_log("panos_update_address_group", "update", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_update_address_group", data=sim.model_dump(), device=device)

        res = await client.rest.update_object("Objects/AddressGroups", name=clean_name, payload=payload, location=location, vsys=vsys)
        audit_log("panos_update_address_group", "update", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_update_address_group", data=res, device=device)
    except Exception as e:
        audit_log("panos_update_address_group", "update", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_update_address_group", str(e), device=device)


@register_tool(
    name="panos_delete_address_group",
    category="address_objects",
    permission=Permission.DELETE,
    destructive=True,
    supports_dry_run=True,
    description="Exclui um grupo de endereços do firewall. Requer confirm=true.",
)
async def panos_delete_address_group(
    name: str,
    confirm: bool = False,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Exclui um Address Group com confirmação obrigatória."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.DELETE, destructive=True, confirmed=confirm, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="DELETE_ADDRESS_GROUP",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Objects/AddressGroups",
                parameters={"name": clean_name, "confirm": confirm},
                risk_level="HIGH",
                predicted_changes={"action": "delete_group", "name": clean_name},
            )
            audit_log("panos_delete_address_group", "delete", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_delete_address_group", data=sim.model_dump(), device=device)

        res = await client.rest.delete_object("Objects/AddressGroups", name=clean_name, location=location, vsys=vsys)
        audit_log("panos_delete_address_group", "delete", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_delete_address_group", data=res, device=device)
    except Exception as e:
        audit_log("panos_delete_address_group", "delete", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_delete_address_group", str(e), device=device)


# ============================================================================
# GRUPO D — SERVICE OBJECTS (31-40)
# ============================================================================

@register_tool(
    name="panos_list_service_objects",
    category="service_objects",
    permission=Permission.READ,
    description="Lista todos os objetos de serviço e portas (TCP/UDP) configurados no PAN-OS.",
)
async def panos_list_service_objects(
    vsys: str = "vsys1",
    location: str = "vsys",
    limit: int = 100,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista Service Objects configurados."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Objects/Services", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])
        paginated = items[offset : offset + limit]
        audit_log("panos_list_service_objects", "list", device, "Objects/Services", False, True, cid)
        return MCPResponse.ok("panos_list_service_objects", data={"total": len(items), "services": paginated}, device=device)
    except Exception as e:
        audit_log("panos_list_service_objects", "list", device, "Objects/Services", False, False, cid)
        return MCPResponse.fail("panos_list_service_objects", str(e), device=device)


@register_tool(
    name="panos_get_service_object",
    category="service_objects",
    permission=Permission.READ,
    description="Consulta detalhes de um objeto de serviço específico pelo seu nome.",
)
async def panos_get_service_object(
    name: str,
    vsys: str = "vsys1",
    location: str = "vsys",
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta detalhes de um Service Object por nome."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        data = await client.rest.get_objects("Objects/Services", location=location, vsys=vsys, name=clean_name)
        audit_log("panos_get_service_object", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_get_service_object", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_service_object", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_get_service_object", str(e), device=device)


@register_tool(
    name="panos_create_service_object",
    category="service_objects",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Cria um novo objeto de serviço TCP ou UDP com porta de destino especificada. Suporta dry_run.",
)
async def panos_create_service_object(
    name: str,
    protocol: str,
    port: str,
    source_port: Optional[str] = None,
    description: Optional[str] = None,
    tags: Optional[List[str]] = None,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Cria um Service Object (tcp/udp)."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    proto_clean = protocol.lower().strip()
    if proto_clean not in ("tcp", "udp"):
        raise PaloAltoValidationError("Protocolo inválido. Use 'tcp' ou 'udp'.")

    proto_config: Dict[str, Any] = {"port": port}
    if source_port:
        proto_config["source-port"] = source_port

    payload: Dict[str, Any] = {
        "@name": clean_name,
        "protocol": {proto_clean: proto_config},
    }
    if description:
        payload["description"] = description
    if tags:
        payload["tag"] = {"member": tags}

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="CREATE_SERVICE_OBJECT",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Objects/Services",
                parameters=payload,
                risk_level="LOW",
                predicted_changes={"action": "create_service", "name": clean_name, "protocol": proto_clean, "port": port},
            )
            audit_log("panos_create_service_object", "create", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_create_service_object", data=sim.model_dump(), device=device)

        res = await client.rest.create_object("Objects/Services", payload=payload, location=location, vsys=vsys, name=clean_name)
        audit_log("panos_create_service_object", "create", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_create_service_object", data=res, device=device)
    except Exception as e:
        audit_log("panos_create_service_object", "create", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_create_service_object", str(e), device=device)


@register_tool(
    name="panos_update_service_object",
    category="service_objects",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Atualiza a porta ou protocolo de um objeto de serviço existente. Suporta dry_run.",
)
async def panos_update_service_object(
    name: str,
    protocol: str,
    port: str,
    source_port: Optional[str] = None,
    description: Optional[str] = None,
    tags: Optional[List[str]] = None,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Atualiza um Service Object existente."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    proto_clean = protocol.lower().strip()
    if proto_clean not in ("tcp", "udp"):
        raise PaloAltoValidationError("Protocolo inválido. Use 'tcp' ou 'udp'.")

    proto_config: Dict[str, Any] = {"port": port}
    if source_port:
        proto_config["source-port"] = source_port

    payload: Dict[str, Any] = {
        "@name": clean_name,
        "protocol": {proto_clean: proto_config},
    }
    if description:
        payload["description"] = description
    if tags:
        payload["tag"] = {"member": tags}

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="UPDATE_SERVICE_OBJECT",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Objects/Services",
                parameters=payload,
                risk_level="MEDIUM",
                predicted_changes={"action": "update_service", "name": clean_name, "port": port},
            )
            audit_log("panos_update_service_object", "update", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_update_service_object", data=sim.model_dump(), device=device)

        res = await client.rest.update_object("Objects/Services", name=clean_name, payload=payload, location=location, vsys=vsys)
        audit_log("panos_update_service_object", "update", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_update_service_object", data=res, device=device)
    except Exception as e:
        audit_log("panos_update_service_object", "update", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_update_service_object", str(e), device=device)


@register_tool(
    name="panos_delete_service_object",
    category="service_objects",
    permission=Permission.DELETE,
    destructive=True,
    supports_dry_run=True,
    description="Exclui um objeto de serviço do firewall. Requer confirm=true.",
)
async def panos_delete_service_object(
    name: str,
    confirm: bool = False,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Exclui um Service Object com confirmação obrigatória."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.DELETE, destructive=True, confirmed=confirm, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="DELETE_SERVICE_OBJECT",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Objects/Services",
                parameters={"name": clean_name, "confirm": confirm},
                risk_level="HIGH",
                predicted_changes={"action": "delete_service", "name": clean_name},
            )
            audit_log("panos_delete_service_object", "delete", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_delete_service_object", data=sim.model_dump(), device=device)

        res = await client.rest.delete_object("Objects/Services", name=clean_name, location=location, vsys=vsys)
        audit_log("panos_delete_service_object", "delete", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_delete_service_object", data=res, device=device)
    except Exception as e:
        audit_log("panos_delete_service_object", "delete", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_delete_service_object", str(e), device=device)


@register_tool(
    name="panos_list_service_groups",
    category="service_objects",
    permission=Permission.READ,
    description="Lista todos os grupos de serviços (Service Groups) configurados no PAN-OS.",
)
async def panos_list_service_groups(
    vsys: str = "vsys1",
    location: str = "vsys",
    limit: int = 100,
    offset: int = 0,
    device: Optional[str] = None,
) -> MCPResponse:
    """Lista Service Groups configurados."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        entries = await client.rest.get_objects("Objects/ServiceGroups", location=location, vsys=vsys)
        items = entries if isinstance(entries, list) else ([entries] if entries else [])
        paginated = items[offset : offset + limit]
        audit_log("panos_list_service_groups", "list", device, "Objects/ServiceGroups", False, True, cid)
        return MCPResponse.ok("panos_list_service_groups", data={"total": len(items), "groups": paginated}, device=device)
    except Exception as e:
        audit_log("panos_list_service_groups", "list", device, "Objects/ServiceGroups", False, False, cid)
        return MCPResponse.fail("panos_list_service_groups", str(e), device=device)


@register_tool(
    name="panos_get_service_group",
    category="service_objects",
    permission=Permission.READ,
    description="Consulta membros e definição de um grupo de serviços específico por nome.",
)
async def panos_get_service_group(
    name: str,
    vsys: str = "vsys1",
    location: str = "vsys",
    device: Optional[str] = None,
) -> MCPResponse:
    """Consulta detalhes de um Service Group por nome."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.READ)
        data = await client.rest.get_objects("Objects/ServiceGroups", location=location, vsys=vsys, name=clean_name)
        audit_log("panos_get_service_group", "get", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_get_service_group", data=data, device=device)
    except Exception as e:
        audit_log("panos_get_service_group", "get", device, clean_name, False, False, cid)
        return MCPResponse.fail("panos_get_service_group", str(e), device=device)


@register_tool(
    name="panos_create_service_group",
    category="service_objects",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Cria um novo grupo de serviços agregando múltiplos objetos de serviço. Suporta dry_run.",
)
async def panos_create_service_group(
    name: str,
    members: List[str],
    description: Optional[str] = None,
    tags: Optional[List[str]] = None,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Cria um Service Group."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    if not members:
        raise PaloAltoValidationError("O grupo de serviços deve conter ao menos um membro.")

    payload: Dict[str, Any] = {
        "@name": clean_name,
        "members": {"member": members},
    }
    if description:
        payload["description"] = description
    if tags:
        payload["tag"] = {"member": tags}

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="CREATE_SERVICE_GROUP",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Objects/ServiceGroups",
                parameters=payload,
                risk_level="LOW",
                predicted_changes={"action": "create_service_group", "name": clean_name, "members": members},
            )
            audit_log("panos_create_service_group", "create", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_create_service_group", data=sim.model_dump(), device=device)

        res = await client.rest.create_object("Objects/ServiceGroups", payload=payload, location=location, vsys=vsys, name=clean_name)
        audit_log("panos_create_service_group", "create", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_create_service_group", data=res, device=device)
    except Exception as e:
        audit_log("panos_create_service_group", "create", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_create_service_group", str(e), device=device)


@register_tool(
    name="panos_update_service_group",
    category="service_objects",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Atualiza a lista de membros de um grupo de serviços existente. Suporta dry_run.",
)
async def panos_update_service_group(
    name: str,
    members: List[str],
    description: Optional[str] = None,
    tags: Optional[List[str]] = None,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Atualiza um Service Group existente."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    payload: Dict[str, Any] = {
        "@name": clean_name,
        "members": {"member": members},
    }
    if description:
        payload["description"] = description
    if tags:
        payload["tag"] = {"member": tags}

    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="UPDATE_SERVICE_GROUP",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Objects/ServiceGroups",
                parameters=payload,
                risk_level="MEDIUM",
                predicted_changes={"action": "update_service_group", "name": clean_name, "members": members},
            )
            audit_log("panos_update_service_group", "update", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_update_service_group", data=sim.model_dump(), device=device)

        res = await client.rest.update_object("Objects/ServiceGroups", name=clean_name, payload=payload, location=location, vsys=vsys)
        audit_log("panos_update_service_group", "update", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_update_service_group", data=res, device=device)
    except Exception as e:
        audit_log("panos_update_service_group", "update", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_update_service_group", str(e), device=device)


@register_tool(
    name="panos_delete_service_group",
    category="service_objects",
    permission=Permission.DELETE,
    destructive=True,
    supports_dry_run=True,
    description="Exclui um grupo de serviços do firewall. Requer confirm=true.",
)
async def panos_delete_service_group(
    name: str,
    confirm: bool = False,
    vsys: str = "vsys1",
    location: str = "vsys",
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Exclui um Service Group com confirmação obrigatória."""
    cid = generate_correlation_id()
    clean_name = sanitize_object_name(name)
    try:
        enforce_authorization(Permission.DELETE, destructive=True, confirmed=confirm, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="DELETE_SERVICE_GROUP",
                target_object=clean_name,
                endpoint="/restapi/v10.2/Objects/ServiceGroups",
                parameters={"name": clean_name, "confirm": confirm},
                risk_level="HIGH",
                predicted_changes={"action": "delete_service_group", "name": clean_name},
            )
            audit_log("panos_delete_service_group", "delete", device, clean_name, True, True, cid)
            return MCPResponse.ok("panos_delete_service_group", data=sim.model_dump(), device=device)

        res = await client.rest.delete_object("Objects/ServiceGroups", name=clean_name, location=location, vsys=vsys)
        audit_log("panos_delete_service_group", "delete", device, clean_name, False, True, cid)
        return MCPResponse.ok("panos_delete_service_group", data=res, device=device)
    except Exception as e:
        audit_log("panos_delete_service_group", "delete", device, clean_name, dry_run, False, cid)
        return MCPResponse.fail("panos_delete_service_group", str(e), device=device)
