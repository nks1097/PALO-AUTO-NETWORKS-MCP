"""
Ferramentas MCP do Grupo B: CONFIGURAÇÃO (Ferramentas 11 a 20).
Suporta leitura, alteração via XPath, validação, diff e commit seguro no PAN-OS.
"""

from typing import Optional

from ..client import client
from ..models.common import DryRunResult, MCPResponse
from ..registry import register_tool
from ..security.auth import audit_log, generate_correlation_id
from ..security.permissions import Permission, enforce_authorization
from ..security.sanitizer import sanitize_xpath


@register_tool(
    name="panos_get_config",
    category="config",
    permission=Permission.READ,
    description="Obtém a configuração completa ativa (running config) do firewall via XPath raiz.",
)
async def panos_get_config(device: Optional[str] = None) -> MCPResponse:
    """Obtém configuração ativa completa."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.get_config("/config")
        audit_log("panos_get_config", "read", device, "/config", False, True, cid)
        return MCPResponse.ok("panos_get_config", data=res.get("result", {}), device=device)
    except Exception as e:
        audit_log("panos_get_config", "read", device, "/config", False, False, cid)
        return MCPResponse.fail("panos_get_config", str(e), device=device)


@register_tool(
    name="panos_get_config_path",
    category="config",
    permission=Permission.READ,
    description="Consulta um nó específico da configuração através de um caminho XPath seguro.",
)
async def panos_get_config_path(xpath: str, device: Optional[str] = None) -> MCPResponse:
    """Consulta configuração em um XPath específico."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        clean_xpath = sanitize_xpath(xpath)
        res = await client.xml.get_config(clean_xpath)
        audit_log("panos_get_config_path", "read", device, clean_xpath, False, True, cid)
        return MCPResponse.ok("panos_get_config_path", data=res.get("result", {}), device=device)
    except Exception as e:
        audit_log("panos_get_config_path", "read", device, xpath, False, False, cid)
        return MCPResponse.fail("panos_get_config_path", str(e), device=device)


@register_tool(
    name="panos_set_config",
    category="config",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Adiciona ou mescla nós de configuração em um XPath especificado. Suporta dry_run.",
)
async def panos_set_config(
    xpath: str,
    element_xml: str,
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Altera configuração via XPath (set)."""
    cid = generate_correlation_id()
    clean_xpath = sanitize_xpath(xpath)
    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="SET_CONFIG",
                target_object=clean_xpath,
                endpoint="/api/?type=config&action=set",
                parameters={"xpath": clean_xpath, "element_xml": element_xml},
                risk_level="MEDIUM",
                predicted_changes={"action": "add_or_merge_nodes", "xpath": clean_xpath},
            )
            audit_log("panos_set_config", "set", device, clean_xpath, True, True, cid)
            return MCPResponse.ok("panos_set_config", data=sim.model_dump(), device=device)

        res = await client.xml.set_config(clean_xpath, element_xml)
        audit_log("panos_set_config", "set", device, clean_xpath, False, True, cid)
        return MCPResponse.ok("panos_set_config", data=res, device=device)
    except Exception as e:
        audit_log("panos_set_config", "set", device, clean_xpath, dry_run, False, cid)
        return MCPResponse.fail("panos_set_config", str(e), device=device)


@register_tool(
    name="panos_edit_config",
    category="config",
    permission=Permission.WRITE,
    destructive=False,
    supports_dry_run=True,
    description="Substitui um objeto ou nó inteiro existente em um caminho XPath. Suporta dry_run.",
)
async def panos_edit_config(
    xpath: str,
    element_xml: str,
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Substitui configuração em determinado XPath (edit)."""
    cid = generate_correlation_id()
    clean_xpath = sanitize_xpath(xpath)
    try:
        enforce_authorization(Permission.WRITE, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="EDIT_CONFIG",
                target_object=clean_xpath,
                endpoint="/api/?type=config&action=edit",
                parameters={"xpath": clean_xpath, "element_xml": element_xml},
                risk_level="HIGH",
                predicted_changes={"action": "replace_node", "xpath": clean_xpath},
            )
            audit_log("panos_edit_config", "edit", device, clean_xpath, True, True, cid)
            return MCPResponse.ok("panos_edit_config", data=sim.model_dump(), device=device)

        res = await client.xml.edit_config(clean_xpath, element_xml)
        audit_log("panos_edit_config", "edit", device, clean_xpath, False, True, cid)
        return MCPResponse.ok("panos_edit_config", data=res, device=device)
    except Exception as e:
        audit_log("panos_edit_config", "edit", device, clean_xpath, dry_run, False, cid)
        return MCPResponse.fail("panos_edit_config", str(e), device=device)


@register_tool(
    name="panos_delete_config",
    category="config",
    permission=Permission.DELETE,
    destructive=True,
    supports_dry_run=True,
    description="Exclui um nó ou objeto da configuração no XPath indicado. Requer confirm=true.",
)
async def panos_delete_config(
    xpath: str,
    confirm: bool = False,
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Exclui configuração no caminho XPath informado."""
    cid = generate_correlation_id()
    clean_xpath = sanitize_xpath(xpath)
    try:
        enforce_authorization(Permission.DELETE, destructive=True, confirmed=confirm, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="DELETE_CONFIG",
                target_object=clean_xpath,
                endpoint="/api/?type=config&action=delete",
                parameters={"xpath": clean_xpath, "confirm": confirm},
                risk_level="CRITICAL",
                predicted_changes={"action": "delete_node", "xpath": clean_xpath},
            )
            audit_log("panos_delete_config", "delete", device, clean_xpath, True, True, cid)
            return MCPResponse.ok("panos_delete_config", data=sim.model_dump(), device=device)

        res = await client.xml.delete_config(clean_xpath)
        audit_log("panos_delete_config", "delete", device, clean_xpath, False, True, cid)
        return MCPResponse.ok("panos_delete_config", data=res, device=device)
    except Exception as e:
        audit_log("panos_delete_config", "delete", device, clean_xpath, dry_run, False, cid)
        return MCPResponse.fail("panos_delete_config", str(e), device=device)


@register_tool(
    name="panos_get_candidate_config",
    category="config",
    permission=Permission.READ,
    description="Consulta a candidate configuration (configuração em rascunho com alterações pendentes).",
)
async def panos_get_candidate_config(xpath: str = "/config", device: Optional[str] = None) -> MCPResponse:
    """Consulta a configuração candidata pendente."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        clean_xpath = sanitize_xpath(xpath)
        res = await client.xml.show_candidate_config(clean_xpath)
        audit_log("panos_get_candidate_config", "read", device, clean_xpath, False, True, cid)
        return MCPResponse.ok("panos_get_candidate_config", data=res.get("result", {}), device=device)
    except Exception as e:
        audit_log("panos_get_candidate_config", "read", device, xpath, False, False, cid)
        return MCPResponse.fail("panos_get_candidate_config", str(e), device=device)


@register_tool(
    name="panos_get_running_config",
    category="config",
    permission=Permission.READ,
    description="Consulta a running configuration (configuração ativa e em execução no plano de dados).",
)
async def panos_get_running_config(xpath: str = "/config", device: Optional[str] = None) -> MCPResponse:
    """Consulta a configuração ativa (running)."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        clean_xpath = sanitize_xpath(xpath)
        res = await client.xml.get_config(clean_xpath)
        audit_log("panos_get_running_config", "read", device, clean_xpath, False, True, cid)
        return MCPResponse.ok("panos_get_running_config", data=res.get("result", {}), device=device)
    except Exception as e:
        audit_log("panos_get_running_config", "read", device, xpath, False, False, cid)
        return MCPResponse.fail("panos_get_running_config", str(e), device=device)


@register_tool(
    name="panos_validate_config",
    category="config",
    permission=Permission.READ,
    description="Executa uma validação formal da configuração candidata antes de submeter ao commit.",
)
async def panos_validate_config(device: Optional[str] = None) -> MCPResponse:
    """Valida a integridade sintática e lógica da configuração candidata."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<validate><full></full></validate>")
        audit_log("panos_validate_config", "validate", device, "config", False, True, cid)
        return MCPResponse.ok("panos_validate_config", data=res.get("result", {}), device=device)
    except Exception as e:
        audit_log("panos_validate_config", "validate", device, "config", False, False, cid)
        return MCPResponse.fail("panos_validate_config", str(e), device=device)


@register_tool(
    name="panos_get_config_diff",
    category="config",
    permission=Permission.READ,
    description="Compara as diferenças entre a candidate configuration e a running configuration.",
)
async def panos_get_config_diff(device: Optional[str] = None) -> MCPResponse:
    """Compara candidate vs running configuration."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.READ)
        res = await client.xml.op_command("<show><config><diff></diff></config></show>")
        audit_log("panos_get_config_diff", "diff", device, "config", False, True, cid)
        return MCPResponse.ok("panos_get_config_diff", data=res.get("result", {}), device=device)
    except Exception as e:
        audit_log("panos_get_config_diff", "diff", device, "config", False, False, cid)
        return MCPResponse.fail("panos_get_config_diff", str(e), device=device)


@register_tool(
    name="panos_commit",
    category="config",
    permission=Permission.COMMIT,
    destructive=True,
    supports_dry_run=True,
    description="Aplica e efetiva as alterações candidatas no firewall. Requer confirm=true e ALLOW_COMMIT=true.",
)
async def panos_commit(
    description: Optional[str] = None,
    confirm: bool = False,
    dry_run: bool = False,
    device: Optional[str] = None,
) -> MCPResponse:
    """Efetua o commit das alterações no firewall."""
    cid = generate_correlation_id()
    try:
        enforce_authorization(Permission.COMMIT, destructive=True, confirmed=confirm, dry_run=dry_run)
        if dry_run:
            sim = DryRunResult(
                operation="COMMIT",
                target_object="candidate_config",
                endpoint="/api/?type=commit",
                parameters={"description": description, "confirm": confirm},
                risk_level="CRITICAL",
                predicted_changes={
                    "action": "commit_candidate_to_running",
                    "description": description or "Sem descrição fornecida",
                },
                message="Simulação de commit executada. Nenhuma alteração foi gravada em produção.",
            )
            audit_log("panos_commit", "commit", device, "candidate_config", True, True, cid)
            return MCPResponse.ok("panos_commit", data=sim.model_dump(), device=device)

        res = await client.xml.commit_config(description=description)
        audit_log("panos_commit", "commit", device, "candidate_config", False, True, cid)
        return MCPResponse.ok("panos_commit", data=res, device=device)
    except Exception as e:
        audit_log("panos_commit", "commit", device, "candidate_config", dry_run, False, cid)
        return MCPResponse.fail("panos_commit", str(e), device=device)
