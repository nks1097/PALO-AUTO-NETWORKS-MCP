"""
Testes unitários cobrindo execução das ferramentas MCP (dry_run, schemas, simulações e auditoria).
"""

from unittest.mock import AsyncMock, patch

import pytest

from paloalto_mcp.models.common import MCPResponse
from paloalto_mcp.tools import config, objects, policies


@pytest.mark.asyncio
async def test_panos_create_address_object_dry_run():
    resp = await objects.panos_create_address_object(
        name="TEST_SRV",
        value="10.50.0.1/32",
        type="ip-netmask",
        description="Teste de simulação",
        dry_run=True,
    )
    assert isinstance(resp, MCPResponse)
    assert resp.success is True
    assert resp.tool == "panos_create_address_object"
    assert resp.data["dry_run"] is True
    assert resp.data["target_object"] == "TEST_SRV"


@pytest.mark.asyncio
async def test_panos_create_security_rule_dry_run():
    resp = await policies.panos_create_security_rule(
        name="ALLOW_DNS",
        from_zones=["Trust"],
        to_zones=["Untrust"],
        source=["10.0.0.0/24"],
        destination=["8.8.8.8"],
        application=["dns"],
        service=["application-default"],
        action="allow",
        dry_run=True,
    )
    assert isinstance(resp, MCPResponse)
    assert resp.success is True
    assert resp.data["dry_run"] is True
    assert resp.data["target_object"] == "ALLOW_DNS"


@pytest.mark.asyncio
async def test_panos_delete_security_rule_without_confirmation_fails():
    resp = await policies.panos_delete_security_rule(
        name="ALLOW_DNS",
        confirm=False,
    )
    assert isinstance(resp, MCPResponse)
    assert resp.success is False
    assert any("CONFIRMATION_REQUIRED" in err.message or "confirmação" in err.message for err in resp.errors)


@pytest.mark.asyncio
async def test_panos_commit_dry_run():
    resp = await config.panos_commit(
        description="Commit de homologação",
        confirm=True,
        dry_run=True,
    )
    assert isinstance(resp, MCPResponse)
    assert resp.success is True
    assert resp.data["dry_run"] is True


@pytest.mark.asyncio
async def test_panos_analyze_security_rule():
    # Mock da consulta da regra pelo REST client
    mock_rule = {
        "@name": "RULE_PERMISSIVE",
        "from": {"member": ["Trust"]},
        "to": {"member": ["Untrust"]},
        "source": {"member": ["any"]},
        "destination": {"member": ["any"]},
        "application": {"member": ["any"]},
        "service": {"member": ["any"]},
        "action": "allow",
    }
    with patch("paloalto_mcp.client.client.rest.get_objects", new_callable=AsyncMock) as mock_get:
        mock_get.return_value = [mock_rule]
        resp = await policies.panos_analyze_security_rule(name="RULE_PERMISSIVE")
        assert resp.success is True
        data = resp.data
        assert data["rule_name"] == "RULE_PERMISSIVE"
        assert data["is_overly_permissive"] is True
        assert data["source_any"] is True
        assert data["destination_any"] is True
        assert data["risk_level"] in ("HIGH", "CRITICAL")
