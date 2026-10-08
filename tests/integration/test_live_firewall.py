"""
Testes de integração ao vivo contra o firewall Palo Alto Networks em 192.168.0.247.
Valida operações reais de leitura, auditoria, análise de regras e health check.
"""

import pytest

from paloalto_mcp.tools import diagnostics, network, objects, policies, system


@pytest.mark.asyncio
async def test_live_get_system_info():
    """Valida consulta de informações de sistema contra o firewall real 192.168.0.247."""
    resp = await system.panos_get_system_info()
    assert resp.success is True, f"Erro: {resp.errors}"
    assert resp.data is not None
    assert "hostname" in resp.data
    assert "sw-version" in resp.data or "sw_version" in resp.data


@pytest.mark.asyncio
async def test_live_get_system_version():
    """Valida consulta de versão PAN-OS real."""
    resp = await system.panos_get_system_version()
    assert resp.success is True
    assert resp.data["sw_version"] is not None


@pytest.mark.asyncio
async def test_live_list_security_rules():
    """Valida listagem de regras de segurança reais via REST API."""
    resp = await policies.panos_list_security_rules()
    assert resp.success is True
    assert "rules" in resp.data
    assert len(resp.data["rules"]) > 0


@pytest.mark.asyncio
async def test_live_analyze_security_rule():
    """Valida análise e auditoria com IA de regra real existente no firewall."""
    # Primeiro listamos para pegar o nome da regra existente
    rules_resp = await policies.panos_list_security_rules()
    assert rules_resp.success is True
    first_rule = rules_resp.data["rules"][0]
    rule_name = first_rule.get("@name") or first_rule.get("name")

    resp = await policies.panos_analyze_security_rule(name=rule_name)
    assert resp.success is True
    assert resp.data["rule_name"] == rule_name
    assert "risk_level" in resp.data
    assert "recommendations" in resp.data


@pytest.mark.asyncio
async def test_live_list_interfaces():
    """Valida consulta de interfaces reais do firewall."""
    resp = await network.panos_list_interfaces()
    assert resp.success is True
    assert resp.data is not None


@pytest.mark.asyncio
async def test_live_health_check():
    """Valida execução de health check consolidado completo no firewall."""
    resp = await diagnostics.panos_health_check()
    assert resp.success is True
    assert "system" in resp.data
    assert "overall_status" in resp.data


@pytest.mark.asyncio
async def test_live_create_address_object_dry_run():
    """Valida simulação segura de criação de objeto no firewall real sem gravá-lo."""
    resp = await objects.panos_create_address_object(
        name="MOCK_TEST_OBJ",
        value="192.168.100.1/32",
        type="ip-netmask",
        description="Objeto criado em modo simulação",
        dry_run=True,
    )
    assert resp.success is True
    assert resp.data["dry_run"] is True
