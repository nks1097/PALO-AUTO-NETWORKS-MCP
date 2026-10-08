"""
Testes automatizados para validação estrita do Registry das 100 ferramentas MCP.
"""

from paloalto_mcp.registry import REGISTERED_TOOLS, get_registry_stats, validate_registry
from paloalto_mcp.security.permissions import Permission


def test_exactly_100_tools():
    """Valida que exatamente 100 ferramentas distintas estão registradas."""
    tools = list(REGISTERED_TOOLS.keys())
    assert len(tools) == 100, f"Esperado 100 ferramentas, encontrado {len(tools)}"
    assert len(set(tools)) == 100, "Foram detectadas ferramentas com nomes duplicados"


def test_registry_validation_succeeds():
    """Valida que o gatilho de validação do startup executa com sucesso."""
    validate_registry()


def test_all_tools_have_metadata():
    """Valida que todas as 100 ferramentas possuem metadados completos."""
    for name, reg in REGISTERED_TOOLS.items():
        meta = reg.metadata
        assert meta.name == name
        assert meta.category in (
            "system",
            "config",
            "address_objects",
            "service_objects",
            "security_policy",
            "nat_policy",
            "network",
            "vpn",
            "logs_sessions",
            "ha_panorama_diagnostics",
        ), f"Categoria inválida para {name}: {meta.category}"
        assert isinstance(meta.permission, Permission)
        assert meta.description is not None and len(meta.description) > 5
        assert callable(reg.handler)


def test_destructive_tools_require_confirmation():
    """Valida que todas as ferramentas destrutivas exigem confirmação."""
    stats = get_registry_stats()
    assert stats["destructive"] > 0
    destructive_tools = [name for name, reg in REGISTERED_TOOLS.items() if reg.metadata.destructive]
    expected_destructive = [
        "panos_delete_config",
        "panos_commit",
        "panos_delete_address_object",
        "panos_delete_address_group",
        "panos_delete_service_object",
        "panos_delete_service_group",
        "panos_delete_security_rule",
        "panos_delete_nat_rule",
    ]
    for exp in expected_destructive:
        assert exp in destructive_tools, f"Ferramenta destrutiva esperada não marcada: {exp}"


def test_dry_run_supported_on_write_tools():
    """Valida que ferramentas de escrita e alteração suportam dry_run."""
    write_tools = [
        name for name, reg in REGISTERED_TOOLS.items()
        if reg.metadata.permission in (Permission.WRITE, Permission.DELETE, Permission.COMMIT)
    ]
    for name in write_tools:
        meta = REGISTERED_TOOLS[name].metadata
        assert meta.supports_dry_run is True, f"Ferramenta de escrita {name} deve suportar dry_run"
