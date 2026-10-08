"""
Testes unitários para mecanismos de segurança, RBAC, sanitização e proteção contra vazamento de segredos.
"""

import pytest

from paloalto_mcp.exceptions import PaloAltoAuthorizationError, PaloAltoValidationError
from paloalto_mcp.logging import redact_sensitive_data
from paloalto_mcp.security.permissions import Permission, enforce_authorization
from paloalto_mcp.security.sanitizer import (
    sanitize_object_name,
    sanitize_xpath,
    validate_diagnostic_command,
)
from paloalto_mcp.security.secrets import sanitize_secrets_dict


def test_sanitize_object_name_valid():
    assert sanitize_object_name("WEB_SRV-01.local") == "WEB_SRV-01.local"
    assert sanitize_object_name("DMZ-Zone") == "DMZ-Zone"


def test_sanitize_object_name_invalid():
    with pytest.raises(PaloAltoValidationError):
        sanitize_object_name("bad;name")
    with pytest.raises(PaloAltoValidationError):
        sanitize_object_name("bad<tag>")
    with pytest.raises(PaloAltoValidationError):
        sanitize_object_name("")


def test_sanitize_xpath_valid():
    xpath = "/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']/address"
    assert sanitize_xpath(xpath) == xpath


def test_sanitize_xpath_injection():
    with pytest.raises(PaloAltoValidationError):
        sanitize_xpath("/config<!-- comment injection -->")
    with pytest.raises(PaloAltoValidationError):
        sanitize_xpath("/config; rm -rf /")


def test_validate_diagnostic_command_allowlist():
    assert validate_diagnostic_command("show system info") == "show system info"
    assert validate_diagnostic_command("show routing route") == "show routing route"

    with pytest.raises(PaloAltoValidationError):
        validate_diagnostic_command("request restart system")
    with pytest.raises(PaloAltoValidationError):
        validate_diagnostic_command("show password")


def test_redact_sensitive_data():
    raw = "Connecting with key=LUFRPT1HUkF0OEpKWVZTL3kyWG5vbTZ2cldnVENlWjg9UWtGd09z and password=Secret123"
    sanitized = redact_sensitive_data(raw)
    assert "Secret123" not in sanitized
    assert "LUFRPT1H" not in sanitized
    assert "[REDACTED_API_KEY]" in sanitized or "[REDACTED_TOKEN]" in sanitized


def test_sanitize_secrets_dict():
    data = {
        "device": "fw01",
        "api_key": "LUFRPT1H...",
        "admin_password": "supersecretpassword",
        "nested": {"pre_shared_key": "mysecretpsk", "ip": "192.168.1.1"},
    }
    cleaned = sanitize_secrets_dict(data)
    assert cleaned["api_key"] == "[REDACTED_SECRET]"
    assert cleaned["admin_password"] == "[REDACTED_SECRET]"
    assert cleaned["nested"]["pre_shared_key"] == "[REDACTED_SECRET]"
    assert cleaned["nested"]["ip"] == "192.168.1.1"


def test_enforce_authorization_destructive_requires_confirmation():
    # Destructive operation without confirmation must raise AuthorizationError
    with pytest.raises(PaloAltoAuthorizationError):
        enforce_authorization(Permission.DELETE, destructive=True, confirmed=False)

    # With confirmation, it should not raise
    enforce_authorization(Permission.DELETE, destructive=True, confirmed=True)

    # Dry run should never raise
    enforce_authorization(Permission.DELETE, destructive=True, confirmed=False, dry_run=True)
