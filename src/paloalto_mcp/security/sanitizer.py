"""
Sanitização rigorosa contra injeção em XPath, comandos e parâmetros operacionais.
Garante que entradas maliciosas ou caracteres perigosos sejam rejeitados.
"""

import re
from typing import Set

from ..exceptions import PaloAltoValidationError

# Caracteres permitidos em nomes de objetos, regras e zonas do PAN-OS:
# Alfanuméricos, hífen, underline, ponto e espaço restrito
NAME_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.\s]{1,63}$")
XPATH_SAFE_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.\/\[\]\'\"@=:\s]+$")

# Comandos operacionais permitidos exclusivamente para diagnóstico e observabilidade
ALLOWED_DIAGNOSTIC_COMMANDS: Set[str] = {
    "show system info",
    "show system resources",
    "show system state",
    "show routing route",
    "show interface all",
    "show session info",
    "show session all",
    "show arp all",
    "show mac all",
    "show running security-policy",
    "show running nat-policy",
    "show vpn ipsec-sa",
    "show vpn ike-sa",
    "show vpn flow",
    "show high-availability state",
    "show high-availability all",
    "show jobs all",
}


def sanitize_object_name(name: str) -> str:
    """Valida se o nome de um objeto/regra está no padrão seguro do PAN-OS."""
    if not name or not isinstance(name, str):
        raise PaloAltoValidationError("O nome do objeto não pode ser vazio.")
    cleaned = name.strip()
    if not NAME_REGEX.match(cleaned):
        raise PaloAltoValidationError(
            f"Nome inválido '{name}'. Deve conter apenas letras, números, hífens, pontos ou underscores (máx 63 caracteres)."
        )
    return cleaned


def sanitize_xpath(xpath: str) -> str:
    """Valida e previne injeção maliciosa em expressões XPath."""
    if not xpath or not isinstance(xpath, str):
        raise PaloAltoValidationError("XPath não pode ser vazio.")
    cleaned = xpath.strip()
    if not XPATH_SAFE_REGEX.match(cleaned):
        raise PaloAltoValidationError(f"Expressão XPath contém caracteres não permitidos: {xpath}")
    # Bloqueia injeção comum de bypass em XML
    dangerous_keywords = ["<!--", "-->", "<![CDATA[", "]]>", "&quot;"]
    for kw in dangerous_keywords:
        if kw in cleaned:
            raise PaloAltoValidationError(f"Sequência perigosa detectada no XPath: {kw}")
    return cleaned


def validate_diagnostic_command(cmd: str) -> str:
    """
    Valida comando contra a allowlist estrita de diagnósticos operacionais.
    Impede execução arbitrária de comandos não autorizados.
    """
    cleaned = cmd.strip().lower()
    # Verifica correspondência exata ou prefixo seguro
    for allowed in ALLOWED_DIAGNOSTIC_COMMANDS:
        if cleaned == allowed or cleaned.startswith(f"{allowed} "):
            return cleaned

    raise PaloAltoValidationError(
        f"Comando operacional '{cmd}' não permitido. Permitidos apenas comandos da allowlist de observabilidade."
    )
