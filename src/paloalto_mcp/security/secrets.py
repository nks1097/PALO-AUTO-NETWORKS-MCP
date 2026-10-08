"""
Sanitização de segredos em respostas, dados e metadados retornados pelo PAN-OS.
"""

from typing import Any

SECRET_KEYS = {
    "key",
    "api_key",
    "password",
    "secret",
    "token",
    "pre_shared_key",
    "preshared_key",
    "psk",
    "private_key",
    "certificate",
    "passphrase",
    "phash",
}


def sanitize_secrets_dict(data: Any) -> Any:
    """Percorre recursivamente estruturas de dados e mascara qualquer segredo."""
    if isinstance(data, dict):
        sanitized = {}
        for k, v in data.items():
            k_lower = str(k).lower().replace("-", "_")
            if any(secret_term in k_lower for secret_term in SECRET_KEYS):
                sanitized[k] = "[REDACTED_SECRET]"
            else:
                sanitized[k] = sanitize_secrets_dict(v)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_secrets_dict(item) for item in data]
    return data
