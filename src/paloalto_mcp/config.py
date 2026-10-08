"""
Configuração do servidor MCP Palo Alto Networks.
Carrega variáveis de ambiente e valida as configurações de segurança e conexão.
"""

from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Conexão PAN-OS Firewall
    panos_host: str = Field(default="https://192.168.0.247", alias="PANOS_HOST")
    panos_api_key: Optional[str] = Field(default=None, alias="PANOS_API_KEY")
    panos_username: Optional[str] = Field(default=None, alias="PANOS_USERNAME")
    panos_password: Optional[str] = Field(default=None, alias="PANOS_PASSWORD")
    panos_verify_ssl: bool = Field(default=False, alias="PANOS_VERIFY_SSL")
    panos_timeout: int = Field(default=30, alias="PANOS_TIMEOUT")
    panos_connect_timeout: int = Field(default=10, alias="PANOS_CONNECT_TIMEOUT")
    panos_default_device: Optional[str] = Field(default=None, alias="PANOS_DEFAULT_DEVICE")
    panos_default_vsys: str = Field(default="vsys1", alias="PANOS_DEFAULT_VSYS")

    # Conexão Panorama (quando aplicável)
    panorama_host: Optional[str] = Field(default=None, alias="PANORAMA_HOST")
    panorama_api_key: Optional[str] = Field(default=None, alias="PANORAMA_API_KEY")

    # Controles de Segurança & RBAC
    mcp_auth_enabled: bool = Field(default=True, alias="MCP_AUTH_ENABLED")
    mcp_require_confirmation: bool = Field(default=True, alias="MCP_REQUIRE_CONFIRMATION")
    allow_write_operations: bool = Field(default=True, alias="ALLOW_WRITE_OPERATIONS")
    allow_commit: bool = Field(default=False, alias="ALLOW_COMMIT")
    allow_reboot: bool = Field(default=False, alias="ALLOW_REBOOT")

    # Observabilidade
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")


settings = Settings()
