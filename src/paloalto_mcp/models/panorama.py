"""
Modelos tipados para Panorama (Device Groups, Templates, Dispositivos Gerenciados) e Alta Disponibilidade (HA).
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ManagedDeviceModel(BaseModel):
    serial: str
    hostname: str
    ip_address: str
    model: str
    sw_version: str
    connected: bool
    ha_state: Optional[str] = None
    device_group: Optional[str] = None
    template: Optional[str] = None


class DeviceGroupModel(BaseModel):
    name: str
    description: Optional[str] = None
    devices: List[str] = Field(default_factory=list)
    parent: Optional[str] = None


class TemplateModel(BaseModel):
    name: str
    description: Optional[str] = None
    devices: List[str] = Field(default_factory=list)


class TemplateStackModel(BaseModel):
    name: str
    description: Optional[str] = None
    templates: List[str] = Field(default_factory=list)
    devices: List[str] = Field(default_factory=list)


class HaStatusModel(BaseModel):
    enabled: bool = False
    local_state: str = "disabled"
    peer_state: Optional[str] = None
    mode: str = "active-passive"
    sync_status: Optional[str] = None
    version_compat: Optional[str] = None
    app_compat: Optional[str] = None
    link_mon_state: Optional[str] = None


class HealthCheckResult(BaseModel):
    overall_status: str = Field(default="HEALTHY", description="HEALTHY, WARNING, CRITICAL")
    system: Dict[str, Any] = Field(default_factory=dict)
    resources: Dict[str, Any] = Field(default_factory=dict)
    interfaces: Dict[str, Any] = Field(default_factory=dict)
    ha: Dict[str, Any] = Field(default_factory=dict)
    vpn: Dict[str, Any] = Field(default_factory=dict)
    licenses: Dict[str, Any] = Field(default_factory=dict)
    config: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)
    critical_findings: List[str] = Field(default_factory=list)
