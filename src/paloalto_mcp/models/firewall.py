"""
Modelos tipados para informações de sistema, recursos, licenças e hardware do PAN-OS.
"""

from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class SystemInfo(BaseModel):
    hostname: str
    ip_address: str
    netmask: Optional[str] = None
    default_gateway: Optional[str] = None
    model: str
    serial: Optional[str] = None
    sw_version: str
    uptime: Optional[str] = None
    system_mode: Optional[str] = None
    operational_mode: Optional[str] = None
    family: Optional[str] = None
    mac_address: Optional[str] = None
    multi_vsys: Optional[str] = None
    app_version: Optional[str] = None
    threat_version: Optional[str] = None
    wildfire_version: Optional[str] = None


class SystemResources(BaseModel):
    cpu_load_average: Optional[Dict[str, float]] = None
    management_plane_cpu: Optional[float] = None
    dataplane_cpu: Optional[List[float]] = None
    memory_total_kb: Optional[int] = None
    memory_used_kb: Optional[int] = None
    memory_free_kb: Optional[int] = None
    active_sessions: Optional[int] = None
    max_sessions: Optional[int] = None


class SystemLicense(BaseModel):
    feature: str
    description: Optional[str] = None
    issued: Optional[str] = None
    expires: Optional[str] = None
    expired: Optional[bool] = None


class SoftwareVersion(BaseModel):
    version: str
    filename: Optional[str] = None
    size: Optional[str] = None
    released_on: Optional[str] = None
    downloaded: Optional[bool] = None
    current: Optional[bool] = None
    latest: Optional[bool] = None


class DiskUsage(BaseModel):
    filesystem: str
    size: str
    used: str
    available: str
    use_percentage: str
    mounted_on: str


class ServiceStatus(BaseModel):
    name: str
    status: str
    pid: Optional[int] = None


class ConfigDiff(BaseModel):
    has_changes: bool
    summary: str
    diff_lines: List[str] = Field(default_factory=list)


class CommitResult(BaseModel):
    job_id: Optional[str] = None
    status: str
    result: str
    details: List[str] = Field(default_factory=list)
