"""
Modelos tipados para logs (Tráfego, Ameaças, Sistema, Config) e sessões ativas do firewall.
"""

from typing import Optional

from pydantic import BaseModel


class TrafficLogEntry(BaseModel):
    receive_time: Optional[str] = None
    serial: Optional[str] = None
    from_zone: Optional[str] = None
    to_zone: Optional[str] = None
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    application: Optional[str] = None
    rule: Optional[str] = None
    action: Optional[str] = None
    bytes_sent: int = 0
    bytes_received: int = 0
    packets: int = 0
    session_id: Optional[str] = None


class ThreatLogEntry(BaseModel):
    receive_time: Optional[str] = None
    threat_id: Optional[str] = None
    threat_name: Optional[str] = None
    severity: Optional[str] = None
    source_ip: str
    destination_ip: str
    category: Optional[str] = None
    action: Optional[str] = None
    rule: Optional[str] = None


class SystemLogEntry(BaseModel):
    receive_time: Optional[str] = None
    event_id: Optional[str] = None
    severity: Optional[str] = None
    module: Optional[str] = None
    description: str


class ConfigLogEntry(BaseModel):
    receive_time: Optional[str] = None
    admin: str
    client: Optional[str] = None
    command: Optional[str] = None
    path: Optional[str] = None
    result: Optional[str] = None


class UrlLogEntry(BaseModel):
    receive_time: Optional[str] = None
    source_ip: str
    destination_ip: str
    url: str
    category: Optional[str] = None
    action: Optional[str] = None


class AuthLogEntry(BaseModel):
    receive_time: Optional[str] = None
    user: str
    client_ip: Optional[str] = None
    auth_profile: Optional[str] = None
    status: str


class SessionInfo(BaseModel):
    session_id: int
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    application: str
    state: str
    from_zone: Optional[str] = None
    to_zone: Optional[str] = None
    rule: Optional[str] = None


class SessionStatistics(BaseModel):
    active_sessions: int = 0
    max_sessions: int = 0
    tcp_sessions: int = 0
    udp_sessions: int = 0
    icmp_sessions: int = 0
    other_sessions: int = 0
    throughput_kbps: Optional[float] = None


class TopApplication(BaseModel):
    application: str
    sessions_count: int = 0
    bytes_total: int = 0
    percentage: Optional[float] = None
