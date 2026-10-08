"""
Modelos tipados para VPN IPSec, IKE Gateways e GlobalProtect.
"""

from typing import Optional

from pydantic import BaseModel, Field


class IpsecTunnelModel(BaseModel):
    name: str
    state: str = Field(description="init, active, down, disabled")
    gw_id: Optional[str] = None
    inner_if: Optional[str] = None
    outer_if: Optional[str] = None
    local_ip: Optional[str] = None
    peer_ip: Optional[str] = None
    ike_gateway: Optional[str] = None
    enc_alg: Optional[str] = None
    auth_alg: Optional[str] = None
    bytes_in: int = 0
    bytes_out: int = 0


class IkeGatewayModel(BaseModel):
    name: str
    version: str = "ikev2"
    local_address: Optional[str] = None
    peer_address: Optional[str] = None
    interface: Optional[str] = None
    state: Optional[str] = None
    exchange_mode: Optional[str] = None


class GlobalProtectStatus(BaseModel):
    enabled: bool = True
    active_tunnels: int = 0
    gateways_count: int = 0
    portal_status: str = "active"


class GlobalProtectUser(BaseModel):
    username: str
    client_ip: str
    assigned_ip: str
    gateway: str
    login_time: Optional[str] = None
    computer: Optional[str] = None
    client_type: Optional[str] = None


class GlobalProtectGateway(BaseModel):
    name: str
    interface: str
    ip: str
    active_users: int = 0
    status: str = "running"


class VpnStatistics(BaseModel):
    total_tunnels: int = 0
    active_tunnels: int = 0
    down_tunnels: int = 0
    ike_gateways_up: int = 0
    ike_gateways_down: int = 0
    globalprotect_connected_users: int = 0
