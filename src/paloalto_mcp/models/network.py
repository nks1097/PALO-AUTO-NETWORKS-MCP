"""
Modelos tipados para interfaces de rede, zonas de segurança, tabelas de roteamento e ARP.
"""

from typing import List, Optional

from pydantic import BaseModel, Field


class InterfaceModel(BaseModel):
    name: str
    state: str = "up"
    ip: Optional[str] = None
    zone: Optional[str] = None
    virtual_router: Optional[str] = None
    mode: Optional[str] = None
    tag: Optional[int] = None
    comment: Optional[str] = None


class ZoneModel(BaseModel):
    name: str
    network_type: str = Field(default="layer3", description="layer3, layer2, tap, virtual-wire")
    interfaces: List[str] = Field(default_factory=list)
    zone_protection_profile: Optional[str] = None


class VirtualRouterModel(BaseModel):
    name: str
    interfaces: List[str] = Field(default_factory=list)
    protocol_bgp: bool = False
    protocol_ospf: bool = False


class RouteEntry(BaseModel):
    destination: str
    nexthop: str
    metric: Optional[int] = None
    flags: Optional[str] = None
    interface: Optional[str] = None
    virtual_router: Optional[str] = None


class ArpEntry(BaseModel):
    interface: str
    ip: str
    mac: str
    port: Optional[str] = None
    status: Optional[str] = None


class MacEntry(BaseModel):
    interface: str
    mac: str
    vlan: Optional[str] = None


class InterfaceCounters(BaseModel):
    name: str
    ibytes: int = 0
    obytes: int = 0
    ipackets: int = 0
    opackets: int = 0
    ierrors: int = 0
    oerrors: int = 0
    idrops: int = 0
