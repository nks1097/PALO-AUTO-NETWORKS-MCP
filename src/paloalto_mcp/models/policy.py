"""
Modelos tipados para objetos de rede e políticas de segurança, NAT e roteamento.
"""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ============================================================================
# OBJETOS
# ============================================================================

class AddressObject(BaseModel):
    name: str
    type: str = Field(description="ip-netmask, ip-range, fqdn ou ip-wildcard")
    value: str
    description: Optional[str] = None
    tag: List[str] = Field(default_factory=list)


class AddressGroup(BaseModel):
    name: str
    type: str = Field(default="static", description="'static' ou 'dynamic'")
    members: List[str] = Field(default_factory=list)
    dynamic_filter: Optional[str] = None
    description: Optional[str] = None
    tag: List[str] = Field(default_factory=list)


class ServiceObject(BaseModel):
    name: str
    protocol: str = Field(description="tcp ou udp")
    port: str
    source_port: Optional[str] = None
    description: Optional[str] = None
    tag: List[str] = Field(default_factory=list)


class ServiceGroup(BaseModel):
    name: str
    members: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    tag: List[str] = Field(default_factory=list)


# ============================================================================
# POLÍTICAS
# ============================================================================

class SecurityRule(BaseModel):
    name: str
    from_zones: List[str] = Field(default=["any"], alias="from")
    to_zones: List[str] = Field(default=["any"], alias="to")
    source: List[str] = Field(default=["any"])
    destination: List[str] = Field(default=["any"])
    source_user: List[str] = Field(default=["any"])
    category: List[str] = Field(default=["any"])
    application: List[str] = Field(default=["any"])
    service: List[str] = Field(default=["application-default"])
    action: str = Field(default="allow", description="allow, deny, drop, reset-client, reset-server, reset-both")
    description: Optional[str] = None
    disabled: bool = False
    log_start: bool = False
    log_end: bool = True
    profile_setting: Optional[Dict[str, Any]] = None
    tag: List[str] = Field(default_factory=list)


class SecurityRuleAnalysis(BaseModel):
    rule_name: str
    has_shadowing: bool = False
    shadowed_by: Optional[str] = None
    unused_objects: List[str] = Field(default_factory=list)
    is_overly_permissive: bool = False
    permissive_reasons: List[str] = Field(default_factory=list)
    source_any: bool = False
    destination_any: bool = False
    application_any: bool = False
    missing_security_profile: bool = False
    risk_level: str = Field(default="LOW", description="LOW, MEDIUM, HIGH, CRITICAL")
    recommendations: List[str] = Field(default_factory=list)


class NatRule(BaseModel):
    name: str
    from_zones: List[str] = Field(default=["any"], alias="from")
    to_zones: List[str] = Field(default=["any"], alias="to")
    source: List[str] = Field(default=["any"])
    destination: List[str] = Field(default=["any"])
    service: str = "any"
    nat_type: str = Field(default="ipv4", description="ipv4 ou nat64")
    source_translation: Optional[Dict[str, Any]] = None
    destination_translation: Optional[Dict[str, Any]] = None
    description: Optional[str] = None
    disabled: bool = False


class PbfRule(BaseModel):
    name: str
    from_zones: List[str] = Field(default=["any"], alias="from")
    source: List[str] = Field(default=["any"])
    destination: List[str] = Field(default=["any"])
    action: str = Field(default="forward", description="forward, discard, no-pbf")
    forward_interface: Optional[str] = None
    forward_next_hop: Optional[str] = None
    description: Optional[str] = None
    disabled: bool = False


class DecryptionRule(BaseModel):
    name: str
    from_zones: List[str] = Field(default=["any"], alias="from")
    to_zones: List[str] = Field(default=["any"], alias="to")
    source: List[str] = Field(default=["any"])
    destination: List[str] = Field(default=["any"])
    action: str = Field(default="ssl-forward-proxy", description="ssl-forward-proxy, ssl-inbound-inspection, no-decrypt")
    disabled: bool = False


class AuthenticationRule(BaseModel):
    name: str
    from_zones: List[str] = Field(default=["any"], alias="from")
    to_zones: List[str] = Field(default=["any"], alias="to")
    source: List[str] = Field(default=["any"])
    destination: List[str] = Field(default=["any"])
    authentication_enforcement: Optional[str] = None
    disabled: bool = False


class QosRule(BaseModel):
    name: str
    from_zones: List[str] = Field(default=["any"], alias="from")
    to_zones: List[str] = Field(default=["any"], alias="to")
    source: List[str] = Field(default=["any"])
    destination: List[str] = Field(default=["any"])
    qos_class: str = "class4"
    disabled: bool = False
