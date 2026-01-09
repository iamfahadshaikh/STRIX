"""
TargetProfile - Single immutable source of truth for all target information

RULE: Once created, never changes. All evidence accumulated during reconnaissance
is stored here. Tools make decisions based on this profile, not based on scanning.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from enum import Enum
from datetime import datetime


class TargetType(Enum):
    """Classification of target"""
    IP = "ip"
    ROOT_DOMAIN = "root_domain"
    SUBDOMAIN = "subdomain"


class TargetScope(Enum):
    """Scope of reconnaissance to perform"""
    SINGLE_HOST = "single_host"
    DOMAIN_TREE = "domain_tree"


@dataclass(frozen=True)
class TargetProfile:
    """
    Immutable target profile - single source of truth.
    
    All evidence about a target is stored here.
    Never modified after creation.
    Shared by all tools and decision makers.
    """
    
    # Identity
    original_input: str
    target_type: TargetType
    host: str
    scheme: str = "https"
    port: int = 443
    
    # Classification
    base_domain: Optional[str] = None
    scope: TargetScope = TargetScope.SINGLE_HOST
    
    # Resolved state
    resolved_ips: List[str] = field(default_factory=list)
    is_resolvable: bool = False
    is_reachable: bool = False
    http_status: Optional[int] = None
    
    # Network hints
    ports_hint: Set[int] = field(default_factory=set)
    is_web_target: bool = False
    is_https: bool = False
    
    # Detected evidence
    detected_tech: Dict[str, str] = field(default_factory=dict)
    detected_cms: Optional[str] = None
    detected_params: Set[str] = field(default_factory=set)
    has_reflection: bool = False
    is_vulnerable_to_xss: bool = False
    detected_os: Optional[str] = None  # OS detection (run once per host)
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def __post_init__(self):
        """Validate profile consistency"""
        if self.target_type == TargetType.SUBDOMAIN and not self.base_domain:
            raise ValueError("Subdomain target must have base_domain set")
        
        if self.target_type == TargetType.IP and not self.resolved_ips:
            raise ValueError("IP target must have resolved_ips set")
        
        if self.target_type == TargetType.ROOT_DOMAIN and self.base_domain:
            raise ValueError("Root domain target cannot have base_domain")
    
    @property
    def is_ip(self) -> bool:
        """Check if this is an IP target"""
        return self.target_type == TargetType.IP
    
    @property
    def is_root_domain(self) -> bool:
        """Check if this is a root domain target"""
        return self.target_type == TargetType.ROOT_DOMAIN
    
    @property
    def is_subdomain(self) -> bool:
        """Check if this is a subdomain target"""
        return self.target_type == TargetType.SUBDOMAIN
    
    @property
    def has_wordpress(self) -> bool:
        """Check if WordPress detected"""
        return self.detected_cms == "wordpress"
    
    @property
    def has_parameters(self) -> bool:
        """Check if URL parameters detected"""
        return len(self.detected_params) > 0
    
    @property
    def url(self) -> str:
        """Get full URL for this target"""
        if self.is_ip:
            return f"{self.scheme}://{self.host}:{self.port}"
        else:
            if (self.is_https and self.port == 443) or (not self.is_https and self.port == 80):
                return f"{self.scheme}://{self.host}"
            else:
                return f"{self.scheme}://{self.host}:{self.port}"
    
    def to_dict(self) -> Dict:
        """Convert to dictionary"""
        return {
            "original_input": self.original_input,
            "target_type": self.target_type.value,
            "host": self.host,
            "scheme": self.scheme,
            "port": self.port,
            "base_domain": self.base_domain,
            "scope": self.scope.value,
            "resolved_ips": self.resolved_ips,
            "is_resolvable": self.is_resolvable,
            "is_reachable": self.is_reachable,
            "http_status": self.http_status,
            "ports_hint": list(self.ports_hint),
            "is_web_target": self.is_web_target,
            "is_https": self.is_https,
            "detected_tech": self.detected_tech,
            "detected_cms": self.detected_cms,
            "detected_params": list(self.detected_params),
            "has_reflection": self.has_reflection,
            "is_vulnerable_to_xss": self.is_vulnerable_to_xss,
            "created_at": self.created_at.isoformat(),
        }
    
    def __repr__(self) -> str:
        """String representation"""
        return (
            f"TargetProfile(type={self.target_type.value}, "
            f"host={self.host}, "
            f"scope={self.scope.value}, "
            f"is_reachable={self.is_reachable}, "
            f"is_web={self.is_web_target})"
        )

    @classmethod
    def from_target(cls, target: str, scheme: str = "https") -> "TargetProfile":
        """
        Factory method to create TargetProfile from a target string.
        
        Args:
            target: Domain, subdomain, or IP
            scheme: http or https (default: https)
        
        Returns:
            TargetProfile instance
            
        Raises:
            ValueError: If scheme, host, or target is missing/invalid
        """
        import re
        
        # HARD-FAIL: No empty or non-string target
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Target must be a non-empty string")
        
        # HARD-FAIL: Scheme must be explicit and string
        if not isinstance(scheme, str) or scheme not in ("http", "https"):
            raise ValueError(f"Scheme must be 'http' or 'https', got: {scheme}")
        
        # Strip protocol if present
        clean_target = re.sub(r'^https?://', '', target)
        clean_target = clean_target.split('/')[0]  # Remove path
        clean_target = clean_target.split(':')[0]  # Remove port
        
        # HARD-FAIL: No empty host after parsing
        if not clean_target or not clean_target.strip():
            raise ValueError(f"Target resulted in empty host after parsing: {target}")
        
        # Determine target type
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, clean_target):
            target_type = TargetType.IP
            host = clean_target
            base_domain = None
        elif '.' in clean_target:
            parts = clean_target.split('.')
            if len(parts) == 2:
                target_type = TargetType.ROOT_DOMAIN
                host = clean_target
                base_domain = None
            else:
                target_type = TargetType.SUBDOMAIN
                host = clean_target
                base_domain = '.'.join(parts[-2:])
        else:
            target_type = TargetType.ROOT_DOMAIN
            host = clean_target
            base_domain = None
        
        is_https = scheme == "https"
        port = 443 if is_https else 80
        
        return cls(
            original_input=target,
            target_type=target_type,
            host=host,
            scheme=scheme,
            port=port,
            base_domain=base_domain,
            scope=TargetScope.SINGLE_HOST,
            resolved_ips=[host] if target_type == TargetType.IP else [],
            is_resolvable=target_type == TargetType.IP,
            is_web_target=True,
            is_https=is_https,
        )

    @property
    def type(self) -> TargetType:
        """Alias for target_type"""
        return self.target_type

    @property
    def runtime_budget(self) -> int:
        """Runtime budget in seconds"""
        if self.target_type == TargetType.ROOT_DOMAIN:
            return 1800
        elif self.target_type == TargetType.SUBDOMAIN:
            return 900
        else:
            return 600


class TargetProfileBuilder:
    """Fluent builder for creating immutable TargetProfile objects"""
    
    def __init__(self):
        """Initialize empty builder"""
        self._original_input: Optional[str] = None
        self._target_type: Optional[TargetType] = None
        self._host: Optional[str] = None
        self._scheme: str = "https"
        self._port: int = 443
        self._base_domain: Optional[str] = None
        self._scope: TargetScope = TargetScope.SINGLE_HOST
        self._resolved_ips: List[str] = []
        self._is_resolvable: bool = False
        self._is_reachable: bool = False
        self._http_status: Optional[int] = None
        self._ports_hint: Set[int] = set()
        self._is_web_target: bool = False
        self._is_https: bool = False
        self._detected_tech: Dict[str, str] = {}
        self._detected_cms: Optional[str] = None
        self._detected_params: Set[str] = set()
        self._has_reflection: bool = False
        self._is_vulnerable_to_xss: bool = False
    
    def with_original_input(self, input_str: str) -> "TargetProfileBuilder":
        """Set original user input"""
        self._original_input = input_str
        return self
    
    def with_target_type(self, target_type: TargetType) -> "TargetProfileBuilder":
        """Set target type"""
        self._target_type = target_type
        return self
    
    def with_host(self, host: str) -> "TargetProfileBuilder":
        """Set host (domain or IP)"""
        self._host = host
        return self
    
    def with_scheme(self, scheme: str) -> "TargetProfileBuilder":
        """Set scheme (http or https)"""
        self._scheme = scheme
        return self
    
    def with_port(self, port: int) -> "TargetProfileBuilder":
        """Set port"""
        self._port = port
        return self
    
    def with_base_domain(self, base_domain: str) -> "TargetProfileBuilder":
        """Set base domain (for subdomains)"""
        self._base_domain = base_domain
        return self
    
    def with_scope(self, scope: TargetScope) -> "TargetProfileBuilder":
        """Set recon scope"""
        self._scope = scope
        return self
    
    def with_resolved_ips(self, ips: List[str]) -> "TargetProfileBuilder":
        """Set resolved IPs"""
        self._resolved_ips = ips
        self._is_resolvable = len(ips) > 0
        return self
    
    def with_reachability(self, is_reachable: bool, status: Optional[int] = None) -> "TargetProfileBuilder":
        """Set reachability status"""
        self._is_reachable = is_reachable
        self._http_status = status
        return self
    
    def with_ports_hint(self, ports: Set[int]) -> "TargetProfileBuilder":
        """Set ports hint"""
        self._ports_hint = ports
        return self
    
    def with_is_web_target(self, is_web: bool) -> "TargetProfileBuilder":
        """Mark as web target"""
        self._is_web_target = is_web
        return self
    
    def with_is_https(self, is_https: bool) -> "TargetProfileBuilder":
        """Set HTTPS flag"""
        self._is_https = is_https
        return self
    
    def with_detected_tech(self, tech: Dict[str, str]) -> "TargetProfileBuilder":
        """Set detected technology"""
        self._detected_tech = tech
        return self
    
    def with_detected_cms(self, cms: Optional[str]) -> "TargetProfileBuilder":
        """Set detected CMS"""
        self._detected_cms = cms
        return self
    
    def with_detected_params(self, params: Set[str]) -> "TargetProfileBuilder":
        """Set detected parameters"""
        self._detected_params = params
        return self
    
    def with_has_reflection(self, has_reflection: bool) -> "TargetProfileBuilder":
        """Set reflection detection"""
        self._has_reflection = has_reflection
        return self
    
    def with_is_vulnerable_to_xss(self, is_vulnerable: bool) -> "TargetProfileBuilder":
        """Set XSS vulnerability flag"""
        self._is_vulnerable_to_xss = is_vulnerable
        return self
    
    def build(self) -> TargetProfile:
        """Build immutable TargetProfile"""
        if not self._original_input:
            raise ValueError("original_input is required")
        if not self._target_type:
            raise ValueError("target_type is required")
        if not self._host:
            raise ValueError("host is required")
        
        return TargetProfile(
            original_input=self._original_input,
            target_type=self._target_type,
            host=self._host,
            scheme=self._scheme,
            port=self._port,
            base_domain=self._base_domain,
            scope=self._scope,
            resolved_ips=self._resolved_ips,
            is_resolvable=self._is_resolvable,
            is_reachable=self._is_reachable,
            http_status=self._http_status,
            ports_hint=self._ports_hint,
            is_web_target=self._is_web_target,
            is_https=self._is_https,
            detected_tech=self._detected_tech,
            detected_cms=self._detected_cms,
            detected_params=self._detected_params,
            has_reflection=self._has_reflection,
            is_vulnerable_to_xss=self._is_vulnerable_to_xss,
        )
