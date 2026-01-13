"""
Discovery Cache: Mutable store for findings as tools run.

Feeds forward to gate later tools (commix, dalfox, sqlmap, nuclei).
"""

from dataclasses import dataclass, field
from typing import Set
from urllib.parse import urlparse, parse_qs


@dataclass
class DiscoveryCache:
    """
    Mutable discovery cache: grows as tools run.
    
    Used to gate tools:
    - commix: only if params found
    - dalfox: only if reflections found
    - sqlmap: only if GET params found
    - nuclei: scope to discovered endpoints
    
    Endpoint Registry: All tools feed here, later tools consume.
    """
    
    endpoints: Set[str] = field(default_factory=set)
    params: Set[str] = field(default_factory=set)
    reflections: Set[str] = field(default_factory=set)
    subdomains: Set[str] = field(default_factory=set)
    live_endpoints: Set[str] = field(default_factory=set)  # HTTP 200 only
    command_params: Set[str] = field(default_factory=set)
    ssrf_params: Set[str] = field(default_factory=set)
    discovered_ports: Set[int] = field(default_factory=set)  # Consolidate all ports
    signals: Set[str] = field(default_factory=set)  # Discovery signals (e.g., tls_evaluated, ssl_evaluated)
    
    def _normalize_endpoint(self, path: str) -> tuple[str, Set[str]]:
        """Normalize a path/url and extract any query param names."""
        if not path:
            return "", set()
        # Allow callers to pass either full URLs or relative paths
        candidate = path.strip()
        parsed = urlparse(candidate if candidate.startswith("http") else f"https://placeholder{candidate if candidate.startswith('/') else '/' + candidate}")
        clean_path = parsed.path or "/"
        params = set(parse_qs(parsed.query).keys())
        # Normalize double slashes and trailing slashes
        if len(clean_path) > 1 and clean_path.endswith("/"):
            clean_path = clean_path.rstrip("/")
        return clean_path, params

    def add_endpoint(self, path: str, source_tool: str | None = None, confidence: float | None = None, **kwargs):
        """Log discovered endpoint (e.g., /admin, /api/users) and capture params.
        Optional metadata (source_tool, confidence, kwargs) is accepted and ignored for now.
        """
        clean_path, params = self._normalize_endpoint(path)
        if not clean_path:
            return
        self.endpoints.add(clean_path)
        for param in params:
            self.add_param(param, source_tool=source_tool, confidence=confidence)
    
    def add_live_endpoint(self, path: str, source_tool: str = "unknown"):
        """Log live endpoint (HTTP 200 confirmed)."""
        clean_path, params = self._normalize_endpoint(path)
        if not clean_path:
            return
        self.live_endpoints.add(clean_path)
        self.endpoints.add(clean_path)  # Also add to general endpoints
        for param in params:
            self.add_param(param)
    
    def add_param(self, param: str, source_tool: str | None = None, confidence: float | None = None, **kwargs):
        """Log discovered parameter (e.g., id, search, q)
        Optional metadata (source_tool, confidence, kwargs) is accepted and ignored for now.
        """
        if param and param.strip():
            normalized = param.strip()
            self.params.add(normalized)
            # Heuristic: some params are strong reflection indicators
            reflective_hints = {"q", "s", "search", "redirect", "return", "next", "url", "target"}
            if normalized.lower() in reflective_hints:
                self.reflections.add(f"hint:{normalized}")
            command_hints = {"cmd", "command", "exec", "execute", "shell", "ping", "host", "ip", "target", "url", "path"}
            if normalized.lower() in command_hints:
                self.command_params.add(normalized)
            ssrf_hints = {"url", "uri", "target", "redirect", "return", "dest", "domain", "callback", "forward"}
            if normalized.lower() in ssrf_hints:
                self.ssrf_params.add(normalized)
    
    def add_reflection(self, reflection: str):
        """Log reflected parameter (XSS candidate)"""
        if reflection and reflection.strip():
            self.reflections.add(reflection.strip())
    
    def add_subdomain(self, subdomain: str):
        """Log discovered subdomain"""
        if subdomain and subdomain.strip():
            self.subdomains.add(subdomain.strip())
    
    def has_reflections(self) -> bool:
        """Check if any reflections found (XSS candidates)"""
        return len(self.reflections) > 0
    
    def has_params(self) -> bool:
        """Check if any parameters found"""
        return len(self.params) > 0

    def has_command_params(self) -> bool:
        """Check if any command-like parameters exist"""
        return len(self.command_params) > 0

    def has_ssrf_params(self) -> bool:
        """Check if SSRF-prone parameters exist"""
        return len(self.ssrf_params) > 0
    
    def has_endpoints(self) -> bool:
        """Check if any endpoints discovered"""
        return len(self.endpoints) > 0
    
    def has_live_endpoints(self) -> bool:
        """Check if any HTTP 200 endpoints found"""
        return len(self.live_endpoints) > 0
    
    def has_subdomains(self) -> bool:
        """Check if any subdomains enumerated"""
        return len(self.subdomains) > 0
    
    def add_signal(self, signal: str):
        """Add a discovery signal (e.g., tls_evaluated, ssl_evaluated)"""
        if signal and signal.strip():
            self.signals.add(signal.strip())
    
    def has_signal(self, signal: str) -> bool:
        """Check if a specific discovery signal is present"""
        return signal in self.signals
    
    def get_endpoints_for_tool(self, tool: str) -> list[str]:
        """
        Get endpoint list for specific tool.
        
        - commix/sqlmap/dalfox: use live_endpoints (HTTP 200 only)
        - nuclei: use all endpoints
        """
        if tool in ["commix", "sqlmap", "dalfox"]:
            return list(self.live_endpoints)
        return list(self.endpoints)
    
    def get_normalized_endpoints(self) -> list[str]:
        """Get all endpoints, normalized and deduplicated."""
        normalized = set()
        for ep in self.endpoints:
            clean, _ = self._normalize_endpoint(ep)
            if clean:
                normalized.add(clean)
        return sorted(normalized)
    
    def get_live_normalized_endpoints(self) -> list[str]:
        """Get live endpoints (HTTP 200), normalized and deduplicated."""
        normalized = set()
        for ep in self.live_endpoints:
            clean, _ = self._normalize_endpoint(ep)
            if clean:
                normalized.add(clean)
        return sorted(normalized)

    def summary(self) -> str:
        """Human-readable summary of discoveries"""
        return (
            f"Endpoints: {len(self.endpoints)}, "
            f"Live: {len(self.live_endpoints)}, "
            f"Params: {len(self.params)}, "
            f"CmdParams: {len(self.command_params)}, "
            f"SSRFParams: {len(self.ssrf_params)}, "
            f"Reflections: {len(self.reflections)}, "
            f"Subdomains: {len(self.subdomains)}, "
            f"Ports: {len(self.discovered_ports)}"
        )
    
    def add_port(self, port: int):
        """Log discovered port (from DNS, HTTP redirects, nmap, etc.). Single source of truth."""
        if 1 <= port <= 65535:
            self.discovered_ports.add(port)
    
    def get_discovered_ports(self) -> list[int]:
        """Get consolidated list of all discovered ports for nmap scanning"""
        return sorted(self.discovered_ports)

    def verify_subdomains(self, subdomains: list) -> list:
        """Verify subdomains are live via A/AAAA lookup only.
        
        Drop unresolvable hosts per execution_paths enforcement.
        Returns only verified subdomains.
        """
        import socket
        verified = []
        for subdomain in subdomains:
            try:
                # Skip empty or malformed subdomains
                if not subdomain or not subdomain.strip():
                    continue
                
                # Clean trailing dots and whitespace
                clean_subdomain = subdomain.strip().rstrip('.')
                if not clean_subdomain:
                    continue
                
                socket.getaddrinfo(clean_subdomain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                verified.append(clean_subdomain)
            except (socket.gaierror, UnicodeError, UnicodeEncodeError):
                # Unresolvable or malformed - skip
                pass
        return verified

