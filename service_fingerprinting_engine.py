"""
Service Fingerprinting Engine
Purpose: Identify services, versions, and technology stacks on discovered ports
"""

import logging
import socket
import ssl
import requests
import re
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ServiceFingerprint:
    """Service fingerprinting result"""
    host: str
    port: int
    protocol: str  # http, https, ssh, mysql, redis, etc
    service_name: str  # Human readable name
    version: Optional[str] = None
    technology_stack: List[str] = None  # e.g., ["Apache", "PHP", "MySQL"]
    confidence: float = 0.0
    evidence: str = ""
    
    def __post_init__(self):
        if self.technology_stack is None:
            self.technology_stack = []
    
    def to_dict(self) -> Dict:
        return {
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service_name,
            "version": self.version,
            "technology_stack": self.technology_stack,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


class ServiceFingerprintingEngine:
    """
    Service fingerprinting and identification engine
    
    Techniques:
    - Banner grabbing (connect and read banner)
    - HTTP header analysis
    - SSL/TLS certificate inspection
    - Version detection via response patterns
    - Technology stack inference
    """
    
    # Service signatures: port -> list of service candidates
    PORT_SERVICE_MAP = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        5432: "PostgreSQL",
        5984: "CouchDB",
        6379: "Redis",
        8000: "HTTP",
        8080: "HTTP Proxy",
        8081: "HTTP Admin/Proxy",
        8443: "HTTPS",
        9000: "HTTP",
        9200: "Elasticsearch",
        27017: "MongoDB",
        27018: "MongoDB",
        27019: "MongoDB",
    }
    
    # Service-specific patterns for banner analysis
    SERVICE_PATTERNS = {
        "Apache": r"Apache/(\d+\.\d+\.\d+)",
        "Nginx": r"nginx/(\d+\.\d+\.\d+)",
        "IIS": r"IIS/(\d+\.\d+)",
        "PHP": r"PHP/(\d+\.\d+\.\d+)",
        "Java": r"Java/(\d+\.\d+\.\d+)|tomcat",
        "Rails": r"Ruby.*Rails",
        "Django": r"Django",
        "Flask": r"Flask",
        "Node.js": r"Node\.js|Express",
        "Python": r"Python/(\d+\.\d+\.\d+)",
        "OpenSSL": r"OpenSSL/(\d+\.\d+\.\d+)",
    }
    
    def __init__(self):
        self.fingerprints: List[ServiceFingerprint] = []
    
    def fingerprint_service(self, host: str, port: int, 
                          protocol: str = "tcp") -> Optional[ServiceFingerprint]:
        """
        Fingerprint a service on a specific port
        
        Args:
            host: Target host
            port: Port number
            protocol: tcp or udp
        
        Returns: ServiceFingerprint object or None if service not reachable
        """
        logger.info(f"Fingerprinting {host}:{port}...")
        
        # Try multiple fingerprinting techniques
        # 1. Port-based guess
        service = self._guess_service_by_port(port)
        if not service:
            service = "Unknown"
        
        # 2. Banner grabbing
        banner, protocol_type = self._grab_banner(host, port)
        
        if not banner:
            logger.debug(f"No banner for {host}:{port}")
            return None
        
        # 3. Analyze banner for technology
        version, tech_stack, confidence = self._analyze_banner(banner, service)
        
        # 4. Additional HTTP analysis if HTTP service
        if service in ["HTTP", "HTTPS"] or protocol_type == "http":
            http_tech = self._fingerprint_http_service(host, port, 
                                                       protocol="https" if port == 443 else "http")
            if http_tech:
                tech_stack.extend(http_tech.get("technologies", []))
                confidence = max(confidence, http_tech.get("confidence", 0.0))
        
        # Create fingerprint
        fp = ServiceFingerprint(
            host=host,
            port=port,
            protocol=protocol_type or protocol,
            service_name=service,
            version=version,
            technology_stack=tech_stack,
            confidence=confidence,
            evidence=banner[:100] if banner else ""
        )
        
        self.fingerprints.append(fp)
        return fp
    
    def _grab_banner(self, host: str, port: int) -> tuple[Optional[str], Optional[str]]:
        """
        Grab service banner via socket connection
        
        Returns: (banner_text, protocol_type)
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Try to read banner
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            except:
                banner = ""
            
            # Send HTTP request if likely HTTP service
            if not banner or len(banner) < 10:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                try:
                    banner = sock.recv(1024).decode('utf-8', errors='ignore')
                    return banner, "http"
                except:
                    pass
            
            sock.close()
            
            if banner:
                logger.debug(f"Banner captured ({len(banner)} bytes)")
                return banner, self._detect_protocol_from_banner(banner)
        
        except socket.timeout:
            logger.debug(f"Timeout connecting to {host}:{port}")
        except ConnectionRefusedError:
            logger.debug(f"Connection refused to {host}:{port}")
        except Exception as e:
            logger.debug(f"Error grabbing banner: {e}")
        
        return None, None
    
    def _detect_protocol_from_banner(self, banner: str) -> Optional[str]:
        """Detect protocol from banner content"""
        if "HTTP/" in banner:
            return "http"
        elif "SSH" in banner:
            return "ssh"
        elif "SMTP" in banner:
            return "smtp"
        elif "220" in banner:  # FTP response code
            return "ftp"
        elif "IMAP" in banner:
            return "imap"
        elif "POP3" in banner:
            return "pop3"
        return None
    
    def _guess_service_by_port(self, port: int) -> Optional[str]:
        """Guess service name by port number"""
        return self.PORT_SERVICE_MAP.get(port, None)
    
    def _analyze_banner(self, banner: str, service: str) -> tuple[Optional[str], List[str], float]:
        """
        Analyze banner for version and technology information
        
        Returns: (version, tech_stack, confidence)
        """
        tech_stack = []
        version = None
        confidence = 0.0
        
        # Extract version info
        for tech_name, pattern in self.SERVICE_PATTERNS.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                tech_stack.append(tech_name)
                if len(match.groups()) > 0:
                    version = match.group(1)
                confidence = max(confidence, 0.8)
        
        # Known services (increase confidence)
        if service in banner:
            confidence = max(confidence, 0.7)
        
        # Multiple technologies detected (increase confidence)
        if len(tech_stack) > 1:
            confidence = min(0.95, confidence + 0.15)
        
        return version, tech_stack, confidence
    
    def _fingerprint_http_service(self, host: str, port: int,
                                  protocol: str = "http") -> Optional[Dict]:
        """
        Fingerprint HTTP service via HTTP headers and content analysis
        """
        try:
            url = f"{protocol}://{host}:{port}/"
            response = requests.head(url, timeout=5, verify=False, follow_redirects=False)
            
            tech_stack = []
            confidence = 0.5
            
            # Analyze headers
            headers = response.headers
            
            # Server header
            if "Server" in headers:
                server_header = headers["Server"]
                tech_stack.append(server_header)
                
                # Extract version from server header
                if "Apache" in server_header:
                    tech_stack.append("Apache")
                if "Nginx" in server_header:
                    tech_stack.append("Nginx")
                if "IIS" in server_header:
                    tech_stack.append("IIS")
                
                confidence = 0.85
            
            # X-Powered-By header
            if "X-Powered-By" in headers:
                tech_stack.append(headers["X-Powered-By"])
                confidence = 0.90
            
            # X-AspNet-Version (ASP.NET)
            if "X-AspNet-Version" in headers:
                tech_stack.append("ASP.NET")
            
            # Content analysis
            if response.status_code < 300:
                # Try to get more content info
                try:
                    response_full = requests.get(url, timeout=5, verify=False)
                    
                    # Look for technology signatures
                    content = response_full.text
                    
                    if "meta name=\"generator\"" in content:
                        match = re.search(r'content="([^"]+)"', content)
                        if match:
                            tech_stack.append(match.group(1))
                    
                    # Common tech detection
                    if "WordPress" in content:
                        tech_stack.append("WordPress")
                    if "Joomla" in content:
                        tech_stack.append("Joomla")
                    if "Drupal" in content:
                        tech_stack.append("Drupal")
                
                except:
                    pass
            
            return {
                "technologies": list(set(tech_stack)),  # Deduplicate
                "confidence": confidence
            }
        
        except Exception as e:
            logger.debug(f"Error fingerprinting HTTP service: {e}")
            return None
    
    def fingerprint_port_range(self, host: str, ports: List[int],
                              use_common_only: bool = True) -> List[ServiceFingerprint]:
        """
        Fingerprint multiple ports
        
        Args:
            host: Target host
            ports: List of ports to fingerprint
            use_common_only: Only fingerprint common service ports
        
        Returns: List of ServiceFingerprint objects
        """
        results = []
        
        for port in ports:
            # Skip if not in common port map and use_common_only is True
            if use_common_only and port not in self.PORT_SERVICE_MAP:
                continue
            
            fp = self.fingerprint_service(host, port)
            if fp:
                results.append(fp)
        
        return results
    
    def get_fingerprints_by_host(self, host: str) -> List[ServiceFingerprint]:
        """Get all fingerprints for a specific host"""
        return [fp for fp in self.fingerprints if fp.host == host]
    
    def get_fingerprints_by_service(self, service_name: str) -> List[ServiceFingerprint]:
        """Get all fingerprints for a specific service"""
        return [fp for fp in self.fingerprints 
                if service_name.lower() in fp.service_name.lower()]
    
    def export_fingerprints(self) -> List[Dict]:
        """Export all fingerprints as dictionaries"""
        return [fp.to_dict() for fp in self.fingerprints]
