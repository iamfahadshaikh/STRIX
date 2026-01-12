"""
External Intelligence Connector - Phase 1 Fix
Integration for crt.sh, Shodan, Censys (read-only, external_intel tagged)
"""

import logging
import requests
import json
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ExternalIntelResult:
    """Result from external intelligence source"""
    source: str
    data_type: str
    results: List[Dict]
    success: bool
    error: Optional[str] = None


class CrtShConnector:
    """crt.sh certificate transparency connector"""
    
    BASE_URL = "https://crt.sh"
    
    @staticmethod
    def query_domain(domain: str, timeout: int = 10) -> ExternalIntelResult:
        """Query crt.sh for certificate transparency logs"""
        try:
            url = f"{CrtShConnector.BASE_URL}/?q={domain}&output=json"
            
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            
            data = response.json()
            
            # Extract subdomains
            subdomains = set()
            for cert in data:
                name_value = cert.get("name_value", "")
                for subdomain in name_value.split('\n'):
                    subdomain = subdomain.strip()
                    if subdomain and not subdomain.startswith('*'):
                        subdomains.add(subdomain)
            
            results = [{"subdomain": sub} for sub in sorted(subdomains)]
            
            logger.info(f"[crt.sh] Found {len(results)} certificate entries for {domain}")
            
            return ExternalIntelResult(
                source="crt.sh",
                data_type="certificate_transparency",
                results=results,
                success=True
            )
            
        except requests.exceptions.Timeout:
            logger.warning(f"[crt.sh] Timeout for {domain}")
            return ExternalIntelResult(
                source="crt.sh",
                data_type="certificate_transparency",
                results=[],
                success=False,
                error="timeout"
            )
        except Exception as e:
            logger.error(f"[crt.sh] Error: {e}")
            return ExternalIntelResult(
                source="crt.sh",
                data_type="certificate_transparency",
                results=[],
                success=False,
                error=str(e)
            )


class ShodanConnector:
    """Shodan API connector (requires API key)"""
    
    BASE_URL = "https://api.shodan.io"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
    
    def query_host(self, ip: str, timeout: int = 10) -> ExternalIntelResult:
        """Query Shodan for host information"""
        if not self.api_key:
            return ExternalIntelResult(
                source="shodan",
                data_type="host_info",
                results=[],
                success=False,
                error="api_key_required"
            )
        
        try:
            url = f"{self.BASE_URL}/shodan/host/{ip}?key={self.api_key}"
            
            response = requests.get(url, timeout=timeout)
            response.raise_for_status()
            
            data = response.json()
            
            results = [{
                "ip": data.get("ip_str"),
                "ports": data.get("ports", []),
                "hostnames": data.get("hostnames", []),
                "os": data.get("os"),
                "tags": data.get("tags", [])
            }]
            
            logger.info(f"[Shodan] Found data for {ip}")
            
            return ExternalIntelResult(
                source="shodan",
                data_type="host_info",
                results=results,
                success=True
            )
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                error = "invalid_api_key"
            elif e.response.status_code == 404:
                error = "ip_not_found"
            else:
                error = f"http_{e.response.status_code}"
            
            logger.warning(f"[Shodan] Error: {error}")
            return ExternalIntelResult(
                source="shodan",
                data_type="host_info",
                results=[],
                success=False,
                error=error
            )
        except Exception as e:
            logger.error(f"[Shodan] Error: {e}")
            return ExternalIntelResult(
                source="shodan",
                data_type="host_info",
                results=[],
                success=False,
                error=str(e)
            )


class CensysConnector:
    """Censys API connector (requires API ID and Secret)"""
    
    BASE_URL = "https://search.censys.io/api/v2"
    
    def __init__(self, api_id: Optional[str] = None, api_secret: Optional[str] = None):
        self.api_id = api_id
        self.api_secret = api_secret
    
    def query_host(self, ip: str, timeout: int = 10) -> ExternalIntelResult:
        """Query Censys for host information"""
        if not self.api_id or not self.api_secret:
            return ExternalIntelResult(
                source="censys",
                data_type="host_info",
                results=[],
                success=False,
                error="api_credentials_required"
            )
        
        try:
            url = f"{self.BASE_URL}/hosts/{ip}"
            
            response = requests.get(
                url,
                auth=(self.api_id, self.api_secret),
                timeout=timeout
            )
            response.raise_for_status()
            
            data = response.json()
            result = data.get("result", {})
            
            results = [{
                "ip": result.get("ip"),
                "services": result.get("services", []),
                "protocols": result.get("protocols", []),
                "autonomous_system": result.get("autonomous_system", {})
            }]
            
            logger.info(f"[Censys] Found data for {ip}")
            
            return ExternalIntelResult(
                source="censys",
                data_type="host_info",
                results=results,
                success=True
            )
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                error = "invalid_credentials"
            elif e.response.status_code == 404:
                error = "ip_not_found"
            else:
                error = f"http_{e.response.status_code}"
            
            logger.warning(f"[Censys] Error: {error}")
            return ExternalIntelResult(
                source="censys",
                data_type="host_info",
                results=[],
                success=False,
                error=error
            )
        except Exception as e:
            logger.error(f"[Censys] Error: {e}")
            return ExternalIntelResult(
                source="censys",
                data_type="host_info",
                results=[],
                success=False,
                error=str(e)
            )


class ExternalIntelAggregator:
    """Aggregate external intelligence sources"""
    
    def __init__(self, shodan_key: Optional[str] = None, 
                 censys_id: Optional[str] = None, 
                 censys_secret: Optional[str] = None):
        self.crtsh = CrtShConnector()
        self.shodan = ShodanConnector(api_key=shodan_key) if shodan_key else None
        self.censys = CensysConnector(api_id=censys_id, api_secret=censys_secret) if censys_id and censys_secret else None
    
    def gather_intel(self, domain: str, ip: Optional[str] = None) -> Dict[str, ExternalIntelResult]:
        """Gather intelligence from all available sources"""
        results = {}
        
        # crt.sh (always available, no API key)
        crtsh_result = self.crtsh.query_domain(domain)
        results["crtsh"] = crtsh_result
        
        # Shodan (if API key provided)
        if self.shodan and ip:
            shodan_result = self.shodan.query_host(ip)
            results["shodan"] = shodan_result
        
        # Censys (if credentials provided)
        if self.censys and ip:
            censys_result = self.censys.query_host(ip)
            results["censys"] = censys_result
        
        return results
    
    def to_cache_signals(self, intel_results: Dict[str, ExternalIntelResult], cache) -> None:
        """Convert external intel to cache signals (read-only, tagged)"""
        
        for source, result in intel_results.items():
            if not result.success:
                continue
            
            # Tag all signals from external intel
            cache.add_param(f"external_intel_{source}")
            
            # crt.sh subdomains
            if source == "crtsh":
                for item in result.results:
                    subdomain = item.get("subdomain")
                    if subdomain:
                        cache.subdomains.add(subdomain)
                        cache.add_param(f"subdomain_{subdomain}")
            
            # Shodan/Censys ports and services
            elif source in ["shodan", "censys"]:
                for item in result.results:
                    # Ports
                    ports = item.get("ports", [])
                    for port in ports:
                        cache.discovered_ports.add(port)
                    
                    # Services
                    services = item.get("services", [])
                    for service in services:
                        service_name = service.get("service_name") if isinstance(service, dict) else service
                        if service_name:
                            cache.add_param(f"external_service_{service_name}")
        
        logger.info(f"[ExternalIntel] Added signals from {len([r for r in intel_results.values() if r.success])} sources")
