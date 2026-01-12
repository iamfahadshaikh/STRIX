"""
Discovery Signal Parser - Phase 1 Fix
Parse discovery tool stdout into structured signals
"""

import logging
import re
import json
from typing import Dict, List, Set, Optional

logger = logging.getLogger(__name__)


class DiscoverySignalParser:
    """Parse stdout from discovery tools into structured signals"""
    
    @staticmethod
    def parse_dig_output(stdout: str) -> Dict[str, any]:
        """Parse dig output"""
        signals = set()
        parsed_data = {}
        
        if not stdout:
            return {"signals": signals, "parsed": parsed_data, "success": False}
        
        try:
            # Extract IP addresses
            ips = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', stdout)
            if ips:
                signals.add("dns_resolved")
                signals.add("ip_address")
                parsed_data["ips"] = list(set(ips))
            
            # Check for NXDOMAIN
            if "NXDOMAIN" in stdout:
                parsed_data["status"] = "NXDOMAIN"
            elif "NOERROR" in stdout:
                signals.add("dns_noerror")
                parsed_data["status"] = "NOERROR"
            
            return {"signals": signals, "parsed": parsed_data, "success": len(signals) > 0}
        except Exception as e:
            logger.error(f"dig parse failed: {e}")
            return {"signals": set(), "parsed": {}, "success": False}
    
    @staticmethod
    def parse_nmap_output(stdout: str) -> Dict[str, any]:
        """Parse nmap output"""
        signals = set()
        parsed_data = {"ports": [], "services": []}
        
        if not stdout:
            return {"signals": signals, "parsed": parsed_data, "success": False}
        
        try:
            # Extract open ports
            port_pattern = r'(\d+)/(tcp|udp)\s+open\s+(\S+)'
            matches = re.findall(port_pattern, stdout)
            
            if matches:
                signals.add("ports_known")
                signals.add("open_ports")
                for port, proto, service in matches:
                    parsed_data["ports"].append({
                        "port": int(port),
                        "protocol": proto,
                        "service": service
                    })
                    parsed_data["services"].append(service)
                
                # Specific service signals
                services_lower = [s.lower() for s in parsed_data["services"]]
                if "http" in services_lower or "https" in services_lower:
                    signals.add("web_service")
                if "https" in services_lower or "ssl" in services_lower:
                    signals.add("https")
            
            # Check if host is up
            if "Host is up" in stdout:
                signals.add("reachable")
            
            return {"signals": signals, "parsed": parsed_data, "success": len(signals) > 0}
        except Exception as e:
            logger.error(f"nmap parse failed: {e}")
            return {"signals": set(), "parsed": {}, "success": False}
    
    @staticmethod
    def parse_whatweb_output(stdout: str) -> Dict[str, any]:
        """Parse whatweb output"""
        signals = set()
        parsed_data = {"technologies": [], "cms": None, "server": None}
        
        if not stdout:
            return {"signals": signals, "parsed": parsed_data, "success": False}
        
        try:
            # WhatWeb output format: [200 OK] Country[US] HTTPServer[nginx/1.18.0]...
            if "[200 OK]" in stdout or "[301" in stdout or "[302" in stdout:
                signals.add("web_target")
                signals.add("reachable")
            
            # Extract HTTP status
            status_match = re.search(r'\[(\d{3})\s+[^\]]+\]', stdout)
            if status_match:
                parsed_data["http_status"] = int(status_match.group(1))
            
            # Extract server
            server_match = re.search(r'HTTPServer\[([^\]]+)\]', stdout)
            if server_match:
                signals.add("tech_stack")
                parsed_data["server"] = server_match.group(1)
                parsed_data["technologies"].append(server_match.group(1))
            
            # Extract CMS
            cms_patterns = [
                r'WordPress',
                r'Drupal',
                r'Joomla',
                r'Magento',
                r'Shopify'
            ]
            for pattern in cms_patterns:
                if re.search(pattern, stdout, re.IGNORECASE):
                    signals.add("cms_detected")
                    parsed_data["cms"] = pattern
                    break
            
            # Check for HTTPS
            if "https://" in stdout.lower():
                signals.add("https")
            
            return {"signals": signals, "parsed": parsed_data, "success": len(signals) > 0}
        except Exception as e:
            logger.error(f"whatweb parse failed: {e}")
            return {"signals": set(), "parsed": {}, "success": False}
    
    @staticmethod
    def parse_nuclei_output(stdout: str) -> Dict[str, any]:
        """Parse nuclei output"""
        signals = set()
        parsed_data = {"findings": []}
        
        if not stdout:
            return {"signals": signals, "parsed": parsed_data, "success": False}
        
        try:
            # Nuclei output: [severity] [template-id] URL
            lines = stdout.split('\n')
            for line in lines:
                if not line.strip():
                    continue
                
                # Parse severity
                severity_match = re.search(r'\[(critical|high|medium|low|info)\]', line, re.IGNORECASE)
                if severity_match:
                    signals.add("vulnerability_detected")
                    severity = severity_match.group(1).lower()
                    
                    # Extract template ID
                    template_match = re.search(r'\[([^\]]+)\]', line)
                    template_id = template_match.group(1) if template_match else "unknown"
                    
                    parsed_data["findings"].append({
                        "severity": severity,
                        "template": template_id,
                        "raw": line.strip()
                    })
            
            return {"signals": signals, "parsed": parsed_data, "success": len(signals) > 0}
        except Exception as e:
            logger.error(f"nuclei parse failed: {e}")
            return {"signals": set(), "parsed": {}, "success": False}
    
    @staticmethod
    def parse_testssl_output(stdout: str) -> Dict[str, any]:
        """Parse testssl/sslscan output"""
        signals = set()
        parsed_data = {"vulnerabilities": [], "protocols": [], "ciphers": []}
        
        if not stdout:
            return {"signals": signals, "parsed": parsed_data, "success": False}
        
        try:
            # Check for SSL/TLS
            if "SSL" in stdout or "TLS" in stdout:
                signals.add("ssl_evaluated")
            
            # Extract vulnerabilities
            vuln_keywords = ["heartbleed", "poodle", "crime", "breach", "freak", "logjam"]
            for keyword in vuln_keywords:
                if re.search(keyword, stdout, re.IGNORECASE):
                    signals.add("ssl_vulnerability")
                    parsed_data["vulnerabilities"].append(keyword)
            
            # Weak ciphers
            if re.search(r'(RC4|NULL|EXPORT|DES)', stdout, re.IGNORECASE):
                signals.add("weak_cipher")
            
            # TLS versions
            tls_versions = re.findall(r'TLS\s*(\d\.\d)', stdout)
            if tls_versions:
                parsed_data["protocols"] = list(set(tls_versions))
            
            return {"signals": signals, "parsed": parsed_data, "success": len(signals) > 0}
        except Exception as e:
            logger.error(f"testssl parse failed: {e}")
            return {"signals": set(), "parsed": {}, "success": False}
    
    @staticmethod
    def parse_tool_output(tool_name: str, stdout: str) -> Dict[str, any]:
        """Main dispatcher for parsing tool output"""
        
        parsers = {
            "dig_a": DiscoverySignalParser.parse_dig_output,
            "nmap_quick": DiscoverySignalParser.parse_nmap_output,
            "nmap_full": DiscoverySignalParser.parse_nmap_output,
            "whatweb": DiscoverySignalParser.parse_whatweb_output,
            "nuclei": DiscoverySignalParser.parse_nuclei_output,
            "testssl": DiscoverySignalParser.parse_testssl_output,
            "sslscan": DiscoverySignalParser.parse_testssl_output,
        }
        
        # Get appropriate parser
        parser = parsers.get(tool_name)
        
        if not parser:
            # Unknown tool - no structured parsing
            return {
                "signals": set(),
                "parsed": {"raw_stdout": stdout},
                "success": False,
                "reason": "no_parser_available"
            }
        
        try:
            result = parser(stdout)
            return result
        except Exception as e:
            logger.error(f"Parser exception for {tool_name}: {e}")
            return {
                "signals": set(),
                "parsed": {},
                "success": False,
                "reason": f"parse_exception: {str(e)}"
            }


def parse_and_extract_signals(tool_name: str, stdout: str, cache) -> bool:
    """
    Parse tool output and populate cache with signals
    Returns True if signals were extracted, False if parsing failed
    """
    result = DiscoverySignalParser.parse_tool_output(tool_name, stdout)
    
    if not result["success"]:
        logger.warning(f"[{tool_name}] Signal extraction FAILED: {result.get('reason', 'unknown')}")
        return False
    
    # Add signals to cache
    for signal in result["signals"]:
        cache.add_param(signal)
    
    # Add parsed data to cache
    parsed = result.get("parsed", {})
    if "ips" in parsed:
        for ip in parsed["ips"]:
            cache.discovered_ips.add(ip)
    
    if "ports" in parsed:
        for port_info in parsed["ports"]:
            cache.discovered_ports.add(port_info["port"])
    
    logger.info(f"[{tool_name}] Extracted {len(result['signals'])} signals: {result['signals']}")
    return True
