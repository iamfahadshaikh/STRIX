"""
Execution Paths - Completely separate flows for root domain vs subdomain

RULE: Root domain and subdomain never share execution logic.
Not even utilities that might "just skip a few tools".

This prevents the leakage we saw before.
"""

from typing import List, Tuple, Dict
from target_profile import TargetProfile, TargetType
from decision_ledger import DecisionLedger


class RootDomainExecutor:
    """
    Execution path for ROOT DOMAIN targets.
    
    Complete reconnaissance:
    - DNS recon (full)
    - Subdomain enumeration
    - Network scanning
    - Web enumeration
    - Vulnerability scanning
    """
    
    def __init__(self, profile: TargetProfile, ledger: DecisionLedger):
        if profile.target_type != TargetType.ROOT_DOMAIN:
            raise ValueError("RootDomainExecutor only handles ROOT_DOMAIN targets")
        
        self.profile = profile
        self.ledger = ledger
    
    def get_execution_plan(self) -> List[Tuple[str, str, Dict]]:
        """
        Get the execution plan for root domain.
        
        Returns list of (tool_name, command, metadata)
        Only includes tools approved by ledger.
        """
        plan = []
        
        # ============ PHASE 1: DNS RECONNAISSANCE ============
        # AUTHORITATIVE PATH: One tool does comprehensive DNS recon
        # dnsrecon covers A, AAAA, NS, MX, TXT records + zone transfers
        # Removes duplication from dig_a, dig_ns, dig_mx, dig_aaaa
        dns_tools = [
            ("dnsrecon", f"dnsrecon -d {self.profile.host}", {"timeout": 30, "category": "DNS", "blocking": True, "requires": set(), "optional": set(), "produces": {"dns_records"}, "worst_case": 30}),
        ]
        
        for tool_name, cmd, meta in dns_tools:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 2: SUBDOMAIN ENUMERATION ============
        subdomain_tools = [
            ("findomain", f"findomain -t {self.profile.host} -q", {"timeout": 60, "category": "Subdomains", "blocking": True, "requires": set(), "optional": set(), "produces": {"subdomains"}, "worst_case": 60}),
            ("sublist3r", f"sublist3r -d {self.profile.host} -o /dev/null", {"timeout": 120, "category": "Subdomains", "blocking": True, "requires": set(), "optional": set(), "produces": {"subdomains"}, "worst_case": 120}),
            ("assetfinder", f"assetfinder {self.profile.host}", {"timeout": 60, "category": "Subdomains", "blocking": True, "requires": set(), "optional": set(), "produces": {"subdomains"}, "worst_case": 60}),
        ]
        
        for tool_name, cmd, meta in subdomain_tools:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 3: NETWORK SCANNING ============
        network_tools = [
            ("ping", f"ping -c 1 {self.profile.host}", {"timeout": 10, "category": "Network", "blocking": True, "requires": set(), "optional": set(), "produces": {"reachable"}, "worst_case": 10}),
            ("nmap_quick", f"nmap -F {self.profile.host}", {"timeout": 180, "category": "Network", "blocking": True, "requires": {"reachable"}, "optional": set(), "produces": {"ports_known"}, "worst_case": 180}),
            ("nmap_vuln", f"nmap -sV --script vuln --script-timeout 60s --host-timeout 120s {self.profile.host}", {"timeout": 240, "category": "Network", "blocking": True, "requires": {"ports_known"}, "optional": set(), "produces": {"vuln_signal"}, "worst_case": 240}),
        ]
        
        for tool_name, cmd, meta in network_tools:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 4: WEB DETECTION ============
        web_detection = [
            ("whatweb", f"whatweb {self.profile.url} -a 3", {"timeout": 60, "category": "Web", "blocking": True, "requires": {"web_target"}, "optional": set(), "produces": {"tech_stack_detected"}, "worst_case": 60}),
            ("nikto", f"nikto -h {self.profile.url}", {"timeout": 120, "category": "Web", "blocking": True, "requires": {"web_target"}, "optional": set(), "produces": {"web_findings"}, "worst_case": 120}),
        ]
        
        for tool_name, cmd, meta in web_detection:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 5: SSL/TLS ============
        tls_tools = [
            ("sslscan", f"sslscan {self.profile.host}", {"timeout": 120, "category": "SSL", "blocking": True, "requires": {"https"}, "optional": set(), "produces": {"tls_findings"}, "worst_case": 120}),
            ("testssl", f"testssl.sh {self.profile.url}", {"timeout": 240, "category": "SSL", "blocking": True, "requires": {"https"}, "optional": set(), "produces": {"tls_findings"}, "worst_case": 240}),
        ]
        
        for tool_name, cmd, meta in tls_tools:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 6: WEB ENUMERATION ============
        web_enum = [
            ("gobuster", f"gobuster dir -u {self.profile.url} -w /usr/share/wordlists/dirb/common.txt --status-codes-blacklist 403", 
             {"timeout": 9999, "category": "Web", "blocking": True, "requires": {"web_target"}, "optional": {"endpoints_known"}, "produces": {"endpoints_known", "live_endpoints"}, "worst_case": 9999}),
            ("dirsearch", f"dirsearch -u {self.profile.url} -w /usr/share/wordlists/dirb/common.txt", 
             {"timeout": 150, "category": "Web", "blocking": True, "requires": {"web_target"}, "optional": {"endpoints_known"}, "produces": {"endpoints_known", "live_endpoints"}, "worst_case": 150}),
        ]
        
        for tool_name, cmd, meta in web_enum:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 7: VULNERABILITY SCANNING ============
        vuln_tools = [
            ("dalfox", f"dalfox url {self.profile.url} --silence", 
             {"timeout": 300, "category": "XSS", "blocking": True, "requires": {"endpoints_known"}, "optional": {"reflections"}, "produces": {"xss_findings"}, "worst_case": 300}),
            ("xsstrike", f"xsstrike -u {self.profile.url} --crawl", 
             {"timeout": 300, "category": "XSS", "blocking": True, "requires": {"endpoints_known"}, "optional": {"reflections"}, "produces": {"xss_findings"}, "worst_case": 300}),
            ("sqlmap", f"sqlmap -u {self.profile.url} --batch --crawl=2", 
             {"timeout": 300, "category": "SQLi", "blocking": True, "requires": {"endpoints_known", "params_known"}, "optional": set(), "produces": {"sqli_findings"}, "worst_case": 300}),
            ("xsser", f"xsser -u {self.profile.url}", 
             {"timeout": 300, "category": "XSS", "blocking": True, "requires": {"endpoints_known"}, "optional": {"reflections"}, "produces": {"xss_findings"}, "worst_case": 300}),
            ("commix", f"commix -u {self.profile.url}", 
             {"timeout": 300, "category": "Injection", "blocking": True, "requires": {"endpoints_known", "params_known"}, "optional": {"command_params"}, "produces": {"rce_findings"}, "worst_case": 300}),
        ]
        
        for tool_name, cmd, meta in vuln_tools:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 8: NUCLEI SCANNING (FORCED ON ALL) ============
        nuclei_tools = [
            ("nuclei_crit", f"nuclei -u {self.profile.url} -tags critical -silent", 
             {"timeout": 600, "category": "Nuclei", "blocking": True, "requires": {"web_target"}, "optional": {"ports_known", "endpoints_known", "live_endpoints"}, "produces": {"web_findings"}, "worst_case": 600}),
            ("nuclei_high", f"nuclei -u {self.profile.url} -tags high -silent", 
             {"timeout": 600, "category": "Nuclei", "blocking": True, "requires": {"web_target"}, "optional": {"ports_known", "endpoints_known", "live_endpoints"}, "produces": {"web_findings"}, "worst_case": 600}),
        ]
        
        for tool_name, cmd, meta in nuclei_tools:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        return plan


class SubdomainExecutor:
    """
    Execution path for SUBDOMAIN targets.
    
    Minimal, targeted reconnaissance:
    - DNS A/AAAA only (inherit NS from base)
    - No subdomain enumeration
    - Network scanning (minimal)
    - Web enumeration (if web target)
    - Vulnerability scanning (if evidence)
    
    Never runs full recon like root domain.
    """
    
    def __init__(self, profile: TargetProfile, ledger: DecisionLedger):
        if profile.target_type != TargetType.SUBDOMAIN:
            raise ValueError("SubdomainExecutor only handles SUBDOMAIN targets")
        
        self.profile = profile
        self.ledger = ledger
    
    def get_execution_plan(self) -> List[Tuple[str, str, Dict]]:
        """
        Get the execution plan for subdomain.
        
        Returns list of (tool_name, command, metadata)
        Only includes tools approved by ledger.
        """
        plan = []
        
        # ============ PHASE 1: MINIMAL DNS ============
        # AUTHORITATIVE PATH: Lightweight dig for A/AAAA only
        # Subdomains inherit NS/MX from root domain (no duplication)
        dns_tools = [
            ("dig_a", f"dig A {self.profile.host} +short", {"timeout": 30, "category": "DNS", "blocking": True, "requires": set(), "optional": set(), "produces": {"dns_records"}, "worst_case": 30}),
        ]
        for tool_name, cmd, meta in dns_tools:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        # NO SUBDOMAIN ENUMERATION - inherited from base_domain
        
        # ============ PHASE 2: NETWORK SCANNING (MINIMAL) ============
        network_tools = [
            ("ping", f"ping -c 1 {self.profile.host}", {"timeout": 10, "category": "Network", "blocking": True, "requires": set(), "optional": set(), "produces": {"reachable"}, "worst_case": 10}),
            ("nmap_quick", f"nmap -F {self.profile.host}", {"timeout": 180, "category": "Network", "blocking": True, "requires": {"reachable"}, "optional": set(), "produces": {"ports_known"}, "worst_case": 180}),
        ]
        
        for tool_name, cmd, meta in network_tools:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 3: WEB DETECTION ============
        if self.profile.is_web_target:
            web_detection = [
                ("whatweb", f"whatweb {self.profile.url} -a 3", {"timeout": 60, "category": "Web", "blocking": True, "requires": {"web_target"}, "optional": set(), "produces": {"tech_stack_detected"}, "worst_case": 60}),
                ("nikto", f"nikto -h {self.profile.url}", {"timeout": 90, "category": "Web", "blocking": True, "requires": {"web_target"}, "optional": set(), "produces": {"web_findings"}, "worst_case": 90}),
            ]
            
            for tool_name, cmd, meta in web_detection:
                if self.ledger.allows(tool_name):
                    plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 4: SSL/TLS (IF HTTPS) ============
        if self.profile.is_https:
            tls_tools = [
                ("sslscan", f"sslscan {self.profile.host}", {"timeout": 120, "category": "SSL", "blocking": True, "requires": {"https"}, "optional": set(), "produces": {"tls_findings"}, "worst_case": 120}),
            ]
            
            for tool_name, cmd, meta in tls_tools:
                if self.ledger.allows(tool_name):
                    plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 5: WEB ENUMERATION (IF WEB TARGET) ============
        if self.profile.is_web_target:
            web_enum = [
                ("gobuster", f"gobuster dir -u {self.profile.url} -w /usr/share/wordlists/dirb/common.txt --status-codes-blacklist 403", 
                 {"timeout": 9999, "category": "Web", "blocking": True, "requires": {"web_target"}, "optional": {"endpoints_known"}, "produces": {"endpoints_known", "live_endpoints"}, "worst_case": 9999}),
            ]
            
            for tool_name, cmd, meta in web_enum:
                if self.ledger.allows(tool_name):
                    plan.append((tool_name, cmd, meta))
        
        # ============ VULNERABILITY SCANNING (SUBDOMAIN ONLY) ============
        vuln_tools = [
            ("nuclei_crit", f"nuclei -u {self.profile.url} -tags critical -silent", 
             {"timeout": 600, "category": "Nuclei", "blocking": True, "requires": {"web_target"}, "optional": {"ports_known", "endpoints_known", "live_endpoints"}, "produces": {"web_findings"}, "worst_case": 600}),
            ("nuclei_high", f"nuclei -u {self.profile.url} -tags high -silent", 
             {"timeout": 600, "category": "Nuclei", "blocking": True, "requires": {"web_target"}, "optional": {"ports_known", "endpoints_known", "live_endpoints"}, "produces": {"web_findings"}, "worst_case": 600}),
        ]
        
        for tool_name, cmd, meta in vuln_tools:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        return plan


class IPExecutor:
    """
    Execution path for IP targets.
    
    Minimal reconnaissance (no DNS, no domain recon):
    - Network scanning
    - Web enumeration (if web port open)
    - SSL/TLS (if HTTPS port open)
    - Vulnerability scanning (if evidence)
    """
    
    def __init__(self, profile: TargetProfile, ledger: DecisionLedger):
        if profile.target_type != TargetType.IP:
            raise ValueError("IPExecutor only handles IP targets")
        
        self.profile = profile
        self.ledger = ledger
    
    def get_execution_plan(self) -> List[Tuple[str, str, Dict]]:
        """
        Get the execution plan for IP.
        
        Returns list of (tool_name, command, metadata)
        Only includes tools approved by ledger.
        """
        plan = []
        
        # NO DNS - IP is already resolved
        
        # ============ PHASE 1: NETWORK SCANNING ============
        network_tools = [
            ("ping", f"ping -c 1 {self.profile.host}", {"timeout": 10, "category": "Network", "blocking": True, "requires": set(), "optional": set(), "produces": {"reachable"}, "worst_case": 10}),
            ("nmap_quick", f"nmap -F {self.profile.host}", {"timeout": 180, "category": "Network", "blocking": True, "requires": {"reachable"}, "optional": set(), "produces": {"ports_known"}, "worst_case": 180}),
        ]
        
        for tool_name, cmd, meta in network_tools:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 2: WEB DETECTION (IF WEB) ============
        if self.profile.is_web_target:
            web_detection = [
                ("whatweb", f"whatweb {self.profile.url} -a 3", {"timeout": 60, "category": "Web", "blocking": True, "requires": {"web_target"}, "optional": set(), "produces": {"tech_stack_detected"}, "worst_case": 60}),
            ]
            
            for tool_name, cmd, meta in web_detection:
                if self.ledger.allows(tool_name):
                    plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 3: SSL/TLS (IF HTTPS) ============
        if self.profile.is_https:
            tls_tools = [
                ("sslscan", f"sslscan {self.profile.host}:{self.profile.port}", 
                 {"timeout": 120, "category": "SSL", "blocking": True, "requires": {"https"}, "optional": set(), "produces": {"tls_findings"}, "worst_case": 120}),
            ]
            
            for tool_name, cmd, meta in tls_tools:
                if self.ledger.allows(tool_name):
                    plan.append((tool_name, cmd, meta))
        
        # ============ PHASE 4: WEB ENUMERATION ============
        if self.profile.is_web_target:
            web_enum = [
                ("gobuster", f"gobuster dir -u {self.profile.url} -w /usr/share/wordlists/dirb/common.txt --status-codes-blacklist 403", 
                 {"timeout": 9999, "category": "Web", "blocking": True, "requires": {"web_target"}, "optional": {"endpoints_known"}, "produces": {"endpoints_known", "live_endpoints"}, "worst_case": 9999}),
            ]
            
            for tool_name, cmd, meta in web_enum:
                if self.ledger.allows(tool_name):
                    plan.append((tool_name, cmd, meta))
        
        # ============ VULNERABILITY SCANNING (IP ONLY) ============
        vuln_tools = [
            ("nuclei_crit", f"nuclei -u {self.profile.url} -tags critical -silent", 
             {"timeout": 600, "category": "Nuclei", "blocking": True, "requires": {"web_target"}, "optional": {"ports_known", "endpoints_known", "live_endpoints"}, "produces": {"web_findings"}, "worst_case": 600}),
            ("nuclei_high", f"nuclei -u {self.profile.url} -tags high -silent", 
             {"timeout": 600, "category": "Nuclei", "blocking": True, "requires": {"web_target"}, "optional": {"ports_known", "endpoints_known", "live_endpoints"}, "produces": {"web_findings"}, "worst_case": 600}),
        ]
        
        for tool_name, cmd, meta in vuln_tools:
            if self.ledger.allows(tool_name):
                plan.append((tool_name, cmd, meta))
        
        return plan


def get_executor(profile: TargetProfile, ledger: DecisionLedger):
    """
    Get the appropriate executor for target type.
    
    This is the ONLY place target type is checked.
    Execution never splits on target type after this point.
    """
    if profile.is_root_domain:
        return RootDomainExecutor(profile, ledger)
    elif profile.is_subdomain:
        return SubdomainExecutor(profile, ledger)
    elif profile.is_ip:
        return IPExecutor(profile, ledger)
    else:
        raise ValueError(f"Unknown target type: {profile.target_type}")
