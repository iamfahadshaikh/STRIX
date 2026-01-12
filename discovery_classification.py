"""
Discovery Tool Classification - Phase 1 Hardening
Purpose: Classify every discovery tool with explicit contracts
"""

from dataclasses import dataclass
from enum import Enum
from typing import Set, Optional


class ToolClass(Enum):
    """Discovery tool classification"""
    SIGNAL_PRODUCER = "signal_producer"  # Produces actionable signals
    INFORMATIONAL_ONLY = "informational_only"  # Nice-to-have, no hard signals
    EXTERNAL_INTEL = "external_intel"  # Third-party enrichment


@dataclass
class ToolContract:
    """Explicit contract for discovery tools"""
    tool_name: str
    classification: ToolClass
    signals_produced: Set[str]
    confidence_weight: float  # 0.0-1.0
    missing_output_acceptable: bool
    requires_network: bool = True
    description: str = ""


# Tool Registry - Single Source of Truth
DISCOVERY_TOOLS = {
    # === DNS Tools (signal_producer) ===
    "dig_a": ToolContract(
        tool_name="dig_a",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"dns_resolved", "ip_address"},
        confidence_weight=0.95,
        missing_output_acceptable=False,
        description="DNS A record resolution"
    ),
    "dig_ns": ToolContract(
        tool_name="dig_ns",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"nameservers"},
        confidence_weight=0.9,
        missing_output_acceptable=True,
        description="DNS NS record enumeration"
    ),
    "dig_mx": ToolContract(
        tool_name="dig_mx",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"mail_servers"},
        confidence_weight=0.9,
        missing_output_acceptable=True,
        description="DNS MX record enumeration"
    ),
    "dnsrecon": ToolContract(
        tool_name="dnsrecon",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"subdomains", "dns_records"},
        confidence_weight=0.85,
        missing_output_acceptable=True,
        description="Comprehensive DNS reconnaissance"
    ),
    
    # === Network Tools (signal_producer) ===
    "ping": ToolContract(
        tool_name="ping",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"reachable", "network_latency"},
        confidence_weight=0.9,
        missing_output_acceptable=False,
        description="ICMP reachability check"
    ),
    "nmap_quick": ToolContract(
        tool_name="nmap_quick",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"ports_known", "open_ports", "services"},
        confidence_weight=0.95,
        missing_output_acceptable=False,
        description="Port scan (common ports)"
    ),
    "nmap_vuln": ToolContract(
        tool_name="nmap_vuln",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"vulnerabilities", "service_versions"},
        confidence_weight=0.85,
        missing_output_acceptable=True,
        description="Vulnerability scan via NSE scripts"
    ),
    
    # === Web Detection (signal_producer) ===
    "whatweb": ToolContract(
        tool_name="whatweb",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"web_target", "tech_stack", "cms"},
        confidence_weight=0.9,
        missing_output_acceptable=False,
        description="Web technology fingerprinting"
    ),
    
    # === SSL/TLS (signal_producer) ===
    "sslscan": ToolContract(
        tool_name="sslscan",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"https", "ssl_version", "ciphers"},
        confidence_weight=0.95,
        missing_output_acceptable=True,
        description="SSL/TLS configuration scan"
    ),
    "testssl": ToolContract(
        tool_name="testssl",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"https", "ssl_vulnerabilities"},
        confidence_weight=0.9,
        missing_output_acceptable=True,
        description="Comprehensive SSL/TLS testing"
    ),
    
    # === Subdomain Enumeration (signal_producer) ===
    "findomain": ToolContract(
        tool_name="findomain",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"subdomains"},
        confidence_weight=0.85,
        missing_output_acceptable=True,
        description="Fast subdomain enumeration"
    ),
    "sublist3r": ToolContract(
        tool_name="sublist3r",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"subdomains"},
        confidence_weight=0.8,
        missing_output_acceptable=True,
        description="Multi-source subdomain enumeration"
    ),
    "assetfinder": ToolContract(
        tool_name="assetfinder",
        classification=ToolClass.SIGNAL_PRODUCER,
        signals_produced={"subdomains"},
        confidence_weight=0.8,
        missing_output_acceptable=True,
        description="Asset discovery via passive sources"
    ),
    
    # === Directory Enumeration (informational_only - high noise) ===
    "gobuster": ToolContract(
        tool_name="gobuster",
        classification=ToolClass.INFORMATIONAL_ONLY,
        signals_produced={"endpoints"},
        confidence_weight=0.7,
        missing_output_acceptable=True,
        description="Directory brute-force (wordlist-based)"
    ),
    "dirsearch": ToolContract(
        tool_name="dirsearch",
        classification=ToolClass.INFORMATIONAL_ONLY,
        signals_produced={"endpoints"},
        confidence_weight=0.7,
        missing_output_acceptable=True,
        description="Web path scanner"
    ),
    
    # === External Intel (external_intel) ===
    "crtsh": ToolContract(
        tool_name="crtsh",
        classification=ToolClass.EXTERNAL_INTEL,
        signals_produced={"subdomains", "certificates"},
        confidence_weight=0.8,
        missing_output_acceptable=True,
        requires_network=True,
        description="Certificate transparency logs (crt.sh)"
    ),
}


def get_tool_contract(tool_name: str) -> Optional[ToolContract]:
    """Get contract for a tool"""
    return DISCOVERY_TOOLS.get(tool_name)


def get_tool_contract(tool_name: str) -> ToolContract:
    """Get contract for a tool, with default fallback"""
    if tool_name in DISCOVERY_TOOLS:
        return DISCOVERY_TOOLS[tool_name]
    
    # Default for unknown tools: informational_only
    logger.warning(f"Tool '{tool_name}' not in registry - defaulting to INFORMATIONAL_ONLY")
    return ToolContract(
        tool_name=tool_name,
        classification=ToolClass.INFORMATIONAL_ONLY,
        signals_produced=set(),
        confidence_weight=0.5,
        missing_output_acceptable=True,
        description="Unknown tool - informational only"
    )


def is_signal_producer(tool_name: str) -> bool:
    """Check if tool produces hard signals"""
    contract = get_tool_contract(tool_name)
    return contract and contract.classification == ToolClass.SIGNAL_PRODUCER


def is_informational_only(tool_name: str) -> bool:
    """Check if tool is informational only"""
    contract = get_tool_contract(tool_name)
    return contract and contract.classification == ToolClass.INFORMATIONAL_ONLY


def is_external_intel(tool_name: str) -> bool:
    """Check if tool is external intelligence"""
    contract = get_tool_contract(tool_name)
    return contract and contract.classification == ToolClass.EXTERNAL_INTEL


def get_expected_signals(tool_name: str) -> Set[str]:
    """Get signals expected from tool"""
    contract = get_tool_contract(tool_name)
    return contract.signals_produced if contract else set()
