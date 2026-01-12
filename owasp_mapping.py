"""
OWASP Top 10 Mapping - Phase 4 Hardening
Purpose: Map tool findings to OWASP Top 10 2021 categories
"""

from typing import Dict, Optional
from enum import Enum


class OWASPCategory(Enum):
    """OWASP Top 10 2021 Categories"""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021-Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021-Cryptographic Failures"
    A03_INJECTION = "A03:2021-Injection"
    A04_INSECURE_DESIGN = "A04:2021-Insecure Design"
    A05_SECURITY_MISCONFIGURATION = "A05:2021-Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021-Vulnerable and Outdated Components"
    A07_AUTH_FAILURES = "A07:2021-Identification and Authentication Failures"
    A08_DATA_INTEGRITY = "A08:2021-Software and Data Integrity Failures"
    A09_LOGGING_FAILURES = "A09:2021-Security Logging and Monitoring Failures"
    A10_SSRF = "A10:2021-Server-Side Request Forgery (SSRF)"
    UNMAPPED = "Unmapped"


# Mapping table: vulnerability type → OWASP category
OWASP_MAPPING = {
    # === A03: Injection ===
    "xss": OWASPCategory.A03_INJECTION,
    "xss_reflected": OWASPCategory.A03_INJECTION,
    "xss_stored": OWASPCategory.A03_INJECTION,
    "xss_dom": OWASPCategory.A03_INJECTION,
    "sql_injection": OWASPCategory.A03_INJECTION,
    "sqli": OWASPCategory.A03_INJECTION,
    "sql": OWASPCategory.A03_INJECTION,
    "command_injection": OWASPCategory.A03_INJECTION,
    "cmd_injection": OWASPCategory.A03_INJECTION,
    "ldap_injection": OWASPCategory.A03_INJECTION,
    "xpath_injection": OWASPCategory.A03_INJECTION,
    "template_injection": OWASPCategory.A03_INJECTION,
    "ssti": OWASPCategory.A03_INJECTION,
    
    # === A01: Broken Access Control ===
    "path_traversal": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "directory_traversal": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "lfi": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "local_file_inclusion": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "rfi": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "remote_file_inclusion": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "idor": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "insecure_direct_object_reference": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    "unauthorized_access": OWASPCategory.A01_BROKEN_ACCESS_CONTROL,
    
    # === A02: Cryptographic Failures ===
    "weak_ssl": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "ssl_vulnerability": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "tls_vulnerability": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "weak_cipher": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "cleartext_transmission": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "no_https": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    "sensitive_data_exposure": OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
    
    # === A05: Security Misconfiguration ===
    "default_credentials": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "directory_listing": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "misconfiguration": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "open_redirect": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "cors_misconfiguration": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "missing_security_headers": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    "info_disclosure": OWASPCategory.A05_SECURITY_MISCONFIGURATION,
    
    # === A06: Vulnerable Components ===
    "outdated_component": OWASPCategory.A06_VULNERABLE_COMPONENTS,
    "vulnerable_library": OWASPCategory.A06_VULNERABLE_COMPONENTS,
    "known_vulnerability": OWASPCategory.A06_VULNERABLE_COMPONENTS,
    "cve": OWASPCategory.A06_VULNERABLE_COMPONENTS,
    
    # === A07: Authentication Failures ===
    "broken_authentication": OWASPCategory.A07_AUTH_FAILURES,
    "weak_password": OWASPCategory.A07_AUTH_FAILURES,
    "session_fixation": OWASPCategory.A07_AUTH_FAILURES,
    "credential_stuffing": OWASPCategory.A07_AUTH_FAILURES,
    
    # === A10: SSRF ===
    "ssrf": OWASPCategory.A10_SSRF,
    "server_side_request_forgery": OWASPCategory.A10_SSRF,
}


def map_to_owasp(vuln_type: str) -> OWASPCategory:
    """
    Map vulnerability type to OWASP Top 10 category
    
    Args:
        vuln_type: Vulnerability type (e.g., "xss", "sql_injection")
        
    Returns:
        OWASPCategory
    """
    # Normalize input
    normalized = vuln_type.lower().replace(" ", "_").replace("-", "_")
    
    # Direct match
    if normalized in OWASP_MAPPING:
        return OWASP_MAPPING[normalized]
    
    # Partial match (e.g., "xss_reflected" matches "xss")
    for key, category in OWASP_MAPPING.items():
        if key in normalized or normalized in key:
            return category
    
    return OWASPCategory.UNMAPPED


def get_owasp_description(category: OWASPCategory) -> str:
    """Get description for OWASP category"""
    descriptions = {
        OWASPCategory.A01_BROKEN_ACCESS_CONTROL: "Access control enforces policy such that users cannot act outside their intended permissions",
        OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES: "Failures related to cryptography (or lack thereof) which often lead to exposure of sensitive data",
        OWASPCategory.A03_INJECTION: "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection, occur when untrusted data is sent to an interpreter",
        OWASPCategory.A04_INSECURE_DESIGN: "Missing or ineffective control design",
        OWASPCategory.A05_SECURITY_MISCONFIGURATION: "Security misconfiguration is commonly a result of insecure default configurations",
        OWASPCategory.A06_VULNERABLE_COMPONENTS: "Components with known vulnerabilities may allow attackers to compromise systems",
        OWASPCategory.A07_AUTH_FAILURES: "Confirmation of user identity, authentication, and session management is critical",
        OWASPCategory.A08_DATA_INTEGRITY: "Code and infrastructure that does not protect against integrity violations",
        OWASPCategory.A09_LOGGING_FAILURES: "Logging and monitoring failures allow attackers to achieve their goals undetected",
        OWASPCategory.A10_SSRF: "SSRF flaws occur when a web application fetches a remote resource without validating the user-supplied URL",
        OWASPCategory.UNMAPPED: "Vulnerability not mapped to OWASP Top 10 2021"
    }
    return descriptions.get(category, "No description available")


def get_severity_for_owasp(category: OWASPCategory) -> str:
    """Get typical severity for OWASP category"""
    severity_map = {
        OWASPCategory.A03_INJECTION: "CRITICAL",
        OWASPCategory.A01_BROKEN_ACCESS_CONTROL: "HIGH",
        OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES: "HIGH",
        OWASPCategory.A07_AUTH_FAILURES: "HIGH",
        OWASPCategory.A10_SSRF: "HIGH",
        OWASPCategory.A05_SECURITY_MISCONFIGURATION: "MEDIUM",
        OWASPCategory.A06_VULNERABLE_COMPONENTS: "MEDIUM",
        OWASPCategory.A04_INSECURE_DESIGN: "MEDIUM",
        OWASPCategory.A08_DATA_INTEGRITY: "MEDIUM",
        OWASPCategory.A09_LOGGING_FAILURES: "LOW",
        OWASPCategory.UNMAPPED: "INFORMATIONAL"
    }
    return severity_map.get(category, "MEDIUM")
