"""
OWASP Top-10 Mapper - Phase 2
Purpose: Map findings to OWASP Top-10 2021 categories
No inflated claims: distinguish discovery vs exploitation vs confirmed

OWASP 2021 Categories:
  A01:2021 – Broken Access Control
  A02:2021 – Cryptographic Failures
  A03:2021 – Injection
  A04:2021 – Insecure Design
  A05:2021 – Security Misconfiguration
  A06:2021 – Vulnerable and Outdated Components
  A07:2021 – Authentication and Session Management
  A08:2021 – Software and Data Integrity Failures
  A09:2021 – Logging and Monitoring Failures
  A10:2021 – Server-Side Request Forgery (SSRF)
"""

import logging
from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class OWASP2021(Enum):
    """OWASP Top-10 2021 Categories"""
    A01_BROKEN_ACCESS_CONTROL = "A01:2021 – Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021 – Cryptographic Failures"
    A03_INJECTION = "A03:2021 – Injection"
    A04_INSECURE_DESIGN = "A04:2021 – Insecure Design"
    A05_MISCONFIGURATION = "A05:2021 – Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS = "A06:2021 – Vulnerable and Outdated Components"
    A07_AUTH_SESSION = "A07:2021 – Authentication and Session Management"
    A08_DATA_INTEGRITY = "A08:2021 – Software and Data Integrity Failures"
    A09_LOGGING = "A09:2021 – Logging and Monitoring Failures"
    A10_SSRF = "A10:2021 – Server-Side Request Forgery (SSRF)"


class FindingClassification(Enum):
    """How conclusive the finding is"""
    DISCOVERY = "discovery"           # Endpoint/parameter discovered
    EXPLOITATION_ATTEMPT = "attempt"  # Tool attempted exploitation, inconclusive
    CONFIRMED = "confirmed"           # Vulnerability confirmed via payload
    FALSE_POSITIVE = "false_positive" # Tool flagged but not real


@dataclass
class OWASPMapping:
    """Mapping of finding to OWASP category"""
    category: OWASP2021
    cwe: Optional[str] = None  # CWE identifier
    classification: FindingClassification = FindingClassification.DISCOVERY
    confidence: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    evidence: str = ""  # Why mapped to this category
    remediation: str = ""  # How to fix


class OWASPMapper:
    """
    Map vulnerability findings to OWASP Top-10 categories.
    
    Design principles:
    - No claim inflation (discovery ≠ confirmed)
    - Clear distinction between attempt and confirmed
    - CWE references for developer clarity
    - Actionable remediation
    """

    # Vulnerability type -> OWASP mappings
    MAPPINGS = {
        # Injection (A03)
        "sqli": {
            "category": OWASP2021.A03_INJECTION,
            "cwe": "CWE-89",
            "name": "SQL Injection",
        },
        "xss": {
            "category": OWASP2021.A03_INJECTION,
            "cwe": "CWE-79",
            "name": "Cross-Site Scripting (XSS)",
        },
        "command_injection": {
            "category": OWASP2021.A03_INJECTION,
            "cwe": "CWE-78",
            "name": "Improper Neutralization of Special Elements used in an OS Command",
        },
        "ldap_injection": {
            "category": OWASP2021.A03_INJECTION,
            "cwe": "CWE-90",
            "name": "LDAP Injection",
        },
        "xml_injection": {
            "category": OWASP2021.A03_INJECTION,
            "cwe": "CWE-91",
            "name": "XML Injection",
        },
        "xxe": {
            "category": OWASP2021.A03_INJECTION,
            "cwe": "CWE-611",
            "name": "Improper Restriction of XML External Entity Reference",
        },

        # Broken Access Control (A01)
        "idor": {
            "category": OWASP2021.A01_BROKEN_ACCESS_CONTROL,
            "cwe": "CWE-639",
            "name": "Authorization Bypass Through User-Controlled Key",
        },
        "path_traversal": {
            "category": OWASP2021.A01_BROKEN_ACCESS_CONTROL,
            "cwe": "CWE-22",
            "name": "Improper Limitation of a Pathname to a Restricted Directory",
        },
        "auth_bypass": {
            "category": OWASP2021.A01_BROKEN_ACCESS_CONTROL,
            "cwe": "CWE-287",
            "name": "Improper Authentication",
        },

        # SSRF (A10)
        "ssrf": {
            "category": OWASP2021.A10_SSRF,
            "cwe": "CWE-918",
            "name": "Server-Side Request Forgery (SSRF)",
        },

        # Cryptographic Failures (A02)
        "weak_crypto": {
            "category": OWASP2021.A02_CRYPTOGRAPHIC_FAILURES,
            "cwe": "CWE-327",
            "name": "Use of a Broken or Risky Cryptographic Algorithm",
        },
        "outdated_tls": {
            "category": OWASP2021.A02_CRYPTOGRAPHIC_FAILURES,
            "cwe": "CWE-327",
            "name": "Insecure Transport Layer (TLS < 1.2)",
        },
        "self_signed_cert": {
            "category": OWASP2021.A02_CRYPTOGRAPHIC_FAILURES,
            "cwe": "CWE-295",
            "name": "Improper Certificate Validation",
        },

        # Security Misconfiguration (A05)
        "default_credentials": {
            "category": OWASP2021.A05_MISCONFIGURATION,
            "cwe": "CWE-798",
            "name": "Use of Hard-coded Credentials",
        },
        "unnecessary_services": {
            "category": OWASP2021.A05_MISCONFIGURATION,
            "cwe": "CWE-665",
            "name": "Improper Initialization with Hard-Coded Network Resource Configuration Data",
        },
        "directory_listing": {
            "category": OWASP2021.A05_MISCONFIGURATION,
            "cwe": "CWE-548",
            "name": "Exposure of Information Through Directory Listing",
        },
        "debug_enabled": {
            "category": OWASP2021.A05_MISCONFIGURATION,
            "cwe": "CWE-215",
            "name": "Information Exposure Through Debug Information",
        },
        "cors_misconfiguration": {
            "category": OWASP2021.A05_MISCONFIGURATION,
            "cwe": "CWE-942",
            "name": "Permissive Cross-domain Policy",
        },

        # Vulnerable Components (A06)
        "outdated_software": {
            "category": OWASP2021.A06_VULNERABLE_COMPONENTS,
            "cwe": "CWE-1035",
            "name": "Use of Vulnerable and Outdated Components",
        },
        "known_cve": {
            "category": OWASP2021.A06_VULNERABLE_COMPONENTS,
            "cwe": "CWE-1035",
            "name": "Use of Vulnerable and Outdated Components",
        },

        # Authentication/Session (A07)
        "weak_password_policy": {
            "category": OWASP2021.A07_AUTH_SESSION,
            "cwe": "CWE-521",
            "name": "Weak Password Requirements",
        },
        "session_fixation": {
            "category": OWASP2021.A07_AUTH_SESSION,
            "cwe": "CWE-384",
            "name": "Session Fixation",
        },
        "broken_mfa": {
            "category": OWASP2021.A07_AUTH_SESSION,
            "cwe": "CWE-287",
            "name": "Improper Authentication",
        },

        # Insecure Design (A04)
        "missing_rate_limit": {
            "category": OWASP2021.A04_INSECURE_DESIGN,
            "cwe": "CWE-770",
            "name": "Allocation of Resources Without Limits",
        },

        # Data Integrity (A08)
        "code_injection": {
            "category": OWASP2021.A08_DATA_INTEGRITY,
            "cwe": "CWE-94",
            "name": "Improper Control of Generation of Code",
        },
        "deserialization_rce": {
            "category": OWASP2021.A08_DATA_INTEGRITY,
            "cwe": "CWE-502",
            "name": "Deserialization of Untrusted Data",
        },

        # Logging/Monitoring (A09)
        "insufficient_logging": {
            "category": OWASP2021.A09_LOGGING,
            "cwe": "CWE-778",
            "name": "Insufficient Logging",
        },

        # Generic
        "information_disclosure": {
            "category": OWASP2021.A05_MISCONFIGURATION,
            "cwe": "CWE-200",
            "name": "Exposure of Sensitive Information",
        },
    }

    def map_finding(self, vuln_type: str, 
                   classification: FindingClassification = FindingClassification.DISCOVERY,
                   confidence: str = "MEDIUM",
                   evidence: str = "") -> OWASPMapping:
        """
        Map vulnerability type to OWASP category
        
        Args:
            vuln_type: Type of vulnerability (sqli, xss, etc)
            classification: DISCOVERY/ATTEMPT/CONFIRMED
            confidence: LOW/MEDIUM/HIGH
            evidence: Why this mapping
            
        Returns:
            OWASPMapping with category and details
        """
        vuln_lower = vuln_type.lower().strip()
        
        if vuln_lower not in self.MAPPINGS:
            logger.warning(f"Unknown vulnerability type: {vuln_type}")
            # Default to generic misconfiguration
            return OWASPMapping(
                category=OWASP2021.A05_MISCONFIGURATION,
                classification=classification,
                confidence=confidence,
                evidence=evidence or "Unknown vulnerability type, categorized as misconfiguration"
            )
        
        mapping_def = self.MAPPINGS[vuln_lower]
        
        return OWASPMapping(
            category=mapping_def["category"],
            cwe=mapping_def.get("cwe"),
            classification=classification,
            confidence=confidence,
            evidence=evidence or mapping_def["name"]
        )

    def bulk_map_findings(self, findings: List[Dict]) -> Dict[str, OWASPMapping]:
        """
        Map multiple findings at once
        
        Args:
            findings: List of dicts with type, classification, confidence, evidence
            
        Returns:
            Dict[finding_id -> OWASPMapping]
        """
        results = {}
        for finding in findings:
            mapping = self.map_finding(
                finding.get("type", "information_disclosure"),
                FindingClassification[finding.get("classification", "DISCOVERY").upper()],
                finding.get("confidence", "MEDIUM"),
                finding.get("evidence", "")
            )
            results[finding.get("id", "unknown")] = mapping
        return results

    def get_owasp_summary(self, findings: List[OWASPMapping]) -> Dict[str, int]:
        """Get summary: count of findings per OWASP category"""
        summary = {}
        for finding in findings:
            cat_name = finding.category.value
            summary[cat_name] = summary.get(cat_name, 0) + 1
        return summary

    def get_recommendations(self, mapping: OWASPMapping) -> str:
        """
        Get remediation recommendations based on OWASP category
        
        Args:
            mapping: OWASPMapping instance
            
        Returns:
            Actionable recommendations
        """
        cat = mapping.category
        
        recommendations = {
            OWASP2021.A01_BROKEN_ACCESS_CONTROL: (
                "1. Implement proper access control checks\n"
                "2. Verify user authorization before data access\n"
                "3. Use role-based access control (RBAC)\n"
                "4. Audit authorization logic regularly"
            ),
            OWASP2021.A02_CRYPTOGRAPHIC_FAILURES: (
                "1. Use TLS 1.2 or higher for all data in transit\n"
                "2. Ensure strong encryption algorithms\n"
                "3. Never use deprecated or weak crypto\n"
                "4. Properly manage cryptographic keys"
            ),
            OWASP2021.A03_INJECTION: (
                "1. Use parameterized queries (prepared statements)\n"
                "2. Validate and sanitize all user input\n"
                "3. Use ORM frameworks with built-in protection\n"
                "4. Implement input whitelisting"
            ),
            OWASP2021.A04_INSECURE_DESIGN: (
                "1. Perform threat modeling\n"
                "2. Implement rate limiting\n"
                "3. Add resource limits\n"
                "4. Use security design patterns"
            ),
            OWASP2021.A05_MISCONFIGURATION: (
                "1. Disable unnecessary services\n"
                "2. Remove default credentials\n"
                "3. Apply security hardening\n"
                "4. Regularly audit configurations"
            ),
            OWASP2021.A06_VULNERABLE_COMPONENTS: (
                "1. Maintain software inventory\n"
                "2. Keep dependencies updated\n"
                "3. Monitor CVE databases\n"
                "4. Use dependency scanning tools"
            ),
            OWASP2021.A07_AUTH_SESSION: (
                "1. Implement strong password policies\n"
                "2. Use multi-factor authentication (MFA)\n"
                "3. Secure session management\n"
                "4. Implement account lockout protection"
            ),
            OWASP2021.A08_DATA_INTEGRITY: (
                "1. Avoid deserialization of untrusted data\n"
                "2. Validate all data sources\n"
                "3. Implement code signing\n"
                "4. Use integrity checks"
            ),
            OWASP2021.A09_LOGGING: (
                "1. Enable comprehensive logging\n"
                "2. Log security events\n"
                "3. Implement monitoring and alerting\n"
                "4. Retain logs for forensic analysis"
            ),
            OWASP2021.A10_SSRF: (
                "1. Whitelist allowed URLs\n"
                "2. Disable HTTP redirects\n"
                "3. Use network segmentation\n"
                "4. Implement DNS rebinding protection"
            ),
        }
        
        return recommendations.get(cat, "Review OWASP Top-10 documentation for remediation")

    def format_finding_report(self, mapping: OWASPMapping, description: str = "") -> str:
        """Format finding for report"""
        report = f"""
OWASP Category: {mapping.category.value}
CWE: {mapping.cwe or "N/A"}
Classification: {mapping.classification.value}
Confidence: {mapping.confidence}

Evidence:
  {mapping.evidence}

{description}

Recommendations:
{self.get_recommendations(mapping)}
"""
        return report.strip()


# Example usage
"""
mapper = OWASPMapper()

# Simple XSS discovery
xss_mapping = mapper.map_finding(
    vuln_type="xss",
    classification=FindingClassification.DISCOVERY,
    confidence="LOW",
    evidence="Reflected parameter detected in crawl"
)
print(xss_mapping.category.value)  # A03:2021 – Injection
print(xss_mapping.cwe)              # CWE-79

# Confirmed SQL injection
sqli_mapping = mapper.map_finding(
    vuln_type="sqli",
    classification=FindingClassification.CONFIRMED,
    confidence="HIGH",
    evidence="Sqlmap confirmed time-based injection"
)
print(sqli_mapping.cwe)  # CWE-89

# Bulk mapping
findings = [
    {"id": "xss_001", "type": "xss", "classification": "CONFIRMED", "confidence": "HIGH"},
    {"id": "sqli_001", "type": "sqli", "classification": "ATTEMPT", "confidence": "MEDIUM"},
    {"id": "cors_001", "type": "cors_misconfiguration", "classification": "DISCOVERY", "confidence": "HIGH"},
]

mapped = mapper.bulk_map_findings(findings)
for f_id, mapping in mapped.items():
    print(f"{f_id}: {mapping.category.value}")

# Get recommendations
print(mapper.get_recommendations(xss_mapping))
"""
