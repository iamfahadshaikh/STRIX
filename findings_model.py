"""
Normalized findings model: deduplicated, OWASP-mapped, actionable intelligence.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Set, List, Optional
from datetime import datetime


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingType(Enum):
    XSS = "XSS"
    SQLI = "SQLi"
    COMMAND_INJECTION = "Command Injection"
    SSRF = "SSRF"
    XXE = "XXE"
    IDOR = "IDOR"
    AUTH_BYPASS = "Authentication Bypass"
    INFO_DISCLOSURE = "Information Disclosure"
    MISCONFIGURATION = "Misconfiguration"
    OUTDATED_SOFTWARE = "Outdated Software"
    WEAK_CRYPTO = "Weak Cryptography"
    OTHER = "Other"


@dataclass(frozen=True)
class Finding:
    """
    Immutable finding record.
    
    Deduplication key: (type, location, cwe)
    """
    type: FindingType
    severity: Severity
    location: str  # URL, endpoint, or host
    description: str
    cwe: Optional[str] = None
    owasp: Optional[str] = None  # e.g., "A03:2021"
    tool: str = "unknown"
    evidence: str = ""
    remediation: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def __hash__(self):
        """Deduplication hash: type + location + CWE"""
        return hash((self.type, self.location, self.cwe))
    
    def __eq__(self, other):
        """Deduplication equality: only type, location, CWE matter"""
        if not isinstance(other, Finding):
            return False
        return (self.type, self.location, self.cwe) == (other.type, other.location, other.cwe)


class FindingsRegistry:
    """
    Central findings store: deduplicates, maps to OWASP, tracks severity.
    """
    
    def __init__(self):
        self._findings: Set[Finding] = set()
        self._by_severity: dict[Severity, List[Finding]] = {s: [] for s in Severity}
    
    def add(self, finding: Finding) -> bool:
        """
        Add finding to registry. Returns True if new, False if duplicate.
        """
        if finding in self._findings:
            return False  # Duplicate
        
        self._findings.add(finding)
        self._by_severity[finding.severity].append(finding)
        return True
    
    def deduplicate_nuclei(self, tool_findings: List[Finding]) -> List[Finding]:
        """Deduplicate nuclei findings within a tool run.
        
        Nuclei often reports the same vulnerability from multiple templates.
        Group by (type, location) and keep highest severity instance only.
        """
        by_location = {}
        for f in tool_findings:
            key = (f.type, f.location)
            if key not in by_location:
                by_location[key] = f
            else:
                # Keep higher severity
                existing = by_location[key]
                sev_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
                if sev_order.index(f.severity) < sev_order.index(existing.severity):
                    by_location[key] = f
        
        return list(by_location.values())
    
    def get_all(self) -> List[Finding]:
        """Get all findings (sorted by severity)"""
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        return [f for sev in order for f in self._by_severity[sev]]
    
    def get_by_severity(self, severity: Severity) -> List[Finding]:
        """Get findings by severity"""
        return self._by_severity[severity]
    
    def count_by_severity(self) -> dict[Severity, int]:
        """Count findings by severity"""
        return {sev: len(findings) for sev, findings in self._by_severity.items()}
    
    def has_critical(self) -> bool:
        """Check if any critical findings exist"""
        return len(self._by_severity[Severity.CRITICAL]) > 0
    
    def summary(self) -> str:
        """Human-readable summary"""
        counts = self.count_by_severity()
        return (
            f"Critical: {counts[Severity.CRITICAL]}, "
            f"High: {counts[Severity.HIGH]}, "
            f"Medium: {counts[Severity.MEDIUM]}, "
            f"Low: {counts[Severity.LOW]}, "
            f"Info: {counts[Severity.INFO]}"
        )
    
    def to_dict(self) -> dict:
        """Export to dict for JSON serialization"""
        from enum import Enum
        return {
            "total": len(self._findings),
            "by_severity": {s.value: len(f) for s, f in self._by_severity.items()},
            "findings": [
                {
                    "type": f.type.value,
                    "severity": f.severity.value,
                    "location": f.location,
                    "description": f.description,
                    "cwe": f.cwe,
                    "owasp": f.owasp.value if isinstance(f.owasp, Enum) else f.owasp,
                    "tool": f.tool,
                    "evidence": f.evidence[:200],  # Truncate
                    "remediation": f.remediation,
                    "discovered_at": f.discovered_at,
                }
                for f in self.get_all()
            ],
        }


# OWASP Top 10 2021 Mapping
OWASP_2021_MAP = {
    FindingType.AUTH_BYPASS: "A07:2021 - Identification and Authentication Failures",
    FindingType.IDOR: "A01:2021 - Broken Access Control",
    FindingType.XSS: "A03:2021 - Injection",
    FindingType.SQLI: "A03:2021 - Injection",
    FindingType.COMMAND_INJECTION: "A03:2021 - Injection",
    FindingType.XXE: "A03:2021 - Injection",
    FindingType.INFO_DISCLOSURE: "A01:2021 - Broken Access Control",
    FindingType.MISCONFIGURATION: "A05:2021 - Security Misconfiguration",
    FindingType.WEAK_CRYPTO: "A02:2021 - Cryptographic Failures",
    FindingType.OUTDATED_SOFTWARE: "A06:2021 - Vulnerable and Outdated Components",
    FindingType.SSRF: "A10:2021 - Server-Side Request Forgery",
}


def map_to_owasp(finding_type: FindingType) -> str:
    """Map finding type to OWASP Top 10 2021"""
    return OWASP_2021_MAP.get(finding_type, "Unknown")
