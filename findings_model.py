"""
Normalized findings model: deduplicated, OWASP-mapped, actionable intelligence.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Set, List, Optional, Dict, Any
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
    endpoint: str = ""
    method: str = ""
    parameter: str = ""
    category: str = ""
    confidence: float = 0.0
    proof: Dict[str, Any] = field(default_factory=dict)
    evidence: str = ""
    evidence_file: str = ""
    evidence_line: int = 0
    remediation: str = ""
    impact: str = ""
    exploitability: str = ""
    verification_steps: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def __hash__(self):
        """Deduplication hash: method + endpoint/location + parameter + category/type."""
        return hash(
            (
                (self.method or "").upper(),
                (self.endpoint or self.location or "").rstrip("/").lower(),
                (self.parameter or "").strip().lower(),
                (self.category or self.type.value or "").strip().lower(),
            )
        )
    
    def __eq__(self, other):
        """Deduplication equality aligned with endpoint+method+parameter+category."""
        if not isinstance(other, Finding):
            return False
        return (
            (self.method or "").upper(),
            (self.endpoint or self.location or "").rstrip("/").lower(),
            (self.parameter or "").strip().lower(),
            (self.category or self.type.value or "").strip().lower(),
        ) == (
            (other.method or "").upper(),
            (other.endpoint or other.location or "").rstrip("/").lower(),
            (other.parameter or "").strip().lower(),
            (other.category or other.type.value or "").strip().lower(),
        )

    def to_exploitation_dict(self) -> Dict[str, Any]:
        """Compatibility adapter for proof/reporting pipelines that still consume dicts."""
        endpoint = self.endpoint or self.location
        return {
            "type": self.type.value,
            "severity": self.severity.value,
            "endpoint": endpoint,
            "location": self.location or endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "payload": self.proof.get("payload", ""),
            "confidence": float(self.confidence or 0.0),
            "proof": self.proof or {},
            "description": self.description,
            "cwe": self.cwe,
            "owasp": self.owasp,
            "tool": self.tool,
            "evidence": self.evidence,
            "impact": self.impact,
            "exploitability": self.exploitability,
            "verification_steps": self.verification_steps,
        }

    @staticmethod
    def _coerce_finding_type(value: Any) -> FindingType:
        if isinstance(value, FindingType):
            return value
        text = str(value or "OTHER").strip()
        for item in FindingType:
            if text.upper() in {item.name.upper(), item.value.upper()}:
                return item
        if text.lower() in {"sqli", "sql", "sqlinjection", "sql injection"}:
            return FindingType.SQLI
        if text.lower() in {"xss", "crosssitescripting", "cross-site scripting"}:
            return FindingType.XSS
        return FindingType.OTHER

    @staticmethod
    def _coerce_severity(value: Any) -> Severity:
        if isinstance(value, Severity):
            return value
        text = str(value or "INFO").strip().upper()
        if text == "INFORMATIONAL":
            text = "INFO"
        return Severity[text] if text in Severity.__members__ else Severity.INFO

    @staticmethod
    def from_exploitation_dict(data: Dict[str, Any]) -> "Finding":
        """Create a strict Finding from exploitation-engine dict output."""
        proof = data.get("proof") if isinstance(data.get("proof"), dict) else {}
        endpoint = str(data.get("endpoint") or data.get("location") or "")
        parameter = str(data.get("parameter") or "")
        vuln_type = Finding._coerce_finding_type(data.get("type"))
        severity = Finding._coerce_severity(data.get("severity") or "HIGH")
        category = str(data.get("category") or data.get("type") or vuln_type.value)
        method = str(data.get("method") or data.get("http_method") or "GET").upper()
        confidence = float(data.get("confidence", 0.0) or 0.0)
        description = str(data.get("description") or f"Confirmed {vuln_type.value} exploitation signal")
        payload = str(data.get("payload") or data.get("payload_true") or "")
        if payload and "payload" not in proof:
            proof["payload"] = payload

        return Finding(
            type=vuln_type,
            severity=severity,
            location=endpoint,
            description=description,
            cwe=data.get("cwe"),
            owasp=data.get("owasp"),
            tool=str(data.get("tool") or "exploitation_engine"),
            endpoint=endpoint,
            method=method,
            parameter=parameter,
            category=category,
            confidence=confidence,
            proof=proof,
            evidence=str(data.get("evidence") or proof.get("evidence") or ""),
            remediation=str(data.get("remediation") or ""),
            impact=str(data.get("impact") or ""),
            exploitability=str(data.get("exploitability") or ""),
            verification_steps=str(data.get("verification_steps") or ""),
        )


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
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "parameter": f.parameter,
                    "category": f.category,
                    "confidence": f.confidence,
                    "proof": f.proof,
                    "evidence": f.evidence[:200],  # Truncate
                    "evidence_file": f.evidence_file,
                    "evidence_line": f.evidence_line,
                    "remediation": f.remediation,
                    "impact": f.impact,
                    "exploitability": f.exploitability,
                    "verification_steps": f.verification_steps,
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
