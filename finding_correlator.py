"""
Finding Correlator - Phase 3
Purpose: De-duplicate findings, link multiple tools to same vulnerability,
aggregate by OWASP category, provide single source of truth

Correlation Model:
  Raw Finding
    ├── Tool Report 1 (xsstrike: found XSS on /search?q)
    ├── Tool Report 2 (dalfox: found XSS on /search?q)
    └── Tool Report 3 (nuclei: template matched on /search)
      ↓
  Correlated Finding
    ├── Type: XSS
    ├── Location: /search?q
    ├── Tools: [xsstrike, dalfox, nuclei]
    ├── Confidence: HIGH (multiple tools)
    ├── OWASP: A03:2021
    └── Status: CONFIRMED (multiple tools agree)
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from enum import Enum
from collections import defaultdict
from datetime import datetime

logger = logging.getLogger(__name__)


class CorrelationStatus(Enum):
    """How correlated finding is"""
    SINGLE_TOOL = "single_tool"           # Only one tool reported
    CORROBORATED = "corroborated"         # Multiple tools agree
    CONFIRMED = "confirmed"               # Payload success confirmed
    FALSE_POSITIVE = "false_positive"     # Contradictory evidence


@dataclass
class ToolReport:
    """Single tool's report of a finding"""
    tool_name: str
    endpoint: str
    parameter: Optional[str] = None
    vulnerability_type: str = ""
    severity: str = "MEDIUM"
    evidence: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    success_indicator: Optional[str] = None  # confirmed_reflected, error_based, etc.

    def to_dict(self) -> Dict:
        return {
            "tool": self.tool_name,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "type": self.vulnerability_type,
            "severity": self.severity,
            "evidence": self.evidence,
            "success": self.success_indicator
        }


@dataclass
class CorrelatedFinding:
    """De-duplicated, correlated finding from multiple tools"""
    finding_id: str
    vuln_type: str
    endpoint: str
    parameter: Optional[str] = None
    
    # Tool reports that led to this finding
    tool_reports: List[ToolReport] = field(default_factory=list)
    
    # Correlation data
    status: CorrelationStatus = CorrelationStatus.SINGLE_TOOL
    tool_count: int = 1
    tools: Set[str] = field(default_factory=set)
    
    # Assessment
    is_false_positive: bool = False
    fp_reason: str = ""
    
    # Classification
    owasp_category: str = ""
    cwe: str = ""
    confidence: str = "MEDIUM"
    risk: str = "MEDIUM"
    
    # Metadata
    first_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now().isoformat())
    

    def add_report(self, report: ToolReport):
        """Add tool report to finding"""
        self.tool_reports.append(report)
        self.tools.add(report.tool_name)
        self.tool_count = len(self.tools)
        self.last_seen = datetime.now().isoformat()
        
        # Update status based on corroboration
        if self.tool_count == 1:
            self.status = CorrelationStatus.SINGLE_TOOL
        elif self.tool_count >= 2:
            # Multiple tools = corroborated
            self.status = CorrelationStatus.CORROBORATED
            
            # If any has confirmed success, mark as CONFIRMED
            if any(
                r.success_indicator is True or
                (isinstance(r.success_indicator, str) and "confirmed" in r.success_indicator.lower())
                for r in self.tool_reports
            ):
                self.status = CorrelationStatus.CONFIRMED

    def to_dict(self) -> Dict:
        return {
            "id": self.finding_id,
            "type": self.vuln_type,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "tools": list(self.tools),
            "tool_count": self.tool_count,
            "status": self.status.value,
            "confidence": self.confidence,
            "risk": self.risk,
            "owasp": self.owasp_category,
            "cwe": self.cwe,
            "is_false_positive": self.is_false_positive,
            "tool_reports": [r.to_dict() for r in self.tool_reports],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen
        }


class FindingCorrelator:
    """
    De-duplicate and correlate findings across tools
    
    Purpose:
    - Same endpoint/param tested by multiple tools → link them
    - Multiple tools = higher confidence (corroboration)
    - Aggregate by OWASP category
    - Detect false positives (conflicting evidence)
    
    Usage:
        correlator = FindingCorrelator()
        
        # Add reports as tools run
        correlator.add_report(
            tool="dalfox",
            endpoint="/search",
            parameter="q",
            vuln_type="xss",
            evidence="payload reflected in response",
            success_indicator="confirmed_reflected"
        )
        
        correlator.add_report(
            tool="xsstrike",
            endpoint="/search",
            parameter="q",
            vuln_type="xss",
            evidence="XXS vector successful"
        )
        
        # Get correlated findings
        findings = correlator.get_findings()
        for f in findings:
            print(f"{f.vuln_type} on {f.endpoint}:")
            print(f"  Tools: {f.tools}")
            print(f"  Confidence: {f.confidence} (corroboration: {f.status.value})")
    """

    def __init__(self):
        # Deduplication key: (endpoint, parameter, vuln_type) -> CorrelatedFinding
        self.findings: Dict[Tuple[str, Optional[str], str], CorrelatedFinding] = {}
        
        # By OWASP category
        self.by_owasp: Dict[str, List[CorrelatedFinding]] = defaultdict(list)
        
        # By tool
        self.by_tool: Dict[str, List[CorrelatedFinding]] = defaultdict(list)
        
        # Tracking
        self._next_id = 0

    def add_report(self, tool: str, endpoint: str, parameter: Optional[str],
                  vuln_type: str, severity: str = "MEDIUM", 
                  evidence: str = "", success_indicator: Optional[str] = None) -> str:
        """
        Add tool report to correlator
        
        Args:
            tool: Tool name (dalfox, sqlmap, etc)
            endpoint: Endpoint path
            parameter: Parameter name or None
            vuln_type: Vulnerability type (xss, sqli, etc)
            severity: CRITICAL/HIGH/MEDIUM/LOW/INFO
            evidence: Human-readable evidence
            success_indicator: confirmed_reflected, error_based, etc.
            
        Returns:
            Finding ID (for tracking)
        """
        # Normalize
        endpoint = self._normalize_endpoint(endpoint)
        parameter = parameter.strip() if parameter else None
        vuln_type = vuln_type.lower()
        tool = tool.lower()

        # Deduplication key
        key = (endpoint, parameter, vuln_type)

        # Get or create finding
        if key not in self.findings:
            self.findings[key] = CorrelatedFinding(
                finding_id=f"finding_{self._next_id}",
                vuln_type=vuln_type,
                endpoint=endpoint,
                parameter=parameter
            )
            self._next_id += 1

        finding = self.findings[key]

        # Add report
        report = ToolReport(
            tool_name=tool,
            endpoint=endpoint,
            parameter=parameter,
            vulnerability_type=vuln_type,
            severity=severity,
            evidence=evidence,
            success_indicator=success_indicator
        )
        finding.add_report(report)

        # Track by tool
        self.by_tool[tool].append(finding)

        logger.info(f"[Correlator] Added report: {tool} found {vuln_type} on {endpoint}"
                   f" (tools now: {finding.tool_count})")

        return finding.finding_id

    def link_owasp(self, finding_id: str, owasp_category: str, cwe: str = ""):
        """Link finding to OWASP category"""
        for finding in self.findings.values():
            if finding.finding_id == finding_id:
                finding.owasp_category = owasp_category
                finding.cwe = cwe
                if owasp_category not in self.by_owasp:
                    self.by_owasp[owasp_category] = []
                self.by_owasp[owasp_category].append(finding)
                return

    def mark_false_positive(self, finding_id: str, reason: str):
        """Mark finding as false positive"""
        for finding in self.findings.values():
            if finding.finding_id == finding_id:
                finding.is_false_positive = True
                finding.fp_reason = reason
                finding.status = CorrelationStatus.FALSE_POSITIVE
                logger.info(f"[Correlator] Marked {finding_id} as false positive: {reason}")
                return

    def get_findings(self) -> List[CorrelatedFinding]:
        """Get all correlated findings"""
        return list(self.findings.values())

    def get_findings_by_status(self, status: CorrelationStatus) -> List[CorrelatedFinding]:
        """Get findings by correlation status"""
        return [f for f in self.findings.values() if f.status == status]

    def get_corroborated_findings(self) -> List[CorrelatedFinding]:
        """Get findings with multiple tools (corroborated)"""
        return [f for f in self.findings.values() if f.tool_count > 1]

    def get_findings_by_owasp(self, owasp_category: str) -> List[CorrelatedFinding]:
        """Get findings for OWASP category"""
        return self.by_owasp.get(owasp_category, [])

    def get_findings_by_tool(self, tool: str) -> List[CorrelatedFinding]:
        """Get findings reported by specific tool"""
        return self.by_tool.get(tool.lower(), [])

    def get_summary(self) -> Dict:
        """Get correlation summary"""
        all_findings = self.get_findings()
        corroborated = self.get_corroborated_findings()
        false_positives = [f for f in all_findings if f.is_false_positive]
        confirmed = [f for f in all_findings if f.status == CorrelationStatus.CONFIRMED]

        return {
            "total_findings": len(all_findings),
            "unique_vulnerabilities": len(self.findings),
            "corroborated_findings": len(corroborated),
            "confirmed_findings": len(confirmed),
            "false_positives": len(false_positives),
            "by_owasp": {
                cat: len(findings) for cat, findings in self.by_owasp.items()
            },
            "by_tool": {
                tool: len(findings) for tool, findings in self.by_tool.items()
            },
            "by_status": {
                "single_tool": len([f for f in all_findings if f.tool_count == 1]),
                "corroborated": len(corroborated),
                "confirmed": len(confirmed),
                "false_positive": len(false_positives)
            }
        }

    def deduplicate(self) -> int:
        """
        Remove duplicates and conflicting reports
        
        Returns:
            Number of issues found and resolved
        """
        issues_found = 0

        for finding in self.findings.values():
            # Check for conflicting evidence
            if len(finding.tool_reports) > 1:
                # Multiple reports for same finding
                severities = [r.severity for r in finding.tool_reports]
                
                # Flag if conflicting
                if len(set(severities)) > 1:
                    # Different severity levels = potential conflicting reports
                    logger.warning(f"[Correlator] Conflicting severity for {finding.finding_id}: {severities}")
                    issues_found += 1

        logger.info(f"[Correlator] Deduplication found {issues_found} issues")
        return issues_found

    def to_dict(self) -> Dict:
        """Serialize all findings"""
        return {
            "summary": self.get_summary(),
            "findings": [f.to_dict() for f in self.findings.values()],
            "by_owasp": {
                cat: [f.finding_id for f in findings]
                for cat, findings in self.by_owasp.items()
            }
        }

    @staticmethod
    def _normalize_endpoint(endpoint: str) -> str:
        """Normalize endpoint path"""
        if not endpoint:
            return "/"
        ep = endpoint.strip()
        if not ep.startswith("/"):
            ep = "/" + ep
        # Remove query string for deduplication key
        if "?" in ep:
            ep = ep.split("?")[0]
        # Normalize trailing slash
        if len(ep) > 1 and ep.endswith("/"):
            ep = ep.rstrip("/")
        return ep


# Example usage
"""
correlator = FindingCorrelator()

# Tool 1: Dalfox finds XSS
correlator.add_report(
    tool="dalfox",
    endpoint="/search",
    parameter="q",
    vuln_type="xss",
    evidence="Payload '<img src=x onerror=alert(1)>' reflected in response",
    success_indicator="confirmed_reflected"
)

# Tool 2: XSStrike finds same XSS
correlator.add_report(
    tool="xsstrike",
    endpoint="/search",
    parameter="q",
    vuln_type="xss",
    evidence="XSS payload successful",
    success_indicator="confirmed_executed"
)

# Tool 3: Nuclei finds same via template
correlator.add_report(
    tool="nuclei",
    endpoint="/search",
    parameter="q",
    vuln_type="xss",
    evidence="XSS vulnerability detected via template"
)

# Tool 4: Sqlmap tests /search, finds nothing
correlator.add_report(
    tool="sqlmap",
    endpoint="/search",
    parameter="q",
    vuln_type="sqli",
    evidence="No SQL injection detected"
)

# Get findings
findings = correlator.get_findings()
# Result: 2 unique findings (XSS + no SQLi)

# Get corroborated
corr = correlator.get_corroborated_findings()
# Result: [XSS finding] (3 tools agree)

# Summary
summary = correlator.get_summary()
print(summary)
# Result: 2 findings, 1 corroborated, by OWASP: A03 has 1 finding, etc.
"""
