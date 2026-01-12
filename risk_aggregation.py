"""
Risk Aggregation & Business View - Phase 4 Task 5
Purpose: Aggregate findings for business decision-making

Features:
  1. Per-endpoint aggregation
  2. Per-OWASP category aggregation
  3. Per-application aggregation
  4. Risk trends over time
  5. Confidence-weighted severity
  6. Business risk scoring
"""

import logging
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class RiskLevel(str, Enum):
    """Business risk levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class AggregatedFinding:
    """Aggregated finding (multiple tools agreement)"""
    identifier: str          # e.g., "endpoint:/api/users?id"
    vulnerability_type: str
    affected_endpoints: List[str] = field(default_factory=list)
    affected_parameters: List[str] = field(default_factory=list)
    
    tool_agreement: int = 0  # Number of tools that found this
    max_confidence: float = 0.0
    
    severity_distribution: Dict[str, int] = field(default_factory=dict)  # severity -> count
    business_impact: str = ""  # Description of business impact
    
    owasp_category: str = ""
    cwe_ids: List[str] = field(default_factory=list)
    
    estimated_fix_effort: str = ""  # EASY|MEDIUM|HARD


@dataclass
class PerEndpointRisk:
    """Risk aggregation per endpoint"""
    endpoint: str
    parameters: List[str] = field(default_factory=list)
    
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    business_risk_score: float = 0.0  # 0-100
    overall_severity: str = "LOW"
    
    def calculate_risk_score(self) -> float:
        """Calculate business risk (0-100)"""
        score = (
            self.critical_count * 25 +
            self.high_count * 10 +
            self.medium_count * 3 +
            self.low_count * 0.5
        )
        return min(100, score)


@dataclass
class PerOWASPRisk:
    """Risk aggregation per OWASP category"""
    owasp_category: str  # e.g., "A01:2021 - Broken Authentication"
    affected_endpoints: List[str] = field(default_factory=list)
    
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    trend: str = "STABLE"  # STABLE|IMPROVING|DEGRADING
    
    def calculate_risk_score(self) -> float:
        """Calculate OWASP category risk"""
        score = (
            self.critical_count * 25 +
            self.high_count * 10 +
            self.medium_count * 3 +
            self.low_count * 0.5
        )
        return min(100, score)


@dataclass
class PerApplicationRisk:
    """Risk aggregation per application"""
    app_name: str
    endpoints_scanned: int = 0
    total_findings: int = 0
    
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    
    top_vulnerabilities: List[str] = field(default_factory=list)
    owasp_distribution: Dict[str, int] = field(default_factory=dict)
    
    business_risk_score: float = 0.0  # 0-100
    risk_rating: str = "LOW"  # CRITICAL|HIGH|MEDIUM|LOW
    
    def calculate_risk_score(self) -> float:
        """Calculate application risk"""
        score = (
            self.critical_count * 25 +
            self.high_count * 10 +
            self.medium_count * 3 +
            self.low_count * 0.5
        )
        return min(100, score)
    
    def calculate_risk_rating(self) -> str:
        """Rating for executives"""
        if self.critical_count > 0:
            return "CRITICAL"
        elif self.high_count >= 3:
            return "HIGH"
        elif self.medium_count >= 5 or self.high_count > 0:
            return "MEDIUM"
        else:
            return "LOW"


class RiskAggregator:
    """
    Aggregate findings for business view
    
    Usage:
        agg = RiskAggregator(app_name="myapp")
        
        # Add findings
        for finding in findings_from_scanner:
            agg.add_finding(
                endpoint=finding.endpoint,
                parameter=finding.parameter,
                vulnerability_type=finding.type,
                severity=finding.severity,
                tool_name=finding.tool,
                confidence=finding.confidence,
                owasp_category=finding.owasp
            )
        
        # Aggregate
        per_endpoint = agg.aggregate_by_endpoint()
        per_owasp = agg.aggregate_by_owasp()
        per_app = agg.aggregate_by_application()
        
        # Generate report
        report = agg.generate_report()
    """

    def __init__(self, app_name: str):
        self.app_name = app_name
        self.findings: List[Dict] = []
        
    def add_finding(
        self,
        endpoint: str,
        vulnerability_type: str,
        severity: str,
        tool_name: str,
        confidence: float = 0.5,
        parameter: Optional[str] = None,
        owasp_category: Optional[str] = None,
        cwe_ids: Optional[List[str]] = None,
        business_impact: Optional[str] = None
    ) -> None:
        """Add finding for aggregation"""
        finding = {
            "endpoint": endpoint,
            "parameter": parameter,
            "vulnerability_type": vulnerability_type,
            "severity": severity,
            "tool_name": tool_name,
            "confidence": confidence,
            "owasp_category": (owasp_category.value if hasattr(owasp_category, "value") else owasp_category) or "UNKNOWN",
            "cwe_ids": cwe_ids or [],
            "business_impact": business_impact or ""
        }
        self.findings.append(finding)
        logger.debug(f"[RiskAggregator] Added finding: {vulnerability_type} on {endpoint}")

    def aggregate_by_endpoint(self) -> Dict[str, PerEndpointRisk]:
        """Group findings by endpoint"""
        endpoint_risks: Dict[str, PerEndpointRisk] = {}
        
        for finding in self.findings:
            endpoint = finding["endpoint"]
            param = finding["parameter"]
            severity = finding["severity"]
            
            if endpoint not in endpoint_risks:
                endpoint_risks[endpoint] = PerEndpointRisk(endpoint=endpoint)
            
            risk = endpoint_risks[endpoint]
            
            if param and param not in risk.parameters:
                risk.parameters.append(param)
            
            # Count by severity
            if severity == "CRITICAL":
                risk.critical_count += 1
            elif severity == "HIGH":
                risk.high_count += 1
            elif severity == "MEDIUM":
                risk.medium_count += 1
            elif severity == "LOW":
                risk.low_count += 1
            
            # Update overall severity (max)
            severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
            current_order = severity_order.get(risk.overall_severity, -1)
            finding_order = severity_order.get(severity, -1)
            
            if finding_order > current_order:
                risk.overall_severity = severity
        
        # Calculate risk scores
        for risk in endpoint_risks.values():
            risk.business_risk_score = risk.calculate_risk_score()
        
        logger.info(f"[RiskAggregator] Aggregated {len(endpoint_risks)} endpoints")
        return endpoint_risks

    def aggregate_by_owasp(self) -> Dict[str, PerOWASPRisk]:
        """Group findings by OWASP category"""
        owasp_risks: Dict[str, PerOWASPRisk] = {}
        
        for finding in self.findings:
            owasp_raw = finding["owasp_category"]
            # Ensure owasp is always a string for dict keys
            owasp = owasp_raw.value if hasattr(owasp_raw, 'value') else str(owasp_raw) if owasp_raw else "UNKNOWN"
            endpoint = finding["endpoint"]
            severity = finding["severity"]
            
            if owasp not in owasp_risks:
                owasp_risks[owasp] = PerOWASPRisk(owasp_category=owasp)
            
            risk = owasp_risks[owasp]
            
            if endpoint not in risk.affected_endpoints:
                risk.affected_endpoints.append(endpoint)
            
            # Count by severity
            if severity == "CRITICAL":
                risk.critical_count += 1
            elif severity == "HIGH":
                risk.high_count += 1
            elif severity == "MEDIUM":
                risk.medium_count += 1
            elif severity == "LOW":
                risk.low_count += 1
        
        logger.info(f"[RiskAggregator] Aggregated {len(owasp_risks)} OWASP categories")
        return owasp_risks

    def aggregate_by_application(self) -> PerApplicationRisk:
        """Aggregate all findings for entire application"""
        app_risk = PerApplicationRisk(app_name=self.app_name)
        
        endpoints: Set[str] = set()
        owasp_dist: Dict[str, int] = {}

        for finding in self.findings:
            endpoints.add(finding["endpoint"])
            severity = finding["severity"]
            owasp_raw = finding["owasp_category"]
            owasp = owasp_raw.value if hasattr(owasp_raw, "value") else str(owasp_raw)
            
            app_risk.total_findings += 1
            
            if severity == "CRITICAL":
                app_risk.critical_count += 1
            elif severity == "HIGH":
                app_risk.high_count += 1
            elif severity == "MEDIUM":
                app_risk.medium_count += 1
            elif severity == "LOW":
                app_risk.low_count += 1
            
            owasp_dist[owasp] = owasp_dist.get(owasp, 0) + 1
        
        app_risk.endpoints_scanned = len(endpoints)
        app_risk.owasp_distribution = owasp_dist
        app_risk.business_risk_score = app_risk.calculate_risk_score()
        app_risk.risk_rating = app_risk.calculate_risk_rating()
        
        # Top vulnerabilities
        vuln_types: Dict[str, int] = {}
        for finding in self.findings:
            vtype = finding["vulnerability_type"]
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
        
        app_risk.top_vulnerabilities = sorted(
            vuln_types.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        logger.info(f"[RiskAggregator] Application risk: {app_risk.risk_rating} ({app_risk.business_risk_score:.1f})")
        return app_risk

    def generate_report(self) -> Dict:
        """Generate complete aggregation report"""
        per_endpoint = self.aggregate_by_endpoint()
        per_owasp = self.aggregate_by_owasp()
        per_app = self.aggregate_by_application()
        
        report = {
            "metadata": {
                "app_name": self.app_name,
                "timestamp": datetime.now().isoformat(),
                "total_findings": len(self.findings)
            },
            "application_risk": {
                "app_name": per_app.app_name,
                "risk_rating": per_app.risk_rating,
                "business_risk_score": per_app.business_risk_score,
                "total_findings": per_app.total_findings,
                "endpoints_scanned": per_app.endpoints_scanned,
                "severity_distribution": {
                    "critical": per_app.critical_count,
                    "high": per_app.high_count,
                    "medium": per_app.medium_count,
                    "low": per_app.low_count
                },
                "top_vulnerabilities": [
                    {"vulnerability": v[0], "count": v[1]}
                    for v in per_app.top_vulnerabilities
                ],
                "owasp_distribution": per_app.owasp_distribution
            },
            "per_endpoint": {
                endpoint: {
                    "overall_severity": risk.overall_severity,
                    "business_risk_score": risk.business_risk_score,
                    "parameters": risk.parameters,
                    "critical": risk.critical_count,
                    "high": risk.high_count,
                    "medium": risk.medium_count,
                    "low": risk.low_count
                }
                for endpoint, risk in per_endpoint.items()
            },
            "per_owasp_category": {
                owasp: {
                    "affected_endpoints": risk.affected_endpoints,
                    "critical": risk.critical_count,
                    "high": risk.high_count,
                    "medium": risk.medium_count,
                    "low": risk.low_count
                }
                for owasp, risk in per_owasp.items()
            }
        }
        
        return report

    def export_json(self, filepath: str) -> None:
        """Export aggregation report"""
        report = self.generate_report()
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"[RiskAggregator] Exported report to {filepath}")

    def get_executive_summary(self) -> str:
        """Get 1-page executive summary"""
        per_app = self.aggregate_by_application()
        
        summary = f"""
╔════════════════════════════════════════════════════════════════╗
║              SECURITY ASSESSMENT EXECUTIVE SUMMARY              ║
╠════════════════════════════════════════════════════════════════╣
║  Application:              {per_app.app_name:<45} ║
║  Risk Rating:              {per_app.risk_rating:<45} ║
║  Business Risk Score:      {per_app.business_risk_score:.1f}/100{' '*33} ║
╠════════════════════════════════════════════════════════════════╣
║  Endpoints Scanned:        {per_app.endpoints_scanned:<45} ║
║  Total Findings:           {per_app.total_findings:<45} ║
╠════════════════════════════════════════════════════════════════╣
║  SEVERITY BREAKDOWN                                            ║
║    • Critical:             {per_app.critical_count:<45} ║
║    • High:                 {per_app.high_count:<45} ║
║    • Medium:               {per_app.medium_count:<45} ║
║    • Low:                  {per_app.low_count:<45} ║
╚════════════════════════════════════════════════════════════════╝
"""
        return summary


# Example usage
"""
agg = RiskAggregator(app_name="myapp")

# Add findings
agg.add_finding(
    endpoint="/api/users",
    parameter="id",
    vulnerability_type="SQL_INJECTION",
    severity="CRITICAL",
    tool_name="sqlmap",
    confidence=0.95,
    owasp_category="A01:2021 - Injection"
)

agg.add_finding(
    endpoint="/api/users",
    parameter="username",
    vulnerability_type="SQL_INJECTION",
    severity="CRITICAL",
    tool_name="nuclei",
    confidence=0.85,
    owasp_category="A01:2021 - Injection"
)

agg.add_finding(
    endpoint="/api/login",
    vulnerability_type="BROKEN_AUTH",
    severity="HIGH",
    tool_name="nuclei",
    confidence=0.90,
    owasp_category="A07:2021 - Identification and Authentication Failures"
)

# Generate report
report = agg.generate_report()
agg.export_json("risk_report.json")

# Print executive summary
print(agg.get_executive_summary())
"""
