"""
Risk Scoring Engine - Phase 3
Purpose: Complement confidence scoring with real payload evidence
Transform (confidence + corroboration + auth context) into risk severity

Risk Scoring Factors:
  1. Payload Success Rate (30%) - Does the payload actually execute?
  2. Corroboration Count (30%) - How many tools agree?
  3. Tool Agreement (20%) - Which tools confirmed it?
  4. Impact Multiplier (15%) - OWASP category impact
  5. Authentication Context (5%) - Privilege level

Output Severity: INFO | LOW | MEDIUM | HIGH | CRITICAL
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class RiskSeverity(str, Enum):
    """Risk severity levels"""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ImpactCategory(str, Enum):
    """OWASP impact mapping"""
    # OWASP Top-10 2021
    A01_BROKEN_ACCESS_CONTROL = "A01_BROKEN_ACCESS_CONTROL"
    A02_CRYPTOGRAPHIC_FAILURES = "A02_CRYPTOGRAPHIC_FAILURES"
    A03_INJECTION = "A03_INJECTION"
    A04_INSECURE_DESIGN = "A04_INSECURE_DESIGN"
    A05_SECURITY_MISCONFIGURATION = "A05_SECURITY_MISCONFIGURATION"
    A06_VULNERABLE_COMPONENTS = "A06_VULNERABLE_COMPONENTS"
    A07_AUTH_FAILURES = "A07_AUTH_FAILURES"
    A08_DATA_INTEGRITY_FAILURES = "A08_DATA_INTEGRITY_FAILURES"
    A09_LOGGING_MONITORING_FAILURES = "A09_LOGGING_MONITORING_FAILURES"
    A10_SSRF = "A10_SSRF"

    def base_severity(self) -> str:
        """Base severity for this category"""
        # High-impact categories
        if self in [
            ImpactCategory.A01_BROKEN_ACCESS_CONTROL,
            ImpactCategory.A02_CRYPTOGRAPHIC_FAILURES,
            ImpactCategory.A03_INJECTION
        ]:
            return "HIGH"
        # Medium-impact categories
        elif self in [
            ImpactCategory.A04_INSECURE_DESIGN,
            ImpactCategory.A05_SECURITY_MISCONFIGURATION,
            ImpactCategory.A07_AUTH_FAILURES
        ]:
            return "MEDIUM"
        # Lower-impact categories
        else:
            return "LOW"


@dataclass
class PayloadEvidence:
    """Evidence of successful payload execution"""
    tool_name: str  # dalfox, sqlmap, commix
    endpoint: str
    parameter: str
    payload: str  # Actual payload sent
    response: str  # Response (truncated)
    success_indicator: str  # What proves success? (e.g., "JSESSIONID reflected", "UNION SELECT returned rows")
    execution_time_ms: float = 0.0
    response_status_code: int = 200
    is_confirmed: bool = True  # Payload definitively succeeded


@dataclass
class RiskFinding:
    """Final risk-scored finding"""
    endpoint: str
    parameter: str
    vulnerability_type: str
    owasp_category: str
    risk_severity: str  # INFO | LOW | MEDIUM | HIGH | CRITICAL
    confidence_score: float  # 0-1 from ConfidenceEngine
    corroboration_count: int  # How many tools found it
    payload_success_rate: float  # 0-1
    tools: List[str]  # Tools that found it
    evidence: List[PayloadEvidence]  # Payloads that worked
    privilege_level: str = "UNAUTHENTICATED"
    affected_by_auth: bool = False  # Is this only exploitable with auth?


class RiskEngine:
    """
    Convert confidence + corroboration + evidence into risk severity
    
    Scoring Model:
    1. Payload Success Rate (30%) - 0-1 score
    2. Corroboration Count (30%) - normalized (1 tool = 0.3, 2 = 0.6, 3+ = 1.0)
    3. Tool Agreement (20%) - weight by tool reliability
    4. Impact Multiplier (15%) - OWASP category base severity
    5. Auth Context (5%) - privilege level multiplier
    """

    # Tool reliability weights (by historical accuracy)
    TOOL_WEIGHTS = {
        "sqlmap": 0.95,  # SQL injection specialist
        "dalfox": 0.90,  # XSS specialist
        "commix": 0.88,  # Command injection specialist
        "nuclei": 0.85,  # Template-based
        "burp": 0.92,  # Industry standard
        "zaproxy": 0.88,  # Good general tool
        "custom": 0.50,  # Custom tools less reliable
    }

    def __init__(self):
        self.findings: Dict[Tuple[str, str, str], RiskFinding] = {}
        self.payload_evidence: Dict[str, List[PayloadEvidence]] = {}

    def add_payload_evidence(self, evidence: PayloadEvidence) -> None:
        """Register successful payload execution"""
        key = (evidence.endpoint, evidence.parameter, evidence.tool_name)
        key_str = f"{key[0]}[{key[1]}]@{key[2]}"

        if key_str not in self.payload_evidence:
            self.payload_evidence[key_str] = []

        self.payload_evidence[key_str].append(evidence)
        logger.info(
            f"[RiskEngine] Registered payload evidence: {evidence.tool_name} "
            f"on {evidence.endpoint}[{evidence.parameter}]"
        )

    def calculate_payload_success_rate(
        self,
        endpoint: str,
        parameter: str,
        attempts: int = 10,
        successes: int = 8
    ) -> float:
        """
        Calculate payload success rate for given endpoint/parameter
        
        Args:
            endpoint: Target endpoint
            parameter: Target parameter
            attempts: Total payload attempts
            successes: How many succeeded
            
        Returns:
            Success rate (0-1)
        """
        if attempts == 0:
            return 0.0
        rate = min(successes / attempts, 1.0)
        return rate

    def calculate_risk(
        self,
        endpoint: str,
        parameter: str,
        vulnerability_type: str,
        owasp_category: str,
        confidence_score: float,  # From ConfidenceEngine (0-1)
        corroboration_count: int,  # How many tools found it
        tools: List[str],  # Which tools
        payload_success_rate: float = 0.0,  # Success rate (0-1)
        privilege_level: str = "UNAUTHENTICATED"
    ) -> RiskFinding:
        """
        Calculate final risk severity
        
        Args:
            endpoint: Target endpoint
            parameter: Target parameter
            vulnerability_type: Type (SQL_INJECTION, XSS, etc.)
            owasp_category: OWASP category (A01, A03, etc.)
            confidence_score: Confidence from ConfidenceEngine (0-1)
            corroboration_count: Number of tools that found it
            tools: List of tool names
            payload_success_rate: Payload execution success rate (0-1)
            privilege_level: UNAUTHENTICATED | USER | ADMIN
            
        Returns:
            RiskFinding with calculated severity
        """

        # 1. Payload Success Rate (30%) - actual evidence it works
        success_score = payload_success_rate  # 0-1

        # 2. Corroboration Count (30%) - normalized
        # 1 tool = 0.3, 2 tools = 0.6, 3+ tools = 1.0
        corroboration_score = min((corroboration_count - 1) / 2, 1.0)

        # 3. Tool Agreement (20%) - average reliability of tools
        if tools:
            tool_scores = [self.TOOL_WEIGHTS.get(tool.lower(), 0.5) for tool in tools]
            tool_agreement_score = sum(tool_scores) / len(tool_scores)
        else:
            tool_agreement_score = 0.0

        # 4. Impact Multiplier (15%) - OWASP category
        try:
            impact_enum = ImpactCategory[owasp_category]
            base_sev = impact_enum.base_severity()
            impact_multiplier = {"LOW": 1.0, "MEDIUM": 1.5, "HIGH": 2.0}[base_sev]
        except (KeyError, ValueError):
            impact_multiplier = 1.0

        # 5. Authentication Context (5%) - privilege level
        # ADMIN findings are more valuable than USER findings
        auth_multiplier = {
            "UNAUTHENTICATED": 1.0,
            "USER": 1.2,
            "ADMIN": 1.5,
            "SERVICE_ACCOUNT": 1.3
        }.get(privilege_level, 1.0)

        # Weighted calculation
        raw_score = (
            (success_score * 0.30) +  # Payload success (30%)
            (corroboration_score * 0.30) +  # Corroboration (30%)
            (tool_agreement_score * 0.20) +  # Tool agreement (20%)
            (confidence_score * 0.20)  # Confidence from engine (20%)
        )

        # Apply multipliers
        adjusted_score = raw_score * impact_multiplier * auth_multiplier

        # Clamp to 0-1
        final_score = min(adjusted_score, 1.0)

        # Map to severity
        severity = self._score_to_severity(final_score, owasp_category)

        # Create finding
        finding = RiskFinding(
            endpoint=endpoint,
            parameter=parameter,
            vulnerability_type=vulnerability_type,
            owasp_category=owasp_category,
            risk_severity=severity,
            confidence_score=confidence_score,
            corroboration_count=corroboration_count,
            payload_success_rate=payload_success_rate,
            tools=tools,
            evidence=[],  # Will be populated from payload_evidence
            privilege_level=privilege_level,
            affected_by_auth=(privilege_level != "UNAUTHENTICATED")
        )

        # Attach evidence
        for tool in tools:
            key_str = f"{endpoint}[{parameter}]@{tool}"
            if key_str in self.payload_evidence:
                finding.evidence.extend(self.payload_evidence[key_str])

        self.findings[(endpoint, parameter, vulnerability_type)] = finding

        logger.info(
            f"[RiskEngine] Calculated risk for {endpoint}[{parameter}] ({vulnerability_type}): "
            f"{severity} (score={final_score:.2f}, tools={len(tools)}, success_rate={payload_success_rate:.2f})"
        )

        return finding

    def _score_to_severity(self, score: float, owasp_category: str) -> str:
        """Map score + OWASP category to severity"""
        try:
            impact_enum = ImpactCategory[owasp_category]
            base_sev = impact_enum.base_severity()
        except (KeyError, ValueError):
            base_sev = "MEDIUM"

        # Score-based thresholds vary by base severity
        if base_sev == "HIGH":
            # High-impact categories: lower thresholds
            if score >= 0.8:
                return "CRITICAL"
            elif score >= 0.6:
                return "HIGH"
            elif score >= 0.4:
                return "MEDIUM"
            elif score >= 0.2:
                return "LOW"
            else:
                return "INFO"
        elif base_sev == "MEDIUM":
            # Medium-impact categories
            if score >= 0.8:
                return "HIGH"
            elif score >= 0.6:
                return "MEDIUM"
            elif score >= 0.3:
                return "LOW"
            else:
                return "INFO"
        else:  # LOW
            # Low-impact categories: high thresholds
            if score >= 0.9:
                return "HIGH"
            elif score >= 0.7:
                return "MEDIUM"
            elif score >= 0.4:
                return "LOW"
            else:
                return "INFO"

    def get_findings_by_severity(self, severity: str) -> List[RiskFinding]:
        """Get findings at specific severity level"""
        return [f for f in self.findings.values() if f.risk_severity == severity]

    def get_critical_findings(self) -> List[RiskFinding]:
        """Get all CRITICAL findings"""
        return self.get_findings_by_severity("CRITICAL")

    def get_high_findings(self) -> List[RiskFinding]:
        """Get all HIGH findings"""
        return self.get_findings_by_severity("HIGH")

    def get_findings_by_owasp(self, category: str) -> List[RiskFinding]:
        """Get findings for specific OWASP category"""
        return [f for f in self.findings.values() if f.owasp_category == category]

    def get_summary(self) -> Dict:
        """Get risk summary"""
        by_severity = {
            "CRITICAL": len(self.get_critical_findings()),
            "HIGH": len(self.get_high_findings()),
            "MEDIUM": len(self.get_findings_by_severity("MEDIUM")),
            "LOW": len(self.get_findings_by_severity("LOW")),
            "INFO": len(self.get_findings_by_severity("INFO"))
        }

        top_vulnerable_endpoints = {}
        for finding in self.findings.values():
            if finding.endpoint not in top_vulnerable_endpoints:
                top_vulnerable_endpoints[finding.endpoint] = 0
            top_vulnerable_endpoints[finding.endpoint] += 1

        top_vulnerable_endpoints = dict(
            sorted(
                top_vulnerable_endpoints.items(),
                key=lambda x: x[1],
                reverse=True
            )[:10]
        )

        return {
            "total_findings": len(self.findings),
            "by_severity": by_severity,
            "top_vulnerable_endpoints": top_vulnerable_endpoints,
            "avg_confidence": (
                sum(f.confidence_score for f in self.findings.values()) / len(self.findings)
                if self.findings else 0
            ),
            "avg_corroboration": (
                sum(f.corroboration_count for f in self.findings.values()) / len(self.findings)
                if self.findings else 0
            )
        }

    def to_dict(self) -> Dict:
        """Serialize risk findings"""
        return {
            "summary": self.get_summary(),
            "findings": [
                {
                    "endpoint": f.endpoint,
                    "parameter": f.parameter,
                    "vulnerability_type": f.vulnerability_type,
                    "owasp_category": f.owasp_category,
                    "risk_severity": f.risk_severity,
                    "confidence_score": f.confidence_score,
                    "corroboration_count": f.corroboration_count,
                    "payload_success_rate": f.payload_success_rate,
                    "tools": f.tools,
                    "privilege_level": f.privilege_level,
                    "evidence_count": len(f.evidence)
                }
                for f in sorted(
                    self.findings.values(),
                    key=lambda f: (
                        {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}[f.risk_severity],
                        -f.confidence_score
                    )
                )
            ]
        }


# Example usage
"""
risk_engine = RiskEngine()

# Register payload evidence
evidence = PayloadEvidence(
    tool_name="sqlmap",
    endpoint="/api/users",
    parameter="id",
    payload="1' OR '1'='1",
    response="SELECT * FROM users WHERE id = 1' OR '1'='1'",
    success_indicator="UNION SELECT returned rows"
)
risk_engine.add_payload_evidence(evidence)

# Calculate risk
finding = risk_engine.calculate_risk(
    endpoint="/api/users",
    parameter="id",
    vulnerability_type="SQL_INJECTION",
    owasp_category="A03_INJECTION",
    confidence_score=0.95,
    corroboration_count=2,
    tools=["sqlmap", "nuclei"],
    payload_success_rate=0.9,
    privilege_level="UNAUTHENTICATED"
)

print(f"Risk Severity: {finding.risk_severity}")

# Get summary
print(risk_engine.get_summary())

# Get critical findings
critical = risk_engine.get_critical_findings()
"""
