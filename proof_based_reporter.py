"""
Proof-Based Vulnerability Reporter
Purpose: Report only confirmed vulnerabilities with explicit proof and evidence
"""

import logging
from typing import Dict, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from payload_execution_validator import PayloadExecutionValidator
from findings_model import Finding
from validation_engine import validate_finding_proof
from global_confidence_system import GlobalConfidenceSystem

logger = logging.getLogger(__name__)


class ConfirmationMethod(Enum):
    """How vulnerability was confirmed"""
    RESPONSE_DIFF = "response_diff"     # Response comparison showed difference
    CALLBACK = "callback"               # OOB callback received
    ERROR_SIGNATURE = "error_signature" # Error message in response
    PAYLOAD_REFLECTION = "reflection"   # Payload reflected in response
    TIMING = "timing"                   # Time-based detection
    DIRECT_EXPLOITATION = "direct"      # Direct proof of exploitation


@dataclass
class ProofOfExploitation:
    """Evidence of successful exploitation"""
    method: ConfirmationMethod
    confidence: float  # 0.0 - 1.0
    details: Dict = field(default_factory=dict)
    captured_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "method": self.method.value,
            "confidence": self.confidence,
            "details": self.details,
            "captured_at": self.captured_at,
        }


@dataclass
class ConfirmedVulnerability:
    """A vulnerability confirmed with proof"""
    type: str  # XSS, SSRF, SQLi, etc
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    endpoint: str
    parameter: str
    payload_used: str
    proof: ProofOfExploitation
    reproduction_steps: List[str] = field(default_factory=list)
    remediation: str = ""
    impact: str = ""
    exploitation_complexity: str = "low"  # low, medium, high
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "type": self.type,
            "severity": self.severity,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "payload": self.payload_used,
            "proof": self.proof.to_dict(),
            "reproduction_steps": self.reproduction_steps,
            "remediation": self.remediation,
            "impact": self.impact,
            "exploitation_complexity": self.exploitation_complexity,
            "discovered_at": self.discovered_at,
        }


class ProofBasedReporter:
    """
    Proof-based vulnerability reporter
    
    Principles:
    - Only report confirmed vulnerabilities
    - Include explicit proof for each finding
    - Show reproduction steps
    - Provide remediation guidance
    - Exclude "possible" or "potential" findings
    - Confidence must be > 0.7 for reporting
    """
    
    MIN_CONFIDENCE_FOR_REPORTING = 0.50
    FALSE_POSITIVE_KILL_SWITCH_THRESHOLD = 5
    
    def __init__(self):
        self.confirmed_vulnerabilities: List[ConfirmedVulnerability] = []
        self.rejected_findings: List[Dict] = []
        self.total_tested_vectors: int = 0
        self.discarded_false_positive_patterns: int = 0

    def register_test_attempt(self, count: int = 1) -> None:
        """Track how many exploit vectors were tested (for report honesty)."""
        self.total_tested_vectors += max(0, int(count))
    
    def add_confirmed_vulnerability(self, vuln_type: str, severity: str,
                                   endpoint: str, parameter: str,
                                   payload: str, confirmation_method: ConfirmationMethod,
                                   confidence: float, details: Dict,
                                   reproduction_steps: Optional[List[str]] = None,
                                   remediation: str = "",
                                   impact: str = "") -> Optional[ConfirmedVulnerability]:
        """
        Add a confirmed vulnerability to report
        
        Args:
            vuln_type: Vulnerability type (XSS, SSRF, SQLi, etc)
            severity: CRITICAL, HIGH, MEDIUM, LOW
            endpoint: Target endpoint
            parameter: Target parameter
            payload: Payload used
            confirmation_method: How it was confirmed
            confidence: Confidence score 0.0-1.0
            details: Dict with confirmation details
            reproduction_steps: How to reproduce
            remediation: How to fix
            impact: Business/technical impact
        
        Returns: ConfirmedVulnerability if accepted, None if confidence too low
        """
        if confidence < self.MIN_CONFIDENCE_FOR_REPORTING:
            self.rejected_findings.append({
                "reason": f"Low confidence ({confidence:.2f})",
                "type": vuln_type,
                "endpoint": endpoint,
            })
            logger.warning(f"Rejected {vuln_type} finding: confidence {confidence:.2f} < {self.MIN_CONFIDENCE_FOR_REPORTING}")
            return None
        
        proof = ProofOfExploitation(
            method=confirmation_method,
            confidence=confidence,
            details=details
        )
        
        vuln = ConfirmedVulnerability(
            type=vuln_type,
            severity=severity,
            endpoint=endpoint,
            parameter=parameter,
            payload_used=payload,
            proof=proof,
            reproduction_steps=reproduction_steps or [],
            remediation=remediation,
            impact=impact,
        )
        
        self.confirmed_vulnerabilities.append(vuln)
        logger.info(f"Confirmed {severity} {vuln_type}: {endpoint}?{parameter}=...")

        # Debug logging for validation transparency.
        baseline_hash = details.get("baseline_response_hash", "n/a")
        payload_hash = details.get("payload_response_hash", "n/a")
        diff_score = details.get("diff_score", "n/a")
        validation_method = details.get("validation_method", confirmation_method.value)
        logger.info(
            "CONFIRMED_VULN_DEBUG type=%s endpoint=%s param=%s baseline_hash=%s payload_hash=%s diff_score=%s validation=%s",
            vuln_type,
            endpoint,
            parameter,
            baseline_hash,
            payload_hash,
            diff_score,
            validation_method,
        )
        
        return vuln
    
    def add_from_exploitation_result(self, exploitation_result: Union[Dict, Finding]) -> Optional[ConfirmedVulnerability]:
        """
        Add vulnerability from exploitation engine result
        
        Exploitation engines return dicts with:
        - type: vulnerability type
        - endpoint: target endpoint
        - parameter: target parameter
        - payload: the payload used
        - confidence: confidence score
        - proof: dict with proof details
        """
        if isinstance(exploitation_result, Finding):
            exploitation_result = exploitation_result.to_exploitation_dict()

        # Map proof details to confirmation method
        proof_dict = exploitation_result.get("proof", {})
        confidence = float(exploitation_result.get("confidence", 0.0) or 0.0)

        # Wave 1: strict proof validation engine (type-aware, evidence-driven)
        strict_validation = validate_finding_proof(
            vuln_type=exploitation_result.get("type", ""),
            proof=proof_dict,
            confidence=confidence,
        )
        if not strict_validation.valid:
            self.rejected_findings.append({
                "reason": strict_validation.reason,
                "type": exploitation_result.get("type", "Unknown"),
                "endpoint": exploitation_result.get("endpoint", "unknown"),
                "parameter": exploitation_result.get("parameter", "unknown"),
            })
            logger.info(
                "Rejected by ValidationEngine type=%s endpoint=%s reason=%s",
                exploitation_result.get("type", "Unknown"),
                exploitation_result.get("endpoint", "unknown"),
                strict_validation.reason,
            )
            return None

        confidence = max(0.0, min(1.0, confidence + strict_validation.confidence_adjustment))

        valid, reason = PayloadExecutionValidator.validate_exploitation_proof(
            vuln_type=exploitation_result.get("type", ""),
            proof=proof_dict,
            confidence=confidence,
        )
        if not valid:
            self.rejected_findings.append({
                "reason": reason,
                "type": exploitation_result.get("type", "Unknown"),
                "endpoint": exploitation_result.get("endpoint", "unknown"),
                "parameter": exploitation_result.get("parameter", "unknown"),
            })
            logger.info(
                "Rejected exploitation result type=%s endpoint=%s reason=%s",
                exploitation_result.get("type", "Unknown"),
                exploitation_result.get("endpoint", "unknown"),
                reason,
            )
            return None

        # Wave 2: global confidence policy gate (report only high-confidence findings)
        confidence = GlobalConfidenceSystem.score(
            base_confidence=confidence,
            corroborated=False,
            validated=True,
            source="internal",
        )
        if not GlobalConfidenceSystem.should_report(confidence):
            self.rejected_findings.append({
                "reason": f"Global confidence gate: {confidence:.2f} < {GlobalConfidenceSystem.REPORT_THRESHOLD:.2f}",
                "type": exploitation_result.get("type", "Unknown"),
                "endpoint": exploitation_result.get("endpoint", "unknown"),
                "parameter": exploitation_result.get("parameter", "unknown"),
            })
            logger.info(
                "Rejected by GlobalConfidence gate type=%s endpoint=%s confidence=%.2f",
                exploitation_result.get("type", "Unknown"),
                exploitation_result.get("endpoint", "unknown"),
                confidence,
            )
            return None
        
        if proof_dict.get("callback_id"):
            confirmation_method = ConfirmationMethod.CALLBACK
        elif proof_dict.get("diff_result"):
            confirmation_method = ConfirmationMethod.RESPONSE_DIFF
        elif proof_dict.get("error_signature_found"):
            confirmation_method = ConfirmationMethod.ERROR_SIGNATURE
        elif proof_dict.get("payload_reflected"):
            confirmation_method = ConfirmationMethod.PAYLOAD_REFLECTION
        elif proof_dict.get("time_difference"):
            confirmation_method = ConfirmationMethod.TIMING
        else:
            confirmation_method = ConfirmationMethod.DIRECT_EXPLOITATION
        
        # Determine severity
        severity = self._determine_severity(
            exploitation_result.get("type"),
            exploitation_result.get("endpoint")
        )
        
        payload_value = (
            exploitation_result.get("payload")
            or exploitation_result.get("payload_true")
            or exploitation_result.get("payload_false")
            or ""
        )

        return self.add_confirmed_vulnerability(
            vuln_type=exploitation_result.get("type", "Unknown"),
            severity=severity,
            endpoint=exploitation_result.get("endpoint", "unknown"),
            parameter=exploitation_result.get("parameter", "unknown"),
            payload=payload_value,
            confirmation_method=confirmation_method,
            confidence=confidence,
            details=proof_dict,
            reproduction_steps=self._generate_reproduction_steps(
                exploitation_result.get("type"),
                exploitation_result.get("endpoint"),
                exploitation_result.get("parameter"),
                payload_value
            ),
            remediation=self._get_remediation(exploitation_result.get("type")),
            impact=self._get_impact(exploitation_result.get("type")),
        )
    
    def _determine_severity(self, vuln_type: str, endpoint: str) -> str:
        """
        Determine severity based on type and endpoint
        """
        severity_map = {
            "SSRF": "HIGH",
            "SQLi": "CRITICAL",
            "XSS": "HIGH",
            "RCE": "CRITICAL",
            "XXE": "HIGH",
            "IDOR": "MEDIUM",
            "Auth Bypass": "CRITICAL",
            "File Upload": "HIGH",
        }
        
        base_severity = severity_map.get(vuln_type, "MEDIUM")
        
        # Increase severity if on admin/sensitive endpoint
        if any(x in endpoint.lower() for x in ["admin", "api", "panel", "user", "account"]):
            if base_severity == "MEDIUM":
                base_severity = "HIGH"
            elif base_severity == "HIGH":
                base_severity = "CRITICAL"
        
        return base_severity
    
    def _generate_reproduction_steps(self, vuln_type: str, endpoint: str,
                                    parameter: str, payload: str) -> List[str]:
        """Generate step-by-step reproduction instructions"""
        safe_payload = payload or ""
        steps = [
            f"1. Open target URL: {endpoint}",
            f"2. Locate parameter: {parameter}",
            f"3. Inject payload: {safe_payload[:50]}{'...' if len(safe_payload) > 50 else ''}",
            f"4. Observe response for indicators",
        ]
        
        if vuln_type == "XSS":
            steps.append("5. Verify JavaScript execution or payload reflection")
        elif vuln_type == "SSRF":
            steps.append("5. Check callback logs or response for metadata access")
        elif vuln_type == "SQLi":
            steps.append("5. Analyze response timing or error messages")
        
        steps.append("6. Document findings for remediation")
        
        return steps
    
    def _get_remediation(self, vuln_type: str) -> str:
        """Get remediation guidance for vulnerability type"""
        remediations = {
            "XSS": "Implement output encoding, use Content Security Policy (CSP), validate and sanitize all user inputs",
            "SSRF": "Validate and whitelist allowed URL schemes/hosts, use network segmentation, implement firewall rules",
            "SQLi": "Use parameterized queries/prepared statements, implement input validation, use ORM frameworks",
            "RCE": "Remove or disable dangerous functions, use security libraries, implement input validation",
            "XXE": "Disable XML external entity processing, use safe XML parsers, implement DTD validation",
            "IDOR": "Implement proper authorization checks, verify user access for each resource operation",
            "Auth Bypass": "Review authentication logic, implement secure session handling, audit access controls",
            "File Upload": "Validate file types and size, store outside webroot, implement virus scanning",
        }
        
        return remediations.get(vuln_type, "Review security controls and implement input validation/output encoding")
    
    def _get_impact(self, vuln_type: str) -> str:
        """Get business impact description"""
        impacts = {
            "XSS": "Attackers can steal user sessions, perform actions on behalf of users, deface content, deploy malware",
            "SSRF": "Access to internal services, metadata endpoint exposure, port scanning, potential RCE",
            "SQLi": "Data breach, authentication bypass, potential remote code execution, complete database compromise",
            "RCE": "Complete system compromise, unauthorized access, data theft, malware deployment, lateral movement",
            "XXE": "File read, Server-Side Request Forgery, Denial of Service, potential RCE",
            "IDOR": "Unauthorized access to protected resources, data breach, privilege escalation",
            "Auth Bypass": "Unauthorized system access, privilege escalation, complete account takeover",
            "File Upload": "Malware deployment, remote code execution, denial of service, file system access",
        }
        
        return impacts.get(vuln_type, "Unauthorized access and potential system compromise")
    
    def generate_report(self) -> Dict:
        """
        Generate comprehensive vulnerability report
        
        Returns: Dict with executive summary and detailed findings
        """
        filtered_vulns = self._apply_false_positive_kill_switch(self.confirmed_vulnerabilities)
        total_confirmed = len(filtered_vulns)
        
        # Count by severity
        by_severity = {}
        for vuln in filtered_vulns:
            key = vuln.severity
            by_severity[key] = by_severity.get(key, 0) + 1
        
        # Count by type
        by_type = {}
        for vuln in filtered_vulns:
            key = vuln.type
            by_type[key] = by_type.get(key, 0) + 1

        tested_vectors = self.total_tested_vectors
        if tested_vectors <= 0:
            tested_vectors = total_confirmed + len(self.rejected_findings)
        discarded_total = max(0, tested_vectors - total_confirmed)
        
        return {
            "summary": {
                "total_confirmed": total_confirmed,
                "report_generated": datetime.now().isoformat(),
                "confidence_threshold_used": self.MIN_CONFIDENCE_FOR_REPORTING,
                "by_severity": by_severity,
                "by_type": by_type,
                "rejected_low_confidence": len(self.rejected_findings),
                "tested_vectors": tested_vectors,
                "confirmed_vectors": total_confirmed,
                "discarded_vectors": discarded_total,
                "discarded_false_positive_patterns": self.discarded_false_positive_patterns,
            },
            "findings": [v.to_dict() for v in filtered_vulns],
            "statistics": {
                "critical": by_severity.get("CRITICAL", 0),
                "high": by_severity.get("HIGH", 0),
                "medium": by_severity.get("MEDIUM", 0),
                "low": by_severity.get("LOW", 0),
                "critical_and_high": by_severity.get("CRITICAL", 0) + by_severity.get("HIGH", 0),
            }
        }

    def _apply_false_positive_kill_switch(
        self,
        vulnerabilities: List[ConfirmedVulnerability],
    ) -> List[ConfirmedVulnerability]:
        """Discard repeated identical vuln signatures across many endpoints."""
        groups: Dict[tuple, List[ConfirmedVulnerability]] = {}
        for vuln in vulnerabilities:
            signature = (
                vuln.type,
                vuln.parameter,
                vuln.payload_used,
                vuln.proof.method.value,
            )
            groups.setdefault(signature, []).append(vuln)

        kept: List[ConfirmedVulnerability] = []
        for signature, items in groups.items():
            unique_endpoints = {item.endpoint for item in items}
            if len(unique_endpoints) > self.FALSE_POSITIVE_KILL_SWITCH_THRESHOLD:
                self.discarded_false_positive_patterns += len(items)
                self.rejected_findings.append({
                    "reason": (
                        f"False-positive pattern kill switch: signature repeated across "
                        f"{len(unique_endpoints)} endpoints"
                    ),
                    "type": signature[0],
                    "parameter": signature[1],
                    "payload": signature[2],
                })
                continue
            kept.extend(items)

        return kept
    
    def has_critical_findings(self) -> bool:
        """Check if report contains CRITICAL severity findings"""
        return any(v.severity == "CRITICAL" for v in self.confirmed_vulnerabilities)
    
    def get_findings_by_severity(self, severity: str) -> List[ConfirmedVulnerability]:
        """Get findings filtered by severity"""
        return [v for v in self.confirmed_vulnerabilities if v.severity == severity]
    
    def get_findings_by_type(self, vuln_type: str) -> List[ConfirmedVulnerability]:
        """Get findings filtered by type"""
        return [v for v in self.confirmed_vulnerabilities if v.type == vuln_type]
