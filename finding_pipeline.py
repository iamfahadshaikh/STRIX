"""
FINDING PIPELINE — Standardize all tool outputs to Finding objects.

Purpose: Enforce uniform data flow across all sources.

Flow:
    tool_output → parser → Finding(id, category, endpoint, param, severity, confidence, evidence, source)
    ↓
    validator → (confirm/reject)
    ↓
    correlator → (deduplicate/merge)
    ↓
    reporter → (final report)
"""

import logging
import uuid
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict, field

logger = logging.getLogger(__name__)

# Import the existing Finding model if available
try:
    from findings_model import Finding, Severity
    FINDING_MODEL_AVAILABLE = True
except ImportError:
    FINDING_MODEL_AVAILABLE = False
    # Fallback dataclass if findings_model not available
    @dataclass
    class Severity:
        """Severity levels."""
        CRITICAL = "Critical"
        HIGH = "High"
        MEDIUM = "Medium"
        LOW = "Low"
        INFO = "Info"
    
    @dataclass
    class Finding:
        """Fallback Finding dataclass."""
        id: str
        category: str
        endpoint: str
        parameter: Optional[str]
        method: str
        severity: str
        confidence: float
        proof: Dict = field(default_factory=dict)
        evidence: Dict = field(default_factory=dict)
        source: str = "unknown"
        timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class FindingParser:
    """
    Convert tool outputs into Finding objects.
    """
    
    def __init__(self):
        logger.info("[FindingParser] Initialized")
    
    def parse_exploitation_result(self, result: Dict, source: str) -> Optional[Finding]:
        """
        Parse exploitation engine output into Finding.
        
        Expected result dict:
        {
            "endpoint": "/api/users",
            "parameter": "id",
            "method": "GET",
            "type": "SQLi",
            "confidence": 0.87,
            "proof": {...},
            ...
        }
        """
        if not result:
            return None
        
        try:
            finding_id = result.get("id") or str(uuid.uuid4())
            category = result.get("type") or result.get("category", "Unknown")
            endpoint = result.get("endpoint", "unknown")
            parameter = result.get("parameter")
            method = result.get("method", "GET")
            confidence = float(result.get("confidence", 0.0))
            proof = result.get("proof", {})
            
            # Determine severity from confidence
            severity = self._confidence_to_severity(confidence, category)
            
            finding = Finding(
                id=finding_id,
                category=category,
                endpoint=endpoint,
                parameter=parameter,
                method=method,
                severity=severity,
                confidence=confidence,
                proof=proof,
                evidence=result.get("evidence", {}),
                source=source,
            )
            
            logger.debug(f"Parsed finding: {finding.id} ({category}) from {source}")
            return finding
        
        except Exception as e:
            logger.error(f"Failed to parse exploitation result: {e}")
            return None
    
    def parse_zap_alert(self, alert: Dict) -> Optional[Finding]:
        """
        Parse ZAP alert into Finding.
        
        Expected alert dict (from ZAP JSON):
        {
            "alert": "SQL Injection",
            "confidence": "High",
            "url": "http://target.com/api/users?id=1",
            "param": "id",
            ...
        }
        """
        if not alert:
            return None
        
        try:
            finding_id = str(uuid.uuid4())
            alert_name = alert.get("alert", "Unknown")
            url = alert.get("url", "unknown")
            endpoint = self._extract_endpoint(url)
            parameter = alert.get("param")
            method = alert.get("method", "GET")
            
            # Map ZAP confidence to 0-1 float
            zap_confidence = alert.get("confidence", "Medium")
            confidence = self._zap_confidence_to_float(zap_confidence)
            
            # Map ZAP severity to our severity
            severity = self._zap_severity_to_severity(alert.get("riskcode", 1))
            
            finding = Finding(
                id=finding_id,
                category=alert_name,
                endpoint=endpoint,
                parameter=parameter,
                method=method,
                severity=severity,
                confidence=confidence,
                proof={"source": "zap", "alert": alert_name},
                evidence={"zap_alert": alert},
                source="zap",
            )
            
            logger.debug(f"Parsed ZAP alert: {finding.id} ({alert_name}) from {endpoint}")
            return finding
        
        except Exception as e:
            logger.error(f"Failed to parse ZAP alert: {e}")
            return None
    
    def parse_passive_finding(self, finding_dict: Dict) -> Optional[Finding]:
        """
        Parse passive analysis finding (headers, CSP, CORS, etc).
        
        Expected dict:
        {
            "category": "Missing CSP Header",
            "severity": "Medium",
            "confidence": 0.95,
            "endpoint": "https://target.com",
            "evidence": {"header": "..."}
        }
        """
        if not finding_dict:
            return None
        
        try:
            finding_id = finding_dict.get("id") or str(uuid.uuid4())
            category = finding_dict.get("category", "Unknown")
            endpoint = finding_dict.get("endpoint", "unknown")
            parameter = finding_dict.get("parameter")
            method = finding_dict.get("method", "GET")
            severity = finding_dict.get("severity", "Low")
            confidence = float(finding_dict.get("confidence", 0.95))
            
            finding = Finding(
                id=finding_id,
                category=category,
                endpoint=endpoint,
                parameter=parameter,
                method=method,
                severity=severity,
                confidence=confidence,
                proof={},
                evidence=finding_dict.get("evidence", {}),
                source="passive",
            )
            
            logger.debug(f"Parsed passive finding: {finding.id} ({category}) from {endpoint}")
            return finding
        
        except Exception as e:
            logger.error(f"Failed to parse passive finding: {e}")
            return None
    
    def _extract_endpoint(self, url: str) -> str:
        """Extract endpoint path from full URL."""
        if not url:
            return "unknown"
        try:
            # Simple parsing: extract path from URL
            from urllib.parse import urlparse
            parsed = urlparse(url)
            return parsed.path or "/"
        except:
            return url
    
    def _confidence_to_severity(self, confidence: float, category: str) -> str:
        """Map confidence score to severity level."""
        if confidence >= 0.95:
            return Severity.CRITICAL
        elif confidence >= 0.85:
            return Severity.HIGH
        elif confidence >= 0.70:
            return Severity.MEDIUM
        elif confidence >= 0.50:
            return Severity.LOW
        else:
            return Severity.INFO
    
    def _zap_confidence_to_float(self, zap_confidence: str) -> float:
        """Map ZAP confidence (High/Medium/Low) to float."""
        mapping = {
            "High": 0.90,
            "Medium": 0.70,
            "Low": 0.50,
            "Certain": 0.95,
        }
        return mapping.get(zap_confidence, 0.60)
    
    def _zap_severity_to_severity(self, riskcode: int) -> str:
        """Map ZAP risk code to severity."""
        mapping = {
            0: Severity.INFO,
            1: Severity.LOW,
            2: Severity.MEDIUM,
            3: Severity.HIGH,
            4: Severity.CRITICAL,
        }
        return mapping.get(riskcode, Severity.MEDIUM)


class FindingPipeline:
    """
    Orchestrate finding flow: parse → validate → correlate → report.
    """
    
    def __init__(self):
        self.parser = FindingParser()
        self.findings: List[Finding] = []
        self.rejected_findings: List[Finding] = []
        logger.info("[FindingPipeline] Initialized")
    
    def ingest_exploitation_results(self, results: List[Dict], source: str) -> List[Finding]:
        """Ingest multiple exploitation results."""
        findings = []
        for result in results:
            finding = self.parser.parse_exploitation_result(result, source)
            if finding:
                findings.append(finding)
        
        logger.info(f"Ingested {len(findings)} findings from {source}")
        return findings
    
    def ingest_zap_alerts(self, alerts: List[Dict]) -> List[Finding]:
        """Ingest ZAP alerts."""
        findings = []
        for alert in alerts:
            finding = self.parser.parse_zap_alert(alert)
            if finding:
                findings.append(finding)
        
        logger.info(f"Ingested {len(findings)} findings from ZAP")
        return findings
    
    def ingest_passive_findings(self, findings_list: List[Dict]) -> List[Finding]:
        """Ingest passive analysis findings."""
        findings = []
        for finding_dict in findings_list:
            finding = self.parser.parse_passive_finding(finding_dict)
            if finding:
                findings.append(finding)
        
        logger.info(f"Ingested {len(findings)} passive findings")
        return findings
    
    def add_findings(self, findings: List[Finding]) -> None:
        """Add findings to pipeline."""
        self.findings.extend(findings)
        logger.info(f"Total findings in pipeline: {len(self.findings)}")
    
    def reject_finding(self, finding: Finding, reason: str) -> None:
        """Reject a finding during validation."""
        finding_dict = asdict(finding) if hasattr(finding, '__dataclass_fields__') else finding.__dict__
        logger.warning(f"Rejected finding {finding.id}: {reason}")
        self.rejected_findings.append(finding)
    
    def summary(self) -> Dict[str, Any]:
        """Generate pipeline summary."""
        return {
            "total_findings": len(self.findings),
            "accepted": len(self.findings),
            "rejected": len(self.rejected_findings),
            "by_source": self._count_by_source(),
            "by_category": self._count_by_category(),
            "by_severity": self._count_by_severity(),
        }
    
    def _count_by_source(self) -> Dict[str, int]:
        """Count findings by source."""
        counts = {}
        for finding in self.findings:
            source = finding.source
            counts[source] = counts.get(source, 0) + 1
        return counts
    
    def _count_by_category(self) -> Dict[str, int]:
        """Count findings by category."""
        counts = {}
        for finding in self.findings:
            category = finding.category
            counts[category] = counts.get(category, 0) + 1
        return counts
    
    def _count_by_severity(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {}
        for finding in self.findings:
            severity = finding.severity
            counts[severity] = counts.get(severity, 0) + 1
        return counts


# Singleton
_pipeline = FindingPipeline()


def get_pipeline() -> FindingPipeline:
    """Get the global finding pipeline instance."""
    return _pipeline


def parse_exploitation_result(result: Dict, source: str) -> Optional[Finding]:
    """Public API: Parse exploitation result."""
    parser = FindingParser()
    return parser.parse_exploitation_result(result, source)


def parse_zap_alert(alert: Dict) -> Optional[Finding]:
    """Public API: Parse ZAP alert."""
    parser = FindingParser()
    return parser.parse_zap_alert(alert)


def parse_passive_finding(finding_dict: Dict) -> Optional[Finding]:
    """Public API: Parse passive finding."""
    parser = FindingParser()
    return parser.parse_passive_finding(finding_dict)
