"""
Regression & Baseline Comparison - Phase 4 Task 3
Purpose: Compare scans, detect changes (NEW|FIXED|REGRESSED|PERSISTING)

Features:
  1. Baseline snapshots (immutable)
  2. Delta detection
  3. Trending over time
  4. Stability scoring
  5. Suspicious FP detection (single-tool fixes)
"""

import logging
import json
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class DeltaStatus(str, Enum):
    """Change status of finding"""
    NEW = "NEW"                  # Not in baseline
    PERSISTING = "PERSISTING"    # Same in both
    REGRESSED = "REGRESSED"      # Severity increased
    IMPROVED = "IMPROVED"        # Severity decreased
    FIXED = "FIXED"              # In baseline but not current


@dataclass
class Finding:
    """Normalized finding for comparison"""
    endpoint: str
    parameter: Optional[str]
    vulnerability_type: str
    risk_severity: str  # INFO|LOW|MEDIUM|HIGH|CRITICAL
    tool_count: int = 1
    tools: List[str] = field(default_factory=list)
    owasp_category: str = ""
    
    def get_key(self) -> Tuple:
        """Deduplication key"""
        return (self.endpoint, self.parameter, self.vulnerability_type)
    
    def to_dict(self) -> Dict:
        return {
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "vulnerability_type": self.vulnerability_type,
            "risk_severity": self.risk_severity,
            "tool_count": self.tool_count,
            "tools": self.tools,
            "owasp_category": self.owasp_category
        }


@dataclass
class ScanSnapshot:
    """Immutable scan snapshot"""
    scan_id: str
    timestamp: str
    endpoints: Dict[str, List[str]] = field(default_factory=dict)  # endpoint -> params
    findings: Dict[Tuple, Finding] = field(default_factory=dict)  # key -> Finding
    tool_count: int = 0
    duration_seconds: float = 0.0
    
    def get_hash(self) -> str:
        """Deterministic hash of all findings"""
        finding_strings = []
        for key, finding in sorted(self.findings.items()):
            finding_strings.append(f"{key[0]}|{key[1]}|{key[2]}|{finding.risk_severity}")
        all_findings = "|".join(finding_strings)
        return hashlib.sha256(all_findings.encode()).hexdigest()[:16]
    
    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp,
            "endpoints": self.endpoints,
            "findings": {str(k): v.to_dict() for k, v in self.findings.items()},
            "tool_count": self.tool_count,
            "duration_seconds": self.duration_seconds,
            "hash": self.get_hash()
        }
    
    @staticmethod
    def from_dict(data: Dict) -> 'ScanSnapshot':
        """Deserialize snapshot"""
        snapshot = ScanSnapshot(
            scan_id=data["scan_id"],
            timestamp=data["timestamp"],
            endpoints=data["endpoints"],
            tool_count=data["tool_count"],
            duration_seconds=data["duration_seconds"]
        )
        
        for key_str, finding_data in data.get("findings", {}).items():
            # Parse key
            parts = eval(key_str)  # (endpoint, parameter, type)
            finding = Finding(
                endpoint=finding_data["endpoint"],
                parameter=finding_data["parameter"],
                vulnerability_type=finding_data["vulnerability_type"],
                risk_severity=finding_data["risk_severity"],
                tool_count=finding_data["tool_count"],
                tools=finding_data["tools"],
                owasp_category=finding_data["owasp_category"]
            )
            snapshot.findings[parts] = finding
        
        return snapshot


@dataclass
class DeltaFinding:
    """Finding with delta status"""
    finding: Finding
    status: DeltaStatus
    baseline_severity: Optional[str] = None  # For REGRESSED/IMPROVED
    change_reason: str = ""


@dataclass
class DeltaReport:
    """Complete comparison report"""
    baseline_id: str
    current_scan_id: str
    delta: Dict[str, List[DeltaFinding]] = field(default_factory=dict)
    
    stability_score: float = 100.0  # 0-100, lower = more changes
    change_count: int = 0
    change_percentage: float = 0.0
    
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "baseline_id": self.baseline_id,
            "current_scan_id": self.current_scan_id,
            "delta": {
                status: [
                    {
                        **finding.finding.to_dict(),
                        "status": finding.status.value,
                        "baseline_severity": finding.baseline_severity,
                        "change_reason": finding.change_reason
                    }
                    for finding in delta_findings
                ]
                for status, delta_findings in self.delta.items()
            },
            "stability_score": self.stability_score,
            "change_count": self.change_count,
            "change_percentage": self.change_percentage,
            "summary": self.get_summary(),
            "timestamp": self.timestamp
        }
    
    def get_summary(self) -> Dict:
        """Get summary counts"""
        return {
            "new": len(self.delta.get(DeltaStatus.NEW, [])),
            "fixed": len(self.delta.get(DeltaStatus.FIXED, [])),
            "regressed": len(self.delta.get(DeltaStatus.REGRESSED, [])),
            "improved": len(self.delta.get(DeltaStatus.IMPROVED, [])),
            "persisting": len(self.delta.get(DeltaStatus.PERSISTING, []))
        }


class RegressionEngine:
    """
    Compare scans and detect changes
    
    Usage:
        engine = RegressionEngine()
        
        # Create baseline
        baseline = ScanSnapshot(
            scan_id="baseline_20260101",
            timestamp="2026-01-01T00:00:00Z",
            endpoints={"/api/users": ["id", "limit"]},
            findings={...}
        )
        engine.create_baseline("baseline_20260101", baseline)
        
        # Compare current scan
        current = ScanSnapshot(
            scan_id="scan_20260112",
            timestamp="2026-01-12T14:30:00Z",
            endpoints={"/api/users": ["id", "limit"], "/api/posts": ["id"]},
            findings={...}
        )
        report = engine.compare_to_baseline("baseline_20260101", current)
        
        # Analyze
        print(f"New findings: {len(report.delta[DeltaStatus.NEW])}")
        print(f"Fixed findings: {len(report.delta[DeltaStatus.FIXED])}")
        print(f"Stability: {report.stability_score}/100")
    """

    def __init__(self):
        self.baselines: Dict[str, ScanSnapshot] = {}
        self.reports: Dict[str, DeltaReport] = {}

    def create_baseline(self, baseline_id: str, snapshot: ScanSnapshot) -> None:
        """Create immutable baseline snapshot"""
        self.baselines[baseline_id] = snapshot
        logger.info(
            f"[RegressionEngine] Created baseline '{baseline_id}': "
            f"{len(snapshot.findings)} findings, hash={snapshot.get_hash()}"
        )

    def compare_to_baseline(
        self,
        baseline_id: str,
        current_snapshot: ScanSnapshot
    ) -> DeltaReport:
        """
        Compare current scan to baseline
        
        Args:
            baseline_id: Baseline to compare against
            current_snapshot: Current scan snapshot
            
        Returns:
            DeltaReport with NEW|FIXED|REGRESSED findings
        """
        if baseline_id not in self.baselines:
            logger.error(f"[RegressionEngine] Baseline not found: {baseline_id}")
            return DeltaReport(baseline_id=baseline_id, current_scan_id=current_snapshot.scan_id)

        baseline = self.baselines[baseline_id]
        report = DeltaReport(
            baseline_id=baseline_id,
            current_scan_id=current_snapshot.scan_id
        )

        # Track processed keys
        processed_keys: Set[Tuple] = set()

        # Check current findings
        for key, finding in current_snapshot.findings.items():
            processed_keys.add(key)

            if key not in baseline.findings:
                # NEW finding
                delta_finding = DeltaFinding(
                    finding=finding,
                    status=DeltaStatus.NEW,
                    change_reason=f"New {finding.vulnerability_type} on {finding.endpoint}"
                )
                if DeltaStatus.NEW not in report.delta:
                    report.delta[DeltaStatus.NEW] = []
                report.delta[DeltaStatus.NEW].append(delta_finding)

            else:
                # Finding existed in baseline
                baseline_finding = baseline.findings[key]

                # Severity change?
                severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                baseline_idx = severity_order.index(baseline_finding.risk_severity)
                current_idx = severity_order.index(finding.risk_severity)

                if current_idx > baseline_idx:
                    # REGRESSED
                    delta_finding = DeltaFinding(
                        finding=finding,
                        status=DeltaStatus.REGRESSED,
                        baseline_severity=baseline_finding.risk_severity,
                        change_reason=f"Severity increased: {baseline_finding.risk_severity} → {finding.risk_severity}"
                    )
                    if DeltaStatus.REGRESSED not in report.delta:
                        report.delta[DeltaStatus.REGRESSED] = []
                    report.delta[DeltaStatus.REGRESSED].append(delta_finding)

                elif current_idx < baseline_idx:
                    # IMPROVED
                    delta_finding = DeltaFinding(
                        finding=finding,
                        status=DeltaStatus.IMPROVED,
                        baseline_severity=baseline_finding.risk_severity,
                        change_reason=f"Severity decreased: {baseline_finding.risk_severity} → {finding.risk_severity}"
                    )
                    if DeltaStatus.IMPROVED not in report.delta:
                        report.delta[DeltaStatus.IMPROVED] = []
                    report.delta[DeltaStatus.IMPROVED].append(delta_finding)

                else:
                    # PERSISTING (same severity)
                    delta_finding = DeltaFinding(
                        finding=finding,
                        status=DeltaStatus.PERSISTING,
                        change_reason="Persisting finding, same severity"
                    )
                    if DeltaStatus.PERSISTING not in report.delta:
                        report.delta[DeltaStatus.PERSISTING] = []
                    report.delta[DeltaStatus.PERSISTING].append(delta_finding)

        # Check for FIXED findings (in baseline but not current)
        for key, baseline_finding in baseline.findings.items():
            if key not in processed_keys:
                delta_finding = DeltaFinding(
                    finding=baseline_finding,
                    status=DeltaStatus.FIXED,
                    change_reason=f"Fixed: {baseline_finding.vulnerability_type} is no longer present"
                )
                if DeltaStatus.FIXED not in report.delta:
                    report.delta[DeltaStatus.FIXED] = []
                report.delta[DeltaStatus.FIXED].append(delta_finding)

        # Calculate stability score
        baseline_count = len(baseline.findings)
        change_count = (
            len(report.delta.get(DeltaStatus.NEW, [])) +
            len(report.delta.get(DeltaStatus.FIXED, [])) +
            len(report.delta.get(DeltaStatus.REGRESSED, []))
        )

        if baseline_count > 0:
            change_percentage = (change_count / baseline_count) * 100
            # Stability: 100% = no changes, 0% = all changed
            report.stability_score = max(0, 100 - change_percentage)
        else:
            report.stability_score = 100 if change_count == 0 else 0

        report.change_count = change_count
        report.change_percentage = change_percentage if baseline_count > 0 else 0

        self.reports[current_snapshot.scan_id] = report

        logger.info(
            f"[RegressionEngine] Comparison complete: "
            f"NEW={len(report.delta.get(DeltaStatus.NEW, []))} "
            f"FIXED={len(report.delta.get(DeltaStatus.FIXED, []))} "
            f"REGRESSED={len(report.delta.get(DeltaStatus.REGRESSED, []))} "
            f"STABILITY={report.stability_score:.1f}%"
        )

        return report

    def detect_suspicious_fixes(self, report: DeltaReport) -> List[Tuple[Finding, str]]:
        """
        Detect suspicious fixes (single-tool findings that "fixed")
        
        These might be false positives that got removed
        
        Returns:
            List of (finding, reason) tuples
        """
        suspicious = []

        for delta_finding in report.delta.get(DeltaStatus.FIXED, []):
            finding = delta_finding.finding
            
            # If finding had tool_count=1, it's suspicious
            if finding.tool_count == 1:
                reason = f"Suspicious fix: {finding.tools[0]} found it, but no corroboration"
                suspicious.append((finding, reason))
                logger.warning(f"[RegressionEngine] {reason}")

        return suspicious

    def get_trend_analysis(
        self,
        baseline: ScanSnapshot,
        current: ScanSnapshot
    ) -> Dict:
        """
        Analyze trend (stable, improving, degrading)
        
        Returns:
            Trend analysis dict
        """
        baseline_count = len(baseline.findings)
        current_count = len(current.findings)
        
        trend = "STABLE"
        if current_count > baseline_count:
            trend = "DEGRADING"
        elif current_count < baseline_count:
            trend = "IMPROVING"

        return {
            "trend": trend,
            "baseline_findings": baseline_count,
            "current_findings": current_count,
            "change": current_count - baseline_count,
            "change_percentage": (
                ((current_count - baseline_count) / baseline_count * 100)
                if baseline_count > 0 else 0
            )
        }

    def save_baseline(self, baseline_id: str, filepath: str) -> None:
        """Export baseline to JSON"""
        if baseline_id not in self.baselines:
            logger.error(f"[RegressionEngine] Baseline not found: {baseline_id}")
            return

        with open(filepath, 'w') as f:
            json.dump(self.baselines[baseline_id].to_dict(), f, indent=2)

        logger.info(f"[RegressionEngine] Saved baseline to {filepath}")

    def load_baseline(self, filepath: str) -> str:
        """Load baseline from JSON"""
        with open(filepath, 'r') as f:
            data = json.load(f)

        snapshot = ScanSnapshot.from_dict(data)
        self.baselines[snapshot.scan_id] = snapshot

        logger.info(f"[RegressionEngine] Loaded baseline from {filepath}")
        return snapshot.scan_id

    def save_report(self, scan_id: str, filepath: str) -> None:
        """Export comparison report"""
        if scan_id not in self.reports:
            logger.error(f"[RegressionEngine] Report not found: {scan_id}")
            return

        with open(filepath, 'w') as f:
            json.dump(self.reports[scan_id].to_dict(), f, indent=2)

        logger.info(f"[RegressionEngine] Saved report to {filepath}")


# Example usage
"""
engine = RegressionEngine()

# Create baseline
baseline_findings = {
    ("/api/users", "id", "SQL_INJECTION"): Finding(
        endpoint="/api/users",
        parameter="id",
        vulnerability_type="SQL_INJECTION",
        risk_severity="CRITICAL",
        tool_count=2,
        tools=["sqlmap", "nuclei"]
    )
}

baseline = ScanSnapshot(
    scan_id="baseline_20260101",
    timestamp="2026-01-01T00:00:00Z",
    findings=baseline_findings
)
engine.create_baseline("baseline_20260101", baseline)

# Current scan (same finding, but fixed)
current_findings = {
    ("/api/users", "id", "SQL_INJECTION"): Finding(
        endpoint="/api/users",
        parameter="id",
        vulnerability_type="SQL_INJECTION",
        risk_severity="LOW",
        tool_count=1,
        tools=["dalfox"]
    ),
    ("/api/posts", "id", "XSS"): Finding(
        endpoint="/api/posts",
        parameter="id",
        vulnerability_type="XSS",
        risk_severity="HIGH",
        tool_count=1,
        tools=["nuclei"]
    )
}

current = ScanSnapshot(
    scan_id="scan_20260112",
    timestamp="2026-01-12T14:30:00Z",
    findings=current_findings
)

# Compare
report = engine.compare_to_baseline("baseline_20260101", current)

print(f"New: {len(report.delta[DeltaStatus.NEW])}")  # 1 (/api/posts?id)
print(f"Improved: {len(report.delta[DeltaStatus.IMPROVED])}")  # 1 (/api/users?id improved)
print(f"Stability: {report.stability_score}%")
"""
