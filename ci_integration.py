"""
CI/CD Integration Layer - Phase 4 Task 4
Purpose: Headless scanning mode for build pipelines

Features:
  1. Headless mode (no TUI, JSON output only)
  2. Exit codes by severity (0-5)
  3. Build gates (CRITICAL fail, MEDIUM warn)
  4. SARIF export (GitHub/GitLab native)
  5. JUnit export (standard CI/CD)
  6. Deterministic output format
"""

import logging
import json
import sys
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

logger = logging.getLogger(__name__)


class ExitCode(int, Enum):
    """Exit codes for build pipelines"""
    SUCCESS = 0              # No issues
    LOW_ISSUES = 1           # Low/Info only
    MEDIUM_ISSUES = 2        # Medium or above
    HIGH_ISSUES = 3          # High or above
    CRITICAL_ISSUES = 4      # Critical present
    ERROR = 5                # Engine error (crash, timeout, etc.)


@dataclass
class ScanIssue:
    """CI/CD normalized issue"""
    ruleId: str              # e.g., "OWASP_A01_SQL_INJECTION"
    message: str
    level: str               # "note"|"warning"|"error"
    locations: List[Dict] = field(default_factory=list)  # file, line, column
    properties: Dict = field(default_factory=dict)        # additional context


@dataclass
class SARIFRun:
    """SARIF format run"""
    tool_name: str
    version: str
    rules: List[Dict] = field(default_factory=list)
    results: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "tool": {"driver": {"name": self.tool_name, "version": self.version}},
            "results": self.results,
            "rules": self.rules
        }


@dataclass
class JUnitTestCase:
    """JUnit test case"""
    name: str
    classname: str
    time: float = 0.0
    failure_message: Optional[str] = None
    failure_text: Optional[str] = None
    
    def to_xml(self) -> str:
        xml = f'  <testcase name="{self.name}" classname="{self.classname}" time="{self.time}">\n'
        if self.failure_message:
            xml += f'    <failure message="{self.failure_message}">{self.failure_text}</failure>\n'
        xml += '  </testcase>\n'
        return xml


@dataclass
class JUnitTestSuite:
    """JUnit test suite"""
    name: str
    tests: int = 0
    failures: int = 0
    errors: int = 0
    time: float = 0.0
    testcases: List[JUnitTestCase] = field(default_factory=list)
    
    def to_xml(self) -> str:
        xml = f'<?xml version="1.0" encoding="UTF-8"?>\n'
        xml += f'<testsuite name="{self.name}" tests="{self.tests}" '
        xml += f'failures="{self.failures}" errors="{self.errors}" time="{self.time}">\n'
        
        for tc in self.testcases:
            xml += tc.to_xml()
        
        xml += '</testsuite>\n'
        return xml


class CIDDIntegration:
    """
    CI/CD integration for build pipelines
    
    Usage:
        ci = CIDDIntegration(
            app_name="myapp",
            scan_type="security",
            fail_on_critical=True,
            warn_on_medium=True
        )
        
        # Add findings
        for finding in findings:
            ci.add_issue(
                ruleId=f"OWASP_{finding.owasp}_{finding.type}",
                message=finding.description,
                level=severity_to_level(finding.severity),
                location={"endpoint": finding.endpoint, "parameter": finding.parameter}
            )
        
        # Generate reports
        ci.export_sarif("results.sarif")
        ci.export_junit("results.xml")
        ci.export_json("results.json")
        
        # Get exit code
        exit_code = ci.get_exit_code()
        sys.exit(exit_code)
    """

    def __init__(
        self,
        app_name: str,
        scan_type: str = "security",
        version: str = "4.0.0",
        fail_on_critical: bool = True,
        warn_on_medium: bool = True
    ):
        self.app_name = app_name
        self.scan_type = scan_type
        self.version = version
        self.fail_on_critical = fail_on_critical
        self.warn_on_medium = warn_on_medium
        
        self.issues: List[ScanIssue] = []
        self.start_time = datetime.now().isoformat()
        self.rules: Dict[str, Dict] = {}

    def add_issue(
        self,
        ruleId: str,
        message: str,
        level: str,
        location: Optional[Dict] = None,
        properties: Optional[Dict] = None
    ) -> None:
        """Add finding"""
        issue = ScanIssue(
            ruleId=ruleId,
            message=message,
            level=level,
            locations=[location] if location else [],
            properties=properties or {}
        )
        self.issues.append(issue)
        
        # Register rule
        if ruleId not in self.rules:
            self.rules[ruleId] = {
                "id": ruleId,
                "shortDescription": {"text": message},
                "level": level,
                "help": {"text": f"For more details on {ruleId}, see documentation."}
            }
        
        logger.debug(f"[CI/CD] Added issue: {ruleId} ({level})")

    def get_exit_code(self) -> ExitCode:
        """
        Calculate exit code based on findings
        
        Logic:
          - CRITICAL found → 4
          - HIGH found → 3
          - MEDIUM found → 2 (if warn_on_medium)
          - LOW/INFO found → 1
          - No issues → 0
        """
        levels = [issue.level for issue in self.issues]
        
        if "error" in levels:
            return ExitCode.CRITICAL_ISSUES if self.fail_on_critical else ExitCode.MEDIUM_ISSUES
        
        if "warning" in levels and self.warn_on_medium:
            return ExitCode.MEDIUM_ISSUES
        
        if "note" in levels:
            return ExitCode.LOW_ISSUES
        
        return ExitCode.SUCCESS

    def get_summary(self) -> Dict:
        """Get scan summary"""
        level_counts = {"error": 0, "warning": 0, "note": 0}
        for issue in self.issues:
            level_counts[issue.level] += 1
        
        return {
            "app_name": self.app_name,
            "scan_type": self.scan_type,
            "start_time": self.start_time,
            "total_issues": len(self.issues),
            "critical_count": level_counts["error"],
            "high_count": level_counts["warning"],
            "low_count": level_counts["note"],
            "exit_code": self.get_exit_code(),
            "exit_code_name": self.get_exit_code().name
        }

    def export_json(self, filepath: str) -> None:
        """Export to JSON format (for automation)"""
        report = {
            "metadata": {
                "app_name": self.app_name,
                "scan_type": self.scan_type,
                "scanner_version": self.version,
                "timestamp": self.start_time
            },
            "summary": self.get_summary(),
            "issues": [
                {
                    "ruleId": issue.ruleId,
                    "message": issue.message,
                    "level": issue.level,
                    "locations": issue.locations,
                    "properties": issue.properties
                }
                for issue in self.issues
            ]
        }
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"[CI/CD] Exported JSON to {filepath}")

    def export_sarif(self, filepath: str) -> None:
        """Export to SARIF format (GitHub/GitLab native)"""
        run = SARIFRun(
            tool_name=self.app_name,
            version=self.version
        )
        
        # Add rules
        for rule_id, rule_data in self.rules.items():
            run.rules.append(rule_data)
        
        # Add results
        for issue in self.issues:
            result = {
                "ruleId": issue.ruleId,
                "message": {"text": issue.message},
                "level": issue.level,
                "locations": issue.locations,
                "properties": issue.properties
            }
            run.results.append(result)
        
        sarif = {
            "version": "2.1.0",
            "runs": [run.to_dict()]
        }
        
        with open(filepath, 'w') as f:
            json.dump(sarif, f, indent=2)
        
        logger.info(f"[CI/CD] Exported SARIF to {filepath}")

    def export_junit(self, filepath: str) -> None:
        """Export to JUnit format (Jenkins/Azure Pipelines)"""
        suite = JUnitTestSuite(
            name=f"{self.app_name}_{self.scan_type}_scan",
            tests=len(self.issues),
            errors=0,
            failures=0,
            time=0.0
        )
        
        level_to_status = {
            "error": "CRITICAL",
            "warning": "HIGH",
            "note": "LOW"
        }
        
        for issue in self.issues:
            status = level_to_status.get(issue.level, "INFO")
            endpoint = issue.locations[0].get("endpoint", "unknown") if issue.locations else "unknown"
            
            tc = JUnitTestCase(
                name=f"{issue.ruleId}_{endpoint}",
                classname=status,
                time=0.0,
                failure_message=issue.message,
                failure_text=json.dumps(issue.properties, indent=2) if issue.properties else ""
            )
            
            if issue.level in ["error", "warning"]:
                suite.failures += 1
            
            suite.testcases.append(tc)
        
        with open(filepath, 'w') as f:
            f.write(suite.to_xml())
        
        logger.info(f"[CI/CD] Exported JUnit to {filepath}")

    def print_summary(self) -> None:
        """Print to stdout (for CI/CD logs)"""
        summary = self.get_summary()
        
        print("\n" + "="*70)
        print(f"  {self.app_name} - {self.scan_type.upper()} Scan Results")
        print("="*70)
        print(f"  Total Issues:     {summary['total_issues']}")
        print(f"  Critical:         {summary['critical_count']}")
        print(f"  High:             {summary['high_count']}")
        print(f"  Low/Info:         {summary['low_count']}")
        print(f"  Exit Code:        {summary['exit_code']} ({summary['exit_code_name']})")
        print("="*70 + "\n")

    def should_fail_build(self) -> bool:
        """Determine if build should fail"""
        has_critical = any(i.level == "error" for i in self.issues)
        has_medium = any(i.level == "warning" for i in self.issues)
        
        if self.fail_on_critical and has_critical:
            return True
        
        if self.warn_on_medium and has_medium:
            return True
        
        return False


class CIDDGateway:
    """
    Build gate enforcement
    
    Usage:
        gate = CIDDGateway(
            fail_on_critical=True,
            fail_on_high=False,
            warn_on_medium=True
        )
        
        passed = gate.evaluate(ci_results)
        if not passed:
            logger.error("Build gate failed")
            sys.exit(ExitCode.CRITICAL_ISSUES)
    """

    def __init__(
        self,
        fail_on_critical: bool = True,
        fail_on_high: bool = False,
        warn_on_medium: bool = True
    ):
        self.fail_on_critical = fail_on_critical
        self.fail_on_high = fail_on_high
        self.warn_on_medium = warn_on_medium

    def evaluate(self, ci: CIDDIntegration) -> bool:
        """
        Evaluate build gate
        
        Returns:
            True if build should proceed, False otherwise
        """
        has_critical = any(i.level == "error" for i in ci.issues)
        has_high = any(i.level == "warning" for i in ci.issues)
        has_medium = any(i.level == "note" for i in ci.issues)
        
        if self.fail_on_critical and has_critical:
            logger.error("[CI/CD] Gate FAILED: Critical issues found")
            return False
        
        if self.fail_on_high and has_high:
            logger.error("[CI/CD] Gate FAILED: High issues found")
            return False
        
        if self.warn_on_medium and has_medium:
            logger.warning("[CI/CD] Gate WARNING: Medium issues found (build continues)")
        
        logger.info("[CI/CD] Gate PASSED")
        return True


# Example usage
"""
# Initialize CI/CD
ci = CIDDIntegration(
    app_name="myapp",
    scan_type="security",
    fail_on_critical=True,
    warn_on_medium=True
)

# Add findings
ci.add_issue(
    ruleId="OWASP_A01_SQL_INJECTION",
    message="SQL injection in /api/users?id parameter",
    level="error",  # Critical
    location={"endpoint": "/api/users", "parameter": "id"},
    properties={"tool": "sqlmap", "confidence": 95}
)

ci.add_issue(
    ruleId="OWASP_A05_BROKEN_AUTH",
    message="Missing rate limiting on /api/login",
    level="warning",  # High
    location={"endpoint": "/api/login"},
    properties={"tool": "nuclei"}
)

# Export reports
ci.export_json("results.json")
ci.export_sarif("results.sarif")
ci.export_junit("results.xml")

# Print summary
ci.print_summary()

# Evaluate gate
gate = CIDDGateway(fail_on_critical=True)
if not gate.evaluate(ci):
    sys.exit(ExitCode.CRITICAL_ISSUES)
else:
    sys.exit(ExitCode.SUCCESS)
"""
