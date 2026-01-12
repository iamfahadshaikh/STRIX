"""
Phase 4 Comprehensive Testing
Purpose: Validate all Phase 4 components work correctly

Tests:
  1. Traffic Capture & Replay
  2. Regression & Baseline Comparison
  3. CI/CD Integration
  4. Risk Aggregation
  5. Scan Profiles
  6. Engine Resilience
"""

import unittest
import json
import os
import tempfile
from datetime import datetime

# Import Phase 4 modules
from traffic_capture import TrafficCapture, HTTPRequest, HTTPResponse, HTTPExchange
from regression_engine import (
    RegressionEngine, ScanSnapshot, Finding, DeltaStatus, DeltaReport
)
from ci_integration import CIDDIntegration, ExitCode, CIDDGateway
from risk_aggregation import RiskAggregator, RiskLevel
from scan_profiles import ScanProfileManager, ProfileType
from engine_resilience import (
    ResilienceEngine, TimeoutHandler, ToolCrashIsolator, PartialFailureHandler,
    CheckpointManager, TimeoutException
)


class TestTrafficCapture(unittest.TestCase):
    """Test HTTP traffic capture and replay"""

    def setUp(self):
        self.capture = TrafficCapture(session_id="test_session_001")

    def test_capture_request(self):
        """Test request capture"""
        request_hash = self.capture.capture_request(
            url="https://example.com/api/users",
            method="GET",
            headers={"Authorization": "Bearer token123"},
            tool_name="dalfox"
        )
        self.assertIsNotNone(request_hash)
        self.assertEqual(len(self.capture.exchanges), 0)  # No response yet

    def test_capture_response(self):
        """Test request + response capture"""
        self.capture.capture_request(
            url="https://example.com/api/users",
            method="GET",
            headers={"Authorization": "Bearer token123"},
            tool_name="dalfox"
        )

        self.capture.capture_response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"users": []}',
            execution_time_ms=150.5
        )

        self.assertEqual(len(self.capture.exchanges), 1)
        exchange = self.capture.exchanges[0]
        self.assertEqual(exchange.response.status_code, 200)
        self.assertEqual(exchange.response.execution_time_ms, 150.5)

    def test_replay_mode(self):
        """Test replay mode"""
        # Record exchange
        self.capture.capture_request(
            url="https://example.com/api/users?id=1",
            method="GET",
            tool_name="dalfox"
        )
        self.capture.capture_response(
            status_code=200,
            body='{"user": {"id": 1, "name": "John"}}'
        )

        # Enable replay
        self.capture.set_replay_mode(True)
        self.assertTrue(self.capture.replay_mode)

        # Try to replay
        response = self.capture.get_next_response("https://example.com/api/users?id=1")
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 200)

    def test_session_tracking(self):
        """Test endpoint and tool tracking"""
        self.capture.capture_request(
            url="https://example.com/api/users",
            method="GET",
            tool_name="nuclei"
        )
        self.capture.capture_response(status_code=200)

        self.capture.capture_request(
            url="https://example.com/api/posts",
            method="POST",
            tool_name="dalfox"
        )
        self.capture.capture_response(status_code=201)

        summary = self.capture.get_session_summary()
        self.assertEqual(summary["exchanges_count"], 2)
        self.assertIn("https://example.com/api/users", summary["endpoints"])
        self.assertIn("nuclei", summary["tools"])
        self.assertIn("dalfox", summary["tools"])

    def test_har_export(self):
        """Test HAR format export"""
        self.capture.capture_request(
            url="https://example.com/api/users",
            method="GET",
            headers={"Accept": "application/json"}
        )
        self.capture.capture_response(
            status_code=200,
            headers={"Content-Type": "application/json"},
            body='{"users": []}'
        )

        har = self.capture.export_har()
        self.assertIn("log", har)
        self.assertIn("entries", har["log"])
        self.assertEqual(len(har["log"]["entries"]), 1)


class TestRegressionEngine(unittest.TestCase):
    """Test regression detection"""

    def setUp(self):
        self.engine = RegressionEngine()

    def test_baseline_creation(self):
        """Test baseline creation"""
        findings = {
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
            scan_id="baseline_001",
            timestamp=datetime.now().isoformat(),
            findings=findings
        )

        self.engine.create_baseline("baseline_001", baseline)
        self.assertIn("baseline_001", self.engine.baselines)

    def test_new_findings_detection(self):
        """Test detection of new findings"""
        baseline_findings = {}
        baseline = ScanSnapshot(
            scan_id="baseline_001",
            timestamp=datetime.now().isoformat(),
            findings=baseline_findings
        )
        self.engine.create_baseline("baseline_001", baseline)

        # New scan with findings
        current_findings = {
            ("/api/users", "id", "SQL_INJECTION"): Finding(
                endpoint="/api/users",
                parameter="id",
                vulnerability_type="SQL_INJECTION",
                risk_severity="CRITICAL",
                tool_count=1,
                tools=["sqlmap"]
            )
        }

        current = ScanSnapshot(
            scan_id="scan_002",
            timestamp=datetime.now().isoformat(),
            findings=current_findings
        )

        report = self.engine.compare_to_baseline("baseline_001", current)

        self.assertEqual(len(report.delta.get(DeltaStatus.NEW, [])), 1)
        self.assertEqual(len(report.delta.get(DeltaStatus.FIXED, [])), 0)

    def test_fixed_findings_detection(self):
        """Test detection of fixed findings"""
        baseline_findings = {
            ("/api/users", "id", "SQL_INJECTION"): Finding(
                endpoint="/api/users",
                parameter="id",
                vulnerability_type="SQL_INJECTION",
                risk_severity="CRITICAL",
                tool_count=1,
                tools=["sqlmap"]
            )
        }

        baseline = ScanSnapshot(
            scan_id="baseline_001",
            timestamp=datetime.now().isoformat(),
            findings=baseline_findings
        )
        self.engine.create_baseline("baseline_001", baseline)

        # Current scan with no findings
        current = ScanSnapshot(
            scan_id="scan_002",
            timestamp=datetime.now().isoformat(),
            findings={}
        )

        report = self.engine.compare_to_baseline("baseline_001", current)

        self.assertEqual(len(report.delta.get(DeltaStatus.FIXED, [])), 1)

    def test_regressed_findings_detection(self):
        """Test detection of regressed findings (severity increased)"""
        baseline_findings = {
            ("/api/users", "id", "SQL_INJECTION"): Finding(
                endpoint="/api/users",
                parameter="id",
                vulnerability_type="SQL_INJECTION",
                risk_severity="LOW",
                tool_count=1,
                tools=["dalfox"]
            )
        }

        baseline = ScanSnapshot(
            scan_id="baseline_001",
            timestamp=datetime.now().isoformat(),
            findings=baseline_findings
        )
        self.engine.create_baseline("baseline_001", baseline)

        # Same finding but higher severity
        current_findings = {
            ("/api/users", "id", "SQL_INJECTION"): Finding(
                endpoint="/api/users",
                parameter="id",
                vulnerability_type="SQL_INJECTION",
                risk_severity="CRITICAL",
                tool_count=2,
                tools=["sqlmap", "nuclei"]
            )
        }

        current = ScanSnapshot(
            scan_id="scan_002",
            timestamp=datetime.now().isoformat(),
            findings=current_findings
        )

        report = self.engine.compare_to_baseline("baseline_001", current)

        self.assertEqual(len(report.delta.get(DeltaStatus.REGRESSED, [])), 1)


class TestCIDDIntegration(unittest.TestCase):
    """Test CI/CD integration"""

    def setUp(self):
        self.ci = CIDDIntegration(
            app_name="testapp",
            scan_type="security",
            fail_on_critical=True,
            warn_on_medium=True
        )

    def test_add_critical_issue(self):
        """Test adding critical issue"""
        self.ci.add_issue(
            ruleId="OWASP_A01_SQL_INJECTION",
            message="SQL injection in /api/users?id",
            level="error",  # Critical
            location={"endpoint": "/api/users", "parameter": "id"}
        )

        self.assertEqual(len(self.ci.issues), 1)
        self.assertEqual(self.ci.issues[0].level, "error")

    def test_exit_code_critical(self):
        """Test exit code for critical findings"""
        self.ci.add_issue(
            ruleId="OWASP_A01_SQL_INJECTION",
            message="SQL injection",
            level="error"
        )

        exit_code = self.ci.get_exit_code()
        self.assertEqual(exit_code, ExitCode.CRITICAL_ISSUES)

    def test_exit_code_medium(self):
        """Test exit code for medium findings"""
        self.ci.add_issue(
            ruleId="WEAK_AUTH",
            message="Weak authentication",
            level="warning"
        )

        exit_code = self.ci.get_exit_code()
        self.assertEqual(exit_code, ExitCode.MEDIUM_ISSUES)

    def test_exit_code_clean(self):
        """Test exit code with no findings"""
        exit_code = self.ci.get_exit_code()
        self.assertEqual(exit_code, ExitCode.SUCCESS)

    def test_summary_generation(self):
        """Test summary generation"""
        self.ci.add_issue(
            ruleId="CRITICAL_BUG",
            message="Critical bug",
            level="error"
        )
        self.ci.add_issue(
            ruleId="MEDIUM_BUG",
            message="Medium bug",
            level="warning"
        )

        summary = self.ci.get_summary()
        self.assertEqual(summary["critical_count"], 1)
        self.assertEqual(summary["high_count"], 1)
        self.assertEqual(summary["total_issues"], 2)

    def test_build_gate(self):
        """Test build gate evaluation"""
        gate = CIDDGateway(fail_on_critical=True)

        self.ci.add_issue(
            ruleId="MEDIUM_BUG",
            message="Medium bug",
            level="warning"
        )

        # Should pass (medium only)
        self.assertTrue(gate.evaluate(self.ci))

        # Add critical
        self.ci.add_issue(
            ruleId="CRITICAL_BUG",
            message="Critical bug",
            level="error"
        )

        # Should fail
        self.assertFalse(gate.evaluate(self.ci))


class TestRiskAggregation(unittest.TestCase):
    """Test risk aggregation"""

    def setUp(self):
        self.agg = RiskAggregator(app_name="testapp")

    def test_add_findings(self):
        """Test adding findings"""
        self.agg.add_finding(
            endpoint="/api/users",
            vulnerability_type="SQL_INJECTION",
            severity="CRITICAL",
            tool_name="sqlmap",
            confidence=0.95
        )

        self.assertEqual(len(self.agg.findings), 1)

    def test_endpoint_aggregation(self):
        """Test per-endpoint aggregation"""
        self.agg.add_finding(
            endpoint="/api/users",
            parameter="id",
            vulnerability_type="SQL_INJECTION",
            severity="CRITICAL",
            tool_name="sqlmap"
        )

        self.agg.add_finding(
            endpoint="/api/users",
            parameter="username",
            vulnerability_type="XSS",
            severity="HIGH",
            tool_name="dalfox"
        )

        endpoint_risks = self.agg.aggregate_by_endpoint()

        self.assertIn("/api/users", endpoint_risks)
        risk = endpoint_risks["/api/users"]
        self.assertEqual(risk.critical_count, 1)
        self.assertEqual(risk.high_count, 1)
        self.assertEqual(risk.overall_severity, "CRITICAL")

    def test_application_risk_score(self):
        """Test application risk score calculation"""
        self.agg.add_finding(
            endpoint="/api/users",
            vulnerability_type="SQL_INJECTION",
            severity="CRITICAL",
            tool_name="sqlmap"
        )

        app_risk = self.agg.aggregate_by_application()

        self.assertEqual(app_risk.critical_count, 1)
        self.assertGreater(app_risk.business_risk_score, 20)
        self.assertEqual(app_risk.risk_rating, "CRITICAL")


class TestScanProfiles(unittest.TestCase):
    """Test scan profiles"""

    def setUp(self):
        self.manager = ScanProfileManager()

    def test_list_profiles(self):
        """Test listing available profiles"""
        profiles = self.manager.list_profiles()

        self.assertEqual(len(profiles), 5)
        self.assertIn("recon-only", profiles)
        self.assertIn("safe-va", profiles)
        self.assertIn("auth-va", profiles)
        self.assertIn("ci-fast", profiles)
        self.assertIn("full-va", profiles)

    def test_get_profile(self):
        """Test getting profile"""
        profile = self.manager.get_profile("safe-va")

        self.assertIsNotNone(profile)
        self.assertEqual(profile.name, "safe-va")
        self.assertIn("nuclei", profile.enabled_tools)

    def test_profile_validation(self):
        """Test profile validation"""
        valid, errors = self.manager.validate_profile("auth-va")

        self.assertTrue(valid)
        self.assertEqual(len(errors), 0)

    def test_custom_profile_creation(self):
        """Test creating custom profile"""
        custom = self.manager.create_custom_profile(
            name="custom_test",
            base_profile="safe-va",
            enabled_tools=["nuclei"],
            timeout_minutes=20
        )

        self.assertIsNotNone(custom)
        self.assertEqual(custom.name, "custom_test")
        self.assertEqual(custom.timeout_minutes, 20)


class TestEngineResilience(unittest.TestCase):
    """Test engine resilience"""

    def test_timeout_handler(self):
        """Test timeout handler"""
        handler = TimeoutHandler(timeout_seconds=1.0)

        handler.start()
        handler.check()  # Should pass

        # Wait and check again
        import time
        time.sleep(1.1)

        with self.assertRaises(TimeoutException):
            handler.check()

    def test_crash_isolator(self):
        """Test tool crash isolation"""
        isolator = ToolCrashIsolator()

        # Function that works
        def good_function():
            return [1, 2, 3]

        result = isolator.execute_tool_safe(
            tool_name="test_tool",
            tool_function=good_function,
            timeout_seconds=5
        )

        self.assertEqual(result, [1, 2, 3])

    def test_crash_isolator_with_exception(self):
        """Test crash isolator handles exceptions"""
        isolator = ToolCrashIsolator()

        def bad_function():
            raise Exception("Tool crashed!")

        result = isolator.execute_tool_safe(
            tool_name="test_tool",
            tool_function=bad_function,
            timeout_seconds=5,
            fallback_value=[]
        )

        self.assertEqual(result, [])
        crash_report = isolator.get_crash_report()
        self.assertEqual(crash_report["total_crashes"], 1)

    def test_partial_failure_handler(self):
        """Test partial failure handling"""
        handler = PartialFailureHandler(fail_threshold=0.5)

        handler.add_endpoint_attempt("/api/users", tools_count=2)
        handler.record_success("/api/users", "tool1")
        handler.record_failure("/api/users", "tool2")

        # Should not skip (50% success)
        self.assertFalse(handler.should_skip_endpoint("/api/users"))

    def test_resilience_engine(self):
        """Test complete resilience engine"""
        engine = ResilienceEngine(
            scan_id="test_scan",
            timeout_seconds=60,
            checkpoint_enabled=False
        )

        def test_tool():
            return [{"finding": "test"}]

        result = engine.execute_tool_safe(
            tool_name="test_tool",
            endpoint="/api/test",
            tool_function=test_tool
        )

        self.assertIsNotNone(result)

        report = engine.get_resilience_report()
        self.assertEqual(report["scan_id"], "test_scan")


def run_tests():
    """Run all tests"""
    unittest.main(argv=[""], verbosity=2, exit=False)


if __name__ == "__main__":
    run_tests()
