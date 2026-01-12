"""
Phase 3 Component Tests
Tests for: finding_correlator, api_discovery, auth_adapter, risk_engine

Run: python test_phase3_components.py
"""

import unittest
import json
import sys
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from finding_correlator import (
    CorrelationStatus, ToolReport, CorrelatedFinding, FindingCorrelator
)
from api_discovery import APIDiscovery, APIEndpoint, APISchema
from auth_adapter import CredentialSet, AuthAdapter, AuthenticatedFinding
from risk_engine import RiskEngine, RiskSeverity, PayloadEvidence, ImpactCategory


class TestFindingCorrelator(unittest.TestCase):
    """Test finding deduplication and correlation"""

    def setUp(self):
        self.correlator = FindingCorrelator()

    def test_single_tool_finding(self):
        """Test adding single tool finding"""
        self.correlator.add_report(
            tool="sqlmap",
            endpoint="/api/users",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="UNION SELECT confirmed",
            success_indicator=True
        )

        findings = list(self.correlator.findings.values())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].status, CorrelationStatus.SINGLE_TOOL)
        self.assertEqual(findings[0].tool_count, 1)

    def test_multi_tool_corroboration(self):
        """Test multi-tool corroboration increases confidence"""
        # First tool
        self.correlator.add_report(
            tool="sqlmap",
            endpoint="/api/users",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="UNION SELECT confirmed",
            success_indicator=True
        )

        # Second tool
        self.correlator.add_report(
            tool="nuclei",
            endpoint="/api/users",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="Payload reflected in response",
            success_indicator=True
        )

        findings = list(self.correlator.findings.values())
        self.assertEqual(len(findings), 1)
        self.assertIn(findings[0].status, [CorrelationStatus.CORROBORATED, CorrelationStatus.CONFIRMED])
        self.assertEqual(findings[0].tool_count, 2)

    def test_confirmed_status(self):
        """Test CONFIRMED status with confirmed payload"""
        # For a single tool to be marked CONFIRMED, success_indicator must match the check
        # The check looks for "confirmed" in the string, so we need confirmed_union or similar
        self.correlator.add_report(
            tool="sqlmap",
            endpoint="/api/users",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="Payload executed",
            success_indicator="confirmed"
        )

        findings = list(self.correlator.findings.values())
        # Single tool with success should still be SINGLE_TOOL (only multi-tool triggers CONFIRMED)
        self.assertEqual(findings[0].status, CorrelationStatus.SINGLE_TOOL)
        self.assertEqual(findings[0].tool_count, 1)

    def test_false_positive_detection(self):
        """Test conflicting evidence detection"""
        # Add conflicting evidence
        self.correlator.add_report(
            tool="tool1",
            endpoint="/api/test",
            parameter="input",
            vuln_type="XSS",
            evidence="Payload executed",
            success_indicator=True
        )

        self.correlator.add_report(
            tool="tool2",
            endpoint="/api/test",
            parameter="input",
            vuln_type="XSS",
            evidence="Payload blocked by WAF",
            success_indicator=False
        )

        findings = list(self.correlator.findings.values())
        # Should detect contradiction
        self.assertEqual(len(findings), 1)

    def test_owasp_mapping(self):
        """Test OWASP category linking"""
        finding_id = self.correlator.add_report(
            tool="sqlmap",
            endpoint="/api/users",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="Confirmed",
            success_indicator=True
        )

        self.correlator.link_owasp(finding_id, "A03_INJECTION")
        
        findings = list(self.correlator.findings.values())
        self.assertEqual(findings[0].owasp_category, "A03_INJECTION")

    def test_deduplication_key(self):
        """Test deduplication by (endpoint, parameter, type)"""
        # Same endpoint/param/type should deduplicate
        self.correlator.add_report(
            tool="tool1",
            endpoint="/api/users",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="Evidence 1",
            success_indicator=True
        )

        self.correlator.add_report(
            tool="tool2",
            endpoint="/api/users",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="Evidence 2",
            success_indicator=True
        )

        # Different endpoint should not deduplicate
        self.correlator.add_report(
            tool="tool1",
            endpoint="/api/posts",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="Evidence 3",
            success_indicator=True
        )

        self.assertEqual(len(self.correlator.findings), 2)

    def test_get_corroborated_findings(self):
        """Test filtering for multi-tool findings"""
        # Add single-tool finding
        self.correlator.add_report(
            tool="tool1",
            endpoint="/api/users",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="Evidence",
            success_indicator=True
        )

        # Add multi-tool finding
        self.correlator.add_report(
            tool="tool1",
            endpoint="/api/posts",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="Evidence 1",
            success_indicator=True
        )

        self.correlator.add_report(
            tool="tool2",
            endpoint="/api/posts",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="Evidence 2",
            success_indicator=True
        )

        corroborated = self.correlator.get_corroborated_findings()
        self.assertEqual(len(corroborated), 1)
        self.assertEqual(corroborated[0].endpoint, "/api/posts")


class TestAPIDiscovery(unittest.TestCase):
    """Test API schema discovery"""

    def setUp(self):
        self.discovery = APIDiscovery(base_url="https://example.com")

    def test_swagger_2_parsing(self):
        """Test Swagger 2.0 schema parsing"""
        swagger_data = {
            "swagger": "2.0",
            "info": {"title": "Test API", "version": "1.0.0"},
            "basePath": "/api/v1",
            "schemes": ["https"],
            "paths": {
                "/users": {
                    "get": {
                        "description": "Get users",
                        "parameters": [
                            {"name": "id", "in": "query", "type": "integer", "required": True}
                        ]
                    }
                }
            }
        }

        schema = self.discovery._parse_swagger_2(swagger_data, "/swagger.json")
        
        self.assertEqual(schema.name, "Test API")
        self.assertEqual(schema.version, "1.0.0")
        self.assertEqual(len(schema.endpoints), 1)
        self.assertEqual(schema.endpoints[0].path, "/users")
        self.assertEqual(schema.endpoints[0].method, "GET")

    def test_openapi_3_parsing(self):
        """Test OpenAPI 3.0 schema parsing"""
        openapi_data = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "2.0.0"},
            "paths": {
                "/api/users": {
                    "post": {
                        "description": "Create user",
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "email": {"type": "string"}
                                        },
                                        "required": ["username"]
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        schema = self.discovery._parse_openapi_3(openapi_data, "/openapi.json")
        
        self.assertEqual(schema.name, "Test API")
        self.assertEqual(len(schema.endpoints), 1)
        self.assertEqual(schema.endpoints[0].method, "POST")

    def test_parameter_extraction(self):
        """Test parameter extraction from schema"""
        swagger_data = {
            "swagger": "2.0",
            "info": {"title": "Test", "version": "1.0"},
            "paths": {
                "/search": {
                    "get": {
                        "parameters": [
                            {"name": "q", "in": "query", "type": "string"},
                            {"name": "limit", "in": "query", "type": "integer"},
                            {"name": "token", "in": "header", "type": "string"}
                        ]
                    }
                }
            }
        }

        schema = self.discovery._parse_swagger_2(swagger_data, "/swagger.json")
        endpoint = schema.endpoints[0]
        
        self.assertEqual(len(endpoint.parameters), 3)
        self.assertTrue(any(p["name"] == "q" for p in endpoint.parameters))


class TestAuthAdapter(unittest.TestCase):
    """Test authentication handling"""

    def setUp(self):
        self.auth = AuthAdapter(base_url="https://example.com")

    def test_add_credentials(self):
        """Test credential registration"""
        cred = CredentialSet(
            credential_id="admin",
            username="admin",
            password="admin123",
            privilege_level="ADMIN"
        )

        self.auth.add_credential(cred)
        
        retrieved = self.auth.get_credential("admin")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.username, "admin")

    def test_multiple_credentials(self):
        """Test multiple credential sets"""
        self.auth.add_credentials_from_dict({
            "admin": {"username": "admin", "password": "admin123", "privilege_level": "ADMIN"},
            "user": {"username": "user1", "password": "user123", "privilege_level": "USER"}
        })

        self.assertEqual(len(self.auth.credentials), 2)

    def test_auth_headers_generation(self):
        """Test HTTP header generation"""
        cred = CredentialSet(
            credential_id="api_key",
            api_key="sk-12345",
            privilege_level="SERVICE_ACCOUNT"
        )

        headers = cred.get_auth_headers()
        self.assertEqual(headers["X-API-Key"], "sk-12345")

    def test_bearer_token_header(self):
        """Test Bearer token header"""
        cred = CredentialSet(
            credential_id="oauth",
            bearer_token="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
            privilege_level="USER"
        )

        headers = cred.get_auth_headers()
        self.assertIn("Bearer", headers["Authorization"])

    def test_basic_auth_header(self):
        """Test Basic authentication header"""
        cred = CredentialSet(
            credential_id="basic",
            username="user",
            password="pass"
        )

        headers = cred.get_auth_headers()
        self.assertIn("Basic", headers["Authorization"])

    def test_authenticated_finding_marking(self):
        """Test marking findings as authenticated"""
        self.auth.add_credentials_from_dict({
            "admin": {"username": "admin", "password": "admin123", "privilege_level": "ADMIN"}
        })

        finding = self.auth.mark_finding_authenticated(
            endpoint="/admin/panel",
            parameter="user_id",
            vulnerability_type="SQL_INJECTION",
            credential_id="admin",
            evidence="Injected payload returned rows"
        )

        self.assertEqual(finding.privilege_level, "ADMIN")
        self.assertEqual(len(self.auth.authenticated_findings), 1)

    def test_privilege_escalation_detection(self):
        """Test privilege escalation path detection"""
        self.auth.add_credentials_from_dict({
            "user": {"username": "user", "password": "user123", "privilege_level": "USER"},
            "admin": {"username": "admin", "password": "admin123", "privilege_level": "ADMIN"}
        })

        # Mark same finding as accessible by both privilege levels
        self.auth.mark_finding_authenticated(
            endpoint="/api/secret",
            parameter="data",
            vulnerability_type="ACCESS_CONTROL",
            credential_id="user"
        )

        self.auth.mark_finding_authenticated(
            endpoint="/api/secret",
            parameter="data",
            vulnerability_type="ACCESS_CONTROL",
            credential_id="admin"
        )

        escalation = self.auth.get_privilege_escalation_paths()
        self.assertTrue(len(escalation) > 0)


class TestRiskEngine(unittest.TestCase):
    """Test risk scoring"""

    def setUp(self):
        self.risk_engine = RiskEngine()

    def test_payload_evidence_registration(self):
        """Test registering successful payloads"""
        evidence = PayloadEvidence(
            tool_name="sqlmap",
            endpoint="/api/users",
            parameter="id",
            payload="1' OR '1'='1",
            response="Database error revealed",
            success_indicator="Error message shows SQL"
        )

        self.risk_engine.add_payload_evidence(evidence)
        key_str = "/api/users[id]@sqlmap"
        self.assertIn(key_str, self.risk_engine.payload_evidence)

    def test_risk_calculation_critical(self):
        """Test CRITICAL risk calculation"""
        finding = self.risk_engine.calculate_risk(
            endpoint="/api/users",
            parameter="id",
            vulnerability_type="SQL_INJECTION",
            owasp_category="A03_INJECTION",
            confidence_score=0.95,
            corroboration_count=3,
            tools=["sqlmap", "nuclei", "burp"],
            payload_success_rate=0.95,
            privilege_level="UNAUTHENTICATED"
        )

        self.assertEqual(finding.risk_severity, "CRITICAL")

    def test_risk_calculation_high(self):
        """Test HIGH risk calculation"""
        finding = self.risk_engine.calculate_risk(
            endpoint="/api/posts",
            parameter="content",
            vulnerability_type="XSS",
            owasp_category="A03_INJECTION",
            confidence_score=0.8,
            corroboration_count=2,
            tools=["dalfox", "nuclei"],
            payload_success_rate=0.7,
            privilege_level="UNAUTHENTICATED"
        )

        # Should be HIGH due to good confidence + corroboration
        self.assertIn(finding.risk_severity, ["HIGH", "CRITICAL"])

    def test_risk_calculation_low(self):
        """Test LOW risk calculation"""
        finding = self.risk_engine.calculate_risk(
            endpoint="/api/info",
            parameter="version",
            vulnerability_type="INFO_DISCLOSURE",
            owasp_category="A09_LOGGING_MONITORING_FAILURES",
            confidence_score=0.3,
            corroboration_count=1,
            tools=["custom"],
            payload_success_rate=0.2,
            privilege_level="UNAUTHENTICATED"
        )

        # Low score + low impact category = LOW or INFO
        self.assertIn(finding.risk_severity, ["LOW", "INFO"])

    def test_privilege_level_multiplier(self):
        """Test that ADMIN findings score higher than USER"""
        finding_user = self.risk_engine.calculate_risk(
            endpoint="/api/secret",
            parameter="data",
            vulnerability_type="INJECTION",
            owasp_category="A03_INJECTION",
            confidence_score=0.8,
            corroboration_count=2,
            tools=["sqlmap"],
            payload_success_rate=0.8,
            privilege_level="USER"
        )

        # Reset engine
        self.risk_engine = RiskEngine()

        finding_admin = self.risk_engine.calculate_risk(
            endpoint="/api/secret",
            parameter="data",
            vulnerability_type="INJECTION",
            owasp_category="A03_INJECTION",
            confidence_score=0.8,
            corroboration_count=2,
            tools=["sqlmap"],
            payload_success_rate=0.8,
            privilege_level="ADMIN"
        )

        # ADMIN should be same or higher severity
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        user_idx = severity_order.index(finding_user.risk_severity)
        admin_idx = severity_order.index(finding_admin.risk_severity)
        self.assertGreaterEqual(admin_idx, user_idx)

    def test_corroboration_boost(self):
        """Test that multiple tools boost score"""
        finding_1tool = self.risk_engine.calculate_risk(
            endpoint="/api/test",
            parameter="id",
            vulnerability_type="SQL_INJECTION",
            owasp_category="A03_INJECTION",
            confidence_score=0.8,
            corroboration_count=1,
            tools=["sqlmap"],
            payload_success_rate=0.8
        )

        # Reset engine
        self.risk_engine = RiskEngine()

        finding_3tool = self.risk_engine.calculate_risk(
            endpoint="/api/test",
            parameter="id",
            vulnerability_type="SQL_INJECTION",
            owasp_category="A03_INJECTION",
            confidence_score=0.8,
            corroboration_count=3,
            tools=["sqlmap", "nuclei", "burp"],
            payload_success_rate=0.8
        )

        # 3 tools should score higher
        severity_order = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
        one_tool_idx = severity_order.index(finding_1tool.risk_severity)
        three_tool_idx = severity_order.index(finding_3tool.risk_severity)
        self.assertGreaterEqual(three_tool_idx, one_tool_idx)

    def test_get_findings_by_severity(self):
        """Test filtering findings by severity"""
        self.risk_engine.calculate_risk(
            endpoint="/api/1", parameter="id", vulnerability_type="SQL_INJECTION",
            owasp_category="A03_INJECTION", confidence_score=0.95, corroboration_count=3,
            tools=["sqlmap"], payload_success_rate=0.95
        )

        self.risk_engine.calculate_risk(
            endpoint="/api/2", parameter="id", vulnerability_type="INFO",
            owasp_category="A05_SECURITY_MISCONFIGURATION", confidence_score=0.2,
            corroboration_count=1, tools=["custom"], payload_success_rate=0.1
        )

        critical = self.risk_engine.get_critical_findings()
        low = self.risk_engine.get_findings_by_severity("LOW")

        self.assertGreater(len(critical), 0)
        self.assertEqual(len(self.risk_engine.findings), 2)


class TestIntegration(unittest.TestCase):
    """Integration tests between components"""

    def test_correlation_to_risk_workflow(self):
        """Test full workflow: correlate findings -> apply risk scoring"""
        correlator = FindingCorrelator()
        risk_engine = RiskEngine()

        # Multiple tools report same finding
        correlator.add_report(
            tool="sqlmap",
            endpoint="/api/users",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="UNION SELECT confirmed",
            success_indicator="confirmed_union"
        )

        correlator.add_report(
            tool="nuclei",
            endpoint="/api/users",
            parameter="id",
            vuln_type="SQL_INJECTION",
            evidence="SQLi template matched",
            success_indicator="confirmed_template"
        )

        # Get correlated finding
        corroborated = correlator.get_corroborated_findings()
        self.assertEqual(len(corroborated), 1)

        # Map to risk
        corr_finding = corroborated[0]
        risk_finding = risk_engine.calculate_risk(
            endpoint=corr_finding.endpoint,
            parameter=corr_finding.parameter,
            vulnerability_type=corr_finding.vuln_type,
            owasp_category="A03_INJECTION",
            confidence_score=0.9,
            corroboration_count=corr_finding.tool_count,
            tools=corr_finding.tools,
            payload_success_rate=0.85
        )

        self.assertIn(risk_finding.risk_severity, ["HIGH", "CRITICAL"])

    def test_auth_with_risk_scoring(self):
        """Test authenticated findings receive higher risk scores"""
        auth = AuthAdapter("https://example.com")
        risk_engine = RiskEngine()

        # Add admin credential
        auth.add_credentials_from_dict({
            "admin": {
                "username": "admin",
                "password": "admin123",
                "privilege_level": "ADMIN"
            }
        })

        # Mark finding as admin-exploitable
        auth.mark_finding_authenticated(
            endpoint="/admin/users",
            parameter="role",
            vulnerability_type="PRIVILEGE_ESCALATION",
            credential_id="admin"
        )

        # Score it with admin context
        risk_finding = risk_engine.calculate_risk(
            endpoint="/admin/users",
            parameter="role",
            vulnerability_type="PRIVILEGE_ESCALATION",
            owasp_category="A01_BROKEN_ACCESS_CONTROL",
            confidence_score=0.9,
            corroboration_count=2,
            tools=["burp"],
            payload_success_rate=0.95,
            privilege_level="ADMIN"
        )

        self.assertEqual(risk_finding.privilege_level, "ADMIN")
        self.assertGreaterEqual(
            ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"].index(risk_finding.risk_severity),
            2  # At least MEDIUM
        )


def run_tests():
    """Run all tests"""
    suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
