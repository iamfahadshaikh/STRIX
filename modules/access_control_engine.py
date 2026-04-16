"""
Access Control Engine - Privilege Escalation and Unauthorized Access Testing
Purpose: Test for vertical privilege escalation, forced browsing, and method tampering
Detects: Unauthorized endpoint access, privilege escalation, horizontal escalation
"""

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from auth_utils.response_analyzer import ResponseAnalyzer, SensitivityLevel
from core.request_engine import HTTPResponse, RequestEngine
from findings_model import Finding, FindingsRegistry, FindingType, Severity

logger = logging.getLogger(__name__)


class AccessControlViolationType(Enum):
    """Types of access control violations"""

    UNAUTHORIZED_ENDPOINT = (
        "unauthorized_endpoint"  # Not authenticated user accessing admin endpoint
    )
    PRIVILEGE_ESCALATION = "privilege_escalation"  # User accessing admin features
    METHOD_OVERRIDE = "method_override"  # POST returned 405, but GET worked
    ROLE_BYPASS = "role_bypass"  # User accessing admin by changing role header


@dataclass
class AccessControlFinding:
    """Access control vulnerability finding"""

    violation_type: AccessControlViolationType
    endpoint: str
    method: str
    low_role: str  # e.g., "user"
    high_role: str  # e.g., "admin"
    response_status: int
    evidence: str
    severity: Severity = Severity.HIGH
    exposed_data: Optional[str] = None

    def to_finding(self) -> Finding:
        """Convert to Finding for reporting"""

        messages = {
            AccessControlViolationType.UNAUTHORIZED_ENDPOINT: (
                f"Unauthenticated users can access admin endpoint {self.endpoint}"
            ),
            AccessControlViolationType.PRIVILEGE_ESCALATION: (
                f"Users with {self.low_role} role can access {self.high_role}-only endpoint {self.endpoint}"
            ),
            AccessControlViolationType.METHOD_OVERRIDE: (
                f"Method override possible on {self.endpoint} - {self.method} allowed when other methods denied"
            ),
            AccessControlViolationType.ROLE_BYPASS: (
                f"Role bypass in {self.endpoint} - role header manipulation allows privilege escalation"
            ),
        }

        return Finding(
            type=FindingType.AUTH_BYPASS,
            severity=self.severity,
            location=self.endpoint,
            description=messages.get(self.violation_type, "Access control violation"),
            cwe=(
                "CWE-434"
                if self.violation_type
                == AccessControlViolationType.UNAUTHORIZED_ENDPOINT
                else "CWE-639"
            ),
            owasp="A01:2021",
            evidence=self.evidence,
            remediation=(
                f"Implement proper access control checks. Verify user authentication "
                f"and authorization for {self.endpoint} before returning sensitive data."
            ),
            impact=(
                f"Attackers can access restricted functionality and data intended only "
                f"for {self.high_role} users."
            ),
            exploitability="High" if self.severity == Severity.HIGH else "Medium",
        )


class AccessControlEngine:
    """
    Test for access control vulnerabilities

    Tests:
    1. Unauthorized endpoint access (unauthenticated)
    2. Privilege escalation (low role → high role)
    3. Method tampering (GET when POST blocked)
    4. Role header manipulation
    """

    # Common admin endpoints to test
    ADMIN_ENDPOINTS = [
        "/admin",
        "/admin/users",
        "/admin/dashboard",
        "/admin/settings",
        "/api/admin",
        "/api/admin/users",
        "/api/management",
        "/internal",
        "/internal/api",
        "/api/internal",
    ]

    # HTTP methods to test
    METHODS_TO_TEST = ["GET", "POST", "PUT", "DELETE", "PATCH"]

    # Role headers to test
    ROLE_HEADERS = [
        "X-Role",
        "X-User-Role",
        "Role",
        "User-Role",
        "X-Access",
        "is_admin",
    ]

    def __init__(
        self,
        request_engine: RequestEngine,
        response_analyzer: ResponseAnalyzer,
        findings_registry: Optional[FindingsRegistry] = None,
    ):
        """
        Args:
            request_engine: HTTP request engine
            response_analyzer: Response analysis engine
            findings_registry: Optional findings registry
        """
        self.request_engine = request_engine
        self.response_analyzer = response_analyzer
        self.findings_registry = findings_registry or FindingsRegistry()
        self.findings_discovered: List[AccessControlFinding] = []
        self.endpoints_tested: Set[str] = set()

    async def test_privilege_escalation(
        self, endpoint: str, low_role: str = "user", high_role: str = "admin"
    ) -> List[AccessControlFinding]:
        """
        Test if low-privilege users can access high-privilege endpoints

        Args:
            endpoint: Endpoint to test
            low_role: Low privilege role (e.g., "user")
            high_role: High privilege role (e.g., "admin")

        Returns:
            List of findings
        """
        findings = []
        logger.info(
            f"Testing privilege escalation: {low_role} → {high_role} on {endpoint}"
        )

        # Get baseline response as high-privilege role
        try:
            high_resp = await self.request_engine.get(endpoint, role=high_role)
        except Exception as e:
            logger.warning(f"Could not get baseline as {high_role}: {e}")
            return findings

        # Try to access as low-privilege role
        try:
            low_resp = await self.request_engine.get(endpoint, role=low_role)
        except Exception as e:
            logger.debug(f"Access denied for {low_role}: {e}")
            return findings  # Expected behavior

        # Analyze if privilege escalation occurred
        if 200 <= low_resp.status_code < 300:
            # Successfully accessed with low privilege
            analysis = self.response_analyzer.analyze(
                low_resp.status_code, low_resp.body, low_resp.headers
            )

            if analysis.has_sensitive_data:
                finding = AccessControlFinding(
                    violation_type=AccessControlViolationType.PRIVILEGE_ESCALATION,
                    endpoint=endpoint,
                    method="GET",
                    low_role=low_role,
                    high_role=high_role,
                    response_status=low_resp.status_code,
                    evidence=f"User with {low_role} role accessed {high_role}-only endpoint",
                    exposed_data=str(analysis.exposed_pii_fields),
                )
                findings.append(finding)
                logger.warning(f"PRIVILEGE ESCALATION: {endpoint}")

        return findings

    async def test_unauthorized_endpoint_access(
        self, endpoint: str, required_role: str = "admin"
    ) -> List[AccessControlFinding]:
        """
        Test if unauthenticated users can access protected endpoints

        Args:
            endpoint: Protected endpoint
            required_role: Required role (used for baseline)

        Returns:
            List of findings
        """
        findings = []
        logger.info(f"Testing unauthorized access to {endpoint}")

        # Try without authentication (no role specified)
        try:
            resp = await self.request_engine.get(endpoint)
        except Exception as e:
            logger.debug(f"Unauthenticated request failed: {e}")
            return findings

        # Check if unauth access granted
        if 200 <= resp.status_code < 300:
            analysis = self.response_analyzer.analyze(
                resp.status_code, resp.body, resp.headers
            )

            if analysis.has_sensitive_data or resp.content_length > 100:
                finding = AccessControlFinding(
                    violation_type=AccessControlViolationType.UNAUTHORIZED_ENDPOINT,
                    endpoint=endpoint,
                    method="GET",
                    low_role="unauthenticated",
                    high_role=required_role,
                    response_status=resp.status_code,
                    evidence=f"Unauthenticated access to {required_role}-only endpoint returned sensitive data",
                    severity=Severity.CRITICAL,
                    exposed_data=str(analysis.exposed_pii_fields),
                )
                findings.append(finding)
                logger.error(f"CRITICAL: Unauthenticated access to {endpoint}")

        return findings

    async def test_method_tampering(
        self, endpoint: str, role: str = "user"
    ) -> List[AccessControlFinding]:
        """
        Test method tampering (GET when POST denied, etc)

        Args:
            endpoint: Endpoint to test
            role: Role to test with

        Returns:
            List of findings
        """
        findings = []
        logger.info(f"Testing method tampering on {endpoint}")

        results = {}

        # Test different methods
        for method in self.METHODS_TO_TEST:
            try:
                if method == "GET":
                    resp = await self.request_engine.get(endpoint, role=role)
                elif method == "POST":
                    resp = await self.request_engine.post(endpoint, role=role)
                elif method == "PUT":
                    resp = await self.request_engine.put(endpoint, role=role)
                elif method == "DELETE":
                    resp = await self.request_engine.delete(endpoint, role=role)
                else:
                    continue

                results[method] = resp.status_code

            except Exception as e:
                logger.debug(f"Method {method} failed: {e}")
                results[method] = None

        # Analyze for inconsistency
        successful_methods = [
            m for m, status in results.items() if status and 200 <= status < 300
        ]
        failed_methods = [
            m for m, status in results.items() if status and status >= 400
        ]

        # If some methods work and others don't, might be tampering
        if successful_methods and failed_methods:
            finding = AccessControlFinding(
                violation_type=AccessControlViolationType.METHOD_OVERRIDE,
                endpoint=endpoint,
                method=",".join(successful_methods),
                low_role=role,
                high_role=role,
                response_status=results.get(successful_methods[0], 0),
                evidence=f"Methods {successful_methods} allowed, but {failed_methods} were denied",
                severity=Severity.MEDIUM,
            )
            findings.append(finding)

        return findings

    async def test_role_header_bypass(
        self, endpoint: str, low_role: str = "user", high_role: str = "admin"
    ) -> List[AccessControlFinding]:
        """
        Test if role headers can be manipulated for privilege escalation

        Args:
            endpoint: Endpoint to test
            low_role: Low privilege role
            high_role: High privilege role

        Returns:
            List of findings
        """
        findings = []
        logger.info(f"Testing role header bypass on {endpoint}")

        # Test each role header variant
        for role_header in self.ROLE_HEADERS:
            try:
                headers = {
                    role_header: high_role,
                    "X-Forwarded-User": high_role,
                }

                resp = await self.request_engine.get(
                    endpoint, role=low_role, headers=headers
                )

                if 200 <= resp.status_code < 300:
                    analysis = self.response_analyzer.analyze(
                        resp.status_code, resp.body, resp.headers
                    )

                    if analysis.has_sensitive_data:
                        finding = AccessControlFinding(
                            violation_type=AccessControlViolationType.ROLE_BYPASS,
                            endpoint=endpoint,
                            method="GET",
                            low_role=low_role,
                            high_role=high_role,
                            response_status=resp.status_code,
                            evidence=f"Setting {role_header}={high_role} bypassed access control",
                            severity=Severity.CRITICAL,
                            exposed_data=str(analysis.exposed_pii_fields),
                        )
                        findings.append(finding)
                        logger.error(f"CRITICAL: Role header bypass via {role_header}")

            except Exception as e:
                logger.debug(f"Role header test failed: {e}")

        return findings

    async def test_common_admin_endpoints(
        self, roles: List[str]
    ) -> List[AccessControlFinding]:
        """
        Test common admin endpoints for unauthorized access

        Args:
            roles: List of roles to test

        Returns:
            List of findings
        """
        findings = []

        for endpoint in self.ADMIN_ENDPOINTS:
            for role in roles:
                try:
                    resp = await self.request_engine.get(endpoint, role=role)

                    if 200 <= resp.status_code < 300 and role != "admin":
                        finding = AccessControlFinding(
                            violation_type=AccessControlViolationType.PRIVILEGE_ESCALATION,
                            endpoint=endpoint,
                            method="GET",
                            low_role=role,
                            high_role="admin",
                            response_status=resp.status_code,
                            evidence=f"{role} role accessed admin-only endpoint",
                        )
                        findings.append(finding)

                except Exception as e:
                    logger.debug(f"Admin endpoint test failed: {e}")

        return findings

    def get_findings(self) -> List[AccessControlFinding]:
        """Get all access control findings"""
        return self.findings_discovered

    async def convert_findings_to_registry(self) -> FindingsRegistry:
        """Convert findings to Finding objects"""
        for ac_finding in self.findings_discovered:
            finding = ac_finding.to_finding()
            self.findings_registry.add(finding)

        return self.findings_registry
