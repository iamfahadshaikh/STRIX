"""
Auth + IDOR Testing Orchestrator - Integration Example
Purpose: Show how to use AuthEngine, IDOREngine, and AccessControlEngine together
Demonstrates: Full workflow from authentication to vulnerability detection
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional

from auth_utils.param_extractor import ParameterExtractor
from auth_utils.response_analyzer import ResponseAnalyzer
from core.request_engine import RequestEngine
from core.session_manager import AuthType, SessionManager
from findings_model import Finding, FindingsRegistry, Severity
from modules.access_control_engine import AccessControlEngine
from modules.auth_engine import AuthEngine, LoginConfig
from modules.idor_engine import IDOREngine

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


class AuthenticationAndIDOROrchestrator:
    """
    Complete orchestration of authentication + IDOR/access control testing
    """

    def __init__(self, target_url: str, config_path: Optional[str] = None):
        """
        Args:
            target_url: Base URL of target (e.g., https://api.target.com)
            config_path: Path to auth_config.json
        """
        self.target_url = target_url
        self.config = config_path
        self.findings_registry = FindingsRegistry()

        # Initialize components
        self.request_engine = None
        self.auth_engine = None
        self.idor_engine = None
        self.access_control_engine = None

    async def initialize(self) -> bool:
        """Initialize all engines"""
        try:
            logger.info("Initializing authentication and testing engines...")

            # Request engine
            self.request_engine = RequestEngine(timeout=30.0, verify_ssl=False)

            # Auth engine (will inject into request engine)
            self.auth_engine = AuthEngine(self.request_engine)

            # IDOR engine dependencies
            param_extractor = ParameterExtractor()
            response_analyzer = ResponseAnalyzer()

            self.idor_engine = IDOREngine(
                self.request_engine,
                param_extractor,
                response_analyzer,
                self.findings_registry,
            )

            # Access control engine
            self.access_control_engine = AccessControlEngine(
                self.request_engine, response_analyzer, self.findings_registry
            )

            logger.info("Engines initialized successfully")
            return True

        except Exception as e:
            logger.error(f"Initialization failed: {e}")
            return False

    async def load_config(self, config_path: str) -> bool:
        """Load authentication configuration from JSON"""
        try:
            with open(config_path, "r") as f:
                config = json.load(f)

            # Register login flows
            for auth_config in config.get("authentication_engines", []):
                if not auth_config.get("enabled"):
                    continue

                login_config = LoginConfig(
                    role=auth_config["role"],
                    auth_type=AuthType[auth_config["auth_type"].upper()],
                    login_url=self.target_url + auth_config["login_url"],
                    username=auth_config.get("username"),
                    password=auth_config.get("password"),
                    api_key=auth_config.get("api_key"),
                    bearer_token=auth_config.get("bearer_token"),
                    login_data=auth_config.get("login_data", {}),
                    token_field_path=auth_config.get("token_field_path", "token"),
                )

                await self.auth_engine.register_login_flow(login_config)

            logger.info(
                f"Loaded {len(config.get('authentication_engines', []))} auth configs"
            )
            return True

        except Exception as e:
            logger.error(f"Config loading failed: {e}")
            return False

    async def authenticate(self) -> Dict[str, bool]:
        """Authenticate all configured roles"""
        logger.info("Starting authentication...")
        results = await self.auth_engine.authenticate_all_roles()

        for role, success in results.items():
            status = "✓ Success" if success else "✗ Failed"
            logger.info(f"  {role}: {status}")

        return results

    async def test_idor(self, endpoints: List[str], roles: List[str]) -> int:
        """Test endpoints for IDOR vulnerabilities"""
        logger.info(f"Testing IDOR on {len(endpoints)} endpoints...")

        total_findings = 0

        for endpoint in endpoints:
            findings = await self.idor_engine.test_endpoint(
                endpoint, method="GET", roles=roles
            )

            if findings:
                total_findings += len(findings)
                logger.warning(f"  {endpoint}: {len(findings)} IDOR issues found")
            else:
                logger.info(f"  {endpoint}: OK")

        logger.info(f"IDOR testing complete: {total_findings} findings")
        return total_findings

    async def test_access_control(self, endpoints: List[str], roles: List[str]) -> int:
        """Test endpoints for access control issues"""
        logger.info(f"Testing access control on {len(endpoints)} endpoints...")

        total_findings = 0

        for endpoint in endpoints:
            # Test privilege escalation
            findings = await self.access_control_engine.test_privilege_escalation(
                endpoint, low_role=roles[0] if roles else "user", high_role="admin"
            )

            if findings:
                total_findings += len(findings)
                logger.warning(f"  {endpoint}: {len(findings)} access control issues")

            # Test unauthorized access
            unauth_findings = (
                await self.access_control_engine.test_unauthorized_endpoint_access(
                    endpoint
                )
            )
            if unauth_findings:
                total_findings += len(unauth_findings)

        logger.info(f"Access control testing complete: {total_findings} findings")
        return total_findings

    async def generate_report(self, output_file: str) -> bool:
        """Generate comprehensive report"""
        try:
            # Convert IDOR findings
            await self.idor_engine.convert_findings_to_registry()

            # Convert access control findings
            await self.access_control_engine.convert_findings_to_registry()

            # Get all findings
            all_findings = list(self.findings_registry._findings)

            # Group by severity
            by_severity = {}
            for finding in all_findings:
                sev = finding.severity.value
                if sev not in by_severity:
                    by_severity[sev] = []
                by_severity[sev].append(finding)

            # Create report structure
            report = {
                "summary": {
                    "total_findings": len(all_findings),
                    "by_severity": {
                        sev: len(findings) for sev, findings in by_severity.items()
                    },
                },
                "idor_findings": [
                    {
                        "endpoint": f.location,
                        "type": f.type.value,
                        "severity": f.severity.value,
                        "cwe": f.cwe,
                        "evidence": f.evidence,
                    }
                    for f in all_findings
                    if f.type.value == "IDOR"
                ],
                "access_control_findings": [
                    {
                        "endpoint": f.location,
                        "type": f.type.value,
                        "severity": f.severity.value,
                        "evidence": f.evidence,
                    }
                    for f in all_findings
                    if f.type.value == "Authentication Bypass"
                ],
                "statistics": {
                    "idor": self.idor_engine.get_statistics(),
                },
            }

            with open(output_file, "w") as f:
                json.dump(report, f, indent=2)

            logger.info(f"Report written to {output_file}")
            return True

        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return False

    async def run_full_assessment(
        self, config_path: str, endpoints: List[str], roles: List[str], output_file: str
    ) -> bool:
        """Run complete authentication + IDOR/access control assessment"""
        try:
            # Initialize
            if not await self.initialize():
                return False

            # Load config
            if not await self.load_config(config_path):
                return False

            # Authenticate
            auth_results = await self.authenticate()
            if not any(auth_results.values()):
                logger.error("Authentication failed for all roles")
                return False

            # Test IDOR
            idor_count = await self.test_idor(endpoints, roles)

            # Test access control
            ac_count = await self.test_access_control(endpoints, roles)

            # Generate report
            await self.generate_report(output_file)

            logger.info(
                f"\n{'='*60}\n"
                f"Assessment Complete\n"
                f"IDOR findings: {idor_count}\n"
                f"Access control findings: {ac_count}\n"
                f"Report: {output_file}\n"
                f"{'='*60}"
            )

            return True

        except Exception as e:
            logger.error(f"Assessment failed: {e}")
            return False


# Example usage
async def main():
    """Example: Running authentication + IDOR testing"""

    orchestrator = AuthenticationAndIDOROrchestrator(
        target_url="https://api.target.com"
    )

    # Endpoints to test
    test_endpoints = [
        "https://api.target.com/api/users/123",
        "https://api.target.com/api/accounts/456",
        "https://api.target.com/api/orders/789",
    ]

    # Roles to test
    test_roles = ["user", "admin"]

    # Run assessment
    success = await orchestrator.run_full_assessment(
        config_path="config/auth_config.json",
        endpoints=test_endpoints,
        roles=test_roles,
        output_file="auth_idor_assessment_report.json",
    )

    if success:
        logger.info("Assessment completed successfully")

        # Print summary
        status = await orchestrator.auth_engine.check_session_status()
        logger.info(f"Active sessions: {list(status.keys())}")
    else:
        logger.error("Assessment failed")


if __name__ == "__main__":
    asyncio.run(main())
