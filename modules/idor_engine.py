"""
IDOR Engine - Insecure Direct Object Reference Detection
Purpose: Automated IDOR vulnerability detection through parameter mutation and baseline comparison
Strategies: Numeric increment, UUID substitution, role-based comparison, response diffing
"""

import asyncio
import logging
import random
import string
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

from auth_utils.param_extractor import Parameter, ParameterExtractor, ParameterType
from auth_utils.response_analyzer import (
    ResponseAnalysisResult,
    ResponseAnalyzer,
    SensitivityLevel,
)
from core.request_engine import HTTPResponse, RequestEngine, RequestMethod
from findings_model import Finding, FindingsRegistry, FindingType, Severity

logger = logging.getLogger(__name__)


class MutationStrategy(Enum):
    """Parameter mutation strategies"""

    INCREMENT = "increment"  # 123 -> 124
    DECREMENT = "decrement"  # 123 -> 122
    RANDOM_ID = "random_id"  # 123 -> random_numeric
    KNOWN_IDS = "known_ids"  # 123 -> other_seen_ids
    ZERO = "zero"  # 123 -> 0
    NEGATIVE = "negative"  # 123 -> -1


@dataclass
class MutationResult:
    """Result of parameter mutation"""

    original_value: str
    mutated_value: str
    mutation_strategy: MutationStrategy
    endpoint: str
    parameter_name: str
    role_tested: str
    response: HTTPResponse


@dataclass
class IDORFinding:
    """IDOR vulnerability finding"""

    endpoint: str
    parameter: str
    parameter_type: str
    original_id: str
    mutated_id: str
    mutation_strategy: str
    user_role: str
    evidence: str  # What sensitive data was exposed
    exposed_fields: List[str] = field(default_factory=list)
    confidence: float = 0.8
    severity: Severity = Severity.HIGH
    is_confirmed: bool = False  # Requires manual verification or reliable proof
    affected_data_sensitivity: Optional[str] = None

    def to_finding(self) -> Finding:
        """Convert to Finding object for reporting"""
        return Finding(
            type=FindingType.IDOR,
            severity=self.severity,
            location=self.endpoint,
            description=(
                f"IDOR in {self.parameter} parameter. "
                f"User with {self.user_role} role can access other users' data "
                f"by mutating {self.parameter}."
            ),
            cwe="CWE-639",  # Insecure Direct Object References
            owasp="A01:2021",
            evidence=self.evidence,
            remediation=(
                f"Implement access control checks before returning {self.parameter} data. "
                f"Verify that the requesting user has permission to access the requested resource."
            ),
            impact=(
                f"An attacker can access and potentially modify data belonging to other users "
                f"by changing the {self.parameter} parameter. "
                f"Sensitive fields exposed: {', '.join(self.exposed_fields)}"
            ),
            exploitability="High - simple parameter mutation required",
        )


class IDOREngine:
    """
    Detect IDOR vulnerabilities through systematic testing

    Workflow:
    1. Extract parameters from endpoints
    2. For each parameter, build mutation payloads
    3. Request as different roles (user, admin)
    4. Compare responses for unauthorized data access
    5. Generate findings with proof
    """

    def __init__(
        self,
        request_engine: RequestEngine,
        param_extractor: ParameterExtractor,
        response_analyzer: ResponseAnalyzer,
        findings_registry: Optional[FindingsRegistry] = None,
    ):
        """
        Args:
            request_engine: HTTPRequestEngine for authenticated requests
            param_extractor: Parameter extraction engine
            response_analyzer: Response sensitivity analysis
            findings_registry: Optional existing findings registry
        """
        self.request_engine = request_engine
        self.param_extractor = param_extractor
        self.response_analyzer = response_analyzer
        self.findings_registry = findings_registry or FindingsRegistry()
        self.seen_ids: Dict[str, Set[str]] = {}  # param_name -> set of values seen
        self.baseline_responses: Dict[str, HTTPResponse] = {}  # for comparison
        self.mutations_tested = 0
        self.findings_discovered: List[IDORFinding] = []

    async def test_endpoint(
        self,
        endpoint: str,
        method: str = "GET",
        roles: Optional[List[str]] = None,
        parameter_names: Optional[List[str]] = None,
    ) -> List[IDORFinding]:
        """
        Test endpoint for IDOR vulnerabilities

        Args:
            endpoint: URL to test (e.g., "/api/users/123")
            method: HTTP method (GET, POST, etc)
            roles: Roles to test (default: ["user", "admin"])
            parameter_names: Specific parameters to mutate (auto-extract if None)

        Returns:
            List of IDOR findings
        """
        if not roles:
            roles = ["user", "admin"]

        logger.info(f"Testing {endpoint} for IDOR with roles: {roles}")
        findings = []

        # Extract parameters if not specified
        params_to_test = parameter_names or await self._extract_params_from_endpoint(
            endpoint
        )

        if not params_to_test:
            logger.warning(f"No testable parameters found in {endpoint}")
            return findings

        # For each parameter
        for param in params_to_test:
            if not param.is_likely_id():
                continue

            # Get baseline response (user role)
            baseline_resp = await self._get_baseline_response(
                endpoint, method, param, roles[0]
            )

            if not baseline_resp:
                logger.warning(f"Could not get baseline for {endpoint}")
                continue

            # Test mutations with each role
            for role in roles:
                mutations = self._generate_mutations(param, endpoint)

                for mutation in mutations:
                    try:
                        # Make request with mutated parameter
                        mutated_resp = await self._make_mutated_request(
                            endpoint, method, param, mutation, role
                        )

                        if not mutated_resp:
                            continue

                        # Analyze for IDOR
                        idor_finding = await self._analyze_for_idor(
                            endpoint, param, mutation, baseline_resp, mutated_resp, role
                        )

                        if idor_finding:
                            findings.append(idor_finding)

                        self.mutations_tested += 1

                    except Exception as e:
                        logger.warning(f"Error testing mutation: {e}")

        # Store findings
        self.findings_discovered.extend(findings)

        return findings

    async def _extract_params_from_endpoint(self, endpoint: str) -> List[Parameter]:
        """Extract parameters from endpoint URL"""
        params = self.param_extractor.extract_from_url(endpoint, endpoint)
        logger.debug(f"Extracted {len(params)} parameters from {endpoint}")
        return params

    async def _get_baseline_response(
        self, endpoint: str, method: str, param: Parameter, role: str
    ) -> Optional[HTTPResponse]:
        """Get baseline response before mutation"""
        try:
            if method.upper() == "GET":
                resp = await self.request_engine.get(endpoint, role=role)
            else:
                resp = await self.request_engine.request(method, endpoint, role=role)

            # Store baseline
            self.baseline_responses[endpoint] = resp

            # Record IDs seen
            if param.name not in self.seen_ids:
                self.seen_ids[param.name] = set()
            self.seen_ids[param.name].add(param.example_value)

            return resp

        except Exception as e:
            logger.error(f"Error getting baseline: {e}")
            return None

    def _generate_mutations(
        self, param: Parameter, endpoint: str
    ) -> List[MutationStrategy]:
        """Generate mutation strategies for parameter"""
        mutations = []

        # Based on parameter type
        if param.param_type == ParameterType.NUMERIC_ID:
            mutations = [
                MutationStrategy.INCREMENT,
                MutationStrategy.DECREMENT,
                MutationStrategy.ZERO,
                MutationStrategy.NEGATIVE,
                MutationStrategy.RANDOM_ID,
            ]

        elif param.param_type == ParameterType.UUID:
            mutations = [MutationStrategy.RANDOM_ID, MutationStrategy.ZERO]

        elif param.param_type == ParameterType.ALPHANUMERIC_ID:
            mutations = [
                MutationStrategy.RANDOM_ID,
                (
                    MutationStrategy.KNOWN_IDS
                    if param.name in self.seen_ids
                    else MutationStrategy.RANDOM_ID
                ),
            ]

        return mutations

    def _mutate_value(self, original: str, strategy: MutationStrategy) -> str:
        """Apply mutation strategy to value"""
        try:
            if strategy == MutationStrategy.INCREMENT:
                if original.isdigit():
                    return str(int(original) + 1)

            elif strategy == MutationStrategy.DECREMENT:
                if original.isdigit() and int(original) > 0:
                    return str(int(original) - 1)

            elif strategy == MutationStrategy.ZERO:
                return "0"

            elif strategy == MutationStrategy.NEGATIVE:
                return "-1"

            elif strategy == MutationStrategy.RANDOM_ID:
                # Generate random ID similar to original
                if original.isdigit():
                    return str(random.randint(1000, 9999))
                else:
                    # Random alphanumeric
                    return "".join(
                        random.choices(string.ascii_letters + string.digits, k=8)
                    )

            elif strategy == MutationStrategy.KNOWN_IDS:
                # Try previously seen IDs
                param_name = None
                for name, values in self.seen_ids.items():
                    if original in values:
                        param_name = name
                        break

                if param_name and self.seen_ids[param_name]:
                    other_ids = self.seen_ids[param_name] - {original}
                    if other_ids:
                        return list(other_ids)[0]

        except Exception as e:
            logger.debug(f"Mutation error: {e}")

        return original

    async def _make_mutated_request(
        self,
        endpoint: str,
        method: str,
        param: Parameter,
        mutation_strategy: MutationStrategy,
        role: str,
    ) -> Optional[HTTPResponse]:
        """Make request with mutated parameter"""
        try:
            mutated_value = self._mutate_value(param.example_value, mutation_strategy)

            # Replace parameter in URL
            mutated_endpoint = endpoint.replace(
                f"{param.name}={param.example_value}", f"{param.name}={mutated_value}"
            )

            if method.upper() == "GET":
                return await self.request_engine.get(mutated_endpoint, role=role)
            else:
                return await self.request_engine.request(
                    method, mutated_endpoint, role=role
                )

        except Exception as e:
            logger.debug(f"Error making mutated request: {e}")
            return None

    async def _analyze_for_idor(
        self,
        endpoint: str,
        param: Parameter,
        mutation_strategy: MutationStrategy,
        baseline_resp: HTTPResponse,
        mutated_resp: HTTPResponse,
        role: str,
    ) -> Optional[IDORFinding]:
        """
        Analyze responses for IDOR vulnerability

        Requires proof of:
        1. Status indicated access granted (200-399)
        2. Unauthorized data returned
        3. Sensitive field exposure
        """

        # Check if response indicates success
        if mutated_resp.status_code >= 400:
            return None  # Access denied, no IDOR

        # Analyze sensitivity of mutated response
        analysis = self.response_analyzer.analyze(
            mutated_resp.status_code, mutated_resp.body, mutated_resp.headers
        )

        # Compare with baseline
        baseline_analysis = self.response_analyzer.analyze(
            baseline_resp.status_code, baseline_resp.body, baseline_resp.headers
        )

        comparison = self.response_analyzer.compare_responses(
            baseline_analysis, analysis
        )

        # Strict IDOR detection: requires new sensitive data exposure
        if comparison["new_sensitive_data"] == 0:
            return None  # No new sensitive data exposed

        if (
            comparison["new_critical_data"] == 0
            and analysis.max_sensitivity != SensitivityLevel.HIGH
        ):
            return None  # Low sensitivity, not exploit-worthy

        # Build evidence
        evidence_lines = [
            f"Mutated {param.name} from {param.example_value} to {self._mutate_value(param.example_value, mutation_strategy)}",
            f"Response status: {mutated_resp.status_code}",
            f"New sensitive fields exposed: {comparison['new_sensitive_fields']}",
            f"Critical data exposed: {comparison['new_critical_data']} fields",
            f"Risk increase: {comparison['risk_increase']:.2f}",
        ]

        evidence = "\n".join(evidence_lines)

        # Create finding
        finding = IDORFinding(
            endpoint=endpoint,
            parameter=param.name,
            parameter_type=param.param_type.value,
            original_id=param.example_value,
            mutated_id=self._mutate_value(param.example_value, mutation_strategy),
            mutation_strategy=mutation_strategy.value,
            user_role=role,
            evidence=evidence,
            exposed_fields=comparison["new_sensitive_fields"],
            affected_data_sensitivity=(
                analysis.max_sensitivity.value if analysis.max_sensitivity else None
            ),
            is_confirmed=True,
        )

        logger.warning(f"IDOR FOUND: {endpoint} - {param.name} parameter - Role {role}")

        return finding

    def get_findings(self) -> List[IDORFinding]:
        """Get all discovered IDOR findings"""
        return self.findings_discovered

    async def convert_findings_to_registry(self) -> FindingsRegistry:
        """Convert IDOR findings to Finding objects for reporting"""
        for idor_finding in self.findings_discovered:
            finding = idor_finding.to_finding()
            self.findings_registry.add(finding)

        return self.findings_registry

    def get_statistics(self) -> Dict:
        """Get testing statistics"""
        return {
            "mutations_tested": self.mutations_tested,
            "idor_found": len(self.findings_discovered),
            "confirmed_idor": len(
                [f for f in self.findings_discovered if f.is_confirmed]
            ),
            "by_severity": {
                "CRITICAL": len(
                    [
                        f
                        for f in self.findings_discovered
                        if f.severity == Severity.CRITICAL
                    ]
                ),
                "HIGH": len(
                    [f for f in self.findings_discovered if f.severity == Severity.HIGH]
                ),
                "MEDIUM": len(
                    [
                        f
                        for f in self.findings_discovered
                        if f.severity == Severity.MEDIUM
                    ]
                ),
            },
        }
