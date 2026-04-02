"""
Response Analyzer - Detect sensitive data in responses
Purpose: Identify PII, tokens, and confidential information in HTTP responses
Used by IDOR engine for baseline comparison and vulnerability detection
"""

import difflib
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class SensitivityLevel(Enum):
    """Data sensitivity classification"""

    CRITICAL = "CRITICAL"  # Passwords, tokens, keys
    HIGH = "HIGH"  # Email, phone, SSN, financial
    MEDIUM = "MEDIUM"  # Names, addresses, DOB
    LOW = "LOW"  # Public profile data
    HARMLESS = "HARMLESS"  # No sensitive data


@dataclass
class SensitiveDataPattern:
    """Pattern for detecting sensitive data"""

    name: str
    pattern: str  # Regex pattern
    sensitivity: SensitivityLevel
    description: str = ""


@dataclass
class SensitiveDataMatch:
    """Match of sensitivity data in response"""

    field_name: str
    field_value: str
    pattern_name: str
    sensitivity: SensitivityLevel
    context: str = ""  # Surrounding context


@dataclass
class ResponseAnalysisResult:
    """Result of analyzing a response"""

    status_code: int
    content_length: int
    is_json: bool = False
    is_html: bool = False
    json_structure: Optional[Dict] = None
    sensitive_matches: List[SensitiveDataMatch] = field(default_factory=list)
    max_sensitivity: Optional[SensitivityLevel] = None
    exposed_pii_fields: Set[str] = field(default_factory=set)
    exposed_secret_fields: Set[str] = field(default_factory=set)
    analysis_notes: List[str] = field(default_factory=list)

    @property
    def has_sensitive_data(self) -> bool:
        """Check if sensitive data detected"""
        return len(self.sensitive_matches) > 0

    @property
    def risk_score(self) -> float:
        """Risk score 0.0-1.0 based on exposed data"""
        if not self.has_sensitive_data:
            return 0.0

        # Weight by sensitivity level
        weights = {
            SensitivityLevel.CRITICAL: 1.0,
            SensitivityLevel.HIGH: 0.8,
            SensitivityLevel.MEDIUM: 0.5,
            SensitivityLevel.LOW: 0.2,
        }

        max_weight = max(weights.get(m.sensitivity, 0) for m in self.sensitive_matches)
        return max_weight


class ResponseAnalyzer:
    """
    Analyze HTTP responses for sensitive data exposure

    Detects:
    - PII (email, phone, SSN)
    - Credentials (passwords, tokens, API keys)
    - Financial data
    - Internal identifiers
    """

    # Sensitive field name patterns
    SENSITIVE_FIELD_NAMES = {
        # Passwords/tokens
        "password": SensitivityLevel.CRITICAL,
        "passwd": SensitivityLevel.CRITICAL,
        "pwd": SensitivityLevel.CRITICAL,
        "token": SensitivityLevel.CRITICAL,
        "access_token": SensitivityLevel.CRITICAL,
        "refresh_token": SensitivityLevel.CRITICAL,
        "api_key": SensitivityLevel.CRITICAL,
        "apikey": SensitivityLevel.CRITICAL,
        "secret": SensitivityLevel.CRITICAL,
        "private_key": SensitivityLevel.CRITICAL,
        "auth": SensitivityLevel.CRITICAL,
        "bearer": SensitivityLevel.CRITICAL,
        # PII
        "email": SensitivityLevel.HIGH,
        "phone": SensitivityLevel.HIGH,
        "phone_number": SensitivityLevel.HIGH,
        "ssn": SensitivityLevel.HIGH,
        "social_security": SensitivityLevel.HIGH,
        "credit_card": SensitivityLevel.HIGH,
        "card_number": SensitivityLevel.HIGH,
        # Identifiers
        "user_id": SensitivityLevel.LOW,
        "userid": SensitivityLevel.LOW,
        "id": SensitivityLevel.LOW,
        "account_id": SensitivityLevel.LOW,
    }

    # Pattern definitions
    PATTERNS = [
        # Email
        SensitiveDataPattern(
            "email", r"[\w\.-]+@[\w\.-]+\.\w+", SensitivityLevel.HIGH, "Email address"
        ),
        # Phone
        SensitiveDataPattern(
            "phone",
            r"\b(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            SensitivityLevel.HIGH,
            "Phone number",
        ),
        # SSN
        SensitiveDataPattern(
            "ssn",
            r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4}\b",
            SensitivityLevel.HIGH,
            "Social Security Number",
        ),
        # Credit card
        SensitiveDataPattern(
            "credit_card",
            r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
            SensitivityLevel.CRITICAL,
            "Credit card number",
        ),
        # API Key
        SensitiveDataPattern(
            "api_key",
            r"(?:api[_-]?key|apikey)['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9\-._~+/]+=*)['\"]?",
            SensitivityLevel.CRITICAL,
            "API Key",
        ),
        # Bearer token
        SensitiveDataPattern(
            "bearer_token",
            r"Bearer\s+([A-Za-z0-9\-._~+/]+=*)",
            SensitivityLevel.CRITICAL,
            "Bearer token",
        ),
        # Password in plaintext
        SensitiveDataPattern(
            "password",
            r"(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]+)['\"]",
            SensitivityLevel.CRITICAL,
            "Password",
        ),
    ]

    def __init__(self):
        self.patterns = self.PATTERNS

    def analyze(
        self, status_code: int, body: str, headers: Optional[Dict[str, str]] = None
    ) -> ResponseAnalysisResult:
        """
        Analyze response for sensitive data

        Args:
            status_code: HTTP status code
            body: Response body
            headers: Response headers

        Returns:
            ResponseAnalysisResult with findings
        """
        result = ResponseAnalysisResult(
            status_code=status_code, content_length=len(body)
        )

        # Detect content type
        if headers:
            content_type = headers.get("Content-Type", "").lower()
            result.is_json = "application/json" in content_type
            result.is_html = "text/html" in content_type

        # Try JSON parsing
        if result.is_json:
            try:
                result.json_structure = json.loads(body)
            except json.JSONDecodeError:
                result.analysis_notes.append(
                    "Content-Type claims JSON but body not valid JSON"
                )

        # Search for sensitive data
        self._find_sensitive_data(body, result)

        # Determine max sensitivity level
        if result.sensitive_matches:
            sensitivities = [m.sensitivity for m in result.sensitive_matches]
            result.max_sensitivity = max(
                sensitivities,
                key=lambda s: (
                    SensitivityLevel.CRITICAL,
                    SensitivityLevel.HIGH,
                    SensitivityLevel.MEDIUM,
                    SensitivityLevel.LOW,
                    SensitivityLevel.HARMLESS,
                ).index(s),
            )

        return result

    def _find_sensitive_data(self, body: str, result: ResponseAnalysisResult):
        """Find sensitive data in response body"""
        finding_ids = set()

        # Search by regex patterns
        for pattern in self.patterns:
            matches = re.finditer(pattern.pattern, body, re.IGNORECASE)
            for match in matches:
                match_id = (pattern.name, match.group(0)[:50])  # Deduplicate
                if match_id in finding_ids:
                    continue
                finding_ids.add(match_id)

                # Get context around match
                start = max(0, match.start() - 50)
                end = min(len(body), match.end() + 50)
                context = body[start:end].replace("\n", " ")

                sensitive_match = SensitiveDataMatch(
                    field_name=pattern.name,
                    field_value=match.group(0)[:100],  # Truncate
                    pattern_name=pattern.name,
                    sensitivity=pattern.sensitivity,
                    context=context,
                )

                result.sensitive_matches.append(sensitive_match)

        # Search by field names (if JSON)
        if result.json_structure and isinstance(result.json_structure, dict):
            self._analyze_json_fields(result.json_structure, result)

    def _analyze_json_fields(
        self, obj: Dict, result: ResponseAnalysisResult, prefix: str = ""
    ):
        """Recursively analyze JSON object for sensitive fields"""
        for key, value in obj.items():
            full_key = f"{prefix}.{key}" if prefix else key

            # Check field name against sensitive list
            key_lower = key.lower()
            for pattern_key, sensitivity in self.SENSITIVE_FIELD_NAMES.items():
                if pattern_key in key_lower:
                    value_str = str(value)[:100]

                    match = SensitiveDataMatch(
                        field_name=full_key,
                        field_value=value_str,
                        pattern_name=pattern_key,
                        sensitivity=sensitivity,
                    )
                    result.sensitive_matches.append(match)

                    if sensitivity == SensitivityLevel.CRITICAL:
                        result.exposed_secret_fields.add(full_key)
                    elif sensitivity == SensitivityLevel.HIGH:
                        result.exposed_pii_fields.add(full_key)
                    break

            # Recurse into nested objects
            if isinstance(value, dict):
                self._analyze_json_fields(value, result, full_key)

    def compare_responses(
        self, resp1: ResponseAnalysisResult, resp2: ResponseAnalysisResult
    ) -> Dict:
        """
        Compare two analyzed responses

        Returns:
            Dict with comparison metrics
        """
        # Data exposure comparison
        new_sensitive = []
        for match in resp2.sensitive_matches:
            if match not in resp1.sensitive_matches:
                new_sensitive.append(match)

        # Structure comparison
        structure_changed = False
        if resp1.json_structure and resp2.json_structure:
            structure_changed = resp1.json_structure != resp2.json_structure

        return {
            "status_code_changed": resp1.status_code != resp2.status_code,
            "content_length_changed": resp1.content_length != resp2.content_length,
            "new_sensitive_data": len(new_sensitive),
            "new_sensitive_fields": [m.field_name for m in new_sensitive],
            "new_critical_data": len(
                [m for m in new_sensitive if m.sensitivity == SensitivityLevel.CRITICAL]
            ),
            "resp1_max_sensitivity": (
                resp1.max_sensitivity.value if resp1.max_sensitivity else None
            ),
            "resp2_max_sensitivity": (
                resp2.max_sensitivity.value if resp2.max_sensitivity else None
            ),
            "structure_changed": structure_changed,
            "risk_increase": resp2.risk_score - resp1.risk_score,
        }
