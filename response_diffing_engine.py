"""
Response Diffing Engine - Baseline vs Payload Comparison
Purpose: Establish baseline responses and compare against payload responses to prove exploitation
"""

import logging
import hashlib
import difflib
import re
import json
from typing import Dict, Optional, Tuple, List, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class DiffingStrategy(Enum):
    """Response comparison strategies"""
    EXACT_MATCH = "exact_match"           # Exact response match
    FUZZY_MATCH = "fuzzy_match"           # Similarity percentage
    LENGTH_CHANGE = "length_change"       # Response size change
    STATUS_CODE = "status_code"           # HTTP status code diff
    ERROR_SIGNATURE = "error_signature"   # SQL/error fingerprints
    REFLECTION = "reflection"             # Payload reflected in response
    TIMING = "timing"                     # Response time difference
    JSON_STRUCTURE = "json_structure"     # JSON object diff (new/changed keys)


@dataclass
class HTTPResponse:
    """Single HTTP response capture"""
    status_code: int
    headers: Dict[str, str]
    body: str
    body_hash: str = ""
    response_time: float = 0.0  # seconds
    content_length: int = 0
    captured_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def __post_init__(self):
        if not self.body_hash:
            self.body_hash = hashlib.md5(self.body.encode()).hexdigest()
        if not self.content_length:
            self.content_length = len(self.body)
    
    def to_dict(self) -> Dict:
        return {
            "status_code": self.status_code,
            "body_hash": self.body_hash,
            "content_length": self.content_length,
            "response_time": self.response_time,
            "captured_at": self.captured_at,
        }


@dataclass
class DiffResult:
    """Result of comparing baseline vs payload response"""
    baseline_response: HTTPResponse
    payload_response: HTTPResponse
    strategy: DiffingStrategy
    confidence: float  # 0.0 - 1.0
    payload_reflected: bool = False
    status_code_changed: bool = False
    content_length_changed: bool = False
    body_similarity: float = 0.0  # 0.0 - 1.0
    timing_difference: float = 0.0  # seconds
    error_signature_found: str = ""
    analysis_notes: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "strategy": self.strategy.value,
            "confidence": self.confidence,
            "payload_reflected": self.payload_reflected,
            "status_code_changed": self.status_code_changed,
            "content_length_changed": self.content_length_changed,
            "body_similarity": self.body_similarity,
            "timing_difference": self.timing_difference,
            "error_signature_found": self.error_signature_found,
            "analysis_notes": self.analysis_notes,
            "baseline": self.baseline_response.to_dict(),
            "payload": self.payload_response.to_dict(),
        }


class ResponseDiffingEngine:
    """
    Core response comparison engine for exploitation validation
    
    Establishes baseline responses and compares against payload responses
    to generate confidence scores and proof of exploitation
    """
    
    # SQL error signatures to detect injection
    SQL_ERROR_SIGNATURES = [
        r"SQL syntax",
        r"SQL error",
        r"mysql_fetch",
        r"Warning: mysql",
        r"ORA-\d+",  # Oracle
        r"SQL Server",
        r"PostgreSQL",
        r"SQLite",
        r"Syntax error",
        r"Query failed",
    ]
    
    # XSS reflection patterns
    XSS_CONTEXT_PATTERNS = {
        "html": r"<script>|alert\(|console\.",
        "attribute": r"on\w+\s*=|\"[^\"]*\"",
        "url": r"javascript:|data:",
    }

    SENSITIVE_JSON_KEYS = {
        "password", "passwd", "pwd", "token", "access_token", "refresh_token",
        "secret", "api_key", "apikey", "private_key", "ssn", "credit_card",
        "authorization", "session", "jwt",
    }
    
    def __init__(self):
        self.baselines: Dict[str, HTTPResponse] = {}
        self.payloads: Dict[str, HTTPResponse] = {}
        self.diffs: Dict[str, DiffResult] = {}

    VOLATILE_PATTERNS = [
        r"csrf[_-]?token[\"'\s:=]+[A-Za-z0-9_\-\.]+",
        r"access[_-]?token[\"'\s:=]+[A-Za-z0-9_\-\.]+",
        r"refresh[_-]?token[\"'\s:=]+[A-Za-z0-9_\-\.]+",
        r"\b[0-9]{10,13}\b",
        r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b",
    ]
    
    def capture_baseline(self, endpoint: str, response_text: str, 
                         status_code: int = 200, response_time: float = 0.0,
                         headers: Optional[Dict[str, str]] = None) -> HTTPResponse:
        """
        Capture baseline response for an endpoint (no payload)
        
        Args:
            endpoint: Target endpoint URL
            response_text: Full response body
            status_code: HTTP status code
            response_time: Response time in seconds
            headers: Response headers dict
        
        Returns:
            HTTPResponse object stored in baselines
        """
        baseline = HTTPResponse(
            status_code=status_code,
            headers=headers or {},
            body=response_text,
            response_time=response_time
        )
        self.baselines[endpoint] = baseline
        logger.debug(f"Captured baseline for {endpoint}: {status_code} ({len(response_text)} bytes)")
        return baseline
    
    def compare_response(self, endpoint: str, payload: str, 
                        payload_response_text: str,
                        status_code: int = 200, response_time: float = 0.0,
                        headers: Optional[Dict[str, str]] = None) -> Optional[DiffResult]:
        """
        Compare payload response against baseline for same endpoint
        
        Args:
            endpoint: Target endpoint
            payload: Payload string used
            payload_response_text: Response from payload request
            status_code: HTTP status code
            response_time: Response time in seconds
            headers: Response headers
        
        Returns:
            DiffResult with confidence score, or None if no baseline exists
        """
        if endpoint not in self.baselines:
            logger.warning(f"No baseline for {endpoint}, skipping comparison")
            return None
        
        baseline = self.baselines[endpoint]
        payload_response = HTTPResponse(
            status_code=status_code,
            headers=headers or {},
            body=payload_response_text,
            response_time=response_time
        )
        
        # Perform multi-strategy analysis
        diff_result = self._multi_strategy_diff(
            baseline, payload_response, payload, endpoint
        )
        
        # Store for later reporting
        self.diffs[f"{endpoint}_{payload[:20]}"] = diff_result
        self.payloads[endpoint] = payload_response
        
        return diff_result
    
    def _multi_strategy_diff(self, baseline: HTTPResponse, 
                            payload_response: HTTPResponse, 
                            payload: str, endpoint: str) -> DiffResult:
        """
        Apply multiple diffing strategies to find evidence of vulnerability
        STRICT VALIDATION: All scores raised to 0.7+ minimum for vulnerabilities
        
        Returns DiffResult with highest confidence score from all strategies
        """
        strategies_scores = {}
        
        # Strategy 1: Status code change - STRICT
        # Status code changes have many benign causes (redirects, error handling)
        # Accept only specific exploitation indicators
        status_changed = baseline.status_code != payload_response.status_code
        status_score = 0.0  # Raised from 0.35 - status code alone is NOT proof
        if status_changed and payload_response.status_code in [403, 404, 500]:
            # Only accept if payload triggers error (potential vulnerability indicator)
            status_score = 0.65  # Still high bar
        strategies_scores[DiffingStrategy.STATUS_CODE] = status_score
        
        # Strategy 2: Content length change - STRICT
        # Require substantial length difference (>20%) for meaningful evidence
        length_changed = baseline.content_length != payload_response.content_length
        length_diff = abs(baseline.content_length - payload_response.content_length)
        length_diff_percent = (length_diff / (baseline.content_length or 1)) * 100
        
        if length_changed and length_diff_percent > 20:  # Raised threshold from any % to 20%
            length_score = min(0.75, 0.65 + (length_diff_percent / 200))  # 0.65-0.75 range
        else:
            length_score = 0.0  # Raised from 0.40 - minor changes are noise
        strategies_scores[DiffingStrategy.LENGTH_CHANGE] = length_score
        
        # Strategy 3: Body similarity (sequence matching) - STRICT
        # Only accept substantial structural differences
        similarity = self._calculate_body_similarity(baseline.body, payload_response.body)
        if similarity < 0.80:  # Require >20% structural change (raised from 0.95 threshold)
            similarity_score = 0.70 + ((1.0 - similarity) * 0.25)  # 0.70-0.95 range
        else:
            similarity_score = 0.0  # Raised from 0.45 - similar responses are not exploited
        strategies_scores[DiffingStrategy.FUZZY_MATCH] = similarity_score
        
        # Strategy 4: Payload reflection (for XSS) - STRICT
        # Actual reflection is good evidence; accept at 0.85+
        reflected, context = self._check_reflection(payload, payload_response.body)
        reflection_score = 0.85 if reflected else 0.0  # Raised from 0.50 - must be actual reflection
        strategies_scores[DiffingStrategy.REFLECTION] = reflection_score
        
        # Strategy 5: Error signature (for SQLi) - STRICT
        # Confirmed SQL errors are strong evidence
        error_sig, error_type = self._check_error_signature(payload_response.body)
        error_score = 0.85 if error_sig else 0.0  # Raised from 0.55 - must be confirmed error
        strategies_scores[DiffingStrategy.ERROR_SIGNATURE] = error_score
        
        # Strategy 6: Timing difference (for time-based SQLi) - STRICT
        # Only accept significant delays (>3s for SLEEP(5) payloads)
        timing_diff = abs(payload_response.response_time - baseline.response_time)
        if timing_diff > 3.0:  # Strict: require >3s delay (raised from 1.0)
            timing_score = 0.75 + min(0.2, timing_diff / 20)  # 0.75-0.95 range
        else:
            timing_score = 0.0  # Raised from 0.45 - small delays are noise
        strategies_scores[DiffingStrategy.TIMING] = timing_score

        # Strategy 7: JSON structural drift (new/changed/sensitive fields)
        json_diff = self.compare_json(baseline.body, payload_response.body)
        json_score = 0.0
        if json_diff.get("sensitive_leak"):
            json_score = 0.95
        elif json_diff.get("new_fields") or json_diff.get("changed_fields"):
            json_score = 0.75
        strategies_scores[DiffingStrategy.JSON_STRUCTURE] = json_score
        
        # Select best strategy
        best_strategy = max(strategies_scores.items(), key=lambda x: x[1])
        best_strategy_enum, best_confidence = best_strategy
        
        # GLOBAL THRESHOLD: Minimum 0.7 confidence for acceptance
        if best_confidence < 0.70:
            best_confidence = 0.0  # Raised threshold from 0.35 to 0.70
            logger.debug(f"Diff result for {endpoint}: below 0.7 threshold, rejecting")
        
        # Build comprehensive DiffResult
        diff_result = DiffResult(
            baseline_response=baseline,
            payload_response=payload_response,
            strategy=best_strategy_enum,
            confidence=best_confidence,
            payload_reflected=reflected,
            status_code_changed=status_changed,
            content_length_changed=length_changed,
            body_similarity=similarity,
            timing_difference=timing_diff,
            error_signature_found=error_type,
        )
        
        # Add analysis notes
        diff_result.analysis_notes = [
            f"Status code: {baseline.status_code} → {payload_response.status_code}",
            f"Body size: {baseline.content_length} → {payload_response.content_length} bytes ({length_diff_percent:.1f}% change)",
            f"Similarity: {similarity*100:.1f}%",
            f"Response time: {baseline.response_time:.2f}s → {payload_response.response_time:.2f}s",
        ]
        if reflected:
            diff_result.analysis_notes.append(f"Payload reflected in {context} context")
        if error_sig:
            diff_result.analysis_notes.append(f"Error signature detected: {error_type}")
        if json_diff.get("new_fields") or json_diff.get("changed_fields"):
            diff_result.analysis_notes.append(
                f"JSON diff new={len(json_diff.get('new_fields', []))}, changed={len(json_diff.get('changed_fields', []))}, sensitive={json_diff.get('sensitive_leak', False)}"
            )
        
        if best_confidence >= 0.70:
            logger.info(f"Diff result for {endpoint}: {best_strategy_enum.value} "
                       f"({best_confidence:.2f} confidence) - ACCEPTED")
        
        return diff_result

    def compare_json(self, baseline_body: str, payload_body: str) -> Dict[str, Any]:
        """Compare JSON payloads and surface structural/security-significant changes."""
        baseline_json = self._safe_json_loads(baseline_body)
        payload_json = self._safe_json_loads(payload_body)
        if baseline_json is None or payload_json is None:
            return {
                "new_fields": [],
                "changed_fields": [],
                "sensitive_leak": False,
                "confidence": 0.0,
            }

        new_fields: List[str] = []
        changed_fields: List[str] = []
        self._walk_json_diff(baseline_json, payload_json, "", new_fields, changed_fields)

        sensitive_leak = any(
            segment.lower() in self.SENSITIVE_JSON_KEYS
            for path in (new_fields + changed_fields)
            for segment in path.replace("[", ".").replace("]", "").split(".")
            if segment
        )

        confidence = 0.0
        if sensitive_leak:
            confidence = 0.95
        elif new_fields or changed_fields:
            confidence = 0.75

        return {
            "new_fields": new_fields,
            "changed_fields": changed_fields,
            "sensitive_leak": sensitive_leak,
            "confidence": confidence,
        }

    def _safe_json_loads(self, body: str) -> Optional[Any]:
        try:
            return json.loads(body)
        except Exception:
            return None

    def _walk_json_diff(
        self,
        baseline: Any,
        payload: Any,
        path: str,
        new_fields: List[str],
        changed_fields: List[str],
    ) -> None:
        if isinstance(baseline, dict) and isinstance(payload, dict):
            baseline_keys = set(baseline.keys())
            payload_keys = set(payload.keys())
            for key in sorted(payload_keys - baseline_keys):
                new_fields.append(f"{path}.{key}" if path else str(key))
            for key in sorted(baseline_keys & payload_keys):
                next_path = f"{path}.{key}" if path else str(key)
                self._walk_json_diff(baseline[key], payload[key], next_path, new_fields, changed_fields)
            return

        if isinstance(baseline, list) and isinstance(payload, list):
            if len(payload) > len(baseline):
                new_fields.append(f"{path}[]" if path else "[]")
            compare_len = min(len(baseline), len(payload))
            for idx in range(compare_len):
                self._walk_json_diff(baseline[idx], payload[idx], f"{path}[{idx}]", new_fields, changed_fields)
            return

        if baseline != payload:
            changed_fields.append(path or "$root")
    
    def _calculate_body_similarity(self, baseline: str, payload_response: str) -> float:
        """
        Calculate body similarity using SequenceMatcher
        Returns 0.0 - 1.0 (1.0 = identical)
        """
        baseline_norm = self._normalize_for_diff(baseline)
        payload_norm = self._normalize_for_diff(payload_response)
        matcher = difflib.SequenceMatcher(None, baseline_norm, payload_norm)
        return matcher.ratio()

    def _normalize_for_diff(self, body: str) -> str:
        """Remove high-churn tokens to reduce false diffs."""
        normalized = body or ""
        for pattern in self.VOLATILE_PATTERNS:
            normalized = re.sub(pattern, "<redacted>", normalized, flags=re.IGNORECASE)
        return normalized
    
    def _check_reflection(self, payload: str, response_body: str) -> Tuple[bool, str]:
        """
        Check if payload is reflected in response (XSS indicator)
        Returns (reflected: bool, context: str)
        """
        # Simple reflection check
        if payload in response_body:
            return True, "literal"
        
        # Check for HTML-encoded reflection
        import html
        encoded_payload = html.escape(payload)
        if encoded_payload in response_body:
            return True, "html-encoded"
        
        # Check for URL-encoded reflection
        from urllib.parse import quote
        encoded_payload = quote(payload)
        if encoded_payload in response_body:
            return True, "url-encoded"
        
        return False, ""
    
    def _check_error_signature(self, response_body: str) -> Tuple[bool, str]:
        """
        Check for SQL error signatures in response
        Returns (found: bool, error_type: str)
        """
        for pattern in self.SQL_ERROR_SIGNATURES:
            if re.search(pattern, response_body, re.IGNORECASE):
                return True, pattern
        return False, ""
    
    def get_diff_summary(self, endpoint: str) -> Optional[Dict]:
        """Get summary of all diffs for an endpoint"""
        diffs = [d for k, d in self.diffs.items() if k.startswith(endpoint)]
        if not diffs:
            return None
        
        avg_confidence = sum(d.confidence for d in diffs) / len(diffs)
        return {
            "endpoint": endpoint,
            "attempts": len(diffs),
            "avg_confidence": avg_confidence,
            "best_result": max(diffs, key=lambda d: d.confidence).to_dict(),
        }
    
    def has_evidence_of_exploitation(self, endpoint: str, 
                                     confidence_threshold: float = 0.70) -> bool:
        """
        Check if we have high-confidence evidence of exploitation for endpoint
        STRICT: Threshold raised from 0.35 to 0.70 for genuine proof
        """
        diffs = [d for k, d in self.diffs.items() if k.startswith(endpoint)]
        return any(d.confidence >= confidence_threshold for d in diffs)
