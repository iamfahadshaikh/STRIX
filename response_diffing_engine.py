"""
Response Diffing Engine - Baseline vs Payload Comparison
Purpose: Establish baseline responses and compare against payload responses to prove exploitation
"""

import logging
import hashlib
import difflib
import re
from typing import Dict, Optional, Tuple, List
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
    
    def __init__(self):
        self.baselines: Dict[str, HTTPResponse] = {}
        self.payloads: Dict[str, HTTPResponse] = {}
        self.diffs: Dict[str, DiffResult] = {}
    
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
        
        Returns DiffResult with highest confidence score from all strategies
        """
        strategies_scores = {}
        
        # Strategy 1: Status code change
        status_changed = baseline.status_code != payload_response.status_code
        status_score = 0.35 if status_changed else 0.0
        strategies_scores[DiffingStrategy.STATUS_CODE] = status_score
        
        # Strategy 2: Content length change
        length_changed = baseline.content_length != payload_response.content_length
        length_diff = abs(baseline.content_length - payload_response.content_length)
        length_score = min(0.40, length_diff / (baseline.content_length or 1) * 0.5) if length_changed else 0.0
        strategies_scores[DiffingStrategy.LENGTH_CHANGE] = length_score
        
        # Strategy 3: Body similarity (sequence matching)
        similarity = self._calculate_body_similarity(baseline.body, payload_response.body)
        similarity_score = 0.0 if similarity > 0.95 else (1.0 - similarity) * 0.45
        strategies_scores[DiffingStrategy.FUZZY_MATCH] = similarity_score
        
        # Strategy 4: Payload reflection (for XSS)
        reflected, context = self._check_reflection(payload, payload_response.body)
        reflection_score = 0.50 if reflected else 0.0
        strategies_scores[DiffingStrategy.REFLECTION] = reflection_score
        
        # Strategy 5: Error signature (for SQLi)
        error_sig, error_type = self._check_error_signature(payload_response.body)
        error_score = 0.55 if error_sig else 0.0
        strategies_scores[DiffingStrategy.ERROR_SIGNATURE] = error_score
        
        # Strategy 6: Timing difference (for time-based SQLi)
        timing_diff = abs(payload_response.response_time - baseline.response_time)
        timing_score = min(0.45, timing_diff / 5.0) if timing_diff > 1.0 else 0.0
        strategies_scores[DiffingStrategy.TIMING] = timing_score
        
        # Select best strategy
        best_strategy = max(strategies_scores.items(), key=lambda x: x[1])
        best_strategy_enum, best_confidence = best_strategy
        
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
            f"Body size: {baseline.content_length} → {payload_response.content_length} bytes",
            f"Similarity: {similarity*100:.1f}%",
            f"Response time: {baseline.response_time:.2f}s → {payload_response.response_time:.2f}s",
        ]
        if reflected:
            diff_result.analysis_notes.append(f"Payload reflected in {context} context")
        if error_sig:
            diff_result.analysis_notes.append(f"Error signature detected: {error_type}")
        
        logger.info(f"Diff result for {endpoint}: {best_strategy_enum.value} "
                   f"({best_confidence:.2f} confidence)")
        
        return diff_result
    
    def _calculate_body_similarity(self, baseline: str, payload_response: str) -> float:
        """
        Calculate body similarity using SequenceMatcher
        Returns 0.0 - 1.0 (1.0 = identical)
        """
        matcher = difflib.SequenceMatcher(None, baseline, payload_response)
        return matcher.ratio()
    
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
                                     confidence_threshold: float = 0.35) -> bool:
        """
        Check if we have high-confidence evidence of exploitation for endpoint
        """
        diffs = [d for k, d in self.diffs.items() if k.startswith(endpoint)]
        return any(d.confidence >= confidence_threshold for d in diffs)
