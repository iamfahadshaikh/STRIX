"""
PARAMETER INTELLIGENCE ENGINE — Per-endpoint parameter classification and scoring.

Purpose: Classify parameters by type/sensitivity, assign exploitation priority,
and skip metadata/non-user-controllable parameters.

Output: Enriched parameter data with confidence scores for gating decisions.
"""

import logging
import re
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ParameterType(Enum):
    """Parameter classification."""
    # User input
    SEARCH_QUERY = "search_query"
    TEXT_INPUT = "text_input"
    ID = "id"
    UUID = "uuid"
    EMAIL = "email"
    URL = "url"
    FILE_UPLOAD = "file_upload"
    
    # Authentication/sensitive
    PASSWORD = "password"
    TOKEN = "token"
    API_KEY = "api_key"
    SESSION = "session"
    
    # Metadata/non-controllable
    EXTERNAL_INTEL = "external_intel"
    FORM_METADATA = "form_metadata"
    STATIC_CONFIG = "static_config"
    VERSION = "version"
    
    # Unknown
    UNKNOWN = "unknown"


@dataclass
class Parameter:
    """Enhanced parameter with intelligence."""
    name: str
    endpoint: str
    method: str  # GET, POST, etc.
    source: str  # "url_param", "json_body", "nested_json", "form_field"
    param_type: ParameterType = ParameterType.UNKNOWN
    confidence: float = 0.0  # 0.0–1.0: how confident this is a real user param
    is_controllable: bool = True  # Can user influence this?
    exploitability_score: float = 0.0  # 0.0–1.0: likelihood of successful exploit
    evidence: Dict = field(default_factory=dict)  # Why this classification?
    
    def __hash__(self):
        return hash((self.name, self.endpoint, self.method))
    
    def __eq__(self, other):
        if not isinstance(other, Parameter):
            return False
        return (self.name == other.name and 
                self.endpoint == other.endpoint and 
                self.method == other.method)
    
    def __repr__(self):
        return (f"Parameter(name={self.name}, type={self.param_type.value}, "
                f"confidence={self.confidence:.2f}, controllable={self.is_controllable})")


class ParameterIntelligenceEngine:
    """
    Classify parameters by type and controllability.
    
    Known metadata patterns (skip these):
    - external_intel_*
    - form_fields[*]
    - crawler_*
    - static_*
    - config_*
    - ver, version, post_id, form_id, referer_title, queried_id
    
    Known injectable patterns (test these):
    - id, user_id, product_id (numeric IDs)
    - search, q, query (search boxes)
    - url, href, redirect (URL params)
    - username, email (auth)
    """
    
    # Non-controllable parameter patterns
    METADATA_PREFIXES = {
        "external_intel_",
        "crawler_",
        "static_",
        "config_",
        "cache_",
        "debug_",
    }
    
    METADATA_NAMES = {
        "ver", "version", "post_id", "form_id", "page_id", "article_id",
        "referer_title", "queried_id", "timestamp", "nonce", "csrf_token",
        "origin", "referrer", "user_agent", "accept_language",
        "content_type", "accept_encoding",
    }
    
    # Form builder fields (typically not injectable)
    FORM_FIELD_PATTERN = r"^form_fields\[[^\]]+\]$"
    
    # Injectable parameter patterns
    ID_PATTERNS = [
        r"^(user_)?id$",
        r"_id$",
        r"^(product|order|post|comment|article)_id",
        r"^(id|uid|user_id|product_id|order_id)",
    ]
    
    SEARCH_PATTERNS = [
        r"^(search|q|query)$",
        r"^(keyword|keywords|term|text)$",
        r"^(name|title)$",  # Often searchable
    ]
    
    URL_PATTERNS = [
        r"^(url|href|redirect|next|return_to|goto|dest|target|back)$",
        r"_url$",
    ]
    
    AUTH_PATTERNS = [
        r"^(username|user|email|password)$",
        r"^(login|signin|auth)_.*",
    ]
    
    FILE_PATTERNS = [
        r"^(file|upload|attachment|document)$",
        r"_file$",
    ]
    
    API_PATTERNS = [
        r"^(api_key|apikey|api-key)$",
        r"^(token|access_token|jwt)$",
        r"^(key|secret|credential)$",
    ]
    
    def __init__(self):
        self.params_seen: Set[Parameter] = set()
        logger.info("[ParameterIntelligenceEngine] Initialized")
    
    def classify_parameters(self, endpoint: str, method: str, 
                           params: List[Dict]) -> List[Parameter]:
        """
        Classify a list of parameters for a given endpoint.
        
        Args:
            endpoint: "/api/users"
            method: "GET", "POST", "PUT", etc.
            params: [{name: "id", source: "url_param", value: "123"}, ...]
        
        Returns:
            List[Parameter] with types, confidence, and controllability set
        """
        classified = []
        
        for param_dict in params:
            param_name = param_dict.get("name", "")
            param_source = param_dict.get("source", "unknown")
            param_value = param_dict.get("value", "")
            
            param = self._classify_single(
                param_name, endpoint, method, param_source, param_value
            )
            classified.append(param)
            self.params_seen.add(param)
        
        return classified
    
    def _classify_single(self, param_name: str, endpoint: str, method: str,
                         source: str, value: str = "") -> Parameter:
        """Classify a single parameter."""
        
        # Check if metadata (non-controllable)
        is_metadata = self._is_metadata(param_name)
        
        # Determine parameter type
        param_type = self._infer_type(param_name, value)
        
        # Assign confidence and controllability
        confidence, exploitability = self._score_parameter(
            param_name, param_type, is_metadata, source, value
        )
        
        param = Parameter(
            name=param_name,
            endpoint=endpoint,
            method=method,
            source=source,
            param_type=param_type,
            confidence=confidence,
            is_controllable=not is_metadata,
            exploitability_score=exploitability,
        )
        
        logger.debug(f"Classified {param}")
        return param
    
    def _is_metadata(self, param_name: str) -> bool:
        """Check if parameter is metadata (non-user-controllable)."""
        param_lower = param_name.lower()
        
        # Check prefixes
        for prefix in self.METADATA_PREFIXES:
            if param_lower.startswith(prefix):
                return True
        
        # Check known metadata names
        if param_lower in self.METADATA_NAMES:
            return True
        
        # Check form builder fields
        if re.match(self.FORM_FIELD_PATTERN, param_name, re.IGNORECASE):
            return True
        
        # Check for tracking/analytics
        if re.match(r"^(utm_|ga_|fbclid|gclid|msclkid)", param_lower):
            return True
        
        return False
    
    def _infer_type(self, param_name: str, value: str = "") -> ParameterType:
        """Infer parameter type from name and value patterns."""
        param_lower = param_name.lower()
        
        # Check name patterns
        for pattern in self.ID_PATTERNS:
            if re.search(pattern, param_lower):
                # Distinguish UUID from numeric ID
                if self._looks_like_uuid(value):
                    return ParameterType.UUID
                return ParameterType.ID
        
        for pattern in self.SEARCH_PATTERNS:
            if re.search(pattern, param_lower):
                return ParameterType.SEARCH_QUERY
        
        for pattern in self.URL_PATTERNS:
            if re.search(pattern, param_lower):
                return ParameterType.URL
        
        for pattern in self.AUTH_PATTERNS:
            if re.search(pattern, param_lower):
                # Distinguish password from other auth fields
                if "password" in param_lower:
                    return ParameterType.PASSWORD
                return ParameterType.EMAIL
        
        for pattern in self.FILE_PATTERNS:
            if re.search(pattern, param_lower):
                return ParameterType.FILE_UPLOAD
        
        for pattern in self.API_PATTERNS:
            if re.search(pattern, param_lower):
                if any(x in param_lower for x in ["password", "secret"]):
                    return ParameterType.PASSWORD
                if any(x in param_lower for x in ["token", "jwt"]):
                    return ParameterType.TOKEN
                return ParameterType.API_KEY
        
        return ParameterType.UNKNOWN
    
    def _score_parameter(self, param_name: str, param_type: ParameterType,
                         is_metadata: bool, source: str,
                         value: str = "") -> Tuple[float, float]:
        """
        Score parameter confidence (is it a real user param?) and exploitability.
        
        Returns:
            (confidence: 0.0–1.0, exploitability: 0.0–1.0)
        """
        
        if is_metadata:
            return 0.0, 0.0  # Not controllable
        
        # Base confidence by type
        type_confidence = {
            ParameterType.SEARCH_QUERY: 0.95,  # Very likely injectable
            ParameterType.ID: 0.92,  # Usually injectable
            ParameterType.UUID: 0.90,  # Often injectable
            ParameterType.URL: 0.85,  # Possibly injectable (SSRF)
            ParameterType.EMAIL: 0.88,  # Often injectable
            ParameterType.TEXT_INPUT: 0.90,  # Generic text input
            ParameterType.FILE_UPLOAD: 0.80,  # Depends on validation
            ParameterType.PASSWORD: 0.70,  # Usually protected
            ParameterType.TOKEN: 0.65,  # Usually protected
            ParameterType.API_KEY: 0.60,  # Usually protected
            ParameterType.SESSION: 0.60,  # Usually protected
            ParameterType.UNKNOWN: 0.50,  # Unknown confidence
        }
        
        confidence = type_confidence.get(param_type, 0.50)
        
        # Adjust by source
        source_adjustments = {
            "url_param": +0.05,  # URL params slightly more likely to be injectable
            "json_body": +0.03,  # JSON body params
            "form_field": +0.02,  # Form fields
            "nested_json": +0.04,  # Nested keys
        }
        confidence += source_adjustments.get(source, 0.0)
        confidence = min(1.0, confidence)  # Cap at 1.0
        
        # Exploitability scoring
        type_exploitability = {
            ParameterType.SEARCH_QUERY: 0.90,  # High exploitability
            ParameterType.ID: 0.75,  # Depends on implementation
            ParameterType.UUID: 0.50,  # UUIDs hard to guess
            ParameterType.URL: 0.80,  # SSRF likely if injectable
            ParameterType.EMAIL: 0.60,  # Depends on how it's used
            ParameterType.TEXT_INPUT: 0.85,  # Generic text is very exploitable
            ParameterType.FILE_UPLOAD: 0.70,  # Depends on file handling
            ParameterType.PASSWORD: 0.20,  # Low (usually protected)
            ParameterType.TOKEN: 0.15,  # Low (usually protected)
            ParameterType.API_KEY: 0.10,  # Low (usually protected)
            ParameterType.SESSION: 0.10,  # Low (usually protected)
            ParameterType.UNKNOWN: 0.50,  # Medium
        }
        exploitability = type_exploitability.get(param_type, 0.50)
        
        # Adjust by evidence from value
        if value:
            if self._looks_like_uuid(value):
                exploitability -= 0.20  # UUIDs less exploitable
            if self._looks_like_hash(value):
                exploitability -= 0.15  # Hashes less exploitable
        
        exploitability = max(0.0, min(1.0, exploitability))  # Clamp to [0, 1]
        
        return confidence, exploitability
    
    def _looks_like_uuid(self, value: str) -> bool:
        """Check if value looks like a UUID."""
        return bool(re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            str(value).lower()
        ))
    
    def _looks_like_hash(self, value: str) -> bool:
        """Check if value looks like a cryptographic hash."""
        value_str = str(value)
        # Common hash patterns
        patterns = [
            r"^[a-f0-9]{32}$",  # MD5
            r"^[a-f0-9]{40}$",  # SHA1
            r"^[a-f0-9]{64}$",  # SHA256
            r"^[a-f0-9]{128}$",  # SHA512
        ]
        return any(re.match(p, value_str.lower()) for p in patterns)
    
    def filter_controllable(self, parameters: List[Parameter]) -> List[Parameter]:
        """Return only controllable parameters (skip metadata)."""
        controllable = [p for p in parameters if p.is_controllable]
        rejected = [p for p in parameters if not p.is_controllable]
        
        logger.info(f"Filtered {len(rejected)} metadata params, {len(controllable)} controllable remain")
        for p in rejected:
            logger.debug(f"  Rejected (metadata): {p.name}")
        
        return controllable
    
    def filter_high_confidence(self, parameters: List[Parameter],
                               threshold: float = 0.70) -> List[Parameter]:
        """Return only parameters with confidence >= threshold."""
        high_conf = [p for p in parameters if p.confidence >= threshold]
        low_conf = [p for p in parameters if p.confidence < threshold]
        
        logger.info(f"Filtered by confidence ({threshold}): {len(high_conf)} remain, {len(low_conf)} rejected")
        for p in low_conf:
            logger.debug(f"  Rejected (low confidence {p.confidence:.2f}): {p.name}")
        
        return high_conf
    
    def get_priority_params(self, parameters: List[Parameter],
                           top_n: int = 5) -> List[Parameter]:
        """Get top N parameters by exploitability score."""
        sorted_params = sorted(
            parameters,
            key=lambda p: (p.is_controllable, p.exploitability_score),
            reverse=True
        )
        return sorted_params[:top_n]
    
    def summary(self, parameters: List[Parameter]) -> Dict:
        """Generate summary statistics."""
        controllable = [p for p in parameters if p.is_controllable]
        high_conf = [p for p in parameters if p.confidence >= 0.70]
        
        return {
            "total": len(parameters),
            "controllable": len(controllable),
            "high_confidence": len(high_conf),
            "by_type": self._count_by_type(parameters),
            "by_source": self._count_by_source(parameters),
            "avg_confidence": sum(p.confidence for p in parameters) / len(parameters) if parameters else 0,
            "avg_exploitability": sum(p.exploitability_score for p in controllable) / len(controllable) if controllable else 0,
        }
    
    def _count_by_type(self, parameters: List[Parameter]) -> Dict[str, int]:
        """Count parameters by type."""
        counts = {}
        for p in parameters:
            key = p.param_type.value
            counts[key] = counts.get(key, 0) + 1
        return counts
    
    def _count_by_source(self, parameters: List[Parameter]) -> Dict[str, int]:
        """Count parameters by source."""
        counts = {}
        for p in parameters:
            counts[p.source] = counts.get(p.source, 0) + 1
        return counts


# Singleton
_engine = ParameterIntelligenceEngine()


def classify_parameters(endpoint: str, method: str, params: List[Dict]) -> List[Parameter]:
    """Public API: Classify parameters for an endpoint."""
    return _engine.classify_parameters(endpoint, method, params)


def filter_controllable(parameters: List[Parameter]) -> List[Parameter]:
    """Public API: Filter out metadata parameters."""
    return _engine.filter_controllable(parameters)


def filter_high_confidence(parameters: List[Parameter],
                          threshold: float = 0.70) -> List[Parameter]:
    """Public API: Filter low-confidence parameters."""
    return _engine.filter_high_confidence(parameters, threshold)
