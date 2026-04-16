"""
Parameter Extractor - Identify and categorize potential IDOR parameters
Purpose: Extract and analyze parameters from URLs/JSON bodies for ID mutation testing
"""

import logging
import re
import json
import base64
from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Optional, Set, Tuple, Any

logger = logging.getLogger(__name__)


class ParameterType(Enum):
    """Parameter type classification"""
    NUMERIC_ID = "numeric_id"          # 1, 123, 999999
    UUID = "uuid"                       # a1b2c3d4-e5f6...
    ALPHANUMERIC_ID = "alphanumeric"   # user_123_abc
    EMAIL = "email"                     # user@example.com
    USERNAME = "username"               # john_doe
    API_KEY = "api_key"                 # Looks like key
    TOKEN = "token"                     # JWT-like
    ENUM = "enum"                       # true/false, admin/user
    UNKNOWN = "unknown"


@dataclass
class Parameter:
    """Extracted parameter"""
    name: str
    param_type: ParameterType
    example_value: str
    source: str  # "url", "json_body", "header"
    endpoint: str  # URL this came from
    json_path: str = ""
    identifier_kind: str = "generic"
    frequency: int = 1  # How many times seen
    confidence: float = 0.8  # Confidence this is an ID
    
    def is_likely_id(self) -> bool:
        """Check if parameter likely represents an ID"""
        return self.param_type in [
            ParameterType.NUMERIC_ID,
            ParameterType.UUID,
            ParameterType.ALPHANUMERIC_ID
        ]


class ParameterExtractor:
    """
    Extract and classify parameters from HTTP requests
    
    Identifies:
    - Numeric IDs (user_id, order_id, etc)
    - UUIDs
    - Enums (role, status)
    - API keys/tokens (for exclusion from mutation)
    """
    
    # Common ID field name patterns
    ID_FIELD_PATTERNS = [
        r"(?:user|customer|account|author|owner|creator|member|player|student)_?id",
        r"(?:order|transaction|invoice|receipt|payment)_?id",
        r"(?:post|article|comment|message|thread)_?id",
        r"(?:product|item|resource|object|entity)_?id",
        r"(?:org|organization|team|group|company)_?id",
        r"(?:session|request|job|task|batch)_?id",
        r"^id$",
        r"^ids?$",
    ]
    
    # UUID pattern (loose match)
    UUID_PATTERN = re.compile(
        r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}",
        re.IGNORECASE
    )
    
    # Fields to exclude (likely not IDs)
    EXCLUDE_FIELDS = {
        "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
        "authorization", "bearer", "auth", "access_key", "session",
        "csrf_token", "nonce", "x-api-key",
        "timestamp", "date", "created_at", "updated_at",
        "page", "limit", "offset", "page_size", "sort", "order",
        "filter", "query", "search", "q", "category", "type",
        "format", "encoding", "version", "v",
    }
    
    def __init__(self):
        self.extracted_params: Dict[str, Parameter] = {}  # param_name -> Parameter
    
    def extract_from_url(self, url: str, endpoint: str) -> List[Parameter]:
        """
        Extract parameters from URL query string
        
        Args:
            url: Full URL with query string
            endpoint: Base endpoint path
        
        Returns:
            List of extracted parameters
        """
        params = []
        
        # Parse query string
        if "?" not in url:
            return params
        
        query_string = url.split("?", 1)[1]
        
        try:
            for param_pair in query_string.split("&"):
                if "=" not in param_pair:
                    continue
                
                name, value = param_pair.split("=", 1)
                name = name.strip()
                
                # Skip excluded fields
                if self._is_excluded_field(name):
                    continue
                
                param_type, confidence = self._classify_parameter(name, value)
                
                param = Parameter(
                    name=name,
                    param_type=param_type,
                    example_value=value[:100],
                    source="url",
                    endpoint=endpoint,
                    confidence=confidence
                )
                params.append(param)
                self._register_param(param)
        
        except Exception as e:
            logger.warning(f"Error parsing query string from {url}: {e}")
        
        return params
    
    def extract_from_json_body(self, body_str: str, endpoint: str) -> List[Parameter]:
        """
        Extract parameters from JSON request body
        
        Args:
            body_str: JSON string
            endpoint: Base endpoint path
        
        Returns:
            List of extracted parameters
        """
        params = []
        
        try:
            body = json.loads(body_str)
        except (json.JSONDecodeError, TypeError):
            return params
        
        for key, value, json_path in self._iter_json_scalars(body):
            if self._is_excluded_field(key):
                continue

            value_str = str(value)
            param_type, confidence = self._classify_parameter(key, value_str)
            param = Parameter(
                name=key,
                param_type=param_type,
                example_value=value_str[:100],
                source="json_body",
                endpoint=endpoint,
                json_path=json_path,
                identifier_kind=self._infer_identifier_kind(key, value_str),
                confidence=confidence
            )
            params.append(param)
            self._register_param(param)
        
        return params
    
    def _is_excluded_field(self, field_name: str) -> bool:
        """Check if field should be excluded from IDOR testing"""
        field_lower = field_name.lower()
        return any(
            excl in field_lower for excl in self.EXCLUDE_FIELDS
        )
    
    def _classify_parameter(self, field_name: str, value: str) -> Tuple[ParameterType, float]:
        """
        Classify parameter type and return confidence
        
        Returns:
            (ParameterType, confidence_0_1)
        """
        value_str = str(value).strip()
        field_lower = field_name.lower()
        
        # Check if field name suggests ID
        is_id_field = any(
            re.search(pattern, field_lower)
            for pattern in self.ID_FIELD_PATTERNS
        )
        
        # Numeric ID
        if value_str.isdigit() and len(value_str) <= 10:
            conf = 0.95 if is_id_field else 0.7
            return ParameterType.NUMERIC_ID, conf
        
        # UUID
        if self.UUID_PATTERN.match(value_str):
            return ParameterType.UUID, 0.95

        if self._looks_like_base64(value_str):
            conf = 0.8 if is_id_field else 0.55
            return ParameterType.ALPHANUMERIC_ID, conf
        
        # Email
        if "@" in value_str and "." in value_str:
            return ParameterType.EMAIL, 0.85
        
        # Alphanumeric ID (mix of letters/numbers/underscores)
        if re.match(r"^[a-zA-Z0-9_-]{5,}$", value_str):
            conf = 0.85 if is_id_field else 0.5
            return ParameterType.ALPHANUMERIC_ID, conf
        
        # Boolean/enum
        if value_str.lower() in ["true", "false", "0", "1", "yes", "no"]:
            return ParameterType.ENUM, 0.8
        
        # Token-like
        if len(value_str) > 20 and re.match(r"^[a-zA-Z0-9._-]+$", value_str):
            return ParameterType.TOKEN, 0.6
        
        return ParameterType.UNKNOWN, 0.3

    def _iter_json_scalars(self, node: Any, path: str = "") -> List[Tuple[str, Any, str]]:
        """Yield (key, scalar_value, json_path) from nested JSON dict/list structures."""
        found: List[Tuple[str, Any, str]] = []
        if isinstance(node, dict):
            for key, value in node.items():
                next_path = f"{path}.{key}" if path else str(key)
                if isinstance(value, (dict, list)):
                    found.extend(self._iter_json_scalars(value, next_path))
                elif isinstance(value, (str, int, float, bool)):
                    found.append((str(key), value, next_path))
        elif isinstance(node, list):
            for idx, value in enumerate(node):
                next_path = f"{path}[{idx}]" if path else f"[{idx}]"
                if isinstance(value, (dict, list)):
                    found.extend(self._iter_json_scalars(value, next_path))
                elif isinstance(value, (str, int, float, bool)):
                    found.append((path or "item", value, next_path))
        return found

    def _looks_like_base64(self, value: str) -> bool:
        value = (value or "").strip()
        if len(value) < 12 or len(value) % 4 != 0:
            return False
        if not re.match(r"^[A-Za-z0-9+/=_-]+$", value):
            return False
        try:
            base64.b64decode(value + "===", validate=False)
            return True
        except Exception:
            return False

    def _infer_identifier_kind(self, field_name: str, value: str) -> str:
        name = (field_name or "").lower()
        val = (value or "").strip()
        if self.UUID_PATTERN.match(val):
            return "uuid"
        if self._looks_like_base64(val):
            return "base64"
        if val.isdigit():
            return "numeric"
        if "email" in name:
            return "email"
        if any(token in name for token in ["id", "user", "account", "order", "resource"]):
            return "identifier"
        return "generic"
    
    def _register_param(self, param: Parameter):
        """Register or update parameter in registry"""
        key = (param.name, param.endpoint)
        if key in self.extracted_params:
            self.extracted_params[key].frequency += 1
        else:
            self.extracted_params[key] = param
    
    def get_id_parameters(self) -> List[Parameter]:
        """Get likely ID parameters for IDOR testing"""
        return [
            p for p in self.extracted_params.values()
            if p.is_likely_id() and p.confidence > 0.5
        ]
    
    def get_parameters_for_endpoint(self, endpoint: str) -> List[Parameter]:
        """Get all parameters for specific endpoint"""
        return [
            p for p in self.extracted_params.values()
            if p.endpoint == endpoint
        ]
    
    def get_parameter_summary(self) -> Dict:
        """Get summary of extracted parameters"""
        all_params = list(self.extracted_params.values())
        id_params = self.get_id_parameters()
        
        return {
            "total_parameters": len(all_params),
            "id_parameters": len(id_params),
            "numeric_ids": len([p for p in all_params if p.param_type == ParameterType.NUMERIC_ID]),
            "uuids": len([p for p in all_params if p.param_type == ParameterType.UUID]),
            "high_confidence": len([p for p in all_params if p.confidence > 0.8]),
            "by_type": {
                ptype.value: len([p for p in all_params if p.param_type == ptype])
                for ptype in ParameterType
            }
        }
