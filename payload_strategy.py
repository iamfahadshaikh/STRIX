"""
Payload Strategy Layer - Phase 3 Hardening
Purpose: Wrap payload tools with intelligent strategy and attempt tracking
"""

import logging
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlencode

logger = logging.getLogger(__name__)


class PayloadType(Enum):
    """Payload classification"""
    BASELINE = "baseline"  # Basic test payloads
    MUTATION = "mutation"  # Parameter mutations
    ENCODING = "encoding"  # Encoded variants


@dataclass
class PayloadAttempt:
    """Track individual payload attempt"""
    payload: str
    payload_type: PayloadType
    target_endpoint: str
    target_parameter: str
    http_method: str
    encoding: Optional[str] = None
    success: bool = False
    response_code: Optional[int] = None
    evidence: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "payload": self.payload,
            "type": self.payload_type.value,
            "endpoint": self.target_endpoint,
            "parameter": self.target_parameter,
            "method": self.http_method,
            "encoding": self.encoding,
            "success": self.success,
            "response_code": self.response_code,
            "evidence": self.evidence
        }


class PayloadStrategy:
    """
    Intelligent payload strategy wrapper
    
    Generates:
    - Baseline payloads (standard XSS/SQLi/CMD payloads)
    - Mutation payloads (parameter value variations)
    - Encoding variants (URL, base64, unicode escapes)
    
    Tracks all attempts for correlation and reporting
    """
    
    # XSS baseline payloads
    XSS_BASELINE = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "'\"><script>alert(String.fromCharCode(88,83,83))</script>",
    ]
    
    # SQLi baseline payloads
    SQLI_BASELINE = [
        "' OR '1'='1",
        "1' AND '1'='1",
        "admin'--",
        "' UNION SELECT NULL--",
    ]
    
    # CMD injection baseline payloads
    CMD_BASELINE = [
        "; ls",
        "| whoami",
        "`id`",
        "$(whoami)",
    ]
    
    def __init__(self):
        self.attempts: List[PayloadAttempt] = []
    
    def generate_xss_payloads(self, parameter: str, endpoint: str, method: str = "GET") -> List[Dict]:
        """Generate XSS payload set"""
        payloads = []
        
        # Baseline
        for payload in self.XSS_BASELINE:
            payloads.append({
                "payload": payload,
                "type": PayloadType.BASELINE,
                "parameter": parameter,
                "endpoint": endpoint,
                "method": method,
                "encoding": None
            })
        
        # Encoded variants
        for base_payload in self.XSS_BASELINE[:1]:  # Just first payload
            # URL encoded
            payloads.append({
                "payload": urlencode({parameter: base_payload}),
                "type": PayloadType.ENCODING,
                "parameter": parameter,
                "endpoint": endpoint,
                "method": method,
                "encoding": "url"
            })
        
        return payloads
    
    def generate_sqli_payloads(self, parameter: str, endpoint: str, method: str = "GET") -> List[Dict]:
        """Generate SQLi payload set"""
        payloads = []
        
        # Baseline
        for payload in self.SQLI_BASELINE:
            payloads.append({
                "payload": payload,
                "type": PayloadType.BASELINE,
                "parameter": parameter,
                "endpoint": endpoint,
                "method": method,
                "encoding": None
            })
        
        return payloads
    
    def generate_cmd_payloads(self, parameter: str, endpoint: str, method: str = "GET") -> List[Dict]:
        """Generate command injection payload set"""
        payloads = []
        
        # Baseline
        for payload in self.CMD_BASELINE:
            payloads.append({
                "payload": payload,
                "type": PayloadType.BASELINE,
                "parameter": parameter,
                "endpoint": endpoint,
                "method": method,
                "encoding": None
            })
        
        return payloads
    
    def track_attempt(self, payload: str, payload_type: PayloadType, 
                     endpoint: str, parameter: str, method: str,
                     success: bool = False, response_code: Optional[int] = None,
                     evidence: Optional[str] = None, encoding: Optional[str] = None):
        """Track payload attempt"""
        attempt = PayloadAttempt(
            payload=payload,
            payload_type=payload_type,
            target_endpoint=endpoint,
            target_parameter=parameter,
            http_method=method,
            encoding=encoding,
            success=success,
            response_code=response_code,
            evidence=evidence
        )
        self.attempts.append(attempt)
    
    def get_successful_attempts(self) -> List[PayloadAttempt]:
        """Get successful payload attempts"""
        return [a for a in self.attempts if a.success]
    
    def get_attempts_summary(self) -> Dict:
        """Get summary of all attempts"""
        total = len(self.attempts)
        successful = len(self.get_successful_attempts())
        
        by_type = {}
        for attempt in self.attempts:
            ptype = attempt.payload_type.value
            if ptype not in by_type:
                by_type[ptype] = {"total": 0, "successful": 0}
            by_type[ptype]["total"] += 1
            if attempt.success:
                by_type[ptype]["successful"] += 1
        
        return {
            "total_attempts": total,
            "successful_attempts": successful,
            "success_rate": successful / total if total > 0 else 0.0,
            "by_type": by_type,
            "attempts": [a.to_dict() for a in self.attempts]
        }


class PayloadReadinessGate:
    """
    Payload Readiness Gate - Phase 3 Critical
    
    Validates payload prerequisites before execution:
    - Parameter type (reflectable, injectable, etc.)
    - HTTP method compatibility
    - Endpoint context (API vs form vs query)
    - Content-type expectations
    """
    
    def __init__(self, endpoint_graph):
        self.graph = endpoint_graph
    
    def check_xss_readiness(self, endpoint: str, parameter: str) -> tuple[bool, str]:
        """Check if endpoint+param ready for XSS testing"""
        ep = self.graph.get_endpoint(endpoint)
        if not ep:
            return False, f"Endpoint {endpoint} not in graph"
        
        if parameter not in ep.parameters:
            return False, f"Parameter {parameter} not found in endpoint"
        
        param = ep.parameters[parameter]
        
        # Must be reflectable
        if not param.reflectable:
            return False, f"Parameter {parameter} not marked as reflectable"
        
        # Check methods
        if not ep.methods:
            return False, "No HTTP methods known for endpoint"
        
        return True, "Ready for XSS testing"
    
    def check_sqli_readiness(self, endpoint: str, parameter: str) -> tuple[bool, str]:
        """Check if endpoint+param ready for SQLi testing"""
        ep = self.graph.get_endpoint(endpoint)
        if not ep:
            return False, f"Endpoint {endpoint} not in graph"
        
        if parameter not in ep.parameters:
            return False, f"Parameter {parameter} not found in endpoint"
        
        param = ep.parameters[parameter]
        
        # Should be dynamic or injectable
        if not (param.is_dynamic() or param.injectable_sql):
            return False, f"Parameter {parameter} not injectable or dynamic"
        
        return True, "Ready for SQLi testing"
    
    def check_cmd_readiness(self, endpoint: str, parameter: str) -> tuple[bool, str]:
        """Check if endpoint+param ready for command injection testing"""
        ep = self.graph.get_endpoint(endpoint)
        if not ep:
            return False, f"Endpoint {endpoint} not in graph"
        
        if parameter not in ep.parameters:
            return False, f"Parameter {parameter} not found in endpoint"
        
        param = ep.parameters[parameter]
        
        # Must be command-injectable
        if not param.injectable_cmd:
            return False, f"Parameter {parameter} not marked as command-injectable"
        
        return True, "Ready for command injection testing"
