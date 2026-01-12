"""
Payload Execution Wrapper - Phase 3 Fix
Enforce payload readiness validation and outcome tracking
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class PayloadOutcome(Enum):
    """Payload execution outcomes"""
    EXECUTED_CONFIRMED = "EXECUTED_CONFIRMED"           # Vuln confirmed with evidence
    EXECUTED_NO_SIGNAL = "EXECUTED_NO_SIGNAL"           # Executed but no vuln found
    BLOCKED_NO_CRAWL = "BLOCKED_NO_CRAWL"               # Crawler didn't run
    BLOCKED_NO_PARAM = "BLOCKED_NO_PARAM"               # No parameters to test
    BLOCKED_NO_METHOD = "BLOCKED_NO_METHOD"             # Method unknown
    BLOCKED_READINESS_FAILED = "BLOCKED_READINESS_FAILED"  # Readiness gate failed


@dataclass
class PayloadExecutionContext:
    """Context for payload execution"""
    tool_name: str
    endpoint: str
    parameter: str
    http_method: str
    payload: str
    context: str  # query/body/header/path
    
    def __repr__(self):
        return f"{self.tool_name}({self.http_method} {self.endpoint}?{self.parameter}={self.payload[:20]})"


class PayloadExecutionValidator:
    """
    Validates payload tool execution prerequisites
    Phase 3 requirement: No blind payload execution
    """
    
    @staticmethod
    def validate_dalfox_execution(endpoint: str, parameter: str, method: str, 
                                   crawler_data: Dict) -> Tuple[bool, str]:
        """
        Validate dalfox can execute on this endpoint+param
        
        Requirements:
        - Endpoint must be crawler-verified
        - Parameter must exist
        - Parameter must be reflectable (or at least verified)
        - Method must be known
        """
        if not endpoint:
            return False, "endpoint_missing"
        
        if not parameter:
            return False, "parameter_missing"
        
        if not method or method == "UNKNOWN":
            return False, "method_unknown"
        
        # Check crawler data
        if not crawler_data:
            return False, "no_crawler_data"
        
        # Endpoint should be in crawler results
        crawler_endpoints = crawler_data.get("endpoints", [])
        if endpoint not in crawler_endpoints:
            return False, "endpoint_not_crawled"
        
        # Parameter should be reflectable (ideal) or at least present
        reflectable_params = crawler_data.get("reflectable_params", [])
        all_params = crawler_data.get("all_params", [])
        
        if parameter not in reflectable_params and parameter not in all_params:
            return False, "parameter_not_found"
        
        return True, "ready"
    
    @staticmethod
    def validate_sqlmap_execution(endpoint: str, parameter: str, method: str,
                                   crawler_data: Dict) -> Tuple[bool, str]:
        """
        Validate sqlmap can execute
        
        Requirements:
        - Endpoint crawled
        - Parameter exists
        - Parameter is dynamic (not static)
        - Method known
        """
        if not endpoint:
            return False, "endpoint_missing"
        
        if not parameter:
            return False, "parameter_missing"
        
        if not method or method == "UNKNOWN":
            return False, "method_unknown"
        
        if not crawler_data:
            return False, "no_crawler_data"
        
        # Endpoint crawled?
        crawler_endpoints = crawler_data.get("endpoints", [])
        if endpoint not in crawler_endpoints:
            return False, "endpoint_not_crawled"
        
        # Parameter should be injectable or at least dynamic
        injectable_params = crawler_data.get("injectable_sql_params", [])
        dynamic_params = crawler_data.get("dynamic_params", [])
        all_params = crawler_data.get("all_params", [])
        
        if parameter not in injectable_params and parameter not in dynamic_params and parameter not in all_params:
            return False, "parameter_not_injectable"
        
        return True, "ready"
    
    @staticmethod
    def validate_commix_execution(endpoint: str, parameter: str, method: str,
                                   crawler_data: Dict) -> Tuple[bool, str]:
        """
        Validate commix can execute
        
        Requirements:
        - Endpoint crawled
        - Parameter is command-injectable type
        - Method known
        """
        if not endpoint:
            return False, "endpoint_missing"
        
        if not parameter:
            return False, "parameter_missing"
        
        if not method or method == "UNKNOWN":
            return False, "method_unknown"
        
        if not crawler_data:
            return False, "no_crawler_data"
        
        # Endpoint crawled?
        crawler_endpoints = crawler_data.get("endpoints", [])
        if endpoint not in crawler_endpoints:
            return False, "endpoint_not_crawled"
        
        # Parameter should be command-injectable
        cmd_params = crawler_data.get("command_params", [])
        all_params = crawler_data.get("all_params", [])
        
        if parameter not in cmd_params and parameter not in all_params:
            return False, "parameter_not_cmd_injectable"
        
        return True, "ready"
    
    @staticmethod
    def validate_tool_execution(tool_name: str, endpoint: str, parameter: str,
                                method: str, crawler_data: Dict) -> Tuple[bool, str]:
        """Main dispatcher for tool validation"""
        
        tool_lower = tool_name.lower()
        
        if "dalfox" in tool_lower or "xss" in tool_lower:
            return PayloadExecutionValidator.validate_dalfox_execution(
                endpoint, parameter, method, crawler_data
            )
        elif "sqlmap" in tool_lower:
            return PayloadExecutionValidator.validate_sqlmap_execution(
                endpoint, parameter, method, crawler_data
            )
        elif "commix" in tool_lower:
            return PayloadExecutionValidator.validate_commix_execution(
                endpoint, parameter, method, crawler_data
            )
        else:
            # Unknown tool - allow by default (nuclei, etc.)
            return True, "unknown_tool_allowed"


class PayloadOutcomeTracker:
    """Track payload execution outcomes"""
    
    def __init__(self):
        self.outcomes: List[Dict] = []
    
    def record_outcome(self, context: PayloadExecutionContext, 
                      outcome: PayloadOutcome, evidence: str = ""):
        """Record a payload execution outcome"""
        self.outcomes.append({
            "tool": context.tool_name,
            "endpoint": context.endpoint,
            "parameter": context.parameter,
            "method": context.http_method,
            "payload": context.payload[:100],  # Truncate
            "context": context.context,
            "outcome": outcome.value,
            "evidence": evidence[:200]  # Truncate
        })
        
        logger.info(f"[PayloadOutcome] {context.tool_name}: {outcome.value} on {context.endpoint}")
    
    def get_summary(self) -> Dict:
        """Get summary of outcomes"""
        by_outcome = {}
        for record in self.outcomes:
            outcome = record["outcome"]
            by_outcome[outcome] = by_outcome.get(outcome, 0) + 1
        
        return {
            "total_attempts": len(self.outcomes),
            "by_outcome": by_outcome,
            "confirmed_vulns": by_outcome.get(PayloadOutcome.EXECUTED_CONFIRMED.value, 0),
            "no_signal": by_outcome.get(PayloadOutcome.EXECUTED_NO_SIGNAL.value, 0),
            "blocked": sum(v for k, v in by_outcome.items() if "BLOCKED" in k)
        }
    
    def get_all_outcomes(self) -> List[Dict]:
        """Get all recorded outcomes"""
        return self.outcomes
