"""
Enhanced Confidence Engine - Phase 4 Hardening
Purpose: Multi-factor confidence scoring with corroboration
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ConfidenceFactors:
    """Breakdown of confidence score components"""
    tool_confidence: float = 0.0  # Tool's inherent reliability
    payload_confidence: float = 0.0  # Payload success indicators
    corroboration_bonus: float = 0.0  # Multiple tools agree
    context_penalty: float = 0.0  # Negative adjustments
    final_score: float = 0.0  # 0-100
    
    def to_dict(self) -> Dict:
        return {
            "tool_confidence": round(self.tool_confidence, 2),
            "payload_confidence": round(self.payload_confidence, 2),
            "corroboration_bonus": round(self.corroboration_bonus, 2),
            "context_penalty": round(self.context_penalty, 2),
            "final_score": round(self.final_score, 2)
        }


class EnhancedConfidenceEngine:
    """
    Multi-factor confidence scoring
    
    Factors:
    1. Tool Confidence (0-40 points)
       - Tool reliability rating
       - False positive history
    
    2. Payload Confidence (0-40 points)
       - Evidence strength
       - Response analysis
       - Crawler depth
    
    3. Corroboration Bonus (0-30 points)
       - Multiple tools find same vuln
       - Different techniques confirm
    
    4. Context Penalties (-20 to 0 points)
       - Weak evidence
       - Partial failures
       - Crawler missed context
    
    Final Score: 0-100
    - 80-100: High confidence
    - 60-79: Medium confidence
    - 40-59: Low confidence
    - 0-39: Very low confidence
    """
    
    # Tool confidence ratings (0.0-1.0)
    TOOL_CONFIDENCE = {
        "nuclei": 0.9,
        "nmap_vuln": 0.85,
        "dalfox": 0.85,
        "sqlmap": 0.9,
        "commix": 0.8,
        "xsstrike": 0.75,
        "testssl": 0.9,
        "sslscan": 0.85,
        "whatweb": 0.7,
        "default": 0.6
    }
    
    def __init__(self, endpoint_graph=None):
        self.graph = endpoint_graph
    
    def calculate_confidence(
        self,
        finding_type: str,
        tool_name: str,
        crawler_depth: int = 0,
        payload_confirmed: bool = False,
        evidence: Optional[str] = None,
        endpoint: Optional[str] = None,
        corroborating_tools: Optional[List[str]] = None,
        crawler_verified: bool = False,
        payload_attempts: int = 0,
        successful_payloads: int = 0,
    ) -> ConfidenceFactors:
        """
        Calculate multi-factor confidence score
        
        Args:
            finding_type: Type of vulnerability
            tool_name: Tool that found it
            evidence: Evidence string
            endpoint: Target endpoint
            corroborating_tools: Other tools that found same vuln
            crawler_verified: Did crawler verify this endpoint?
            payload_attempts: Number of payloads tried
            successful_payloads: Number that succeeded
            
        Returns:
            ConfidenceFactors with breakdown
        """
        factors = ConfidenceFactors()
        
        # 1. Tool Confidence (0-40 points)
        tool_rating = self.TOOL_CONFIDENCE.get(tool_name, self.TOOL_CONFIDENCE["default"])
        factors.tool_confidence = tool_rating * 40
        
        # 2. Payload Confidence (0-40 points)
        payload_score = 0.0
        
        # Evidence strength
        if evidence:
            if len(evidence) > 100:
                payload_score += 15  # Strong evidence
            elif len(evidence) > 20:
                payload_score += 10  # Moderate evidence
            else:
                payload_score += 5  # Weak evidence
        
        # Crawler verification
        if crawler_verified:
            payload_score += 10
        elif self.graph and endpoint:
            ep = self.graph.get_endpoint(endpoint)
            if ep and ep.status_code == 200:
                payload_score += 5
        
        # Payload success rate
        if payload_attempts > 0:
            success_rate = successful_payloads / payload_attempts
            payload_score += success_rate * 15
        
        factors.payload_confidence = min(payload_score, 40)
        
        # 3. Corroboration Bonus (0-30 points)
        if corroborating_tools:
            # Multiple tools = higher confidence
            num_tools = len(corroborating_tools) + 1  # +1 for primary tool
            if num_tools >= 3:
                factors.corroboration_bonus = 30
            elif num_tools == 2:
                factors.corroboration_bonus = 20
            else:
                factors.corroboration_bonus = 10
        
        # 4. Context Penalties
        penalty = 0.0
        
        # No crawler verification for payload finding
        if finding_type in ["xss", "sql_injection", "command_injection"] and not crawler_verified:
            penalty += 10
        
        # Weak evidence
        if evidence and len(evidence) < 20:
            penalty += 5
        
        factors.context_penalty = -penalty
        
        # Final score (0-100)
        factors.final_score = max(0, min(100, 
            factors.tool_confidence + 
            factors.payload_confidence + 
            factors.corroboration_bonus + 
            factors.context_penalty
        ))
        
        return factors
    
    def get_confidence_label(self, score: float) -> str:
        """Get confidence label for score"""
        if score >= 80:
            return "High"
        elif score >= 60:
            return "Medium"
        elif score >= 40:
            return "Low"
        else:
            return "Very Low"
    
    def calculate_finding_confidence(self, finding: Dict) -> float:
        """
        Calculate confidence for a finding dict
        
        Args:
            finding: Finding dictionary with tool, type, evidence, etc.
            
        Returns:
            Confidence score (0-100)
        """
        factors = self.calculate_confidence(
            finding_type=finding.get("type", ""),
            tool_name=finding.get("tool", "unknown"),
            evidence=finding.get("evidence", ""),
            endpoint=finding.get("location", ""),
            corroborating_tools=finding.get("corroborating_tools", []),
            crawler_verified=finding.get("crawler_verified", False)
        )
        
        return factors.final_score
