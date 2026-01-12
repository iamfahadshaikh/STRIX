"""
Confidence Engine - Phase 2
Purpose: Score findings confidence LOW/MEDIUM/HIGH based on:
  - Signal count (more signals = higher confidence)
  - Tool agreement (multiple tools = higher confidence)
  - Payload success rate (successful exploitation = higher confidence)
  - Parameter repetition (appears multiple times = higher confidence)
  - Source strength (crawler > heuristic > guess)
"""

import logging
from enum import Enum
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class Confidence(Enum):
    """Finding confidence level"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class ConfidenceSignal:
    """Individual piece of evidence for confidence"""
    signal_type: str  # "tool_agreement", "payload_success", "param_repetition", "source_strength"
    tool: str  # Tool that produced signal
    weight: float  # 0.0-1.0
    evidence: str  # Human-readable evidence


class ConfidenceEngine:
    """
    Score findings confidence based on signals.
    
    Scoring model:
    - 0.0-0.33: LOW confidence (single tool, weak evidence)
    - 0.33-0.66: MEDIUM confidence (multiple signals, tool agreement)
    - 0.66-1.0: HIGH confidence (payload success, multiple tools, strong evidence)
    """

    # Tool weights (trust level)
    TOOL_WEIGHT = {
        "dalfox": 0.9,      # JS-aware XSS testing
        "xsstrike": 0.8,    # Payload-heavy XSS
        "sqlmap": 0.95,     # Authoritative SQL injection
        "commix": 0.85,     # Good command injection
        "nuclei": 0.7,      # Template-based (can be high false positive)
        "whatweb": 0.6,     # Fingerprinting (informational)
        "nikto": 0.65,      # Web server scanning
        "nmap": 0.75,       # Network scanning (when service identified)
        "testssl": 0.7,     # SSL/TLS scanning
        "crawler": 0.5,     # Discovery only (no exploitation)
    }

    # Source weights
    SOURCE_WEIGHT = {
        "crawled": 0.9,           # From actual crawl
        "form_input": 0.85,       # From form
        "url_query": 0.75,        # From URL
        "js_detected": 0.8,       # JS-rendered
        "heuristic": 0.5,         # Guessed
        "pattern_match": 0.6,     # Pattern-matched
        "manual": 0.8,            # Manual testing
    }

    # Payload success weights
    PAYLOAD_SUCCESS = {
        "confirmed_reflected": 1.0,    # We see our payload reflected
        "confirmed_executed": 1.0,     # We see command output
        "time_delayed": 0.9,           # Time-based confirmation
        "oob_confirmed": 0.95,         # Out-of-band confirmed
        "successful_injection": 0.9,   # Tool reports success
        "error_based": 0.75,           # Error-based detection
        "boolean_based": 0.7,          # Boolean-based inference
        "potential_vulnerability": 0.5, # Tool suspects vulnerability
        "configuration_issue": 0.4,    # Config issue detected
    }

    def __init__(self):
        self.signals: Dict[str, List[ConfidenceSignal]] = {}  # finding_id -> [signals]

    def add_signal(self, finding_id: str, signal: ConfidenceSignal):
        """Add confidence signal to finding"""
        if finding_id not in self.signals:
            self.signals[finding_id] = []
        self.signals[finding_id].append(signal)

    def score_finding(self, finding_id: str, 
                     tools_reporting: List[str],
                     success_indicator: Optional[str] = None,
                     source_type: str = "crawled",
                     param_frequency: int = 1) -> Confidence:
        """
        Score finding confidence
        
        Args:
            finding_id: Unique finding ID
            tools_reporting: List of tools that reported this finding
            success_indicator: Type of success (confirmed_reflected, etc)
            source_type: How parameter was discovered
            param_frequency: How many times parameter appeared
            
        Returns:
            Confidence level (LOW/MEDIUM/HIGH)
        """
        if not finding_id or not tools_reporting:
            return Confidence.LOW

        score = 0.0
        signal_count = 0

        # 1. Tool agreement weight (higher with multiple tools)
        tool_weights = [self.TOOL_WEIGHT.get(t, 0.6) for t in tools_reporting]
        avg_tool_weight = sum(tool_weights) / len(tool_weights) if tool_weights else 0.6
        
        # Bonus for multiple tools
        tool_agreement_weight = avg_tool_weight
        if len(tools_reporting) > 1:
            tool_agreement_weight *= 1.2  # 20% bonus for multiple tools
        if len(tools_reporting) > 2:
            tool_agreement_weight *= 1.15  # Additional 15% for 3+ tools
        
        tool_agreement_weight = min(tool_agreement_weight, 1.0)
        score += tool_agreement_weight * 0.35  # 35% of score
        signal_count += len(tools_reporting)

        # 2. Source strength weight
        source_weight = self.SOURCE_WEIGHT.get(source_type, 0.5)
        score += source_weight * 0.25  # 25% of score
        signal_count += 1

        # 3. Success indicator weight
        if success_indicator:
            success_weight = self.PAYLOAD_SUCCESS.get(success_indicator, 0.3)
            score += success_weight * 0.30  # 30% of score
            signal_count += 1

        # 4. Parameter frequency weight
        if param_frequency > 1:
            freq_weight = min(0.2 + (param_frequency * 0.05), 0.5)
            score += freq_weight * 0.10  # 10% of score
            signal_count += 1

        # Score is already normalized (0-1 range from percentages)
        # No additional normalization needed

        # Classification
        if score >= 0.66:
            return Confidence.HIGH
        elif score >= 0.33:
            return Confidence.MEDIUM
        else:
            return Confidence.LOW

    def batch_score(self, findings: List[Dict]) -> Dict[str, Confidence]:
        """
        Score multiple findings at once
        
        Args:
            findings: List of finding dicts with:
              - id: unique ID
              - tools: list of tools reporting
              - success: success indicator (optional)
              - source: source type
              - frequency: param frequency
              
        Returns:
            Dict[finding_id -> Confidence]
        """
        results = {}
        for finding in findings:
            conf = self.score_finding(
                finding.get("id"),
                finding.get("tools", []),
                finding.get("success"),
                finding.get("source", "crawled"),
                finding.get("frequency", 1)
            )
            results[finding["id"]] = conf
        return results

    def explain_confidence(self, finding_id: str, confidence: Confidence) -> str:
        """Generate human-readable explanation of confidence score"""
        if finding_id not in self.signals:
            return "No signals recorded"

        signals = self.signals[finding_id]
        if not signals:
            return "No signals recorded"

        explanations = []
        for signal in signals:
            explanations.append(f"  - {signal.signal_type}: {signal.evidence} (tool: {signal.tool}, weight: {signal.weight:.2f})")

        summary = f"Confidence: {confidence.value}\n"
        summary += "Signals:\n"
        summary += "\n".join(explanations)
        return summary

    @staticmethod
    def get_confidence_recommendations(confidence: Confidence) -> str:
        """Get remediation urgency based on confidence"""
        if confidence == Confidence.HIGH:
            return "IMMEDIATE ACTION REQUIRED: Vulnerability confirmed with high confidence"
        elif confidence == Confidence.MEDIUM:
            return "INVESTIGATE: Multiple signals suggest vulnerability; manual testing recommended"
        else:
            return "LOW PRIORITY: Manual verification recommended before remediation"


# Example usage
"""
engine = ConfidenceEngine()

# Simple finding: dalfox detected XSS
conf1 = engine.score_finding(
    finding_id="xss_001",
    tools_reporting=["dalfox"],
    success_indicator="confirmed_reflected",
    source_type="crawled"
)
print(f"XSS (1 tool): {conf1}")  # Likely HIGH (confirmed reflected)

# Multi-tool finding: both dalfox and xsstrike agree
conf2 = engine.score_finding(
    finding_id="xss_002",
    tools_reporting=["dalfox", "xsstrike"],
    success_indicator="confirmed_executed",
    source_type="form_input",
    param_frequency=2
)
print(f"XSS (2 tools, confirmed): {conf2}")  # HIGH

# Single tool, weak signal
conf3 = engine.score_finding(
    finding_id="xss_003",
    tools_reporting=["nuclei"],
    success_indicator="potential_vulnerability",
    source_type="pattern_match"
)
print(f"XSS (nuclei, potential): {conf3}")  # MEDIUM or LOW

# Batch scoring
findings = [
    {"id": "xss_001", "tools": ["dalfox"], "success": "confirmed_reflected", "source": "crawled"},
    {"id": "xss_002", "tools": ["dalfox", "xsstrike"], "success": "confirmed_executed", "source": "form_input", "frequency": 2},
    {"id": "sqli_001", "tools": ["sqlmap"], "success": "confirmed_executed", "source": "url_query"},
]

results = engine.batch_score(findings)
for finding_id, conf in results.items():
    print(f"{finding_id}: {conf.value}")
    print(engine.get_confidence_recommendations(conf))
"""
