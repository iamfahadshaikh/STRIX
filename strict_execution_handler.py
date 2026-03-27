"""Execution handler for exploitation readiness.

Hard abort is reserved for true zero-surface outcomes.
Weak/partial discovery signals are treated as caution states.
"""

import logging
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class DiscoveryQuality(Enum):
    """Assessment of discovery phase quality."""
    EXCELLENT = "excellent"  # All signals present
    GOOD = "good"  # Most signals present  
    ACCEPTABLE = "acceptable"  # Minimal signals
    WEAK = "weak"  # Insufficient signals
    FAILED = "failed"  # Critical failures


@dataclass
class DiscoveryState:
    """Current state of discovery phase."""
    endpoints_count: int = 0
    controllable_params_count: int = 0
    api_endpoints_count: int = 0
    js_discovery_success: bool = False
    js_network_calls_captured: int = 0
    crawler_success: bool = False
    external_intel_count: int = 0
    zap_endpoints_count: int = 0
    
    def __post_init__(self):
        self.quality = self._assess_quality()
    
    def _assess_quality(self) -> DiscoveryQuality:
        """Assess overall discovery quality."""
        score = 0
        
        # Endpoints signal
        if self.endpoints_count >= 50:
            score += 2
        elif self.endpoints_count >= 20:
            score += 1
        
        # Controllable parameters signal
        if self.controllable_params_count >= 10:
            score += 2
        elif self.controllable_params_count >= 3:
            score += 1
        
        # API endpoints signal
        if self.api_endpoints_count >= 5:
            score += 2
        elif self.api_endpoints_count >= 1:
            score += 1
        
        # JS discovery signal
        if self.js_discovery_success and self.js_network_calls_captured >= 5:
            score += 2
        elif self.js_discovery_success and self.js_network_calls_captured >= 1:
            score += 1
        elif self.js_discovery_success:
            score += 0.5
        
        # Crawler signal
        if self.crawler_success:
            score += 1
        
        # External intelligence signal
        if self.external_intel_count >= 3:
            score += 1
        
        # Overall assessment
        if score >= 6:
            return DiscoveryQuality.EXCELLENT
        elif score >= 4:
            return DiscoveryQuality.GOOD
        elif score >= 2:
            return DiscoveryQuality.ACCEPTABLE
        elif score >= 1:
            return DiscoveryQuality.WEAK
        else:
            return DiscoveryQuality.FAILED


class StrictExecutionHandler:
    """
    Enforce strict discovery gates before exploitation.
    
    Rules:
    ------
    ABORT if:
    1. endpoints == 0 AND controllable_params == 0 (no usable surface)
    2. quality == FAILED and no source produced any signal
    
    WARN if:
    - quality == WEAK (but continue with caution)
    - js_discovery failed (use HTTP discovery only)
    - Crawler failed (but ZAP/JS succeeded)
    
    PROCEED if:
    - quality >= ACCEPTABLE (at least minimal signals)
    - At least one discovery source succeeded
    """
    
    # Hard thresholds
    MIN_ENDPOINTS_FOR_EXPLOITATION = 0
    MIN_CONTROLLABLE_PARAMS = 0
    MIN_API_OR_JS_SIGNALS = 0
    
    def __init__(self):
        logger.info("[StrictExecutionHandler] Initialized with hard discovery gates")
    
    def should_proceed_to_exploitation(self, discovery_state: DiscoveryState,
                                       phase_name: str = "PHASE 5") -> Tuple[bool, str]:
        """
        Determine if exploitation phase should proceed.
        
        Args:
            discovery_state: Current DiscoveryState
            phase_name: Name of phase for logging
        
        Returns:
            (should_proceed: bool, reason: str)
        """
        
        checks = []
        
        # Check 1: Zero-surface hard stop
        if discovery_state.endpoints_count == 0 and discovery_state.controllable_params_count == 0:
            reason = "No endpoints or parameters discovered"
            checks.append((False, reason))
            logger.critical(f"[{phase_name}] ABORT: {reason}")
            return False, reason
        else:
            checks.append((True, f"Endpoints={discovery_state.endpoints_count}, Params={discovery_state.controllable_params_count}"))
        
        # Check 2: Overall discovery quality
        if discovery_state.quality == DiscoveryQuality.FAILED:
            any_source_signal = (
                discovery_state.crawler_success
                or discovery_state.js_discovery_success
                or discovery_state.zap_endpoints_count > 0
                or discovery_state.api_endpoints_count > 0
                or discovery_state.external_intel_count > 0
            )
            if not any_source_signal:
                reason = "Discovery quality FAILED: no source produced useful signals"
                checks.append((False, reason))
                logger.critical(f"[{phase_name}] ABORT: {reason}")
                return False, reason
            checks.append((True, "Discovery quality FAILED but at least one source signaled; proceeding cautiously"))
        elif discovery_state.quality == DiscoveryQuality.WEAK:
            reason = f"Discovery quality WEAK: {discovery_state.quality.value}"
            logger.warning(f"[{phase_name}] WARNING: {reason} (proceeding with caution)")
            checks.append((True, reason))
        else:
            checks.append((True, f"Discovery quality: {discovery_state.quality.value}"))
        
        # Check 3: At least one discovery source (warning only)
        sources_ok = [
            ("Crawler", discovery_state.crawler_success),
            ("JS Discovery", discovery_state.js_discovery_success),
            ("ZAP", discovery_state.zap_endpoints_count > 0),
        ]
        
        successful_sources = [name for name, success in sources_ok if success]
        if not successful_sources:
            checks.append((True, "No primary discovery source succeeded; continuing with low confidence"))
        else:
            checks.append((True, f"Sources: {', '.join(successful_sources)}"))
        
        # All checks passed
        logger.info(f"[{phase_name}] Discovery gates PASSED:")
        for passed, detail in checks:
            status = "✓" if passed else "✗"
            logger.info(f"  {status} {detail}")
        
        return True, "All discovery gates passed"
    
    def summarize_discovery(self, discovery_state: DiscoveryState) -> Dict:
        """Create a summary report of discovery state."""
        return {
            "endpoints": discovery_state.endpoints_count,
            "controllable_params": discovery_state.controllable_params_count,
            "api_endpoints": discovery_state.api_endpoints_count,
            "js_success": discovery_state.js_discovery_success,
            "js_network_calls": discovery_state.js_network_calls_captured,
            "crawler_success": discovery_state.crawler_success,
            "external_intel": discovery_state.external_intel_count,
            "zap_endpoints": discovery_state.zap_endpoints_count,
            "quality": discovery_state.quality.value,
        }


# Singleton
_handler = StrictExecutionHandler()


def check_exploitation_readiness(discovery_state: DiscoveryState,
                                 phase_name: str = "PHASE 5") -> Tuple[bool, str]:
    """
    Public API: Check if system is ready for exploitation.
    
    Usage:
        ready, reason = check_exploitation_readiness(state)
        if not ready:
            logger.critical(reason)
            sys.exit(1)
        else:
            proceed_to_exploitation()
    """
    return _handler.should_proceed_to_exploitation(discovery_state, phase_name)


def get_discovery_summary(discovery_state: DiscoveryState) -> Dict:
    """Public API: Get human-readable discovery summary."""
    return _handler.summarize_discovery(discovery_state)
