"""
STRICT EXECUTION HANDLER — Fail-fast enforcement for weak discovery states.

Purpose: Abort exploitation phase if discovery hasn't gathered enough signals.
No fake success states. If JS discovery = 0, if params = 0, if API calls = 0 → ABORT.
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
    1. controllable_params == 0 (no injection targets)
    2. endpoints == 0 (no targets at all)
    3. api_endpoints == 0 AND js_calls == 0 (no API discovery)
    4. ALL discovery sources failed (crawler, JS, ZAP)
    5. quality == FAILED (not enough signals)
    
    WARN if:
    - quality == WEAK (but continue with caution)
    - js_discovery failed (use HTTP discovery only)
    - Crawler failed (but ZAP/JS succeeded)
    
    PROCEED if:
    - quality >= ACCEPTABLE (at least minimal signals)
    - At least one discovery source succeeded
    """
    
    # Hard thresholds
    MIN_ENDPOINTS_FOR_EXPLOITATION = 1
    MIN_CONTROLLABLE_PARAMS = 0  # If 0, check other signals
    MIN_API_OR_JS_SIGNALS = 1  # At least one of: API endpoints or JS calls
    
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
        
        # Check 1: Endpoints
        if discovery_state.endpoints_count < self.MIN_ENDPOINTS_FOR_EXPLOITATION:
            reason = f"Zero endpoints discovered"
            checks.append((False, reason))
            logger.critical(f"[{phase_name}] ABORT: {reason}")
            return False, reason
        else:
            checks.append((True, f"Endpoints: {discovery_state.endpoints_count}"))
        
        # Check 2: Controllable parameters (allow 0 if other signals present)
        if discovery_state.controllable_params_count == 0:
            # Check if we have API or JS signals
            has_api_or_js = (discovery_state.api_endpoints_count > 0 or
                            discovery_state.js_network_calls_captured > 0)
            
            if not has_api_or_js:
                reason = "Zero controllable params AND no API/JS signals"
                checks.append((False, reason))
                logger.critical(f"[{phase_name}] ABORT: {reason}")
                return False, reason
            else:
                checks.append((True, f"Params: 0, but API/JS signals present"))
        else:
            checks.append((True, f"Controllable params: {discovery_state.controllable_params_count}"))
        
        # Check 3: Overall discovery quality
        if discovery_state.quality == DiscoveryQuality.FAILED:
            reason = f"Discovery quality FAILED: insufficient signals from all sources"
            checks.append((False, reason))
            logger.critical(f"[{phase_name}] ABORT: {reason}")
            return False, reason
        elif discovery_state.quality == DiscoveryQuality.WEAK:
            reason = f"Discovery quality WEAK: {discovery_state.quality.value}"
            logger.warning(f"[{phase_name}] WARNING: {reason} (proceeding with caution)")
            checks.append((True, reason))
        else:
            checks.append((True, f"Discovery quality: {discovery_state.quality.value}"))
        
        # Check 4: At least one discovery source
        sources_ok = [
            ("Crawler", discovery_state.crawler_success),
            ("JS Discovery", discovery_state.js_discovery_success),
            ("ZAP", discovery_state.zap_endpoints_count > 0),
        ]
        
        successful_sources = [name for name, success in sources_ok if success]
        if not successful_sources:
            reason = "No discovery sources succeeded (Crawler, JS, ZAP all failed)"
            checks.append((False, reason))
            logger.critical(f"[{phase_name}] ABORT: {reason}")
            return False, reason
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
