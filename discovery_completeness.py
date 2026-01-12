"""
Discovery Completeness Evaluator - Phase 1 Hardening
Purpose: Evaluate if discovery phase gathered sufficient signals
"""

import logging
from typing import Dict, List, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class CompletenessReport:
    """Discovery completeness assessment"""
    complete: bool
    missing_signals: List[str] = field(default_factory=list)
    present_signals: List[str] = field(default_factory=list)
    completeness_score: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "complete": self.complete,
            "missing_signals": self.missing_signals,
            "present_signals": self.present_signals,
            "completeness_score": self.completeness_score,
            "recommendations": self.recommendations
        }


class DiscoveryCompletenessEvaluator:
    """
    Evaluates discovery phase completeness
    
    Critical Signals (MUST have):
    - dns_resolved: Can we resolve the target?
    - reachable: Is the target network-reachable?
    - web_target: Is this a web target?
    
    Important Signals (SHOULD have for web targets):
    - https: HTTPS availability known?
    - ports_known: Port scan completed?
    - endpoints_known: Endpoints discovered?
    """
    
    # Critical signals (mandatory)
    CRITICAL_SIGNALS = {
        "dns_resolved",
        "reachable",
        "web_target",
    }
    
    # Important signals (strongly recommended for web targets)
    IMPORTANT_SIGNALS = {
        "https",
        "ports_known",
        "tech_stack",
    }
    
    # Optional signals (nice-to-have)
    OPTIONAL_SIGNALS = {
        "endpoints_known",
        "subdomains",
        "ssl_vulnerabilities",
        "service_versions",
    }
    
    def __init__(self, cache, profile):
        """
        Args:
            cache: DiscoveryCache instance
            profile: TargetProfile instance
        """
        self.cache = cache
        self.profile = profile
    
    def evaluate(self) -> CompletenessReport:
        """
        Evaluate discovery completeness
        
        Returns:
            CompletenessReport
        """
        present = self._detect_present_signals()
        missing_critical = self.CRITICAL_SIGNALS - present
        missing_important = self.IMPORTANT_SIGNALS - present
        
        # Critical signals missing = INCOMPLETE
        if missing_critical:
            return CompletenessReport(
                complete=False,
                missing_signals=sorted(list(missing_critical | missing_important)),
                present_signals=sorted(list(present)),
                completeness_score=len(present) / (len(self.CRITICAL_SIGNALS) + len(self.IMPORTANT_SIGNALS)),
                recommendations=self._generate_recommendations(missing_critical, missing_important)
            )
        
        # All critical present, some important missing = PARTIAL
        if missing_important and self.profile.is_web_target:
            score = len(present) / (len(self.CRITICAL_SIGNALS) + len(self.IMPORTANT_SIGNALS))
            return CompletenessReport(
                complete=(score >= 0.7),  # 70% threshold for web targets
                missing_signals=sorted(list(missing_important)),
                present_signals=sorted(list(present)),
                completeness_score=score,
                recommendations=self._generate_recommendations(set(), missing_important)
            )
        
        # All critical and important present = COMPLETE
        return CompletenessReport(
            complete=True,
            missing_signals=[],
            present_signals=sorted(list(present)),
            completeness_score=1.0,
            recommendations=[]
        )
    
    def _detect_present_signals(self) -> set:
        """Detect which signals are present in cache"""
        signals = set()
        
        # DNS resolved?
        if hasattr(self.cache, 'discovered_ports') and len(self.cache.discovered_ports) > 0:
            signals.add("dns_resolved")
        if hasattr(self.profile, 'host') and self.profile.host:
            signals.add("dns_resolved")
        
        # Reachable?
        if hasattr(self.cache, 'live_endpoints') and len(self.cache.live_endpoints) > 0:
            signals.add("reachable")
        if hasattr(self.cache, 'discovered_ports') and len(self.cache.discovered_ports) > 0:
            signals.add("reachable")
        
        # Web target?
        if self.profile.is_web_target:
            signals.add("web_target")
        
        # HTTPS?
        if self.profile.is_https is not None:
            signals.add("https")
        
        # Ports known?
        if hasattr(self.cache, 'discovered_ports') and len(self.cache.discovered_ports) > 0:
            signals.add("ports_known")
        
        # Tech stack?
        if hasattr(self.profile, 'detected_tech') and self.profile.detected_tech:
            signals.add("tech_stack")
        if hasattr(self.profile, 'detected_cms') and self.profile.detected_cms:
            signals.add("tech_stack")
        
        # Endpoints known?
        if hasattr(self.cache, 'endpoints') and len(self.cache.endpoints) > 0:
            signals.add("endpoints_known")
        
        # Subdomains?
        if hasattr(self.cache, 'subdomains') and len(self.cache.subdomains) > 0:
            signals.add("subdomains")
        
        return signals
    
    def _generate_recommendations(self, missing_critical: set, missing_important: set) -> List[str]:
        """Generate recommendations for missing signals"""
        recommendations = []
        
        if "dns_resolved" in missing_critical:
            recommendations.append("DNS resolution failed - verify target is valid")
        
        if "reachable" in missing_critical:
            recommendations.append("Target unreachable - check network connectivity or firewall rules")
        
        if "https" in missing_important and self.profile.is_web_target:
            recommendations.append("Run sslscan or testssl to determine HTTPS availability")
        
        if "ports_known" in missing_important:
            recommendations.append("Run nmap_quick to discover open ports")
        
        if "tech_stack" in missing_important and self.profile.is_web_target:
            recommendations.append("Run whatweb to identify web technologies")
        
        return recommendations
    
    def log_report(self, report: CompletenessReport):
        """Log completeness report"""
        if report.complete:
            logger.info(f"[DiscoveryCompleteness] ✓ COMPLETE ({report.completeness_score:.0%})")
        else:
            logger.warning(f"[DiscoveryCompleteness] ⚠ INCOMPLETE ({report.completeness_score:.0%})")
            logger.warning(f"[DiscoveryCompleteness] Missing: {', '.join(report.missing_signals)}")
        
        if report.recommendations:
            logger.info("[DiscoveryCompleteness] Recommendations:")
            for rec in report.recommendations:
                logger.info(f"  - {rec}")
