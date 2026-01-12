"""
Intelligence Layer for Phase 2B implementation.

Provides confidence scoring, evidence correlation, false positive filtering,
exploitability assessment, and attack surface quantification.
"""

from typing import List, Dict, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field
from findings_model import Finding, FindingType, Severity


@dataclass
class ConfidenceScore:
    """Confidence assessment for a finding."""
    score: float  # 0.0-1.0
    confirming_tools: List[str]
    evidence_count: int
    reasoning: str


@dataclass
class CorrelatedFinding:
    """A finding confirmed by multiple tools with correlation data."""
    primary_finding: Finding
    confidence: ConfidenceScore
    related_findings: List[Finding] = field(default_factory=list)
    exploitability: str = "UNKNOWN"  # LOW, MEDIUM, HIGH, CRITICAL
    attack_surface_score: float = 0.0


class IntelligenceEngine:
    """
    Analyzes findings to provide actionable intelligence.
    
    Phase 2B capabilities:
    - Confidence scoring (single vs multi-tool confirmation)
    - Evidence correlation (3 tools find same vuln = high confidence)
    - False positive filtering (noise patterns, CDN/WAF)
    - Exploitability assessment
    - Attack surface quantification
    """
    
    def __init__(self):
        self.noise_patterns = self._load_noise_patterns()
        self.cdn_indicators = ['cloudflare', 'akamai', 'fastly', 'cloudfront']
        self.waf_indicators = ['modsecurity', 'imperva', 'f5', 'barracuda']
    
    def _load_noise_patterns(self) -> Set[str]:
        """Known false positive patterns."""
        return {
            'test page',
            'default installation',
            'sample application',
            'coming soon',
            'under construction',
            'placeholder',
        }
    
    def calculate_confidence(self, finding: Finding, all_findings: List[Finding]) -> ConfidenceScore:
        """
        Calculate confidence score for a finding.
        
        Factors:
        - Tool reputation (some tools have lower FP rates)
        - Multi-tool confirmation
        - Evidence quality
        - Noise filtering
        """
        confirming_tools = [finding.tool]
        evidence_count = 1
        
        # Find related findings (same type, similar location)
        for other in all_findings:
            if other == finding:
                continue
            
            if (other.type == finding.type and 
                self._locations_match(finding.location, other.location)):
                confirming_tools.append(other.tool)
                evidence_count += 1
        
        # Base score from tool reputation
        tool_reputation = {
            'nuclei': 0.9,
            'sqlmap': 0.95,
            'nmap': 0.85,
            'testssl': 0.9,
            'dalfox': 0.85,
            'nikto': 0.7,  # Higher FP rate
            'xsstrike': 0.75,
            'commix': 0.85,
        }
        base_score = tool_reputation.get(finding.tool, 0.6)
        
        # Boost for multi-tool confirmation
        if len(set(confirming_tools)) > 1:
            base_score = min(1.0, base_score + 0.1 * (len(set(confirming_tools)) - 1))
        
        # Penalty for noise patterns
        if any(noise in finding.description.lower() for noise in self.noise_patterns):
            base_score *= 0.5
        
        # Boost for critical severity
        if finding.severity == Severity.CRITICAL:
            base_score = min(1.0, base_score + 0.05)
        
        reasoning = f"Confirmed by {len(set(confirming_tools))} tool(s)"
        if len(set(confirming_tools)) > 1:
            reasoning += f" ({', '.join(set(confirming_tools))})"
        
        return ConfidenceScore(
            score=base_score,
            confirming_tools=list(set(confirming_tools)),
            evidence_count=evidence_count,
            reasoning=reasoning
        )
    
    def _locations_match(self, loc1: str, loc2: str) -> bool:
        """Check if two locations refer to the same endpoint/parameter."""
        # Normalize URLs
        loc1_clean = loc1.split('?')[0].rstrip('/')
        loc2_clean = loc2.split('?')[0].rstrip('/')
        
        # Exact match or one is substring of other
        return loc1_clean == loc2_clean or loc1_clean in loc2_clean or loc2_clean in loc1_clean
    
    def correlate_findings(self, findings: List[Finding]) -> List[CorrelatedFinding]:
        """
        Correlate findings from multiple tools.
        
        Groups related findings and calculates aggregate confidence.
        """
        correlated = []
        processed = set()
        
        for finding in findings:
            if id(finding) in processed:
                continue
            
            # Find all related findings
            related = []
            for other in findings:
                if other == finding or id(other) in processed:
                    continue
                
                if (other.type == finding.type and 
                    self._locations_match(finding.location, other.location)):
                    related.append(other)
                    processed.add(id(other))
            
            # Calculate confidence
            all_related = [finding] + related
            confidence = self.calculate_confidence(finding, all_related)
            
            # Assess exploitability
            exploitability = self._assess_exploitability(finding, related)
            
            # Calculate attack surface
            attack_surface = self._quantify_attack_surface(finding, related)
            
            correlated.append(CorrelatedFinding(
                primary_finding=finding,
                confidence=confidence,
                related_findings=related,
                exploitability=exploitability,
                attack_surface_score=attack_surface
            ))
            
            processed.add(id(finding))
        
        return correlated
    
    def filter_false_positives(self, findings: List) -> List:
        """
        Filter out likely false positives.
        
        Removes:
        - Noise patterns (test pages, defaults)
        - CDN/WAF artifacts
        - Low-confidence single-tool findings
        """
        filtered = []
        
        for finding in findings:
            # Handle both dict and Finding objects
            desc = finding.get("description", "") if isinstance(finding, dict) else finding.description
            evidence = finding.get("evidence", "") if isinstance(finding, dict) else finding.evidence
            severity = finding.get("severity", "") if isinstance(finding, dict) else finding.severity
            tool = finding.get("tool", "") if isinstance(finding, dict) else finding.tool
            
            # Check noise patterns
            if any(noise in desc.lower() for noise in self.noise_patterns):
                continue
            
            # Check CDN indicators (may be CDN config, not target)
            if any(cdn in evidence.lower() for cdn in self.cdn_indicators):
                # Don't skip critical findings even if CDN detected
                if severity not in ["CRITICAL", "HIGH", Severity.CRITICAL, Severity.HIGH]:
                    continue
            
            # Check WAF indicators
            if any(waf in evidence.lower() for waf in self.waf_indicators):
                # WAF-blocked requests are FPs
                if 'blocked' in evidence.lower():
                    continue
            
            # Low severity + single tool = likely FP
            if severity in ["LOW", Severity.LOW] and tool in ['nikto', 'whatweb']:
                continue
            
            filtered.append(finding)
        
        return filtered
    
    def _assess_exploitability(self, finding: Finding, related: List[Finding]) -> str:
        """
        Assess how exploitable a vulnerability is.
        
        Factors:
        - Type of vulnerability
        - Authentication requirements
        - Public exploits available
        - Network accessibility
        """
        # Critical types are highly exploitable
        if finding.type in [FindingType.SQLI, FindingType.COMMAND_INJECTION, FindingType.XXE]:
            return "CRITICAL"
        
        # XSS/SSRF are high
        if finding.type in [FindingType.XSS, FindingType.SSRF]:
            return "HIGH"
        
        # Info disclosure + auth bypass = critical
        if finding.type == FindingType.AUTH_BYPASS:
            return "CRITICAL"
        
        # Misconfigurations vary
        if finding.type == FindingType.MISCONFIGURATION:
            # Admin panels, debug endpoints = high
            if any(keyword in finding.description.lower() 
                   for keyword in ['admin', 'debug', 'phpinfo', '.git', '.env']):
                return "HIGH"
            return "MEDIUM"
        
        # Weak crypto/outdated software
        if finding.type in [FindingType.WEAK_CRYPTO, FindingType.OUTDATED_SOFTWARE]:
            if finding.severity == Severity.CRITICAL:
                return "HIGH"
            return "MEDIUM"
        
        return "MEDIUM"
    
    def _quantify_attack_surface(self, finding: Finding, related: List[Finding]) -> float:
        """
        Quantify attack surface exposed by this finding.
        
        Score: 0.0-10.0
        
        Factors:
        - Number of affected endpoints
        - Number of injectable parameters
        - Authentication requirements
        - Network exposure
        """
        score = 0.0
        
        # Base score by type
        type_scores = {
            FindingType.SQLI: 8.0,
            FindingType.COMMAND_INJECTION: 9.0,
            FindingType.XSS: 6.0,
            FindingType.SSRF: 7.0,
            FindingType.AUTH_BYPASS: 9.0,
            FindingType.MISCONFIGURATION: 5.0,
            FindingType.INFO_DISCLOSURE: 4.0,
            FindingType.WEAK_CRYPTO: 5.0,
        }
        score += type_scores.get(finding.type, 3.0)
        
        # Multiple related findings = larger surface
        score += min(2.0, len(related) * 0.5)
        
        # Unauthenticated = higher surface
        if 'auth' not in finding.description.lower():
            score += 1.0
        
        # Public-facing (not localhost/internal)
        if not any(internal in finding.location.lower() 
                  for internal in ['localhost', '127.0.0.1', '192.168', '10.', '172.']):
            score += 1.0
        
        return min(10.0, score)
    
    def prioritize_findings(self, correlated: List[CorrelatedFinding]) -> List[CorrelatedFinding]:
        """
        Prioritize findings for remediation.
        
        Sort by:
        1. Exploitability (CRITICAL > HIGH > MEDIUM > LOW)
        2. Confidence score
        3. Attack surface
        4. Severity
        """
        exploit_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'UNKNOWN': 0}
        
        return sorted(
            correlated,
            key=lambda cf: (
                -exploit_order.get(cf.exploitability, 0),
                -cf.confidence.score,
                -cf.attack_surface_score,
                -['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(cf.primary_finding.severity.value)
            )
        )
    
    def generate_intelligence_report(self, correlated: List[CorrelatedFinding]) -> Dict:
        """
        Generate intelligence summary.
        
        Returns actionable intelligence with prioritization.
        """
        prioritized = self.prioritize_findings(correlated)
        
        # Group by exploitability
        by_exploitability = defaultdict(list)
        for cf in prioritized:
            by_exploitability[cf.exploitability].append(cf)
        
        # Top 10 most critical
        top_critical = prioritized[:10]
        
        # Attack surface summary
        total_surface = sum(cf.attack_surface_score for cf in correlated)
        avg_confidence = sum(cf.confidence.score for cf in correlated) / len(correlated) if correlated else 0
        
        return {
            'total_findings': len(correlated),
            'high_confidence': len([cf for cf in correlated if cf.confidence.score >= 0.8]),
            'multi_tool_confirmed': len([cf for cf in correlated if len(cf.confidence.confirming_tools) > 1]),
            'by_exploitability': {
                exploit: len(findings) 
                for exploit, findings in by_exploitability.items()
            },
            'top_10_critical': [
                {
                    'type': cf.primary_finding.type.value,
                    'severity': cf.primary_finding.severity.value,
                    'location': cf.primary_finding.location,
                    'confidence': cf.confidence.score,
                    'exploitability': cf.exploitability,
                    'tools': cf.confidence.confirming_tools,
                    'description': cf.primary_finding.description,
                }
                for cf in top_critical
            ],
            'attack_surface': {
                'total_score': round(total_surface, 2),
                'average_per_finding': round(total_surface / len(correlated), 2) if correlated else 0,
            },
            'confidence_stats': {
                'average': round(avg_confidence, 2),
                'high_confidence_ratio': round(
                    len([cf for cf in correlated if cf.confidence.score >= 0.8]) / len(correlated), 2
                ) if correlated else 0,
            }
        }
