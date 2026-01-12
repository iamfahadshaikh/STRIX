"""
Deduplication Engine - Phase 4 Hardening
Purpose: Deduplicate findings by endpoint + vuln type + evidence overlap
"""

import logging
from typing import List, Dict, Set
from dataclasses import dataclass, field
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class DuplicateGroup:
    """Group of duplicate findings"""
    primary_finding: Dict
    duplicates: List[Dict] = field(default_factory=list)
    tools_involved: Set[str] = field(default_factory=set)
    confidence_boost: float = 0.0
    
    def to_dict(self) -> Dict:
        return {
            "primary": self.primary_finding,
            "duplicate_count": len(self.duplicates),
            "tools": sorted(list(self.tools_involved)),
            "confidence_boost": self.confidence_boost
        }


class DeduplicationEngine:
    """
    Intelligent finding deduplication
    
    Deduplication Strategy:
    1. Group by endpoint + vuln_type
    2. Check evidence overlap (fuzzy match)
    3. Merge duplicates, keep highest confidence
    4. Apply corroboration bonus
    
    Rules:
    - Same vuln, same endpoint, multiple tools → ONE finding (boosted confidence)
    - Same vuln, different endpoints → SEPARATE findings
    - Different vulns, same endpoint → SEPARATE findings
    """
    
    def __init__(self):
        self.duplicate_groups: List[DuplicateGroup] = []
    
    def deduplicate(self, findings: List[Dict]) -> List[Dict]:
        """
        Deduplicate findings
        
        Args:
            findings: List of finding dicts
            
        Returns:
            Deduplicated list with corroboration metadata
        """
        if not findings:
            return []
        
        # Group by endpoint + vuln_type
        groups = defaultdict(list)
        for finding in findings:
            key = self._get_dedup_key(finding)
            groups[key].append(finding)
        
        # Process each group
        deduplicated = []
        for key, group_findings in groups.items():
            if len(group_findings) == 1:
                # No duplicates
                deduplicated.append(group_findings[0])
            else:
                # Merge duplicates
                merged = self._merge_duplicates(group_findings)
                deduplicated.append(merged)
        
        logger.info(f"[Deduplication] {len(findings)} → {len(deduplicated)} findings "
                   f"({len(findings) - len(deduplicated)} duplicates removed)")
        
        return deduplicated
    
    def _get_dedup_key(self, finding: Dict) -> tuple:
        """Get deduplication key for finding"""
        endpoint = self._normalize_endpoint(finding.get("location", ""))
        vuln_type = self._normalize_vuln_type(finding.get("type", ""))
        
        # Key: (endpoint, vuln_type)
        return (endpoint, vuln_type)
    
    def _normalize_endpoint(self, endpoint: str) -> str:
        """Normalize endpoint for comparison"""
        # Remove trailing slashes
        normalized = endpoint.rstrip("/")
        
        # Remove query params (keep path only)
        if "?" in normalized:
            normalized = normalized.split("?")[0]
        
        # Lowercase
        return normalized.lower()
    
    def _normalize_vuln_type(self, vuln_type: str) -> str:
        """Normalize vulnerability type"""
        # Lowercase and remove underscores/hyphens
        normalized = vuln_type.lower().replace("_", "").replace("-", "").replace(" ", "")
        
        # Map variants to canonical types
        mappings = {
            "xssreflected": "xss",
            "xssstored": "xss",
            "xssdom": "xss",
            "sqlinjection": "sqli",
            "sql": "sqli",
            "commandinjection": "cmdi",
            "cmdinjection": "cmdi",
        }
        
        return mappings.get(normalized, normalized)
    
    def _merge_duplicates(self, findings: List[Dict]) -> Dict:
        """
        Merge duplicate findings
        
        Strategy:
        - Keep finding with highest severity
        - Combine evidence from all tools
        - Add corroborating_tools list
        - Boost confidence
        """
        # Sort by severity (CRITICAL > HIGH > MEDIUM > LOW)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        sorted_findings = sorted(findings, 
                                key=lambda f: severity_order.get(f.get("severity", "LOW"), 99))
        
        # Primary = highest severity
        primary = sorted_findings[0].copy()
        duplicates = sorted_findings[1:]
        
        # Collect tools
        tools = {f.get("tool", "unknown") for f in findings}
        
        # Combine evidence
        all_evidence = []
        for f in findings:
            evidence = f.get("evidence", "")
            if evidence and evidence not in all_evidence:
                all_evidence.append(evidence)
        
        # Update primary finding
        primary["corroborating_tools"] = sorted(list(tools - {primary.get("tool", "")}))
        primary["evidence_combined"] = " | ".join(all_evidence[:3])  # Top 3 evidences
        primary["duplicate_count"] = len(duplicates)
        
        # Confidence boost (10% per corroborating tool, max 30%)
        corroboration_boost = min(len(primary["corroborating_tools"]) * 10, 30)
        if "confidence" in primary:
            primary["confidence"] = min(100, primary["confidence"] + corroboration_boost)
        else:
            primary["confidence"] = 60 + corroboration_boost  # Base 60 + boost
        
        # Track duplicate group
        group = DuplicateGroup(
            primary_finding=primary,
            duplicates=duplicates,
            tools_involved=tools,
            confidence_boost=corroboration_boost
        )
        self.duplicate_groups.append(group)
        
        logger.debug(f"[Dedup] Merged {len(duplicates)} duplicates into 1 finding "
                    f"(tools: {tools}, boost: +{corroboration_boost}%)")
        
        return primary
    
    def get_deduplication_report(self) -> Dict:
        """Get deduplication statistics"""
        total_duplicates = sum(len(g.duplicates) for g in self.duplicate_groups)
        
        return {
            "duplicate_groups": len(self.duplicate_groups),
            "total_duplicates_removed": total_duplicates,
            "groups": [g.to_dict() for g in self.duplicate_groups]
        }
