"""
DecisionLedger - Precomputed, explicit allow/deny list for all tools

This is the brain that decides what runs.
Every tool has an explicit decision with reasoning.
No tool runs without a ledger entry.
No tool can run if ledger says DENY.

Built once during pre-scan phase.
Read-only during execution.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum
from datetime import datetime


class Decision(Enum):
    """Tool execution decision"""
    ALLOW = "allow"
    DENY = "deny"
    CONDITIONAL = "conditional"  # Runs only if specific condition met


@dataclass
class ToolDecision:
    """Decision for a single tool"""
    
    tool_name: str
    decision: Decision
    reason: str
    prerequisites: List[str] = field(default_factory=list)  # What evidence is required
    priority: int = 0  # Higher = run earlier
    timeout: int = 300  # Default timeout
    
    def __repr__(self) -> str:
        return f"{self.tool_name}: {self.decision.value} ({self.reason})"


class DecisionLedger:
    """
    Precomputed tool execution decisions.
    
    Built once. Read everywhere. Never modified.
    Each tool has explicit decision with justification.
    """
    
    def __init__(self, profile):
        """Initialize ledger for a target profile"""
        self.profile = profile
        self.decisions: Dict[str, ToolDecision] = {}
        # Keep a datetime so isoformat() calls are safe during serialization
        self.created_at = datetime.now()
        self._is_built = False
    
    def add_decision(
        self, 
        tool_name: str, 
        decision: Decision, 
        reason: str,
        prerequisites: List[str] = None,
        priority: int = 0,
        timeout: int = 300
    ) -> None:
        """Add a tool decision to the ledger"""
        if self._is_built:
            raise RuntimeError("Cannot modify ledger after build()")
        
        self.decisions[tool_name] = ToolDecision(
            tool_name=tool_name,
            decision=decision,
            reason=reason,
            prerequisites=prerequisites or [],
            priority=priority,
            timeout=timeout,
        )
    
    def allows(self, tool_name: str) -> bool:
        """Check if tool is allowed to run"""
        if tool_name not in self.decisions:
            raise KeyError(f"Tool {tool_name} not in decision ledger (architecture violation)")
        
        return self.decisions[tool_name].decision in (Decision.ALLOW, Decision.CONDITIONAL)
    
    def denies(self, tool_name: str) -> bool:
        """Check if tool is denied"""
        if tool_name not in self.decisions:
            raise KeyError(f"Tool {tool_name} not in decision ledger (architecture violation)")
        
        return self.decisions[tool_name].decision == Decision.DENY
    
    def get_reason(self, tool_name: str) -> str:
        """Get reason for decision"""
        if tool_name not in self.decisions:
            return "NOT IN LEDGER (architecture violation)"
        
        return self.decisions[tool_name].reason
    
    def get_prerequisites(self, tool_name: str) -> List[str]:
        """Get prerequisites for running tool"""
        if tool_name not in self.decisions:
            return []
        
        return self.decisions[tool_name].prerequisites
    
    def get_timeout(self, tool_name: str) -> int:
        """Get timeout for tool"""
        if tool_name not in self.decisions:
            return 300
        
        return self.decisions[tool_name].timeout
    
    def get_priority(self, tool_name: str) -> int:
        """Get priority for tool"""
        if tool_name not in self.decisions:
            return 0
        
        return self.decisions[tool_name].priority
    
    def get_allowed_tools(self) -> List[str]:
        """Get list of allowed tools in priority order"""
        allowed = [
            name for name, decision in self.decisions.items()
            if decision.decision in (Decision.ALLOW, Decision.CONDITIONAL)
        ]
        # Sort by priority (higher first)
        allowed.sort(key=lambda x: -self.decisions[x].priority)
        return allowed
    
    def get_denied_tools(self) -> List[str]:
        """Get list of denied tools"""
        return [
            name for name, decision in self.decisions.items()
            if decision.decision == Decision.DENY
        ]
    
    def build(self) -> "DecisionLedger":
        """Finalize ledger (no more modifications)"""
        self._is_built = True
        return self
    
    @property
    def is_built(self) -> bool:
        """Check if ledger is finalized"""
        return self._is_built
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for logging/reporting"""
        created = self.created_at if isinstance(self.created_at, str) else self.created_at.isoformat()
        return {
            "created_at": created,
            "profile": str(self.profile),
            "decisions": {
                name: {
                    "decision": decision.decision.value if hasattr(decision.decision, 'value') else str(decision.decision),
                    "reason": decision.reason,
                    "prerequisites": sorted(decision.prerequisites) if isinstance(decision.prerequisites, set) else decision.prerequisites,
                    "priority": decision.priority,
                    "timeout": decision.timeout,
                }
                for name, decision in self.decisions.items()
            },
            "summary": {
                "total_tools": len(self.decisions),
                "allowed": len(self.get_allowed_tools()),
                "denied": len(self.get_denied_tools()),
            }
        }
    
    def __repr__(self) -> str:
        allowed = len(self.get_allowed_tools())
        denied = len(self.get_denied_tools())
        return f"DecisionLedger({allowed} allowed, {denied} denied)"

    def record_tool_decision(self, tool_name: str, decision: Decision, reason: str) -> None:
        """Update or insert a tool decision even after build time (used for runtime gating)."""
        existing = self.decisions.get(tool_name)
        prerequisites = existing.prerequisites if existing else []
        priority = existing.priority if existing else 0
        timeout = existing.timeout if existing else 300
        self.decisions[tool_name] = ToolDecision(
            tool_name=tool_name,
            decision=decision,
            reason=reason,
            prerequisites=prerequisites,
            priority=priority,
            timeout=timeout,
        )

    # ===== CRAWL-BASED GATING (NEW) =====
    # Non-invasive: adds new methods without touching existing logic
    
    def should_run_payload_tool_with_crawl(self, tool_name: str, crawl_adapter) -> bool:
        """
        Per-tool gating with crawl signals (IMMUTABLE-SAFE)
        
        Does NOT modify ledger - only queries crawl signals.
        Ledger remains immutable after build().
        
        Args:
            tool_name: Tool identifier (xsstrike, sqlmap, etc.)
            crawl_adapter: CrawlAdapter with crawl results
            
        Returns:
            bool: True if tool should run (based on ledger decision AND crawl signals)
            
        Usage:
            if ledger.should_run_payload_tool_with_crawl("xsstrike", adapter):
                # Run xsstrike on crawled endpoints
        """
        # First check: ledger already says NO -> don't run
        if not self.allows(tool_name):
            return False
        
        # Second check: crawl signals say NO -> don't run
        gating = crawl_adapter.gating_signals
        if not gating:
            # No crawl data: use ledger decision
            return True

        tool_lower = tool_name.lower()

        # XSS tools: need reflectable params or forms
        if "xss" in tool_lower or tool_lower == "dalfox":
            return gating['reflection_count'] > 0 or gating['has_forms']

        # SQL injection: need any parameters
        elif "sql" in tool_lower:
            return gating['parameter_count'] > 0

        # Command injection: need any parameters
        elif "commix" in tool_lower:
            return gating['parameter_count'] > 0

        # Template-based (nuclei always runs if ledger allows)
        elif "nuclei" in tool_lower:
            return True

        # Default: use ledger decision
        else:
            return self.allows(tool_name)

    def get_crawl_gating_summary(self, crawl_adapter) -> dict:
        """
        Get crawl-gated decisions for all tools (for logging/summary)
        
        Args:
            crawl_adapter: CrawlAdapter with crawl results
            
        Returns:
            dict: {tool_name: {decision, reason}}
        """
        gating = crawl_adapter.gating_signals
        summary = {}

        logger = __import__('logging').getLogger(__name__)

        # Check each major tool (only those in ledger)
        for tool in ["xsstrike", "dalfox", "sqlmap", "commix"]:
            if tool not in self.decisions:
                continue
                
            allowed_by_ledger = self.allows(tool)
            allowed_by_crawl = self.should_run_payload_tool_with_crawl(tool, crawl_adapter)
            can_run = allowed_by_ledger and allowed_by_crawl

            if can_run:
                if tool in ["xsstrike", "dalfox"]:
                    reason = f"XSS testing ({gating['reflection_count']} reflection targets)"
                elif tool == "sqlmap":
                    reason = f"SQL injection ({gating['parameter_count']} parameters)"
                elif tool == "commix":
                    reason = f"Command injection ({gating['parameter_count']} parameters)"
                else:
                    reason = "Testing enabled"
            else:
                if not allowed_by_ledger:
                    reason = f"Blocked by ledger"
                elif not allowed_by_crawl:
                    if tool in ["xsstrike", "dalfox"]:
                        reason = f"No reflections ({gating['reflection_count']} found)"
                    else:
                        reason = f"No parameters ({gating['parameter_count']} found)"
                else:
                    reason = "Disabled"

            summary[tool] = {
                'can_run': can_run,
                'reason': reason,
                'ledger_allows': allowed_by_ledger,
                'crawl_allows': allowed_by_crawl
            }
            
            status = "✓" if can_run else "✗"
            logger.info(f"[Crawl Gating] {tool}: {status} - {reason}")

        return summary


class DecisionEngine:
    """Builds DecisionLedger for a given TargetProfile"""
    
    @staticmethod
    def build_ledger(profile) -> DecisionLedger:
        """
        Build complete decision ledger for target profile.
        
        This is the critical pre-execution phase.
        All decisions are made here based on profile evidence.
        """
        ledger = DecisionLedger(profile)
        
        # ============ DNS TOOLS ============
        if profile.is_ip:
            # IP targets skip DNS entirely
            ledger.add_decision("dig_a", Decision.DENY, "Target is IP (no DNS needed)")
            ledger.add_decision("dig_ns", Decision.DENY, "Target is IP (no DNS needed)")
            ledger.add_decision("dig_mx", Decision.DENY, "Target is IP (no DNS needed)")
            ledger.add_decision("dnsrecon", Decision.DENY, "Target is IP (no DNS needed)")
        elif profile.is_subdomain:
            # Subdomains get minimal DNS (A/AAAA only)
            ledger.add_decision("dig_a", Decision.ALLOW, "Subdomain A record resolution", priority=10)
            ledger.add_decision("dig_aaaa", Decision.ALLOW, "Subdomain AAAA record resolution", priority=10)
            ledger.add_decision("dig_ns", Decision.DENY, "NS lookup not needed for subdomain")
            ledger.add_decision("dig_mx", Decision.DENY, "MX lookup not needed for subdomain")
            ledger.add_decision("dnsrecon", Decision.DENY, "Full DNS recon not needed for subdomain")
        else:
            # Root domains get full DNS
            ledger.add_decision("dig_a", Decision.ALLOW, "Root domain A record resolution", priority=10)
            ledger.add_decision("dig_ns", Decision.ALLOW, "Root domain NS record resolution", priority=10)
            ledger.add_decision("dig_mx", Decision.ALLOW, "Root domain MX record resolution", priority=9)
            ledger.add_decision("dnsrecon", Decision.ALLOW, "Full DNS recon for root domain", priority=8)
        
        # ============ SUBDOMAIN ENUMERATION ============
        if profile.is_root_domain:
            # Only root domains get subdomain enum
            ledger.add_decision("findomain", Decision.ALLOW, "Subdomain enumeration (root domain)", priority=15)
            ledger.add_decision("sublist3r", Decision.ALLOW, "Subdomain enumeration (root domain)", priority=14)
            ledger.add_decision("assetfinder", Decision.ALLOW, "Subdomain enumeration (root domain)", priority=13)
        else:
            # Subdomains and IPs don't enumerate subdomains
            ledger.add_decision("findomain", Decision.DENY, "Not applicable for non-root domain")
            ledger.add_decision("sublist3r", Decision.DENY, "Not applicable for non-root domain")
            ledger.add_decision("assetfinder", Decision.DENY, "Not applicable for non-root domain")
        
        # ============ NETWORK SCANNING ============
        ledger.add_decision("ping", Decision.ALLOW, "Reachability check", priority=5)
        ledger.add_decision("nmap_quick", Decision.ALLOW, "Quick port scan", priority=20, timeout=9999)
        ledger.add_decision("nmap_vuln", Decision.ALLOW, "Vulnerability-focused nmap", priority=19, timeout=9999)
        
        # ============ WEB DETECTION ============
        ledger.add_decision("whatweb", Decision.ALLOW, "Early web technology detection", priority=25)
        
        # ============ SSL/TLS ============
        if profile.is_https and profile.is_web_target:
            ledger.add_decision("sslscan", Decision.ALLOW, "SSL/TLS certificate analysis", priority=18)
            ledger.add_decision("testssl", Decision.ALLOW, "SSL/TLS vulnerability scan", priority=17)
        else:
            ledger.add_decision("sslscan", Decision.DENY, "Target not HTTPS")
            ledger.add_decision("testssl", Decision.DENY, "Target not HTTPS")
        
        # ============ WEB SCANNING ============
        # FORCED: gobuster, nikto, nuclei run on all targets regardless of type
        ledger.add_decision("gobuster", Decision.ALLOW, "Directory enumeration (all targets)", priority=16, timeout=9999)
        ledger.add_decision("dirsearch", Decision.ALLOW, "Directory/file search", priority=15)
        ledger.add_decision("nikto", Decision.ALLOW, "Baseline web scan (all targets)", priority=14, timeout=9999)
        
        # ============ CMS-SPECIFIC TOOLS ============
        if profile.has_wordpress:
            ledger.add_decision("wpscan", Decision.ALLOW, "WordPress vulnerability scanner", priority=12)
        else:
            ledger.add_decision("wpscan", Decision.DENY, "WordPress not detected")
        
        # ============ PARAMETER-BASED TOOLS ============
        # FORCED: commix runs on all targets regardless of parameters
        ledger.add_decision("dalfox", Decision.ALLOW, "XSS discovery", priority=11)
        ledger.add_decision("xsstrike", Decision.ALLOW, "XSS testing", priority=10)
        ledger.add_decision("sqlmap", Decision.ALLOW, "SQLi testing", priority=9)
        ledger.add_decision("commix", Decision.ALLOW, "Command injection testing (all targets)", priority=8, timeout=9999)
        
        # ============ REFLECTION-BASED TOOLS ============
        if profile.has_reflection:
            ledger.add_decision("xsser", Decision.ALLOW, "XSS testing (reflection detected)", priority=7)
        else:
            ledger.add_decision("xsser", Decision.DENY, "No reflection detected")
        
        # ============ TEMPLATE SCANNING ============
        # FORCED: nuclei runs on all targets regardless of type
        ledger.add_decision("nuclei_crit", Decision.ALLOW, "Nuclei critical templates (all targets)", priority=6, timeout=9999)
        ledger.add_decision("nuclei_high", Decision.ALLOW, "Nuclei high severity templates (all targets)", priority=5, timeout=9999)
        
        return ledger.build()