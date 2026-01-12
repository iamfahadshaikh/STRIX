"""
===== GATING LOOP ORCHESTRATOR =====
Coordinates crawl → graph → per-tool decisions

This module ties together:
  1. crawl_adapter.py - crawl signals (reflections, parameters, forms)
  2. endpoint_param_graph.py - endpoint targeting per-tool
  3. decision_ledger.py - crawl-aware tool gating decisions

NO MODIFICATIONS to automation_scanner_v2.py - works via integration hook.

USAGE:
------
from gating_loop import GatingLoopOrchestrator
from crawl_adapter import CrawlAdapter
from decision_ledger import DecisionLedger, DecisionEngine

# Step 1: Crawl target
adapter = CrawlAdapter(target_domain)
adapter.run()

# Step 2: Initialize ledger with crawl gating
engine = DecisionEngine()
ledger = engine.build_ledger()
ledger.apply_crawl_gating(adapter)

# Step 3: Instantiate gating loop
orchestrator = GatingLoopOrchestrator(ledger, adapter)

# Step 4: Get targeting for each tool
xss_endpoints = orchestrator.get_tool_targets("xsstrike")
sql_endpoints = orchestrator.get_tool_targets("sqlmap")

# Step 5: Execute payload tools on targeted endpoints only
for url in xss_endpoints:
    run_xsstrike(url)  # Only runs if gated to run
for url in sql_endpoints:
    run_sqlmap(url)
"""

import logging
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TargetingStrategy(Enum):
    """Tool-specific targeting strategies"""
    XSS = "xss"           # Reflection-focused endpoints
    SQL = "sql"           # Parameter-carrying endpoints
    COMMIX = "commix"     # Any parameter endpoints
    TEMPLATE = "template" # All endpoints (nuclei)
    API = "api"           # API-specific (OpenAPI endpoints)


@dataclass
class ToolTargets:
    """Per-tool targeting information"""
    tool_name: str
    can_run: bool
    target_urls: List[str] = field(default_factory=list)
    parameters: Dict[str, List[str]] = field(default_factory=dict)  # url → param list
    forms: Dict[str, List[Dict]] = field(default_factory=dict)      # url → form data
    reflections: List[str] = field(default_factory=list)            # Reflected URLs
    strategy: TargetingStrategy = TargetingStrategy.TEMPLATE
    priority: int = 0
    reason: str = ""

    def __repr__(self) -> str:
        return (f"ToolTargets({self.tool_name}, can_run={self.can_run}, "
                f"targets={len(self.target_urls)}, params={sum(len(p) for p in self.parameters.values())})")

    def to_dict(self) -> dict:
        return {
            'tool': self.tool_name,
            'can_run': self.can_run,
            'target_count': len(self.target_urls),
            'targets': self.target_urls,
            'param_count': sum(len(p) for p in self.parameters.values()),
            'parameters': self.parameters,
            'forms': self.forms,
            'reflection_count': len(self.reflections),
            'reflections': self.reflections,
            'strategy': self.strategy.value,
            'priority': self.priority,
            'reason': self.reason
        }


class GatingLoopOrchestrator:
    """
    Orchestrates crawl → graph → per-tool decisions
    
    Coordinates:
      1. Crawl adapter signals (reflection_count, parameter_count, etc.)
      2. Decision ledger (per-tool allow/deny)
      3. Endpoint graph (tool-specific endpoint/param mapping)
      4. Execution targeting (which endpoints run which tools)
    """

    def __init__(self, decision_ledger, crawl_adapter, endpoint_graph=None):
        """
        Initialize gating loop
        
        Args:
            decision_ledger: DecisionLedger instance (with crawl gating applied)
            crawl_adapter: CrawlAdapter instance (with crawl results)
            endpoint_graph: Optional EndpointParamGraph for detailed targeting
        """
        self.ledger = decision_ledger
        self.adapter = crawl_adapter
        self.graph = endpoint_graph
        self._targets_cache: Dict[str, ToolTargets] = {}
        
        logger.info("[GatingLoop] Initialized with decision ledger and crawl adapter")

    def build_targets(self) -> Dict[str, ToolTargets]:
        """
        Build per-tool targeting from crawl signals + decisions
        
        Returns:
            Dict[tool_name] → ToolTargets
            
        Usage:
            targets_map = orchestrator.build_targets()
            for tool, targets in targets_map.items():
                print(f"{tool}: {len(targets.target_urls)} endpoints")
        """
        gating = self.adapter.gating_signals
        targets_map = {}

        logger.info(f"[GatingLoop] Building targets for {gating.get('crawled_url_count', 0)} endpoints, "
                   f"{gating['parameter_count']} parameters, {gating['reflection_count']} reflections")

        # === XSSTRIKE ===
        xss_targets = ToolTargets(
            tool_name="xsstrike",
            can_run=self.ledger.should_run_payload_tool_with_crawl("xsstrike", self.adapter),
            strategy=TargetingStrategy.XSS
        )
        if xss_targets.can_run:
            # Note: we don't have specific endpoint URLs from basic gating signals
            # In production, you'd integrate with endpoint_param_graph.py for detailed URLs
            xss_targets.target_urls = [f"[{gating['reflection_count']} reflection endpoints]"]
            xss_targets.reflections = gating.get('reflectable_params', [])
            xss_targets.priority = self.ledger.get_priority("xsstrike")
            xss_targets.reason = f"Reflection endpoints: {gating['reflection_count']} identified"
            logger.info(f"[GatingLoop] xsstrike ENABLED: {gating['reflection_count']} reflection targets")
        else:
            xss_targets.reason = "No reflectable parameters (crawl)"
            logger.info(f"[GatingLoop] xsstrike DISABLED: {xss_targets.reason}")

        targets_map["xsstrike"] = xss_targets

        # === DALFOX ===
        dalfox_targets = ToolTargets(
            tool_name="dalfox",
            can_run=self.ledger.should_run_payload_tool_with_crawl("dalfox", self.adapter),
            strategy=TargetingStrategy.XSS
        )
        if dalfox_targets.can_run:
            dalfox_targets.target_urls = [f"[{gating['reflection_count']} reflection endpoints]"]
            dalfox_targets.reflections = gating.get('reflectable_params', [])
            dalfox_targets.priority = self.ledger.get_priority("dalfox")
            dalfox_targets.reason = f"XSS testing on {gating['reflection_count']} reflection endpoints"
            logger.info(f"[GatingLoop] dalfox ENABLED: {gating['reflection_count']} targets")
        else:
            dalfox_targets.reason = "No reflection endpoints"
            logger.info(f"[GatingLoop] dalfox DISABLED: {dalfox_targets.reason}")

        targets_map["dalfox"] = dalfox_targets

        # === SQLMAP ===
        sql_targets = ToolTargets(
            tool_name="sqlmap",
            can_run=self.ledger.should_run_payload_tool_with_crawl("sqlmap", self.adapter),
            strategy=TargetingStrategy.SQL
        )
        if sql_targets.can_run:
            sql_targets.target_urls = [f"[{gating['parameter_count']} parameter-carrying endpoints]"]
            sql_targets.priority = self.ledger.get_priority("sqlmap")
            sql_targets.reason = f"SQL injection on {gating['parameter_count']} parameters ({gating.get('parameter_names', [])})"
            logger.info(f"[GatingLoop] sqlmap ENABLED: {gating['parameter_count']} param-carrying endpoints")
        else:
            sql_targets.reason = "No parameters discovered"
            logger.info(f"[GatingLoop] sqlmap DISABLED: {sql_targets.reason}")

        targets_map["sqlmap"] = sql_targets

        # === COMMIX ===
        commix_targets = ToolTargets(
            tool_name="commix",
            can_run=self.ledger.should_run_payload_tool_with_crawl("commix", self.adapter),
            strategy=TargetingStrategy.COMMIX
        )
        if commix_targets.can_run:
            commix_targets.target_urls = [f"[{gating['parameter_count']} parameter-carrying endpoints]"]
            commix_targets.priority = self.ledger.get_priority("commix")
            commix_targets.reason = f"Command injection on {gating['parameter_count']} parameters"
            logger.info(f"[GatingLoop] commix ENABLED: {len(commix_targets.target_urls)} targets")
        else:
            commix_targets.reason = "No parameters or tool disabled"
            logger.info(f"[GatingLoop] commix DISABLED: {commix_targets.reason}")

        targets_map["commix"] = commix_targets

        self._targets_cache = targets_map
        return targets_map

    def get_tool_targets(self, tool_name: str) -> List[str]:
        """
        Get target URLs for specific tool
        
        Args:
            tool_name: Tool identifier
            
        Returns:
            List[str]: Target URLs
            
        Usage:
            urls = orchestrator.get_tool_targets("xsstrike")
        """
        if not self._targets_cache:
            self.build_targets()

        targets = self._targets_cache.get(tool_name)
        if targets:
            return targets.target_urls if targets.can_run else []
        return []

    def get_targets_for_all_tools(self) -> Dict[str, ToolTargets]:
        """
        Get targeting information for all tools
        
        Returns:
            Dict[tool_name] → ToolTargets
        """
        if not self._targets_cache:
            self.build_targets()
        return self._targets_cache

    def should_run_tool(self, tool_name: str) -> bool:
        """
        Check if tool should run (gated decision)
        
        Args:
            tool_name: Tool identifier
            
        Returns:
            bool: True if tool should run
        """
        return self.ledger.should_run_payload_tool_with_crawl(tool_name, self.adapter)

    def get_summary(self) -> str:
        """Get human-readable gating summary"""
        if not self._targets_cache:
            self.build_targets()

        gating = self.adapter.gating_signals
        summary_lines = [
            "===== GATING LOOP SUMMARY =====",
            f"Crawl: {gating.get('crawled_url_count', 0)} endpoints, {gating['parameter_count']} parameters, {gating['reflection_count']} reflections",
            "",
            "Tool Decisions:"
        ]

        for tool_name, targets in sorted(self._targets_cache.items()):
            status = "✓ RUN" if targets.can_run else "✗ SKIP"
            target_info = f"({len(targets.target_urls)} URLs)" if targets.target_urls else "(no targets)"
            summary_lines.append(f"  {tool_name}: {status} {target_info} - {targets.reason}")

        summary_lines.append("")
        summary_lines.append("Execution Order (by priority):")
        sorted_tools = sorted(
            [t for t in self._targets_cache.values() if t.can_run],
            key=lambda x: -x.priority
        )
        for i, targets in enumerate(sorted_tools, 1):
            summary_lines.append(f"  {i}. {targets.tool_name} (priority {targets.priority})")

        return "\n".join(summary_lines)

    def to_dict(self) -> dict:
        """Export gating decisions as dict"""
        if not self._targets_cache:
            self.build_targets()

        return {
            'crawl': self.adapter.gating_signals,
            'tools': {
                tool: targets.to_dict()
                for tool, targets in self._targets_cache.items()
            },
            'summary': self.get_summary()
        }


# ===== CLI TESTING =====
if __name__ == "__main__":
    import json
    from crawl_adapter import CrawlAdapter
    from decision_ledger import DecisionEngine

    logging.basicConfig(level=logging.INFO, 
                       format='%(name)s - %(levelname)s - %(message)s')

    # Test domain
    TEST_DOMAIN = "https://dev-erp.sisschools.org"

    print(f"\n[TEST] Running gating loop on {TEST_DOMAIN}...\n")

    # Step 1: Crawl
    adapter = CrawlAdapter(TEST_DOMAIN, output_dir="/tmp/gating_test")
    success, msg = adapter.run()
    print(f"[Crawl] {msg}\n")

    if not success:
        print("[ERROR] Crawl failed, exiting")
        exit(1)

    # Step 2: Build ledger with crawl gating
    engine = DecisionEngine()
    # Build minimal profile
    from target_profile import TargetProfileBuilder, TargetType
    profile = (TargetProfileBuilder()
              .with_original_input(TEST_DOMAIN)
              .with_target_type(TargetType.SUBDOMAIN)
              .with_host("dev-erp.sisschools.org")
              .with_base_domain("sisschools.org")
              .with_is_web_target(True)
              .with_is_https(True)
              .build())
    ledger = engine.build_ledger(profile)
    
    # Log crawl-based gating decisions (no modification to ledger)
    logger.info("Applying crawl signals to payload tool gating...")
    gating_summary = ledger.get_crawl_gating_summary(adapter)

    # Step 3: Instantiate orchestrator
    orchestrator = GatingLoopOrchestrator(ledger, adapter)

    # Step 4: Build targets
    print("[Gating] Building tool targets...\n")
    orchestrator.build_targets()

    # Step 5: Display summary
    print(orchestrator.get_summary())
    print()

    # Step 6: Detailed breakdown
    print("===== TOOL TARGETING DETAILS =====\n")
    for tool, targets in orchestrator.get_targets_for_all_tools().items():
        print(f"[{tool}] Can run: {targets.can_run}")
        if targets.target_urls:
            print(f"  URLs: {targets.target_urls[:3]}")
            if len(targets.target_urls) > 3:
                print(f"  ... and {len(targets.target_urls) - 3} more")
        if targets.parameters:
            param_count = sum(len(p) for p in targets.parameters.values())
            print(f"  Parameters: {param_count}")
        print()

    # Step 7: Export as JSON
    print("===== EXPORTED AS JSON =====\n")
    export = orchestrator.to_dict()
    print(json.dumps({
        'crawl_summary': export['crawl'],
        'tools': {k: v for k, v in export['tools'].items() if v['can_run']}
    }, indent=2))
