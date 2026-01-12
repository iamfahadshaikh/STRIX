"""
Crawler Mandatory Gate - Phase 2 Critical Fix
Purpose: BLOCK all payload tools if crawler hasn't run successfully

Architecture Rule:
  Crawler is NOT optional. It is MANDATORY.
  No payload tool may run without crawler confirmation.
  
  If crawler fails:
    - BLOCK all payload tools (dalfox, sqlmap, commix, etc.)
    - ALLOW only discovery tools (nuclei passive scan)
    - Report clearly: "Payload testing skipped - crawler failed"

Integration:
  - Called by automation_scanner_v2.py BEFORE payload phase
  - Checks DiscoveryCache for crawler results
  - Updates DecisionLedger to BLOCK payload tools if no crawler data
"""

import logging
from typing import Dict, List, Tuple
from enum import Enum

logger = logging.getLogger(__name__)


class CrawlerStatus(str, Enum):
    """Crawler execution status"""
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    NOT_RUN = "NOT_RUN"


class CrawlerMandatoryGate:
    """
    Enforces crawler as mandatory prerequisite for payload testing
    
    Usage:
        gate = CrawlerMandatoryGate(discovery_cache, endpoint_graph)
        
        if not gate.crawler_succeeded():
            # Block payload tools
            blocked_tools = gate.get_blocked_tools()
            logger.error(f"Crawler failed, blocking {len(blocked_tools)} payload tools")
        else:
            # Continue with payload testing
            logger.info("Crawler succeeded, payload tools allowed")
    """

    # Payload tools that REQUIRE crawler data
    PAYLOAD_TOOLS = [
        "dalfox",
        "sqlmap",
        "commix",
        "xsstrike",
        "arjun",  # param fuzzer
    ]

    # Discovery tools that can run WITHOUT crawler
    DISCOVERY_TOOLS = [
        "nuclei",  # passive scan mode
        "nmap",
        "whatweb",
        "wafw00f",
        "sublist3r",
        "amass",
    ]

    def __init__(self, discovery_cache, endpoint_graph=None):
        """
        Args:
            discovery_cache: DiscoveryCache instance
            endpoint_graph: EndpointGraph instance (optional)
        """
        self.cache = discovery_cache
        self.graph = endpoint_graph
        self._crawler_status = CrawlerStatus.NOT_RUN
        self._failure_reason = ""

    def check_crawler_status(self) -> Tuple[CrawlerStatus, str]:
        """
        Check if crawler ran successfully
        
        Returns:
            (status, reason)
        """
        # Check cache for crawler signals
        cache_has_endpoints = (hasattr(self.cache, 'endpoints') and len(self.cache.endpoints) > 0)
        
        if not cache_has_endpoints:
            self._crawler_status = CrawlerStatus.FAILED
            self._failure_reason = "No endpoints discovered by crawler"
            return self._crawler_status, self._failure_reason

        # Check for parameters (crawler should find params)
        if not hasattr(self.cache, 'params') or len(self.cache.params) == 0:
            logger.warning("[CrawlerGate] Crawler found endpoints but no parameters")
            # This is OK - some sites have no params
            # But log it as suspicious

        # Check graph if available
        if self.graph:
            if not self.graph.is_finalized:
                self._crawler_status = CrawlerStatus.FAILED
                self._failure_reason = "EndpointGraph not finalized"
                return self._crawler_status, self._failure_reason

            graph_endpoints = self.graph.get_all_endpoints()
            if len(graph_endpoints) == 0:
                self._crawler_status = CrawlerStatus.FAILED
                self._failure_reason = "EndpointGraph has no endpoints"
                return self._crawler_status, self._failure_reason
            
            # Populate parameter flags based on heuristics and cache signals
            self._populate_parameter_flags()

        # Crawler succeeded
        self._crawler_status = CrawlerStatus.SUCCESS
        self._failure_reason = ""
        return self._crawler_status, ""
    def _populate_parameter_flags(self):
        """
        Populate parameter flags in EndpointGraph based on cache signals
        This bridges crawler → cache → graph integration
        """
        if not self.graph or not self.cache:
            return
        
        # Mark reflectable parameters (from cache.reflections)
        if hasattr(self.cache, 'reflections'):
            for reflection in self.cache.reflections:
                # Remove "hint:" prefix if present
                param_name = reflection.replace("hint:", "")
                self.graph.mark_reflectable(param_name)
        
        # Mark command-injectable parameters (from cache.command_params)
        if hasattr(self.cache, 'command_params'):
            for param_name in self.cache.command_params:
                self.graph.mark_injectable_cmd(param_name)
        
        # Mark SSRF-prone parameters (from cache.ssrf_params)
        if hasattr(self.cache, 'ssrf_params'):
            for param_name in self.cache.ssrf_params:
                self.graph.mark_injectable_ssrf(param_name)
        
        # Mark SQL-injectable parameters (heuristic: any numeric or id-like param)
        for param_name, param in self.graph.get_all_parameters().items():
            if any(x in param_name.lower() for x in ['id', 'uid', 'user_id', 'post_id', 'order_id']):
                self.graph.mark_injectable_sql(param_name)
        
        logger.info(f"[CrawlerGate] Populated parameter flags: "
                   f"{len(self.graph.get_reflectable_endpoints())} reflectable, "
                   f"{len(self.graph.get_injectable_sql_endpoints())} SQL-injectable, "
                   f"{len(self.graph.get_injectable_cmd_endpoints())} cmd-injectable")


    def crawler_succeeded(self) -> bool:
        """
        Check if crawler ran successfully
        
        Returns:
            bool: True if crawler succeeded
        """
        status, reason = self.check_crawler_status()
        return status == CrawlerStatus.SUCCESS

    def get_blocked_tools(self) -> List[str]:
        """
        Get list of tools that should be blocked due to crawler failure
        
        Returns:
            List of tool names
        """
        if self.crawler_succeeded():
            return []

        return self.PAYLOAD_TOOLS.copy()

    def get_allowed_tools(self) -> List[str]:
        """
        Get list of tools that can run even without crawler
        
        Returns:
            List of tool names
        """
        return self.DISCOVERY_TOOLS.copy()

    def should_block_tool(self, tool_name: str) -> Tuple[bool, str]:
        """
        Check if tool should be blocked due to crawler failure
        
        Args:
            tool_name: Tool to check
            
        Returns:
            (should_block: bool, reason: str)
        """
        if self.crawler_succeeded():
            return False, ""

        if tool_name in self.PAYLOAD_TOOLS:
            return True, f"Crawler {self._crawler_status.value}: {self._failure_reason}"

        return False, ""

    def get_gate_report(self) -> Dict:
        """
        Get detailed gate report
        
        Returns:
            Dict with gate status and details
        """
        status, reason = self.check_crawler_status()

        return {
            "crawler_status": status.value,
            "crawler_succeeded": status == CrawlerStatus.SUCCESS,
            "failure_reason": reason,
            "blocked_tools": self.get_blocked_tools(),
            "allowed_tools": self.get_allowed_tools(),
            "endpoints_discovered": (
                len(self.cache.endpoints) if hasattr(self.cache, 'endpoints') else 0
            ),
            "parameters_discovered": (
                len(self.cache.params) if hasattr(self.cache, 'params') else 0
            ),
            "graph_endpoints": (
                len(self.graph.get_all_endpoints()) if self.graph and self.graph.is_finalized else 0
            )
        }

    def update_decision_ledger(self, ledger) -> None:
        """
        Update decision ledger to block payload tools if crawler failed
        
        Args:
            ledger: DecisionLedger instance
        """
        if self.crawler_succeeded():
            logger.info("[CrawlerGate] Crawler succeeded, no ledger updates needed")
            return

        # Block payload tools
        blocked_tools = self.get_blocked_tools()
        for tool_name in blocked_tools:
            if tool_name in ledger.decisions:
                # Update existing decision to DENY
                ledger.decisions[tool_name].decision = "DENY"
                ledger.decisions[tool_name].reason = (
                    f"BLOCKED: Crawler {self._crawler_status.value} - {self._failure_reason}"
                )
                logger.warning(f"[CrawlerGate] Blocked {tool_name} due to crawler failure")

        logger.error(
            f"[CrawlerGate] Crawler failed, blocked {len(blocked_tools)} payload tools"
        )


# Example usage
"""
from cache_discovery import DiscoveryCache
from endpoint_graph import EndpointGraph
from decision_ledger import DecisionLedger

# Initialize
cache = DiscoveryCache()
graph = EndpointGraph(target="https://example.com")
ledger = DecisionLedger()

# After crawler runs (or fails)
gate = CrawlerMandatoryGate(cache, graph)

if not gate.crawler_succeeded():
    # Block payload tools
    gate.update_decision_ledger(ledger)
    
    report = gate.get_gate_report()
    print(f"Crawler Status: {report['crawler_status']}")
    print(f"Blocked Tools: {report['blocked_tools']}")
    print(f"Reason: {report['failure_reason']}")
else:
    print("Crawler succeeded, proceeding with payload testing")
"""
