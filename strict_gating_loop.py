"""
Strict Gating Loop with Graph-Based Targeting - Phase 2
Purpose: Enforce strict payload tool gating based on endpoint graph
  
Gating Rules (Strict):
  - Dalfox: ONLY if reflectable parameters found AND endpoints crawled
  - Xsstrike: ONLY if reflectable parameters in forms
  - Sqlmap: ONLY if dynamic parameters found
  - Commix: ONLY if command-like parameters detected
  - Nuclei: Always runs (template-based, no gating needed)

Graph-based means we use actual endpoint + parameter discovery,
not just signal counts.
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class TargetingStrategy(Enum):
    """Tool-specific targeting strategies"""
    XSS = "xss"           # Reflection-focused endpoints
    SQL = "sql"           # Parameter-carrying endpoints
    COMMIX = "commix"     # Command-like parameters
    TEMPLATE = "template" # All endpoints (nuclei)


@dataclass
class ToolTargets:
    """Per-tool targeting information (graph-based)"""
    tool_name: str
    can_run: bool
    # Graph-based targeting
    target_endpoints: List[str] = field(default_factory=list)  # /api/users, /login
    target_parameters: List[str] = field(default_factory=list)  # id, search, cmd
    target_methods: List[str] = field(default_factory=list)  # GET, POST
    # Supporting info
    strategy: TargetingStrategy = TargetingStrategy.TEMPLATE
    priority: int = 0
    reason: str = ""
    evidence: str = ""  # Why this tool gates on/off

    def __repr__(self) -> str:
        return (f"{self.tool_name}: {'✓' if self.can_run else '✗'} "
                f"({len(self.target_endpoints)} endpoints, "
                f"{len(self.target_parameters)} params)")

    def to_dict(self) -> Dict:
        return {
            "tool": self.tool_name,
            "can_run": self.can_run,
            "target_endpoints": self.target_endpoints,
            "target_parameters": self.target_parameters,
            "target_methods": self.target_methods,
            "strategy": self.strategy.value,
            "priority": self.priority,
            "reason": self.reason,
            "evidence": self.evidence
        }


class StrictGatingLoop:
    """
    Strict gating using endpoint graph.
    
    Replaces old crawl-signals-only approach with actual graph queries.
    """

    def __init__(self, endpoint_graph, decision_ledger):
        """
        Args:
            endpoint_graph: EndpointGraph instance (finalized)
            decision_ledger: DecisionLedger instance
        """
        self.graph = endpoint_graph
        self.ledger = decision_ledger
        self._targets_cache: Dict[str, ToolTargets] = {}

    def gate_tool(self, tool_name: str) -> ToolTargets:
        """
        Gate a specific tool based on graph
        
        Returns:
            ToolTargets with can_run flag and targeting info
        """
        if tool_name in self._targets_cache:
            return self._targets_cache[tool_name]

        # Check ledger first
        if not self.ledger.allows(tool_name):
            targets = ToolTargets(
                tool_name=tool_name,
                can_run=False,
                reason=self.ledger.get_reason(tool_name),
                evidence="Blocked by decision ledger"
            )
            self._targets_cache[tool_name] = targets
            return targets

        # Apply strict graph-based gating
        tool_lower = tool_name.lower()

        if "xss" in tool_lower or tool_lower == "dalfox":
            targets = self._gate_xss_tool(tool_name)
        elif "sql" in tool_lower:
            targets = self._gate_sql_tool(tool_name)
        elif tool_lower == "commix":
            targets = self._gate_commix_tool(tool_name)
        elif "nuclei" in tool_lower:
            targets = self._gate_nuclei_tool(tool_name)
        else:
            targets = ToolTargets(
                tool_name=tool_name,
                can_run=True,
                reason="Unknown tool, allowing by default",
                evidence="Default allow"
            )

        self._targets_cache[tool_name] = targets
        return targets

    def _gate_xss_tool(self, tool_name: str) -> ToolTargets:
        """
        XSS tools (dalfox, xsstrike): ONLY if reflectable parameters found
        """
        reflectable_endpoints = self.graph.get_reflectable_endpoints()

        targets = ToolTargets(
            tool_name=tool_name,
            can_run=len(reflectable_endpoints) > 0,
            strategy=TargetingStrategy.XSS,
            reason="Reflection detected in crawl" if reflectable_endpoints else "No reflectable parameters",
            evidence=f"{len(reflectable_endpoints)} reflection endpoints"
        )

        if targets.can_run:
            targets.target_endpoints = reflectable_endpoints
            # Get parameters for these endpoints
            param_names = set()
            methods = set()
            for endpoint in reflectable_endpoints:
                ep = self.graph.get_endpoint(endpoint)
                if ep:
                    param_names.update(ep.parameters.keys())
                    methods.update(m.value for m in ep.methods)
            targets.target_parameters = list(param_names)
            targets.target_methods = sorted(list(methods))
            targets.priority = 10  # High priority for XSS

        return targets

    def _gate_sql_tool(self, tool_name: str) -> ToolTargets:
        """
        SQL tools (sqlmap): ONLY if parameters found in dynamic endpoints
        """
        sql_endpoints = self.graph.get_injectable_sql_endpoints()
        if not sql_endpoints:
            # Fallback: any parametric endpoint
            sql_endpoints = self.graph.get_parametric_endpoints()

        targets = ToolTargets(
            tool_name=tool_name,
            can_run=len(sql_endpoints) > 0,
            strategy=TargetingStrategy.SQL,
            reason="Parameters detected in dynamic endpoints" if sql_endpoints else "No injectable parameters",
            evidence=f"{len(sql_endpoints)} SQL-targetable endpoints"
        )

        if targets.can_run:
            targets.target_endpoints = sql_endpoints
            # Get parameters
            param_names = set()
            methods = set()
            for endpoint in sql_endpoints:
                ep = self.graph.get_endpoint(endpoint)
                if ep:
                    param_names.update(ep.parameters.keys())
                    methods.update(m.value for m in ep.methods)
            targets.target_parameters = list(param_names)
            targets.target_methods = sorted(list(methods))
            targets.priority = 8  # High priority for SQL injection

        return targets

    def _gate_commix_tool(self, tool_name: str) -> ToolTargets:
        """
        Commix (command injection): ONLY if command-like parameters
        """
        cmd_endpoints = self.graph.get_injectable_cmd_endpoints()

        targets = ToolTargets(
            tool_name=tool_name,
            can_run=len(cmd_endpoints) > 0,
            strategy=TargetingStrategy.COMMIX,
            reason="Command-injectable parameters detected" if cmd_endpoints else "No command parameters",
            evidence=f"{len(cmd_endpoints)} command-targetable endpoints"
        )

        if targets.can_run:
            targets.target_endpoints = cmd_endpoints
            # Get parameters
            param_names = set()
            methods = set()
            for endpoint in cmd_endpoints:
                ep = self.graph.get_endpoint(endpoint)
                if ep:
                    # Only include actual command-injectable params
                    for param_name, param in ep.parameters.items():
                        if param.injectable_cmd:
                            param_names.add(param_name)
                    methods.update(m.value for m in ep.methods)
            targets.target_parameters = list(param_names)
            targets.target_methods = sorted(list(methods))
            targets.priority = 9  # High priority for command injection

        return targets

    def _gate_nuclei_tool(self, tool_name: str) -> ToolTargets:
        """
        Nuclei (templates): Always runs, but targets all endpoints
        """
        all_endpoints = list(self.graph.get_all_endpoints().keys())

        targets = ToolTargets(
            tool_name=tool_name,
            can_run=True,
            strategy=TargetingStrategy.TEMPLATE,
            reason="Template-based scanning, always enabled",
            evidence=f"Will scan all {len(all_endpoints)} discovered endpoints"
        )

        targets.target_endpoints = all_endpoints
        targets.priority = 5  # Medium priority

        return targets

    def get_all_targets(self) -> Dict[str, ToolTargets]:
        """Get targeting for all major payload tools"""
        tools = ["dalfox", "sqlmap", "commix", "nuclei"]
        result = {}
        for tool in tools:
            result[tool] = self.gate_tool(tool)
        return result

    def get_summary(self) -> Dict:
        """Get gating summary for reporting"""
        all_targets = self.get_all_targets()

        enabled_tools = [t.tool_name for t in all_targets.values() if t.can_run]
        disabled_tools = [t.tool_name for t in all_targets.values() if not t.can_run]

        return {
            "enabled_tools": enabled_tools,
            "disabled_tools": disabled_tools,
            "targeting": {
                tool_name: targets.to_dict()
                for tool_name, targets in all_targets.items()
            },
            "graph_summary": self.graph.get_summary()
        }


# Usage example
"""
from endpoint_graph import EndpointGraph
from decision_ledger import DecisionLedger, Decision
from strict_gating_loop import StrictGatingLoop

# Build graph from crawl
graph = EndpointGraph(target="https://example.com")
graph.add_crawl_result("/api/users?id=123", params={"id": ["123"]}, is_api=True)
graph.add_crawl_result("/search?q=test", params={"q": ["test"]})
graph.add_crawl_result("/login", is_form=True)

# Mark parameters
graph.mark_reflectable("q")
graph.mark_injectable_sql("id")

graph.finalize()

# Build decision ledger
ledger = DecisionLedger(target_profile=None)
ledger.add_decision("dalfox", Decision.CONDITIONAL, "If reflections found")
ledger.add_decision("sqlmap", Decision.CONDITIONAL, "If parameters found")
ledger.build()

# Create gating loop
gating = StrictGatingLoop(graph, ledger)

# Gate each tool
dalfox_targets = gating.gate_tool("dalfox")
print(f"dalfox: {dalfox_targets.can_run}")  # True if reflections found
print(f"  Targets: {dalfox_targets.target_endpoints}")

sqlmap_targets = gating.gate_tool("sqlmap")
print(f"sqlmap: {sqlmap_targets.can_run}")  # True if parameters found
print(f"  Targets: {sqlmap_targets.target_endpoints}")

# Summary
print(gating.get_summary())
"""
