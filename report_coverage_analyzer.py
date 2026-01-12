"""
Report Coverage Analyzer - Phase 4 Fix
Track what was tested, blocked, and why - for reporting
"""

import logging
from typing import Dict, List, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class BlockReason(Enum):
    """Why a tool was blocked"""
    NO_CRAWLER_DATA = "no_crawler_data"
    NO_PARAMETERS = "no_parameters"
    NO_ENDPOINTS = "no_endpoints"
    READINESS_FAILED = "readiness_failed"
    DECISION_LEDGER = "decision_ledger_blocked"
    PARSE_FAILED = "signal_parse_failed"
    TOOL_NOT_INSTALLED = "tool_not_installed"


@dataclass
class CoverageGap:
    """Represents a coverage gap"""
    tool: str
    category: str
    reason: BlockReason
    impact: str  # What wasn't tested
    remediation: str  # How to fix
    

@dataclass
class TestCoverage:
    """What was actually tested"""
    tested_endpoints: Set[str] = field(default_factory=set)
    tested_parameters: Set[str] = field(default_factory=set)
    tested_methods: Set[str] = field(default_factory=set)
    blocked_tools: List[str] = field(default_factory=list)
    executed_tools: List[str] = field(default_factory=list)
    coverage_gaps: List[CoverageGap] = field(default_factory=list)


class ReportCoverageAnalyzer:
    """
    Analyze test coverage for reporting
    Phase 4 requirement: Reports must show what was tested, blocked, and why
    """
    
    def __init__(self):
        self.coverage = TestCoverage()
        self.tool_outcomes: Dict[str, str] = {}  # tool -> outcome
        self.block_reasons: Dict[str, BlockReason] = {}  # tool -> reason
    
    def record_tool_executed(self, tool: str, endpoints: List[str], 
                            parameters: List[str], methods: List[str]):
        """Record that a tool was executed"""
        self.coverage.executed_tools.append(tool)
        self.coverage.tested_endpoints.update(endpoints)
        self.coverage.tested_parameters.update(parameters)
        self.coverage.tested_methods.update(methods)
        self.tool_outcomes[tool] = "executed"
    
    def record_tool_blocked(self, tool: str, category: str, reason: BlockReason):
        """Record that a tool was blocked"""
        self.coverage.blocked_tools.append(tool)
        self.tool_outcomes[tool] = "blocked"
        self.block_reasons[tool] = reason
        
        # Create coverage gap
        gap = self._create_coverage_gap(tool, category, reason)
        if gap:
            self.coverage.coverage_gaps.append(gap)
    
    def _create_coverage_gap(self, tool: str, category: str, 
                            reason: BlockReason) -> CoverageGap:
        """Create coverage gap from block reason"""
        
        impact_map = {
            BlockReason.NO_CRAWLER_DATA: f"{tool} could not test any endpoints - crawler failed",
            BlockReason.NO_PARAMETERS: f"{tool} could not test parameters - none discovered",
            BlockReason.NO_ENDPOINTS: f"{tool} could not test endpoints - none crawled",
            BlockReason.READINESS_FAILED: f"{tool} prerequisites not met",
            BlockReason.DECISION_LEDGER: f"{tool} blocked by decision logic",
            BlockReason.PARSE_FAILED: f"{tool} output could not be parsed into signals",
            BlockReason.TOOL_NOT_INSTALLED: f"{tool} not available on system"
        }
        
        remediation_map = {
            BlockReason.NO_CRAWLER_DATA: "Fix crawler errors - crawler is mandatory for payload tools",
            BlockReason.NO_PARAMETERS: "Ensure target has parameters (query/form/body)",
            BlockReason.NO_ENDPOINTS: "Check if target is reachable and has web endpoints",
            BlockReason.READINESS_FAILED: "Verify tool prerequisites (params, methods, context)",
            BlockReason.DECISION_LEDGER: "Review decision ledger rules",
            BlockReason.PARSE_FAILED: "Tool output format not recognized - check tool version",
            BlockReason.TOOL_NOT_INSTALLED: "Install tool on system"
        }
        
        return CoverageGap(
            tool=tool,
            category=category,
            reason=reason,
            impact=impact_map.get(reason, f"{tool} blocked"),
            remediation=remediation_map.get(reason, "Unknown")
        )
    
    def get_coverage_report(self) -> Dict:
        """Generate coverage report"""
        return {
            "tested": {
                "endpoints": sorted(list(self.coverage.tested_endpoints)),
                "parameters": sorted(list(self.coverage.tested_parameters)),
                "methods": sorted(list(self.coverage.tested_methods)),
                "tools": self.coverage.executed_tools
            },
            "blocked": {
                "tools": self.coverage.blocked_tools,
                "reasons": {tool: reason.value for tool, reason in self.block_reasons.items()}
            },
            "coverage_gaps": [
                {
                    "tool": gap.tool,
                    "category": gap.category,
                    "reason": gap.reason.value,
                    "impact": gap.impact,
                    "remediation": gap.remediation
                }
                for gap in self.coverage.coverage_gaps
            ],
            "summary": {
                "total_tools_planned": len(self.tool_outcomes),
                "tools_executed": len(self.coverage.executed_tools),
                "tools_blocked": len(self.coverage.blocked_tools),
                "execution_rate": (
                    len(self.coverage.executed_tools) / len(self.tool_outcomes)
                    if self.tool_outcomes else 0
                ),
                "endpoints_tested": len(self.coverage.tested_endpoints),
                "parameters_tested": len(self.coverage.tested_parameters)
            }
        }
    
    def log_coverage_summary(self):
        """Log coverage summary"""
        report = self.get_coverage_report()
        summary = report["summary"]
        
        logger.info(f"[Coverage] Executed: {summary['tools_executed']}, Blocked: {summary['tools_blocked']}")
        logger.info(f"[Coverage] Tested: {summary['endpoints_tested']} endpoints, {summary['parameters_tested']} parameters")
        
        if self.coverage.coverage_gaps:
            logger.warning(f"[Coverage] {len(self.coverage.coverage_gaps)} coverage gaps detected:")
            for gap in self.coverage.coverage_gaps:
                logger.warning(f"  - {gap.tool}: {gap.impact}")
