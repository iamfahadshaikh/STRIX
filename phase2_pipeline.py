"""
Phase 2 Pipeline Orchestrator - Unified Integration
Purpose: Coordinate crawling → graph building → strict gating → confidence scoring → OWASP mapping

Architecture:
  1. Crawl target (Katana or light_crawler)
  2. Extract crawl results into EndpointGraph
  3. Mark parameters (reflectable, injectable)
  4. Apply strict gating (which tools run)
  5. Score confidence for each finding
  6. Map to OWASP categories
  7. Report with clear classifications (discovery vs confirmed)

This layer sits BETWEEN crawl_adapter and automation_scanner_v2
Preserves existing gating architecture while adding graph + scoring
"""

import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

from crawl_adapter import CrawlAdapter
from endpoint_graph import EndpointGraph, ParameterSource
from strict_gating_loop import StrictGatingLoop
from confidence_engine import ConfidenceEngine, Confidence
from owasp_mapper import OWASPMapper, FindingClassification
from decision_ledger import DecisionLedger

logger = logging.getLogger(__name__)


class Phase2Pipeline:
    """
    Unified Phase 2 pipeline: crawl → graph → gate → score → map → report
    
    Usage:
        pipeline = Phase2Pipeline(target_url, output_dir, decision_ledger)
        pipeline.run()
        summary = pipeline.get_summary()
    """

    def __init__(self, target_url: str, output_dir: str, decision_ledger: DecisionLedger, 
                 timeout: int = 180):
        """
        Args:
            target_url: Target to scan (with scheme)
            output_dir: Where to store results
            decision_ledger: Decision ledger (from scanner)
            timeout: Crawl timeout seconds
        """
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.decision_ledger = decision_ledger
        self.timeout = timeout

        # Phase 2 components
        self.crawl_adapter: Optional[CrawlAdapter] = None
        self.graph: Optional[EndpointGraph] = None
        self.gating_loop: Optional[StrictGatingLoop] = None
        self.confidence_engine: Optional[ConfidenceEngine] = None
        self.owasp_mapper: Optional[OWASPMapper] = None

        # Results
        self.gating_decisions: Dict = {}
        self.confidence_scores: Dict = {}
        self.owasp_mappings: Dict = {}
        self._complete = False

    def run(self) -> bool:
        """
        Execute full Phase 2 pipeline
        
        Returns:
            bool: Success flag
        """
        try:
            logger.info("[Phase2Pipeline] Starting...")

            # Step 1: Crawl target
            if not self._crawl_target():
                logger.warning("[Phase2Pipeline] Crawl failed, continuing with empty graph")
                self._init_empty_graph()

            # Step 2: Build endpoint graph
            if not self._build_graph():
                logger.error("[Phase2Pipeline] Graph building failed")
                return False

            # Step 3: Apply strict gating
            if not self._apply_gating():
                logger.error("[Phase2Pipeline] Gating failed")
                return False

            # Step 4: Initialize scoring engines
            self.confidence_engine = ConfidenceEngine()
            self.owasp_mapper = OWASPMapper()

            self._complete = True
            logger.info("[Phase2Pipeline] Complete")
            return True

        except Exception as e:
            logger.error(f"[Phase2Pipeline] Unexpected error: {e}")
            return False

    def _crawl_target(self) -> bool:
        """Step 1: Execute crawl"""
        logger.info(f"[Phase2Pipeline] Crawling {self.target_url}...")

        try:
            self.crawl_adapter = CrawlAdapter(
                target=self.target_url,
                output_dir=str(self.output_dir),
                timeout=self.timeout
            )

            success, signals = self.crawl_adapter.run()

            if success:
                logger.info(f"[Phase2Pipeline] Crawl success: {signals['crawled_url_count']} endpoints, "
                           f"{signals['parameter_count']} params, {signals['reflection_count']} reflections")
                return True
            else:
                logger.warning("[Phase2Pipeline] Crawl unsuccessful but continuing")
                return False

        except Exception as e:
            logger.error(f"[Phase2Pipeline] Crawl error: {e}")
            return False

    def _build_graph(self) -> bool:
        """Step 2: Extract crawl results into graph"""
        logger.info("[Phase2Pipeline] Building endpoint graph...")

        try:
            self.graph = EndpointGraph(target=self.target_url)

            # If we have crawl results, populate graph
            if self.crawl_adapter and self.crawl_adapter.crawl_result:
                crawl_data = self.crawl_adapter.crawl_result
                summary = crawl_data.get("summary", {})
                results = crawl_data.get("results", [])

                for result in results:
                    self.graph.add_crawl_result(
                        url=result.get("url", ""),
                        method=result.get("method", "GET"),
                        params=result.get("params"),
                        is_api=result.get("is_api", False),
                        is_form=result.get("is_form", False),
                        status_code=result.get("status_code")
                    )

                # Mark parameters based on crawl analysis
                signals = self.crawl_adapter.gating_signals or {}
                for param_name in signals.get("reflectable_params", []):
                    self.graph.mark_reflectable(param_name)

            # Finalize graph
            self.graph.finalize()
            logger.info(f"[Phase2Pipeline] Graph built: {self.graph.get_summary()}")
            return True

        except Exception as e:
            logger.error(f"[Phase2Pipeline] Graph building error: {e}")
            return False

    def _init_empty_graph(self):
        """Initialize empty graph if crawl failed"""
        logger.info("[Phase2Pipeline] Initializing empty graph")
        self.graph = EndpointGraph(target=self.target_url)
        self.graph.finalize()

    def _apply_gating(self) -> bool:
        """Step 3: Apply strict gating"""
        logger.info("[Phase2Pipeline] Applying strict gating...")

        try:
            if not self.graph:
                logger.error("[Phase2Pipeline] No graph for gating")
                return False

            self.gating_loop = StrictGatingLoop(self.graph, self.decision_ledger)
            self.gating_decisions = self.gating_loop.get_all_targets()

            logger.info("[Phase2Pipeline] Gating decisions:")
            for tool_name, targets in self.gating_decisions.items():
                logger.info(f"  {targets}")

            return True

        except Exception as e:
            logger.error(f"[Phase2Pipeline] Gating error: {e}")
            return False

    def should_run_tool(self, tool_name: str) -> bool:
        """
        Check if tool should run (from strict gating)
        
        Usage in automation_scanner_v2:
            if pipeline.should_run_tool("dalfox"):
                run_dalfox()
        """
        if tool_name not in self.gating_decisions:
            return False
        return self.gating_decisions[tool_name].can_run

    def get_tool_targets(self, tool_name: str) -> List[str]:
        """Get list of endpoints for a tool"""
        if tool_name not in self.gating_decisions:
            return []
        return self.gating_decisions[tool_name].target_endpoints

    def score_finding(self, finding_id: str, vuln_type: str,
                     tools_reporting: List[str],
                     success_indicator: Optional[str] = None) -> Tuple[Confidence, str]:
        """
        Score a finding's confidence
        
        Usage:
            conf, owasp = pipeline.score_finding(
                finding_id="xss_001",
                vuln_type="xss",
                tools_reporting=["dalfox"],
                success_indicator="confirmed_reflected"
            )
            print(f"Confidence: {conf.value}")  # HIGH
            print(f"OWASP: {owasp}")  # A03:2021
        """
        if not self.confidence_engine or not self.owasp_mapper:
            logger.warning("[Phase2Pipeline] Scoring engines not initialized")
            return Confidence.LOW, "A03:2021"

        # Determine classification
        classification = FindingClassification.DISCOVERY
        if success_indicator and "confirmed" in success_indicator.lower():
            classification = FindingClassification.CONFIRMED
        elif success_indicator and "error" in success_indicator.lower():
            classification = FindingClassification.EXPLOITATION_ATTEMPT

        # Score confidence
        param_frequency = 1
        source_type = "crawled"
        confidence = self.confidence_engine.score_finding(
            finding_id=finding_id,
            tools_reporting=tools_reporting,
            success_indicator=success_indicator,
            source_type=source_type,
            param_frequency=param_frequency
        )

        # Map to OWASP
        mapping = self.owasp_mapper.map_finding(
            vuln_type=vuln_type,
            classification=classification,
            confidence=confidence.value
        )

        # Store
        self.confidence_scores[finding_id] = confidence
        self.owasp_mappings[finding_id] = mapping

        return confidence, mapping.category.value

    def get_summary(self) -> Dict:
        """Get full pipeline summary"""
        if not self._complete:
            return {"status": "incomplete"}

        summary = {
            "status": "complete",
            "target": self.target_url,
            "timestamp": datetime.now().isoformat(),
        }

        # Graph summary
        if self.graph:
            summary["graph"] = self.graph.get_summary()

        # Gating summary
        if self.gating_loop:
            summary["gating"] = self.gating_loop.get_summary()

        # Confidence scores
        if self.confidence_scores:
            summary["confidence_scores"] = {
                fid: conf.value for fid, conf in self.confidence_scores.items()
            }

        # OWASP mappings
        if self.owasp_mappings:
            summary["owasp_mappings"] = {
                fid: {
                    "category": mapping.category.value,
                    "cwe": mapping.cwe,
                    "classification": mapping.classification.value
                }
                for fid, mapping in self.owasp_mappings.items()
            }

        return summary

    def to_dict(self) -> Dict:
        """Serialize entire pipeline"""
        return {
            "target": self.target_url,
            "complete": self._complete,
            "graph": self.graph.to_dict() if self.graph else None,
            "gating": {
                tool_name: targets.to_dict()
                for tool_name, targets in self.gating_decisions.items()
            },
            "confidence_scores": {
                fid: conf.value for fid, conf in self.confidence_scores.items()
            },
            "owasp_mappings": {
                fid: {
                    "category": mapping.category.value,
                    "cwe": mapping.cwe,
                    "classification": mapping.classification.value
                }
                for fid, mapping in self.owasp_mappings.items()
            }
        }


# Example usage
"""
from decision_ledger import DecisionLedger, Decision, DecisionEngine

# Create pipeline
pipeline = Phase2Pipeline(
    target_url="https://example.com",
    output_dir="./results",
    decision_ledger=decision_ledger  # from automation_scanner_v2
)

# Run pipeline
if pipeline.run():
    # Check if tools should run
    if pipeline.should_run_tool("dalfox"):
        targets = pipeline.get_tool_targets("dalfox")
        print(f"Running dalfox on: {targets}")

    if pipeline.should_run_tool("sqlmap"):
        targets = pipeline.get_tool_targets("sqlmap")
        print(f"Running sqlmap on: {targets}")

    # Score findings
    conf, owasp = pipeline.score_finding(
        finding_id="xss_001",
        vuln_type="xss",
        tools_reporting=["dalfox"],
        success_indicator="confirmed_reflected"
    )

    print(f"Confidence: {conf.value}")
    print(f"OWASP: {owasp}")

    # Summary
    print(pipeline.get_summary())
"""
