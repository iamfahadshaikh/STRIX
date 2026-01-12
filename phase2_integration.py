"""
Phase 2 Integration Helper for automation_scanner_v2
Purpose: Wrap Phase 2 pipeline for easy integration without breaking existing code

This module provides:
  1. Lazy initialization of Phase 2 components
  2. Backward compatibility with old gating_loop
  3. Safe error handling with fallback
  4. Clear API for tool gating queries
"""

import logging
import threading
from typing import Optional, Dict, List
from pathlib import Path

from phase2_pipeline import Phase2Pipeline
from decision_ledger import DecisionLedger

logger = logging.getLogger(__name__)


class Phase2IntegrationHelper:
    """
    Wrapper for Phase 2 pipeline, safe to integrate into automation_scanner_v2
    
    Usage:
        helper = Phase2IntegrationHelper(
            target_url="https://example.com",
            output_dir="./results",
            decision_ledger=ledger
        )
        
        if helper.should_run_tool("dalfox"):
            targets = helper.get_tool_targets("dalfox")
            # Run tool on targets
            
        conf, owasp = helper.score_finding(...)
    """

    def __init__(self, target_url: str, output_dir: str, decision_ledger: DecisionLedger,
                 timeout: int = 180, enabled: bool = True):
        """
        Args:
            target_url: Target URL (with scheme)
            output_dir: Output directory
            decision_ledger: Decision ledger from scanner
            timeout: Crawl timeout
            enabled: Whether to enable Phase 2 (default True)
        """
        self.target_url = target_url
        self.output_dir = Path(output_dir)
        self.decision_ledger = decision_ledger
        self.timeout = timeout
        self.enabled = enabled

        self.pipeline: Optional[Phase2Pipeline] = None
        self._initialized = False
        self._lock = threading.Lock()
        self._init_thread: Optional[threading.Thread] = None

    def initialize_async(self):
        """
        Initialize Phase 2 pipeline in background thread
        Call this early in scan to parallelize with other phases
        
        Usage:
            helper.initialize_async()
            # ... do other work ...
            helper.wait_for_initialization()  # Will block if still initializing
        """
        if not self.enabled or self._initialized:
            return

        def _init():
            try:
                logger.info("[Phase2Helper] Initializing Phase 2 pipeline in background...")
                pipeline = Phase2Pipeline(
                    target_url=self.target_url,
                    output_dir=str(self.output_dir),
                    decision_ledger=self.decision_ledger,
                    timeout=self.timeout
                )

                if pipeline.run():
                    with self._lock:
                        self.pipeline = pipeline
                        self._initialized = True
                    logger.info("[Phase2Helper] Phase 2 pipeline initialized successfully")
                else:
                    logger.warning("[Phase2Helper] Phase 2 pipeline initialization failed, gating disabled")
                    with self._lock:
                        self._initialized = True

            except Exception as e:
                logger.error(f"[Phase2Helper] Phase 2 initialization error: {e}")
                with self._lock:
                    self._initialized = True

        self._init_thread = threading.Thread(target=_init, daemon=True)
        self._init_thread.start()

    def wait_for_initialization(self, timeout: int = 180) -> bool:
        """
        Wait for Phase 2 initialization to complete
        
        Args:
            timeout: Max seconds to wait
            
        Returns:
            bool: True if pipeline is ready, False if timed out or failed
        """
        if not self.enabled:
            return False

        if self._init_thread:
            self._init_thread.join(timeout=timeout)

        return self._initialized and self.pipeline is not None

    def should_run_tool(self, tool_name: str) -> bool:
        """
        Check if tool should run (from Phase 2 gating)
        
        Returns:
            bool: True if tool should run based on graph analysis
        """
        if not self.enabled or not self.pipeline:
            return True  # Fall back to allow if Phase 2 unavailable

        try:
            return self.pipeline.should_run_tool(tool_name)
        except Exception as e:
            logger.warning(f"[Phase2Helper] Error checking gating for {tool_name}: {e}")
            return True  # Fall back to allow

    def get_tool_targets(self, tool_name: str) -> List[str]:
        """
        Get endpoints that tool should target (from graph)
        
        Returns:
            List of endpoint paths for tool to test
        """
        if not self.enabled or not self.pipeline:
            return []

        try:
            return self.pipeline.get_tool_targets(tool_name)
        except Exception as e:
            logger.warning(f"[Phase2Helper] Error getting targets for {tool_name}: {e}")
            return []

    def score_finding(self, finding_id: str, vuln_type: str,
                     tools_reporting: List[str],
                     success_indicator: Optional[str] = None) -> tuple:
        """
        Score finding confidence and get OWASP category
        
        Args:
            finding_id: Unique finding ID
            vuln_type: Vulnerability type (xss, sqli, etc)
            tools_reporting: Tools that detected this
            success_indicator: Type of success (confirmed_reflected, etc)
            
        Returns:
            (confidence_level, owasp_category)
            Example: ("HIGH", "A03:2021 – Injection")
        """
        if not self.enabled or not self.pipeline:
            return ("MEDIUM", "A05:2021")  # Safe default

        try:
            confidence, owasp = self.pipeline.score_finding(
                finding_id=finding_id,
                vuln_type=vuln_type,
                tools_reporting=tools_reporting,
                success_indicator=success_indicator
            )
            return (confidence.value, owasp)
        except Exception as e:
            logger.warning(f"[Phase2Helper] Error scoring finding {finding_id}: {e}")
            return ("MEDIUM", "A05:2021")  # Safe default

    def get_summary(self) -> Dict:
        """Get Phase 2 pipeline summary"""
        if not self.enabled or not self.pipeline:
            return {"status": "disabled"}

        try:
            return self.pipeline.get_summary()
        except Exception as e:
            logger.warning(f"[Phase2Helper] Error getting summary: {e}")
            return {"status": "error"}

    def get_graph_summary(self) -> Optional[Dict]:
        """Get endpoint graph summary"""
        if not self.enabled or not self.pipeline or not self.pipeline.graph:
            return None

        try:
            return self.pipeline.graph.get_summary()
        except Exception as e:
            logger.warning(f"[Phase2Helper] Error getting graph summary: {e}")
            return None


# Example integration into automation_scanner_v2
"""
In automation_scanner_v2.run_full_scan():

# Early initialization (parallelizes with DNS/network phases)
phase2_helper = Phase2IntegrationHelper(
    target_url=f"{'https' if profile.is_https else 'http'}://{profile.host}",
    output_dir=str(self.output_dir),
    decision_ledger=self.ledger,
    enabled=True
)
phase2_helper.initialize_async()

# ... Run DNS, Network, WebDetection phases ...

# Before payload tools, wait for Phase 2
phase2_helper.wait_for_initialization(timeout=180)

# During execution loop
for tool_name, cmd, meta in plan:
    # Use Phase 2 gating for payload tools
    if tool_name in ["dalfox", "xsstrike", "sqlmap", "commix"]:
        if not phase2_helper.should_run_tool(tool_name):
            self.log(f"[{tool_name}] GATED (Phase 2 analysis)", "INFO")
            continue
        
        targets = phase2_helper.get_tool_targets(tool_name)
        if targets:
            self.log(f"[{tool_name}] Targeting: {targets}", "DEBUG")

# For findings
conf, owasp = phase2_helper.score_finding(
    finding_id="xss_001",
    vuln_type="xss",
    tools_reporting=["dalfox"],
    success_indicator="confirmed_reflected"
)

# Report
summary = phase2_helper.get_summary()
"""
