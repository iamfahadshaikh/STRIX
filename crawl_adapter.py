"""
Crawler Adapter - Integration Bridge
Purpose: Connect crawler layer to automation_scanner_v2 without core modifications
Approach: Optional crawl phase that feeds gating signals to decision_ledger
"""

import logging
import json
from pathlib import Path
from typing import Dict, Optional, Tuple
from crawler_integration import CrawlerIntegration
from crawl_parser import CrawlParser

logger = logging.getLogger(__name__)


class CrawlAdapter:
    """
    Bridge between crawler layer and scanner orchestration
    
    Workflow:
    1. Scanner runs DNS/Network phase
    2. CrawlAdapter.run() executes crawl (Katana or light_crawler)
    3. Returns gating signals for payload tools
    4. decision_ledger uses signals to gate xsstrike/sqlmap/etc
    """

    def __init__(self, target: str, output_dir: str, cache=None, timeout: int = 180):
        """
        Args:
            target: Target URL (HTTPS scheme required)
            output_dir: Scan results directory
            cache: DiscoveryCache instance (optional but recommended)
            timeout: Crawl timeout
        """
        self.target = target
        self.output_dir = Path(output_dir)
        self.cache = cache
        self.timeout = timeout
        self.crawl_result: Optional[Dict] = None
        self.gating_signals: Optional[Dict] = None

    def run(self) -> Tuple[bool, Dict]:
        """
        Execute crawl and return gating signals
        
        Returns:
            (success, gating_signals)
            
        Safe to call multiple times (caches result)
        """
        if self.crawl_result is not None:
            logger.info("[CrawlAdapter] Using cached crawl result")
            return True, self.gating_signals

        logger.info("[CrawlAdapter] Starting crawler integration...")

        try:
            crawler_int = CrawlerIntegration(
                target=self.target,
                cache=self.cache,
                output_dir=str(self.output_dir),
                timeout=self.timeout,
                depth=1
            )

            success, gating = crawler_int.run()

            if success:
                self.crawl_result = crawler_int.crawl_result
                self.gating_signals = gating
                logger.info(f"[CrawlAdapter] Crawl success (type={gating.get('crawler_type')})")
                logger.info(f"[CrawlAdapter]   Endpoints: {gating['parameter_count']} params, "
                           f"{gating['reflection_count']} reflections")
            else:
                logger.warning("[CrawlAdapter] Crawl failed, using empty signals")
                self.gating_signals = self._empty_signals()

            return success, self.gating_signals

        except Exception as e:
            logger.error(f"[CrawlAdapter] Unexpected error: {e}")
            self.gating_signals = self._empty_signals()
            return False, self.gating_signals

    def get_gating_for_tool(self, tool_name: str) -> bool:
        """
        Determine if a payload tool should run based on crawl
        
        Args:
            tool_name: Tool identifier (xsstrike, sqlmap, commix, dalfox, nuclei)
            
        Returns:
            bool: True if tool should run
        """
        if not self.gating_signals:
            return False

        gating = self.gating_signals
        tool_lower = tool_name.lower()

        # XSS tools: need reflectable parameters or forms
        if "xss" in tool_lower or tool_lower == "dalfox":
            return gating['reflection_count'] > 0 or gating['has_forms']

        # SQL injection: need any parameters
        elif "sql" in tool_lower:
            return gating['parameter_count'] > 0

        # Command injection: need any parameters
        elif "commix" in tool_lower:
            return gating['parameter_count'] > 0

        # Template-based: different model (always runs)
        elif "nuclei" in tool_lower:
            return True

        else:
            return False

    def apply_to_decision_ledger(self, decision_ledger) -> None:
        """
        Update decision_ledger with crawl-based gating
        
        Usage:
            adapter = CrawlAdapter(target, output_dir)
            adapter.run()
            adapter.apply_to_decision_ledger(decision_ledger)
        
        This updates ALLOW/BLOCK decisions based on crawl findings.
        """
        if not self.gating_signals:
            logger.warning("[CrawlAdapter] No gating signals available")
            return

        gating = self.gating_signals

        # XSS tools (xsstrike, dalfox)
        for tool in ['xsstrike', 'dalfox']:
            if gating['reflection_count'] > 0 or gating['has_forms']:
                decision_ledger.ALLOW[tool] = True
                logger.info(f"[CrawlAdapter] ALLOW {tool} (found reflections/forms)")
            else:
                decision_ledger.BLOCK[tool] = "No reflectable parameters found via crawl"
                logger.info(f"[CrawlAdapter] BLOCK {tool}")

        # SQL injection tools
        for tool in ['sqlmap']:
            if gating['parameter_count'] > 0:
                decision_ledger.ALLOW[tool] = True
                logger.info(f"[CrawlAdapter] ALLOW {tool} (found parameters)")
            else:
                decision_ledger.BLOCK[tool] = "No parameters found via crawl"
                logger.info(f"[CrawlAdapter] BLOCK {tool}")

        # Command injection
        for tool in ['commix']:
            if gating['parameter_count'] > 0:
                decision_ledger.ALLOW[tool] = True
                logger.info(f"[CrawlAdapter] ALLOW {tool} (found parameters)")
            else:
                decision_ledger.BLOCK[tool] = "No parameters found via crawl"
                logger.info(f"[CrawlAdapter] BLOCK {tool}")

        logger.info("[CrawlAdapter] Applied crawl-based gating to decision ledger")

    def summary(self) -> Dict:
        """Get summary for reporting"""
        if not self.crawl_result:
            return {"status": "no_crawl", "crawled": False}

        summary = self.crawl_result.get("summary", {})
        return {
            "status": "crawled",
            "crawled": True,
            "endpoints": summary.get("endpoints", 0),
            "unique_parameters": summary.get("unique_parameters", 0),
            "forms": summary.get("forms", 0),
            "api_endpoints": summary.get("api_endpoints", 0),
            "crawled_urls": summary.get("crawled_urls", 0),
            "gating_signals": self.gating_signals
        }

    @staticmethod
    def _empty_signals() -> Dict:
        """Empty signals when crawl unavailable"""
        return {
            "has_parameters": False,
            "parameter_count": 0,
            "parameter_names": [],
            "has_forms": False,
            "form_count": 0,
            "has_api": False,
            "api_count": 0,
            "reflectable_params": [],
            "reflection_count": 0,
            "crawled_url_count": 0,
            "crawl_success": False,
            "crawler_type": "none"
        }


# Usage Examples
"""
APPROACH 1: Standalone Crawler (No Scanner Integration)
=======================================================

from crawl_adapter import CrawlAdapter

adapter = CrawlAdapter(
    target="https://example.com",
    output_dir="./scan_results",
    timeout=180
)

success, gating = adapter.run()

if success:
    print(f"Found {gating['parameter_count']} parameters")
    print(f"Should run xsstrike: {adapter.get_gating_for_tool('xsstrike')}")
    print(f"Should run sqlmap: {adapter.get_gating_for_tool('sqlmap')}")


APPROACH 2: Integrated with Scanner (After DNS/Network Phase)
=============================================================

In automation_scanner_v2.py (optional, non-invasive):

    # After nmap runs (after phase 3)
    if self.target_profile.is_web():
        from crawl_adapter import CrawlAdapter
        
        crawl_adapter = CrawlAdapter(
            target=self.target,
            output_dir=self.output_dir,
            timeout=300
        )
        crawl_adapter.run()
        crawl_adapter.apply_to_decision_ledger(self.decision_ledger)


APPROACH 3: Gating Specific Tools
=================================

In decision_ledger.py (modify should_run_*() methods):

    def should_run_xsstrike(self) -> bool:
        # Existing logic
        if not self._is_web_target():
            return False
        
        # New: Check crawl signals if available
        if hasattr(self, 'crawl_gating'):
            return self.crawl_gating.get('reflection_count', 0) > 0
        
        # Fallback: conservative
        return False
"""
