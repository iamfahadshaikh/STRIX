"""
Crawler Integration Layer
Purpose: Orchestrate crawler execution, feed results to discovery cache,
         gate payload tools based on crawl signals
         
Architecture:
  crawler_integration.run() 
    -> KatanaCrawler.crawl() OR LightCrawler.crawl()
    -> CrawlParser.parse_katana_results()
    -> cache_discovery.add_endpoints(), add_parameters()
    -> Returns gating signals for payload tools
"""

import logging
import json
from typing import Dict, Optional, Tuple, List
from pathlib import Path

logger = logging.getLogger(__name__)


class CrawlerIntegration:
    """
    Bridges crawler (Katana) with discovery cache and payload gating
    
    Workflow:
    1. Check if web is reachable (gating signal)
    2. Run Katana crawl if available
    3. Parse results and feed to cache
    4. Return gating signals for downstream payload tools
    """

    def __init__(self, target: str, cache, output_dir: str, 
                 timeout: int = 180, depth: int = 2, js_crawl: bool = True):
        """
        Args:
            target: Target URL (scheme required: https://example.com)
            cache: cache_discovery.DiscoveryCache instance
            output_dir: Where to save crawl results
            timeout: Crawl timeout (seconds)
            depth: Crawl depth (1-3)
            js_crawl: Enable JavaScript execution (MANDATORY for modern apps)
        """
        self.target = target
        self.cache = cache
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.depth = depth
        self.js_crawl = js_crawl
        self.crawl_result: Optional[Dict] = None
        self.crawl_file = self.output_dir / "crawl_results.json"

    def should_crawl(self) -> bool:
        """
        Determine if crawling is worth attempting
        
        Gating logic:
        - Only crawl if web is reachable (from cache signals)
        - Skip if we've already crawled (check crawl_file)
        - Skip if no params/endpoints discovered yet (can't determine yet)
        
        Returns:
            bool: True if we should attempt crawl
        """
        # Check if already crawled
        if self.crawl_file.exists():
            logger.info("[CrawlerInt] Crawl result already exists, skipping recrawl")
            self._load_cached_crawl()
            return False

        # Check if web is reachable (would have been discovered by nmap/whatweb)
        # This is implicit for now - if target has HTTP service, web is reachable
        
        logger.info("[CrawlerInt] Web crawling eligible")
        return True

    def run(self) -> Tuple[bool, Dict]:
        """
        Execute crawl and integrate results
        
        Strategy:
        1. Try light_crawler first (fast, always works)
        2. If insufficient results, try Katana (comprehensive but slow)
        
        Returns:
            (success: bool, gating_signals: Dict)
            
        gating_signals keys:
            - has_parameters: bool
            - parameter_count: int
            - has_forms: bool
            - has_api: bool
            - reflectable_params: List[str]
            - crawl_success: bool
            - crawler_type: str (light or katana)
        """
        # Import here to avoid hard dependency
        try:
            from crawl_parser import CrawlParser
        except ImportError:
            logger.warning("[CrawlerInt] Crawl modules not available")
            return False, self._empty_signals()

        if not self.should_crawl():
            return self._load_or_empty()

        # Try light crawler first (always fast)
        try:
            from light_crawler import LightCrawler
            light = LightCrawler(self.target, timeout=self.timeout)
            logger.info("[CrawlerInt] Starting light crawler (fast)...")
            if light.crawl():
                crawl_json = light.to_json()
                self.crawl_result = json.loads(crawl_json)
                
                # Convert light crawl format to standard format
                summary = self.crawl_result.get("summary", {})
                parsed = {
                    "endpoints": summary.get("endpoints_list", []),
                    "parameters": summary.get("parameters", {}),
                    "forms": summary.get("forms_list", []),
                    "api_endpoints": summary.get("api_endpoints_list", []),
                    "reflections": self._identify_reflections_from_light(summary),
                    "total_crawled": summary.get("crawled_urls", 0),
                    "total_endpoints": summary.get("endpoints", 0)
                }
                
                self._integrate_with_cache(parsed)
                self._save_crawl_results(crawl_json)
                
                gating = CrawlParser.extract_for_payload_gating(parsed)
                gating['crawl_success'] = True
                gating['crawler_type'] = 'light'
                
                logger.info(f"[CrawlerInt] Light crawl: {len(parsed['endpoints'])} endpoints, "
                           f"{len(parsed['parameters'])} params")
                return True, gating
        except ImportError:
            logger.warning("[CrawlerInt] Light crawler not available")
        except Exception as e:
            logger.warning(f"[CrawlerInt] Light crawler failed: {e}")

        # Fall back to Katana (comprehensive but slow)
        try:
            from katana_crawler import KatanaCrawler
            from crawl_parser import CrawlParser
            
            crawler = KatanaCrawler(self.target, timeout=self.timeout, depth=self.depth)
            if crawler.is_available():
                logger.info("[CrawlerInt] Light crawler insufficient, trying Katana...")
                if crawler.crawl():
                    crawl_json = crawler.to_json()
                    self.crawl_result = json.loads(crawl_json)
                    parsed = CrawlParser.parse_katana_results(crawl_json)
                    self._integrate_with_cache(parsed)
                    self._save_crawl_results(crawl_json)
                    
                    gating = CrawlParser.extract_for_payload_gating(parsed)
                    gating['crawl_success'] = True
                    gating['crawler_type'] = 'katana'
                    
                    logger.info(f"[CrawlerInt] Katana crawl: {len(parsed['endpoints'])} endpoints, "
                               f"{len(parsed['parameters'])} params")
                    return True, gating
        except ImportError:
            pass
        except Exception as e:
            logger.warning(f"[CrawlerInt] Katana crawl failed: {e}")

        logger.error("[CrawlerInt] All crawlers failed or unavailable")
        return False, self._empty_signals()

    def _integrate_with_cache(self, parsed: Dict):
        """Feed crawl results into cache_discovery"""
        if not self.cache:
            logger.warning("[CrawlerInt] No cache provided, skipping integration")
            return
            
        # Add endpoints (limit to 100 to avoid cache bloat)
        endpoints_added = 0
        for endpoint in parsed.get("endpoints", [])[:100]:
            self.cache.add_endpoint(endpoint, source_tool="crawler", confidence=0.8)
            endpoints_added += 1

        # Add parameters as signals
        params_added = 0
        for param_name, values in parsed.get("parameters", {}).items():
            self.cache.add_param(param_name, source_tool="crawler", confidence=0.8)
            params_added += 1

        # Add reflections (high-confidence XSS/injection targets)
        reflections_added = 0
        for reflection in parsed.get("reflections", []):
            self.cache.add_reflection(reflection)
            reflections_added += 1
        
        # Add API endpoints to live_endpoints (crawler verified they respond)
        api_endpoints_added = 0
        for api_endpoint in parsed.get("api_endpoints", [])[:50]:
            self.cache.live_endpoints.add(api_endpoint)
            api_endpoints_added += 1

        logger.info(f"[CrawlerInt] Integrated crawl results: "
                   f"{endpoints_added} endpoints, {params_added} params, "
                   f"{reflections_added} reflections, {api_endpoints_added} API endpoints")

    def _identify_reflections_from_light(self, summary: Dict) -> List[str]:
        """Identify reflectable params from light crawler output"""
        reflections = set()
        
        reflectable_keywords = {
            'search', 'q', 'query', 'text', 'message', 'comment',
            'id', 'uid', 'user_id', 'post_id',
            'redirect', 'callback', 'return', 'url', 'redirect_to',
            'file', 'path', 'filename',
            'name', 'email', 'username',
            'title', 'description', 'content',
            'filter', 'sort', 'order', 'category'
        }
        
        # Check parameter names
        for param in summary.get("parameters", {}).keys():
            if param.lower() in reflectable_keywords:
                reflections.add(param)
            elif any(x in param.lower() for x in ['_id', '_name', '_param', '_query']):
                reflections.add(param)
        
        # Check form fields
        for form in summary.get("forms_list", []):
            for field in form.get("fields", []):
                if field.lower() in reflectable_keywords:
                    reflections.add(field)
        
        return list(reflections)

    def _save_crawl_results(self, crawl_json: str):
        """Save crawl JSON to output directory"""
        try:
            self.crawl_file.write_text(crawl_json)
            logger.info(f"[CrawlerInt] Crawl results saved: {self.crawl_file}")
        except Exception as e:
            logger.error(f"[CrawlerInt] Failed to save crawl results: {e}")

    def _load_cached_crawl(self) -> bool:
        """Load previously saved crawl results"""
        try:
            with open(self.crawl_file) as f:
                self.crawl_result = json.load(f)
            logger.info("[CrawlerInt] Loaded cached crawl results")
            return True
        except Exception as e:
            logger.warning(f"[CrawlerInt] Failed to load cached crawl: {e}")
            return False

    def _load_or_empty(self) -> Tuple[bool, Dict]:
        """Load cached crawl or return empty signals"""
        if self._load_cached_crawl():
            try:
                from crawl_parser import CrawlParser
                # Re-parse cached results
                crawl_json = json.dumps(self.crawl_result)
                parsed = CrawlParser.parse_katana_results(crawl_json)
                gating = CrawlParser.extract_for_payload_gating(parsed)
                gating['crawl_success'] = True
                return True, gating
            except Exception as e:
                logger.warning(f"[CrawlerInt] Error loading cached crawl: {e}")
        
        return False, self._empty_signals()

    @staticmethod
    def _empty_signals() -> Dict:
        """Empty/default gating signals when crawl unavailable"""
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
            "crawl_success": False
        }

    def get_gating_decision(self, tool_name: str) -> bool:
        """
        Decide if a payload tool should run based on crawl signals
        
        Tool gating rules:
        - xsstrike: Needs reflectable params OR forms
        - sqlmap: Needs any parameters (URL or form)
        - commix: Needs any parameters
        - dalfox: Needs reflectable params
        - nuclei: Run always (no gating)
        """
        if not self.crawl_result:
            return False

        try:
            from crawl_parser import CrawlParser
            parsed = CrawlParser.parse_katana_results(json.dumps(self.crawl_result))
            gating = CrawlParser.extract_for_payload_gating(parsed)
        except:
            return False

        tool_lower = tool_name.lower()

        if "xss" in tool_lower or tool_lower == "dalfox":
            # XSS tools: need reflectable parameters or forms
            return gating['reflection_count'] > 0 or gating['has_forms']
        
        elif "sql" in tool_lower:
            # SQL injection: need any parameters
            return gating['parameter_count'] > 0
        
        elif "commix" in tool_lower:
            # Command injection: need any parameters
            return gating['parameter_count'] > 0
        
        elif "nuclei" in tool_lower:
            # Template-based: always run (different gating model)
            return True
        
        else:
            # Default: conservative (don't run)
            return False

    def summary(self) -> Dict:
        """Get human-readable summary"""
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
            "results_file": str(self.crawl_file)
        }


# Integration guide for decision_ledger.py:
"""
Decision Ledger Integration Points
==================================

In decision_ledger.py, to gate payload tools on crawl signals:

    # After crawl_integration.run()
    crawler_success, gating_signals = crawler_integration.run()
    
    # Gating for xsstrike
    if gating_signals['reflection_count'] > 0:
        decision_ledger.ALLOW['xsstrike'] = True
    else:
        decision_ledger.BLOCK['xsstrike'] = "No reflectable parameters found via crawl"
    
    # Gating for sqlmap
    if gating_signals['parameter_count'] > 0:
        decision_ledger.ALLOW['sqlmap'] = True
    else:
        decision_ledger.BLOCK['sqlmap'] = "No parameters found via crawl"

Future: This should be formalized in decision_ledger.py as:
    def gate_payload_tools(crawler_integration) -> None:
        '''Update allow/block decisions based on crawler signals'''
"""
