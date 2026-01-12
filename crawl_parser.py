"""
Crawl Output Parser
Purpose: Convert Katana crawl results into cache_discovery format
Output: Feeds cache_discovery endpoints, params, reflections for payload gating
"""

import json
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse, parse_qs
import logging

logger = logging.getLogger(__name__)


class CrawlParser:
    """
    Parse crawler output (Katana JSON) into discovery cache format
    
    Input: Katana JSON (endpoints, params, forms)
    Output: cache_discovery compatible signals
    """

    @staticmethod
    def parse_katana_results(crawl_json: str) -> Dict:
        """
        Parse Katana crawl JSON output
        
        Args:
            crawl_json: JSON string from katana_crawler.get_summary()
            
        Returns:
            dict with keys:
            - endpoints: List[str] - discovered URLs
            - parameters: Dict[str, List[str]] - param_name -> [values]
            - forms: List[Dict] - form definitions
            - api_endpoints: List[str] - API URLs
            - reflections: Set[str] - potentially reflectable params
        """
        try:
            data = json.loads(crawl_json)
        except json.JSONDecodeError:
            logger.error("Failed to parse crawl JSON")
            return CrawlParser._empty_result()

        summary = data.get("summary", {})
        results = data.get("results", [])

        endpoints = summary.get("endpoints_list", [])
        parameters = summary.get("parameters", {})
        forms = summary.get("forms_list", [])
        api_endpoints = [r for r in results if r.get("is_api")]

        # Extract reflectable parameters (common injection points)
        reflections = CrawlParser._identify_reflections(
            endpoints, 
            parameters, 
            forms
        )

        return {
            "endpoints": endpoints,
            "parameters": parameters,
            "forms": forms,
            "api_endpoints": [e.get("url") for e in api_endpoints][:20],
            "reflections": list(reflections),
            "total_crawled": len(results),
            "total_endpoints": summary.get("endpoints", 0)
        }

    @staticmethod
    def _identify_reflections(endpoints: List[str], 
                             parameters: Dict[str, List[str]],
                             forms: List[Dict]) -> Set[str]:
        """
        Identify potentially reflectable parameters (injection candidates)
        
        Common patterns:
        - search, q, query
        - id, uid, user_id
        - redirect, callback, return, url
        - file, path, url
        - message, comment, text
        """
        reflections = set()
        
        # From URL parameters
        reflectable_keywords = {
            'search', 'q', 'query', 'text', 'message', 'comment',
            'id', 'uid', 'user_id', 'post_id',
            'redirect', 'callback', 'return', 'url', 'redirect_to',
            'file', 'path', 'filename',
            'name', 'email', 'username',
            'title', 'description', 'content',
            'filter', 'sort', 'order', 'category'
        }
        
        for param in parameters.keys():
            if param.lower() in reflectable_keywords:
                reflections.add(param)
            # Also catch *_id, *_name patterns
            elif any(x in param.lower() for x in ['_id', '_name', '_param', '_query']):
                reflections.add(param)

        # From form fields
        for form in forms:
            for field in form.get("fields", []):
                field_name = field.get("name", "").lower()
                if field_name in reflectable_keywords:
                    reflections.add(field_name)

        logger.info(f"[CrawlParser] Identified {len(reflections)} reflectable parameters")
        return reflections

    @staticmethod
    def to_cache_format(crawl_result: Dict) -> Dict:
        """
        Convert parsed crawl to cache_discovery format
        
        Returns dict suitable for cache_discovery.DiscoveryCache.add_*() calls
        """
        return {
            "endpoints": crawl_result.get("endpoints", []),
            "parameters": crawl_result.get("parameters", {}),
            "forms": crawl_result.get("forms", []),
            "api_endpoints": crawl_result.get("api_endpoints", []),
            "reflections": crawl_result.get("reflections", []),
            "crawled_urls_count": crawl_result.get("total_crawled", 0),
        }

    @staticmethod
    def extract_for_payload_gating(crawl_result: Dict) -> Dict:
        """
        Extract signals needed for payload tool gating
        
        Used by decision_ledger to decide which payload tools to run
        
        Returns:
            {
                "has_params": bool - any parameters found?,
                "param_count": int,
                "has_forms": bool - form-based XSS/CSRF vectors?,
                "has_api": bool - JSON APIs present?,
                "api_count": int,
                "reflections": List[str] - which params might reflect?
            }
        """
        params = crawl_result.get("parameters", {})
        forms = crawl_result.get("forms", [])
        api_endpoints = crawl_result.get("api_endpoints", [])
        reflections = crawl_result.get("reflections", [])

        return {
            "has_parameters": len(params) > 0,
            "parameter_count": len(params),
            "parameter_names": list(params.keys()),
            "has_forms": len(forms) > 0,
            "form_count": len(forms),
            "has_api": len(api_endpoints) > 0,
            "api_count": len(api_endpoints),
            "reflectable_params": reflections,
            "reflection_count": len(reflections),
            "crawled_url_count": crawl_result.get("total_crawled", 0)
        }

    @staticmethod
    def _empty_result() -> Dict:
        """Return empty crawl result"""
        return {
            "endpoints": [],
            "parameters": {},
            "forms": [],
            "api_endpoints": [],
            "reflections": [],
            "total_crawled": 0,
            "total_endpoints": 0
        }


# Integration example (to be wired into automation_scanner_v2.py decision layer):
"""
Example usage in decision_ledger.py:

def should_run_xsstrike(cache) -> bool:
    '''Gate xsstrike on crawl signals'''
    crawl_data = cache.get_crawl_result()
    if not crawl_data:
        return False  # No crawl data yet
    
    gating = CrawlParser.extract_for_payload_gating(crawl_data)
    
    # Run if: (1) we found reflectable params OR (2) we have forms
    return gating['reflection_count'] > 0 or gating['has_forms']

def should_run_sqlmap(cache) -> bool:
    '''Gate sqlmap on crawl signals'''
    crawl_data = cache.get_crawl_result()
    if not crawl_data:
        return False
    
    gating = CrawlParser.extract_for_payload_gating(crawl_data)
    
    # Run if we found any parameters (URL or form)
    return gating['parameter_count'] > 0
"""
