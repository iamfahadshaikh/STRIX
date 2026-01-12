"""
Lightweight HTTP-based Crawler (Alternative to Katana)
Purpose: Fast endpoint discovery without JS rendering
Use when: Katana is slow or not available, or for initial reconnaissance

This crawler:
- Fetches main page
- Extracts links via regex (HTML, JS, JSON)
- Extracts forms and input fields
- Identifies parameters
- Does NOT require Go installation or Katana
"""

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


@dataclass
class LightCrawlResult:
    """Lightweight crawl output"""
    url: str
    status: int = 0
    title: Optional[str] = None
    params: Dict[str, List[str]] = field(default_factory=dict)
    forms: List[Dict] = field(default_factory=list)
    links: List[str] = field(default_factory=list)
    js_endpoints: List[str] = field(default_factory=list)
    api_endpoints: List[str] = field(default_factory=list)


class LightCrawler:
    """
    Fast HTTP-based crawler (no browser automation)
    - Suitable for quick reconnaissance
    - Finds URLs, forms, parameters via regex
    - No JS rendering (limitation but much faster)
    """

    def __init__(self, target: str, timeout: int = 30, max_pages: int = 50):
        """
        Args:
            target: URL to crawl
            timeout: Request timeout
            max_pages: Max pages to crawl before stopping
        """
        self.target = target
        self.timeout = timeout
        self.max_pages = max_pages
        self.endpoints: Set[str] = set()
        self.parameters: Dict[str, Set[str]] = {}
        self.forms: List[Dict] = []
        self.js_endpoints: Set[str] = set()
        self.api_endpoints: Set[str] = set()
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create session with retries"""
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        session = requests.Session()
        retry = Retry(connect=1, backoff_factor=0.1, status_forcelist=[429, 500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        return session

    def crawl(self) -> bool:
        """
        Quick crawl of target
        
        Returns:
            bool: True if crawl succeeded
        """
        try:
            logger.info(f"[LightCrawl] Starting crawl: {self.target}")
            
            # Fetch main page
            resp = self.session.get(self.target, timeout=self.timeout, verify=False)
            resp.raise_for_status()
            
            logger.info(f"[LightCrawl] Got response: {resp.status_code}")
            
            # Extract from HTML
            self._extract_from_html(resp.text, self.target)
            
            logger.info(f"[LightCrawl] Crawl complete: {len(self.endpoints)} endpoints found")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"[LightCrawl] Request failed: {e}")
            return False
        except Exception as e:
            logger.error(f"[LightCrawl] Crawl error: {e}")
            return False

    def _extract_from_html(self, html: str, page_url: str):
        """Extract links, forms, parameters from HTML"""
        
        # Extract URLs from href and src
        href_pattern = r'''(href|src)=["']([^"']+)["']'''
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            url = match.group(2)
            full_url = urljoin(page_url, url)
            
            # Filter to same domain
            if self._is_same_domain(full_url, page_url):
                self.endpoints.add(full_url)
                
                # Check if API endpoint
                if '/api/' in full_url.lower():
                    self.api_endpoints.add(full_url)
                elif full_url.endswith('.js'):
                    self.js_endpoints.add(full_url)
        
        # Extract forms
        form_pattern = r'<form[^>]*>.*?</form>'
        for form_match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(0)
            action_match = re.search(r'action=["\'](.*?)["\']', form_html, re.IGNORECASE)
            
            action = action_match.group(1) if action_match else page_url
            action = urljoin(page_url, action)
            
            # Extract input fields
            fields = []
            input_pattern = r'<input[^>]*name=["\'](.*?)["\']'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                fields.append(input_match.group(1))
            
            if fields:
                self.forms.append({
                    "action": action,
                    "method": "POST",
                    "fields": fields,
                    "found_on": page_url
                })
                
                # Add field names as parameters
                for field in fields:
                    if field not in self.parameters:
                        self.parameters[field] = set()
                    self.parameters[field].add("")
        
        # Extract parameters from URLs already found
        for endpoint in list(self.endpoints):
            parsed = urlparse(endpoint)
            if parsed.query:
                params = parse_qs(parsed.query)
                for key, vals in params.items():
                    if key not in self.parameters:
                        self.parameters[key] = set()
                    self.parameters[key].update(vals)

    def _is_same_domain(self, url: str, base_url: str) -> bool:
        """Check if URL is on same domain as base"""
        try:
            parsed_url = urlparse(url)
            parsed_base = urlparse(base_url)
            return parsed_url.netloc == parsed_base.netloc
        except Exception:
            return False

    def get_summary(self) -> Dict:
        """Get crawl summary"""
        return {
            "target": self.target,
            "endpoints": len(self.endpoints),
            "unique_parameters": len(self.parameters),
            "forms": len(self.forms),
            "api_endpoints": len(self.api_endpoints),
            "crawled_urls": len(self.endpoints),
            "parameters": {k: list(v) for k, v in self.parameters.items()},
            "endpoints_list": sorted(list(self.endpoints))[:50],
            "forms_list": self.forms[:20],
            "api_endpoints_list": sorted(list(self.api_endpoints))[:20]
        }

    def to_json(self) -> str:
        """Serialize to JSON"""
        return json.dumps({
            "summary": self.get_summary(),
            "results": []
        }, indent=2)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 light_crawler.py <url>")
        sys.exit(1)
    
    target = sys.argv[1]
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    crawler = LightCrawler(target, timeout=30)
    
    if crawler.crawl():
        print(crawler.to_json())
    else:
        print(json.dumps({"error": "Crawl failed"}))
        sys.exit(1)
