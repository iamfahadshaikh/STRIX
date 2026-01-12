"""
Stateful Web Crawler - Katana Wrapper
Purpose: Discover endpoints, parameters, forms, API patterns via crawling
Integration: Feeds cache_discovery with discovered signals
"""

import json
import subprocess
import logging
import re
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


@dataclass
class CrawlResult:
    """Crawler output model"""
    url: str
    status_code: int = 200
    title: Optional[str] = None
    method: str = "GET"
    body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    params: Dict[str, List[str]] = field(default_factory=dict)
    is_api: bool = False
    form_fields: List[Dict[str, str]] = field(default_factory=list)
    tags: Set[str] = field(default_factory=set)

    def to_dict(self):
        """Convert to dict, handling sets"""
        d = asdict(self)
        d['tags'] = list(self.tags)
        return d


class KatanaCrawler:
    """
    Stateful web crawler using projectdiscovery/katana
    - Crawls JavaScript-rendered pages
    - Discovers endpoints, parameters, forms
    - Tracks cookies/sessions across crawl
    """

    def __init__(self, target: str, timeout: int = 180, depth: int = 2, 
                 headless: bool = True, js_crawl: bool = True):
        """
        Args:
            target: URL to crawl (https://example.com)
            timeout: Max crawl time (seconds)
            depth: Crawl depth (1-3 recommended)
            headless: Use headless browser
            js_crawl: Enable JavaScript rendering
        """
        self.target = target
        self.timeout = timeout
        self.depth = depth
        self.headless = headless
        self.js_crawl = js_crawl
        self.results: List[CrawlResult] = []
        self.endpoints: Set[str] = set()
        self.parameters: Dict[str, Set[str]] = {}  # param_name -> {values}
        self.forms: List[Dict] = []

    def is_available(self) -> bool:
        """Check if katana is installed"""
        try:
            result = subprocess.run(
                ["katana", "-version"],
                capture_output=True,
                timeout=5
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def crawl(self) -> bool:
        """
        Execute Katana crawl
        
        Returns:
            bool: True if crawl succeeded
        """
        if not self.is_available():
            logger.error("katana not installed")
            return False

        # Build katana command (v1.4.0 compatible flags)
        cmd = [
            "katana",
            "-u", self.target,
            "-d", str(self.depth),
            "-timeout", str(self.timeout),
            "-jc",  # JS crawling ENABLED
            "-headless",  # Headless browser for JS execution
            "-xhr",  # Extract XHR/fetch requests from JS
            "-fx",  # Form extraction ENABLED
            "-ef", "png,jpg,gif,svg,ico,woff,eot,css",  # Exclude file types
            "-kf", "all",  # Known files mode: all (include common endpoints)
            "-field", "endpoint,method,status_code,body",  # Extract full response data
            "-jsonl",  # JSONL output for structured parsing
        ]

        try:
            logger.info(f"[Katana] Starting crawl: {self.target} (depth={self.depth})")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout + 30
            )

            if result.returncode != 0:
                logger.warning(f"[Katana] Crawl failed (code {result.returncode})")
                if result.stderr:
                    logger.warning(f"[Katana] stderr: {result.stderr[:200]}")
                return False

            # Parse output (lines from stdout)
            if not result.stdout.strip():
                logger.warning("[Katana] No output from crawl")
                return False

            self._parse_katana_output(result.stdout)
            
            if len(self.endpoints) == 0:
                logger.warning("[Katana] No endpoints parsed from output")
                return False
            
            logger.info(f"[Katana] Crawl complete: {len(self.endpoints)} endpoints found")
            return True

        except subprocess.TimeoutExpired:
            logger.warning("[Katana] Crawl timeout")
            return False
        except Exception as e:
            logger.error(f"[Katana] Crawl error: {e}")
            return False

    def _parse_katana_output(self, output: str):
        """Parse Katana JSONL output with DOM/JS context"""
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Skip info/debug lines
            if line.startswith('[') or 'katana' in line.lower():
                continue
            
            # Parse JSONL format
            if line.startswith('{'):
                try:
                    data = json.loads(line)
                    self._extract_from_katana_result(data)
                    continue
                except json.JSONDecodeError:
                    pass
            
            # Otherwise treat as plain URL
            if line.startswith('http://') or line.startswith('https://'):
                self.endpoints.add(line)
                
                # Extract parameters from URL
                parsed = urlparse(line)
                if parsed.query:
                    params = parse_qs(parsed.query)
                    for key, vals in params.items():
                        if key not in self.parameters:
                            self.parameters[key] = set()
                        self.parameters[key].update(vals)

    def _extract_from_katana_result(self, data: Dict):
        """Extract endpoints, params, forms from Katana result"""
        url = data.get("request", {}).get("url") or data.get("url")
        if not url:
            return

        # Add endpoint
        self.endpoints.add(url)

        # Extract status code
        status = data.get("response", {}).get("status_code", 200)

        # Extract parameters from URL
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for key, vals in params.items():
                if key not in self.parameters:
                    self.parameters[key] = set()
                self.parameters[key].update(vals)

        # Extract form fields if present
        response_body = data.get("response", {}).get("body", "")
        forms = self._extract_forms(response_body, url)
        self.forms.extend(forms)

        # Tag if looks like API
        is_api = ("/api/" in url.lower() or 
                 any(x in url.lower() for x in [".json", ".xml", "graphql"]))

        # Create result object
        result = CrawlResult(
            url=url,
            status_code=status,
            method=data.get("request", {}).get("method", "GET"),
            params=params if parsed.query else {},
            is_api=is_api,
            tags={
                "crawled",
                "api" if is_api else "web",
                f"status_{status}"
            }
        )

        self.results.append(result)

    def _extract_forms(self, html: str, page_url: str) -> List[Dict]:
        """Extract form definitions from HTML"""
        forms = []
        
        # Simple regex form extraction (for static forms)
        form_pattern = r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>.*?</form>'
        for match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            form_html = match.group(0)
            action = match.group(1)

            # Resolve relative URLs
            if action.startswith('/'):
                base = f"{urlparse(page_url).scheme}://{urlparse(page_url).netloc}"
                action = base + action
            elif not action.startswith('http'):
                action = page_url

            # Extract input fields
            fields = []
            input_pattern = r'<input[^>]*name=["\']?([^"\'>\s]+)["\']?[^>]*(?:type=["\']?([^"\'>\s]+)["\']?)?'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                field_name = input_match.group(1)
                field_type = input_match.group(2) or "text"
                fields.append({"name": field_name, "type": field_type})

            if fields:
                forms.append({
                    "action": action,
                    "method": "POST",
                    "fields": fields,
                    "found_on": page_url
                })

        return forms

    def get_unique_parameters(self) -> Dict[str, List[str]]:
        """Get deduplicated parameter map"""
        return {k: list(v) for k, v in self.parameters.items()}

    def get_endpoints(self) -> List[str]:
        """Get list of discovered endpoints"""
        return sorted(list(self.endpoints))

    def get_summary(self) -> Dict:
        """Get crawl summary for cache integration"""
        return {
            "target": self.target,
            "endpoints": len(self.endpoints),
            "unique_parameters": len(self.parameters),
            "forms": len(self.forms),
            "api_endpoints": len([r for r in self.results if r.is_api]),
            "crawled_urls": len(self.results),
            "parameters": self.get_unique_parameters(),
            "endpoints_list": self.get_endpoints()[:50],  # Top 50
            "forms_list": self.forms[:20]  # Top 20 forms
        }

    def to_json(self) -> str:
        """Serialize crawl results to JSON"""
        return json.dumps({
            "summary": self.get_summary(),
            "results": [r.to_dict() for r in self.results]
        }, indent=2)


if __name__ == "__main__":
    # Test: python3 katana_crawler.py https://dev-erp.sisschools.org
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python3 katana_crawler.py <url>")
        sys.exit(1)
    
    target = sys.argv[1]
    crawler = KatanaCrawler(target, depth=2, timeout=120)
    
    if not crawler.is_available():
        print("[ERROR] Katana not installed. Install: go install -v github.com/projectdiscovery/katana/cmd/katana@latest")
        sys.exit(1)
    
    if crawler.crawl():
        print(crawler.to_json())
    else:
        print("[ERROR] Crawl failed")
        sys.exit(1)
