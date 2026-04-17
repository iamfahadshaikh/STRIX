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
from urllib.parse import parse_qs, urljoin, urlparse

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


DEBUG_PAGE_MARKERS = [
    "you're seeing this error because you have debug = true",
    "django version",
    "using the urlconf defined in",
    "the current path",
    "url patterns",
]


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
        self.leaked_routes: Set[str] = set()
        self.debug_page_exposed = False
        self.debug_indicators: Set[str] = set()
        self.session = self._create_session()

    def _create_session(self) -> requests.Session:
        """Create session with retries"""
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        session = requests.Session()
        retry = Retry(
            connect=1, backoff_factor=0.1, status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
            }
        )
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
            self._extract_api_candidates_from_text(resp.text, self.target)
            self._detect_debug_page(resp.text, self.target)
            self._probe_api_entrypoints(self.target)

            logger.info(
                f"[LightCrawl] Crawl complete: {len(self.endpoints)} endpoints found"
            )
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
        href_pattern = r"""(href|src)=["']([^"']+)["']"""
        for match in re.finditer(href_pattern, html, re.IGNORECASE):
            url = match.group(2)
            full_url = urljoin(page_url, url)

            # Filter to same domain
            if self._is_same_domain(full_url, page_url):
                self.endpoints.add(full_url)

                # Check if API endpoint
                if self._is_api_like_path(full_url):
                    self.api_endpoints.add(full_url)
                elif full_url.endswith(".js"):
                    self.js_endpoints.add(full_url)

        # Extract forms
        form_pattern = r"<form[^>]*>.*?</form>"
        for form_match in re.finditer(form_pattern, html, re.IGNORECASE | re.DOTALL):
            form_html = form_match.group(0)
            action_match = re.search(
                r'action=["\'](.*?)["\']', form_html, re.IGNORECASE
            )

            action = action_match.group(1) if action_match else page_url
            action = urljoin(page_url, action)

            # Extract input fields
            fields = []
            input_pattern = r'<input[^>]*name=["\'](.*?)["\']'
            for input_match in re.finditer(input_pattern, form_html, re.IGNORECASE):
                fields.append(input_match.group(1))

            if fields:
                self.forms.append(
                    {
                        "action": action,
                        "method": "POST",
                        "fields": fields,
                        "found_on": page_url,
                    }
                )

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

    def _extract_api_candidates_from_text(self, html: str, page_url: str):
        """Extract API-looking routes from raw page text (including debug pages)."""
        text = html or ""

        # Paths such as /api/users, api/v1/login, '/api/token/' often leak in debug pages.
        path_pattern = r"(?:['\"(\s]|^)((?:/)?api(?:/[A-Za-z0-9._~!$&()*+,;=:@%-]*)?/?)(?=$|['\"\s<>)\]])"
        for match in re.finditer(path_pattern, text, re.IGNORECASE):
            candidate = (match.group(1) or "").strip()
            if not candidate:
                continue
            if not candidate.startswith("/"):
                candidate = "/" + candidate
            self._register_endpoint_candidate(candidate, page_url, is_api_hint=True)

    def _probe_api_entrypoints(self, page_url: str):
        """Probe common API roots when initial crawl finds mostly static assets."""
        probe_paths = [
            "/api",
            "/api/",
            "/api/v1",
            "/api/v1/",
            "/api/customer-account/",
            "/api/base/",
            "/api/project/",
            "/api/upload_data/",
            "/swagger",
            "/swagger/",
            "/swagger.json",
            "/openapi.json",
            "/v3/api-docs",
        ]
        valid_statuses = {200, 201, 202, 204, 301, 302, 307, 308, 401, 403, 405, 500}

        for path in probe_paths:
            url = urljoin(page_url, path)
            if not self._is_same_domain(url, page_url):
                continue
            try:
                resp = self.session.get(url, timeout=min(self.timeout, 8), verify=False)
            except requests.exceptions.RequestException:
                continue

            if resp.status_code in valid_statuses:
                self.endpoints.add(url)
                if self._is_api_like_path(url):
                    self.api_endpoints.add(url)

                if resp.text:
                    self._extract_api_candidates_from_text(resp.text, page_url)
                    self._detect_debug_page(resp.text, url)
                    self._extract_openapi_paths(resp.text, page_url)

    def _extract_openapi_paths(self, content: str, page_url: str):
        """Extract endpoint paths from OpenAPI/Swagger JSON content."""
        text = (content or "").strip()
        if not text:
            return

        if '"paths"' not in text and "'paths'" not in text:
            return

        try:
            data = json.loads(text)
        except Exception:
            return

        paths = data.get("paths") if isinstance(data, dict) else None
        if not isinstance(paths, dict):
            return

        for raw_path, methods in paths.items():
            if not isinstance(raw_path, str):
                continue
            cleaned_path = raw_path.strip()
            if not cleaned_path:
                continue

            # Normalize path params and track parameter hints.
            normalized = re.sub(r"\{[^}]+\}", "{param}", cleaned_path)
            for _ in re.finditer(r"\{param\}", normalized):
                if "id" not in self.parameters:
                    self.parameters["id"] = set()
                self.parameters["id"].add("")

            self._register_endpoint_candidate(normalized, page_url, is_api_hint=True)

            # Add query/body parameter names from method definitions when present.
            if isinstance(methods, dict):
                for _, method_spec in methods.items():
                    if not isinstance(method_spec, dict):
                        continue
                    for p in method_spec.get("parameters", []) or []:
                        if isinstance(p, dict):
                            name = p.get("name")
                            if isinstance(name, str) and name.strip():
                                if name not in self.parameters:
                                    self.parameters[name] = set()
                                self.parameters[name].add("")

    def _register_endpoint_candidate(
        self, candidate_path: str, page_url: str, is_api_hint: bool = False
    ):
        """Normalize, scope, and register a candidate endpoint path."""
        full_url = urljoin(page_url, candidate_path)
        if not self._is_same_domain(full_url, page_url):
            return

        self.endpoints.add(full_url)
        if is_api_hint or self._is_api_like_path(full_url):
            self.api_endpoints.add(full_url)
            self.leaked_routes.add(full_url)

    def _is_api_like_path(self, url_or_path: str) -> bool:
        """Return True for /api, /api/*, and versioned API styles."""
        try:
            parsed = urlparse(url_or_path)
            path = (parsed.path or url_or_path or "").lower()
        except Exception:
            path = (url_or_path or "").lower()

        return bool(re.search(r"(^|/)api(?:/|$)", path))

    def _detect_debug_page(self, html: str, page_url: str):
        """Detect exposed framework debug pages and collect evidence."""
        if not html:
            return

        lower = html.lower()
        hits = [m for m in DEBUG_PAGE_MARKERS if m in lower]
        if hits:
            self.debug_page_exposed = True
            self.debug_indicators.update(hits)
            self._extract_api_candidates_from_text(html, page_url)
            self._extract_django_url_patterns(html, page_url)

    def _extract_django_url_patterns(self, html: str, page_url: str):
        """Extract endpoint paths from Django DEBUG 404 URL pattern listing."""
        lines = [ln.strip() for ln in (html or "").splitlines()]
        if not lines:
            return

        in_patterns = False
        base_prefix = ""

        for line in lines:
            if not in_patterns:
                if "django tried these url patterns" in line.lower():
                    in_patterns = True
                continue

            # End section when Django switches to mismatch/debug explanation.
            if (
                "didn't match any of these" in line.lower()
                or "debug = true" in line.lower()
            ):
                break

            # Remove numbering (e.g., "12.") and normalize whitespace.
            line = re.sub(r"^\d+\.\s*", "", line)
            line = re.sub(r"\s+", " ", line).strip()
            if not line:
                continue

            # Remove trailing [name='...'] metadata.
            line = re.sub(r"\s*\[name=.*?\]\s*$", "", line)
            if not line:
                continue

            # Ignore obvious non-route lines.
            if line.lower().startswith("the current path"):
                continue

            # Handle split routes like "api/customer-account/ request-otp/".
            parts = line.split(" ")
            candidate = ""
            if len(parts) >= 2 and parts[0].startswith("api/"):
                candidate = parts[0].rstrip("/") + "/" + parts[1].lstrip("/")
            else:
                candidate = parts[0]

            candidate = candidate.strip()
            if not candidate:
                continue

            # Track base prefix from entries like "api/customer-account/".
            if (
                candidate.startswith("api/")
                and candidate.endswith("/")
                and "<" not in candidate
                and len(parts) == 1
            ):
                base_prefix = candidate

            # If this line is a leaf route and we have a prefix, compose full path.
            if (
                base_prefix
                and not candidate.startswith("api/")
                and not candidate.startswith("admin/")
            ):
                candidate = base_prefix.rstrip("/") + "/" + candidate.lstrip("/")

            # Convert Django typed converters into a stable placeholder path segment.
            candidate = re.sub(r"<[^>]+>", "{param}", candidate)

            # Register params from placeholders.
            for _ in re.finditer(r"\{param\}", candidate):
                if "id" not in self.parameters:
                    self.parameters["id"] = set()
                self.parameters["id"].add("")

            self._register_endpoint_candidate(
                candidate, page_url, is_api_hint=candidate.startswith("api/")
            )

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
            "debug_page_exposed": self.debug_page_exposed,
            "debug_indicators": sorted(list(self.debug_indicators))[:10],
            "parameters": {k: list(v) for k, v in self.parameters.items()},
            "endpoints_list": sorted(list(self.endpoints))[:50],
            "forms_list": self.forms[:20],
            "api_endpoints_list": sorted(list(self.api_endpoints))[:20],
            "leaked_routes": sorted(list(self.leaked_routes))[:50],
        }

    def to_json(self) -> str:
        """Serialize to JSON"""
        return json.dumps({"summary": self.get_summary(), "results": []}, indent=2)


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
