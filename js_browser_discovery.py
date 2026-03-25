"""Strict Playwright JS discovery with hard fail behavior.

Discovery must be browser-backed and request-driven. There is no HTTP parsing
fallback because fake JS success states create low-quality attack surfaces.
"""

import importlib
import logging
import time
from typing import Dict, Optional, Set
from urllib.parse import parse_qs, urlparse, urljoin

logger = logging.getLogger(__name__)


class JSBrowserDiscovery:
    def __init__(self, timeout: int = 20, max_pages: int = 20):
        self.timeout = timeout
        self.max_pages = max_pages

    def discover(self, base_url: str, role_headers: Optional[Dict[str, Dict[str, str]]] = None) -> Dict:
        role_headers = role_headers or {}
        pw_result = self._discover_with_playwright(base_url, role_headers)
        if not pw_result or not pw_result.get("success", False):
            raise Exception("JS discovery failed - aborting scan")
        return pw_result

    def _discover_with_playwright(self, base_url: str, role_headers: Dict[str, Dict[str, str]]) -> Optional[Dict]:
        try:
            playwright_sync_api = importlib.import_module("playwright.sync_api")
            sync_playwright = getattr(playwright_sync_api, "sync_playwright")
        except Exception as e:
            raise Exception(
                "Playwright not available. Install with 'pip install playwright' and "
                "'python -m playwright install chromium'."
            ) from e

        endpoints: Set[str] = set()
        api_endpoints: Set[str] = set()
        js_assets: Set[str] = set()
        network_requests: Set[str] = set()
        params: Set[str] = set()

        requests_captured = 0
        api_calls_detected = 0

        try:
            with sync_playwright() as p:
                browser = None
                launch_error = None
                for _ in range(2):
                    try:
                        browser = p.chromium.launch(headless=True)
                        break
                    except Exception as e:
                        launch_error = e
                        time.sleep(0.8)

                if browser is None:
                    raise Exception(f"Chromium launch failed after retry: {launch_error}")

                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()

                page.add_init_script(
                    """
                    (() => {
                      const cap = [];
                      window.__vaptCaptured = cap;

                      const oldFetch = window.fetch;
                      window.fetch = function(...args) {
                        try {
                          const u = args && args[0] ? String(args[0]) : '';
                          cap.push({ kind: 'fetch', url: u });
                        } catch (e) {}
                        return oldFetch.apply(this, args);
                      };

                      const oldOpen = XMLHttpRequest.prototype.open;
                      const oldSend = XMLHttpRequest.prototype.send;
                      XMLHttpRequest.prototype.open = function(method, url, ...rest) {
                        try {
                          this.__vaptUrl = String(url || '');
                          cap.push({ kind: 'xhr_open', url: this.__vaptUrl });
                        } catch (e) {}
                        return oldOpen.call(this, method, url, ...rest);
                      };
                      XMLHttpRequest.prototype.send = function(...args) {
                        try {
                          cap.push({ kind: 'xhr_send', url: this.__vaptUrl || '' });
                        } catch (e) {}
                        return oldSend.apply(this, args);
                      };
                    })();
                    """
                )

                def on_response(resp):
                    nonlocal requests_captured, api_calls_detected
                    try:
                        url = resp.url
                        if not self._is_same_host(base_url, url):
                            return
                        requests_captured += 1
                        network_requests.add(url)
                        endpoints.add(self._path_only(url))
                        if self._is_api_like(url):
                            api_calls_detected += 1
                            api_endpoints.add(self._path_only(url))
                        for param_name in parse_qs(urlparse(url).query).keys():
                            params.add(param_name)
                    except Exception:
                        return

                def on_request(req):
                    nonlocal requests_captured, api_calls_detected
                    try:
                        url = req.url
                        if not self._is_same_host(base_url, url):
                            return
                        requests_captured += 1
                        network_requests.add(url)
                        endpoints.add(self._path_only(url))
                        if self._is_api_like(url):
                            api_calls_detected += 1
                            api_endpoints.add(self._path_only(url))
                        for param_name in parse_qs(urlparse(url).query).keys():
                            params.add(param_name)
                    except Exception:
                        return

                page.on("request", on_request)
                page.on("response", on_response)
                page.goto(base_url, wait_until="networkidle", timeout=self.timeout * 1000)

                try:
                    captured = page.evaluate("window.__vaptCaptured || []")
                    if isinstance(captured, list):
                        for item in captured:
                            if not isinstance(item, dict):
                                continue
                            raw = str(item.get("url") or "").strip()
                            if not raw:
                                continue
                            url = raw if raw.startswith("http") else f"{base_url.rstrip('/')}/{raw.lstrip('/')}"
                            if not self._is_same_host(base_url, url):
                                continue
                            network_requests.add(url)
                            endpoints.add(self._path_only(url))
                            if self._is_api_like(url):
                                api_endpoints.add(self._path_only(url))
                                api_calls_detected += 1
                            for param_name in parse_qs(urlparse(url).query).keys():
                                params.add(param_name)
                except Exception:
                    pass

                browser.close()
        except Exception as e:
            logger.error("Playwright discovery failed: %s", e)
            raise

        success = requests_captured > 0 and len(endpoints) > 0

        result = {
            "executed": True,
            "success": success,
            "playwright_used": True,
            "requests_captured": requests_captured,
            "api_calls_detected": api_calls_detected,
            "endpoints": sorted(endpoints),
            "api_endpoints": sorted(api_endpoints),
            "js_assets": sorted(js_assets),
            "network_requests": sorted(network_requests),
            "params": sorted(params),
            "stats": {
                "endpoints": len(endpoints),
                "api_endpoints": len(api_endpoints),
                "js_assets": len(js_assets),
                "network_requests": len(network_requests),
                "params": len(params),
            },
        }

        if not result["success"]:
            raise Exception("JS discovery failed - aborting scan")

        return result

    def _is_api_like(self, value: str) -> bool:
        low = value.lower()
        return "/api" in low or low.endswith(".json") or "graphql" in low

    def _is_same_host(self, base_url: str, other: str) -> bool:
        return urlparse(base_url).netloc == urlparse(urljoin(base_url, other)).netloc

    def _path_only(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.path or "/"
