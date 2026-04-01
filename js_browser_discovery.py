"""Playwright JS discovery used as an optional enrichment source.

Discovery remains browser-backed and request-driven, but low-signal outcomes
are reported without forcing hard scan failure.
"""

import importlib
import logging
import os
import time
from typing import Dict, List, Optional, Set
from urllib.parse import parse_qs, urlparse, urljoin

logger = logging.getLogger(__name__)


def validate_playwright_environment() -> bool:
    """Validate Python Playwright + Chromium availability.

    This performs a minimal launch/close cycle.
    """
    try:
        playwright_module = importlib.import_module("playwright")
        playwright_file = str(getattr(playwright_module, "__file__", ""))

        # Debian/apt package variant sometimes expects Node CLI at this path.
        # If missing, fail fast with explicit remediation before launching driver.
        if playwright_file.startswith("/usr/lib/python3/dist-packages/"):
            node_cli = "/usr/share/nodejs/playwright/cli.js"
            if not os.path.exists(node_cli):
                raise RuntimeError(
                    "Detected distro Playwright package with missing Node CLI "
                    f"({node_cli}). Use a Python venv and install Playwright via pip."
                )

        playwright_sync_api = importlib.import_module("playwright.sync_api")
        sync_playwright = getattr(playwright_sync_api, "sync_playwright")

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception as e:
        raise RuntimeError(
            "Playwright not properly installed. Use Python Playwright only: "
            "'pip install playwright' and 'python -m playwright install chromium'."
        ) from e


class JSBrowserDiscovery:
    def __init__(self, timeout: int = 20, max_pages: int = 20):
        self.timeout = timeout
        self.max_pages = max_pages

    def discover(self, base_url: str, role_headers: Optional[Dict[str, Dict[str, str]]] = None) -> Dict:
        logger.info("JS_DISCOVERY_START target=%s", base_url)
        role_headers = role_headers or {}
        pw_result = self._discover_with_playwright(base_url, role_headers)
        if not pw_result:
            raise Exception("JS discovery runtime failed")
        if pw_result.get("signal_strength") == "low":
            logger.info("JS_DISCOVERY_LOW_SIGNAL: browser ran but produced limited signals")
        logger.info(
            "JS_DISCOVERY_SUCCESS requests=%d responses=%d api_calls=%d",
            len(pw_result.get("requests", [])),
            len(pw_result.get("responses", [])),
            len(pw_result.get("api_calls", [])),
        )
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
        requests_list: List[Dict[str, str]] = []
        responses_list: List[Dict[str, str]] = []
        api_calls_list: List[Dict[str, str]] = []

        browser = None
        context = None
        page = None

        try:
            with sync_playwright() as p:
                launch_error = None
                for _ in range(3):
                    try:
                        browser = p.chromium.launch(headless=True)
                        break
                    except Exception as e:
                        launch_error = e
                        time.sleep(1.0)

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

                                            if (window.axios && window.axios.request) {
                                                const oldAxiosRequest = window.axios.request.bind(window.axios);
                                                window.axios.request = function(config) {
                                                    try {
                                                        const u = config && config.url ? String(config.url) : '';
                                                        cap.push({ kind: 'axios', url: u });
                                                    } catch (e) {}
                                                    return oldAxiosRequest(config);
                                                };
                                            }
                    })();
                    """
                )

                def on_response(resp):
                    nonlocal requests_captured, api_calls_detected
                    try:
                        url = resp.url
                        if not self._is_same_host(base_url, url):
                            return
                        if not self._is_js_api_signal_url(url):
                            return
                        requests_captured += 1
                        responses_list.append({"url": url, "status": str(resp.status)})
                        network_requests.add(url)
                        endpoints.add(self._path_only(url))
                        api_calls_detected += 1
                        api_calls_list.append({"url": url, "source": "response"})
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
                        if not self._is_js_api_signal_url(url):
                            return
                        requests_captured += 1
                        requests_list.append({"url": url, "method": req.method})
                        network_requests.add(url)
                        endpoints.add(self._path_only(url))
                        api_calls_detected += 1
                        api_calls_list.append({"url": url, "source": "request"})
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
                            kind = str(item.get("kind") or "").lower()
                            if kind not in {"fetch", "xhr_open", "xhr_send", "axios"}:
                                continue
                            url = raw if raw.startswith("http") else f"{base_url.rstrip('/')}/{raw.lstrip('/')}"
                            if not self._is_same_host(base_url, url):
                                continue
                            if not self._is_js_api_signal_url(url):
                                continue
                            network_requests.add(url)
                            endpoints.add(self._path_only(url))
                            api_endpoints.add(self._path_only(url))
                            api_calls_detected += 1
                            api_calls_list.append({"url": url, "source": f"runtime_hook:{kind}"})
                            for param_name in parse_qs(urlparse(url).query).keys():
                                params.add(param_name)
                except Exception:
                    pass
        except Exception as e:
            reason = str(e)
            if "Connection.init" in reason or "_playwright" in reason:
                reason = f"Playwright driver bootstrap failure: {reason}"
            logger.error("JS_DISCOVERY_FAILED: %s", reason)
            raise RuntimeError(reason) from e
        finally:
            try:
                if page is not None:
                    page.close()
            except Exception:
                pass
            try:
                if context is not None:
                    context.close()
            except Exception:
                pass
            try:
                if browser is not None:
                    browser.close()
            except Exception:
                pass

        signal_count = len(endpoints) + len(params) + api_calls_detected
        if signal_count >= 30:
            signal_strength = "high"
        elif signal_count >= 8:
            signal_strength = "medium"
        else:
            signal_strength = "low"

        result = {
            "executed": True,
            "success": True,
            "signal_strength": signal_strength,
            "playwright_used": True,
            "requests_captured": requests_captured,
            "api_calls_detected": api_calls_detected,
            "requests": requests_list,
            "responses": responses_list,
            "api_calls": api_calls_list,
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

        if signal_strength == "low":
            result["warning"] = "JS discovery executed but returned no useful network signals"

        return result

    def _is_api_like(self, value: str) -> bool:
        low = value.lower()
        return "/api" in low or low.endswith(".json") or "graphql" in low

    def _is_js_api_signal_url(self, value: str) -> bool:
        low = value.lower()
        if any(part in low for part in ["/node_modules/", "/src/"]):
            return False
        if low.endswith((".ts", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".woff", ".woff2", ".ttf", ".css")):
            return False
        if low.endswith(".js") and not self._is_api_like(low):
            return False
        return self._is_api_like(low) or "?" in low

    def _is_same_host(self, base_url: str, other: str) -> bool:
        return urlparse(base_url).netloc == urlparse(urljoin(base_url, other)).netloc

    def _path_only(self, url: str) -> str:
        parsed = urlparse(url)
        return parsed.path or "/"
