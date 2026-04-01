"""
OWASP ZAP adapter for discovery enrichment and validation support.

Design rule: ZAP is secondary intelligence only, never the primary scanner.
"""

import json
import logging
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qs, urlparse

import requests

logger = logging.getLogger(__name__)


@dataclass
class ZAPDiscoveryResult:
    executed: bool
    success: bool
    endpoints: List[str] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    headers: List[Dict[str, Any]] = field(default_factory=list)
    cookies: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None
    source: str = "zap"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executed": self.executed,
            "success": self.success,
            "endpoints": sorted(list(set(self.endpoints))),
            "params": sorted(list(set(self.params))),
            "alerts": self.alerts,
            "headers": self.headers,
            "cookies": self.cookies,
            "error": self.error,
            "source": self.source,
            "stats": {
                "endpoints": len(set(self.endpoints)),
                "params": len(set(self.params)),
                "alerts": len(self.alerts),
                "headers": len(self.headers),
                "cookies": len(self.cookies),
            },
        }


class ZAPAdapter:
    def __init__(self, timeout_seconds: int = 300):
        self.timeout_seconds = timeout_seconds
        self.api_base_url = "http://localhost:8090"
        self._managed_container_name: Optional[str] = None

    def run_intelligence_scan(self, target_url: str, include_active_scan: bool = True) -> ZAPDiscoveryResult:
        """Run API-driven ZAP intelligence workflow.

        ZAP is used as a secondary intelligence source and optional corroborator.
        """
        try:
            self._ensure_api_ready()

            # 1. Spider
            spider = self._api_get("spider", "action", "scan", {"url": target_url, "maxChildren": 500, "recurse": True})
            spider_id = str(spider.get("scan") or "")
            if spider_id:
                self._wait_scan_status("spider", spider_id)

            # 2. AJAX Spider
            try:
                self._api_get("ajaxSpider", "action", "setOptionMaxDuration", {"Integer": 2})
                self._api_get("ajaxSpider", "action", "setOptionMaxCrawlDepth", {"Integer": 6})
                self._api_get("ajaxSpider", "action", "setOptionNumberOfBrowsers", {"Integer": 2})
            except Exception:
                logger.debug("ZAP ajaxSpider option tuning unavailable; using defaults")
            self._api_get("ajaxSpider", "action", "scan", {"url": target_url, "inScope": False})
            if not self._wait_ajax_spider():
                logger.warning("ZAP ajaxSpider timed out; continuing with spider/passive data")

            # 3. Optional active scan
            if include_active_scan:
                ascan = self._api_get("ascan", "action", "scan", {"url": target_url, "recurse": True, "inScopeOnly": False})
                ascan_id = str(ascan.get("scan") or "")
                if ascan_id:
                    self._wait_scan_status("ascan", ascan_id)

            # 4. Wait passive scan queue
            self._wait_passive_scan_queue()

            # 5. Collect URLs and alerts
            urls_resp = self._api_get("core", "view", "urls", {"baseurl": target_url})
            urls = [str(u) for u in urls_resp.get("urls", []) if str(u).strip()]

            alerts_resp = self._api_get("core", "view", "alerts", {"baseurl": target_url, "start": 0, "count": 9999})
            alerts = alerts_resp.get("alerts", []) if isinstance(alerts_resp.get("alerts"), list) else []

            endpoints: List[str] = []
            params: List[str] = []
            for u in urls:
                endpoints.append(self._normalize_endpoint(u))
                for k in parse_qs(urlparse(u).query).keys():
                    params.append(k)

            headers: List[Dict[str, Any]] = []
            cookies: List[Dict[str, Any]] = []

            # Enrich from alert instances where available.
            for alert in alerts:
                if not isinstance(alert, dict):
                    continue
                alert_param = str(alert.get("param") or "").strip()
                if alert_param:
                    params.append(alert_param)
                instances = alert.get("instances", [])
                if isinstance(instances, list):
                    for inst in instances:
                        if not isinstance(inst, dict):
                            continue
                        uri = str(inst.get("uri") or "").strip()
                        if uri:
                            endpoints.append(self._normalize_endpoint(uri))
                            for k in parse_qs(urlparse(uri).query).keys():
                                params.append(k)

            return ZAPDiscoveryResult(
                executed=True,
                success=True,
                endpoints=sorted(set(endpoints)),
                params=sorted(set(params)),
                alerts=alerts,
                headers=headers,
                cookies=cookies,
                source="zap_api",
            )
        except Exception as e:  # noqa: BLE001
            return ZAPDiscoveryResult(
                executed=True,
                success=False,
                error=f"ZAP API intelligence scan failed: {e}",
                source="zap_api",
            )
        finally:
            try:
                self._stop_managed_api_container()
            except Exception as cleanup_error:  # noqa: BLE001
                logger.warning("ZAP managed container cleanup failed (non-fatal): %s", cleanup_error)

    def _api_get(self, component: str, operation_type: str, operation: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        base = f"{self.api_base_url}/JSON/{component}/{operation_type}/{operation}/"
        resp = requests.get(base, params=params or {}, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, dict) else {}

    def _is_api_reachable(self) -> bool:
        try:
            resp = requests.get(f"{self.api_base_url}/JSON/core/view/version/", timeout=3)
            return resp.status_code == 200
        except Exception:  # noqa: BLE001
            return False

    def _ensure_api_ready(self) -> None:
        """Ensure ZAP API is available; start a managed Docker daemon if not."""
        if self._is_api_reachable():
            return

        self._start_managed_api_container()
        max_wait = max(60, min(self.timeout_seconds, 180))
        start = time.time()
        while (time.time() - start) < max_wait:
            if self._is_api_reachable():
                return
            time.sleep(1.5)
        raise TimeoutError(f"ZAP API not reachable on localhost:8090 after startup attempt ({int(max_wait)}s)")

    def _start_managed_api_container(self) -> None:
        if self._managed_container_name:
            return

        container_name = f"vapt-zap-api-{uuid.uuid4().hex[:8]}"
        cmd = [
            "docker",
            "run",
            "--rm",
            "-d",
            "--name",
            container_name,
            "-p",
            "8090:8090",
            "zaproxy/zap-stable",
            "zap.sh",
            "-daemon",
            "-host",
            "0.0.0.0",
            "-port",
            "8090",
            "-config",
            "api.disablekey=true",
            "-config",
            "api.addrs.addr.name=.*",
            "-config",
            "api.addrs.addr.regex=true",
            "-config",
            "autoupdate.checkOnStart=false",
            "-config",
            "autoupdate.installAddonUpdates=false",
            "-config",
            "autoupdate.downloadNewRelease=false",
        ]

        try:
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=40,
                check=False,
            )
            if completed.returncode != 0:
                err = (completed.stderr or completed.stdout or "unknown docker error").strip()
                raise RuntimeError(f"Unable to start managed ZAP API container: {self._docker_error_hint(err)}")
            self._managed_container_name = container_name
        except FileNotFoundError as e:
            raise RuntimeError(f"Docker not available for managed ZAP API startup: {self._docker_error_hint(str(e))}") from e

    def _stop_managed_api_container(self) -> None:
        if not self._managed_container_name:
            return
        container_name = self._managed_container_name
        try:
            subprocess.run(
                ["docker", "rm", "-f", container_name],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.warning("Timed out while removing managed ZAP container %s; continuing", container_name)
        except FileNotFoundError:
            logger.warning("Docker executable not found during managed ZAP cleanup; continuing")
        except Exception as e:  # noqa: BLE001
            logger.warning("Managed ZAP cleanup error (non-fatal): %s", e)
        finally:
            self._managed_container_name = None

    def _wait_scan_status(self, component: str, scan_id: str) -> None:
        start = time.time()
        while (time.time() - start) < self.timeout_seconds:
            status = self._api_get(component, "view", "status", {"scanId": scan_id})
            raw = str(status.get("status") or "0")
            try:
                percent = int(raw)
            except ValueError:
                percent = 0
            if percent >= 100:
                return
            time.sleep(1.5)
        raise TimeoutError(f"ZAP {component} scan timed out")

    def _wait_ajax_spider(self) -> bool:
        start = time.time()
        ajax_timeout = min(180, max(120, self.timeout_seconds // 2))
        while (time.time() - start) < ajax_timeout:
            status = self._api_get("ajaxSpider", "view", "status", {})
            raw = str(status.get("status") or "")
            if raw.lower() == "stopped":
                return True
            time.sleep(1.5)
        return False

    def _wait_passive_scan_queue(self) -> None:
        start = time.time()
        while (time.time() - start) < self.timeout_seconds:
            rec = self._api_get("pscan", "view", "recordsToScan", {})
            left_raw = str(rec.get("recordsToScan") or "0")
            try:
                left = int(left_raw)
            except ValueError:
                left = 0
            if left <= 0:
                return
            time.sleep(1.0)
        raise TimeoutError("ZAP passive scan queue did not drain")

    def run_baseline_docker(self, target_url: str, output_dir: Path) -> ZAPDiscoveryResult:
        """Run ZAP baseline scan in Docker and parse JSON output."""
        zap_json_path = output_dir / "zap.json"
        image_candidates = ["zaproxy/zap-stable", "owasp/zap2docker-stable"]

        try:
            last_error = "Unknown ZAP error"
            for image in image_candidates:
                cmd = [
                    "docker",
                    "run",
                    "--rm",
                    "-t",
                    "-v",
                    f"{str(output_dir.resolve())}:/zap/wrk:rw",
                    image,
                    # "zap-baseline.py",
                    "zap-full-scan.py",
                    "-t",
                    target_url,
                    "-J",
                    "zap.json",
                ]

                logger.info("[ZAP] Running baseline docker scan with image %s", image)
                completed = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.timeout_seconds,
                    check=False,
                )
                if completed.returncode == 0:
                    break

                last_error = (completed.stderr or completed.stdout or "Unknown ZAP error").strip()
                if "pull access denied" in last_error.lower() or "repository does not exist" in last_error.lower():
                    continue
                return ZAPDiscoveryResult(
                    executed=True,
                    success=False,
                    error=f"ZAP baseline failed: {self._docker_error_hint(last_error)}",
                )
            else:
                return ZAPDiscoveryResult(
                    executed=True,
                    success=False,
                    error=f"ZAP baseline failed: {self._docker_error_hint(last_error)}",
                )

            if not zap_json_path.exists():
                return ZAPDiscoveryResult(
                    executed=True,
                    success=False,
                    error="ZAP baseline completed but zap.json not found",
                )

            parsed = self._parse_zap_json(zap_json_path)
            parsed.executed = True
            parsed.success = True
            return parsed

        except FileNotFoundError as e:
            return ZAPDiscoveryResult(executed=True, success=False, error=f"Docker not available: {self._docker_error_hint(str(e))}")
        except subprocess.TimeoutExpired:
            return ZAPDiscoveryResult(executed=True, success=False, error="ZAP baseline timed out")
        except Exception as e:  # noqa: BLE001
            return ZAPDiscoveryResult(executed=True, success=False, error=f"ZAP execution error: {e}")

    def _docker_error_hint(self, raw_error: str) -> str:
        text = str(raw_error or "").strip()
        lower = text.lower()
        if "docker-desktop wsl2 distribution" in lower or "enable the docker desktop wsl2 integration" in lower:
            return (
                f"{text}. Fix: enable Docker Desktop WSL integration for this distro, "
                "or run scanner from PowerShell/Command Prompt where Docker daemon is reachable."
            )
        if "cannot connect to the docker daemon" in lower or "docker daemon" in lower:
            return f"{text}. Fix: start Docker Desktop/daemon before running ZAP."
        return text

    def _parse_zap_json(self, zap_json_path: Path) -> ZAPDiscoveryResult:
        try:
            data = json.loads(zap_json_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception as e:  # noqa: BLE001
            return ZAPDiscoveryResult(executed=True, success=False, error=f"Invalid ZAP JSON: {e}")

        endpoints: List[str] = []
        params: List[str] = []
        alerts: List[Dict[str, Any]] = []

        # Baseline output can vary by image version. Parse defensively.
        sites = data.get("site") if isinstance(data, dict) else None
        if isinstance(sites, list):
            for site in sites:
                site_alerts = site.get("alerts", []) if isinstance(site, dict) else []
                for alert in site_alerts:
                    if isinstance(alert, dict):
                        alerts.append(alert)
                        instances = alert.get("instances", [])
                        for instance in instances if isinstance(instances, list) else []:
                            if not isinstance(instance, dict):
                                continue
                            uri = str(instance.get("uri") or "").strip()
                            if uri:
                                endpoints.append(self._normalize_endpoint(uri))
                                for k in parse_qs(urlparse(uri).query).keys():
                                    params.append(k)
                            p = str(instance.get("param") or "").strip()
                            if p:
                                params.append(p)

        # Fallback: alerts at root level.
        root_alerts = data.get("alerts") if isinstance(data, dict) else None
        if isinstance(root_alerts, list):
            for alert in root_alerts:
                if isinstance(alert, dict):
                    alerts.append(alert)

        return ZAPDiscoveryResult(
            executed=True,
            success=True,
            endpoints=sorted(set(endpoints)),
            params=sorted(set(params)),
            alerts=alerts,
        )

    def _normalize_endpoint(self, url: str) -> str:
        parsed = urlparse(url)
        path = parsed.path or "/"
        return path if path.startswith("/") else f"/{path}"
