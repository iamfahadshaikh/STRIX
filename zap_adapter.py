"""
OWASP ZAP adapter for discovery enrichment and validation support.

Design rule: ZAP is secondary intelligence only, never the primary scanner.
"""

import json
import logging
import subprocess
import time
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

    def run_intelligence_scan(self, target_url: str, include_active_scan: bool = True) -> ZAPDiscoveryResult:
        """Run API-driven ZAP intelligence workflow.

        ZAP is used as a secondary intelligence source and optional corroborator.
        """
        try:
            # 1. Spider
            spider = self._api_get("spider", "action", "scan", {"url": target_url, "maxChildren": 0, "recurse": True})
            spider_id = str(spider.get("scan") or "")
            if spider_id:
                self._wait_scan_status("spider", spider_id)

            # 2. AJAX Spider
            self._api_get("ajaxSpider", "action", "scan", {"url": target_url, "inScope": False})
            self._wait_ajax_spider()

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

    def _api_get(self, component: str, operation_type: str, operation: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        base = f"http://localhost:8090/JSON/{component}/{operation_type}/{operation}/"
        resp = requests.get(base, params=params or {}, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, dict) else {}

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

    def _wait_ajax_spider(self) -> None:
        start = time.time()
        while (time.time() - start) < self.timeout_seconds:
            status = self._api_get("ajaxSpider", "view", "status", {})
            raw = str(status.get("status") or "")
            if raw.lower() == "stopped":
                return
            time.sleep(1.5)
        raise TimeoutError("ZAP ajaxSpider timed out")

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
        cmd = [
            "docker",
            "run",
            "--rm",
            "-t",
            "-v",
            f"{str(output_dir.resolve())}:/zap/wrk:rw",
            "owasp/zap2docker-stable",
            "zap-baseline.py",
            "-t",
            target_url,
            "-J",
            "zap.json",
        ]

        try:
            logger.info("[ZAP] Running baseline docker scan")
            completed = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )

            if completed.returncode != 0:
                err = (completed.stderr or completed.stdout or "Unknown ZAP error").strip()
                return ZAPDiscoveryResult(
                    executed=True,
                    success=False,
                    error=f"ZAP baseline failed: {err}",
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
            return ZAPDiscoveryResult(executed=True, success=False, error=f"Docker not available: {e}")
        except subprocess.TimeoutExpired:
            return ZAPDiscoveryResult(executed=True, success=False, error="ZAP baseline timed out")
        except Exception as e:  # noqa: BLE001
            return ZAPDiscoveryResult(executed=True, success=False, error=f"ZAP execution error: {e}")

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
