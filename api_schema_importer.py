"""API schema importer for OpenAPI/Swagger/GraphQL endpoint discovery."""

import json
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


@dataclass
class APISchemaResult:
    endpoints: List[Dict]
    source: str
    success: bool
    error: Optional[str] = None


class APISchemaImporter:
    CANDIDATES = ["/swagger.json", "/openapi.json", "/graphql"]

    def __init__(self, timeout: int = 12):
        self.timeout = timeout

    def discover(self, base_url: str) -> APISchemaResult:
        for candidate in self.CANDIDATES:
            try:
                url = f"{base_url.rstrip('/')}{candidate}"
                resp = requests.get(url, timeout=self.timeout, verify=False)
                if resp.status_code >= 400:
                    continue

                if candidate == "/graphql":
                    if "graphql" in resp.text.lower():
                        return APISchemaResult(
                            endpoints=[
                                {
                                    "endpoint": "/graphql",
                                    "method": "POST",
                                    "params": ["query", "variables"],
                                }
                            ],
                            source="graphql_probe",
                            success=True,
                        )
                    continue

                doc = resp.json()
                endpoints = self._parse_openapi(doc)
                if endpoints:
                    return APISchemaResult(
                        endpoints=endpoints, source=candidate, success=True
                    )
            except Exception:
                continue

        return APISchemaResult(
            endpoints=[], source="none", success=False, error="No API schema detected"
        )

    def _parse_openapi(self, doc: Dict) -> List[Dict]:
        paths = doc.get("paths", {}) if isinstance(doc, dict) else {}
        out: List[Dict] = []
        if not isinstance(paths, dict):
            return out

        for endpoint, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, meta in methods.items():
                if method.upper() not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
                    continue
                params: List[str] = []
                if isinstance(meta, dict):
                    for p in (
                        meta.get("parameters", [])
                        if isinstance(meta.get("parameters"), list)
                        else []
                    ):
                        if isinstance(p, dict) and p.get("name"):
                            params.append(str(p["name"]))
                out.append(
                    {
                        "endpoint": endpoint,
                        "method": method.upper(),
                        "params": sorted(set(params)),
                    }
                )
        return out
