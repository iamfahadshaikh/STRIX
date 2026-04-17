#!/usr/bin/env python3

import argparse
import asyncio
import json
import logging
import re
import shutil
import socket
import ssl
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urljoin, urlparse
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if SRC_DIR.exists() and str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from adaptive_fuzzing_engine import AdaptiveFuzzingEngine
from api_schema_importer import APISchemaImporter
from auth_utils.param_extractor import ParameterExtractor
from auth_utils.response_analyzer import ResponseAnalyzer
from cache_discovery import DiscoveryCache
from core.request_engine import RequestEngine
from core.session_manager import AuthType
from crawl_adapter import CrawlAdapter
from crawler_mandatory_gate import CrawlerMandatoryGate
from decision_ledger import Decision, DecisionEngine, DecisionLedger
from deduplication_engine import DeduplicationEngine
from discovery_classification import get_tool_contract, is_signal_producer
from discovery_completeness import DiscoveryCompletenessEvaluator
from discovery_metrics import assess_discovery_status, collect_discovery_metrics
from discovery_quality_scorer import score_discovery
from discovery_signal_parser import DiscoverySignalParser, parse_and_extract_signals
from endpoint_graph import EndpointGraph
from enhanced_confidence import EnhancedConfidenceEngine
from execution_paths import get_executor
from external_intel_connector import ExternalIntelAggregator
from finding_pipeline import get_pipeline
from findings_model import (
    Finding,
    FindingsRegistry,
    FindingType,
    Severity,
    map_to_owasp,
)
from gating_loop import GatingLoopOrchestrator
from global_confidence_system import GlobalConfidenceSystem
from html_report_generator import HTMLReportGenerator
from intelligence_layer import IntelligenceEngine
from js_browser_discovery import JSBrowserDiscovery, validate_playwright_environment
from modules.access_control_engine import AccessControlEngine
from modules.auth_engine import AuthEngine, LoginConfig
from modules.idor_engine import IDOREngine
from oob_callback_system import OOBCallbackSystem
from owasp_mapping import OWASPCategory, map_to_owasp
from param_intelligence import (
    classify_parameters,
    filter_controllable,
    filter_high_confidence,
)
from passive_analysis_engine import analyze_headers
from payload_command_builder import PayloadCommandBuilder
from payload_execution_validator import PayloadExecutionValidator, PayloadOutcomeTracker
from payload_strategy import PayloadReadinessGate, PayloadStrategy, PayloadType
from proof_based_reporter import ConfirmationMethod, ProofBasedReporter
from report_coverage_analyzer import BlockReason, ReportCoverageAnalyzer
from request_context import RequestContextManager
from response_diffing_engine import ResponseDiffingEngine
from risk_aggregation import RiskAggregator
from risk_engine import RiskEngine
from service_fingerprinting_engine import ServiceFingerprintingEngine
from sqli_exploitation_engine import SQLinjectionEngine
from ssl_certificate_checker import SSLCertificateChecker
from ssrf_exploitation_engine import SSRFExploitationEngine
from strict_execution_handler import DiscoveryState, check_exploitation_readiness
from strict_gating_loop import StrictGatingLoop
from subdomain_prioritization import SubdomainPrioritizationEngine
from target_profile import TargetProfile, TargetType
from tool_manager import ToolManager
from tool_parsers import WhatwebParser, parse_tool_output
from validation_engine import validate_finding_proof
from vulnerability_centric_reporter import VulnerabilityCentricReporter
from xss_exploitation_engine import XSSExploitationEngine
from zap_adapter import ZAPAdapter

logger = logging.getLogger(__name__)


class ToolOutcome(Enum):
    SUCCESS_WITH_FINDINGS = "SUCCESS_WITH_FINDINGS"
    SUCCESS_NO_FINDINGS = "SUCCESS_NO_FINDINGS"
    EXECUTED_NO_SIGNAL = "EXECUTED_NO_SIGNAL"
    EXECUTED_CONFIRMED = "EXECUTED_CONFIRMED"
    TIMEOUT = "TIMEOUT"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    SKIPPED = "SKIPPED"
    BLOCKED = "BLOCKED"
    BLOCKED_NO_CRAWL = "BLOCKED_NO_CRAWL"
    BLOCKED_NO_PARAM = "BLOCKED_NO_PARAM"
    BLOCKED_PARSE_FAILED = "BLOCKED_PARSE_FAILED"


class DecisionOutcome(Enum):
    ALLOW = "ALLOW"
    SKIP = "SKIP"
    BLOCK = "BLOCK"


class AutomationScannerV2:
    MAX_TOOL_TIMEOUT = 300  # Global hard cap: 5 minutes per tool

    def __init__(
        self,
        target: str,
        output_dir: str | None = None,
        skip_tool_check: bool = False,
        custom_budget: int | None = None,
        manual_out_of_scope_mode: str = "ask",
        strict_js_required: bool = False,
        full_report: bool = False,
        quiet_mode: bool = False,
    ) -> None:
        self.target = target
        self.strict_js_required = strict_js_required
        self.full_report = full_report
        self.quiet_mode = quiet_mode
        self._configure_logging(quiet_mode)
        self.start_time = datetime.now()
        self.correlation_id = self.start_time.strftime("%Y%m%d_%H%M%S")

        self.profile = TargetProfile.from_target(target, custom_budget=custom_budget)
        self.manual_out_of_scope_mode = manual_out_of_scope_mode
        self.manual_out_of_scope_report: dict = {
            "mode": manual_out_of_scope_mode,
            "prompt_response": "skip",
            "attempted": False,
            "candidate_tools": [],
            "targets": [],
            "executed": [],
            "failed": [],
            "non_actionable_failures": [],
            "classified_failures": {
                "ENV_ERROR": 0,
                "TARGET_BLOCKED": 0,
                "NOT_APPLICABLE": 0,
                "EXECUTION_ERROR": 0,
            },
            "missing_or_unavailable": [],
            "summary_by_tool": {},
            "unique_counts": {
                "executed": 0,
                "failed": 0,
                "non_actionable_failures": 0,
                "missing_or_unavailable": 0,
            },
        }
        self.executed_tool_names: set[str] = set()
        self._tool_execution_meta: dict[str, dict] = {}

        # Resolve IPs early for report accuracy (equivalent to nslookup/ping visibility).
        self._resolve_target_ips()

        # Explicit HTTPS probe to set capability before planning/ledger
        self.profile = self._with_https_probe(self.profile)
        self._https_capability = self.profile.is_https  # cache immutable HTTPS verdict

        self.ledger = DecisionEngine.build_ledger(self.profile)
        self.executor = get_executor(self.profile, self.ledger)
        self.cache = DiscoveryCache()  # NEW: discovery cache for gating
        self._lock = threading.Lock()  # Thread-safety for concurrent non-blocking tools

        # NEW: Runtime watchdog
        self.runtime_deadline = (
            self.start_time.timestamp() + self.profile.runtime_budget
        )

        # Auto-install/gate tools unless explicitly skipped
        self.tool_manager = None if skip_tool_check else ToolManager()

        self.output_dir = Path(
            output_dir or f"scan_results_{self.profile.host}_{self.correlation_id}"
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.execution_results: list[dict] = []

        # NEW: Findings registry for normalized, deduplicated findings
        self.findings = FindingsRegistry()

        # NEW: Intelligence engine for confidence scoring and correlation
        self.intelligence = IntelligenceEngine()

        # Phase 1-4 hardening engines
        self.discovery_evaluator = None  # Initialized after discovery phase
        self.payload_strategy = PayloadStrategy()
        self.payload_command_builder = None  # Initialized after crawler success
        self.enhanced_confidence = None  # Initialized after crawler
        self.dedup_engine = DeduplicationEngine()
        self.external_intel = ExternalIntelAggregator()  # Phase 1: External intel
        self.payload_tracker = PayloadOutcomeTracker()  # Phase 3: Outcome tracking
        self.coverage_analyzer = ReportCoverageAnalyzer()  # Phase 4: Coverage gaps

        # Phase 5: Exploitation and Active Validation Engines
        self.response_diffing = ResponseDiffingEngine()  # Response comparison
        self.oob_system = OOBCallbackSystem()  # Out-of-band callback detection
        self.ssrf_engine = None  # Initialized after OOB setup
        self.xss_engine = None  # Initialized in exploitation phase
        self.sqli_engine = None  # Initialized in exploitation phase
        self.fuzzing_engine = AdaptiveFuzzingEngine()  # Payload mutation/retry
        self.fingerprint_engine = (
            ServiceFingerprintingEngine()
        )  # Service identification
        self.service_fingerprints: List[Dict] = []
        self.certificate_checker = (
            SSLCertificateChecker()
        )  # TLS chain/expiry validation
        self.certificate_assessments: List[Dict] = []
        self.host_network_assessment: List[Dict] = []
        self.subdomain_prioritizer = (
            SubdomainPrioritizationEngine()
        )  # Attack surface ranking
        self.prioritized_subdomains: List[Dict] = []
        self.proof_reporter = ProofBasedReporter()  # Confirmed findings only
        scheme = "https" if self.profile.is_https else "http"
        self.request_context = RequestContextManager(f"{scheme}://{self.profile.host}")
        self.finding_pipeline = get_pipeline()
        self.zap_adapter = ZAPAdapter(timeout_seconds=300)
        self.api_schema_importer = APISchemaImporter(timeout=12)
        self.js_discovery_summary: Dict[str, Any] = {
            "executed": False,
            "playwright_used": False,
            "endpoints": 0,
            "api_endpoints": 0,
            "js_assets": 0,
            "network_requests": 0,
            "params": 0,
        }
        self.zap_discovery_summary: Dict[str, Any] = {
            "executed": False,
            "success": False,
            "endpoints": 0,
            "params": 0,
            "alerts": 0,
        }
        self.api_schema_summary: Dict[str, Any] = {
            "executed": False,
            "success": False,
            "source": "none",
            "endpoints": 0,
            "params": 0,
        }
        self.multi_source_summary: Dict[str, Any] = {
            "executed": False,
            "sources": {},
            "urls": 0,
            "endpoints": 0,
            "params": 0,
        }
        self.endpoint_inventory: Dict[str, Dict[str, Any]] = {}
        self.param_inventory: Dict[str, Dict[str, Any]] = {}
        self.param_sources_by_endpoint: Dict[str, List[Dict[str, str]]] = {}
        self.js_asset_inventory: Dict[str, List[str]] = {}
        self.discovery_quality: Dict[str, Any] = {
            "score": 0,
            "status": "UNKNOWN",
            "should_abort_exploitation": False,
        }
        self.auth_access_control_summary: Dict[str, Any] = {
            "executed": False,
            "enabled_roles": [],
            "authenticated_roles": [],
            "endpoints_tested": 0,
            "idor_findings": 0,
            "access_control_findings": 0,
            "errors": [],
        }
        self.scan_status: str = "completed"
        self.abort_reason: str | None = None

        # Error semantics counters for planning influence
        self.error_counters = {
            "network_failures": 0,
            "timeouts": 0,
        }

        # DNS budget (global cap across all DNS tools)
        self.dns_time_budget = 30
        self.dns_time_spent = 0.0

        # Seed discoveries from the input itself (URL params, base path)
        self._prefill_param_hints()

        self.log(f"Target Profile: {self.profile.host}")
        self.log(f"Target Type: {self.profile.type}")
        self.log(
            f"Runtime Budget: {self.profile.runtime_budget}s "
            f"({self.profile.runtime_budget/60:.1f}m)"
        )

        if self.tool_manager:
            self._ensure_required_tools()

        # Cheap probes to improve signal-based gating
        self._run_cheap_probes()

    def _configure_logging(self, quiet_mode: bool) -> None:
        """Configure logging level based on quiet mode."""
        if quiet_mode:
            # Suppress INFO and DEBUG messages, only show WARN and ERROR
            logging.getLogger().setLevel(logging.WARNING)
            for handler in logging.getLogger().handlers:
                handler.setLevel(logging.WARNING)
            # Also suppress noisy third-party loggers
            logging.getLogger("urllib3").setLevel(logging.ERROR)
            logging.getLogger("requests").setLevel(logging.ERROR)
            logging.getLogger("paramiko").setLevel(logging.ERROR)
        else:
            # Default INFO level
            logging.getLogger().setLevel(logging.INFO)
            for handler in logging.getLogger().handlers:
                handler.setLevel(logging.INFO)

    def log(self, msg: str, level: str = "INFO") -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{level}] {msg}")

    def _resolve_target_ips(self) -> None:
        """Resolve and store target IPs for reporting (nslookup/ping equivalent context)."""
        if self.profile.is_ip:
            object.__setattr__(self.profile, "resolved_ips", [self.profile.host])
            object.__setattr__(self.profile, "is_resolvable", True)
            return

        try:
            addresses = sorted(
                {item[4][0] for item in socket.getaddrinfo(self.profile.host, None)}
            )
            if addresses:
                object.__setattr__(self.profile, "resolved_ips", addresses)
                object.__setattr__(self.profile, "is_resolvable", True)
        except Exception:
            object.__setattr__(self.profile, "resolved_ips", [])
            object.__setattr__(self.profile, "is_resolvable", False)

    def _extract_tech_stack_summary(self) -> dict:
        """Build a readable tech stack summary from parsed detections."""
        tech = {
            "server": [],
            "cms": [],
            "languages": [],
            "frameworks": [],
            "javascript": [],
        }

        if getattr(self.profile, "detected_cms", None):
            tech["cms"].append(str(self.profile.detected_cms))

        technical_names = set()
        for row in self.param_inventory.values():
            tags = row.get("tags", []) or []
            if "technical_metadata" in tags:
                technical_names.add(str(row.get("name", "")))

        for param in sorted(technical_names):
            p = str(param)
            if p.startswith("tech_server_"):
                tech["server"].append(p.replace("tech_server_", ""))
            elif p.startswith("tech_cms_"):
                tech["cms"].append(p.replace("tech_cms_", ""))
            elif p.startswith("tech_lang_"):
                tech["languages"].append(p.replace("tech_lang_", ""))
            elif p.startswith("framework_"):
                tech["frameworks"].append(p.replace("framework_", ""))
            elif p.startswith("js_"):
                tech["javascript"].append(p.replace("js_", ""))

        for key in tech:
            tech[key] = sorted(set(tech[key]))
        return tech

    def _build_discovery_detail_lists(self) -> dict:
        """Build detailed discovery lists for report sections."""
        endpoints = self.cache.get_normalized_endpoints()
        api_endpoints = []
        for ep in endpoints:
            low = ep.lower()
            if any(
                marker in low
                for marker in [
                    "/api",
                    "/v1",
                    "/v2",
                    "/graphql",
                    "/wp-json",
                    "swagger.json",
                    "openapi.json",
                    "/v3/api-docs",
                ]
            ):
                api_endpoints.append(ep)
        params = sorted(
            str(p) for p in self.cache.params if self._is_testable_param_name(str(p))
        )
        technical_params = sorted(
            str(p.get("name", ""))
            for p in self.param_inventory.values()
            if "technical_metadata" in (p.get("tags") or [])
        )
        reflections = sorted(str(r) for r in self.cache.reflections)
        subdomains = sorted(str(s) for s in self.cache.subdomains)
        ports = [str(p) for p in sorted(self.cache.discovered_ports)]
        command_params = sorted(str(p) for p in self.cache.command_params)
        ssrf_params = sorted(str(p) for p in self.cache.ssrf_params)

        return {
            "endpoints_list": endpoints,
            "api_endpoints_list": sorted(set(api_endpoints)),
            "parameters_list": params,
            "technical_parameters_list": technical_params,
            "reflections_list": reflections,
            "subdomains_list": subdomains,
            "ports_list": ports,
            "command_params_list": command_params,
            "ssrf_params_list": ssrf_params,
        }

    def _normalize_endpoint_path(self, value: str) -> str:
        candidate = str(value or "").strip()
        if not candidate:
            return ""
        parsed = urlparse(
            candidate
            if candidate.startswith("http")
            else f"https://placeholder{candidate if candidate.startswith('/') else '/' + candidate}"
        )
        path = parsed.path or "/"
        if len(path) > 1 and path.endswith("/"):
            path = path.rstrip("/")
        return path

    def _classify_endpoint(self, path: str) -> str:
        low = str(path or "").lower()
        if not low:
            return "UNKNOWN"
        if self._is_api_doc_path(low):
            return "API"
        if any(s in low for s in ["/api", "/v1", "/v2", "/graphql", "/auth"]):
            return "API"
        if any(s in low for s in ["/node_modules/", "/src/"]) or low.endswith(
            (".ts", ".tsx", ".map")
        ):
            return "CODE"
        if low.endswith(
            (
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".svg",
                ".css",
                ".woff",
                ".woff2",
                ".ttf",
                ".ico",
                ".pdf",
            )
        ):
            return "STATIC"
        if (
            low.endswith((".html", ".htm", ".php", ".asp", ".aspx", ".jsp"))
            or low == "/"
        ):
            return "PAGE"
        if low.endswith(".js"):
            return "STATIC"
        return "UNKNOWN"

    def _is_api_doc_path(self, path: str) -> bool:
        low = str(path or "").lower()
        return any(
            marker in low
            for marker in ["/swagger", "swagger.json", "openapi.json", "/v3/api-docs"]
        )

    def _is_tech_metadata_param(self, param_name: str) -> bool:
        low = str(param_name or "").strip().lower()
        return low.startswith(
            ("tech_", "framework_", "js_", "service_", "fingerprint_")
        )

    def _is_testable_param_name(self, param_name: str) -> bool:
        name = str(param_name or "").strip()
        if not name:
            return False
        if self._is_tech_metadata_param(name):
            return False
        return not self._should_skip_parameter(name)

    def _endpoint_confidence_tier(self, path: str, item: Dict[str, Any]) -> str:
        cls = str(item.get("classification") or self._classify_endpoint(path))
        sources = set(item.get("sources", []) or [])
        is_live = path in self.cache.live_endpoints
        if cls in {"STATIC", "CODE"}:
            return "static_asset"
        if (
            cls == "API"
            and is_live
            and (len(sources) >= 2 or "api_schema" in sources or "zap" in sources)
        ):
            return "verified_live_api"
        if cls == "API" and (
            is_live
            or bool(sources & {"api_schema", "zap", "js_discovery", "multi_source"})
        ):
            return "probable_api"
        if cls == "PAGE" and is_live:
            return "verified_page"
        return "unverified_path"

    def _should_feed_exploitation(self, path: str, item: Dict[str, Any]) -> bool:
        tier = self._endpoint_confidence_tier(path, item)
        return tier in {"verified_live_api", "probable_api", "verified_page"}

    def _is_noise_endpoint(self, path: str) -> bool:
        low = str(path or "").lower()
        if any(s in low for s in ["/node_modules/", "/src/"]):
            return True
        if low.endswith(
            (
                ".map",
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".svg",
                ".css",
                ".woff",
                ".woff2",
                ".ttf",
                ".ico",
                ".pdf",
            )
        ):
            return True
        if low.endswith((".ts", ".tsx")):
            return True
        return False

    def _register_param(self, param_name: str, source: str, endpoint: str = "") -> None:
        name = str(param_name or "").strip()
        if not name:
            return
        if not self._is_tech_metadata_param(name):
            self.cache.add_param(name, source_tool=source, confidence=0.75)

        entry = self.param_inventory.setdefault(
            name,
            {
                "name": name,
                "sources": [],
                "tags": ["unknown"],
            },
        )
        if source not in entry["sources"]:
            entry["sources"].append(source)
        if self._is_tech_metadata_param(name):
            tag = "technical_metadata"
        elif source in {
            "url_param",
            "url",
            "multi_source",
            "api_schema",
            "zap",
            "js_discovery",
            "query",
        }:
            tag = "potential_controllable"
        elif source in {"form", "form_field", "crawler_form"}:
            tag = "confirmed_controllable"
        else:
            tag = "unknown"
        entry["tags"] = sorted(list(set(entry.get("tags", []) + [tag])))

        if endpoint:
            endpoint_key = self._normalize_endpoint_path(endpoint)
            rows = self.param_sources_by_endpoint.setdefault(endpoint_key, [])
            exists = any(
                r.get("name") == name and r.get("source") == source for r in rows
            )
            if not exists:
                rows.append({"name": name, "source": source, "tag": tag})

    def _register_endpoint(
        self,
        endpoint: str,
        source: str,
        confidence: float = 0.75,
        is_live: bool = False,
        param_source: str = "url_param",
    ) -> None:
        path = self._normalize_endpoint_path(endpoint)
        if not path:
            return

        self.cache.add_endpoint(path, source_tool=source, confidence=confidence)
        if is_live:
            self.cache.live_endpoints.add(path)

        item = self.endpoint_inventory.setdefault(
            path,
            {
                "path": path,
                "sources": [],
                "classification": self._classify_endpoint(path),
                "has_params": False,
                "params": [],
                "urls": [],
            },
        )
        if source not in item["sources"]:
            item["sources"].append(source)

        raw = str(endpoint or "").strip()
        if raw.startswith("http") and raw not in item["urls"]:
            item["urls"].append(raw)

        parsed = urlparse(
            raw if raw.startswith("http") else f"https://placeholder{path}"
        )
        for param_name in parse_qs(parsed.query).keys():
            self._register_param(param_name, param_source, endpoint=path)
            if param_name not in item["params"]:
                item["params"].append(param_name)
                item["has_params"] = True

    def _synchronize_inventory_from_cache(self) -> None:
        for ep in self.cache.get_normalized_endpoints():
            path = self._normalize_endpoint_path(ep)
            if not path:
                continue
            item = self.endpoint_inventory.setdefault(
                path,
                {
                    "path": path,
                    "sources": ["unknown"],
                    "classification": self._classify_endpoint(path),
                    "has_params": False,
                    "params": [],
                    "urls": [],
                },
            )
            if not item.get("sources"):
                item["sources"] = ["unknown"]

    def _apply_endpoint_quality_filter(self) -> None:
        """Filter noisy endpoints before quality scoring and exploitation steps."""
        self._synchronize_inventory_from_cache()

        filtered_endpoints = set()
        filtered_live = set()
        for ep in self.cache.get_normalized_endpoints():
            cls = self._classify_endpoint(ep)
            has_params = bool(self.param_sources_by_endpoint.get(ep))
            if (
                self._is_noise_endpoint(ep)
                and cls not in {"API", "PAGE"}
                and not has_params
            ):
                continue
            filtered_endpoints.add(ep)

        for ep in self.cache.get_live_normalized_endpoints():
            if ep in filtered_endpoints:
                filtered_live.add(ep)

        self.cache.endpoints = filtered_endpoints
        self.cache.live_endpoints = filtered_live

        # Ensure params are never empty when endpoints exist.
        if self.cache.endpoints and not self.cache.params:
            self._register_param(
                "id", "fallback", endpoint=next(iter(self.cache.endpoints))
            )

    def _build_endpoint_inventory_for_report(self) -> List[Dict[str, Any]]:
        self._synchronize_inventory_from_cache()
        rows: List[Dict[str, Any]] = []
        for path in sorted(self.endpoint_inventory.keys()):
            item = self.endpoint_inventory[path]
            cls = item.get("classification", self._classify_endpoint(path))
            if (
                not self.full_report
                and self._is_noise_endpoint(path)
                and cls in {"STATIC", "CODE"}
            ):
                continue
            has_params = bool(item.get("has_params")) or bool(
                self.param_sources_by_endpoint.get(path)
            )
            rows.append(
                {
                    "url": path,
                    "sources": sorted(item.get("sources", [])),
                    "has_params": has_params,
                    "classification": cls,
                    "confidence_tier": self._endpoint_confidence_tier(path, item),
                    "eligible_for_exploitation": self._should_feed_exploitation(
                        path, item
                    ),
                    "params": sorted(item.get("params", [])),
                }
            )
        return rows

    def _build_api_candidate_inventory(self) -> List[Dict[str, Any]]:
        candidates = []
        for row in self._build_endpoint_inventory_for_report():
            low = str(row.get("url", "")).lower()
            tier = str(row.get("confidence_tier", "unverified_path"))
            if any(
                marker in low
                for marker in [
                    "/api",
                    "/v1",
                    "/graphql",
                    "/auth",
                    "/swagger",
                    "openapi.json",
                    "swagger.json",
                    "/v3/api-docs",
                ]
            ) and tier in {"verified_live_api", "probable_api"}:
                candidates.append(row)
        return candidates

    def _build_high_value_targets(self) -> List[Dict[str, Any]]:
        targets = []
        for row in self._build_endpoint_inventory_for_report():
            classification = row.get("classification", "UNKNOWN")
            tier = str(row.get("confidence_tier", "unverified_path"))
            if tier not in {"verified_live_api", "probable_api", "verified_page"}:
                continue
            if classification == "API" and row.get("has_params"):
                priority = 1
            elif classification == "API":
                priority = 2
            elif classification == "PAGE":
                priority = 3
            else:
                continue
            targets.append(
                {
                    "priority": priority,
                    "url": row.get("url"),
                    "sources": row.get("sources", []),
                    "params": row.get("params", []),
                    "classification": classification,
                    "confidence_tier": tier,
                }
            )
        targets.sort(key=lambda x: (x["priority"], x["url"]))
        return targets

    def _build_endpoint_confidence_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {
            "verified_live_api": 0,
            "probable_api": 0,
            "verified_page": 0,
            "static_asset": 0,
            "unverified_path": 0,
        }
        for row in self._build_endpoint_inventory_for_report():
            tier = str(row.get("confidence_tier", "unverified_path"))
            counts[tier] = counts.get(tier, 0) + 1
        return counts

    def _build_api_doc_exposure(self) -> Dict[str, Any]:
        docs = []
        for row in self._build_endpoint_inventory_for_report():
            path = str(row.get("url", ""))
            if not self._is_api_doc_path(path):
                continue
            docs.append(
                {
                    "url": path,
                    "sources": row.get("sources", []),
                    "confidence_tier": row.get("confidence_tier", "unverified_path"),
                    "recommended_checks": [
                        "Auth bypass on documentation endpoints",
                        "Schema leakage and hidden operations",
                        "Exposed internal server URLs",
                    ],
                }
            )
        return {
            "count": len(docs),
            "paths": docs,
        }

    def _build_service_focus_tracks(self) -> List[Dict[str, Any]]:
        tracks: List[Dict[str, Any]] = []
        seen: set[tuple[str, int]] = set()
        for host in self.host_network_assessment or []:
            host_name = str(host.get("host", self.profile.host))
            for port in host.get("open_ports", []) or []:
                port_num = int(port)
                if port_num in {80, 443}:
                    continue
                key = (host_name, port_num)
                if key in seen:
                    continue
                seen.add(key)
                tracks.append(
                    {
                        "host": host_name,
                        "port": port_num,
                        "priority": "HIGH" if port_num == 8081 else "MEDIUM",
                        "track": "non_standard_service",
                        "checks": [
                            "Route mapping and hidden endpoints",
                            "Default middleware/debug endpoints",
                            "Admin and proxy surface checks",
                        ],
                    }
                )

        for port in sorted(self.cache.discovered_ports):
            port_num = int(port)
            if port_num in {80, 443}:
                continue
            key = (self.profile.host, port_num)
            if key in seen:
                continue
            seen.add(key)
            tracks.append(
                {
                    "host": self.profile.host,
                    "port": port_num,
                    "priority": "HIGH" if port_num == 8081 else "MEDIUM",
                    "track": "non_standard_service",
                    "checks": [
                        "Route mapping and hidden endpoints",
                        "Default middleware/debug endpoints",
                        "Admin and proxy surface checks",
                    ],
                }
            )
        return tracks

    def _build_residual_risk_statements(self) -> List[str]:
        residual: List[str] = []
        if not self.auth_access_control_summary.get("authenticated_roles"):
            residual.append(
                "No authenticated role sessions were validated; BOLA/IDOR assurance is incomplete."
            )
        if int(self.auth_access_control_summary.get("endpoints_tested", 0) or 0) == 0:
            residual.append(
                "Authenticated authorization paths were not exercised with role context."
            )
        if not self.cache.reflections:
            residual.append(
                "Reflection-driven attack chains remain low-confidence because no reflections were detected."
            )
        if self._build_service_focus_tracks():
            residual.append(
                "Non-standard exposed services require dedicated service-track testing (for example port 8081)."
            )
        return residual

    def _is_api_like_path(self, path: str) -> bool:
        path_lower = str(path or "").lower()
        return (
            "/api" in path_lower
            or path_lower.endswith(".json")
            or "graphql" in path_lower
        )

    def _is_scannable_discovery_url(self, value: str) -> bool:
        value = str(value or "").strip()
        if not value.startswith(("http://", "https://")):
            return False
        parsed = urlparse(value)
        host = parsed.netloc.lower()
        base = (self.profile.base_domain or self.profile.host).lower()
        if host == self.profile.host.lower() or host.endswith(f".{base}"):
            return True
        return False

    def _extract_urls_from_text(self, text: str) -> list[str]:
        if not text:
            return []
        found = re.findall(r"https?://[^\s\"'<>]+", text)
        return [u.strip() for u in found if self._is_scannable_discovery_url(u.strip())]

    def _run_discovery_source_command(
        self, command: str, stdin_text: str | None = None, timeout: int = 40
    ) -> list[str]:
        try:
            completed = subprocess.run(
                command,
                shell=True,
                input=stdin_text,
                text=True,
                capture_output=True,
                timeout=timeout,
            )
        except Exception:
            return []

        content = f"{completed.stdout or ''}\n{completed.stderr or ''}"
        urls = set()
        for line in content.splitlines():
            line = line.strip()
            if self._is_scannable_discovery_url(line):
                urls.add(line)
            else:
                for candidate in self._extract_urls_from_text(line):
                    urls.add(candidate)
        return sorted(urls)

    def _discover_endpoints_from_js_assets(self, base_url: str) -> list[str]:
        """Fallback endpoint extraction from JS sources when crawler output is sparse."""
        discovered_urls: set[str] = set()
        js_asset_map: Dict[str, List[str]] = {}
        try:
            import requests

            response = requests.get(base_url, timeout=12, verify=False)
            body = response.text if response is not None else ""
            script_sources = set(
                re.findall(r"<script[^>]+src=[\"']([^\"']+)[\"']", body, re.IGNORECASE)
            )

            endpoint_pattern = re.compile(
                r"(?:(?:https?://[^\"'\s]+)|(?:/(?:api|v1|v2|graphql|auth)[A-Za-z0-9_\-./]*(?:\?[A-Za-z0-9_\-=&.%]+)?))"
            )
            for src in script_sources:
                js_url = src if src.startswith("http") else urljoin(base_url, src)
                if not self._is_scannable_discovery_url(js_url):
                    continue
                if any(
                    x in js_url.lower() for x in ["/node_modules/", "/src/"]
                ) or js_url.lower().endswith((".map", ".ts")):
                    continue
                try:
                    js_resp = requests.get(js_url, timeout=10, verify=False)
                except Exception:
                    continue
                for match in endpoint_pattern.findall(js_resp.text or ""):
                    candidate = match.strip()
                    if not candidate:
                        continue
                    if candidate.startswith("/"):
                        candidate = urljoin(base_url, candidate)
                    if self._is_scannable_discovery_url(candidate):
                        if any(
                            x in candidate.lower() for x in ["/node_modules/", "/src/"]
                        ) or candidate.lower().endswith((".map", ".ts")):
                            continue
                        discovered_urls.add(candidate)
                        js_asset_map.setdefault(js_url, [])
                        norm = self._normalize_endpoint_path(candidate)
                        if norm and norm not in js_asset_map[js_url]:
                            js_asset_map[js_url].append(norm)
        except Exception:
            return []

        if js_asset_map:
            self.js_asset_inventory = js_asset_map

        return sorted(discovered_urls)

    def _run_multi_source_discovery(self, base_url: str) -> None:
        """Aggregate URL/param discovery from passive and crawl-focused sources."""
        sources: dict[str, int] = {}
        discovered_urls: set[str] = set()

        tool_commands = [
            ("gau", f"gau --subs {self.profile.base_domain or self.profile.host}"),
            (
                "waybackurls",
                f"echo {self.profile.base_domain or self.profile.host} | waybackurls",
            ),
            ("hakrawler", f"echo {base_url} | hakrawler -plain -depth 3"),
        ]

        for source_name, command in tool_commands:
            if shutil.which(source_name) is None:
                sources[source_name] = 0
                continue
            urls = self._run_discovery_source_command(command, timeout=45)
            sources[source_name] = len(urls)
            discovered_urls.update(urls)

        js_fallback_urls = self._discover_endpoints_from_js_assets(base_url)
        sources["js_regex"] = len(js_fallback_urls)
        discovered_urls.update(js_fallback_urls)

        added_endpoints = 0
        added_params = 0
        for url in sorted(discovered_urls):
            path = urlparse(url).path or "/"
            if not path:
                continue
            before_ep = len(self.cache.endpoints)
            self._register_endpoint(
                url,
                source="multi_source",
                confidence=0.78,
                is_live=self._is_api_like_path(path),
                param_source="url",
            )
            if self._is_api_like_path(path):
                self.cache.live_endpoints.add(path)
            if len(self.cache.endpoints) > before_ep:
                added_endpoints += 1

            for param_name in parse_qs(urlparse(url).query).keys():
                before_param = len(self.cache.params)
                self._register_param(param_name, source="url", endpoint=path)
                if len(self.cache.params) > before_param:
                    added_params += 1

        self.multi_source_summary = {
            "executed": True,
            "sources": sources,
            "urls": len(discovered_urls),
            "endpoints": added_endpoints,
            "params": added_params,
        }
        self.log(
            "Multi-source discovery merged: "
            f"{added_endpoints} endpoints, {added_params} params, "
            f"sources={sources}",
            "INFO",
        )

    def _run_js_aware_discovery(self, base_url: str) -> None:
        """Run browser-assisted JS discovery and merge signals into cache."""
        try:
            role_headers: Dict[str, Dict[str, str]] = {}
            for role in self.request_context.active_roles(include_anonymous=False):
                role_headers[role] = self.request_context.build_headers(role)

            js_discovery = JSBrowserDiscovery(timeout=20, max_pages=20)
            result = js_discovery.discover(base_url, role_headers=role_headers)

            for endpoint in result.get("endpoints", []):
                self._register_endpoint(
                    endpoint,
                    source="js_discovery",
                    confidence=0.85,
                    is_live=self._is_api_like_path(endpoint),
                    param_source="js",
                )
                if self._is_api_like_path(endpoint):
                    self.cache.live_endpoints.add(endpoint)

            for endpoint in result.get("api_endpoints", []):
                self._register_endpoint(
                    endpoint,
                    source="js_discovery",
                    confidence=0.9,
                    is_live=True,
                    param_source="js",
                )
                self.cache.live_endpoints.add(endpoint)

            for param in result.get("params", []):
                self._register_param(str(param), source="js")

            stats = result.get("stats", {})
            self.js_discovery_summary = {
                "executed": True,
                "success": bool(result.get("success", False)),
                "playwright_used": bool(result.get("playwright_used", False)),
                "endpoints": int(stats.get("endpoints", 0)),
                "api_endpoints": int(stats.get("api_endpoints", 0)),
                "js_assets": int(stats.get("js_assets", 0)),
                "network_requests": int(stats.get("network_requests", 0)),
                "requests_captured": int(result.get("requests_captured", 0)),
                "api_calls_detected": int(result.get("api_calls_detected", 0)),
                "params": int(stats.get("params", 0)),
                "warning": result.get("warning"),
                "signal_strength": result.get("signal_strength", "low"),
            }
            self.log(
                "JS-aware discovery merged: "
                f"{self.js_discovery_summary['endpoints']} endpoints, "
                f"{self.js_discovery_summary['api_endpoints']} API endpoints, "
                f"{self.js_discovery_summary['params']} params",
                "INFO",
            )
            if not self.js_discovery_summary["success"]:
                self.log(
                    "JS-aware discovery returned low signal; continuing with other sources",
                    "WARN",
                )
        except Exception as e:
            self.js_discovery_summary = {
                "executed": True,
                "playwright_used": False,
                "success": False,
                "endpoints": 0,
                "api_endpoints": 0,
                "js_assets": 0,
                "network_requests": 0,
                "requests_captured": 0,
                "api_calls_detected": 0,
                "params": 0,
                "error": str(e),
            }
            self.log(f"JS-aware discovery failed: {e} (non-fatal)", "WARN")

    def _run_zap_enrichment(self, base_url: str) -> None:
        """Run ZAP API intelligence flow, fallback to baseline docker if API fails.

        ZAP is resource-intensive and can crash on large sites (memory >95%).
        This method has defensive error handling to proceed even if ZAP is unavailable.
        """
        try:
            result = self.zap_adapter.run_intelligence_scan(
                base_url, include_active_scan=False
            )
            if not result.success:
                self.log(
                    f"ZAP API enrichment unavailable, trying baseline fallback: {result.error}",
                    "INFO",
                )
                result = self.zap_adapter.run_baseline_docker(base_url, self.output_dir)
        except (TimeoutError, ConnectionError, OSError) as e:
            # ZAP crashed, hung, or became unreachable - skip enrichment gracefully
            self.log(
                f"ZAP enrichment unavailable: {type(e).__name__} - continuing without ZAP",
                "INFO",
            )
            self.zap_discovery_summary = {
                "executed": False,
                "success": False,
                "endpoints": 0,
                "params": 0,
                "alerts": 0,
                "headers": 0,
                "cookies": 0,
                "error": f"ZAP unavailable: {type(e).__name__}",
            }
            return
        except Exception as e:
            # Catch-all for any other ZAP errors (process termination, memory OOM, etc.)
            self.log(
                f"ZAP enrichment unavailable: {type(e).__name__} - skipping enrichment",
                "INFO",
            )
            self.zap_discovery_summary = {
                "executed": False,
                "success": False,
                "endpoints": 0,
                "params": 0,
                "alerts": 0,
                "headers": 0,
                "cookies": 0,
                "error": f"ZAP exception: {str(e)[:80]}",
            }
            return

        as_dict = result.to_dict()
        self.zap_discovery_summary = {
            "executed": True,
            "success": bool(as_dict.get("success", False)),
            "endpoints": int(as_dict.get("stats", {}).get("endpoints", 0)),
            "params": int(as_dict.get("stats", {}).get("params", 0)),
            "alerts": int(as_dict.get("stats", {}).get("alerts", 0)),
            "headers": int(as_dict.get("stats", {}).get("headers", 0)),
            "cookies": int(as_dict.get("stats", {}).get("cookies", 0)),
            "error": as_dict.get("error"),
        }

        if not result.success:
            self.log(f"ZAP enrichment unavailable: {result.error}", "INFO")
            return

        for endpoint in as_dict.get("endpoints", []):
            self._register_endpoint(
                endpoint,
                source="zap",
                confidence=0.75,
                is_live=self._is_api_like_path(endpoint),
                param_source="url",
            )
            if self._is_api_like_path(endpoint):
                self.cache.live_endpoints.add(endpoint)

        for param in as_dict.get("params", []):
            self._register_param(str(param), source="zap")

        # Keep alerts in finding pipeline for later correlation/validation.
        zap_findings = self.finding_pipeline.ingest_zap_alerts(
            as_dict.get("alerts", [])
        )
        if zap_findings:
            self.finding_pipeline.add_findings(zap_findings)

        self.log(
            "ZAP enrichment merged: "
            f"{self.zap_discovery_summary['endpoints']} endpoints, "
            f"{self.zap_discovery_summary['params']} params, "
            f"{self.zap_discovery_summary['alerts']} alerts",
            "INFO",
        )

    def _run_api_schema_import(self, base_url: str) -> None:
        """Import OpenAPI/Swagger/GraphQL endpoints as structured targets."""
        result = self.api_schema_importer.discover(base_url)
        total_params = 0
        self.api_schema_summary = {
            "executed": True,
            "success": bool(result.success),
            "source": result.source,
            "endpoints": len(result.endpoints),
            "params": 0,
            "error": result.error,
        }

        if not result.success:
            self.log(f"API schema import: {result.error}", "INFO")
            return

        for item in result.endpoints:
            endpoint = str(item.get("endpoint", "")).strip()
            method = str(item.get("method", "GET")).upper()
            params = (
                item.get("params", []) if isinstance(item.get("params"), list) else []
            )
            if not endpoint:
                continue
            self._register_endpoint(
                endpoint,
                source="api_schema",
                confidence=0.95,
                is_live=True,
                param_source="url",
            )
            self.cache.live_endpoints.add(endpoint)
            for param in params:
                self._register_param(str(param), source="api_schema", endpoint=endpoint)
                total_params += 1
            if self.endpoint_graph:
                try:
                    self.endpoint_graph.add_endpoint(endpoint, params, method)
                except Exception:
                    pass

        self.api_schema_summary["params"] = total_params
        self.log(
            "API schema import merged: "
            f"{self.api_schema_summary['endpoints']} endpoints, "
            f"{self.api_schema_summary['params']} params",
            "INFO",
        )

    def _run_passive_analysis(self, base_url: str) -> None:
        """Run lightweight passive header analysis and feed findings pipeline."""
        try:
            import requests

            response = requests.get(base_url, timeout=10, verify=False)
            passive_findings_raw = analyze_headers(base_url, dict(response.headers))
            passive_findings = self.finding_pipeline.ingest_passive_findings(
                passive_findings_raw
            )
            if passive_findings:
                self.finding_pipeline.add_findings(passive_findings)
            self.log(f"Passive analysis findings: {len(passive_findings)}", "INFO")
        except Exception as e:
            self.log(f"Passive analysis failed: {e}", "WARN")

    def _evaluate_discovery_quality(self) -> None:
        """Compute discovery quality and expose abort signal for exploitation."""
        quality_metrics = collect_discovery_metrics(
            endpoints_total=len(self.cache.endpoints),
            api_endpoints=int(self.js_discovery_summary.get("api_endpoints", 0))
            + int(self.api_schema_summary.get("endpoints", 0)),
            params_total=len(self.cache.params),
            reflections=len(self.cache.reflections),
            js_calls=int(self.js_discovery_summary.get("network_requests", 0)),
            zap_urls=int(self.zap_discovery_summary.get("endpoints", 0)),
            gau_urls=int(self.multi_source_summary.get("sources", {}).get("gau", 0)),
            wayback_urls=int(
                self.multi_source_summary.get("sources", {}).get("waybackurls", 0)
            ),
            hakrawler_urls=int(
                self.multi_source_summary.get("sources", {}).get("hakrawler", 0)
            ),
            js_regex_urls=int(
                self.multi_source_summary.get("sources", {}).get("js_regex", 0)
            ),
        )
        quality_state = assess_discovery_status(quality_metrics)

        metrics = {
            "endpoints": len(self.cache.endpoints),
            "params": len(self.cache.params),
            "api_calls": self.js_discovery_summary.get("network_requests", 0),
            "js_success": bool(self.js_discovery_summary.get("success", False)),
            "source_signals": int(self.multi_source_summary.get("urls", 0)),
        }
        self.discovery_quality = score_discovery(metrics)
        self.discovery_quality["metrics"] = quality_metrics
        self.discovery_quality["status_metrics"] = quality_state
        self.discovery_quality["should_abort_exploitation"] = quality_state == "FAILED"
        self.log(
            "Discovery quality: "
            f"{self.discovery_quality.get('status')} "
            f"(score={self.discovery_quality.get('score')})",
            "INFO",
        )

    def _extract_idor_candidate_endpoints(self, base_url: str) -> List[str]:
        """Build endpoint candidates for role-aware IDOR/access-control checks."""
        candidates: List[str] = []
        id_like = re.compile(
            r"(id|user|account|order|profile|invoice|project)", re.IGNORECASE
        )

        for endpoint in self.cache.get_normalized_endpoints()[:150]:
            if not endpoint:
                continue
            if (
                "?" in endpoint
                or re.search(r"/\d+(/|$)", endpoint)
                or id_like.search(endpoint)
            ):
                full = (
                    endpoint
                    if endpoint.startswith("http")
                    else f"{base_url}{endpoint if endpoint.startswith('/') else '/' + endpoint}"
                )
                candidates.append(full)

        return sorted(list(set(candidates)))[:25]

    def _run_auth_access_control_assessment(self, base_url: str) -> None:
        """Run async role-based authentication, IDOR, and access-control checks."""
        try:
            summary = asyncio.run(
                self._run_auth_access_control_assessment_async(base_url)
            )
            self.auth_access_control_summary = summary
            self.log(
                "Auth/IDOR assessment: "
                f"roles={len(summary.get('authenticated_roles', []))}, "
                f"IDOR={summary.get('idor_findings', 0)}, "
                f"access_control={summary.get('access_control_findings', 0)}",
                "INFO",
            )
        except Exception as e:
            self.auth_access_control_summary = {
                "executed": False,
                "enabled_roles": [],
                "authenticated_roles": [],
                "endpoints_tested": 0,
                "idor_findings": 0,
                "access_control_findings": 0,
                "errors": [str(e)],
            }
            self.log(f"Auth/IDOR assessment failed: {e}", "WARN")

    async def _run_auth_access_control_assessment_async(
        self, base_url: str
    ) -> Dict[str, Any]:
        config_path = Path("auth_config") / "auth_config.json"
        if not config_path.exists():
            return {
                "executed": False,
                "enabled_roles": [],
                "authenticated_roles": [],
                "endpoints_tested": 0,
                "idor_findings": 0,
                "access_control_findings": 0,
                "errors": ["auth_config/auth_config.json not found"],
            }

        with config_path.open("r", encoding="utf-8") as fh:
            config = json.load(fh)

        request_engine = RequestEngine(timeout=20.0, verify_ssl=False)
        auth_engine = AuthEngine(request_engine)
        request_engine.auth_engine = auth_engine

        enabled_roles: List[str] = []
        errors: List[str] = []
        auth_entries = config.get("authentication_engines", [])
        for entry in auth_entries:
            if not entry.get("enabled"):
                continue
            login_url = str(entry.get("login_url", "")).strip()
            if not login_url:
                continue
            if login_url.startswith("/"):
                login_url = f"{base_url}{login_url}"
            if "target.com" in login_url:
                continue

            role = entry.get("role")
            auth_type_name = str(entry.get("auth_type", "form_login")).upper()
            try:
                auth_type = AuthType[auth_type_name]
            except KeyError:
                auth_type = AuthType.FORM_LOGIN

            login_config = LoginConfig(
                role=role,
                auth_type=auth_type,
                login_url=login_url,
                username=entry.get("username"),
                password=entry.get("password"),
                api_key=entry.get("api_key"),
                bearer_token=entry.get("bearer_token"),
                custom_headers=entry.get("custom_headers", {}) or {},
                login_data=entry.get("login_data", {}) or {},
                token_field_path=entry.get("token_field_path", "data.access_token"),
                expected_status_success=int(entry.get("expected_status_success", 200)),
                cookie_names=entry.get("cookie_names", []) or [],
            )
            ok = await auth_engine.register_login_flow(login_config)
            if ok:
                enabled_roles.append(role)

        auth_results = (
            await auth_engine.authenticate_all_roles() if enabled_roles else {}
        )
        authenticated_roles = [role for role, ok in auth_results.items() if ok]

        for role in authenticated_roles:
            headers, cookie_header = await auth_engine.get_auth_for_role(role)
            cookies = {}
            if cookie_header:
                for chunk in cookie_header.split(";"):
                    if "=" in chunk:
                        k, v = chunk.strip().split("=", 1)
                        cookies[k] = v
            self.request_context.add_or_update_role(
                role=role,
                headers=headers,
                cookies=cookies,
                authenticated=True,
                source="auth_engine",
            )

        param_extractor = ParameterExtractor()
        response_analyzer = ResponseAnalyzer()
        idor_engine = IDOREngine(request_engine, param_extractor, response_analyzer)
        access_engine = AccessControlEngine(request_engine, response_analyzer)

        endpoints = self._extract_idor_candidate_endpoints(base_url)
        idor_total = 0
        access_total = 0

        if authenticated_roles and endpoints:
            roles_for_idor = (
                authenticated_roles[:2]
                if len(authenticated_roles) > 1
                else authenticated_roles
            )
            low_role = authenticated_roles[0]
            high_role = (
                authenticated_roles[1]
                if len(authenticated_roles) > 1
                else authenticated_roles[0]
            )

            for endpoint in endpoints:
                try:
                    idor_findings = await idor_engine.test_endpoint(
                        endpoint,
                        method="GET",
                        roles=roles_for_idor,
                    )
                    idor_total += len(idor_findings)
                    for f in idor_findings:
                        self.findings.add(f.to_finding())
                except Exception as e:
                    errors.append(f"IDOR {endpoint}: {e}")

                try:
                    ac_findings = await access_engine.test_unauthorized_endpoint_access(
                        endpoint,
                        required_role=high_role,
                    )
                    access_total += len(ac_findings)
                    for f in ac_findings:
                        self.findings.add(f.to_finding())
                except Exception as e:
                    errors.append(f"AC unauth {endpoint}: {e}")

                if len(authenticated_roles) > 1:
                    try:
                        ac_pe = await access_engine.test_privilege_escalation(
                            endpoint,
                            low_role=low_role,
                            high_role=high_role,
                        )
                        access_total += len(ac_pe)
                        for f in ac_pe:
                            self.findings.add(f.to_finding())
                    except Exception as e:
                        errors.append(f"AC privilege {endpoint}: {e}")

        return {
            "executed": True,
            "enabled_roles": enabled_roles,
            "authenticated_roles": authenticated_roles,
            "endpoints_tested": len(endpoints),
            "idor_findings": idor_total,
            "access_control_findings": access_total,
            "errors": errors[:20],
        }

    def _register_crawl_security_findings(
        self,
        crawl_url: str,
        crawl_result: Optional[Dict],
        gating_signals: Optional[Dict],
    ) -> None:
        """Create explicit findings from crawler-observed security leaks."""
        summary = {}
        if isinstance(crawl_result, dict):
            summary = crawl_result.get("summary", {}) or {}
        gating = gating_signals or {}

        debug_page_exposed = bool(
            summary.get("debug_page_exposed") or gating.get("debug_page_exposed")
        )

        debug_indicators = []
        for item in (summary.get("debug_indicators") or []) + (
            gating.get("debug_indicators") or []
        ):
            if item and item not in debug_indicators:
                debug_indicators.append(str(item))

        leaked_routes = []
        for item in (summary.get("leaked_routes") or []) + (
            gating.get("leaked_routes") or []
        ):
            if item and item not in leaked_routes:
                leaked_routes.append(str(item))

        if debug_page_exposed:
            evidence_lines = [
                "Application exposed a framework debug page over HTTP.",
                f"Target: {crawl_url}",
            ]
            if debug_indicators:
                evidence_lines.append("Indicators: " + ", ".join(debug_indicators[:6]))
            if leaked_routes:
                evidence_lines.append("Leaked routes: " + ", ".join(leaked_routes[:8]))

            finding = Finding(
                type=FindingType.MISCONFIGURATION,
                severity=Severity.HIGH,
                location=crawl_url,
                description="Debug page exposed (DEBUG=True) allowing framework internals and route disclosure",
                cwe="CWE-489",
                owasp="A05:2021 - Security Misconfiguration",
                tool="crawler",
                evidence="\n".join(evidence_lines),
                remediation=(
                    "Disable framework debug mode in production (DEBUG=False), "
                    "use custom error handlers, and restrict diagnostic views."
                ),
                impact=(
                    "Attackers can enumerate internal URL patterns and framework details, "
                    "reducing effort needed for targeted endpoint abuse."
                ),
                exploitability="HIGH",
                verification_steps=(
                    "Request an invalid path and verify the response does not disclose framework "
                    "version, URLConf, or full route lists."
                ),
            )
            self.findings.add(finding)
            self.log("Added finding: debug page exposure detected by crawler", "WARN")

        # If routes are leaked but no API endpoint was captured as live, register a separate disclosure.
        if leaked_routes and not any(
            "/api" in ep.lower() for ep in self.cache.endpoints
        ):
            leak_finding = Finding(
                type=FindingType.INFO_DISCLOSURE,
                severity=Severity.MEDIUM,
                location=crawl_url,
                description="API route disclosure observed in server response content",
                cwe="CWE-200",
                owasp="A01:2021 - Broken Access Control",
                tool="crawler",
                evidence="Leaked API routes: " + ", ".join(leaked_routes[:12]),
                remediation="Remove route listings from unauthenticated responses and generic 404/500 pages.",
                impact="Leaked endpoint inventory helps attackers map hidden API surfaces.",
                exploitability="MEDIUM",
                verification_steps="Request non-existent paths and confirm route details are not disclosed.",
            )
            self.findings.add(leak_finding)
            self.log(
                "Added finding: API route disclosure from debug/content leak", "WARN"
            )

    def _populate_cache_from_fallback_sources(self) -> None:
        """When crawler times out, gather alternative targets from already-executed discovery tools.

        Sources: nuclei (template matches), whatweb (detected services), nmap (open ports).
        Allows payload tools to execute with partial endpoint list instead of full block.
        """
        scheme = "https" if self.profile.is_https else "http"
        base_url = f"{scheme}://{self.profile.host}"
        target_count_before = len(self.cache.endpoints)

        # Collect endpoints from tool outputs that might have written to files
        fallback_endpoints = set()
        fallback_endpoints.add(base_url)  # Always include root
        fallback_endpoints.add(f"{base_url}/")

        # Scan execution results for any discovered URLs or endpoints
        for result in self.execution_results:
            try:
                if result.get("output_file"):
                    output_file = Path(result.get("output_file"))
                    if output_file.exists():
                        content = output_file.read_text(
                            encoding="utf-8", errors="ignore"
                        )

                        # Extract URLs from nuclei, whatweb, nmap output
                        url_pattern = r'https?://[^\s\'"<>]+'
                        for match in re.finditer(url_pattern, content):
                            url = match.group(0).split()[0]  # Remove trailing chars
                            if len(url) < 500:  # Skip excessively long matches
                                fallback_endpoints.add(url)

                        # Extract path-only targets
                        path_pattern = r"/([\w\-./]*)"
                        for match in re.finditer(path_pattern, content):
                            path = "/" + match.group(1)
                            if 3 < len(path) < 200 and not any(
                                x in path for x in [".bin", ".so", ".whl", ".mp4"]
                            ):
                                candidate = (
                                    urlparse(base_url)
                                    ._replace(path=path, query="", fragment="")
                                    .geturl()
                                )
                                fallback_endpoints.add(candidate)
            except Exception as e:
                self.log(
                    f"Failed to extract fallback endpoints from {result.get('tool')}: {e}",
                    "DEBUG",
                )
                continue

        # Add to cache
        for endpoint in fallback_endpoints:
            if endpoint and len(endpoint) < 500:
                try:
                    self.cache.add_endpoint(endpoint)
                except Exception:
                    pass

        target_count_after = len(self.cache.endpoints)
        self.log(
            f"Fallback discovery: +{target_count_after - target_count_before} endpoints from tool outputs",
            "WARN",
        )

    def _collect_security_strengths(self) -> list[str]:
        """Extract verified positive security signals from executed tool outputs."""
        strengths: list[str] = []
        output_files = [
            r.get("output_file") for r in self.execution_results if r.get("output_file")
        ]
        seen = set()

        def _add(msg: str) -> None:
            if msg not in seen:
                seen.add(msg)
                strengths.append(msg)

        for path in output_files:
            try:
                p = Path(path)
                if not p.exists():
                    continue
                content = p.read_text(encoding="utf-8", errors="ignore").lower()
                if "tlsv1.3" in content and "enabled" in content:
                    _add("TLS 1.3 is enabled")
                if "tlsv1.2" in content and "enabled" in content:
                    _add("TLS 1.2 is enabled")
                if "sslv3" in content and "disabled" in content:
                    _add("Legacy SSLv3 is disabled")
                if "tlsv1.0" in content and "disabled" in content:
                    _add("Legacy TLS 1.0 is disabled")
                if "heartbleed" in content and "not vulnerable" in content:
                    _add("Heartbleed check passed (not vulnerable)")
                if "poodle" in content and "not vulnerable" in content:
                    _add("POODLE check passed (not vulnerable)")
                if "freak" in content and "not vulnerable" in content:
                    _add("FREAK check passed (not vulnerable)")
            except Exception:
                continue

        return strengths

    def _prompt_manual_out_of_scope_action(self) -> str:
        """Prompt user for manual out-of-scope execution mode: yes/no/skip."""
        if self.manual_out_of_scope_mode in {"yes", "no", "skip"}:
            return self.manual_out_of_scope_mode

        # Non-interactive executions should not block waiting for input.
        if not sys.stdin or not sys.stdin.isatty():
            self.log(
                "Manual out-of-scope sweep prompt skipped (non-interactive mode)",
                "WARN",
            )
            return "skip"

        while True:
            choice = (
                input(
                    "\nRun out-of-scope skipped/missing tools across all discovered API/pages? [yes/no/skip]: "
                )
                .strip()
                .lower()
            )
            if choice in {"yes", "no", "skip"}:
                return choice
            print("Please enter one of: yes, no, skip")

    def _run_tool(self, plan_item: dict, index: int, total: int) -> dict:
        """Orchestrate tool execution: decision → execution → parsing → result.

        Responsibility split:
        - Decision layer: _should_run()
        - Execution layer: _execute_tool_subprocess()
        - Classification layer: _classify_execution_outcome()
        - Parsing layer: _parse_discoveries(), _extract_findings()
        """
        tool = plan_item["tool"]
        command = plan_item["command"]
        configured_timeout = int(plan_item.get("timeout", 300))
        timeout = min(configured_timeout, self.MAX_TOOL_TIMEOUT)
        category = plan_item.get("category", "Unknown")
        retries = plan_item.get("retries", 0)

        # ====== PHASE 1: Budget checks ======
        if category == "DNS":
            remaining = max(0.0, self.dns_time_budget - self.dns_time_spent)
            if remaining <= 0:
                result = {
                    "index": index,
                    "total": total,
                    "tool": tool,
                    "category": category,
                    "status": "SKIPPED",
                    "outcome": ToolOutcome.SKIPPED.value,
                    "reason": "DNS budget exhausted",
                    "return_code": None,
                    "timed_out": False,
                    "failure_reason": "dns_budget_exhausted",
                    "started_at": datetime.now().isoformat(),
                    "finished_at": datetime.now().isoformat(),
                    "stderr_preview": "",
                    "stderr_length": 0,
                    "stderr_truncated": False,
                    "signal": "NO_SIGNAL",
                    "command": command,
                }
                self.log(
                    f"{tool} SKIPPED: DNS budget exhausted ({self.dns_time_budget}s)",
                    "WARN",
                )
                with self._lock:
                    self.execution_results.append(result)
                return result
            timeout = min(timeout, remaining)

        # ====== PHASE 2: Decision layer ======
        decision, reason = self._should_run(tool, plan_item)
        if decision == DecisionOutcome.BLOCK:
            result = {
                "index": index,
                "total": total,
                "tool": tool,
                "category": category,
                "status": "BLOCKED",
                "outcome": ToolOutcome.BLOCKED.value,
                "reason": reason,
                "return_code": None,
                "timed_out": False,
                "failure_reason": "blocked_by_prerequisite",
                "started_at": datetime.now().isoformat(),
                "finished_at": datetime.now().isoformat(),
                "stderr_preview": "",
                "stderr_length": 0,
                "stderr_truncated": False,
                "signal": "NO_SIGNAL",
                "command": command,
            }
            self.log(f"[{index}/{total}] {tool} BLOCKED: {reason}", "WARN")

            # Record coverage gap for blocked tool
            block_reason_map = {
                "crawler failed": BlockReason.NO_CRAWLER_DATA,
                "no parameters": BlockReason.NO_PARAMETERS,
                "no endpoints": BlockReason.NO_ENDPOINTS,
                "readiness": BlockReason.READINESS_FAILED,
            }
            block_reason = BlockReason.DECISION_LEDGER  # Default
            for key, br in block_reason_map.items():
                if key in reason.lower():
                    block_reason = br
                    break
            self.coverage_analyzer.record_tool_blocked(tool, category, block_reason)

            with self._lock:
                self.execution_results.append(result)
            return result
        if decision == DecisionOutcome.SKIP:
            result = {
                "index": index,
                "total": total,
                "tool": tool,
                "category": category,
                "status": "SKIPPED",
                "outcome": ToolOutcome.SKIPPED.value,
                "reason": reason,
                "return_code": None,
                "timed_out": False,
                "failure_reason": "skipped_by_policy",
                "started_at": datetime.now().isoformat(),
                "finished_at": datetime.now().isoformat(),
                "stderr_preview": "",
                "stderr_length": 0,
                "stderr_truncated": False,
                "signal": "NO_SIGNAL",
                "command": command,
            }
            self.log(f"[{index}/{total}] {tool} SKIPPED: {reason}", "WARN")
            with self._lock:
                self.execution_results.append(result)
            return result

        # ====== PHASE 3: Runtime enforcement ======
        if datetime.now().timestamp() >= self.runtime_deadline:
            from architecture_guards import ArchitectureViolation

            raise ArchitectureViolation(
                f"Runtime budget exceeded ({self.profile.runtime_budget}s)"
            )

        self.log(f"[{index}/{total}] ({category}) {tool}")
        started_at = datetime.now()

        # ====== PHASE 4: Execution ======
        rc, stdout, stderr = self._execute_tool_subprocess(command, timeout)

        failure_reason = self._classify_failure_reason(rc, stderr)

        # ====== PHASE 5: Classification ======
        signal_stdout = self._filter_actionable_stdout(tool, stdout)
        effective_stdout = signal_stdout if signal_stdout is not None else stdout
        signal = self._classify_signal(tool, effective_stdout, stderr, rc)
        outcome, status = self._classify_execution_outcome(
            tool, rc, signal, failure_reason
        )

        finished_at = datetime.now()
        elapsed = (finished_at - started_at).total_seconds()

        # Track DNS time
        if category == "DNS":
            self.dns_time_spent += min(timeout, elapsed)

        # Classify signal for feedback (already used for outcome classification)

        # ====== PHASE 6: Result document ======
        stderr_len = len(stderr) if stderr else 0
        stderr_truncated = stderr_len > 2000
        stderr_preview = ""
        if stderr:
            stderr_preview = stderr[:2000] + (
                "... [truncated]" if stderr_truncated else ""
            )

        result = {
            "index": index,
            "total": total,
            "tool": tool,
            "category": category,
            "status": status,
            "outcome": outcome.value,
            "reason": (
                f"Timed out after {timeout}s"
                if outcome == ToolOutcome.TIMEOUT
                else failure_reason or f"Exit code {rc}"
            ),
            "return_code": rc,
            "timed_out": outcome == ToolOutcome.TIMEOUT,
            "failure_reason": failure_reason or "",
            "started_at": started_at.isoformat(),
            "finished_at": finished_at.isoformat(),
            "stderr_preview": stderr_preview,
            "stderr_length": stderr_len,
            "stderr_truncated": stderr_truncated,
            "signal": signal,
            "command": command,
        }

        output_file = self._save_tool_output(tool, command, stdout, stderr, rc)
        if output_file:
            result["output_file"] = output_file

        with self._lock:
            self.execution_results.append(result)
        self._tool_execution_meta[tool] = {
            "status": status,
            "outcome": outcome.value,
            "timed_out": outcome == ToolOutcome.TIMEOUT,
            "failure_reason": failure_reason or "",
        }

        # Graceful degradation: parse partial Nikto output even on timeout.
        if tool == "nikto" and outcome == ToolOutcome.TIMEOUT and stdout.strip():
            self.log(
                "Nikto timed out - parsing partial output for hardening findings",
                "WARN",
            )
            try:
                with self._lock:
                    self._parse_discoveries(tool, stdout)
                self._extract_findings(tool, stdout, stderr, output_file)
            except Exception as e:  # noqa: BLE001
                self.log(f"Partial nikto parse failed: {e}", "WARN")

        # ====== PHASE 7: Parsing (if successful) ======
        if outcome == ToolOutcome.SUCCESS_WITH_FINDINGS:
            with self._lock:
                self._parse_discoveries(tool, stdout)
            self._extract_findings(tool, effective_stdout, stderr, output_file)

        # ====== PHASE 7b: Signal extraction for discovery tools ======
        if category == "discovery":
            # Get tool contract for classification
            from discovery_classification import ToolClass, get_tool_contract

            contract = get_tool_contract(tool)

            # Attempt structured signal parsing
            parse_success = parse_and_extract_signals(tool, stdout, self.cache)

            if not parse_success:
                # Parsing failed - check if acceptable based on classification
                if contract.classification == ToolClass.SIGNAL_PRODUCER:
                    # Signal producer MUST produce signals
                    if not contract.missing_output_acceptable:
                        logger.error(
                            f"[{tool}] SIGNAL_PRODUCER failed to produce signals - BLOCKING"
                        )
                        result["outcome"] = ToolOutcome.BLOCKED_PARSE_FAILED.value
                        result["signal"] = "PARSE_FAILED"
                        self.coverage_analyzer.record_tool_blocked(
                            tool, category, BlockReason.PARSE_FAILED
                        )
                    else:
                        logger.warning(
                            f"[{tool}] SIGNAL_PRODUCER produced no signals (acceptable)"
                        )
                        result["signal"] = "NO_SIGNAL"
                elif contract.classification == ToolClass.INFORMATIONAL_ONLY:
                    # Informational tools don't require signals
                    logger.info(f"[{tool}] INFORMATIONAL_ONLY - signals optional")
                    result["signal"] = "INFORMATIONAL"
                elif contract.classification == ToolClass.EXTERNAL_INTEL:
                    # External intel handled separately
                    logger.info(f"[{tool}] EXTERNAL_INTEL - read-only enrichment")
                    result["signal"] = "EXTERNAL_INTEL"
            else:
                logger.info(f"[{tool}] Signal parsing SUCCESS - signals extracted")

        # ====== PHASE 7c: Record coverage for executed tools ======
        if status == "SUCCESS":
            # Record what was tested
            tested_endpoints = list(self.cache.endpoints)[:10]  # Sample
            tested_params = list(self.cache.params)[:10]  # Sample
            tested_methods = []  # Not tracked at tool level yet
            self.coverage_analyzer.record_tool_executed(
                tool, tested_endpoints, tested_params, tested_methods
            )

        # ====== PHASE 8: Retry logic ======
        if retries and outcome in {ToolOutcome.EXECUTION_ERROR, ToolOutcome.TIMEOUT}:
            with self._lock:
                if self.execution_results:
                    self.execution_results.pop()
            for attempt in range(1, retries + 1):
                self.log(
                    f"{tool} retry {attempt}/{retries} after {outcome.value}", "WARN"
                )
                result = self._run_tool({**plan_item, "retries": 0}, index, total)
                outcome = ToolOutcome(result["outcome"])
                if outcome not in {ToolOutcome.EXECUTION_ERROR, ToolOutcome.TIMEOUT}:
                    return result
            return result

        return result

    def _classify_execution_outcome(
        self, tool: str, rc: int, signal: str, failure_reason: str | None
    ) -> tuple[ToolOutcome, str]:
        """Classify execution result into outcome type using signal + failure_reason."""
        # Accept rc=0 and rc=141 (SIGPIPE - nikto closes pipe after printing results)
        if rc == 0:
            if signal == "POSITIVE":
                return ToolOutcome.SUCCESS_WITH_FINDINGS, "SUCCESS"
            if signal == "NEGATIVE_SIGNAL":
                return ToolOutcome.SUCCESS_NO_FINDINGS, "SUCCESS"
            return ToolOutcome.EXECUTED_NO_SIGNAL, "SUCCESS"
        if rc == 141 and tool == "nikto":
            if signal == "POSITIVE":
                return ToolOutcome.SUCCESS_WITH_FINDINGS, "PARTIAL"
            if signal == "NEGATIVE_SIGNAL":
                return ToolOutcome.SUCCESS_NO_FINDINGS, "PARTIAL"
            return ToolOutcome.EXECUTED_NO_SIGNAL, "PARTIAL"
        if rc == 124:
            return ToolOutcome.TIMEOUT, "FAILED"
        if failure_reason in {
            "tool_not_installed",
            "permission_denied",
            "interactive_prompt_detected",
        }:
            return ToolOutcome.BLOCKED, "BLOCKED"
        if failure_reason == "target_unreachable":
            return ToolOutcome.EXECUTION_ERROR, "FAILED"
        return ToolOutcome.EXECUTION_ERROR, "FAILED"

    def _execute_tool_subprocess(
        self, command: str, timeout: int
    ) -> tuple[int, str, str]:
        """Execute tool as subprocess. Returns (return_code, stdout, stderr)."""
        try:
            completed = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                input="",
                timeout=timeout,
            )
            rc = completed.returncode
            stdout_raw = (
                completed.stdout if isinstance(completed.stdout, (str, bytes)) else ""
            )
            stderr_raw = (
                completed.stderr if isinstance(completed.stderr, (str, bytes)) else ""
            )
            stdout = (
                stdout_raw.decode(errors="ignore")
                if isinstance(stdout_raw, bytes)
                else stdout_raw or ""
            ).strip()
            stderr = (
                stderr_raw.decode(errors="ignore")
                if isinstance(stderr_raw, bytes)
                else stderr_raw or ""
            ).strip()
            return rc, stdout, stderr
        except subprocess.TimeoutExpired as e:
            rc = 124
            stdout = (
                (
                    e.stdout.decode(errors="ignore")
                    if isinstance(e.stdout, bytes)
                    else e.stdout or ""
                ).strip()
                if hasattr(e, "stdout")
                else ""
            )
            stderr = (
                (
                    e.stderr.decode(errors="ignore")
                    if isinstance(e.stderr, bytes)
                    else e.stderr or ""
                ).strip()
                if hasattr(e, "stderr")
                else ""
            )
            return rc, stdout, stderr

    def _classify_failure_reason(self, rc: int, stderr: str) -> str | None:
        """Map return code and stderr to a stable failure_reason label."""
        stderr_lower = (stderr or "").lower()
        if rc == 124:
            return "timeout"
        interactive_markers = [
            "[y/n]",
            "(y/n)",
            "do you want to continue",
            "press enter to continue",
            "waiting for user input",
            "interactive mode",
        ]
        if any(marker in stderr_lower for marker in interactive_markers):
            return "interactive_prompt_detected"
        if (
            "not found" in stderr_lower
            or "command not found" in stderr_lower
            or rc == 127
        ):
            return "tool_not_installed"
        if "permission denied" in stderr_lower:
            return "permission_denied"
        if any(
            msg in stderr_lower
            for msg in [
                "connection refused",
                "no route to host",
                "name or service not known",
                "temporary failure in name resolution",
                "failed to connect",
                "connection timed out",
                "unable to resolve",
                "could not resolve",
            ]
        ):
            return "target_unreachable"
        if rc != 0:
            return "unknown_error"
        return None

    def _build_context(self) -> dict:
        """Aggregate capabilities from profile + cache + error semantics.

        HTTPS is set via explicit probe; do not overwrite silently later.
        """
        ctx = {
            "web_target": bool(self.profile.is_web_target),
            "https": self.profile.is_https,
            "reachable": True,
            "ports_known": len(self.cache.discovered_ports) > 0,
            "endpoints_known": self.cache.has_endpoints(),
            "live_endpoints": self.cache.has_live_endpoints(),
            "params_known": self.cache.has_params(),
            "reflections": self.cache.has_reflections(),
            "command_params": self.cache.has_command_params(),
            "tech_stack_detected": bool(
                getattr(self.profile, "detected_cms", None)
                or getattr(self.profile, "detected_tech", {})
            ),
        }
        # Downgrade reachability if repeated network failures
        if self.error_counters["network_failures"] >= 2:
            ctx["reachable"] = False
        return ctx

    def _should_run(self, tool: str, plan_item: dict) -> tuple[DecisionOutcome, str]:
        """Central decision layer controlling execution.

        Rules:
        - BLOCKED: missing required prerequisite capabilities (technical blocker)
        - SKIPPED: cost/budget exceeds remaining or produces nothing new (efficiency)
        - ALLOW: all checks pass (proceed with execution)

        Note: DENIED tools are filtered upstream by decision_ledger (policy-level).
        This layer enforces prerequisites and budget.
        """
        # ====== PHASE 3: PAYLOAD READINESS VALIDATION ======
        payload_tools = ["dalfox", "xsstrike", "sqlmap", "commix", "xsser"]
        if tool in payload_tools:
            # Get crawler data for validation
            crawler_data = {
                "endpoints": list(self.cache.endpoints),
                "all_params": list(self.cache.params),
                "reflectable_params": [
                    p for p in self.cache.params if "reflect" in str(p).lower()
                ],
                "injectable_sql_params": [
                    p
                    for p in self.cache.params
                    if "sql" in str(p).lower() or "id" in str(p).lower()
                ],
                "dynamic_params": [p for p in self.cache.params],
                "command_params": [
                    p
                    for p in self.cache.params
                    if "cmd" in str(p).lower() or "exec" in str(p).lower()
                ],
            }

            # Pick first endpoint and param for validation (simplified)
            test_endpoint = (
                crawler_data["endpoints"][0] if crawler_data["endpoints"] else ""
            )
            test_param = (
                crawler_data["all_params"][0] if crawler_data["all_params"] else ""
            )
            test_method = "GET"  # Default

            # Validate execution prerequisites
            can_execute, validation_reason = (
                PayloadExecutionValidator.validate_tool_execution(
                    tool, test_endpoint, test_param, test_method, crawler_data
                )
            )

            if not can_execute:
                self.log(f"[PayloadGate] {tool} BLOCKED: {validation_reason}", "WARN")
                return (
                    DecisionOutcome.BLOCK,
                    f"payload_readiness_failed: {validation_reason}",
                )

        meta = {
            k: plan_item.get(k, set()) for k in ["requires", "optional", "produces"]
        }
        configured_worst_case = int(
            plan_item.get("worst_case", plan_item.get("timeout", 300))
        )
        worst_case = min(configured_worst_case, self.MAX_TOOL_TIMEOUT)
        remaining = max(0.0, self.runtime_deadline - datetime.now().timestamp())
        ctx = self._build_context()

        # Required inputs → BLOCK if missing
        for req in meta["requires"]:
            if not ctx.get(req, False):
                return (DecisionOutcome.BLOCK, f"missing required capability: {req}")

        # Budget rule → SKIP if worst-case exceeds remaining
        if worst_case > remaining:
            return (
                DecisionOutcome.SKIP,
                f"insufficient runtime budget ({remaining:.0f}s < worst-case {worst_case}s)",
            )

        # Expected new signal? If all produces already present, SKIP
        if meta["produces"] and all(ctx.get(cap, False) for cap in meta["produces"]):
            return (
                DecisionOutcome.SKIP,
                "no new signal expected (capabilities already present)",
            )

        # Optional inputs missing → ALLOW but note reduced confidence
        for opt in meta["optional"]:
            if not ctx.get(opt, False):
                return (
                    DecisionOutcome.ALLOW,
                    f"optional capability missing: {opt} (reduced confidence)",
                )

        return (DecisionOutcome.ALLOW, "ready")

    def _classify_signal(self, tool: str, stdout: str, stderr: str, rc: int) -> str:
        """Classify result signal type for planning impact.

        POSITIVE: tool produced actionable output
        NO_SIGNAL: tool ran but produced nothing useful
        NEGATIVE_SIGNAL: tool confirmed absence of something (blocks downstream)
        """
        if not stdout:
            # Tool ran but produced nothing
            return "NO_SIGNAL"

        lower_stdout = stdout.lower()
        negative_markers = [
            "no vulnerabilities found",
            "no vulnerabilities detected",
            "no issues found",
            "no issues detected",
            "0 critical",
            "0 high",
            "no open ports",
            "no targets were successfully tested",
        ]
        if any(marker in lower_stdout for marker in negative_markers):
            return "NEGATIVE_SIGNAL"

        # whatweb: no tech stack found ≠ no web service
        if tool == "whatweb":
            if any(
                tech in stdout.lower()
                for tech in [
                    "apache",
                    "nginx",
                    "iis",
                    "wordpress",
                    "drupal",
                    "php",
                    "java",
                    "python",
                ]
            ):
                return "POSITIVE"
            # whatweb with no recognized tech = NO_SIGNAL, not NEGATIVE
            return "NO_SIGNAL"

        # nmap: no open ports found = NEGATIVE_SIGNAL (confirmed absence)
        if tool == "nmap_quick":
            if " open " in stdout:
                return "POSITIVE"
            return "NEGATIVE_SIGNAL"

        # Scanner tools: require explicit finding indicators to avoid noisy banner false positives.
        finding_keywords = [
            "vulnerable",
            "vulnerability",
            "missing security header",
            "suggested security header missing",
            "exposed",
            "injection",
            "xss",
            "sqli",
            "cve-",
            "critical",
            "high",
            "medium",
        ]
        scanner_tools = {
            "nikto",
            "testssl",
            "sslscan",
            "sqlmap",
            "commix",
            "xsstrike",
            "xsser",
            "dalfox",
            "nuclei_all",
            "nuclei_crit",
            "nuclei_high",
            "nuclei_cves",
            "nuclei_ssl",
            "nuclei",
        }
        if tool in scanner_tools:
            lines = [ln.strip().lower() for ln in stdout.splitlines() if ln.strip()]
            if not lines:
                return "NO_SIGNAL"
            positive_lines = 0
            negative_lines = 0
            for line in lines:
                if any(k in line for k in finding_keywords):
                    if any(
                        neg in line
                        for neg in [
                            "not vulnerable",
                            "no vulnerabilities found",
                            "no issues found",
                            "(ok)",
                        ]
                    ):
                        negative_lines += 1
                    else:
                        positive_lines += 1
            if positive_lines > 0:
                return "POSITIVE"
            if negative_lines > 0:
                return "NEGATIVE_SIGNAL"
            return "NO_SIGNAL"

        # Default: non-empty output is treated as signal for non-scanner discovery/info tools.
        if stdout.strip():
            return "POSITIVE"
        return "NO_SIGNAL"

    def _save_tool_output(
        self,
        tool_name: str,
        command: str,
        stdout: str,
        stderr: str,
        returncode: int,
    ) -> str | None:
        try:
            output_file = self.output_dir / f"{tool_name}.txt"
            with output_file.open("w", encoding="utf-8", newline="") as f:
                f.write(f"Tool: {tool_name}\n")
                f.write(f"Command: {command}\n")
                f.write(f"Target: {self.target}\n")
                f.write(f"Correlation ID: {self.correlation_id}\n")
                f.write(f"Execution Time: {datetime.now().isoformat()}\n")
                f.write(f"Return Code: {returncode}\n")
                f.write(f"{'='*70}\n\n")
                f.write("STDOUT:\n")
                f.write(stdout or "[No output]")
                f.write("\n\nSTDERR:\n")
                f.write(stderr or "[No errors]")
            return str(output_file)
        except Exception as e:  # noqa: BLE001
            self.log(f"Could not save output for {tool_name}: {str(e)}", "ERROR")
            return None

    def _check_https_service(self, host: str, port: int = 443) -> bool:
        """Check HTTPS availability using port hints + TLS handshake with lenient fallback."""
        # Use cached capability if already probed; do not re-infer later.
        if hasattr(self, "_https_capability"):
            return bool(self._https_capability)
        # Fast-path: discovery cache already saw 443 open
        try:
            if port in getattr(self.cache, "discovered_ports", set()):
                return True
        except Exception:
            pass

        # Primary: TLS handshake without requiring HTTP response
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port or 443), timeout=2) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    tls_sock.settimeout(2)
                    tls_sock.do_handshake()
            return True
        except Exception:
            # Fallback: permissive HEAD request (handles servers that reject raw TLS handshake)
            try:
                url = f"https://{host}:{port or 443}"
                req = Request(url, method="HEAD")
                urlopen(req, timeout=3)
                return True
            except Exception:
                return False

    def _with_https_probe(self, profile: TargetProfile) -> TargetProfile:
        """Return profile updated with explicit HTTPS probe result."""
        is_https = profile.is_https or self._check_https_service(
            profile.host, profile.port
        )
        scheme = "https" if is_https else "http"
        port = (
            profile.port if profile.port not in {80, 443} else (443 if is_https else 80)
        )
        # TargetProfile is frozen; use object.__setattr__
        object.__setattr__(profile, "is_https", is_https)
        object.__setattr__(profile, "scheme", scheme)
        object.__setattr__(profile, "port", port)
        self.log(
            f"HTTPS probe {'passed' if is_https else 'failed'} -> scheme={scheme}, port={port}"
        )
        return profile

    def _filter_actionable_stdout(self, tool: str, stdout: str) -> str:
        """Filter noisy tool output down to actionable signal."""
        if not stdout:
            return ""

        lines = [ln.strip() for ln in stdout.split("\n") if ln.strip()]

        if tool in {"sslscan", "testssl"}:
            # Keep ONLY findings that matter: protocols, ciphers, certs
            actionable = []
            for ln in lines:
                lower = ln.lower()
                # Protocol versions (keep only if vulnerable/weak)
                if any(
                    k in lower
                    for k in [
                        "sslv2",
                        "sslv3",
                        "tls1.0",
                        "tls 1.0",
                        "poodle",
                        "crime",
                        "heartbleed",
                    ]
                ):
                    actionable.append(ln)
                # Weak ciphers (NULL, RC4, anon, export)
                elif any(
                    k in lower
                    for k in ["null cipher", "rc4", "anonymous", "export", "weak"]
                ):
                    actionable.append(ln)
                # Certificate issues
                elif any(
                    k in lower
                    for k in [
                        "expired",
                        "self-signed",
                        "untrusted",
                        "revoked",
                        "not valid",
                    ]
                ):
                    actionable.append(ln)
                # Key exchange issues
                elif any(k in lower for k in ["insecure renegotiation", "downgrade"]):
                    actionable.append(ln)
            return "\n".join(actionable)

        if tool == "whatweb":
            # Keep only framework/CMS/significant tech detections
            actionable = []
            for ln in lines:
                # Skip headers and trivial output
                if any(
                    k in ln.lower()
                    for k in [
                        "apache",
                        "nginx",
                        "iis",
                        "wordpress",
                        "drupal",
                        "joomla",
                        "magento",
                        "java",
                        "python",
                        "ruby",
                        "rails",
                        "django",
                        "asp",
                        ".net",
                        "php",
                    ]
                ):
                    actionable.append(ln)
            # whatweb success (even with empty actionable) should not block downstream tools
            return "\n".join(actionable)

        # Default: keep stdout as-is
        return stdout

    def _parse_discoveries(self, tool: str, stdout: str) -> None:
        """NEW: Parse tool output into discovery cache for gating later tools."""
        if tool == "nmap_quick" and stdout:
            # Parse nmap output for discovered ports
            import re

            port_pattern = r"(\d+)/tcp\s+open\s+(\S+)"
            ports = []
            for match in re.finditer(port_pattern, stdout):
                port, service = match.groups()
                ports.append((port, service))
                # Store typed port object in cache (single source of truth)
                try:
                    self.cache.add_port(int(port))
                except Exception:
                    pass
            # Count ports for gating
            if ports:
                self.log(f"Discovered {len(ports)} open ports via nmap", "INFO")

        elif tool == "gobuster" and stdout:
            # Parse gobuster output: Status:200, /admin, /api, etc.
            for line in stdout.split("\n"):
                if "200" in line:
                    parts = line.split()
                    candidates = [
                        p for p in parts if p.startswith("/") or p.startswith("http")
                    ]
                    if not candidates and parts:
                        candidates = [parts[0]]
                    for path in candidates:
                        norm_path, _ = self.cache._normalize_endpoint(path)
                        if norm_path:
                            self._register_endpoint(
                                norm_path, source=tool, confidence=0.7, is_live=True
                            )
                            self.cache.live_endpoints.add(norm_path)
                elif "301" in line:
                    parts = line.split()
                    if parts:
                        self._register_endpoint(parts[0], source=tool, confidence=0.65)

        elif tool == "dirsearch" and stdout:
            # Parse dirsearch output
            for line in stdout.split("\n"):
                if "[200]" in line:
                    # Extract path from [200] /admin format
                    if "/" in line:
                        parts = line.split()
                        for part in parts:
                            if part.startswith("/"):
                                norm_path, _ = self.cache._normalize_endpoint(part)
                                self._register_endpoint(
                                    norm_path, source=tool, confidence=0.7, is_live=True
                                )
                                self.cache.live_endpoints.add(
                                    norm_path
                                )  # HTTP 200 only
                elif "[" in line and "]" in line:
                    # Other status codes
                    if "/" in line:
                        parts = line.split()
                        for part in parts:
                            if part.startswith("/"):
                                self._register_endpoint(
                                    part, source=tool, confidence=0.6
                                )

        elif tool in ("findomain", "sublist3r", "assetfinder") and stdout:
            # Parse subdomain enumeration
            discovered = []
            for line in stdout.split("\n"):
                if line.strip():
                    discovered.append(line.strip())

            # Verify subdomains are live (A/AAAA only, no wildcards)
            verified = self.cache.verify_subdomains(discovered)
            for subdomain in verified:
                self.cache.add_subdomain(subdomain)

        elif tool == "whatweb" and stdout:
            # Parse whatweb for framework/CMS detection
            lower = stdout.lower()
            if "wordpress" in lower or "wp-" in lower:
                self.profile.detected_cms = "wordpress"
            elif "drupal" in lower:
                self.profile.detected_cms = "drupal"
            elif "joomla" in lower:
                self.profile.detected_cms = "joomla"

            # Extract tech hints
            if "php" in lower:
                self.cache.add_param("detected_php")
            if "java" in lower or "tomcat" in lower or "jboss" in lower:
                self.cache.add_param("detected_java")
            if "?" in stdout:
                # Likely has parameters
                self.cache.add_param("detected_by_whatweb")

        elif tool == "dalfox" and stdout:
            # Dalfox finds reflected parameters
            if "Reflected" in stdout or "reflected" in stdout:
                self.cache.add_reflection("xss_candidate")

        elif tool.startswith("nuclei") and stdout:
            # All Nuclei variants find endpoints/issues
            for line in stdout.split("\n"):
                if line.strip() and "[" in line:
                    tokens = line.split()
                    for tok in tokens:
                        if tok.startswith("http") or tok.startswith("/"):
                            self._register_endpoint(tok, source=tool, confidence=0.7)

        self._synchronize_inventory_from_cache()

    def _prefill_param_hints(self) -> None:
        """Seed discovery cache from the original target (path + query params)."""
        parsed = urlparse(self.profile.url)
        if parsed.path:
            self._register_endpoint(parsed.path, source="seed", confidence=0.8)
        for name in parse_qs(parsed.query).keys():
            self._register_param(name, source="query", endpoint=parsed.path or "/")
        if self.cache.has_params():
            self.cache.add_reflection("seed:query_param_present")

    def _cheap_reflection_probe(self) -> None:
        """Cheap single-request reflection probe to gate XSS tools."""
        try:
            token = f"copilot_reflect_{self.correlation_id}"
            parsed = urlparse(self.profile.url)
            sep = "&" if parsed.query else "?"
            probe_url = f"{self.profile.url}{sep}__refcheck__={token}"
            req = Request(probe_url, headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(req, timeout=5) as resp:
                body = resp.read(2048).decode(errors="ignore")
                if token in body:
                    self.cache.add_reflection("probe:reflected")
                location = resp.getheader("Location")
                if location and token in location:
                    self.cache.add_reflection("probe:reflected")
        except Exception:
            # Probe failure should not break scan
            return

    def _run_cheap_probes(self) -> None:
        """Run inexpensive heuristics to enable signal-based gating early."""
        self._cheap_reflection_probe()

    def _ensure_required_tools(self) -> None:
        """Auto-install required tools when possible (non-interactive)."""
        if not self.tool_manager:
            return

        allowed_tools = set(self.ledger.get_allowed_tools())
        for tool in allowed_tools:
            try:
                # Check if tool is installed (this handles aliases automatically)
                if self.tool_manager.check_tool_installed(tool):
                    continue

                # Try to get install command
                install_cmd = self.tool_manager.get_install_command(tool)

                # If no install command, check if it's a pseudo-tool (alias)
                if not install_cmd:
                    # Check if this is an alias for a tool that's already installed
                    canonical_tool = self.tool_manager.tool_aliases.get(tool)
                    if canonical_tool and self.tool_manager.check_tool_installed(
                        canonical_tool
                    ):
                        # Pseudo-tool satisfied by canonical tool, skip silently
                        continue
                    # Otherwise, warn about missing tool
                    self.log(f"Missing tool {tool} (no installer available)", "WARN")
                    continue

                # Attempt installation
                self.log(f"Auto-installing missing tool: {tool}", "INFO")
                install_result = subprocess.run(
                    install_cmd, shell=True, capture_output=True, text=True
                )
                if install_result.returncode != 0:
                    self.log(
                        f"Failed to install {tool}: {install_result.stderr.strip()}",
                        "WARN",
                    )
            except Exception as e:  # noqa: BLE001
                self.log(f"Tool install check failed for {tool}: {e}", "WARN")

    def _build_full_url(self, path: str) -> str:
        """Convert a cached path into an absolute URL for tooling."""
        if path.startswith("http"):
            return path
        prefix = f"{self.profile.scheme}://{self.profile.host}"
        return f"{prefix}{path if path.startswith('/') else '/' + path}"

    def _is_actionable_nuclei_target(self, url: str) -> bool:
        """Return True for likely actionable web endpoints, False for static assets."""
        static_ext = {
            ".css",
            ".js",
            ".mjs",
            ".map",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".webp",
            ".svg",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".otf",
            ".mp4",
            ".mp3",
            ".pdf",
            ".zip",
            ".gz",
            ".tgz",
            ".rar",
            ".7z",
        }
        path = urlparse(url).path.lower()

        # Allow obvious dynamic/scripted endpoints even when file extensions are used
        dynamic_ext = {".php", ".asp", ".aspx", ".jsp", ".jspx", ".cgi"}
        for ext in dynamic_ext:
            if path.endswith(ext):
                return True

        for ext in static_ext:
            if path.endswith(ext):
                return False

        return True

    def _materialize_targets(
        self,
        tool: str,
        require_params: bool = False,
        require_command_params: bool = False,
    ) -> list[str]:
        """Materialize full URLs for a tool from discoveries.

        Optionally require parameters (used for injection tooling) to avoid noise.
        Optionally require command-like params for RCE tools.
        Returns normalized, deduplicated endpoints only.
        """
        if require_params and not self.cache.has_params():
            return []
        if require_command_params and not self.cache.has_command_params():
            return []

        # Use normalized endpoints
        if tool in ["commix", "sqlmap", "dalfox"]:
            endpoints = self.cache.get_live_normalized_endpoints()
        else:
            endpoints = self.cache.get_normalized_endpoints()

        if not endpoints:
            parsed = urlparse(self.profile.url)
            endpoints = [parsed.path or "/"]

        urls = {self._build_full_url(ep) for ep in endpoints if ep}
        materialized = sorted(urls)

        # Nuclei should focus on actionable endpoints, not static assets.
        if tool == "nuclei":
            filtered = [u for u in materialized if self._is_actionable_nuclei_target(u)]
            return filtered or [self.profile.url]

        # Payload tools are materially better when URLs include query parameters.
        if tool in {"sqlmap", "dalfox", "commix", "ssrfmap"}:
            seeded_params = self._extract_candidate_param_names(limit=10)
            if seeded_params:
                materialized = sorted(
                    {
                        self._augment_url_with_params(url, seeded_params, max_params=3)
                        for url in materialized
                    }
                )

        return materialized

    def _extract_candidate_param_names(self, limit: int = 8) -> list[str]:
        """Collect likely testable parameter names from cache and parameter inventory."""
        candidates: list[str] = []
        seen: set[str] = set()

        for param in sorted(self.cache.params):
            p = str(param).strip()
            if not p or p in seen or not self._is_testable_param_name(p):
                continue
            seen.add(p)
            candidates.append(p)
            if len(candidates) >= limit:
                return candidates

        for row in self.param_inventory.values():
            p = str(row.get("name", "")).strip()
            if not p or p in seen or not self._is_testable_param_name(p):
                continue
            seen.add(p)
            candidates.append(p)
            if len(candidates) >= limit:
                break
        return candidates

    def _augment_url_with_params(
        self, url: str, param_names: list[str], max_params: int = 3
    ) -> str:
        """Ensure URL carries minimal query parameters for injection-oriented tools."""
        parsed = urlparse(url)
        existing = parse_qs(parsed.query or "", keep_blank_values=True)
        if existing:
            return url

        query_pairs: list[tuple[str, str]] = []
        for name in param_names[:max_params]:
            query_pairs.append((name, "1"))
        if not query_pairs:
            return url

        q = urlencode(query_pairs)
        separator = "&" if "?" in url else "?"
        return f"{url}{separator}{q}"

    def _materialize_ssl_targets(self) -> list[str]:
        """Return host:port targets for SSL template scans to reduce path-level noise."""
        host = self.profile.host
        candidate_ports: set[int] = {443}

        for p in self.cache.discovered_ports:
            try:
                port = int(p)
            except Exception:
                continue
            if port in {443, 8443, 9443, 10443, 4443}:
                candidate_ports.add(port)

        for assessment in self.certificate_assessments or []:
            try:
                port = int(assessment.get("port", 0) or 0)
            except Exception:
                port = 0
            if port:
                candidate_ports.add(port)

        return [f"{host}:{p}" for p in sorted(candidate_ports)]

    def _scope_command(self, tool_name: str, command: str) -> str:
        """Rewrite commands to respect scoped endpoints and discovery signals."""
        if tool_name.startswith("nuclei"):
            targets = self._materialize_targets("nuclei")
            if not targets:
                return command

            # Handle different nuclei variants
            if tool_name == "nuclei_crit":
                severity = "critical"
                if len(targets) == 1:
                    return f"nuclei -u {targets[0]} -severity {severity} -silent -update-templates"
                list_file = self.output_dir / f"{tool_name}_targets.txt"
                list_file.write_text("\n".join(targets), encoding="utf-8")
                return f"nuclei -list {list_file} -severity {severity} -silent -update-templates"

            elif tool_name == "nuclei_high":
                severity = "high"
                if len(targets) == 1:
                    return f"nuclei -u {targets[0]} -severity {severity} -silent -update-templates"
                list_file = self.output_dir / f"{tool_name}_targets.txt"
                list_file.write_text("\n".join(targets), encoding="utf-8")
                return f"nuclei -list {list_file} -severity {severity} -silent -update-templates"

            elif tool_name == "nuclei_all":
                # Run all templates without severity filtering
                if len(targets) == 1:
                    return f"nuclei -target {targets[0]} -silent -update-templates"
                list_file = self.output_dir / f"{tool_name}_targets.txt"
                list_file.write_text("\n".join(targets), encoding="utf-8")
                return f"nuclei -list {list_file} -silent -update-templates"

            elif tool_name == "nuclei_cves":
                # Run with CVE templates
                if len(targets) == 1:
                    return f"nuclei -target {targets[0]} -t http/cves/ -silent -update-templates"
                list_file = self.output_dir / f"{tool_name}_targets.txt"
                list_file.write_text("\n".join(targets), encoding="utf-8")
                return (
                    f"nuclei -list {list_file} -t http/cves/ -silent -update-templates"
                )

            elif tool_name == "nuclei_ssl":
                # SSL templates should receive host:port targets rather than URL paths.
                ssl_targets = self._materialize_ssl_targets()
                if len(ssl_targets) == 1:
                    return f"nuclei -target {ssl_targets[0]} -t ssl -silent -update-templates"
                list_file = self.output_dir / f"{tool_name}_targets.txt"
                list_file.write_text("\n".join(ssl_targets), encoding="utf-8")
                return f"nuclei -list {list_file} -t ssl -silent -update-templates"

        if tool_name == "sqlmap":
            targets = self._materialize_targets(tool_name, require_params=False)
            if not targets:
                return f'sqlmap -u {self.profile.url} --batch --crawl=1 --risk=1 --level=1 --smart --random-agent --answers="follow=N,quit=N"'
            if len(targets) == 1:
                return f'sqlmap -u {targets[0]} --batch --crawl=1 --risk=1 --level=1 --smart --random-agent --answers="follow=N,quit=N"'
            list_file = self.output_dir / "sqlmap_targets.txt"
            list_file.write_text("\n".join(targets), encoding="utf-8")
            return f'sqlmap -m {list_file} --batch --crawl=1 --risk=1 --level=1 --smart --random-agent --answers="follow=N,quit=N"'

        if tool_name == "commix":
            targets = self._materialize_targets(
                tool_name, require_params=True, require_command_params=True
            )
            if not targets:
                return command
            if len(targets) == 1:
                return f"commix -u {targets[0]} --batch --ignore-stdin"
            list_file = self.output_dir / "commix_targets.txt"
            list_file.write_text("\n".join(targets), encoding="utf-8")
            return f"commix -m {list_file} --batch --ignore-stdin"

        if tool_name == "dalfox":
            targets = self._materialize_targets(tool_name)
            if not targets:
                return f"dalfox url {self.profile.url} --silence --no-color"
            if len(targets) == 1:
                return f"dalfox url {targets[0]} --silence --no-color"
            list_file = self.output_dir / "dalfox_targets.txt"
            list_file.write_text("\n".join(targets), encoding="utf-8")
            return f"dalfox file {list_file} --silence --no-color"

        if tool_name == "xsstrike":
            target = self.profile.url
            targets = self._materialize_targets(tool_name)
            if targets:
                target = targets[0]
            return f"python3 /usr/share/xsstrike/xsstrike.py -u {target}"

        if tool_name == "ssrfmap":
            targets = self._materialize_targets(tool_name, require_params=True)
            if not targets or not self.cache.has_ssrf_params():
                return command
            if len(targets) == 1:
                return f"ssrfmap -u {targets[0]} --crawl=0"
            list_file = self.output_dir / "ssrf_targets.txt"
            list_file.write_text("\n".join(targets), encoding="utf-8")
            return f"ssrfmap -m {list_file} --crawl=0"

        return command

    def _build_payload_commands_from_graph(self, tool_name: str) -> list[dict]:
        """Use payload_command_builder to generate scoped payload commands."""
        if not self.payload_command_builder or not self.endpoint_graph:
            return []

        if tool_name == "dalfox":
            return self.payload_command_builder.build_dalfox_commands(self.profile.url)
        if tool_name == "sqlmap":
            return self.payload_command_builder.build_sqlmap_commands(self.profile.url)
        if tool_name == "commix":
            return self.payload_command_builder.build_commix_commands(self.profile.url)

        return []

    def _manual_command_for_tool(self, tool_name: str, target_url: str) -> str | None:
        """Build best-effort manual command for out-of-scope reruns."""
        host = self.profile.host
        base_domain = self.profile.base_domain or host

        templates = {
            "whatweb": f"whatweb -v {target_url}",
            "whatweb_http_fallback": f"whatweb -v {target_url.replace('https://', 'http://')}",
            "nikto": f"nikto -h {target_url} -C all",
            "gobuster": f"gobuster dir -u {target_url} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt --status-codes-blacklist 403 -k",
            "dirsearch": f"dirsearch -u {target_url} -e php,asp,aspx,jsp,js,txt,html -t 20 --random-agent --quiet-mode",
            "nuclei_crit": f"nuclei -u {target_url} -severity critical -silent",
            "nuclei_high": f"nuclei -u {target_url} -severity high -silent",
            "nuclei_all": f"nuclei -u {target_url} -silent",
            "nuclei_cves": f"nuclei -u {target_url} -t http/cves/ -silent",
            "nuclei_ssl": f"nuclei -target {self.profile.host}:443 -t ssl -silent",
            "dalfox": f"dalfox url {target_url} --silence --no-color",
            "sqlmap": f'sqlmap -u {target_url} --batch --crawl=1 --smart --random-agent --answers="follow=N,quit=N"',
            "commix": f"commix -u {target_url} --batch --ignore-stdin",
            "xsstrike": f"python3 /usr/share/xsstrike/xsstrike.py -u {target_url}",
            "xsser": f"xsser --url {target_url}",
            "arjun": f"arjun -u {target_url} --passive",
            "ping": f"ping -c 2 {host}",
            "nmap_quick": f"nmap -F {host}",
            "nmap_vuln": f"nmap -sV --script vuln --script-timeout 120s {host}",
            "sslscan": f"sslscan {host}",
            "testssl": f"testssl.sh --quiet -U {target_url}",
            "openssl_connect": f"openssl s_client -connect {host}:443 -servername {host} </dev/null",
            "openssl_showcerts": f"openssl s_client -connect {host}:443 -servername {host} -showcerts </dev/null",
            "openssl_status": f"openssl s_client -connect {host}:443 -servername {host} -status </dev/null",
            "openssl_state": f"openssl s_client -connect {host}:443 -servername {host} -state </dev/null",
            "findomain": f"findomain -t {base_domain} -q",
            "sublist3r": f"sublist3r -d {base_domain}",
            "assetfinder": f"assetfinder --subs-only {base_domain}",
            "dnsrecon": f"dnsrecon -d {base_domain}",
            "wpscan": f"wpscan --url {target_url} --enumerate vp,vt,u --disable-tls-checks",
        }
        return templates.get(tool_name)

    def _is_exploit_tool(self, tool_name: str) -> bool:
        return tool_name in {"sqlmap", "xsstrike", "dalfox", "commix", "xsser", "arjun"}

    def _should_skip_manual_exploit_for_target(
        self, tool_name: str, target_url: str
    ) -> tuple[bool, str]:
        """Skip exploit tooling when target characteristics make execution non-actionable."""
        if not self._is_exploit_tool(tool_name):
            return False, ""

        has_params = self.cache.has_params()
        has_reflections = self.cache.has_reflections()
        lower_url = target_url.lower()

        if not has_params and tool_name in {"sqlmap", "commix", "arjun"}:
            return True, "NOT_APPLICABLE:no parameters detected"
        if not has_reflections and tool_name in {"dalfox", "xsstrike", "xsser"}:
            return True, "NOT_APPLICABLE:no reflectable parameters"
        if "wp-content/plugins/" in lower_url and "?" not in lower_url:
            return True, "NOT_APPLICABLE:static asset endpoint"

        return False, ""

    def _classify_manual_failure(
        self, rc: int, stdout: str, stderr: str, failure_reason: str | None
    ) -> str:
        """Classify manual sweep failures into actionable buckets."""
        text = f"{stdout}\n{stderr}".lower()

        if (
            failure_reason in {"tool_not_installed", "permission_denied"}
            or "no such file or directory" in text
            or "can't open file" in text
        ):
            return "ENV_ERROR"
        if "403" in text or "waf" in text or "ips" in text or "forbidden" in text:
            return "TARGET_BLOCKED"
        if (
            "no usable links found" in text
            or "no parameters" in text
            or "no reflectable" in text
            or "not applicable" in text
        ):
            return "NOT_APPLICABLE"
        if rc == 0 and ("[no output]" in text or "no issues found" in text):
            return "NOT_APPLICABLE"
        return "EXECUTION_ERROR"

    def _execute_manual_tool_command(
        self, tool_name: str, command: str, target_url: str
    ) -> dict:
        """Execute one manual out-of-scope command and record findings/discoveries."""
        started = datetime.now()
        rc, stdout, stderr = self._execute_tool_subprocess(command, timeout=180)
        signal = self._classify_signal(tool_name, stdout, stderr, rc)
        failure_reason = self._classify_failure_reason(rc, stderr)
        outcome, status = self._classify_execution_outcome(
            tool_name, rc, signal, failure_reason
        )
        failure_class = self._classify_manual_failure(
            rc, stdout, stderr, failure_reason
        )
        output_file = self._save_tool_output(
            f"manual_{tool_name}", command, stdout, stderr, rc
        )

        # Reuse existing parsers for enrichment.
        try:
            self._parse_discoveries(tool_name, stdout)
        except Exception:
            pass
        try:
            self._extract_findings(
                tool_name, stdout, stderr, str(output_file) if output_file else None
            )
        except Exception:
            pass

        result = {
            "index": 0,
            "total": 0,
            "tool": tool_name,
            "category": "ManualOutOfScope",
            "status": status,
            "outcome": outcome.value,
            "reason": f"manual rerun against {target_url}",
            "return_code": rc,
            "timed_out": rc == 124,
            "failure_reason": failure_reason or "",
            "started_at": started.isoformat(),
            "finished_at": datetime.now().isoformat(),
            "stderr_preview": (stderr or "")[:500],
            "stderr_length": len(stderr or ""),
            "stderr_truncated": len(stderr or "") > 500,
            "signal": signal,
            "manual": True,
            "target_url": target_url,
            "failure_class": failure_class,
        }
        if output_file:
            result["output_file"] = str(output_file)
        self.execution_results.append(result)
        return result

    def _run_manual_out_of_scope_sweep(self) -> None:
        """Run denied/skipped/blocked tools manually against all discovered pages/API endpoints."""
        denied_tools = set(self.ledger.get_denied_tools())
        skipped_or_blocked = {
            r.get("tool")
            for r in self.execution_results
            if r.get("status") in {"SKIPPED", "BLOCKED"}
        }
        candidate_tools = sorted(t for t in (denied_tools | skipped_or_blocked) if t)

        discovery_lists = self._build_discovery_detail_lists()
        endpoint_urls = [
            self._build_full_url(ep) for ep in discovery_lists.get("endpoints_list", [])
        ]
        # Keep manual sweep focused on actionable pages/APIs, not static assets.
        static_exts = {
            ".js",
            ".css",
            ".map",
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".svg",
            ".webp",
            ".avif",
            ".ico",
            ".woff",
            ".woff2",
            ".ttf",
            ".eot",
            ".mp4",
            ".mp3",
            ".pdf",
            ".zip",
        }
        raw_targets = sorted(set(endpoint_urls + [self.profile.url]))
        targets = []
        for target in raw_targets:
            parsed = urlparse(target)
            path = (parsed.path or "").lower()
            if any(path.endswith(ext) for ext in static_exts):
                continue
            targets.append(target)

        # Cap target fanout so manual sweep remains practical and deterministic.
        if len(targets) > 120:
            targets = targets[:120]

        self.manual_out_of_scope_report.update(
            {
                "attempted": True,
                "candidate_tools": candidate_tools,
                "targets": targets,
            }
        )

        if not candidate_tools or not targets:
            self.log("Manual out-of-scope sweep: nothing to run", "INFO")
            return

        host_level_tools = {
            "ping",
            "nmap_quick",
            "nmap_vuln",
            "sslscan",
            "testssl",
            "openssl_connect",
            "openssl_showcerts",
            "openssl_status",
            "openssl_state",
            "findomain",
            "sublist3r",
            "assetfinder",
            "dnsrecon",
            # Site-level scanners should run once per host, not per endpoint.
            "gobuster",
            "wpscan",
        }

        estimated_total_runs = 0
        for tool_name in candidate_tools:
            estimated_total_runs += 1 if tool_name in host_level_tools else len(targets)

        self.log(
            "Manual out-of-scope sweep started: "
            f"tools={len(candidate_tools)}, targets={len(targets)}, "
            f"estimated_runs={estimated_total_runs}",
            "INFO",
        )

        # Try to install missing tools for manual sweep.
        if self.tool_manager:
            for tool_name in candidate_tools:
                try:
                    if self.tool_manager.check_tool_installed(tool_name):
                        continue
                    install_cmd = self.tool_manager.get_install_command(tool_name)
                    if not install_cmd:
                        self.manual_out_of_scope_report[
                            "missing_or_unavailable"
                        ].append(
                            {
                                "tool": tool_name,
                                "reason": "no install command available",
                            }
                        )
                        continue
                    rc = subprocess.run(
                        install_cmd, shell=True, capture_output=True, text=True
                    ).returncode
                    if rc != 0:
                        self.manual_out_of_scope_report[
                            "missing_or_unavailable"
                        ].append(
                            {
                                "tool": tool_name,
                                "reason": "install failed",
                            }
                        )
                except Exception as e:  # noqa: BLE001
                    self.manual_out_of_scope_report["missing_or_unavailable"].append(
                        {
                            "tool": tool_name,
                            "reason": f"install exception: {e}",
                        }
                    )

        progress_index = 0
        total_tools = len(candidate_tools)
        tool_failure_rates = {}  # Track failure rates per tool for early exit

        for tool_idx, tool_name in enumerate(candidate_tools, start=1):
            # Host-level tools only need one run.
            host_level = tool_name in host_level_tools
            loop_targets = [self.profile.url] if host_level else targets

            # Initialize failure tracking for this tool
            tool_failure_rates[tool_name] = {"attempts": 0, "failures": 0}

            self.log(
                f"[ManualSweep][Tool {tool_idx}/{total_tools}] {tool_name}: "
                f"{len(loop_targets)} target(s)",
                "INFO",
            )

            for target_idx, target_url in enumerate(loop_targets, start=1):
                progress_index += 1
                tool_failure_rates[tool_name]["attempts"] += 1

                # Early exit: if this tool is failing >80% of the time, skip it
                attempts = tool_failure_rates[tool_name]["attempts"]
                failures = tool_failure_rates[tool_name]["failures"]
                if attempts >= 5 and (failures / attempts) > 0.80:
                    self.log(
                        f"[ManualSweep] {tool_name}: {failures}/{attempts} failures (>80%) - SKIPPING remaining {len(loop_targets) - target_idx} targets",
                        "WARN",
                    )
                    for remaining_target in loop_targets[target_idx:]:
                        self.manual_out_of_scope_report[
                            "non_actionable_failures"
                        ].append(
                            {
                                "tool": tool_name,
                                "target": remaining_target,
                                "reason": "tool_consistently_failing_auto_skip",
                            }
                        )
                        self.manual_out_of_scope_report["classified_failures"][
                            "NOT_APPLICABLE"
                        ] += 1
                    break

                self.log(
                    f"[ManualSweep][{progress_index}/{estimated_total_runs}] "
                    f"{tool_name} -> {target_url} "
                    f"(target {target_idx}/{len(loop_targets)})",
                    "INFO",
                )
                should_skip, skip_reason = self._should_skip_manual_exploit_for_target(
                    tool_name, target_url
                )
                if should_skip:
                    self.log(
                        f"[ManualSweep][{progress_index}/{estimated_total_runs}] "
                        f"SKIPPED {tool_name} on {target_url}: {skip_reason}",
                        "WARN",
                    )
                    self.manual_out_of_scope_report["non_actionable_failures"].append(
                        {
                            "tool": tool_name,
                            "target": target_url,
                            "reason": skip_reason,
                        }
                    )
                    self.manual_out_of_scope_report["classified_failures"][
                        "NOT_APPLICABLE"
                    ] += 1
                    continue

                command = self._manual_command_for_tool(tool_name, target_url)
                if not command:
                    self.log(
                        f"[ManualSweep][{progress_index}/{estimated_total_runs}] "
                        f"UNAVAILABLE command template for {tool_name}",
                        "WARN",
                    )
                    self.manual_out_of_scope_report["missing_or_unavailable"].append(
                        {
                            "tool": tool_name,
                            "reason": "no command template",
                        }
                    )
                    break
                result = self._execute_manual_tool_command(
                    tool_name, command, target_url
                )
                self.log(
                    f"[ManualSweep][{progress_index}/{estimated_total_runs}] "
                    f"{tool_name} outcome={result.get('outcome')} rc={result.get('return_code')}",
                    "INFO",
                )
                if result.get("status") in {"SUCCESS", "PARTIAL"}:
                    self.manual_out_of_scope_report["executed"].append(
                        {
                            "tool": tool_name,
                            "target": target_url,
                            "outcome": result.get("outcome"),
                        }
                    )
                else:
                    # Track this as a failure for early-exit logic
                    tool_failure_rates[tool_name]["failures"] += 1

                    failure_class = result.get("failure_class", "EXECUTION_ERROR")
                    self.manual_out_of_scope_report["classified_failures"][
                        failure_class
                    ] = (
                        self.manual_out_of_scope_report["classified_failures"].get(
                            failure_class, 0
                        )
                        + 1
                    )
                    failure_payload = {
                        "tool": tool_name,
                        "target": target_url,
                        "reason": result.get("failure_reason") or result.get("reason"),
                        "class": failure_class,
                    }
                    if failure_class in {"NOT_APPLICABLE", "TARGET_BLOCKED"}:
                        self.manual_out_of_scope_report[
                            "non_actionable_failures"
                        ].append(failure_payload)
                    else:
                        self.manual_out_of_scope_report["failed"].append(
                            failure_payload
                        )

        self.log(
            "Manual out-of-scope sweep complete: "
            f"executed={len(self.manual_out_of_scope_report.get('executed', []))}, "
            f"failed={len(self.manual_out_of_scope_report.get('failed', []))}, "
            f"non_actionable={len(self.manual_out_of_scope_report.get('non_actionable_failures', []))}",
            "INFO",
        )
        self._finalize_manual_out_of_scope_report()

    def _finalize_manual_out_of_scope_report(self) -> None:
        """Deduplicate manual sweep records and build stable per-tool summaries."""
        report = self.manual_out_of_scope_report

        def _dedupe(rows: list[dict], keys: tuple[str, ...]) -> list[dict]:
            seen: set[tuple[str, ...]] = set()
            out: list[dict] = []
            for row in rows or []:
                sig = tuple(str(row.get(k, "")) for k in keys)
                if sig in seen:
                    continue
                seen.add(sig)
                out.append(row)
            return out

        report["executed"] = _dedupe(
            report.get("executed", []), ("tool", "target", "outcome")
        )
        report["failed"] = _dedupe(
            report.get("failed", []), ("tool", "target", "reason", "class")
        )
        report["non_actionable_failures"] = _dedupe(
            report.get("non_actionable_failures", []),
            ("tool", "target", "reason", "class"),
        )
        report["missing_or_unavailable"] = _dedupe(
            report.get("missing_or_unavailable", []), ("tool", "reason")
        )

        by_tool: dict[str, dict[str, int]] = {}

        def _inc(tool: str, field: str) -> None:
            if tool not in by_tool:
                by_tool[tool] = {
                    "executed": 0,
                    "failed": 0,
                    "non_actionable_failures": 0,
                    "missing_or_unavailable": 0,
                }
            by_tool[tool][field] += 1

        for row in report.get("executed", []):
            _inc(str(row.get("tool", "unknown")), "executed")
        for row in report.get("failed", []):
            _inc(str(row.get("tool", "unknown")), "failed")
        for row in report.get("non_actionable_failures", []):
            _inc(str(row.get("tool", "unknown")), "non_actionable_failures")
        for row in report.get("missing_or_unavailable", []):
            _inc(str(row.get("tool", "unknown")), "missing_or_unavailable")

        report["summary_by_tool"] = by_tool
        report["unique_counts"] = {
            "executed": len(report.get("executed", [])),
            "failed": len(report.get("failed", [])),
            "non_actionable_failures": len(report.get("non_actionable_failures", [])),
            "missing_or_unavailable": len(report.get("missing_or_unavailable", [])),
        }

    def _build_execution_quality_summary(self) -> Dict[str, Any]:
        """Summarize scanner execution quality to avoid over-confident low-risk posture."""
        scanner_tools = {
            "nikto",
            "testssl",
            "sslscan",
            "sqlmap",
            "commix",
            "xsstrike",
            "xsser",
            "dalfox",
            "nuclei_all",
            "nuclei_crit",
            "nuclei_high",
            "nuclei_cves",
            "nuclei_ssl",
            "nuclei",
        }
        blocked = [
            r
            for r in self.execution_results
            if r.get("status") == "BLOCKED" and r.get("tool") in scanner_tools
        ]
        skipped = [
            r
            for r in self.execution_results
            if r.get("status") == "SKIPPED" and r.get("tool") in scanner_tools
        ]
        timed_out = [
            r
            for r in self.execution_results
            if bool(r.get("timed_out")) and r.get("tool") in scanner_tools
        ]
        no_signal = [
            r
            for r in self.execution_results
            if r.get("tool") in scanner_tools
            and r.get("outcome")
            in {ToolOutcome.EXECUTED_NO_SIGNAL.value, ToolOutcome.EXECUTION_ERROR.value}
        ]

        has_quality_gap = bool(blocked or timed_out)
        risk_floor = "LOW"
        if len(blocked) >= 2 or len(timed_out) >= 2:
            risk_floor = "MEDIUM"
        if len(blocked) + len(timed_out) >= 5:
            risk_floor = "HIGH"

        return {
            "blocked_scanner_tools": sorted(
                {r.get("tool") for r in blocked if r.get("tool")}
            ),
            "skipped_scanner_tools": sorted(
                {r.get("tool") for r in skipped if r.get("tool")}
            ),
            "timed_out_scanner_tools": sorted(
                {r.get("tool") for r in timed_out if r.get("tool")}
            ),
            "no_signal_scanner_tools": sorted(
                {r.get("tool") for r in no_signal if r.get("tool")}
            ),
            "has_quality_gap": has_quality_gap,
            "risk_floor": risk_floor,
        }

    def _detect_ssl_consistency_conflicts(self) -> Dict[str, Any]:
        """Detect conflicting TLS posture statements across SSL tooling outputs."""
        results = {
            "has_conflict": False,
            "conflicts": [],
        }
        content_by_tool: dict[str, str] = {}
        for row in self.execution_results:
            tool = str(row.get("tool", ""))
            path = row.get("output_file")
            if tool not in {
                "sslscan",
                "testssl",
                "openssl_connect",
                "openssl_showcerts",
                "openssl_state",
                "openssl_status",
                "nuclei_ssl",
            }:
                continue
            if not path:
                continue
            try:
                txt = Path(path).read_text(encoding="utf-8", errors="ignore").lower()
            except Exception:
                continue
            content_by_tool[tool] = txt

        insecure_seen = any(
            "tls 1.0" in c and ("offered" in c or "enabled" in c)
            for c in content_by_tool.values()
        )
        secure_seen = any(
            "tls 1.0" in c and "disabled" in c for c in content_by_tool.values()
        )
        if insecure_seen and secure_seen:
            results["has_conflict"] = True
            results["conflicts"].append(
                "TLS 1.0 reported as both enabled and disabled across tools"
            )
        return results

    def _enforce_risk_floor(
        self, risk_report: Dict[str, Any], execution_quality: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Raise reported risk level when execution quality indicates material uncertainty."""
        if not isinstance(risk_report, dict):
            risk_report = {}
        app = risk_report.get("application_risk", {}) or {}
        rating = str(app.get("risk_rating", "LOW")).upper()
        floor = str(execution_quality.get("risk_floor", "LOW")).upper()
        rank = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        if rank.get(rating, 1) < rank.get(floor, 1):
            app["original_risk_rating"] = rating
            app["risk_rating"] = floor
            app["confidence_adjusted"] = True
            app["adjustment_reason"] = (
                "Execution quality gaps reduced confidence in low-risk conclusion"
            )
        else:
            app.setdefault("confidence_adjusted", False)
        risk_report["application_risk"] = app
        risk_report["execution_quality"] = execution_quality
        return risk_report

    def _extract_findings(
        self, tool: str, stdout: str, stderr: str, output_file: str | None = None
    ) -> None:
        """
        Extract normalized findings from tool output.

        Maps tool output → Finding objects → FindingsRegistry (deduplicated).
        Uses unified parsers from tool_parsers.py module.
        """
        if not stdout:
            return

        # Use unified parser for supported tools
        findings = parse_tool_output(
            tool, stdout, stderr, self.target, output_file=output_file
        )
        for finding in findings:
            self.findings.add(finding)

        # Legacy parsers for nuclei/dalfox with OWASP enforcement
        if tool.startswith("nuclei"):
            for line in stdout.split("\n"):
                line_lower = line.lower()
                severity = None
                finding_type = FindingType.MISCONFIGURATION

                # Determine severity and type from nuclei output
                if "[critical]" in line_lower:
                    severity = Severity.CRITICAL
                elif "[high]" in line_lower:
                    severity = Severity.HIGH
                elif "[medium]" in line_lower:
                    severity = Severity.MEDIUM
                elif "[low]" in line_lower:
                    severity = Severity.LOW
                elif "[info]" in line_lower:
                    severity = Severity.INFO

                # Extract finding if severity was found
                if severity:
                    # Detect finding type from nuclei output
                    if "xss" in line_lower or "cross-site" in line_lower:
                        finding_type = FindingType.XSS
                    elif "sql" in line_lower or "injection" in line_lower:
                        finding_type = FindingType.SQLI
                    elif "lfi" in line_lower or "file inclusion" in line_lower:
                        finding_type = FindingType.MISCONFIGURATION
                    elif "rce" in line_lower or "command" in line_lower:
                        finding_type = FindingType.COMMAND_INJECTION
                    elif "ssrf" in line_lower:
                        finding_type = FindingType.SSRF
                    elif "cve-" in line_lower:
                        finding_type = FindingType.OUTDATED_SOFTWARE
                    elif (
                        "ssl" in line_lower
                        or "tls" in line_lower
                        or "cipher" in line_lower
                    ):
                        finding_type = FindingType.WEAK_CRYPTO

                    finding = Finding(
                        type=finding_type,
                        severity=severity,
                        location=self.profile.host,
                        description=line.strip(),
                        tool=tool,  # Use actual tool name (nuclei_all, nuclei_cves, etc.)
                        owasp=map_to_owasp(finding_type.value),
                        evidence=line[:500],
                        evidence_file=output_file or "",
                        evidence_line=max(
                            1,
                            (
                                stdout.count("\n", 0, stdout.find(line)) + 1
                                if line in stdout
                                else 1
                            ),
                        ),
                    )
                    self.findings.add(finding)

        elif tool == "dalfox" and "reflected" in stdout.lower():
            finding = Finding(
                type=FindingType.XSS,
                severity=Severity.HIGH,
                location=self.profile.host,
                description="Cross-Site Scripting (XSS) vulnerability detected",
                tool="dalfox",
                cwe="CWE-79",
                owasp=map_to_owasp(FindingType.XSS.value),
                evidence=stdout[:500],
                evidence_file=output_file or "",
            )
            self.findings.add(finding)

        # Whatweb: Extract technology stack for gating
        if tool == "whatweb":
            tech_stack = WhatwebParser.parse(stdout, self.profile.host)
            cms = tech_stack.get("cms")
            if cms:
                self.profile.detected_cms = cms.lower()
                self._register_param(f"tech_cms_{cms.lower()}", source="whatweb")
            server = tech_stack.get("web_server")
            if server:
                self._register_param(f"tech_server_{server.lower()}", source="whatweb")
            for lang in tech_stack.get("languages", []):
                self._register_param(f"tech_lang_{lang.lower()}", source="whatweb")
            for fw in tech_stack.get("frameworks", []):
                self._register_param(f"framework_{fw.lower()}", source="whatweb")
            for lib in tech_stack.get("javascript_libs", []):
                self._register_param(f"js_{lib.lower()}", source="whatweb")

        # SSL/TLS findings are fully handled by dedicated parsers to avoid line-level false positives.

    def _summarize_gating(self, orchestrator) -> str:
        """Summarize gating decisions for logging"""
        summary = []
        for tool in ["xsstrike", "dalfox", "sqlmap", "commix"]:
            can_run = orchestrator.should_run_tool(tool)
            status = "✓ RUN" if can_run else "✗ SKIP"
            summary.append(f"{tool}: {status}")
        return " | ".join(summary)

    def _base_confidence_for_finding(self, tool_name: str) -> float:
        """Provide a baseline confidence seed from execution context."""
        meta = self._tool_execution_meta.get(tool_name, {})
        if meta.get("timed_out"):
            return 0.35
        if meta.get("status") == "PARTIAL":
            return 0.45
        return 0.6

    def _build_finding_evidence_block(self, finding_dict: dict) -> dict:
        tool_name = str(finding_dict.get("tool", "unknown"))
        location = str(finding_dict.get("location", ""))
        result = next(
            (
                r
                for r in reversed(self.execution_results)
                if str(r.get("tool", "")) == tool_name
            ),
            {},
        )

        evidence_text = str(finding_dict.get("evidence", "") or "")
        response_snippet = (
            evidence_text[:280] if evidence_text else "No response snippet captured"
        )
        status_code = "n/a"
        match = re.search(r"\b(20\d|30\d|40\d|50\d)\b", evidence_text)
        if match:
            status_code = match.group(1)

        return {
            "request": f"GET {location or '/'}",
            "response_snippet": response_snippet,
            "status_code": status_code,
            "timestamp": result.get("finished_at") or datetime.now().isoformat(),
            "tool_source": tool_name,
            "reproduction_command": result.get("command")
            or f"Re-run {tool_name} against target to reproduce.",
        }

    def _build_confidence_basis(self, finding_dict: dict) -> dict:
        tool_name = str(finding_dict.get("tool", "unknown"))
        source = "zap" if "zap" in tool_name.lower() else "internal"
        base_conf = float(finding_dict.get("confidence", 0.0) or 0.0)
        corroborated = bool(finding_dict.get("corroborated", False))
        verified = bool(finding_dict.get("verification") == "VERIFIED")

        reasons = [
            f"base={base_conf:.2f}",
            f"source={source}",
            "corroborated=yes" if corroborated else "corroborated=no",
            "validated=yes" if verified else "validated=no",
        ]

        return {
            "base_confidence": base_conf,
            "source": source,
            "corroborated": corroborated,
            "validated": verified,
            "reason": ", ".join(reasons),
        }

    def _autofill_actionability_fields(self, finding_dict: dict) -> None:
        """Fill missing impact/exploitability/verification templates for report quality."""
        f_type = str(finding_dict.get("type", "")).lower()
        description = str(finding_dict.get("description", "")).lower()
        tool = str(finding_dict.get("tool", "unknown"))
        location = finding_dict.get("location", "")

        is_header_gap = (
            "missing security header" in description or "header" in description
        )
        is_breach = "breach" in description
        is_service_exposure = "discovered" in description and "port" in description

        if not (finding_dict.get("impact") or "").strip():
            if is_header_gap:
                finding_dict["impact"] = (
                    "Increases risk of XSS, clickjacking, and data leakage when combined with other weaknesses."
                )
            elif is_breach:
                finding_dict["impact"] = (
                    "Potential side-channel leakage risk when secrets are reflected in compressed HTTPS responses."
                )
            elif is_service_exposure:
                finding_dict["impact"] = (
                    "Exposed service metadata can accelerate reconnaissance and targeted exploit selection."
                )
            else:
                finding_dict["impact"] = (
                    "Security posture degradation with potential exploitation when chained."
                )

        if not (finding_dict.get("exploitability") or "").strip():
            if is_breach or is_header_gap:
                finding_dict["exploitability"] = (
                    "Passive; typically requires chaining with other vulnerabilities."
                )
            elif is_service_exposure:
                finding_dict["exploitability"] = (
                    "Low standalone; primarily recon advantage for attackers."
                )
            else:
                finding_dict["exploitability"] = (
                    "Context dependent based on exposure and attacker capability."
                )

        if not (finding_dict.get("verification_steps") or "").strip():
            if is_header_gap:
                finding_dict["verification_steps"] = (
                    "Run: curl -I https://target and verify expected security headers are present."
                )
            elif is_service_exposure:
                finding_dict["verification_steps"] = (
                    f"Run: nmap -sV {self.profile.host} and validate service/banner exposure at {location}."
                )
            elif is_breach:
                finding_dict["verification_steps"] = (
                    "Re-run testssl/nikto and validate HTTPS compression plus reflection behavior on sensitive endpoints."
                )
            else:
                finding_dict["verification_steps"] = (
                    "Re-run the original command and validate reproducibility from evidence line."
                )

        finding_dict["evidence_details"] = self._build_finding_evidence_block(
            finding_dict
        )
        finding_dict["confidence_basis"] = self._build_confidence_basis(finding_dict)

    def _read_output_text(self, output_path: str) -> str:
        try:
            p = Path(output_path)
            if not p.exists():
                return ""
            return p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return ""

    def _apply_promotion_logic(self, findings: list[dict]) -> list[dict]:
        """Promote hardening findings using cross-tool corroboration and contextual rules."""
        promoted = list(findings)
        existing_descriptions = {
            str(f.get("description", "")).lower()
            for f in promoted
            if isinstance(f, dict)
        }

        nikto_failed = any(
            r.get("tool") == "nikto" and r.get("status") == "FAILED"
            for r in self.execution_results
        )

        tool_text: dict[str, str] = {}
        for r in self.execution_results:
            tool = r.get("tool")
            output_file = r.get("output_file")
            if tool and output_file:
                tool_text[tool] = self._read_output_text(str(output_file)).lower()

        nikto_text = tool_text.get("nikto", "")
        testssl_text = tool_text.get("testssl", "")
        whatweb_text = (
            tool_text.get("whatweb", "")
            + "\n"
            + tool_text.get("whatweb_http_fallback", "")
        )
        nuclei_text = "\n".join(
            [
                tool_text.get("nuclei_all", ""),
                tool_text.get("nuclei_high", ""),
                tool_text.get("nuclei_ssl", ""),
                tool_text.get("nuclei_cves", ""),
            ]
        )

        # Rule 1: Missing header hardening findings (promote from direct observation).
        missing_headers = sorted(
            set(
                re.findall(
                    r"suggested security header missing:\s*([^\.\n]+)",
                    nikto_text,
                    re.IGNORECASE,
                )
            )
        )
        if missing_headers:
            sev = "MEDIUM" if len(missing_headers) >= 3 else "LOW"
            confidence = 0.85 if len(missing_headers) >= 2 else 0.75
            desc = f"Hardening Gap: Missing security headers ({', '.join(h.strip().lower() for h in missing_headers[:6])})"
            if desc.lower() not in existing_descriptions:
                promoted.append(
                    {
                        "type": "Misconfiguration",
                        "severity": sev,
                        "location": self.profile.host,
                        "description": desc,
                        "tool": "nikto",
                        "confidence": confidence,
                        "owasp": "A05:2021 - Security Misconfiguration",
                        "cwe": "CWE-693",
                        "evidence": "Suggested security header missing observed in nikto output",
                        "impact": "Missing browser security headers reduce baseline hardening and increase exploit chainability.",
                        "exploitability": "Passive; usually requires chaining with XSS/clickjacking/content injection.",
                        "verification_steps": "curl -I https://target and validate each listed header is present.",
                    }
                )

        # Rule 2: BREACH contextual promotion with corroboration.
        breach_tools = set()
        if "breach" in nikto_text:
            breach_tools.add("nikto")
        if "breach" in testssl_text and (
            "gzip" in testssl_text or "compression" in testssl_text
        ):
            breach_tools.add("testssl")
        if "content-encoding" in whatweb_text and "gzip" in whatweb_text:
            breach_tools.add("whatweb")
        if "breach" in nuclei_text or "http-missing-security-headers" in nuclei_text:
            breach_tools.add("nuclei")

        if len(breach_tools) >= 2:
            desc = "Potential side-channel risk (BREACH), requires attacker-controlled reflection to exploit"
            if desc.lower() not in existing_descriptions:
                confidence = (
                    0.75
                    if (
                        nikto_failed
                        and len([t for t in breach_tools if t != "nikto"]) >= 2
                    )
                    else 0.65
                )
                promoted.append(
                    {
                        "type": "Weak Cryptography",
                        "severity": "LOW",
                        "location": self.profile.host,
                        "description": desc,
                        "tool": "+".join(sorted(breach_tools)),
                        "confidence": confidence,
                        "owasp": "A02:2021 - Cryptographic Failures",
                        "cwe": "CWE-200",
                        "evidence": "Cross-tool corroboration: BREACH/compression indicators from "
                        + ", ".join(sorted(breach_tools)),
                        "impact": "Compression side-channels may leak secrets under specific reflective conditions.",
                        "exploitability": "Context-dependent and usually requires attacker-controlled reflection and repeated requests.",
                        "verification_steps": "Confirm gzip compression on sensitive endpoints and test reflection of secret-bearing tokens.",
                    }
                )

        # Rule 3: Public API documentation endpoints can leak attack surface.
        api_docs = self._build_api_doc_exposure().get("paths", [])
        if api_docs:
            for doc in api_docs[:4]:
                path = str(doc.get("url", ""))
                desc = f"API documentation endpoint exposed without explicit access controls: {path}"
                if desc.lower() in existing_descriptions:
                    continue
                promoted.append(
                    {
                        "type": "Information Disclosure",
                        "severity": "MEDIUM",
                        "location": path,
                        "description": desc,
                        "tool": "api_schema+discovery",
                        "confidence": 0.72,
                        "owasp": "A01:2021 - Broken Access Control",
                        "cwe": "CWE-200",
                        "evidence": f"Discovered API documentation artifact ({path}) in endpoint inventory.",
                        "impact": "Public API specs can expose internal operations, sensitive fields, and hidden routes.",
                        "exploitability": "Moderate; increases attacker reconnaissance efficiency and bypass path discovery.",
                        "verification_steps": f"Check unauthenticated access to {path}; verify sensitive schemas and hidden routes are not exposed.",
                    }
                )

        # Rule 4: Exposed non-standard service track should be highlighted.
        has_8081 = any(
            int(fp.get("port", 0) or 0) == 8081 for fp in self.service_fingerprints
        )
        if has_8081:
            desc = "Non-standard HTTP service exposed on port 8081 requires dedicated abuse-path testing"
            if desc.lower() not in existing_descriptions:
                promoted.append(
                    {
                        "type": "Misconfiguration",
                        "severity": "MEDIUM",
                        "location": f"{self.profile.host}:8081",
                        "description": desc,
                        "tool": "service_fingerprinting",
                        "confidence": 0.74,
                        "owasp": "A05:2021 - Security Misconfiguration",
                        "cwe": "CWE-16",
                        "evidence": "Service fingerprinting detected HTTP Admin/Proxy-like surface on port 8081.",
                        "impact": "Additional management or proxy services increase attack surface and lateral movement opportunities.",
                        "exploitability": "Moderate; often exploitable through default routes, weak admin controls, or debug features.",
                        "verification_steps": "Map routes on port 8081, test default admin paths, and validate authentication on control endpoints.",
                    }
                )

        return promoted

    def run_full_scan(self) -> None:
        print("\n" + "=" * 80)
        print("ARCHITECTURE-DRIVEN SECURITY SCANNER")
        print(f"Target: {self.profile.host}")
        print(f"Type: {self.profile.type}")
        # Use accessors to avoid attribute errors on ledger internals
        print(f"Tools Approved: {len(self.ledger.get_allowed_tools())}")
        print(f"Tools Denied: {len(self.ledger.get_denied_tools())}")
        print(f"Start Time: {self.start_time.isoformat()}")
        print("=" * 80)

        plan = self.executor.get_execution_plan()

        # Deduplication guard: hard-fail on duplicate tools in plan
        tool_names = [t[0] for t in plan]
        if len(tool_names) != len(set(tool_names)):
            from architecture_guards import ArchitectureViolation

            raise ArchitectureViolation(
                f"Duplicate tool in execution plan: {tool_names}"
            )

        self.log(f"Execution Plan: {len(plan)} tools planned")
        self.log(f"Execution Path: {self.executor.__class__.__name__}")

        # Phase definitions: tools grouped by function
        phases = {
            "DNS": {"tools": {"dig_a", "dig_ns", "dig_mx", "dnsrecon"}},
            "Subdomains": {"tools": {"findomain", "sublist3r", "assetfinder"}},
            "Network": {"tools": {"ping", "nmap_quick", "nmap_vuln"}},
            "WebDetection": {"tools": {"whatweb", "nikto"}},
            "SSL": {
                "tools": {
                    "sslscan",
                    "testssl",
                    "openssl_connect",
                    "openssl_showcerts",
                    "openssl_status",
                    "openssl_state",
                }
            },
            "Crawling": {"tools": {"gating_crawl"}},
            "WebEnum": {"tools": {"gobuster", "dirsearch"}},
            "Exploitation": {
                "tools": {"dalfox", "xsstrike", "sqlmap", "commix", "xsser"}
            },
            "Nuclei": {
                "tools": {
                    "nuclei_crit",
                    "nuclei_high",
                    "nuclei_all",
                    "nuclei_cves",
                    "nuclei_ssl",
                }
            },
        }

        # Track phase success
        phase_success = {phase: False for phase in phases}

        # ====== PHASE 1a-1b: DISCOVERY PHASE (RUN FIRST) ======
        # Execute discovery tools to gather signals BEFORE checking completeness
        self.log(
            "PHASE 1: Running discovery tools (DNS, Network, Web Detection, SSL/TLS)...",
            "INFO",
        )

        discovery_phases = ["DNS", "Subdomains", "Network", "WebDetection", "SSL"]
        discovery_plan = [
            t
            for t in plan
            if any(t[0] in phases[phase]["tools"] for phase in discovery_phases)
        ]

        # Execute discovery tools first
        for i, (tool_name, cmd, meta) in enumerate(discovery_plan, 1):
            if not self.ledger.allows(tool_name):
                continue
            self.log(f"[Discovery] Executing {tool_name}...", "INFO")
            try:
                # Convert tuple to dict format expected by _run_tool
                scoped_cmd = self._scope_command(tool_name, cmd)
                plan_item = {"tool": tool_name, "command": scoped_cmd, **meta}
                result = self._run_tool(plan_item, i, len(discovery_plan))
                if result and result.get("status") == "SUCCESS":
                    self.log(f"  ✓ {tool_name} completed", "INFO")
            except Exception as e:
                self.log(f"  ⚠ {tool_name} error: {e}", "WARN")

        # ====== PHASE 1c: DISCOVERY COMPLETENESS CHECK (AFTER TOOLS) ======
        self.log(
            "PHASE 1c: Evaluating discovery completeness (after discovery tools)...",
            "INFO",
        )

        # Initialize discovery evaluator with cache (NOW populated by discovery tools)
        self.discovery_evaluator = DiscoveryCompletenessEvaluator(
            self.cache, self.profile
        )

        # Evaluate completeness
        self.completeness_report = self.discovery_evaluator.evaluate()

        score_pct = int(self.completeness_report.completeness_score * 100)

        # Log results
        if self.completeness_report.complete:
            self.log(f"✓ Discovery COMPLETE: {score_pct}/100", "INFO")
            self.log(f"✓ All payload tools READY to execute", "INFO")
        else:
            self.log(f"⏳ Discovery INCOMPLETE: {score_pct}/100", "WARN")
            for gap in self.completeness_report.missing_signals:
                self.log(f"  - Waiting for: {gap}", "WARN")

        # STRICT: If discovery incomplete AND score < 60 → BLOCK only heavy web-enum tools.
        # Active exploitation remains enabled and is validated post-execution.
        if (not self.completeness_report.complete) and score_pct < 60:
            self.log(
                "⏳ BLOCKING payload tools: Discovery still incomplete after tools (score < 60)",
                "ERROR",
            )

            # Mark all payload tools as blocked in ledger
            for phase_name in ["WebEnum"]:
                for tool in phases[phase_name]["tools"]:
                    self.ledger.record_tool_decision(
                        tool_name=tool,
                        decision=Decision.DENY,
                        reason=f"discovery_incomplete_score_{score_pct}",
                    )
                    self.log(f"  ⏳ BLOCKED: {tool} (insufficient discovery)", "WARN")

        # ====== PHASE 1d: TLS EVALUATION FOR HTTPS TARGETS ======
        if self.profile.is_https:
            self.log("PHASE 1d: HTTPS detected - enforcing TLS evaluation...", "INFO")

            # Check if TLS was evaluated
            tls_evaluated = self.cache.has_signal(
                "tls_evaluated"
            ) or self.cache.has_signal("ssl_evaluated")
            if not tls_evaluated:
                tls_tools = {
                    "testssl",
                    "sslscan",
                    "openssl_connect",
                    "openssl_showcerts",
                    "openssl_status",
                    "openssl_state",
                }
                tls_evaluated = any(
                    result.get("tool") in tls_tools
                    and result.get("status")
                    not in {"SKIPPED", "BLOCKED", "TIMEOUT", "EXECUTION_ERROR"}
                    for result in self.execution_results
                )

            if not tls_evaluated:
                self.log(
                    "HTTPS target TLS evaluation not confirmed from discovery cache; continuing",
                    "INFO",
                )
            else:
                self.log(f"✓ TLS evaluated for HTTPS target", "INFO")

        # ====== PHASE 1b: EXTERNAL INTELLIGENCE (READ-ONLY) ======
        self.log("PHASE 1b: Gathering external intelligence (crt.sh)...", "INFO")
        try:
            # Only crt.sh (no API key required) - Shodan/Censys require keys
            intel_results = self.external_intel.gather_intel(self.profile.host)

            if intel_results.get("crtsh") and intel_results["crtsh"].success:
                self.external_intel.to_cache_signals(intel_results, self.cache)
                self.log(
                    f"✓ External intel: {len(intel_results['crtsh'].results)} certificate entries",
                    "INFO",
                )
            else:
                self.log(
                    "External intel unavailable (crt.sh timeout/network); continuing without enrichment",
                    "INFO",
                )
        except Exception as e:
            self.log(
                f"External intel unavailable ({type(e).__name__}); continuing", "INFO"
            )

        # ====== PHASE 2: MANDATORY CRAWLER GATE ======
        # Architecture Rule: Crawler is NOT optional. It is MANDATORY.
        # If crawler fails → BLOCK all payload tools (dalfox, sqlmap, commix, etc.)
        # NO CRAWL = NO PAYLOAD. This is non-negotiable.

        self.crawler_executed = False  # Track crawler execution
        self.endpoint_graph = None  # Will be populated by crawler

        gating_orchestrator = None
        gating_signals = None
        self.strict_gating_loop = None
        crawler_gate = CrawlerMandatoryGate(self.cache)  # Initialize gate

        self.log(
            "PHASE 2: Running MANDATORY crawler (payload tools depend on this)...",
            "INFO",
        )
        try:
            # Build full URL with scheme from profile
            scheme = "https" if self.profile.is_https else "http"
            crawl_url = f"{scheme}://{self.profile.host}"

            crawl_adapter = CrawlAdapter(
                crawl_url, output_dir=str(self.output_dir), cache=self.cache
            )

            # Run crawl in a thread with timeout (30s for mandatory crawler)
            crawl_result = [None]

            def run_crawl():
                try:
                    success, msg = crawl_adapter.run()
                    crawl_result[0] = (success, msg)
                except Exception as e:
                    crawl_result[0] = (False, str(e))

            crawl_thread = threading.Thread(target=run_crawl, daemon=True)
            crawl_thread.start()
            crawl_thread.join(timeout=90)  # Increased timeout to 90s for large sites

            if crawl_thread.is_alive():
                self.log(
                    "Crawler TIMEOUT (90s) - ATTEMPTING FALLBACK discovery sources",
                    "WARN",
                )
                # Crawler times out - DON'T immediately block payload tools
                # Instead, gather alternative targets from nuclei, whatweb, nmap
                self._populate_cache_from_fallback_sources()

                # Only block payload tools if NO endpoints were discovered
                if len(self.cache.endpoints) <= 1:  # Only root domain is not enough
                    self.log(
                        "No fallback endpoints found after crawler timeout - BLOCKING payload tools",
                        "ERROR",
                    )
                    crawler_gate.update_decision_ledger(self.ledger)
                else:
                    self.log(
                        f"Fallback discovery found {len(self.cache.endpoints)} endpoints - ALLOWING payload tools to execute",
                        "WARN",
                    )
                    # Don't block - allow payload tools to run on fallback endpoints
            elif crawl_result[0]:
                crawl_success, crawl_msg = crawl_result[0]
                if crawl_success:
                    # Crawler succeeded - populate cache and build gating
                    gating_signals = crawl_adapter.gating_signals

                    # Build endpoint graph from crawl results for strict gating
                    if crawl_adapter.crawl_result:
                        graph = EndpointGraph(target=crawl_url)
                        results = crawl_adapter.crawl_result.get("results", [])
                        for result in results:
                            graph.add_crawl_result(
                                url=result.get("url", ""),
                                method=result.get("method", "GET"),
                                params=result.get("params"),
                                is_api=result.get("is_api", False),
                                is_form=result.get("is_form", False),
                                status_code=result.get("status_code"),
                            )

                        # Mark reflectable parameters from crawl signals
                        for param_name in gating_signals.get("reflectable_params", []):
                            graph.mark_reflectable(param_name)

                        graph.finalize()
                        self.endpoint_graph = graph  # Store for payload tools
                        self.payload_command_builder = PayloadCommandBuilder(
                            self.payload_strategy, self.endpoint_graph
                        )
                        self.crawler_executed = True  # Mark crawler as executed
                        self.strict_gating_loop = StrictGatingLoop(graph, self.ledger)
                        gating_orchestrator = self.strict_gating_loop

                        # Phase 4: Initialize enhanced confidence engine with graph
                        self.enhanced_confidence = EnhancedConfidenceEngine(graph)

                    self.log(
                        f"Crawler SUCCESS: {gating_signals['crawled_url_count']} endpoints, "
                        f"{gating_signals['parameter_count']} parameters, "
                        f"{gating_signals['reflection_count']} reflections",
                        "SUCCESS",
                    )

                    self._register_crawl_security_findings(
                        crawl_url=crawl_url,
                        crawl_result=crawl_adapter.crawl_result,
                        gating_signals=gating_signals,
                    )

                    if self.strict_gating_loop:
                        gating_targets = self.strict_gating_loop.get_all_targets()
                        enabled = [t for t, tg in gating_targets.items() if tg.can_run]
                        disabled = [
                            t for t, tg in gating_targets.items() if not tg.can_run
                        ]
                        self.log(
                            f"Payload gating (strict): enabled={enabled}, disabled={disabled}",
                            "INFO",
                        )
                    else:
                        self.log(
                            "Strict gating not available (no graph built)", "WARNING"
                        )

                    # Update gate with crawler success
                    crawler_gate.check_crawler_status()
                else:
                    # Crawler failed - BLOCK payload tools
                    self.log(
                        f"Crawler FAILED: {crawl_msg} - BLOCKING payload tools", "ERROR"
                    )
                    crawler_gate.update_decision_ledger(self.ledger)
            else:
                # No result - crawler error
                self.log("Crawler ERROR - BLOCKING payload tools", "ERROR")
                crawler_gate.update_decision_ledger(self.ledger)

        except Exception as e:
            self.log(f"Crawler EXCEPTION: {str(e)} - BLOCKING payload tools", "ERROR")
            crawler_gate.update_decision_ledger(self.ledger)

        # Report gate status
        gate_report = crawler_gate.get_gate_report()
        if not gate_report["crawler_succeeded"]:
            self.log(
                f"Crawler gate warning: {gate_report['failure_reason']} (continuing with alternative discovery sources)",
                "WARN",
            )
        else:
            self.log(
                f"✓ Crawler gate passed: {gate_report['endpoints_discovered']} endpoints discovered",
                "SUCCESS",
            )

        # Merge additional discovery sources before quality scoring.
        self._run_multi_source_discovery(crawl_url)

        # JS-aware discovery augments server-side crawl for modern SPA/API traffic.
        try:
            validate_playwright_environment()
            self._run_js_aware_discovery(crawl_url)
        except Exception as e:
            js_failure_reason = f"JS-aware discovery failure: {e}"
            self.js_discovery_summary = {
                "executed": True,
                "playwright_used": False,
                "success": False,
                "endpoints": 0,
                "api_endpoints": 0,
                "js_assets": 0,
                "network_requests": 0,
                "requests_captured": 0,
                "api_calls_detected": 0,
                "params": 0,
                "error": str(e),
            }
            if self.strict_js_required:
                self.abort_reason = js_failure_reason
                self.scan_status = "aborted"
                self.log(self.abort_reason, "ERROR")
                self.log(
                    "Aborting active scan due to strict JS discovery policy", "ERROR"
                )
                self._write_report()
                return
            self.log(f"{js_failure_reason} - continuing without JS discovery", "INFO")

        # Wave 2: secondary enrichment and passive security posture checks.
        self._run_zap_enrichment(crawl_url)
        self._run_api_schema_import(crawl_url)
        self._run_passive_analysis(crawl_url)

        # Critical: remove noisy/static/code endpoints before scoring and exploitation gating.
        self._apply_endpoint_quality_filter()

        self._evaluate_discovery_quality()

        # Run auth/access-control/IDOR checks before active exploitation so role contexts are available.
        self._run_auth_access_control_assessment(crawl_url)

        # PHASE 5: Active exploitation always runs and is filtered only at proof/report stage
        discovery_state = DiscoveryState(
            endpoints_count=len(self.cache.endpoints),
            controllable_params_count=len(self.cache.params),
            api_endpoints_count=int(self.js_discovery_summary.get("api_endpoints", 0))
            + int(self.api_schema_summary.get("endpoints", 0)),
            js_discovery_success=bool(self.js_discovery_summary.get("success", False)),
            js_network_calls_captured=int(
                self.js_discovery_summary.get("network_requests", 0)
            ),
            crawler_success=bool(gate_report.get("crawler_succeeded", False)),
            external_intel_count=len(self.cache.subdomains),
            zap_endpoints_count=int(self.zap_discovery_summary.get("endpoints", 0)),
        )
        ready, ready_reason = check_exploitation_readiness(
            discovery_state, phase_name="PHASE 5"
        )

        if self.discovery_quality.get("should_abort_exploitation"):
            self.log(
                "Scan aborted: insufficient attack surface (discovery quality too weak)",
                "ERROR",
            )
            ready = False
            ready_reason = "Discovery quality scorer flagged weak attack surface"

        has_attack_surface = len(self.cache.endpoints) > 0 or len(self.cache.params) > 0
        if not has_attack_surface:
            ready = False
            ready_reason = (
                "No endpoints or parameters discovered after all discovery sources"
            )
        elif not ready:
            self.log(
                f"Proceeding with low-confidence exploitation mode: {ready_reason}",
                "WARN",
            )
            ready = True
            ready_reason = "Low-confidence mode enabled"

        if not ready:
            self.log(f"Active exploitation skipped: {ready_reason}", "WARN")
        elif self.initialize_exploitation_engines():
            scheme = "https" if self.profile.is_https else "http"
            base_url = f"{scheme}://{self.profile.host}"
            fallback_endpoints = self._build_fallback_endpoints_for_exploitation()
            exploitation_findings = self.run_active_exploitation(
                base_url, endpoints=fallback_endpoints
            )
            self.log(
                f"Exploitation phase complete: {len(exploitation_findings)} findings from active testing",
                "INFO",
            )
        else:
            self.log(
                "Exploitation engines failed to initialize - skipping active testing",
                "WARN",
            )

        # Relax strict gate denials when attack surface exists: run tools in low-confidence mode.
        if has_attack_surface:
            for payload_tool in {
                "sqlmap",
                "dalfox",
                "xsstrike",
                "commix",
                "xsser",
                "arjun",
            }:
                if payload_tool not in self.ledger.decisions:
                    continue
                if self.ledger.denies(payload_tool):
                    self.ledger.record_tool_decision(
                        tool_name=payload_tool,
                        decision=Decision.ALLOW,
                        reason="low_confidence_mode_surface_detected",
                    )
                    self.log(
                        f"[{payload_tool}] Gate relaxed: switching BLOCKED -> WARNING+EXECUTE",
                        "WARN",
                    )

        # Service visibility and target ranking feed prioritization logic.
        self.run_service_fingerprinting()
        self.prioritized_subdomains = self.prioritize_subdomain_targets()

        total = len(plan)
        builder_payload_tools = {"dalfox", "sqlmap", "commix"}

        # Track tools already executed in discovery phase to avoid duplication
        discovery_tool_names = {t[0] for t in discovery_plan}

        for i, item in enumerate(plan, start=1):
            # executor.get_execution_plan() returns tuples (tool, cmd, meta)
            tool_name, cmd, meta = item
            scoped_cmd = None

            # Skip tools that already ran in discovery phase
            if tool_name in discovery_tool_names:
                continue

            # Determine which phase this tool belongs to
            current_phase = None
            for phase, info in phases.items():
                if tool_name in info["tools"]:
                    current_phase = phase
                    break

            # NEW: Strict graph-based gating for payload tools
            payload_tools = {"xsstrike", "dalfox", "sqlmap", "commix"}
            gating_loop = self.strict_gating_loop or gating_orchestrator
            gated_targets = None
            if gating_loop and tool_name in payload_tools:
                try:
                    targets = gating_loop.gate_tool(tool_name)
                except Exception:
                    targets = None

                if not targets or not targets.can_run:
                    reason = (
                        targets.reason
                        if targets
                        else "Gated by crawl analysis (no targets)"
                    )
                    self.log(
                        f"[{tool_name}] strict gating advisory only: {reason} (continuing execution)",
                        "WARN",
                    )
                gated_targets = targets.to_dict() if targets else None

            # Payload tools must use crawler-derived commands only
            if tool_name in builder_payload_tools and self.payload_command_builder:
                built_commands = self._build_payload_commands_from_graph(tool_name)

                if not built_commands:
                    self.log(
                        f"[{tool_name}] No crawler-derived payload targets; using scoped default command in low-confidence mode",
                        "WARN",
                    )
                    scoped_cmd = self._scope_command(tool_name, cmd)
                    plan_item = {"tool": tool_name, "command": scoped_cmd, **meta}
                    if gated_targets:
                        plan_item["gated_targets"] = gated_targets
                    result = self._run_tool(plan_item, i, total)
                    if (
                        current_phase
                        and result
                        and result.get("outcome")
                        == ToolOutcome.SUCCESS_WITH_FINDINGS.value
                    ):
                        phase_success[current_phase] = True
                    continue

                for cmd_info in built_commands:
                    scoped_cmd = cmd_info.get("command")
                    plan_item = {
                        "tool": tool_name,
                        "command": scoped_cmd,
                        **meta,
                        "endpoint": cmd_info.get("endpoint"),
                        "param": cmd_info.get("param"),
                        "method": cmd_info.get("method"),
                        "payload_count": cmd_info.get("payload_count"),
                    }
                    if cmd_info.get("payload") and cmd_info.get("param"):
                        self.payload_strategy.track_attempt(
                            payload=cmd_info["payload"],
                            payload_type=PayloadType.BASELINE,
                            endpoint=cmd_info.get("endpoint", ""),
                            parameter=cmd_info.get("param", ""),
                            method=cmd_info.get("method", "GET"),
                            success=False,
                        )
                    if gated_targets:
                        plan_item["gated_targets"] = gated_targets
                    result = self._run_tool(plan_item, i, total)
                    if (
                        current_phase
                        and result
                        and result.get("outcome")
                        == ToolOutcome.SUCCESS_WITH_FINDINGS.value
                    ):
                        phase_success[current_phase] = True
                continue

            # Orchestrator decides strictly via decision layer; tools never self-skip
            scoped_cmd = scoped_cmd or self._scope_command(tool_name, cmd)
            plan_item = {"tool": tool_name, "command": scoped_cmd, **meta}
            if gated_targets:
                plan_item["gated_targets"] = gated_targets
            result = self._run_tool(plan_item, i, total)
            if (
                current_phase
                and result
                and result.get("outcome") == ToolOutcome.SUCCESS_WITH_FINDINGS.value
            ):
                phase_success[current_phase] = True

        # No parallel execution in strict orchestrator mode

        self.log(f"Discovery summary: {self.cache.summary()}", "INFO")
        self.log(f"Findings summary: {self.findings.summary()}", "SUCCESS")

        if self.findings.has_critical():
            self.log("⚠️  CRITICAL vulnerabilities found!", "CRITICAL")

        # Phase 1: Evaluate discovery completeness
        self.log("Evaluating discovery completeness...", "INFO")
        self.discovery_evaluator = DiscoveryCompletenessEvaluator(
            self.cache, self.profile
        )
        self.completeness_report = self.discovery_evaluator.evaluate()
        self.discovery_evaluator.log_report(self.completeness_report)

        self.log(
            "Scan complete - orchestrator finished (see execution results for skips/blocks)",
            "SUCCESS",
        )

        # Optional manual out-of-scope rerun over discovered API/pages.
        manual_choice = self._prompt_manual_out_of_scope_action()
        self.manual_out_of_scope_report["prompt_response"] = manual_choice
        if manual_choice == "yes":
            self.log("Manual out-of-scope sweep: YES selected", "INFO")
            self._run_manual_out_of_scope_sweep()
        elif manual_choice == "no":
            self.log("Manual out-of-scope sweep: NO selected", "INFO")
        else:
            self.log("Manual out-of-scope sweep: SKIP selected", "INFO")

        self._write_report()

    def _write_report(self) -> None:
        plan = self.executor.get_execution_plan()
        self._finalize_manual_out_of_scope_report()

        # JSON-safe plan (convert sets to sorted lists)
        plan_serialized = []
        for t, c, m in plan:
            safe_meta = {}
            for k, v in m.items():
                if isinstance(v, set):
                    safe_meta[k] = sorted(v)
                else:
                    safe_meta[k] = v
            plan_serialized.append({"tool": t, "command": c, **safe_meta})

        # NEW: Apply intelligence layer for confidence scoring and correlation
        all_findings = list(self.findings.get_all())

        # Phase 4: Convert findings to dicts for processing
        findings_dicts = []
        for finding in all_findings:
            # Convert Finding object to dict
            f_dict = {
                "type": (
                    finding.type.value
                    if hasattr(finding.type, "value")
                    else finding.type
                ),
                "severity": (
                    finding.severity.value
                    if hasattr(finding.severity, "value")
                    else finding.severity
                ),
                "location": finding.location,
                "description": finding.description,
                "cwe": finding.cwe,
                "owasp": finding.owasp,
                "tool": finding.tool,
                "evidence": finding.evidence[:500] if finding.evidence else "",
                "evidence_file": finding.evidence_file,
                "evidence_line": finding.evidence_line,
                "impact": finding.impact,
                "exploitability": finding.exploitability,
                "verification_steps": finding.verification_steps,
                "confidence": self._base_confidence_for_finding(finding.tool),
            }
            # Apply OWASP mapping if not already set
            if not f_dict.get("owasp"):
                try:
                    owasp_cat = map_to_owasp(f_dict["type"])
                    f_dict["owasp"] = owasp_cat.value
                except:
                    pass
            self._autofill_actionability_fields(f_dict)
            findings_dicts.append(f_dict)
        deduplicated_findings = self.dedup_engine.deduplicate(findings_dicts)

        # Filter false positives
        filtered_findings = self.intelligence.filter_false_positives(
            deduplicated_findings
        )

        # Skip advanced correlation for now - work with filtered dicts directly
        correlated_findings = filtered_findings

        # Promotion layer: elevate hardening findings with corroboration/context rules.
        correlated_findings = self._apply_promotion_logic(correlated_findings)

        # Wave 2: Global confidence enforcement. Drop low-confidence findings before reporting.
        high_confidence_findings = []
        for finding in correlated_findings:
            if not isinstance(finding, dict):
                high_confidence_findings.append(finding)
                continue

            base_conf = float(finding.get("confidence", 0.0) or 0.0)
            source = str(finding.get("tool", "internal") or "internal")
            scored_conf = GlobalConfidenceSystem.score(
                base_confidence=base_conf,
                corroborated=bool(finding.get("corroborated", False)),
                validated=bool(finding.get("verification") == "VERIFIED"),
                source="zap" if "zap" in source.lower() else "internal",
            )
            finding["confidence"] = scored_conf
            finding["confidence_percentage"] = GlobalConfidenceSystem.as_percentage(
                scored_conf
            )
            basis = self._build_confidence_basis(finding)
            finding["confidence_basis"] = {
                **basis,
                "final_confidence": scored_conf,
                "reason": (f"{basis.get('reason', '')}, " f"final={scored_conf:.2f}"),
            }

            if GlobalConfidenceSystem.should_report(scored_conf):
                high_confidence_findings.append(finding)

        correlated_findings = high_confidence_findings

        # Phase 4: Enhanced confidence scoring
        if self.enhanced_confidence:
            for finding in correlated_findings:
                if isinstance(finding, dict):
                    confidence_score = (
                        self.enhanced_confidence.calculate_finding_confidence(finding)
                    )
                    finding["confidence"] = confidence_score
                    finding["confidence_label"] = (
                        self.enhanced_confidence.get_confidence_label(confidence_score)
                    )

        vulnerability_report = {}
        risk_report = {}
        try:
            vuln_reporter = VulnerabilityCentricReporter()
            risk_aggregator = RiskAggregator(app_name=self.profile.host)

            for finding in correlated_findings:
                finding_dict = (
                    finding
                    if isinstance(finding, dict)
                    else (
                        finding.primary_finding
                        if hasattr(finding, "primary_finding")
                        else finding
                    )
                )
                if hasattr(finding_dict, "to_dict"):
                    finding_dict = finding_dict.to_dict()

                severity_value = finding_dict.get("severity", "INFO")
                if isinstance(severity_value, Enum):
                    severity_value = severity_value.name

                finding_dict["severity"] = severity_value

                vuln_reporter.ingest_finding(finding_dict)

                risk_aggregator.add_finding(
                    endpoint=finding_dict.get("location", ""),
                    parameter=finding_dict.get("parameter"),
                    vulnerability_type=finding_dict.get("type", "UNKNOWN"),
                    severity=severity_value,
                    tool_name=finding_dict.get("tool", "unknown"),
                    confidence=finding_dict.get("confidence", 0.5),
                    owasp_category=finding_dict.get("owasp"),
                    cwe_ids=(
                        [finding_dict.get("cwe")] if finding_dict.get("cwe") else []
                    ),
                )

            vulnerability_report = vuln_reporter.get_full_report()
            risk_report = risk_aggregator.generate_report()
        except Exception as e:  # noqa: BLE001
            self.log(f"Vulnerability-centric reporting failed: {e}", "WARN")

        execution_quality = self._build_execution_quality_summary()
        ssl_consistency = self._detect_ssl_consistency_conflicts()
        risk_report = self._enforce_risk_floor(risk_report, execution_quality)
        risk_report["ssl_consistency"] = ssl_consistency

        # Generate intelligence report (skip for now - work with dicts directly)
        intelligence_report = {}

        # Merge correlated findings into existing findings registry.
        # Do not reset findings here; correlation may legitimately return empty.
        for cf in correlated_findings:
            # Handle both dict and CorrelatedFinding objects
            if isinstance(cf, dict):
                # Reconstruct Finding objects from dicts
                try:
                    f_type = (
                        FindingType[cf.get("type", "OTHER")]
                        if isinstance(cf.get("type"), str)
                        else FindingType.OTHER
                    )
                except (KeyError, TypeError):
                    f_type = FindingType.OTHER
                try:
                    f_sev = (
                        Severity[cf.get("severity", "INFO")]
                        if isinstance(cf.get("severity"), str)
                        else Severity.INFO
                    )
                except (KeyError, TypeError):
                    f_sev = Severity.INFO
                finding = Finding(
                    type=f_type,
                    severity=f_sev,
                    location=cf.get("location", ""),
                    description=cf.get("description", ""),
                    cwe=cf.get("cwe"),
                    owasp=cf.get("owasp"),
                    tool=cf.get("tool", "unknown"),
                    evidence=cf.get("evidence", ""),
                    evidence_file=cf.get("evidence_file", ""),
                    evidence_line=int(cf.get("evidence_line", 0) or 0),
                    remediation=cf.get("remediation", ""),
                    impact=cf.get("impact", ""),
                    exploitability=cf.get("exploitability", ""),
                    verification_steps=cf.get("verification_steps", ""),
                )
                self.findings.add(finding)
            elif hasattr(cf, "primary_finding"):
                self.findings.add(cf.primary_finding)

        # ====== PHASE 4c: COVERAGE LOGGING ======
        self.log("PHASE 4c: Logging coverage gaps...", "INFO")
        self.coverage_analyzer.log_coverage_summary()
        coverage_report = self.coverage_analyzer.get_coverage_report()
        skipped_tools = sorted(
            {
                r.get("tool")
                for r in self.execution_results
                if r.get("status") == "SKIPPED" and r.get("tool")
            }
        )
        denied_tools = sorted(set(self.ledger.get_denied_tools()))
        missing_tools = []
        if self.tool_manager:
            for tool in sorted(
                set(
                    skipped_tools
                    + denied_tools
                    + coverage_report.get("blocked", {}).get("tools", [])
                )
            ):
                try:
                    if not self.tool_manager.check_tool_installed(tool):
                        missing_tools.append(tool)
                except Exception:
                    continue
        coverage_report["skipped"] = {"tools": skipped_tools}
        coverage_report["denied"] = {"tools": denied_tools}
        coverage_report["missing"] = {
            **coverage_report.get("missing", {}),
            "missing_tools": missing_tools,
        }
        coverage_report["manual_out_of_scope"] = self.manual_out_of_scope_report
        coverage_report["execution_quality"] = execution_quality
        coverage_report["ssl_consistency"] = ssl_consistency

        # Transfer findings from registry to proof reporter (before final report generation)
        for finding in self.findings.get_all():
            try:
                confidence = getattr(finding, "confidence", 0.0)
                if isinstance(confidence, str) and confidence in [
                    "HIGH",
                    "MEDIUM",
                    "LOW",
                ]:
                    confidence_map = {"HIGH": 0.85, "MEDIUM": 0.70, "LOW": 0.50}
                    confidence = confidence_map.get(confidence, 0.70)
                if not isinstance(confidence, (int, float)) or confidence <= 0:
                    sev = (
                        finding.severity.value
                        if hasattr(finding.severity, "value")
                        else str(finding.severity)
                    )
                    severity_confidence = {
                        "CRITICAL": 0.95,
                        "HIGH": 0.85,
                        "MEDIUM": 0.70,
                        "LOW": 0.50,
                        "INFO": 0.30,
                    }
                    confidence = severity_confidence.get(sev, 0.50)

                severity_str = (
                    finding.severity.value
                    if hasattr(finding.severity, "value")
                    else str(finding.severity)
                )
                finding_type = (
                    finding.type.value
                    if hasattr(finding.type, "value")
                    else str(finding.type)
                )

                endpoint = getattr(finding, "endpoint", "") or getattr(
                    finding, "url", self.target
                )
                param = getattr(finding, "parameter", "") or getattr(
                    finding, "param", ""
                )

                self.proof_reporter.add_confirmed_vulnerability(
                    vuln_type=finding_type,
                    severity=severity_str,
                    endpoint=endpoint,
                    parameter=param,
                    payload=getattr(finding, "payload", ""),
                    confirmation_method=ConfirmationMethod.DIRECT_EXPLOITATION,
                    confidence=confidence,
                    details={
                        "source": "scanner_finding",
                        "evidence": getattr(finding, "evidence", ""),
                        "cvss_score": getattr(finding, "cvss_score", 0),
                    },
                    remediation=getattr(finding, "remediation", ""),
                    impact=getattr(finding, "impact", ""),
                )
            except Exception as e:
                self.log(f"Could not add finding to proof reporter: {e}", "DEBUG")

        proof_report = self.generate_proof_based_final_report()
        phase5_risk_report = self._build_phase5_risk_report(proof_report)

        owasp_summary_for_report: dict[str, int] = {}
        for finding in self.findings.get_all():
            owasp_value = finding.owasp
            if isinstance(owasp_value, Enum):
                owasp_value = owasp_value.value
            owasp_key = str(owasp_value) if owasp_value else "Unmapped"
            owasp_summary_for_report[owasp_key] = (
                owasp_summary_for_report.get(owasp_key, 0) + 1
            )

        confirmed_summary = (
            proof_report.get("summary", {}) if isinstance(proof_report, dict) else {}
        )
        confirmed_severity = (
            confirmed_summary.get("by_severity", {})
            if isinstance(confirmed_summary, dict)
            else {}
        )
        findings_summary = {
            "critical": int(confirmed_severity.get("CRITICAL", 0)),
            "high": int(confirmed_severity.get("HIGH", 0)),
            "medium": int(confirmed_severity.get("MEDIUM", 0)),
            "low": int(confirmed_severity.get("LOW", 0)),
            "info": int(confirmed_severity.get("INFO", 0)),
            "total": int(confirmed_summary.get("total_confirmed", 0)),
            "owasp": owasp_summary_for_report,
            "confirmed_by_type": confirmed_summary.get("by_type", {}),
        }
        raw_severity_counts = self.findings.count_by_severity()
        raw_total_findings = len(self.findings.get_all())
        if findings_summary["total"] == 0 and raw_total_findings > 0:
            findings_summary["critical"] = int(
                raw_severity_counts.get(Severity.CRITICAL, 0)
            )
            findings_summary["high"] = int(raw_severity_counts.get(Severity.HIGH, 0))
            findings_summary["medium"] = int(
                raw_severity_counts.get(Severity.MEDIUM, 0)
            )
            findings_summary["low"] = int(raw_severity_counts.get(Severity.LOW, 0))
            findings_summary["info"] = int(raw_severity_counts.get(Severity.INFO, 0))
            findings_summary["total"] = raw_total_findings

        report = {
            "scan_status": self.scan_status,
            "abort_reason": self.abort_reason,
            "full_report": self.full_report,
            "profile": self.profile.to_dict(),
            "ledger": self.ledger.to_dict(),
            "plan": plan_serialized,
            "execution": self.execution_results,
            "category_summary": self._category_summary(),
            "outcome_summary": self._outcome_summary(),
            "findings": self.findings.to_dict(),  # NEW: Include normalized findings
            "discoveries": {
                "endpoints": len(self.cache.endpoints),
                "live_endpoints": len(self.cache.live_endpoints),
                "params": len(self.cache.params),
                "reflections": len(self.cache.reflections),
                "subdomains": len(self.cache.subdomains),
                "ports": len(self.cache.discovered_ports),
            },
            # Phase 1: Discovery completeness
            "discovery_completeness": (
                self.completeness_report.to_dict()
                if hasattr(self, "completeness_report")
                else {}
            ),
            # Phase 4: Deduplication report
            "deduplication": self.dedup_engine.get_deduplication_report(),
            # Phase 3: Payload attempts
            "payload_attempts": self.payload_strategy.get_attempts_summary(),
            # Phase 3: Payload outcomes
            "payload_outcomes": self.payload_tracker.get_summary(),
            # Phase 4: Coverage analysis
            "coverage": coverage_report,
            "enforcement": {
                "all_executed_in_ledger": True,
                "all_meta_present": True,
                "execution_order_documented": True,
            },
            "confidence": self._confidence_summary(),
            "timestamps": {
                "started": self.start_time.isoformat(),
                "finished": datetime.now().isoformat(),
            },
            # NEW: Intelligence analysis results
            "intelligence": intelligence_report,
            # Phase 4: Vulnerability-centric view
            "vulnerabilities": vulnerability_report,
            # Phase 4: Business risk aggregation
            "risk_aggregation": risk_report,
            # Phase 5: Proof-based confirmed exploitation findings
            "confirmed_exploitation": proof_report,
            # Phase 5: strict risk scoring from confirmed exploitation only
            "phase5_risk": phase5_risk_report,
            # Shared findings summary for parity with HTML
            "findings_summary": findings_summary,
            "service_fingerprints": self.service_fingerprints,
            "certificate_assessments": self.certificate_assessments,
            "host_network_assessment": self.host_network_assessment,
            "prioritized_subdomains": self.prioritized_subdomains,
            "js_discovery": self.js_discovery_summary,
            "multi_source_discovery": self.multi_source_summary,
            "js_asset_inventory": self.js_asset_inventory,
            "endpoint_inventory": self._build_endpoint_inventory_for_report(),
            "api_endpoint_candidates": self._build_api_candidate_inventory(),
            "high_value_targets": self._build_high_value_targets(),
            "parameter_inventory": sorted(
                list(self.param_inventory.values()), key=lambda x: x.get("name", "")
            ),
            "zap_discovery": self.zap_discovery_summary,
            "api_schema": self.api_schema_summary,
            "discovery_quality": self.discovery_quality,
            "auth_access_control": self.auth_access_control_summary,
            "request_context": self.request_context.summary(),
            "manual_out_of_scope": self.manual_out_of_scope_report,
            "execution_quality": execution_quality,
            "ssl_consistency": ssl_consistency,
        }

        report_file = self.output_dir / "execution_report.json"
        with report_file.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        # NEW: Generate HTML report
        try:
            html_file = self.output_dir / "security_report.html"

            severity_counts = self.findings.count_by_severity()
            owasp_summary: dict[str, int] = {}
            for finding in self.findings.get_all():
                owasp_value = finding.owasp
                if isinstance(owasp_value, Enum):
                    owasp_value = owasp_value.value
                owasp_key = str(owasp_value) if owasp_value else "Unmapped"
                owasp_summary[owasp_key] = owasp_summary.get(owasp_key, 0) + 1

            discovery_lists = self._build_discovery_detail_lists()
            endpoint_inventory = self._build_endpoint_inventory_for_report()
            api_candidates = self._build_api_candidate_inventory()
            high_value_targets = self._build_high_value_targets()
            endpoints_with_params = len(
                [r for r in endpoint_inventory if r.get("has_params")]
            )
            exploitable_candidates = len(
                [r for r in high_value_targets if int(r.get("priority", 99)) <= 2]
            )
            endpoint_confidence_counts = self._build_endpoint_confidence_counts()
            api_doc_exposure = self._build_api_doc_exposure()
            service_focus_tracks = self._build_service_focus_tracks()
            residual_risks = self._build_residual_risk_statements()
            tech_stack = self._extract_tech_stack_summary()

            skipped_tools = sorted(
                {
                    r.get("tool")
                    for r in self.execution_results
                    if r.get("status") == "SKIPPED" and r.get("tool")
                }
            )
            blocked_tools = sorted(
                {
                    r.get("tool")
                    for r in self.execution_results
                    if r.get("status") == "BLOCKED" and r.get("tool")
                }
            )
            denied_tools = sorted(set(self.ledger.get_denied_tools()))
            missing_tools = []
            if self.tool_manager:
                for tool in sorted(set(skipped_tools + blocked_tools + denied_tools)):
                    try:
                        if not self.tool_manager.check_tool_installed(tool):
                            missing_tools.append(tool)
                    except Exception:
                        continue

            discovery_summary = {
                "scan_status": self.scan_status,
                "abort_reason": self.abort_reason,
                "target_host": self.profile.host,
                "endpoints": len(self.cache.endpoints),
                "live_endpoints": len(self.cache.live_endpoints),
                "params": len(self.cache.params),
                "command_params": len(self.cache.command_params),
                "ssrf_params": len(self.cache.ssrf_params),
                "reflections": len(self.cache.reflections),
                "subdomains": len(self.cache.subdomains),
                "ports": len(self.cache.discovered_ports),
                "target_ips": list(getattr(self.profile, "resolved_ips", []) or []),
                "detected_os": getattr(self.profile, "detected_os", None),
                "tech_stack": tech_stack,
                "skipped_tools": skipped_tools,
                "blocked_tools": blocked_tools,
                "denied_tools": denied_tools,
                "missing_tools": missing_tools,
                "manual_out_of_scope": self.manual_out_of_scope_report,
                "execution_quality": execution_quality,
                "ssl_consistency": ssl_consistency,
                "js_endpoints": self.js_discovery_summary.get("endpoints", 0),
                "js_api_endpoints": self.js_discovery_summary.get("api_endpoints", 0),
                "js_network_requests": self.js_discovery_summary.get(
                    "network_requests", 0
                ),
                "zap_endpoints": self.zap_discovery_summary.get("endpoints", 0),
                "zap_params": self.zap_discovery_summary.get("params", 0),
                "api_schema_endpoints": self.api_schema_summary.get("endpoints", 0),
                "api_schema_params": self.api_schema_summary.get("params", 0),
                "discovery_quality_score": self.discovery_quality.get("score", 0),
                "discovery_quality_status": self.discovery_quality.get(
                    "status", "UNKNOWN"
                ),
                "auth_roles": len(
                    self.auth_access_control_summary.get("authenticated_roles", [])
                ),
                "idor_findings": self.auth_access_control_summary.get(
                    "idor_findings", 0
                ),
                "access_control_findings": self.auth_access_control_summary.get(
                    "access_control_findings", 0
                ),
                "full_report": self.full_report,
                "endpoint_inventory": endpoint_inventory,
                "api_endpoint_candidates": api_candidates,
                "high_value_targets": high_value_targets,
                "js_asset_inventory": self.js_asset_inventory,
                "parameter_inventory": sorted(
                    list(self.param_inventory.values()), key=lambda x: x.get("name", "")
                ),
                "summary_metrics": {
                    "total_endpoints": len(endpoint_inventory),
                    "api_endpoints": len(api_candidates),
                    "endpoints_with_params": endpoints_with_params,
                    "exploitable_candidates": exploitable_candidates,
                    "testable_params": len(
                        [
                            p
                            for p in self.cache.params
                            if self._is_testable_param_name(p)
                        ]
                    ),
                },
                "endpoint_confidence_counts": endpoint_confidence_counts,
                "api_doc_exposure": api_doc_exposure,
                "service_focus_tracks": service_focus_tracks,
                "residual_risks": residual_risks,
                **discovery_lists,
            }

            findings_summary = {
                "critical": int(confirmed_severity.get("CRITICAL", 0)),
                "high": int(confirmed_severity.get("HIGH", 0)),
                "medium": int(confirmed_severity.get("MEDIUM", 0)),
                "low": int(confirmed_severity.get("LOW", 0)),
                "info": int(confirmed_severity.get("INFO", 0)),
                "total": int(confirmed_summary.get("total_confirmed", 0)),
                "owasp": owasp_summary,
                "confirmed_by_type": confirmed_summary.get("by_type", {}),
            }
            if findings_summary["total"] == 0 and self.findings.get_all():
                findings_summary["critical"] = int(severity_counts.get("CRITICAL", 0))
                findings_summary["high"] = int(severity_counts.get("HIGH", 0))
                findings_summary["medium"] = int(severity_counts.get("MEDIUM", 0))
                findings_summary["low"] = int(severity_counts.get("LOW", 0))
                findings_summary["info"] = int(severity_counts.get("INFO", 0))
                findings_summary["total"] = len(self.findings.get_all())

            HTMLReportGenerator.generate(
                target=self.profile.host,
                correlation_id=self.correlation_id,
                scan_date=self.start_time.strftime("%Y-%m-%d %H:%M:%S"),
                correlated_findings=correlated_findings,
                intelligence_report=intelligence_report,
                vulnerability_report=vulnerability_report,
                risk_report=risk_report,
                coverage_report=coverage_report,
                discovery_summary=discovery_summary,
                findings_summary=findings_summary,
                security_strengths=self._collect_security_strengths(),
                confirmed_exploitation=proof_report,
                service_fingerprints=self.service_fingerprints,
                certificate_assessments=self.certificate_assessments,
                host_network_assessment=self.host_network_assessment,
                prioritized_subdomains=self.prioritized_subdomains,
                auth_access_control_summary=self.auth_access_control_summary,
                output_path=html_file,
            )
            self.log(f"HTML report generated: {html_file}", "SUCCESS")
        except Exception as e:
            self.log(f"HTML report generation failed: {e}", "WARN")

        # Human-friendly findings summary
        self._write_findings_summary()

        self.log(f"Report saved: {report_file}", "SUCCESS")

    def _write_findings_summary(self) -> None:
        """Emit a readable findings report with OWASP mapping, deduplication, and OWASP grouping."""
        summary_file = self.output_dir / "findings_summary.txt"
        lines: list[str] = []
        lines.append("=" * 80)
        lines.append(
            "FINDINGS SUMMARY (Deduplicated, OWASP-Mapped, High-Confidence Only)"
        )
        lines.append("=" * 80)

        all_findings = self.findings.get_all()
        severity_counts = self.findings.count_by_severity()

        # Discovery summary first (requested high-level generic context)
        lines.append("\nDISCOVERY SUMMARY")
        lines.append("-" * 80)
        lines.append(
            "Endpoints: {endpoints}, Live: {live}, Params: {params}, CmdParams: {cmd}, "
            "SSRFParams: {ssrf}, Reflections: {refl}, Subdomains: {sub}, Ports: {ports}".format(
                endpoints=len(self.cache.endpoints),
                live=len(self.cache.live_endpoints),
                params=len(self.cache.params),
                cmd=len(self.cache.command_params),
                ssrf=len(self.cache.ssrf_params),
                refl=len(self.cache.reflections),
                sub=len(self.cache.subdomains),
                ports=len(self.cache.discovered_ports),
            )
        )

        # Explicit OWASP visibility
        owasp_counts: dict[str, int] = {}
        for finding in all_findings:
            owasp_value = finding.owasp
            if isinstance(owasp_value, Enum):
                owasp_value = owasp_value.value
            key = str(owasp_value) if owasp_value else "Unmapped"
            owasp_counts[key] = owasp_counts.get(key, 0) + 1

        lines.append("\nOWASP CATEGORY SUMMARY")
        lines.append("-" * 80)
        if owasp_counts:
            for category, count in sorted(
                owasp_counts.items(), key=lambda item: (-item[1], item[0])
            ):
                lines.append(f"- {category}: {count}")
        else:
            lines.append("- No OWASP-mapped findings available.")

        # Filter: suppress LOW/INFO in detailed body unless requested elsewhere
        findings = [
            f
            for f in all_findings
            if f.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
        ]

        lines.append("\nDETAILED FINDINGS (CRITICAL/HIGH/MEDIUM)")
        lines.append("-" * 80)
        if not findings:
            lines.append(
                "No findings detected above medium severity (or all were filtered as noise)."
            )
        else:
            by_owasp: dict[str, list[Finding]] = {}
            for finding in findings:
                owasp_value = finding.owasp
                if isinstance(owasp_value, Enum):
                    owasp_value = owasp_value.value
                owasp_key = str(owasp_value) if owasp_value else "Unmapped"
                by_owasp.setdefault(owasp_key, []).append(finding)

            for owasp_cat in sorted(by_owasp.keys()):
                lines.append(f"\n[{owasp_cat}]")
                cat_findings = by_owasp[owasp_cat]

                crit = [f for f in cat_findings if f.severity == Severity.CRITICAL]
                high = [f for f in cat_findings if f.severity == Severity.HIGH]
                med = [f for f in cat_findings if f.severity == Severity.MEDIUM]

                for severity, group in [
                    (Severity.CRITICAL, crit),
                    (Severity.HIGH, high),
                    (Severity.MEDIUM, med),
                ]:
                    if group:
                        lines.append(f"  {severity.value}:")
                        for finding in group:
                            lines.append(
                                f"    - {finding.type.value}: {finding.description}"
                            )
                            lines.append(f"      Location: {finding.location}")
                            if finding.cwe:
                                cwe_val = str(finding.cwe)
                                if cwe_val.upper().startswith("CWE-"):
                                    lines.append(f"      {cwe_val}")
                                else:
                                    lines.append(f"      CWE-{cwe_val}")

        lines.append("\nSUPPRESSED FINDINGS OVERVIEW (LOW/INFO)")
        lines.append("-" * 80)
        lines.append(
            f"LOW: {severity_counts.get(Severity.LOW, 0)}, "
            f"INFO: {severity_counts.get(Severity.INFO, 0)}"
        )

        suppressed = [
            f for f in all_findings if f.severity in {Severity.LOW, Severity.INFO}
        ][:5]
        if suppressed:
            lines.append("Sample entries:")
            for finding in suppressed:
                lines.append(
                    f"  - {finding.severity.value}: {finding.type.value} @ {finding.location}"
                )

        lines.append("\n" + "=" * 80)
        lines.append(
            "Summary: {critical} CRITICAL, {high} HIGH, {medium} MEDIUM, {low} LOW, {info} INFO".format(
                critical=severity_counts.get(Severity.CRITICAL, 0),
                high=severity_counts.get(Severity.HIGH, 0),
                medium=severity_counts.get(Severity.MEDIUM, 0),
                low=severity_counts.get(Severity.LOW, 0),
                info=severity_counts.get(Severity.INFO, 0),
            )
        )
        lines.append("(LOW and INFO findings suppressed. Use --verbose to see all.)")
        lines.append("=" * 80)

        summary_file.write_text("\n".join(lines), encoding="utf-8")

    def _category_summary(self) -> dict:
        summary: dict[str, dict[str, int]] = {}
        for r in self.execution_results:
            cat = r["category"]
            summary.setdefault(cat, {"success": 0, "failed": 0})
            if r["status"] == "SUCCESS":
                summary[cat]["success"] += 1
            else:
                summary[cat]["failed"] += 1
        return summary

    def _outcome_summary(self) -> dict:
        summary: dict[str, dict[str, int]] = {}
        for r in self.execution_results:
            cat = r["category"]
            outcome = r["outcome"]
            summary.setdefault(cat, {})
            summary[cat].setdefault(outcome, 0)
            summary[cat][outcome] += 1
        return summary

    def _confidence_summary(self) -> dict:
        confidence: dict[str, dict[str, float | str]] = {}
        for cat, stats in self._category_summary().items():
            total = stats["success"] + stats["failed"]
            ratio = stats["success"] / total if total else 0.0
            if ratio >= 0.75:
                level = "high"
            elif ratio >= 0.4:
                level = "medium"
            else:
                level = "low"
            confidence[cat] = {
                "success_ratio": round(ratio, 2),
                "level": level,
            }
        return confidence

    # ============================================================================
    # PHASE 5: ACTIVE EXPLOITATION AND PROOF-BASED VALIDATION
    # ============================================================================

    def initialize_exploitation_engines(self) -> bool:
        """
        Initialize all exploitation engines for active vulnerability testing

        Returns: True if initialization successful, False otherwise
        """
        try:
            self.log("Initializing exploitation engines...", "INFO")

            # Start OOB callback server (required for blind vulnerability detection)
            if not self.oob_system.start_callback_server():
                self.log("Warning: OOB callback server failed to start", "WARN")
            else:
                self.log(
                    f"OOB callback server started on {self.oob_system.external_ip}:{self.oob_system.port}",
                    "SUCCESS",
                )

            # Initialize exploitation engines with shared diffing engine
            self.ssrf_engine = SSRFExploitationEngine(
                response_diffing_engine=self.response_diffing,
                oob_system=self.oob_system,
            )

            self.xss_engine = XSSExploitationEngine(
                response_diffing_engine=self.response_diffing,
                fuzzing_engine=self.fuzzing_engine,
            )

            self.sqli_engine = SQLinjectionEngine(
                response_diffing_engine=self.response_diffing,
                fuzzing_engine=self.fuzzing_engine,
            )

            self.log("All exploitation engines initialized", "SUCCESS")
            return True

        except Exception as e:
            self.log(f"Error initializing exploitation engines: {e}", "ERROR")
            return False

    def run_active_exploitation(
        self, base_url: str, endpoints: Optional[List[Dict]] = None
    ) -> List[Dict]:
        """
        Run active exploitation against discovered endpoints

        Args:
            base_url: Base URL of target (scheme + host)
            endpoints: List of discovered endpoints from crawler (optional)

        Returns: List of exploitation results
        """
        self.log(
            "PHASE 5: ACTIVE EXPLOITATION - Attempting to validate vulnerabilities with proof",
            "INFO",
        )

        exploitation_results = []
        tested_vectors = 0

        # Endpoints can come from graph or fallback cache-derived targets.
        if endpoints:
            endpoints_to_test = endpoints
        elif self.endpoint_graph and self.endpoint_graph.endpoints:
            endpoints_to_test = self.endpoint_graph.endpoints
        else:
            endpoints_to_test = self._build_fallback_endpoints_for_exploitation()

        if not endpoints_to_test:
            self.log("No endpoints discovered - skipping active exploitation", "WARN")
            return []

        self.log(
            f"Testing {len(endpoints_to_test)} endpoint(s) for active vulnerabilities...",
            "INFO",
        )

        # Create per-role sessions for role-segmented exploitation attempts.
        import requests

        role_sessions: Dict[str, requests.Session] = {}
        for role in self.request_context.active_roles(include_anonymous=True):
            role_session = requests.Session()
            role_session.headers.update(
                {"User-Agent": "VAPT-Automated-Engine/1.0 (Vulnerability Assessment)"}
            )
            if role != "anonymous":
                role_headers = self.request_context.build_headers(role)
                role_session.headers.update(role_headers)
            role_sessions[role] = role_session

        # Test each endpoint
        for endpoint_obj in endpoints_to_test[:10]:  # Limit to top 10 to avoid timeout
            endpoint = (
                endpoint_obj.get("url")
                if isinstance(endpoint_obj, dict)
                else str(endpoint_obj)
            )
            params = (
                endpoint_obj.get("params", []) if isinstance(endpoint_obj, dict) else []
            )
            method = (
                endpoint_obj.get("method", "GET").upper()
                if isinstance(endpoint_obj, dict)
                else "GET"
            )

            endpoint_key = self._normalize_endpoint_path(endpoint)
            endpoint_item = self.endpoint_inventory.get(
                endpoint_key,
                {
                    "classification": self._classify_endpoint(endpoint_key),
                    "sources": ["unknown"],
                },
            )
            if not self._should_feed_exploitation(endpoint_key, endpoint_item):
                self.log(
                    f"Skipping {endpoint}: endpoint tier not eligible for exploitation",
                    "DEBUG",
                )
                continue

            self.log(
                f"Testing {endpoint} ({method}) with {len(params)} parameter(s)", "INFO"
            )

            raw_params = []
            for param in params:
                if isinstance(param, dict):
                    raw_params.append(
                        {
                            "name": str(param.get("name", "")),
                            "source": str(param.get("source", "url_param")),
                            "value": str(param.get("value", "")),
                        }
                    )
                else:
                    raw_params.append(
                        {"name": str(param), "source": "url_param", "value": ""}
                    )

            # Wave 1: classify and gate parameters before exploitation.
            classified_params = classify_parameters(
                endpoint=endpoint, method=method, params=raw_params
            )
            controllable_params = filter_controllable(classified_params)
            confirmed_params = [p for p in controllable_params if p.confidence >= 0.70]
            potential_params = [
                p for p in controllable_params if 0.35 <= p.confidence < 0.70
            ]
            unknown_params = [p for p in classified_params if p.confidence < 0.35]

            params_to_test = confirmed_params[:3]
            attack_mode = "full"
            if not params_to_test and potential_params:
                params_to_test = potential_params[:3]
                attack_mode = "light"
            if not params_to_test and unknown_params:
                params_to_test = unknown_params[:2]
                attack_mode = "low"

            if not params_to_test:
                # URL-based low-confidence fallback keeps exploitation best-effort.
                fallback_name = "q"
                params_to_test = [
                    type(
                        "ParamLite",
                        (),
                        {
                            "name": fallback_name,
                            "confidence": 0.2,
                            "exploitability_score": 0.3,
                        },
                    )()
                ]
                attack_mode = "url"

            self.log(
                f"{endpoint}: mode={attack_mode}, confirmed={len(confirmed_params)}, potential={len(potential_params)}, unknown={len(unknown_params)}",
                "DEBUG",
            )

            for param_obj in params_to_test:
                param_name = param_obj.name
                if self._should_skip_parameter(param_name):
                    self.log(f"Skipping {param_name}: static filter matched", "DEBUG")
                    continue

                for role, session in role_sessions.items():
                    # Try SSRF exploitation
                    try:
                        tested_vectors += 1
                        self.proof_reporter.register_test_attempt(1)
                        ssrf_findings = self.ssrf_engine.exploit_ssrf_findings(
                            endpoint=endpoint,
                            parameter=param_name,
                            base_url=base_url,
                            http_method=method,
                            session=session,
                        )
                        for finding in ssrf_findings:
                            finding_dict = finding.to_exploitation_dict()
                            finding_dict["role"] = role
                            finding_dict["attack_mode"] = attack_mode
                            finding_dict["discovery_sources"] = (
                                self.endpoint_inventory.get(
                                    self._normalize_endpoint_path(endpoint), {}
                                ).get("sources", ["unknown"])
                            )
                            exploitation_results.append(finding_dict)
                            self._ingest_exploitation_feedback(finding_dict)
                            self.proof_reporter.add_from_exploitation_result(finding)
                    except Exception as e:
                        self.log(f"SSRF exploitation error: {e}", "DEBUG")

                    # Try XSS exploitation
                    try:
                        tested_vectors += 1
                        self.proof_reporter.register_test_attempt(1)
                        xss_findings = self.xss_engine.exploit_xss_findings(
                            endpoint=endpoint,
                            parameter=param_name,
                            base_url=base_url,
                            http_method=method,
                            session=session,
                        )
                        for finding in xss_findings:
                            finding_dict = finding.to_exploitation_dict()
                            finding_dict["role"] = role
                            finding_dict["attack_mode"] = attack_mode
                            finding_dict["discovery_sources"] = (
                                self.endpoint_inventory.get(
                                    self._normalize_endpoint_path(endpoint), {}
                                ).get("sources", ["unknown"])
                            )
                            exploitation_results.append(finding_dict)
                            self._ingest_exploitation_feedback(finding_dict)
                            self.proof_reporter.add_from_exploitation_result(finding)
                    except Exception as e:
                        self.log(f"XSS exploitation error: {e}", "DEBUG")

                    # Try SQL injection exploitation
                    try:
                        tested_vectors += 1
                        self.proof_reporter.register_test_attempt(1)
                        sqli_findings = self.sqli_engine.exploit_sqli_findings(
                            endpoint=endpoint,
                            parameter=param_name,
                            base_url=base_url,
                            http_method=method,
                            session=session,
                        )
                        for finding in sqli_findings:
                            finding_dict = finding.to_exploitation_dict()
                            finding_dict["role"] = role
                            finding_dict["attack_mode"] = attack_mode
                            finding_dict["discovery_sources"] = (
                                self.endpoint_inventory.get(
                                    self._normalize_endpoint_path(endpoint), {}
                                ).get("sources", ["unknown"])
                            )
                            exploitation_results.append(finding_dict)
                            self._ingest_exploitation_feedback(finding_dict)
                            self.proof_reporter.add_from_exploitation_result(finding)
                    except Exception as e:
                        self.log(f"SQLi exploitation error: {e}", "DEBUG")

        # Wait for OOB callbacks
        self.log("Waiting for out-of-band callbacks (5 seconds)...", "INFO")
        import time

        time.sleep(5)

        # Check OOB callbacks
        oob_confirmed = self.ssrf_engine.check_oob_callbacks()
        for oob_finding in oob_confirmed:
            exploitation_results.append(oob_finding)
            self._ingest_exploitation_feedback(oob_finding)
            self.proof_reporter.add_from_exploitation_result(oob_finding)

        self.log(
            f"Exploitation phase complete: {len(exploitation_results)} vulnerabilities found",
            "INFO",
        )
        self.log(f"Exploitation vectors tested: {tested_vectors}", "INFO")

        return exploitation_results

    def _ingest_exploitation_feedback(self, finding: Dict[str, Any]) -> None:
        """Feed newly confirmed endpoint/param signals back into discovery cache/graph."""
        endpoint = str(finding.get("endpoint") or finding.get("location") or "").strip()
        parameter = str(finding.get("parameter") or "").strip()

        if endpoint:
            self._register_endpoint(
                endpoint,
                source="exploitation_feedback",
                confidence=1.0,
                is_live=True,
                param_source="url",
            )
            self.cache.add_live_endpoint(endpoint, source_tool="exploitation_feedback")
        if parameter:
            self._register_param(
                parameter, source="exploitation_feedback", endpoint=endpoint
            )

        if self.endpoint_graph and endpoint:
            try:
                method = str(finding.get("method") or "GET").upper()
                self.endpoint_graph.add_endpoint(
                    endpoint, [parameter] if parameter else [], method
                )
            except Exception:
                pass

    def _build_phase5_risk_report(self, proof_report: Dict[str, Any]) -> Dict[str, Any]:
        """Run strict risk scoring only on confirmed exploitation findings."""
        risk_engine = RiskEngine()

        def _fallback_owasp_from_type(vuln_type: str) -> str:
            low = str(vuln_type or "").lower()
            if "misconfiguration" in low:
                return "A05_SECURITY_MISCONFIGURATION"
            if "crypto" in low or "tls" in low or "cipher" in low:
                return "A02_CRYPTOGRAPHIC_FAILURES"
            if "info" in low or "disclosure" in low:
                return "A09_LOGGING_MONITORING_FAILURES"
            if "auth" in low or "idor" in low or "access" in low:
                return "A01_BROKEN_ACCESS_CONTROL"
            if "ssrf" in low:
                return "A10_SSRF"
            if "xss" in low or "sql" in low or "inject" in low:
                return "A03_INJECTION"
            return "A05_SECURITY_MISCONFIGURATION"

        findings = (
            proof_report.get("findings", []) if isinstance(proof_report, dict) else []
        )
        for finding in findings:
            try:
                proof = finding.get("proof") or {}
                confidence = float(
                    proof.get("confidence", finding.get("confidence", 0.0)) or 0.0
                )
                vuln_type = str(finding.get("type", "UNKNOWN"))
                owasp_category = str(finding.get("owasp") or "")
                if not owasp_category:
                    owasp_category = _fallback_owasp_from_type(vuln_type)
                sanitized_owasp = owasp_category.split(":", 1)[0].replace("-", "_")
                if sanitized_owasp.startswith("A10"):
                    sanitized_owasp = "A10_SSRF"
                elif sanitized_owasp.startswith("A01"):
                    sanitized_owasp = "A01_BROKEN_ACCESS_CONTROL"
                elif sanitized_owasp.startswith("A07"):
                    sanitized_owasp = "A07_AUTH_FAILURES"
                elif sanitized_owasp.startswith("A03"):
                    sanitized_owasp = "A03_INJECTION"
                elif sanitized_owasp not in {
                    "A01_BROKEN_ACCESS_CONTROL",
                    "A02_CRYPTOGRAPHIC_FAILURES",
                    "A03_INJECTION",
                    "A04_INSECURE_DESIGN",
                    "A05_SECURITY_MISCONFIGURATION",
                    "A06_VULNERABLE_COMPONENTS",
                    "A07_AUTH_FAILURES",
                    "A08_DATA_INTEGRITY_FAILURES",
                    "A09_LOGGING_MONITORING_FAILURES",
                    "A10_SSRF",
                }:
                    sanitized_owasp = "A03_INJECTION"

                risk_engine.calculate_risk(
                    endpoint=str(finding.get("endpoint", "")),
                    parameter=str(finding.get("parameter", "")),
                    vulnerability_type=vuln_type,
                    owasp_category=sanitized_owasp,
                    confidence_score=confidence,
                    corroboration_count=1,
                    tools=["exploitation_engine"],
                    payload_success_rate=max(0.2, min(confidence, 1.0)),
                    privilege_level=str(finding.get("role", "UNAUTHENTICATED")).upper(),
                )
            except Exception:
                continue

        risk_report = risk_engine.to_dict()

        # Keep phase5 risk severity aligned with proof-based confirmed severities.
        severity_by_key: Dict[tuple[str, str, str], str] = {}
        for finding in findings:
            key = (
                str(finding.get("endpoint", "")),
                str(finding.get("parameter", "")),
                str(finding.get("type", "UNKNOWN")),
            )
            severity_by_key[key] = str(finding.get("severity", "INFO")).upper()

        by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for row in risk_report.get("findings", []):
            key = (
                str(row.get("endpoint", "")),
                str(row.get("parameter", "")),
                str(row.get("vulnerability_type", "UNKNOWN")),
            )
            aligned = severity_by_key.get(key, str(row.get("risk_severity", "INFO")).upper())
            row["risk_severity"] = aligned
            by_severity[aligned] = by_severity.get(aligned, 0) + 1

        summary = risk_report.get("summary", {})
        summary["by_severity"] = by_severity
        summary["total_findings"] = len(risk_report.get("findings", []))
        risk_report["summary"] = summary
        return risk_report

    def _build_fallback_endpoints_for_exploitation(self) -> List[Dict]:
        """Build minimal endpoint/param targets from discovery cache when crawler graph is unavailable."""
        fallback_targets: List[Dict] = []
        if not self.cache:
            return fallback_targets

        endpoints = sorted(self.cache.live_endpoints or self.cache.endpoints)
        if not endpoints:
            return fallback_targets

        params = sorted(
            [p for p in self.cache.params if self._is_testable_param_name(p)]
        )
        if not params:
            params = sorted(
                [
                    name
                    for name in self.param_inventory.keys()
                    if self._is_testable_param_name(name)
                ]
            )
        if not params:
            params = ["id", "q"]

        for endpoint in endpoints[:10]:
            endpoint_param_rows = self.param_sources_by_endpoint.get(endpoint, [])
            endpoint_params = [
                r.get("name") for r in endpoint_param_rows if r.get("name")
            ] or params[:5]
            fallback_targets.append(
                {
                    "url": endpoint,
                    "method": "GET",
                    "params": [
                        {"name": p, "source": "url_param"} for p in endpoint_params[:5]
                    ],
                }
            )

        return fallback_targets

    def _should_skip_parameter(self, param_name: str) -> bool:
        """
        PHASE 3: Strict parameter filtering
        Skip non-user-controllable parameters to reduce false positives

        Returns: True if parameter should be skipped, False if should be tested
        """
        # SKIP: External intelligence parameters (metadata, not user input)
        skip_prefixes = [
            "external_intel_",  # CRTSH, ASN, etc - read-only data
            "crawler_",  # Crawler-generated, not real params
            "static_",  # Static/readonly
            "config_",  # Configuration params
            "cache_",  # Cache parameters
            "tech_",  # Fingerprinting metadata
            "framework_",  # Technology metadata
            "js_",  # JS library metadata
            "service_",  # Service fingerprint metadata
            "fingerprint_",  # Fingerprint metadata
        ]

        for prefix in skip_prefixes:
            if param_name.lower().startswith(prefix):
                return True

        # SKIP: WordPress/form-builder and crawler noise parameters.
        if re.match(r"^form_fields\[[^\]]+\]$", param_name, re.IGNORECASE):
            return True
        if param_name.lower().startswith("form_"):
            return True

        # SKIP: Tracking/analytics-like parameter patterns.
        if re.match(r"^(utm_|ga_|fbclid$|gclid$|msclkid$)", param_name, re.IGNORECASE):
            return True

        # SKIP: Known static parameters
        skip_params = {
            "utm_source",
            "utm_medium",
            "utm_campaign",  # Analytics
            "utm_term",
            "utm_content",  # Analytics extension
            "fbclid",
            "gclid",
            "msclkid",  # Tracking IDs
            "ref",
            "referrer",  # Referrers
            "timestamp",
            "nonce",
            "state",  # Tokens/state
            "callback",  # Callbacks (legitimate use)
            "format",
            "type",  # Format params
            "lang",
            "language",
            "locale",  # Localization
            "version",
            "v",  # Version params
            "post_id",
            "form_id",
            "referer_title",  # WP form metadata
            "queried_id",  # WP query metadata
            "tech_lang_asp.net",
            "tech_server_nginx",  # known metadata artifacts
        }

        if param_name.lower() in skip_params:
            return True

        # Otherwise: INCLUDE this parameter for testing
        return False

    def _build_hosts_for_infra_assessment(self) -> List[str]:
        """Build host list for per-host port scan, service fingerprinting, and TLS checks."""
        hosts = {self.profile.host}
        discovered = sorted(self.cache.subdomains) if self.cache else []
        if discovered and self.cache:
            try:
                hosts.update(self.cache.verify_subdomains(discovered))
            except Exception:
                hosts.update(discovered)
        return sorted(h for h in hosts if h)

    def _scan_common_ports(self, host: str) -> List[int]:
        """Perform a lightweight TCP connect scan on common service ports."""
        common_ports = [
            21,
            22,
            25,
            53,
            80,
            110,
            143,
            443,
            465,
            587,
            993,
            995,
            3306,
            5432,
            6379,
            8080,
            8081,
            8443,
            9000,
            9200,
            27017,
        ]

        open_ports: List[int] = []
        for port in common_ports:
            try:
                with socket.create_connection((host, port), timeout=0.6):
                    open_ports.append(port)
            except Exception:
                continue
        return sorted(open_ports)

    def run_service_fingerprinting(self) -> List[Dict]:
        """Run per-host port scan + service fingerprinting + certificate checks."""
        try:
            hosts = self._build_hosts_for_infra_assessment()
            self.log(
                f"Running per-host infra assessment on {len(hosts)} host(s): port scan + service fingerprint + TLS checks",
                "INFO",
            )

            all_fingerprints: List[Dict] = []
            all_cert_checks: List[Dict] = []
            host_rows: List[Dict] = []

            for host in hosts:
                open_ports = self._scan_common_ports(host)
                for port in open_ports:
                    self.cache.add_port(port)

                fingerprint_ports = open_ports or [80, 443, 8080, 8081]
                host_fingerprints = self.fingerprint_engine.fingerprint_port_range(
                    host,
                    fingerprint_ports,
                    use_common_only=False,
                )
                host_fp_dicts = [fp.to_dict() for fp in host_fingerprints]
                all_fingerprints.extend(host_fp_dicts)

                tls_ports = [p for p in open_ports if p in {443, 8443}] or [443]
                host_cert_checks = self.certificate_checker.check_host(host, tls_ports)
                all_cert_checks.extend(host_cert_checks)

                host_rows.append(
                    {
                        "host": host,
                        "open_ports": open_ports,
                        "fingerprints": host_fp_dicts,
                        "certificate_checks": host_cert_checks,
                    }
                )

                self.log(
                    f"[{host}] open_ports={len(open_ports)} fingerprints={len(host_fp_dicts)} cert_checks={len(host_cert_checks)}",
                    "INFO",
                )

            self.host_network_assessment = host_rows
            self.service_fingerprints = all_fingerprints
            self.certificate_assessments = all_cert_checks

            self.log(
                f"Infrastructure assessment complete: hosts={len(hosts)}, fingerprints={len(self.service_fingerprints)}, cert_checks={len(self.certificate_assessments)}",
                "INFO",
            )
            return self.service_fingerprints
        except Exception as e:
            self.log(f"Infrastructure assessment failed: {e}", "WARN")
            self.service_fingerprints = []
            self.certificate_assessments = []
            self.host_network_assessment = []
            return []

    def prioritize_subdomain_targets(self) -> List[Dict]:
        """
        Prioritize discovered subdomains for assessment

        Returns: Ordered list of high-priority targets
        """
        if not self.cache or not self.cache.subdomains:
            return []

        self.log("Prioritizing discovered subdomains by attack surface...", "INFO")

        fp_by_host: Dict[str, List[Dict]] = {}
        for fp in self.service_fingerprints:
            fp_by_host.setdefault(fp.get("host", ""), []).append(fp)

        for subdomain in self.cache.subdomains:
            # Analyze subdomain characteristics
            param_count = len(self.cache.params)
            host_fps = fp_by_host.get(subdomain, [])
            tech_stack: List[str] = []
            open_ports: List[int] = []
            for host_fp in host_fps:
                tech_stack.extend(host_fp.get("technology_stack", []) or [])
                if host_fp.get("port"):
                    open_ports.append(int(host_fp["port"]))

            self.subdomain_prioritizer.add_subdomain(
                subdomain=subdomain,
                parameter_count=param_count,
                has_auth=False,  # TODO: detect from cache/auth adapter
                tech_stack=sorted(set(tech_stack)),
                open_ports=sorted(set(open_ports)),
            )

        # Get prioritized list
        recommendations = self.subdomain_prioritizer.recommend_attack_order()

        if recommendations:
            self.log(f"Top priority targets (by attack surface):", "INFO")
            for i, rec in enumerate(recommendations[:5], 1):
                self.log(
                    f"  {i}. {rec['subdomain']} (score: {rec['score']:.1f}) - {rec['reason']}",
                    "INFO",
                )

        return recommendations

    def generate_proof_based_final_report(self) -> Dict:
        """
        Generate final report showing ONLY confirmed vulnerabilities with proof

        Returns: Report dict with confirmed findings only
        """
        self.log("Generating proof-based vulnerability report...", "INFO")

        report = self.proof_reporter.generate_report()

        # Log summary
        self.log(
            f"FINAL REPORT: {report['summary']['total_confirmed']} confirmed vulnerabilities",
            "INFO",
        )

        if report["statistics"]["critical"] > 0:
            self.log(f"  🔴 CRITICAL: {report['statistics']['critical']}", "ERROR")
        if report["statistics"]["high"] > 0:
            self.log(f"  🔴 HIGH: {report['statistics']['high']}", "WARN")
        if report["statistics"]["medium"] > 0:
            self.log(f"  🟡 MEDIUM: {report['statistics']['medium']}", "INFO")
        if report["statistics"]["low"] > 0:
            self.log(f"  🟢 LOW: {report['statistics']['low']}", "INFO")

        return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Architecture-driven security scanner v2"
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Target domain or URL (optional if using --check-tools, --install-missing, or --install-interactive)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output directory",
        default=None,
    )
    parser.add_argument(
        "--skip-install",
        action="store_true",
        help="Skip tool installation checks",
    )
    parser.add_argument(
        "--install-missing",
        action="store_true",
        help="Auto-install all missing tools non-interactively, then scan target",
    )
    parser.add_argument(
        "--install-interactive",
        action="store_true",
        help="Interactively install missing tools, then scan target",
    )
    parser.add_argument(
        "--check-tools",
        action="store_true",
        help="Check tools status and exit (no scanning)",
    )
    parser.add_argument(
        "--budget",
        type=int,
        default=120000,
        help="Runtime budget in seconds (default: 120000s = 33.3 hours)",
    )
    parser.add_argument(
        "--manual-out-of-scope",
        choices=["ask", "yes", "no", "skip"],
        default="ask",
        help="After scan, run denied/skipped tools on discovered API/pages (yes/no/skip or interactive ask)",
    )
    parser.add_argument(
        "--strict-js-required",
        action="store_true",
        help="Fail-fast and abort scan if JS/Playwright discovery fails",
    )
    parser.add_argument(
        "--full-report",
        action="store_true",
        help="Include full unfiltered endpoint inventory in report output",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress verbose logging output (info and debug messages)",
    )
    args = parser.parse_args()

    # If --check-tools requested, run interactive tool checker and exit
    if args.check_tools:
        try:
            from tool_checker import InteractiveToolChecker

            checker = InteractiveToolChecker()
            checker.run()
        except Exception as e:
            print(f"[!] Tool checker failed: {e}")
            sys.exit(1)
        return

    # If --install-missing requested without target, just install missing tools and exit
    if args.install_missing and not args.target:
        try:
            tool_mgr = ToolManager()
            print("\n[*] Scanning for missing tools...\n")
            tool_mgr.scan_all_tools()
            if tool_mgr.missing_tools:
                print(
                    f"\n[*] Installing {len(tool_mgr.missing_tools)} missing tools...\n"
                )
                ok, failed = tool_mgr.install_missing_tools_non_interactive(
                    list(tool_mgr.missing_tools.keys())
                )
                print(f"\n[*] Installation complete: {ok} installed, {failed} failed\n")
            else:
                print("[✓] All tools are already installed!\n")
        except Exception as e:
            print(f"[!] Tool installation failed: {e}")
            sys.exit(1)
        return

    # If --install-interactive requested without target, run checker and exit
    if args.install_interactive and not args.target:
        try:
            from tool_checker import InteractiveToolChecker

            checker = InteractiveToolChecker()
            checker.run()
        except Exception as e:
            print(f"[!] Tool checker failed: {e}")
            sys.exit(1)
        return

    # Require target for actual scanning
    if not args.target:
        parser.print_help()
        sys.exit(1)

    scanner = AutomationScannerV2(
        target=args.target,
        output_dir=args.output,
        skip_tool_check=args.skip_install,
        custom_budget=args.budget,
        manual_out_of_scope_mode=args.manual_out_of_scope,
        strict_js_required=args.strict_js_required,
        full_report=args.full_report,
        quiet_mode=args.quiet,
    )

    # Optional pre-flight installers (when target is provided)
    if scanner.tool_manager and (args.install_missing or args.install_interactive):
        try:
            if args.install_missing:
                print("\n[*] Pre-flight: Installing missing tools...\n")
                needed = list(scanner.ledger.get_allowed_tools())
                ok, failed = scanner.tool_manager.install_missing_tools_non_interactive(
                    needed
                )
                scanner.log(
                    f"Pre-flight installation complete: {ok} installed, {failed} failed",
                    "INFO",
                )
            if args.install_interactive:
                print("\n[*] Pre-flight: Interactive tool installation...\n")
                scanner.tool_manager.scan_all_tools()
                scanner.tool_manager.install_missing_tools_interactive()
        except Exception as e:
            scanner.log(f"Tool installation step failed: {e}", "WARN")

    scanner.run_full_scan()


if __name__ == "__main__":
    main()
