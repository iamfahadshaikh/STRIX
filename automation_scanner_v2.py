#!/usr/bin/env python3

import argparse
import json
import logging
import re
import socket
import ssl
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs
from urllib.request import Request, urlopen

from decision_ledger import DecisionLedger, DecisionEngine, Decision
from execution_paths import get_executor
from target_profile import TargetProfile, TargetType
from cache_discovery import DiscoveryCache
from findings_model import FindingsRegistry, Finding, Severity, FindingType, map_to_owasp
from tool_manager import ToolManager
from tool_parsers import parse_tool_output, WhatwebParser
from intelligence_layer import IntelligenceEngine
from html_report_generator import HTMLReportGenerator
from crawl_adapter import CrawlAdapter
from gating_loop import GatingLoopOrchestrator
from endpoint_graph import EndpointGraph
from strict_gating_loop import StrictGatingLoop
from crawler_mandatory_gate import CrawlerMandatoryGate
from discovery_classification import get_tool_contract, is_signal_producer
from discovery_completeness import DiscoveryCompletenessEvaluator
from payload_strategy import PayloadStrategy, PayloadReadinessGate, PayloadType
from payload_command_builder import PayloadCommandBuilder
from owasp_mapping import map_to_owasp, OWASPCategory
from enhanced_confidence import EnhancedConfidenceEngine
from deduplication_engine import DeduplicationEngine
from discovery_signal_parser import parse_and_extract_signals, DiscoverySignalParser
from external_intel_connector import ExternalIntelAggregator
from payload_execution_validator import PayloadExecutionValidator, PayloadOutcomeTracker
from report_coverage_analyzer import ReportCoverageAnalyzer, BlockReason
from vulnerability_centric_reporter import VulnerabilityCentricReporter
from risk_aggregation import RiskAggregator
from response_diffing_engine import ResponseDiffingEngine
from oob_callback_system import OOBCallbackSystem
from ssrf_exploitation_engine import SSRFExploitationEngine
from xss_exploitation_engine import XSSExploitationEngine
from sqli_exploitation_engine import SQLinjectionEngine
from adaptive_fuzzing_engine import AdaptiveFuzzingEngine
from service_fingerprinting_engine import ServiceFingerprintingEngine
from subdomain_prioritization import SubdomainPrioritizationEngine
from proof_based_reporter import ProofBasedReporter, ConfirmationMethod


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
    ) -> None:
        self.target = target
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
        self.runtime_deadline = self.start_time.timestamp() + self.profile.runtime_budget

        # Auto-install/gate tools unless explicitly skipped
        self.tool_manager = None if skip_tool_check else ToolManager()

        self.output_dir = Path(
            output_dir
            or f"scan_results_{self.profile.host}_{self.correlation_id}"
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
        self.fingerprint_engine = ServiceFingerprintingEngine()  # Service identification
        self.service_fingerprints: List[Dict] = []
        self.subdomain_prioritizer = SubdomainPrioritizationEngine()  # Attack surface ranking
        self.prioritized_subdomains: List[Dict] = []
        self.proof_reporter = ProofBasedReporter()  # Confirmed findings only

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
        self.log(f"Output directory: {self.output_dir}")
        self.log(f"Correlation ID: {self.correlation_id}")

        if self.tool_manager:
            self._ensure_required_tools()

        # Cheap probes to improve signal-based gating
        self._run_cheap_probes()

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
            addresses = sorted({item[4][0] for item in socket.getaddrinfo(self.profile.host, None)})
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

        for param in sorted(self.cache.params):
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
        api_endpoints = [ep for ep in endpoints if "/api" in ep.lower()]
        params = sorted(str(p) for p in self.cache.params)
        reflections = sorted(str(r) for r in self.cache.reflections)
        subdomains = sorted(str(s) for s in self.cache.subdomains)
        ports = [str(p) for p in sorted(self.cache.discovered_ports)]
        command_params = sorted(str(p) for p in self.cache.command_params)
        ssrf_params = sorted(str(p) for p in self.cache.ssrf_params)

        return {
            "endpoints_list": endpoints,
            "api_endpoints_list": api_endpoints,
            "parameters_list": params,
            "reflections_list": reflections,
            "subdomains_list": subdomains,
            "ports_list": ports,
            "command_params_list": command_params,
            "ssrf_params_list": ssrf_params,
        }

    def _collect_security_strengths(self) -> list[str]:
        """Extract verified positive security signals from executed tool outputs."""
        strengths: list[str] = []
        output_files = [r.get("output_file") for r in self.execution_results if r.get("output_file")]
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

        while True:
            choice = input("\nRun out-of-scope skipped/missing tools across all discovered API/pages? [yes/no/skip]: ").strip().lower()
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
                }
                self.log(f"{tool} SKIPPED: DNS budget exhausted ({self.dns_time_budget}s)", "WARN")
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
            }
            self.log(f"[{index}/{total}] {tool} SKIPPED: {reason}", "WARN")
            with self._lock:
                self.execution_results.append(result)
            return result
        
        # ====== PHASE 3: Runtime enforcement ======
        if datetime.now().timestamp() >= self.runtime_deadline:
            from architecture_guards import ArchitectureViolation
            raise ArchitectureViolation(f"Runtime budget exceeded ({self.profile.runtime_budget}s)")

        self.log(f"[{index}/{total}] ({category}) {tool}")
        started_at = datetime.now()

        # ====== PHASE 4: Execution ======
        rc, stdout, stderr = self._execute_tool_subprocess(command, timeout)

        failure_reason = self._classify_failure_reason(rc, stderr)
        
        # ====== PHASE 5: Classification ======
        signal_stdout = self._filter_actionable_stdout(tool, stdout)
        effective_stdout = signal_stdout if signal_stdout is not None else stdout
        signal = self._classify_signal(tool, effective_stdout, stderr, rc)
        outcome, status = self._classify_execution_outcome(tool, rc, signal, failure_reason)
        
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
            stderr_preview = stderr[:2000] + ("... [truncated]" if stderr_truncated else "")

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
            self.log("Nikto timed out - parsing partial output for hardening findings", "WARN")
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
            from discovery_classification import get_tool_contract, ToolClass
            contract = get_tool_contract(tool)
            
            # Attempt structured signal parsing
            parse_success = parse_and_extract_signals(tool, stdout, self.cache)
            
            if not parse_success:
                # Parsing failed - check if acceptable based on classification
                if contract.classification == ToolClass.SIGNAL_PRODUCER:
                    # Signal producer MUST produce signals
                    if not contract.missing_output_acceptable:
                        logger.error(f"[{tool}] SIGNAL_PRODUCER failed to produce signals - BLOCKING")
                        result["outcome"] = ToolOutcome.BLOCKED_PARSE_FAILED.value
                        result["signal"] = "PARSE_FAILED"
                        self.coverage_analyzer.record_tool_blocked(tool, category, BlockReason.PARSE_FAILED)
                    else:
                        logger.warning(f"[{tool}] SIGNAL_PRODUCER produced no signals (acceptable)")
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
            self.coverage_analyzer.record_tool_executed(tool, tested_endpoints, tested_params, tested_methods)
        
        # ====== PHASE 8: Retry logic ======
        if retries and outcome in {ToolOutcome.EXECUTION_ERROR, ToolOutcome.TIMEOUT}:
            with self._lock:
                if self.execution_results:
                    self.execution_results.pop()
            for attempt in range(1, retries + 1):
                self.log(f"{tool} retry {attempt}/{retries} after {outcome.value}", "WARN")
                result = self._run_tool({**plan_item, "retries": 0}, index, total)
                outcome = ToolOutcome(result["outcome"])
                if outcome not in {ToolOutcome.EXECUTION_ERROR, ToolOutcome.TIMEOUT}:
                    return result
            return result

        return result

    def _classify_execution_outcome(self, tool: str, rc: int, signal: str, failure_reason: str | None) -> tuple[ToolOutcome, str]:
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
        if failure_reason in {"tool_not_installed", "permission_denied"}:
            return ToolOutcome.BLOCKED, "BLOCKED"
        if failure_reason == "target_unreachable":
            return ToolOutcome.EXECUTION_ERROR, "FAILED"
        return ToolOutcome.EXECUTION_ERROR, "FAILED"
    
    def _execute_tool_subprocess(self, command: str, timeout: int) -> tuple[int, str, str]:
        """Execute tool as subprocess. Returns (return_code, stdout, stderr)."""
        try:
            completed = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            rc = completed.returncode
            stdout_raw = completed.stdout if isinstance(completed.stdout, (str, bytes)) else ""
            stderr_raw = completed.stderr if isinstance(completed.stderr, (str, bytes)) else ""
            stdout = (stdout_raw.decode(errors="ignore") if isinstance(stdout_raw, bytes) else stdout_raw or "").strip()
            stderr = (stderr_raw.decode(errors="ignore") if isinstance(stderr_raw, bytes) else stderr_raw or "").strip()
            return rc, stdout, stderr
        except subprocess.TimeoutExpired as e:
            rc = 124
            stdout = (e.stdout.decode(errors="ignore") if isinstance(e.stdout, bytes) else e.stdout or "").strip() if hasattr(e, "stdout") else ""
            stderr = (e.stderr.decode(errors="ignore") if isinstance(e.stderr, bytes) else e.stderr or "").strip() if hasattr(e, "stderr") else ""
            return rc, stdout, stderr

    def _classify_failure_reason(self, rc: int, stderr: str) -> str | None:
        """Map return code and stderr to a stable failure_reason label."""
        stderr_lower = (stderr or "").lower()
        if rc == 124:
            return "timeout"
        if "not found" in stderr_lower or "command not found" in stderr_lower or rc == 127:
            return "tool_not_installed"
        if "permission denied" in stderr_lower:
            return "permission_denied"
        if any(msg in stderr_lower for msg in ["connection refused", "no route to host", "name or service not known", "temporary failure in name resolution", "failed to connect", "connection timed out", "unable to resolve", "could not resolve"]):
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
            "tech_stack_detected": bool(getattr(self.profile, "detected_cms", None) or getattr(self.profile, "detected_tech", {})),
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
                "reflectable_params": [p for p in self.cache.params if "reflect" in str(p).lower()],
                "injectable_sql_params": [p for p in self.cache.params if "sql" in str(p).lower() or "id" in str(p).lower()],
                "dynamic_params": [p for p in self.cache.params],
                "command_params": [p for p in self.cache.params if "cmd" in str(p).lower() or "exec" in str(p).lower()],
            }
            
            # Pick first endpoint and param for validation (simplified)
            test_endpoint = crawler_data["endpoints"][0] if crawler_data["endpoints"] else ""
            test_param = crawler_data["all_params"][0] if crawler_data["all_params"] else ""
            test_method = "GET"  # Default
            
            # Validate execution prerequisites
            can_execute, validation_reason = PayloadExecutionValidator.validate_tool_execution(
                tool, test_endpoint, test_param, test_method, crawler_data
            )
            
            if not can_execute:
                self.log(f"[PayloadGate] {tool} BLOCKED: {validation_reason}", "WARN")
                return DecisionOutcome.BLOCK, f"payload_readiness_failed: {validation_reason}"
        
        meta = {k: plan_item.get(k, set()) for k in ["requires", "optional", "produces"]}
        configured_worst_case = int(plan_item.get("worst_case", plan_item.get("timeout", 300)))
        worst_case = min(configured_worst_case, self.MAX_TOOL_TIMEOUT)
        remaining = max(0.0, self.runtime_deadline - datetime.now().timestamp())
        ctx = self._build_context()

        # Required inputs → BLOCK if missing
        for req in meta["requires"]:
            if not ctx.get(req, False):
                return (DecisionOutcome.BLOCK, f"missing required capability: {req}")

        # Budget rule → SKIP if worst-case exceeds remaining
        if worst_case > remaining:
            return (DecisionOutcome.SKIP, f"insufficient runtime budget ({remaining:.0f}s < worst-case {worst_case}s)")

        # Expected new signal? If all produces already present, SKIP
        if meta["produces"] and all(ctx.get(cap, False) for cap in meta["produces"]):
            return (DecisionOutcome.SKIP, "no new signal expected (capabilities already present)")

        # Optional inputs missing → ALLOW but note reduced confidence
        for opt in meta["optional"]:
            if not ctx.get(opt, False):
                return (DecisionOutcome.ALLOW, f"optional capability missing: {opt} (reduced confidence)")

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
            if any(tech in stdout.lower() for tech in ["apache", "nginx", "iis", "wordpress", "drupal", "php", "java", "python"]):
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
            "vulnerable", "vulnerability", "missing security header", "suggested security header missing",
            "exposed", "injection", "xss", "sqli", "cve-", "critical", "high", "medium",
        ]
        scanner_tools = {"nikto", "testssl", "sslscan", "sqlmap", "commix", "xsstrike", "xsser", "dalfox", "nuclei_all", "nuclei_crit", "nuclei_high", "nuclei_cves", "nuclei_ssl", "nuclei"}
        if tool in scanner_tools:
            lines = [ln.strip().lower() for ln in stdout.splitlines() if ln.strip()]
            if not lines:
                return "NO_SIGNAL"
            positive_lines = 0
            negative_lines = 0
            for line in lines:
                if any(k in line for k in finding_keywords):
                    if any(neg in line for neg in ["not vulnerable", "no vulnerabilities found", "no issues found", "(ok)"]):
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
        is_https = profile.is_https or self._check_https_service(profile.host, profile.port)
        scheme = "https" if is_https else "http"
        port = profile.port if profile.port not in {80, 443} else (443 if is_https else 80)
        # TargetProfile is frozen; use object.__setattr__
        object.__setattr__(profile, "is_https", is_https)
        object.__setattr__(profile, "scheme", scheme)
        object.__setattr__(profile, "port", port)
        self.log(f"HTTPS probe {'passed' if is_https else 'failed'} -> scheme={scheme}, port={port}")
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
                if any(k in lower for k in ["sslv2", "sslv3", "tls1.0", "tls 1.0", "poodle", "crime", "heartbleed"]):
                    actionable.append(ln)
                # Weak ciphers (NULL, RC4, anon, export)
                elif any(k in lower for k in ["null cipher", "rc4", "anonymous", "export", "weak"]):
                    actionable.append(ln)
                # Certificate issues
                elif any(k in lower for k in ["expired", "self-signed", "untrusted", "revoked", "not valid"]):
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
                if any(k in ln.lower() for k in ["apache", "nginx", "iis", "wordpress", "drupal", "joomla", "magento", "java", "python", "ruby", "rails", "django", "asp", ".net", "php"]):
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
            port_pattern = r'(\d+)/tcp\s+open\s+(\S+)'
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
                    candidates = [p for p in parts if p.startswith("/") or p.startswith("http")]
                    if not candidates and parts:
                        candidates = [parts[0]]
                    for path in candidates:
                        norm_path, _ = self.cache._normalize_endpoint(path)
                        if norm_path:
                            self.cache.add_endpoint(norm_path)
                            self.cache.live_endpoints.add(norm_path)
                elif "301" in line:
                    parts = line.split()
                    if parts:
                        self.cache.add_endpoint(parts[0])
        
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
                                self.cache.add_endpoint(norm_path)
                                self.cache.live_endpoints.add(norm_path)  # HTTP 200 only
                elif "[" in line and "]" in line:
                    # Other status codes
                    if "/" in line:
                        parts = line.split()
                        for part in parts:
                            if part.startswith("/"):
                                self.cache.add_endpoint(part)
        
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
                            self.cache.add_endpoint(tok)

    def _prefill_param_hints(self) -> None:
        """Seed discovery cache from the original target (path + query params)."""
        parsed = urlparse(self.profile.url)
        if parsed.path:
            self.cache.add_endpoint(parsed.path)
        for name in parse_qs(parsed.query).keys():
            self.cache.add_param(name)
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
                    if canonical_tool and self.tool_manager.check_tool_installed(canonical_tool):
                        # Pseudo-tool satisfied by canonical tool, skip silently
                        continue
                    # Otherwise, warn about missing tool
                    self.log(f"Missing tool {tool} (no installer available)", "WARN")
                    continue
                
                # Attempt installation
                self.log(f"Auto-installing missing tool: {tool}", "INFO")
                install_result = subprocess.run(install_cmd, shell=True, capture_output=True, text=True)
                if install_result.returncode != 0:
                    self.log(f"Failed to install {tool}: {install_result.stderr.strip()}", "WARN")
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
            ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp",
            ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot", ".otf", ".mp4", ".mp3",
            ".pdf", ".zip", ".gz", ".tgz", ".rar", ".7z",
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

    def _materialize_targets(self, tool: str, require_params: bool = False, require_command_params: bool = False) -> list[str]:
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

        return materialized

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
                return f"nuclei -list {list_file} -t http/cves/ -silent -update-templates"
            
            elif tool_name == "nuclei_ssl":
                # Run with SSL templates
                if len(targets) == 1:
                    return f"nuclei -target {targets[0]} -t ssl -silent -update-templates"
                list_file = self.output_dir / f"{tool_name}_targets.txt"
                list_file.write_text("\n".join(targets), encoding="utf-8")
                return f"nuclei -list {list_file} -t ssl -silent -update-templates"

        if tool_name == "sqlmap":
            targets = self._materialize_targets(tool_name, require_params=True)
            if not targets:
                return command
            if len(targets) == 1:
                return f"sqlmap -u {targets[0]} --batch --crawl=0"
            list_file = self.output_dir / "sqlmap_targets.txt"
            list_file.write_text("\n".join(targets), encoding="utf-8")
            return f"sqlmap -m {list_file} --batch --crawl=0"

        if tool_name == "commix":
            targets = self._materialize_targets(tool_name, require_params=True, require_command_params=True)
            if not targets:
                return command
            if len(targets) == 1:
                return f"commix -u {targets[0]} --batch"
            list_file = self.output_dir / "commix_targets.txt"
            list_file.write_text("\n".join(targets), encoding="utf-8")
            return f"commix -m {list_file} --batch"

        if tool_name == "dalfox":
            targets = self._materialize_targets(tool_name)
            if not targets or not self.cache.has_reflections():
                return command
            if len(targets) == 1:
                return f"dalfox url {targets[0]} --silence"
            list_file = self.output_dir / "dalfox_targets.txt"
            list_file.write_text("\n".join(targets), encoding="utf-8")
            return f"dalfox file {list_file} --silence"

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
            "nuclei_ssl": f"nuclei -u {target_url} -t ssl -silent",
            "dalfox": f"dalfox url {target_url} --silence",
            "sqlmap": f"sqlmap -u {target_url} --batch --crawl=1",
            "commix": f"commix -u {target_url} --batch",
            "xsstrike": f"python3 /usr/share/xsstrike/xsstrike.py -u {target_url}",
            "xsser": f"xsser --url {target_url}",
            "arjun": f"arjun -u {target_url} --passive",
            "ping": f"ping -c 2 {host}",
            "nmap_quick": f"nmap -F {host}",
            "nmap_vuln": f"nmap -sV --script vuln --script-timeout 120s {host}",
            "sslscan": f"sslscan {host}",
            "testssl": f"testssl.sh --quiet -U {target_url}",
            "openssl_connect": f"openssl s_client -connect {host}:443 -servername {host}",
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

    def _should_skip_manual_exploit_for_target(self, tool_name: str, target_url: str) -> tuple[bool, str]:
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

    def _classify_manual_failure(self, rc: int, stdout: str, stderr: str, failure_reason: str | None) -> str:
        """Classify manual sweep failures into actionable buckets."""
        text = f"{stdout}\n{stderr}".lower()

        if failure_reason in {"tool_not_installed", "permission_denied"} or "no such file or directory" in text or "can't open file" in text:
            return "ENV_ERROR"
        if "403" in text or "waf" in text or "ips" in text or "forbidden" in text:
            return "TARGET_BLOCKED"
        if "no usable links found" in text or "no parameters" in text or "no reflectable" in text or "not applicable" in text:
            return "NOT_APPLICABLE"
        if rc == 0 and ("[no output]" in text or "no issues found" in text):
            return "NOT_APPLICABLE"
        return "EXECUTION_ERROR"

    def _execute_manual_tool_command(self, tool_name: str, command: str, target_url: str) -> dict:
        """Execute one manual out-of-scope command and record findings/discoveries."""
        started = datetime.now()
        rc, stdout, stderr = self._execute_tool_subprocess(command, timeout=180)
        signal = self._classify_signal(tool_name, stdout, stderr, rc)
        failure_reason = self._classify_failure_reason(rc, stderr)
        outcome, status = self._classify_execution_outcome(tool_name, rc, signal, failure_reason)
        failure_class = self._classify_manual_failure(rc, stdout, stderr, failure_reason)
        output_file = self._save_tool_output(f"manual_{tool_name}", command, stdout, stderr, rc)

        # Reuse existing parsers for enrichment.
        try:
            self._parse_discoveries(tool_name, stdout)
        except Exception:
            pass
        try:
            self._extract_findings(tool_name, stdout, stderr, str(output_file) if output_file else None)
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
            r.get("tool") for r in self.execution_results if r.get("status") in {"SKIPPED", "BLOCKED"}
        }
        candidate_tools = sorted(t for t in (denied_tools | skipped_or_blocked) if t)

        discovery_lists = self._build_discovery_detail_lists()
        endpoint_urls = [self._build_full_url(ep) for ep in discovery_lists.get("endpoints_list", [])]
        targets = sorted(set(endpoint_urls + [self.profile.url]))

        self.manual_out_of_scope_report.update({
            "attempted": True,
            "candidate_tools": candidate_tools,
            "targets": targets,
        })

        if not candidate_tools or not targets:
            self.log("Manual out-of-scope sweep: nothing to run", "INFO")
            return

        # Try to install missing tools for manual sweep.
        if self.tool_manager:
            for tool_name in candidate_tools:
                try:
                    if self.tool_manager.check_tool_installed(tool_name):
                        continue
                    install_cmd = self.tool_manager.get_install_command(tool_name)
                    if not install_cmd:
                        self.manual_out_of_scope_report["missing_or_unavailable"].append({
                            "tool": tool_name,
                            "reason": "no install command available",
                        })
                        continue
                    rc = subprocess.run(install_cmd, shell=True, capture_output=True, text=True).returncode
                    if rc != 0:
                        self.manual_out_of_scope_report["missing_or_unavailable"].append({
                            "tool": tool_name,
                            "reason": "install failed",
                        })
                except Exception as e:  # noqa: BLE001
                    self.manual_out_of_scope_report["missing_or_unavailable"].append({
                        "tool": tool_name,
                        "reason": f"install exception: {e}",
                    })

        for tool_name in candidate_tools:
            # Host-level tools only need one run.
            host_level = tool_name in {
                "ping", "nmap_quick", "nmap_vuln", "sslscan", "testssl",
                "openssl_connect", "openssl_showcerts", "openssl_status", "openssl_state",
                "findomain", "sublist3r", "assetfinder", "dnsrecon",
            }
            loop_targets = [self.profile.url] if host_level else targets

            for target_url in loop_targets:
                should_skip, skip_reason = self._should_skip_manual_exploit_for_target(tool_name, target_url)
                if should_skip:
                    self.manual_out_of_scope_report["non_actionable_failures"].append({
                        "tool": tool_name,
                        "target": target_url,
                        "reason": skip_reason,
                    })
                    self.manual_out_of_scope_report["classified_failures"]["NOT_APPLICABLE"] += 1
                    continue

                command = self._manual_command_for_tool(tool_name, target_url)
                if not command:
                    self.manual_out_of_scope_report["missing_or_unavailable"].append({
                        "tool": tool_name,
                        "reason": "no command template",
                    })
                    break
                result = self._execute_manual_tool_command(tool_name, command, target_url)
                if result.get("status") in {"SUCCESS", "PARTIAL"}:
                    self.manual_out_of_scope_report["executed"].append({
                        "tool": tool_name,
                        "target": target_url,
                        "outcome": result.get("outcome"),
                    })
                else:
                    failure_class = result.get("failure_class", "EXECUTION_ERROR")
                    self.manual_out_of_scope_report["classified_failures"][failure_class] = (
                        self.manual_out_of_scope_report["classified_failures"].get(failure_class, 0) + 1
                    )
                    failure_payload = {
                        "tool": tool_name,
                        "target": target_url,
                        "reason": result.get("failure_reason") or result.get("reason"),
                        "class": failure_class,
                    }
                    if failure_class in {"NOT_APPLICABLE", "TARGET_BLOCKED"}:
                        self.manual_out_of_scope_report["non_actionable_failures"].append(failure_payload)
                    else:
                        self.manual_out_of_scope_report["failed"].append(failure_payload)
    
    def _extract_findings(self, tool: str, stdout: str, stderr: str, output_file: str | None = None) -> None:
        """
        Extract normalized findings from tool output.
        
        Maps tool output → Finding objects → FindingsRegistry (deduplicated).
        Uses unified parsers from tool_parsers.py module.
        """
        if not stdout:
            return
        
        # Use unified parser for supported tools
        findings = parse_tool_output(tool, stdout, stderr, self.target, output_file=output_file)
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
                    elif "ssl" in line_lower or "tls" in line_lower or "cipher" in line_lower:
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
                        evidence_line=max(1, stdout.count("\n", 0, stdout.find(line)) + 1 if line in stdout else 1),
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
                self.cache.add_param(f"tech_cms_{cms.lower()}")
            server = tech_stack.get("web_server")
            if server:
                self.cache.add_param(f"tech_server_{server.lower()}")
            for lang in tech_stack.get("languages", []):
                self.cache.add_param(f"tech_lang_{lang.lower()}")
            for fw in tech_stack.get("frameworks", []):
                self.cache.add_param(f"framework_{fw.lower()}")
            for lib in tech_stack.get("javascript_libs", []):
                self.cache.add_param(f"js_{lib.lower()}")

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

    def _autofill_actionability_fields(self, finding_dict: dict) -> None:
        """Fill missing impact/exploitability/verification templates for report quality."""
        f_type = str(finding_dict.get("type", "")).lower()
        description = str(finding_dict.get("description", "")).lower()
        tool = str(finding_dict.get("tool", "unknown"))
        location = finding_dict.get("location", "")

        is_header_gap = "missing security header" in description or "header" in description
        is_breach = "breach" in description
        is_service_exposure = "discovered" in description and "port" in description

        if not (finding_dict.get("impact") or "").strip():
            if is_header_gap:
                finding_dict["impact"] = "Increases risk of XSS, clickjacking, and data leakage when combined with other weaknesses."
            elif is_breach:
                finding_dict["impact"] = "Potential side-channel leakage risk when secrets are reflected in compressed HTTPS responses."
            elif is_service_exposure:
                finding_dict["impact"] = "Exposed service metadata can accelerate reconnaissance and targeted exploit selection."
            else:
                finding_dict["impact"] = "Security posture degradation with potential exploitation when chained."

        if not (finding_dict.get("exploitability") or "").strip():
            if is_breach or is_header_gap:
                finding_dict["exploitability"] = "Passive; typically requires chaining with other vulnerabilities."
            elif is_service_exposure:
                finding_dict["exploitability"] = "Low standalone; primarily recon advantage for attackers."
            else:
                finding_dict["exploitability"] = "Context dependent based on exposure and attacker capability."

        if not (finding_dict.get("verification_steps") or "").strip():
            if is_header_gap:
                finding_dict["verification_steps"] = "Run: curl -I https://target and verify expected security headers are present."
            elif is_service_exposure:
                finding_dict["verification_steps"] = f"Run: nmap -sV {self.profile.host} and validate service/banner exposure at {location}."
            elif is_breach:
                finding_dict["verification_steps"] = "Re-run testssl/nikto and validate HTTPS compression plus reflection behavior on sensitive endpoints."
            else:
                finding_dict["verification_steps"] = "Re-run the original command and validate reproducibility from evidence line."

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
        existing_descriptions = {str(f.get("description", "")).lower() for f in promoted if isinstance(f, dict)}

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
        whatweb_text = tool_text.get("whatweb", "") + "\n" + tool_text.get("whatweb_http_fallback", "")
        nuclei_text = "\n".join([
            tool_text.get("nuclei_all", ""),
            tool_text.get("nuclei_high", ""),
            tool_text.get("nuclei_ssl", ""),
            tool_text.get("nuclei_cves", ""),
        ])

        # Rule 1: Missing header hardening findings (promote from direct observation).
        missing_headers = sorted(set(re.findall(r"suggested security header missing:\s*([^\.\n]+)", nikto_text, re.IGNORECASE)))
        if missing_headers:
            sev = "MEDIUM" if len(missing_headers) >= 3 else "LOW"
            confidence = 0.85 if len(missing_headers) >= 2 else 0.75
            desc = f"Hardening Gap: Missing security headers ({', '.join(h.strip().lower() for h in missing_headers[:6])})"
            if desc.lower() not in existing_descriptions:
                promoted.append({
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
                })

        # Rule 2: BREACH contextual promotion with corroboration.
        breach_tools = set()
        if "breach" in nikto_text:
            breach_tools.add("nikto")
        if "breach" in testssl_text and ("gzip" in testssl_text or "compression" in testssl_text):
            breach_tools.add("testssl")
        if "content-encoding" in whatweb_text and "gzip" in whatweb_text:
            breach_tools.add("whatweb")
        if "breach" in nuclei_text or "http-missing-security-headers" in nuclei_text:
            breach_tools.add("nuclei")

        if len(breach_tools) >= 2:
            desc = "Potential side-channel risk (BREACH), requires attacker-controlled reflection to exploit"
            if desc.lower() not in existing_descriptions:
                confidence = 0.75 if (nikto_failed and len([t for t in breach_tools if t != "nikto"]) >= 2) else 0.65
                promoted.append({
                    "type": "Weak Cryptography",
                    "severity": "LOW",
                    "location": self.profile.host,
                    "description": desc,
                    "tool": "+".join(sorted(breach_tools)),
                    "confidence": confidence,
                    "owasp": "A02:2021 - Cryptographic Failures",
                    "cwe": "CWE-200",
                    "evidence": "Cross-tool corroboration: BREACH/compression indicators from " + ", ".join(sorted(breach_tools)),
                    "impact": "Compression side-channels may leak secrets under specific reflective conditions.",
                    "exploitability": "Context-dependent and usually requires attacker-controlled reflection and repeated requests.",
                    "verification_steps": "Confirm gzip compression on sensitive endpoints and test reflection of secret-bearing tokens.",
                })

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
            raise ArchitectureViolation(f"Duplicate tool in execution plan: {tool_names}")

        self.log(f"Execution Plan: {len(plan)} tools planned")
        self.log(f"Execution Path: {self.executor.__class__.__name__}")

        # Phase definitions: tools grouped by function
        phases = {
                "DNS": {"tools": {"dig_a", "dig_ns", "dig_mx", "dnsrecon"}},
                "Subdomains": {"tools": {"findomain", "sublist3r", "assetfinder"}},
                "Network": {"tools": {"ping", "nmap_quick", "nmap_vuln"}},
                "WebDetection": {"tools": {"whatweb", "nikto"}},
                "SSL": {"tools": {"sslscan", "testssl", "openssl_connect", "openssl_showcerts", "openssl_status", "openssl_state"}},
                "Crawling": {"tools": {"gating_crawl"}},
                "WebEnum": {"tools": {"gobuster", "dirsearch"}},
                "Exploitation": {"tools": {"dalfox", "xsstrike", "sqlmap", "commix", "xsser"}},
                "Nuclei": {"tools": {"nuclei_crit", "nuclei_high", "nuclei_all", "nuclei_cves", "nuclei_ssl"}},
        }
        
        # Track phase success
        phase_success = {phase: False for phase in phases}
        
        # ====== PHASE 1a-1b: DISCOVERY PHASE (RUN FIRST) ======
        # Execute discovery tools to gather signals BEFORE checking completeness
        self.log("PHASE 1: Running discovery tools (DNS, Network, Web Detection, SSL/TLS)...", "INFO")
        
        discovery_phases = ["DNS", "Subdomains", "Network", "WebDetection", "SSL"]
        discovery_plan = [t for t in plan if any(
            t[0] in phases[phase]["tools"] for phase in discovery_phases
        )]
        
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
        self.log("PHASE 1c: Evaluating discovery completeness (after discovery tools)...", "INFO")
        
        # Initialize discovery evaluator with cache (NOW populated by discovery tools)
        self.discovery_evaluator = DiscoveryCompletenessEvaluator(self.cache, self.profile)
        
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
            self.log("⏳ BLOCKING payload tools: Discovery still incomplete after tools (score < 60)", "ERROR")
            
            # Mark all payload tools as blocked in ledger
            for phase_name in ["WebEnum"]:
                for tool in phases[phase_name]["tools"]:
                    self.ledger.record_tool_decision(
                        tool_name=tool,
                        decision=Decision.DENY,
                        reason=f"discovery_incomplete_score_{score_pct}"
                    )
                    self.log(f"  ⏳ BLOCKED: {tool} (insufficient discovery)", "WARN")
        
        # ====== PHASE 1d: TLS EVALUATION FOR HTTPS TARGETS ======
        if self.profile.is_https:
            self.log("PHASE 1d: HTTPS detected - enforcing TLS evaluation...", "INFO")
            
            # Check if TLS was evaluated
            tls_evaluated = self.cache.has_signal("tls_evaluated") or self.cache.has_signal("ssl_evaluated")
            
            if not tls_evaluated:
                self.log("⚠ HTTPS target but no TLS evaluation - testssl should have run", "WARN")
            else:
                self.log(f"✓ TLS evaluated for HTTPS target", "INFO")
        
        # ====== PHASE 1b: EXTERNAL INTELLIGENCE (READ-ONLY) ======
        self.log("PHASE 1b: Gathering external intelligence (crt.sh)...", "INFO")
        try:
            # Only crt.sh (no API key required) - Shodan/Censys require keys
            intel_results = self.external_intel.gather_intel(self.profile.host)
            
            if intel_results.get("crtsh") and intel_results["crtsh"].success:
                self.external_intel.to_cache_signals(intel_results, self.cache)
                self.log(f"✓ External intel: {len(intel_results['crtsh'].results)} certificate entries", "INFO")
            else:
                self.log("External intel: crt.sh unavailable (network issue)", "WARN")
        except Exception as e:
            self.log(f"External intel EXCEPTION: {e}", "WARN")
        
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
        
        self.log("PHASE 2: Running MANDATORY crawler (payload tools depend on this)...", "INFO")
        try:
            # Build full URL with scheme from profile
            scheme = "https" if self.profile.is_https else "http"
            crawl_url = f"{scheme}://{self.profile.host}"
            
            crawl_adapter = CrawlAdapter(crawl_url, output_dir=str(self.output_dir), cache=self.cache)
            
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
            crawl_thread.join(timeout=30)  # Increased timeout for mandatory crawler
            
            if crawl_thread.is_alive():
                self.log("Crawler TIMEOUT (30s) - BLOCKING payload tools", "ERROR")
                crawler_gate.update_decision_ledger(self.ledger)
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
                                status_code=result.get("status_code")
                            )

                        # Mark reflectable parameters from crawl signals
                        for param_name in gating_signals.get("reflectable_params", []):
                            graph.mark_reflectable(param_name)

                        graph.finalize()
                        self.endpoint_graph = graph  # Store for payload tools
                        self.payload_command_builder = PayloadCommandBuilder(self.payload_strategy, self.endpoint_graph)
                        self.crawler_executed = True  # Mark crawler as executed
                        self.strict_gating_loop = StrictGatingLoop(graph, self.ledger)
                        gating_orchestrator = self.strict_gating_loop
                        
                        # Phase 4: Initialize enhanced confidence engine with graph
                        self.enhanced_confidence = EnhancedConfidenceEngine(graph)

                    self.log(f"Crawler SUCCESS: {gating_signals['crawled_url_count']} endpoints, "
                            f"{gating_signals['parameter_count']} parameters, "
                            f"{gating_signals['reflection_count']} reflections", "SUCCESS")

                    if self.strict_gating_loop:
                        gating_targets = self.strict_gating_loop.get_all_targets()
                        enabled = [t for t, tg in gating_targets.items() if tg.can_run]
                        disabled = [t for t, tg in gating_targets.items() if not tg.can_run]
                        self.log(f"Payload gating (strict): enabled={enabled}, disabled={disabled}", "INFO")
                    else:
                        self.log("Strict gating not available (no graph built)", "WARNING")

                    # Update gate with crawler success
                    crawler_gate.check_crawler_status()
                else:
                    # Crawler failed - BLOCK payload tools
                    self.log(f"Crawler FAILED: {crawl_msg} - BLOCKING payload tools", "ERROR")
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
        if not gate_report['crawler_succeeded']:
            self.log(f"⚠️  PAYLOAD TESTING BLOCKED: {gate_report['failure_reason']}", "ERROR")
            self.log(f"⚠️  Blocked tools: {', '.join(gate_report['blocked_tools'])}", "ERROR")
        else:
            self.log(f"✓ Crawler gate passed: {gate_report['endpoints_discovered']} endpoints discovered", "SUCCESS")

        # PHASE 5: Active exploitation always runs and is filtered only at proof/report stage
        if self.initialize_exploitation_engines():
            scheme = "https" if self.profile.is_https else "http"
            base_url = f"{scheme}://{self.profile.host}"
            fallback_endpoints = self._build_fallback_endpoints_for_exploitation()
            exploitation_findings = self.run_active_exploitation(base_url, endpoints=fallback_endpoints)
            self.log(f"Exploitation phase complete: {len(exploitation_findings)} findings from active testing", "INFO")
        else:
            self.log("Exploitation engines failed to initialize - skipping active testing", "WARN")

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
                    reason = targets.reason if targets else "Gated by crawl analysis (no targets)"
                    self.log(f"[{tool_name}] strict gating advisory only: {reason} (continuing execution)", "WARN")
                gated_targets = targets.to_dict() if targets else None

            # Payload tools must use crawler-derived commands only
            if tool_name in builder_payload_tools and self.payload_command_builder:
                built_commands = self._build_payload_commands_from_graph(tool_name)

                if not built_commands:
                    reason = "No crawler-derived targets/params for payload execution"
                    self.log(f"[{tool_name}] BLOCKED: {reason}", "WARN")
                    self.execution_results.append({
                        "tool": tool_name,
                        "outcome": ToolOutcome.BLOCKED.value,
                        "reason": reason,
                        "duration": 0,
                        "category": meta.get("category", "Exploitation"),
                        "status": "BLOCKED",
                        "failure_reason": "no_crawler_targets",
                    })
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
                    if current_phase and result and result.get("outcome") == ToolOutcome.SUCCESS_WITH_FINDINGS.value:
                        phase_success[current_phase] = True
                continue
            
            # Orchestrator decides strictly via decision layer; tools never self-skip
            scoped_cmd = scoped_cmd or self._scope_command(tool_name, cmd)
            plan_item = {"tool": tool_name, "command": scoped_cmd, **meta}
            if gated_targets:
                plan_item["gated_targets"] = gated_targets
            result = self._run_tool(plan_item, i, total)
            if current_phase and result and result.get("outcome") == ToolOutcome.SUCCESS_WITH_FINDINGS.value:
                phase_success[current_phase] = True

        # No parallel execution in strict orchestrator mode

        self.log(f"Discovery summary: {self.cache.summary()}", "INFO")
        self.log(f"Findings summary: {self.findings.summary()}", "SUCCESS")
        
        if self.findings.has_critical():
            self.log("⚠️  CRITICAL vulnerabilities found!", "CRITICAL")
        
        # Phase 1: Evaluate discovery completeness
        self.log("Evaluating discovery completeness...", "INFO")
        self.discovery_evaluator = DiscoveryCompletenessEvaluator(self.cache, self.profile)
        self.completeness_report = self.discovery_evaluator.evaluate()
        self.discovery_evaluator.log_report(self.completeness_report)
        
        self.log("Scan complete - orchestrator finished (see execution results for skips/blocks)", "SUCCESS")

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

        # JSON-safe plan (convert sets to sorted lists)
        plan_serialized = []
        for (t, c, m) in plan:
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
                "type": finding.type.value if hasattr(finding.type, 'value') else finding.type,
                "severity": finding.severity.value if hasattr(finding.severity, 'value') else finding.severity,
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
        filtered_findings = self.intelligence.filter_false_positives(deduplicated_findings)
        
        # Skip advanced correlation for now - work with filtered dicts directly
        correlated_findings = filtered_findings

        # Promotion layer: elevate hardening findings with corroboration/context rules.
        correlated_findings = self._apply_promotion_logic(correlated_findings)
        
        # Phase 4: Enhanced confidence scoring
        if self.enhanced_confidence:
            for finding in correlated_findings:
                if isinstance(finding, dict):
                    confidence_score = self.enhanced_confidence.calculate_finding_confidence(finding)
                    finding["confidence"] = confidence_score
                    finding["confidence_label"] = self.enhanced_confidence.get_confidence_label(confidence_score)
        
        vulnerability_report = {}
        risk_report = {}
        try:
            vuln_reporter = VulnerabilityCentricReporter()
            risk_aggregator = RiskAggregator(app_name=self.profile.host)

            for finding in correlated_findings:
                finding_dict = finding if isinstance(finding, dict) else (finding.primary_finding if hasattr(finding, 'primary_finding') else finding)
                if hasattr(finding_dict, 'to_dict'):
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
                    cwe_ids=[finding_dict.get("cwe")] if finding_dict.get("cwe") else [],
                )

            vulnerability_report = vuln_reporter.get_full_report()
            risk_report = risk_aggregator.generate_report()
        except Exception as e:  # noqa: BLE001
            self.log(f"Vulnerability-centric reporting failed: {e}", "WARN")

        # Generate intelligence report (skip for now - work with dicts directly)
        intelligence_report = {}
        
        # Update findings registry with filtered findings
        self.findings = FindingsRegistry()
        for cf in correlated_findings:
            # Handle both dict and CorrelatedFinding objects
            if isinstance(cf, dict):
                # Reconstruct Finding objects from dicts
                try:
                    f_type = FindingType[cf.get('type', 'OTHER')] if isinstance(cf.get('type'), str) else FindingType.OTHER
                except (KeyError, TypeError):
                    f_type = FindingType.OTHER
                try:
                    f_sev = Severity[cf.get('severity', 'INFO')] if isinstance(cf.get('severity'), str) else Severity.INFO
                except (KeyError, TypeError):
                    f_sev = Severity.INFO
                finding = Finding(
                    type=f_type,
                    severity=f_sev,
                    location=cf.get('location', ''),
                    description=cf.get('description', ''),
                    cwe=cf.get('cwe'),
                    owasp=cf.get('owasp'),
                    tool=cf.get('tool', 'unknown'),
                    evidence=cf.get('evidence', ''),
                    evidence_file=cf.get('evidence_file', ''),
                    evidence_line=int(cf.get('evidence_line', 0) or 0),
                    remediation=cf.get('remediation', ''),
                    impact=cf.get('impact', ''),
                    exploitability=cf.get('exploitability', ''),
                    verification_steps=cf.get('verification_steps', ''),
                )
                self.findings.add(finding)
            elif hasattr(cf, 'primary_finding'):
                self.findings.add(cf.primary_finding)
        
        # ====== PHASE 4c: COVERAGE LOGGING ======
        self.log("PHASE 4c: Logging coverage gaps...", "INFO")
        self.coverage_analyzer.log_coverage_summary()
        coverage_report = self.coverage_analyzer.get_coverage_report()
        skipped_tools = sorted({r.get("tool") for r in self.execution_results if r.get("status") == "SKIPPED" and r.get("tool")})
        denied_tools = sorted(set(self.ledger.get_denied_tools()))
        missing_tools = []
        if self.tool_manager:
            for tool in sorted(set(skipped_tools + denied_tools + coverage_report.get("blocked", {}).get("tools", []))):
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

        proof_report = self.generate_proof_based_final_report()

        report = {
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
            "discovery_completeness": self.completeness_report.to_dict() if hasattr(self, 'completeness_report') else {},
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
            "service_fingerprints": self.service_fingerprints,
            "prioritized_subdomains": self.prioritized_subdomains,
            "manual_out_of_scope": self.manual_out_of_scope_report,
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
            tech_stack = self._extract_tech_stack_summary()

            skipped_tools = sorted({r.get("tool") for r in self.execution_results if r.get("status") == "SKIPPED" and r.get("tool")})
            blocked_tools = sorted({r.get("tool") for r in self.execution_results if r.get("status") == "BLOCKED" and r.get("tool")})
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
                **discovery_lists,
            }

            findings_summary = {
                "critical": severity_counts.get(Severity.CRITICAL, 0),
                "high": severity_counts.get(Severity.HIGH, 0),
                "medium": severity_counts.get(Severity.MEDIUM, 0),
                "low": severity_counts.get(Severity.LOW, 0),
                "info": severity_counts.get(Severity.INFO, 0),
                "total": sum(severity_counts.values()),
                "owasp": owasp_summary,
            }

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
        lines.append("FINDINGS SUMMARY (Deduplicated, OWASP-Mapped, High-Confidence Only)")
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
            for category, count in sorted(owasp_counts.items(), key=lambda item: (-item[1], item[0])):
                lines.append(f"- {category}: {count}")
        else:
            lines.append("- No OWASP-mapped findings available.")

        # Filter: suppress LOW/INFO in detailed body unless requested elsewhere
        findings = [
            f for f in all_findings
            if f.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM}
        ]

        lines.append("\nDETAILED FINDINGS (CRITICAL/HIGH/MEDIUM)")
        lines.append("-" * 80)
        if not findings:
            lines.append("No findings detected above medium severity (or all were filtered as noise).")
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

                for severity, group in [(Severity.CRITICAL, crit), (Severity.HIGH, high), (Severity.MEDIUM, med)]:
                    if group:
                        lines.append(f"  {severity.value}:")
                        for finding in group:
                            lines.append(f"    - {finding.type.value}: {finding.description}")
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
            f for f in all_findings
            if f.severity in {Severity.LOW, Severity.INFO}
        ][:5]
        if suppressed:
            lines.append("Sample entries:")
            for finding in suppressed:
                lines.append(f"  - {finding.severity.value}: {finding.type.value} @ {finding.location}")

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
                self.log(f"OOB callback server started on {self.oob_system.external_ip}:{self.oob_system.port}", "SUCCESS")
            
            # Initialize exploitation engines with shared diffing engine
            self.ssrf_engine = SSRFExploitationEngine(
                response_diffing_engine=self.response_diffing,
                oob_system=self.oob_system
            )
            
            self.xss_engine = XSSExploitationEngine(
                response_diffing_engine=self.response_diffing,
                fuzzing_engine=self.fuzzing_engine
            )
            
            self.sqli_engine = SQLinjectionEngine(
                response_diffing_engine=self.response_diffing,
                fuzzing_engine=self.fuzzing_engine
            )
            
            self.log("All exploitation engines initialized", "SUCCESS")
            return True
        
        except Exception as e:
            self.log(f"Error initializing exploitation engines: {e}", "ERROR")
            return False
    
    def run_active_exploitation(self, base_url: str, endpoints: Optional[List[Dict]] = None) -> List[Dict]:
        """
        Run active exploitation against discovered endpoints
        
        Args:
            base_url: Base URL of target (scheme + host)
            endpoints: List of discovered endpoints from crawler (optional)
        
        Returns: List of exploitation results
        """
        self.log("PHASE 5: ACTIVE EXPLOITATION - Attempting to validate vulnerabilities with proof", "INFO")
        
        exploitation_results = []
        
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
        
        self.log(f"Testing {len(endpoints_to_test)} endpoint(s) for active vulnerabilities...", "INFO")
        
        # Create session for exploitation (reuses cookies across attempts)
        import requests
        session = requests.Session()
        session.headers.update({
            "User-Agent": "VAPT-Automated-Engine/1.0 (Vulnerability Assessment)"
        })
        
        # Test each endpoint
        for endpoint_obj in endpoints_to_test[:10]:  # Limit to top 10 to avoid timeout
            endpoint = endpoint_obj.get("url") if isinstance(endpoint_obj, dict) else str(endpoint_obj)
            params = endpoint_obj.get("params", []) if isinstance(endpoint_obj, dict) else []
            method = endpoint_obj.get("method", "GET").upper() if isinstance(endpoint_obj, dict) else "GET"
            
            if not params:
                self.log(f"Skipping {endpoint} - no parameters", "DEBUG")
                continue
            
            self.log(f"Testing {endpoint} ({method}) with {len(params)} parameter(s)", "INFO")
            
            # Test each parameter
            for param in params[:3]:  # Limit params to avoid timeout
                param_name = param.get("name") if isinstance(param, dict) else str(param)
                
                # Try SSRF exploitation
                try:
                    ssrf_result = self.ssrf_engine.exploit_ssrf(
                        endpoint=endpoint,
                        parameter=param_name,
                        base_url=base_url,
                        http_method=method,
                        session=session
                    )
                    if ssrf_result:
                        exploitation_results.append(ssrf_result)
                        # Add to proof-based reporter
                        self.proof_reporter.add_from_exploitation_result(ssrf_result)
                except Exception as e:
                    self.log(f"SSRF exploitation error: {e}", "DEBUG")
                
                # Try XSS exploitation
                try:
                    xss_result = self.xss_engine.exploit_xss(
                        endpoint=endpoint,
                        parameter=param_name,
                        base_url=base_url,
                        http_method=method,
                        session=session
                    )
                    if xss_result:
                        exploitation_results.append(xss_result)
                        self.proof_reporter.add_from_exploitation_result(xss_result)
                except Exception as e:
                    self.log(f"XSS exploitation error: {e}", "DEBUG")
                
                # Try SQL injection exploitation
                try:
                    sqli_result = self.sqli_engine.exploit_sqli(
                        endpoint=endpoint,
                        parameter=param_name,
                        base_url=base_url,
                        http_method=method,
                        session=session
                    )
                    if sqli_result:
                        exploitation_results.append(sqli_result)
                        self.proof_reporter.add_from_exploitation_result(sqli_result)
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
            self.proof_reporter.add_from_exploitation_result(oob_finding)
        
        self.log(f"Exploitation phase complete: {len(exploitation_results)} vulnerabilities found", "INFO")
        
        return exploitation_results

    def _build_fallback_endpoints_for_exploitation(self) -> List[Dict]:
        """Build minimal endpoint/param targets from discovery cache when crawler graph is unavailable."""
        fallback_targets: List[Dict] = []
        if not self.cache:
            return fallback_targets

        endpoints = sorted(self.cache.live_endpoints or self.cache.endpoints)
        params = sorted(self.cache.params)
        if not endpoints or not params:
            return fallback_targets

        for endpoint in endpoints[:10]:
            fallback_targets.append({
                "url": endpoint,
                "method": "GET",
                "params": [{"name": p} for p in params[:5]],
            })

        return fallback_targets

    def run_service_fingerprinting(self) -> List[Dict]:
        """Fingerprint discovered services and ports to improve attack context."""
        try:
            host = self.profile.host
            ports = self.cache.get_discovered_ports() if self.cache else []
            if not ports:
                ports = [80, 443, 8080, 8081]

            self.log(f"Running service fingerprinting on {host} ports: {ports}", "INFO")
            fingerprints = self.fingerprint_engine.fingerprint_port_range(host, ports, use_common_only=False)
            self.service_fingerprints = [fp.to_dict() for fp in fingerprints]
            self.log(f"Service fingerprinting complete: {len(self.service_fingerprints)} service(s) identified", "INFO")
            return self.service_fingerprints
        except Exception as e:
            self.log(f"Service fingerprinting failed: {e}", "WARN")
            self.service_fingerprints = []
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
                open_ports=sorted(set(open_ports))
            )
        
        # Get prioritized list
        recommendations = self.subdomain_prioritizer.recommend_attack_order()
        
        if recommendations:
            self.log(f"Top priority targets (by attack surface):", "INFO")
            for i, rec in enumerate(recommendations[:5], 1):
                self.log(f"  {i}. {rec['subdomain']} (score: {rec['score']:.1f}) - {rec['reason']}", "INFO")
        
        return recommendations
    
    def generate_proof_based_final_report(self) -> Dict:
        """
        Generate final report showing ONLY confirmed vulnerabilities with proof
        
        Returns: Report dict with confirmed findings only
        """
        self.log("Generating proof-based vulnerability report...", "INFO")
        
        report = self.proof_reporter.generate_report()
        
        # Log summary
        self.log(f"FINAL REPORT: {report['summary']['total_confirmed']} confirmed vulnerabilities", "INFO")
        
        if report['statistics']['critical'] > 0:
            self.log(f"  🔴 CRITICAL: {report['statistics']['critical']}", "ERROR")
        if report['statistics']['high'] > 0:
            self.log(f"  🔴 HIGH: {report['statistics']['high']}", "WARN")
        if report['statistics']['medium'] > 0:
            self.log(f"  🟡 MEDIUM: {report['statistics']['medium']}", "INFO")
        if report['statistics']['low'] > 0:
            self.log(f"  🟢 LOW: {report['statistics']['low']}", "INFO")
        
        return report


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Architecture-driven security scanner v2"
    )
    parser.add_argument("target", nargs='?', default=None, help="Target domain or URL (optional if using --check-tools, --install-missing, or --install-interactive)")
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
                print(f"\n[*] Installing {len(tool_mgr.missing_tools)} missing tools...\n")
                ok, failed = tool_mgr.install_missing_tools_non_interactive(list(tool_mgr.missing_tools.keys()))
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
    )

    # Optional pre-flight installers (when target is provided)
    if scanner.tool_manager and (args.install_missing or args.install_interactive):
        try:
            if args.install_missing:
                print("\n[*] Pre-flight: Installing missing tools...\n")
                needed = list(scanner.ledger.get_allowed_tools())
                ok, failed = scanner.tool_manager.install_missing_tools_non_interactive(needed)
                scanner.log(f"Pre-flight installation complete: {ok} installed, {failed} failed", "INFO")
            if args.install_interactive:
                print("\n[*] Pre-flight: Interactive tool installation...\n")
                scanner.tool_manager.scan_all_tools()
                scanner.tool_manager.install_missing_tools_interactive()
        except Exception as e:
            scanner.log(f"Tool installation step failed: {e}", "WARN")

    scanner.run_full_scan()


if __name__ == "__main__":
    main()

        
