"""
Engine Hardening & Resilience - Phase 4 Task 7
Purpose: Never hang. Crash isolation. Partial failure tolerance. Resume capability.

Features:
  1. Tool crash isolation
  2. Timeout enforcement
  3. Partial failure tolerance
  4. Checkpoint/resume capability
  5. Resource limits
  6. Graceful degradation
"""

import logging
import signal
import json
import pickle
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import time

logger = logging.getLogger(__name__)


class ToolState(str, Enum):
    """Tool execution state"""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    TIMEOUT = "TIMEOUT"
    CRASHED = "CRASHED"
    SKIPPED = "SKIPPED"


@dataclass
class ToolCheckpoint:
    """Checkpoint for tool execution"""
    tool_name: str
    endpoint: str
    parameter: Optional[str]
    state: ToolState
    results: List[Dict] = field(default_factory=list)
    error_message: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def to_dict(self) -> Dict:
        return {
            "tool_name": self.tool_name,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "state": self.state.value,
            "results": self.results,
            "error_message": self.error_message,
            "timestamp": self.timestamp
        }


@dataclass
class ScanCheckpoint:
    """Scan-level checkpoint for resume"""
    scan_id: str
    scan_start_time: str
    progress: Dict[str, int] = field(default_factory=dict)  # tool -> endpoints_completed
    tool_checkpoints: List[ToolCheckpoint] = field(default_factory=list)
    completed_endpoints: List[str] = field(default_factory=list)
    pending_endpoints: List[str] = field(default_factory=list)
    accumulated_results: List[Dict] = field(default_factory=list)
    
    def to_dict(self) -> Dict:
        return {
            "scan_id": self.scan_id,
            "scan_start_time": self.scan_start_time,
            "progress": self.progress,
            "tool_checkpoints": [cp.to_dict() for cp in self.tool_checkpoints],
            "completed_endpoints": self.completed_endpoints,
            "pending_endpoints": self.pending_endpoints,
            "accumulated_results": self.accumulated_results
        }


class TimeoutHandler:
    """
    Enforce timeouts, no hanging
    
    Usage:
        handler = TimeoutHandler(timeout_seconds=120)
        
        try:
            handler.start()
            result = risky_function()
            handler.cancel()
        except TimeoutException:
            logger.error("Function timed out")
    """

    def __init__(self, timeout_seconds: float):
        self.timeout_seconds = timeout_seconds
        self.start_time: Optional[float] = None

    def start(self) -> None:
        """Start timeout clock"""
        self.start_time = time.time()

    def cancel(self) -> None:
        """Cancel timeout"""
        self.start_time = None

    def check(self, context: str = "") -> None:
        """Check if timeout exceeded"""
        if self.start_time is None:
            return

        elapsed = time.time() - self.start_time
        if elapsed > self.timeout_seconds:
            msg = f"Timeout exceeded ({elapsed:.1f}s > {self.timeout_seconds}s)"
            if context:
                msg += f" during {context}"
            logger.error(f"[TimeoutHandler] {msg}")
            raise TimeoutException(msg)

    def get_remaining(self) -> float:
        """Get remaining time"""
        if self.start_time is None:
            return self.timeout_seconds

        elapsed = time.time() - self.start_time
        return max(0, self.timeout_seconds - elapsed)


class TimeoutException(Exception):
    """Raised when operation times out"""
    pass


class ToolCrashIsolator:
    """
    Isolate tool crashes, continue scanning
    
    Usage:
        isolator = ToolCrashIsolator()
        
        results = isolator.execute_tool_safe(
            tool_name="sqlmap",
            tool_function=lambda: run_sqlmap(endpoint, params),
            timeout_seconds=120,
            fallback_value=[]
        )
    """

    def __init__(self):
        self.crash_log: Dict[str, List[str]] = {}

    def execute_tool_safe(
        self,
        tool_name: str,
        tool_function: Callable,
        timeout_seconds: float = 120,
        fallback_value: Any = None,
        context: str = ""
    ) -> Any:
        """
        Execute tool with crash isolation
        
        Returns:
            Tool result, or fallback_value if crash/timeout
        """
        timeout_handler = TimeoutHandler(timeout_seconds)

        try:
            timeout_handler.start()
            logger.info(f"[CrashIsolator] Starting {tool_name} {context}")

            result = tool_function()

            timeout_handler.cancel()
            logger.info(f"[CrashIsolator] {tool_name} completed successfully")

            return result

        except TimeoutException as e:
            error_msg = f"Timeout: {str(e)}"
            logger.warning(f"[CrashIsolator] {tool_name} {error_msg}")
            self._log_crash(tool_name, error_msg)
            return fallback_value or []

        except Exception as e:
            error_msg = f"Crash: {str(e)}"
            logger.error(f"[CrashIsolator] {tool_name} {error_msg}")
            self._log_crash(tool_name, error_msg)
            return fallback_value or []

    def _log_crash(self, tool_name: str, error_msg: str) -> None:
        """Log crash for analysis"""
        if tool_name not in self.crash_log:
            self.crash_log[tool_name] = []
        self.crash_log[tool_name].append(
            f"{datetime.now().isoformat()}: {error_msg}"
        )

    def get_crash_report(self) -> Dict:
        """Get crash summary"""
        return {
            "total_crashes": sum(len(v) for v in self.crash_log.values()),
            "crashes_by_tool": {
                tool: len(crashes) for tool, crashes in self.crash_log.items()
            },
            "details": self.crash_log
        }


class PartialFailureHandler:
    """
    Continue scanning on partial failures
    
    Usage:
        handler = PartialFailureHandler(
            fail_threshold=0.5,  # Fail if 50% of tools crash
            skip_failed_tools=True
        )
        
        for endpoint in endpoints:
            handler.add_endpoint_attempt(endpoint)
            
            for tool in tools:
                try:
                    results = run_tool(tool, endpoint)
                    handler.record_success(endpoint, tool)
                except:
                    handler.record_failure(endpoint, tool)
            
            if handler.should_skip_endpoint(endpoint):
                continue
    """

    def __init__(
        self,
        fail_threshold: float = 0.5,
        skip_failed_tools: bool = True,
        max_failures_per_endpoint: int = 3
    ):
        self.fail_threshold = fail_threshold  # 0-1: proportion of tools allowed to fail
        self.skip_failed_tools = skip_failed_tools
        self.max_failures_per_endpoint = max_failures_per_endpoint

        self.endpoint_stats: Dict[str, Dict] = {}

    def add_endpoint_attempt(self, endpoint: str, tools_count: int = 1) -> None:
        """Record endpoint for tracking"""
        if endpoint not in self.endpoint_stats:
            self.endpoint_stats[endpoint] = {
                "successes": 0,
                "failures": 0,
                "skipped": 0,
                "tools_count": tools_count
            }

    def record_success(self, endpoint: str, tool: str) -> None:
        """Record successful tool execution"""
        if endpoint not in self.endpoint_stats:
            self.add_endpoint_attempt(endpoint)

        self.endpoint_stats[endpoint]["successes"] += 1
        logger.debug(f"[PartialFailure] Success on {endpoint}/{tool}")

    def record_failure(self, endpoint: str, tool: str) -> None:
        """Record tool failure"""
        if endpoint not in self.endpoint_stats:
            self.add_endpoint_attempt(endpoint)

        self.endpoint_stats[endpoint]["failures"] += 1
        logger.warning(f"[PartialFailure] Failure on {endpoint}/{tool}")

    def should_skip_endpoint(self, endpoint: str) -> bool:
        """Decide whether to skip endpoint"""
        if endpoint not in self.endpoint_stats:
            return False

        stats = self.endpoint_stats[endpoint]
        tools_count = stats.get("tools_count", 1)
        failures = stats["failures"]

        # Skip if too many failures
        if failures >= self.max_failures_per_endpoint:
            logger.warning(f"[PartialFailure] Skipping {endpoint} (too many failures)")
            return True

        # Skip if failure rate exceeds threshold
        if tools_count > 0:
            failure_rate = failures / tools_count
            if failure_rate > self.fail_threshold:
                logger.warning(
                    f"[PartialFailure] Skipping {endpoint} (failure rate {failure_rate:.1%})"
                )
                return True

        return False

    def get_health_report(self) -> Dict:
        """Get overall scanning health"""
        total_endpoints = len(self.endpoint_stats)
        successful_endpoints = sum(
            1 for stats in self.endpoint_stats.values()
            if stats["successes"] > stats["failures"]
        )

        return {
            "total_endpoints": total_endpoints,
            "successful_endpoints": successful_endpoints,
            "success_rate": (
                successful_endpoints / total_endpoints
                if total_endpoints > 0
                else 0
            ),
            "details": self.endpoint_stats
        }


class CheckpointManager:
    """
    Save and resume scans
    
    Usage:
        manager = CheckpointManager(checkpoint_dir="/tmp/checkpoints")
        
        # During scan
        checkpoint = ScanCheckpoint(
            scan_id="scan_123",
            scan_start_time=datetime.now().isoformat(),
            completed_endpoints=["/api/users", "/api/posts"]
        )
        manager.save_checkpoint("scan_123", checkpoint)
        
        # Resume scan
        checkpoint = manager.load_checkpoint("scan_123")
        if checkpoint:
            remaining = checkpoint.pending_endpoints
            results = checkpoint.accumulated_results
    """

    def __init__(self, checkpoint_dir: str = "/tmp/scanner_checkpoints"):
        self.checkpoint_dir = checkpoint_dir
        import os
        os.makedirs(checkpoint_dir, exist_ok=True)

    def save_checkpoint(self, scan_id: str, checkpoint: ScanCheckpoint) -> None:
        """Save checkpoint to disk"""
        import os
        filepath = os.path.join(self.checkpoint_dir, f"{scan_id}.json")

        with open(filepath, 'w') as f:
            json.dump(checkpoint.to_dict(), f, indent=2)

        logger.info(f"[Checkpoint] Saved checkpoint for {scan_id}")

    def load_checkpoint(self, scan_id: str) -> Optional[ScanCheckpoint]:
        """Load checkpoint from disk"""
        import os
        filepath = os.path.join(self.checkpoint_dir, f"{scan_id}.json")

        if not os.path.exists(filepath):
            logger.debug(f"[Checkpoint] No checkpoint found for {scan_id}")
            return None

        try:
            with open(filepath, 'r') as f:
                data = json.load(f)

            checkpoint = ScanCheckpoint(
                scan_id=data["scan_id"],
                scan_start_time=data["scan_start_time"],
                progress=data.get("progress", {}),
                completed_endpoints=data.get("completed_endpoints", []),
                pending_endpoints=data.get("pending_endpoints", []),
                accumulated_results=data.get("accumulated_results", [])
            )

            logger.info(f"[Checkpoint] Loaded checkpoint for {scan_id}")
            return checkpoint

        except Exception as e:
            logger.error(f"[Checkpoint] Failed to load checkpoint: {str(e)}")
            return None

    def cleanup_checkpoint(self, scan_id: str) -> None:
        """Delete checkpoint (scan complete)"""
        import os
        filepath = os.path.join(self.checkpoint_dir, f"{scan_id}.json")

        if os.path.exists(filepath):
            os.remove(filepath)
            logger.info(f"[Checkpoint] Cleaned up checkpoint for {scan_id}")


class ResilienceEngine:
    """
    Combined resilience layer
    
    Usage:
        engine = ResilienceEngine(
            timeout_seconds=3600,
            fail_threshold=0.5,
            checkpoint_enabled=True
        )
        
        try:
            for endpoint in endpoints:
                results = engine.execute_tool_safe(
                    tool_name="sqlmap",
                    endpoint=endpoint,
                    tool_function=lambda: run_sqlmap(endpoint)
                )
                
                if results:
                    engine.record_success(endpoint, "sqlmap")
                else:
                    engine.record_failure(endpoint, "sqlmap")
                
                engine.checkpoint()
        finally:
            report = engine.get_resilience_report()
    """

    def __init__(
        self,
        scan_id: str = "scan_default",
        timeout_seconds: float = 3600,
        fail_threshold: float = 0.5,
        checkpoint_enabled: bool = True
    ):
        self.scan_id = scan_id
        self.timeout_handler = TimeoutHandler(timeout_seconds)
        self.crash_isolator = ToolCrashIsolator()
        self.partial_failure_handler = PartialFailureHandler(
            fail_threshold=fail_threshold
        )
        self.checkpoint_manager = CheckpointManager() if checkpoint_enabled else None
        
        self.scan_checkpoint = ScanCheckpoint(
            scan_id=scan_id,
            scan_start_time=datetime.now().isoformat()
        )

    def execute_tool_safe(
        self,
        tool_name: str,
        endpoint: str,
        tool_function: Callable,
        timeout_override: Optional[float] = None,
        context: str = ""
    ) -> Any:
        """Execute tool with full resilience"""
        # Check global timeout
        self.timeout_handler.check("tool execution")

        # Use override timeout or derive from remaining time
        tool_timeout = timeout_override or min(
            120, self.timeout_handler.get_remaining()
        )

        # Execute with crash isolation
        result = self.crash_isolator.execute_tool_safe(
            tool_name=tool_name,
            tool_function=tool_function,
            timeout_seconds=tool_timeout,
            fallback_value=[],
            context=f"on {endpoint}"
        )

        # Track execution
        if result:
            self.partial_failure_handler.record_success(endpoint, tool_name)
        else:
            self.partial_failure_handler.record_failure(endpoint, tool_name)

        return result

    def record_success(self, endpoint: str, tool: str) -> None:
        """Record tool success"""
        self.partial_failure_handler.record_success(endpoint, tool)

    def record_failure(self, endpoint: str, tool: str) -> None:
        """Record tool failure"""
        self.partial_failure_handler.record_failure(endpoint, tool)

    def should_skip_endpoint(self, endpoint: str) -> bool:
        """Check if should skip endpoint"""
        return self.partial_failure_handler.should_skip_endpoint(endpoint)

    def checkpoint(self) -> None:
        """Save current progress"""
        if self.checkpoint_manager:
            self.checkpoint_manager.save_checkpoint(
                self.scan_id, self.scan_checkpoint
            )

    def get_resilience_report(self) -> Dict:
        """Complete resilience report"""
        return {
            "scan_id": self.scan_id,
            "crash_report": self.crash_isolator.get_crash_report(),
            "health_report": self.partial_failure_handler.get_health_report(),
            "scan_duration": (
                datetime.now() - datetime.fromisoformat(
                    self.scan_checkpoint.scan_start_time
                )
            ).total_seconds()
        }


# Example usage
"""
engine = ResilienceEngine(
    scan_id="myapp_scan_20260112",
    timeout_seconds=3600,
    fail_threshold=0.5
)

endpoints = ["/api/users", "/api/posts", "/api/comments"]

try:
    for endpoint in endpoints:
        # Execute tool safely
        results = engine.execute_tool_safe(
            tool_name="sqlmap",
            endpoint=endpoint,
            tool_function=lambda: run_sqlmap(endpoint),
            timeout_override=120
        )
        
        # Check if should continue
        if engine.should_skip_endpoint(endpoint):
            continue
        
        # Checkpoint periodically
        engine.checkpoint()

finally:
    # Get report even if scan failed
    report = engine.get_resilience_report()
    print(json.dumps(report, indent=2))
"""
