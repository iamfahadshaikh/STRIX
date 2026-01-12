"""
Traffic Capture & Replay System - Phase 4 Task 2
Purpose: Record all HTTP traffic during scan, enable deterministic replay

Features:
  1. Capture all requests/responses
  2. HAR format export (browser standard)
  3. Deterministic replay mode
  4. No discovery during replay
  5. Same inputs → same outputs
"""

import logging
import json
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse
import hashlib

logger = logging.getLogger(__name__)


@dataclass
class HTTPRequest:
    """Single captured HTTP request"""
    url: str
    method: str = "GET"
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    tool_name: Optional[str] = None  # Which tool generated this
    payload: Optional[str] = None  # The actual payload (if testing)

    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "method": self.method,
            "headers": self.headers,
            "body": self.body,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "payload": self.payload
        }

    def get_hash(self) -> str:
        """Get deterministic hash of request"""
        key = f"{self.method}:{self.url}:{self.body or ''}"
        return hashlib.sha256(key.encode()).hexdigest()


@dataclass
class HTTPResponse:
    """Single captured HTTP response"""
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None  # First 10KB only
    execution_time_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    error_message: Optional[str] = None  # If error occurred
    
    def to_dict(self) -> Dict:
        return {
            "status_code": self.status_code,
            "headers": self.headers,
            "body_preview": self.body[:1000] if self.body else None,
            "body_size": len(self.body) if self.body else 0,
            "execution_time_ms": self.execution_time_ms,
            "timestamp": self.timestamp,
            "error_message": self.error_message
        }


@dataclass
class HTTPExchange:
    """Complete request-response pair"""
    request: HTTPRequest
    response: HTTPResponse
    exchange_id: str = ""

    def __post_init__(self):
        if not self.exchange_id:
            self.exchange_id = hashlib.sha256(
                f"{self.request.get_hash()}:{self.response.status_code}".encode()
            ).hexdigest()[:12]

    def to_dict(self) -> Dict:
        return {
            "exchange_id": self.exchange_id,
            "request": self.request.to_dict(),
            "response": self.response.to_dict()
        }


class TrafficCapture:
    """
    Capture and manage HTTP traffic during scanning
    
    Purpose:
    - Record all requests/responses
    - Enable deterministic replay
    - Export for audit trails
    - Support debugging
    
    Usage:
        capture = TrafficCapture(session_id="scan_20260112_143022")
        
        # During scan
        capture.capture_request(
            url="https://example.com/api/users?id=1",
            method="GET",
            tool_name="dalfox"
        )
        capture.capture_response(
            status_code=200,
            headers={"content-type": "application/json"},
            body='{"users": [...]}',
            execution_time_ms=245.5
        )
        
        # Export
        har = capture.export_har()
        with open("scan_traffic.har", "w") as f:
            json.dump(har, f)
            
        # Replay mode
        replay = TrafficCapture.load_from_har("scan_traffic.har")
        replay.set_replay_mode(True)
        # Now all requests are served from capture, no network calls
    """

    def __init__(self, session_id: str):
        """
        Args:
            session_id: Unique identifier for this scan session
        """
        self.session_id = session_id
        self.exchanges: List[HTTPExchange] = []
        self.replay_mode = False
        self.exchange_index = 0
        self.start_time = datetime.now()
        self.end_time: Optional[datetime] = None
        
        # Metadata
        self.endpoints_scanned: set = set()
        self.tools_used: set = set()
        self.payloads_tested = 0

        logger.info(f"[TrafficCapture] Initialized session: {session_id}")

    def capture_request(
        self,
        url: str,
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        tool_name: Optional[str] = None,
        payload: Optional[str] = None
    ) -> str:
        """
        Capture an HTTP request
        
        Args:
            url: Request URL
            method: HTTP method
            headers: Request headers
            body: Request body
            tool_name: Which tool generated this (dalfox, sqlmap, etc.)
            payload: The actual payload if this is a test
            
        Returns:
            Exchange ID
        """
        # Extract endpoint from URL
        parsed = urlparse(url)
        endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        self.endpoints_scanned.add(endpoint)

        if tool_name:
            self.tools_used.add(tool_name)
            if payload:
                self.payloads_tested += 1

        request = HTTPRequest(
            url=url,
            method=method,
            headers=headers or {},
            body=body,
            tool_name=tool_name,
            payload=payload
        )

        logger.debug(f"[TrafficCapture] Captured request: {method} {url}")

        # Store for matching with response
        self._pending_request = request
        return request.get_hash()

    def capture_response(
        self,
        status_code: int,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        execution_time_ms: float = 0.0,
        error_message: Optional[str] = None
    ):
        """
        Capture an HTTP response (must follow capture_request)
        
        Args:
            status_code: HTTP status code
            headers: Response headers
            body: Response body (truncated to 10KB)
            execution_time_ms: How long the request took
            error_message: Error message if request failed
        """
        if not hasattr(self, '_pending_request'):
            logger.warning("[TrafficCapture] Response captured without request")
            return

        # Truncate body to 10KB
        if body and len(body) > 10240:
            body = body[:10240]

        response = HTTPResponse(
            status_code=status_code,
            headers=headers or {},
            body=body,
            execution_time_ms=execution_time_ms,
            error_message=error_message
        )

        # Create exchange
        exchange = HTTPExchange(
            request=self._pending_request,
            response=response
        )

        self.exchanges.append(exchange)
        logger.debug(f"[TrafficCapture] Captured response: {status_code} ({execution_time_ms:.1f}ms)")

        # Clean up
        delattr(self, '_pending_request')

    def set_replay_mode(self, enabled: bool):
        """Enable/disable replay mode"""
        self.replay_mode = enabled
        self.exchange_index = 0
        logger.info(f"[TrafficCapture] Replay mode: {enabled}")

    def get_next_response(self, expected_url: str) -> Optional[HTTPResponse]:
        """
        During replay mode: get the next expected response
        
        Args:
            expected_url: URL we're about to request
            
        Returns:
            Recorded response if available, None otherwise
        """
        if not self.replay_mode or self.exchange_index >= len(self.exchanges):
            return None

        exchange = self.exchanges[self.exchange_index]
        
        # Check if URL matches
        if exchange.request.url == expected_url:
            self.exchange_index += 1
            return exchange.response

        logger.warning(f"[TrafficCapture] URL mismatch in replay mode")
        return None

    def finish_session(self):
        """Mark session as complete"""
        self.end_time = datetime.now()
        duration_sec = (self.end_time - self.start_time).total_seconds()
        logger.info(
            f"[TrafficCapture] Session complete: {len(self.exchanges)} exchanges "
            f"in {duration_sec:.1f}s, {len(self.endpoints_scanned)} endpoints"
        )

    def get_session_summary(self) -> Dict:
        """Get session summary"""
        duration_sec = (
            (self.end_time - self.start_time).total_seconds()
            if self.end_time else (datetime.now() - self.start_time).total_seconds()
        )

        return {
            "session_id": self.session_id,
            "captured_exchanges": len(self.exchanges),
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": duration_sec,
            "endpoints": len(self.endpoints_scanned),
            "tools_used": list(self.tools_used),
            "payloads_tested": self.payloads_tested,
            "average_response_time_ms": (
                sum(e.response.execution_time_ms for e in self.exchanges) / len(self.exchanges)
                if self.exchanges else 0
            )
        }

    def export_har(self) -> Dict:
        """
        Export to HAR format (HTTP Archive)
        
        Returns:
            HAR-formatted dict
        """
        entries = []
        for exchange in self.exchanges:
            entry = {
                "startedDateTime": exchange.request.timestamp,
                "time": exchange.response.execution_time_ms,
                "request": {
                    "method": exchange.request.method,
                    "url": exchange.request.url,
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in exchange.request.headers.items()
                    ],
                    "body": exchange.request.body,
                    "queryString": []
                },
                "response": {
                    "status": exchange.response.status_code,
                    "statusText": "",
                    "headers": [
                        {"name": k, "value": v}
                        for k, v in exchange.response.headers.items()
                    ],
                    "content": {
                        "size": len(exchange.response.body) if exchange.response.body else 0,
                        "mimeType": exchange.response.headers.get("content-type", "unknown"),
                        "text": exchange.response.body
                    }
                },
                "cache": {},
                "timings": {
                    "wait": exchange.response.execution_time_ms,
                    "receive": 0
                }
            }
            entries.append(entry)

        return {
            "log": {
                "version": "1.2",
                "creator": {
                    "name": "VAPT Scanner",
                    "version": "4.0.0"
                },
                "entries": entries
            }
        }

    def export_json(self) -> Dict:
        """Export to custom JSON format (more detailed)"""
        return {
            "session": self.get_session_summary(),
            "exchanges": [e.to_dict() for e in self.exchanges]
        }

    @staticmethod
    def load_from_har(har_file: str) -> 'TrafficCapture':
        """
        Load traffic from HAR file
        
        Args:
            har_file: Path to .har file
            
        Returns:
            TrafficCapture with loaded exchanges
        """
        with open(har_file, 'r') as f:
            har_data = json.load(f)

        capture = TrafficCapture(session_id=f"replay_{datetime.now().isoformat()}")

        for entry in har_data.get("log", {}).get("entries", []):
            req = entry.get("request", {})
            resp = entry.get("response", {})

            request = HTTPRequest(
                url=req.get("url"),
                method=req.get("method", "GET"),
                headers={h["name"]: h["value"] for h in req.get("headers", [])},
                body=req.get("body")
            )

            response = HTTPResponse(
                status_code=resp.get("status", 0),
                headers={h["name"]: h["value"] for h in resp.get("headers", [])},
                body=resp.get("content", {}).get("text"),
                execution_time_ms=entry.get("time", 0)
            )

            exchange = HTTPExchange(request=request, response=response)
            capture.exchanges.append(exchange)

        logger.info(f"[TrafficCapture] Loaded {len(capture.exchanges)} exchanges from {har_file}")
        return capture

    @staticmethod
    def load_from_json(json_file: str) -> 'TrafficCapture':
        """Load traffic from custom JSON file"""
        with open(json_file, 'r') as f:
            data = json.load(f)

        capture = TrafficCapture(session_id=data["session"]["session_id"])

        for exchange_data in data.get("exchanges", []):
            req_data = exchange_data["request"]
            resp_data = exchange_data["response"]

            request = HTTPRequest(
                url=req_data["url"],
                method=req_data["method"],
                headers=req_data["headers"],
                body=req_data["body"],
                tool_name=req_data.get("tool_name"),
                payload=req_data.get("payload")
            )

            response = HTTPResponse(
                status_code=resp_data["status_code"],
                headers=resp_data["headers"],
                body=resp_data.get("body_preview"),
                execution_time_ms=resp_data["execution_time_ms"],
                error_message=resp_data.get("error_message")
            )

            exchange = HTTPExchange(request=request, response=response)
            capture.exchanges.append(exchange)

        logger.info(f"[TrafficCapture] Loaded {len(capture.exchanges)} exchanges from {json_file}")
        return capture

    def to_dict(self) -> Dict:
        """Serialize traffic capture"""
        return {
            "session": self.get_session_summary(),
            "exchanges": [e.to_dict() for e in self.exchanges]
        }


# Example usage
"""
capture = TrafficCapture(session_id="scan_20260112_143022")

# Capture requests/responses
capture.capture_request(
    url="https://example.com/api/users",
    method="GET",
    tool_name="dalfox"
)
capture.capture_response(
    status_code=200,
    headers={"content-type": "application/json"},
    body='{"users": [{"id": 1, "name": "Admin"}]}',
    execution_time_ms=245.5
)

# More requests...

capture.finish_session()

# Export
with open("traffic.har", "w") as f:
    json.dump(capture.export_har(), f, indent=2)

# Replay
replay_capture = TrafficCapture.load_from_har("traffic.har")
replay_capture.set_replay_mode(True)
response = replay_capture.get_next_response("https://example.com/api/users")
print(response.status_code)  # 200
"""
