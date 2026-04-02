"""
Out-Of-Band (OOB) Callback Detection System
Purpose: Detect blind vulnerabilities (SSRF, XXE, RCE) via out-of-band interactions
Supports: HTTP callbacks, DNS lookups, webhook tracking
"""

import logging
import socket
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class CallbackType(Enum):
    """Types of out-of-band callbacks"""

    HTTP = "http"
    DNS = "dns"
    WEBHOOK = "webhook"


@dataclass
class CallbackPayload:
    """Payload sent to target for OOB callback"""

    callback_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    callback_url: str = ""
    dns_domain: str = ""
    callback_type: CallbackType = CallbackType.HTTP
    endpoint: str = ""
    parameter: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    triggered: bool = False
    triggered_at: Optional[str] = None
    evidence: Dict = field(default_factory=dict)

    def to_dict(self) -> Dict:
        return {
            "callback_id": self.callback_id,
            "callback_url": self.callback_url,
            "dns_domain": self.dns_domain,
            "callback_type": self.callback_type.value,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "triggered": self.triggered,
            "evidence": self.evidence,
        }


class OOBCallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler for OOB callback server"""

    # Shared registry with parent server
    callback_registry: Dict[str, CallbackPayload] = {}

    def do_GET(self):
        """Handle GET requests to callback server"""
        # Extract callback ID from path
        path = self.path  # e.g., /abc12345
        callback_id = path.strip("/")

        if callback_id in self.callback_registry:
            # Mark callback as triggered
            callback = self.callback_registry[callback_id]
            callback.triggered = True
            callback.triggered_at = datetime.now().isoformat()
            callback.evidence = {
                "request_headers": dict(self.headers),
                "request_path": path,
                "client_ip": self.client_address[0],
                "user_agent": self.headers.get("User-Agent", "unknown"),
            }
            logger.info(
                f"OOB Callback triggered: {callback_id} from {self.client_address[0]}"
            )

            # Send 200 OK response
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            # Unknown callback ID
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        """Handle POST requests to callback server"""
        # Similar to GET but with body extraction
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="ignore")

        path = self.path.strip("/")
        callback_id = path

        if callback_id in self.callback_registry:
            callback = self.callback_registry[callback_id]
            callback.triggered = True
            callback.triggered_at = datetime.now().isoformat()
            callback.evidence = {
                "request_headers": dict(self.headers),
                "request_body": body,
                "request_path": path,
                "client_ip": self.client_address[0],
            }
            logger.info(f"OOB Callback triggered (POST): {callback_id}")

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


class OOBCallbackSystem:
    """
    Out-of-band callback detection system

    Stands up local HTTP server to detect blind vulnerabilities
    Generates unique callback URLs/DNS domains for tracking
    Correlates callbacks to original payloads
    """

    def __init__(self, local_ip: str = "127.0.0.1", port: int = 8888):
        """
        Initialize OOB callback system

        Args:
            local_ip: IP to bind callback server to
            port: Port for callback server
        """
        self.local_ip = local_ip
        self.port = port
        self.callback_server: Optional[HTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.callbacks: Dict[str, CallbackPayload] = {}
        self.is_running = False

        # Try to get external IP for public callback URLs
        self.external_ip = self._get_external_ip()

    def _get_external_ip(self) -> str:
        """
        Attempt to determine external IP for callback server
        Falls back to localhost if unable to determine
        """
        try:
            # Connect to Google DNS to determine local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def start_callback_server(self) -> bool:
        """
        Start HTTP callback server in background thread
        Returns: True if server started, False if already running or error
        """
        if self.is_running:
            logger.warning("Callback server already running")
            return False

        try:
            # Set shared registry on handler class
            OOBCallbackHandler.callback_registry = self.callbacks

            # Create HTTP server
            self.callback_server = HTTPServer(
                (self.local_ip, self.port), OOBCallbackHandler
            )

            # Start in background thread
            self.server_thread = threading.Thread(
                target=self.callback_server.serve_forever, daemon=True
            )
            self.server_thread.start()
            self.is_running = True

            logger.info(f"OOB Callback server started on {self.local_ip}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start callback server: {e}")
            return False

    def stop_callback_server(self):
        """Stop callback server"""
        if self.callback_server:
            self.callback_server.shutdown()
            self.is_running = False
            logger.info("OOB Callback server stopped")

    def create_http_callback(self, endpoint: str, parameter: str) -> CallbackPayload:
        """
        Create HTTP callback payload for SSRF/blind vulnerability detection

        Returns: CallbackPayload with callback_url ready to send to target
        """
        callback_id = str(uuid.uuid4())[:8]
        callback_url = f"http://{self.external_ip}:{self.port}/{callback_id}"

        callback = CallbackPayload(
            callback_id=callback_id,
            callback_url=callback_url,
            callback_type=CallbackType.HTTP,
            endpoint=endpoint,
            parameter=parameter,
        )

        self.callbacks[callback_id] = callback
        logger.debug(f"Created HTTP callback: {callback_url}")
        return callback

    def create_dns_callback(
        self, endpoint: str, parameter: str, domain: str = "callback.attacker.com"
    ) -> CallbackPayload:
        """
        Create DNS callback payload for blind vulnerability detection

        Args:
            endpoint: Target endpoint
            parameter: Target parameter
            domain: Base domain for DNS lookups

        Returns: CallbackPayload with dns_domain ready to send to target
        """
        callback_id = str(uuid.uuid4())[:8]
        dns_domain = f"{callback_id}.{domain}"

        callback = CallbackPayload(
            callback_id=callback_id,
            dns_domain=dns_domain,
            callback_type=CallbackType.DNS,
            endpoint=endpoint,
            parameter=parameter,
        )

        self.callbacks[callback_id] = callback
        logger.debug(f"Created DNS callback: {dns_domain}")
        return callback

    def wait_for_callback(
        self, callback: CallbackPayload, timeout_seconds: int = 10
    ) -> bool:
        """
        Wait for callback to be triggered

        Args:
            callback: CallbackPayload to wait for
            timeout_seconds: How long to wait before giving up

        Returns: True if callback triggered, False if timeout
        """
        deadline = datetime.now() + timedelta(seconds=timeout_seconds)

        while datetime.now() < deadline:
            if callback.triggered:
                logger.info(f"Callback {callback.callback_id} detected!")
                return True
            threading.Event().wait(0.5)  # Poll every 500ms

        logger.info(f"Callback {callback.callback_id} timeout after {timeout_seconds}s")
        return False

    def get_triggered_callbacks(self) -> List[CallbackPayload]:
        """Get list of all triggered callbacks"""
        return [cb for cb in self.callbacks.values() if cb.triggered]

    def correlate_callback_to_payload(
        self, callback_id: str, endpoint: str
    ) -> Optional[Dict]:
        """
        Get evidence of callback tied to specific payload

        Returns: Dict with callback evidence if triggered, None otherwise
        """
        if callback_id not in self.callbacks:
            return None

        callback = self.callbacks[callback_id]
        if not callback.triggered:
            return None

        return {
            "callback_id": callback.callback_id,
            "triggered": True,
            "triggered_at": callback.triggered_at,
            "evidence": callback.evidence,
            "endpoint": callback.endpoint,
            "parameter": callback.parameter,
        }

    def generate_ssrf_payloads_with_callbacks(
        self, endpoint: str, parameter: str
    ) -> List[Dict]:
        """
        Generate SSRF payloads with HTTP callbacks for detection

        Returns: List of payloads with embedded callback URLs
        """
        callback = self.create_http_callback(endpoint, parameter)

        payloads = [
            {
                "payload": callback.callback_url,
                "callback_id": callback.callback_id,
                "type": "direct_url",
                "description": "Direct callback URL",
            },
            {
                "payload": f"http://127.0.0.1:8888/{callback.callback_id}",
                "callback_id": callback.callback_id,
                "type": "internal_callback",
                "description": "Callback via localhost",
            },
            {
                "payload": f"http://169.254.169.254/latest/meta-data/?callback={callback.callback_url}",
                "callback_id": callback.callback_id,
                "type": "aws_metadata",
                "description": "AWS metadata with callback",
            },
            {
                "payload": f"file:///etc/passwd",  # Non-callback baseline
                "callback_id": None,
                "type": "baseline",
                "description": "File read baseline",
            },
        ]

        return payloads

    def check_callback_status(self, callback_id: str) -> Dict:
        """Check status of specific callback"""
        if callback_id not in self.callbacks:
            return {"error": "Unknown callback ID"}

        callback = self.callbacks[callback_id]
        return {
            "callback_id": callback.callback_id,
            "triggered": callback.triggered,
            "triggered_at": callback.triggered_at,
            "evidence": callback.evidence if callback.triggered else None,
        }
