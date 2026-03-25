"""
SSL Certificate Checker
Purpose: Validate TLS certificates, chain health, and expiry for hosts/subdomains
"""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Dict, List, Optional


logger = logging.getLogger(__name__)


class SSLCertificateChecker:
    """Checks certificate validity, trust chain, and expiry for TLS endpoints."""

    EXPIRY_WARNING_DAYS = 30

    def check_host(self, host: str, ports: List[int]) -> List[Dict]:
        """Check TLS certificate health for all candidate ports on a host."""
        results: List[Dict] = []
        seen_ports = sorted({int(p) for p in ports if 1 <= int(p) <= 65535})
        for port in seen_ports:
            results.append(self._check_host_port(host, port))
        return results

    def _check_host_port(self, host: str, port: int) -> Dict:
        """Run strict certificate checks for a host:port."""
        base = {
            "host": host,
            "port": port,
            "tls_enabled": False,
            "certificate_present": False,
            "chain_valid": False,
            "chain_complete": False,
            "verified_chain_length": 0,
            "subject": "",
            "issuer": "",
            "expires_at": None,
            "days_until_expiry": None,
            "is_expired": None,
            "expires_soon": None,
            "status": "UNKNOWN",
            "errors": [],
        }

        # 1) Strict verification path: validates trust + chain
        try:
            strict_ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with strict_ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                    tls_sock.settimeout(5)
                    tls_sock.do_handshake()
                    base["tls_enabled"] = True
                    base["chain_valid"] = True
                    cert = tls_sock.getpeercert() or {}
                    base["certificate_present"] = bool(cert)
                    base["subject"] = self._flatten_name(cert.get("subject", ()))
                    base["issuer"] = self._flatten_name(cert.get("issuer", ()))

                    if hasattr(tls_sock, "get_verified_chain"):
                        try:
                            chain = tls_sock.get_verified_chain()  # Python 3.12+
                            if chain:
                                base["verified_chain_length"] = len(chain)
                                base["chain_complete"] = len(chain) >= 2
                            else:
                                base["chain_complete"] = False
                        except Exception:
                            # If unavailable at runtime, fallback to trust result
                            base["chain_complete"] = base["chain_valid"]
                    else:
                        # Fallback: successful trust validation implies usable chain path
                        base["chain_complete"] = base["chain_valid"]

                    self._apply_expiry_fields(base, cert.get("notAfter"))

        except ssl.SSLCertVerificationError as exc:
            base["tls_enabled"] = True
            base["errors"].append(f"certificate_verification_failed: {exc}")
        except ssl.SSLError as exc:
            base["errors"].append(f"tls_handshake_failed: {exc}")
        except (socket.timeout, TimeoutError):
            base["errors"].append("connection_timeout")
        except Exception as exc:  # noqa: BLE001
            base["errors"].append(f"connection_error: {exc}")

        # 2) If strict path failed or provided no cert details, fetch unverified cert for expiry insight
        if not base["certificate_present"]:
            try:
                insecure_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                insecure_ctx.check_hostname = False
                insecure_ctx.verify_mode = ssl.CERT_NONE
                with socket.create_connection((host, port), timeout=5) as sock:
                    with insecure_ctx.wrap_socket(sock, server_hostname=host) as tls_sock:
                        cert = tls_sock.getpeercert() or {}
                        if cert:
                            base["tls_enabled"] = True
                            base["certificate_present"] = True
                            if not base["subject"]:
                                base["subject"] = self._flatten_name(cert.get("subject", ()))
                            if not base["issuer"]:
                                base["issuer"] = self._flatten_name(cert.get("issuer", ()))
                            self._apply_expiry_fields(base, cert.get("notAfter"))
            except Exception:
                pass

        base["status"] = self._derive_status(base)
        return base

    def _apply_expiry_fields(self, result: Dict, not_after: Optional[str]) -> None:
        """Parse and store expiry fields from X.509 notAfter."""
        if not not_after:
            return

        expiry = self._parse_cert_time(not_after)
        if not expiry:
            result["errors"].append(f"unparseable_expiry: {not_after}")
            return

        now = datetime.now(timezone.utc)
        remaining = expiry - now
        days_left = int(remaining.total_seconds() // 86400)

        result["expires_at"] = expiry.isoformat()
        result["days_until_expiry"] = days_left
        result["is_expired"] = days_left < 0
        result["expires_soon"] = 0 <= days_left <= self.EXPIRY_WARNING_DAYS

    def _derive_status(self, result: Dict) -> str:
        """Compute final certificate health status."""
        if not result["tls_enabled"]:
            return "NO_TLS"
        if not result["certificate_present"]:
            return "NO_CERT"
        if result.get("is_expired"):
            return "EXPIRED"
        if result.get("expires_soon"):
            return "EXPIRING_SOON"
        if not result["chain_valid"]:
            return "CHAIN_INVALID"
        if not result["chain_complete"]:
            return "CHAIN_INCOMPLETE"
        return "OK"

    @staticmethod
    def _flatten_name(name_tuple: tuple) -> str:
        """Flatten OpenSSL subject/issuer tuple into readable text."""
        parts: List[str] = []
        for rdn in name_tuple:
            for item in rdn:
                if isinstance(item, tuple) and len(item) == 2:
                    parts.append(f"{item[0]}={item[1]}")
        return ", ".join(parts)

    @staticmethod
    def _parse_cert_time(value: str) -> Optional[datetime]:
        """Parse OpenSSL cert times like 'Mar 12 23:59:59 2027 GMT'."""
        # Common format emitted by ssl.getpeercert()
        formats = [
            "%b %d %H:%M:%S %Y %Z",
            "%b  %d %H:%M:%S %Y %Z",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(value, fmt)
                return dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
        return None
