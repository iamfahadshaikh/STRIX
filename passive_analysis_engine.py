"""Passive response analysis for hardening/security misconfiguration findings."""

from typing import Dict, List


def analyze_headers(url: str, headers: Dict[str, str]) -> List[Dict]:
    findings: List[Dict] = []
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}

    if "content-security-policy" not in lowered:
        findings.append(
            {
                "category": "Missing CSP",
                "severity": "MEDIUM",
                "confidence": 0.95,
                "endpoint": url,
                "evidence": "No Content-Security-Policy header",
                "source": "passive",
            }
        )

    if lowered.get("access-control-allow-origin", "") == "*":
        findings.append(
            {
                "category": "Permissive CORS",
                "severity": "MEDIUM",
                "confidence": 0.90,
                "endpoint": url,
                "evidence": "Access-Control-Allow-Origin: *",
                "source": "passive",
            }
        )

    hsts = lowered.get("strict-transport-security", "")
    if not hsts:
        findings.append(
            {
                "category": "Missing HSTS",
                "severity": "MEDIUM",
                "confidence": 0.92,
                "endpoint": url,
                "evidence": "No Strict-Transport-Security header",
                "source": "passive",
            }
        )

    if "server" in lowered:
        findings.append(
            {
                "category": "Server Header Disclosure",
                "severity": "INFO",
                "confidence": 0.90,
                "endpoint": url,
                "evidence": f"Server: {lowered.get('server', '')}",
                "source": "passive",
            }
        )

    if "set-cookie" in lowered and "secure" not in lowered.get("set-cookie", "").lower():
        findings.append(
            {
                "category": "Cookie Missing Secure Flag",
                "severity": "MEDIUM",
                "confidence": 0.85,
                "endpoint": url,
                "evidence": lowered.get("set-cookie", ""),
                "source": "passive",
            }
        )

    if "set-cookie" in lowered and "httponly" not in lowered.get("set-cookie", "").lower():
        findings.append(
            {
                "category": "Cookie Missing HttpOnly Flag",
                "severity": "MEDIUM",
                "confidence": 0.85,
                "endpoint": url,
                "evidence": lowered.get("set-cookie", ""),
                "source": "passive",
            }
        )

    return findings
