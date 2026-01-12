"""
Authentication Adapter - Phase 3
Purpose: Handle authenticated scanning (cookies, tokens, session reuse)
Enables scanning of authenticated endpoints and privilege-escalation paths

Features:
  1. Cookie-based session injection
  2. Authorization header injection (Bearer, Basic, Custom)
  3. ZAP/OWASP session reuse
  4. Mark findings as AUTHENTICATED
  5. Multi-credential support
  6. Session validation
"""

import base64
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)


@dataclass
class CredentialSet:
    """Single credential set"""
    credential_id: str  # e.g., "admin_user", "service_account"
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    bearer_token: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    privilege_level: str = "USER"  # USER, ADMIN, SERVICE_ACCOUNT
    description: str = ""

    def get_auth_headers(self) -> Dict[str, str]:
        """Generate HTTP headers for authentication"""
        headers = {}

        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"
        elif self.api_key:
            headers["X-API-Key"] = self.api_key
        elif self.username and self.password:
            # Basic auth
            credentials = base64.b64encode(f"{self.username}:{self.password}".encode()).decode()
            headers["Authorization"] = f"Basic {credentials}"

        headers.update(self.custom_headers)
        return headers

    def get_cookies_header(self) -> Optional[str]:
        """Generate Cookie header from cookie dict"""
        if not self.cookies:
            return None
        return "; ".join([f"{k}={v}" for k, v in self.cookies.items()])

    def to_dict(self) -> Dict:
        return {
            "credential_id": self.credential_id,
            "username": self.username,
            "privilege_level": self.privilege_level,
            "has_token": bool(self.bearer_token),
            "has_api_key": bool(self.api_key),
            "cookies_count": len(self.cookies),
            "description": self.description
        }


@dataclass
class AuthenticatedFinding:
    """Finding identified with specific credentials"""
    endpoint: str
    parameter: str
    vulnerability_type: str
    credential_id: str
    privilege_level: str
    evidence: str = ""
    severity: str = "MEDIUM"


class AuthAdapter:
    """
    Multi-credential authenticated scanning
    
    Tracks which credentials can access which endpoints
    Marks findings as AUTHENTICATED with privilege level
    """

    def __init__(self, base_url: str):
        """
        Args:
            base_url: Target URL
        """
        self.base_url = base_url
        self.credentials: Dict[str, CredentialSet] = {}
        self.authenticated_findings: List[AuthenticatedFinding] = []
        self.credential_validation: Dict[str, Tuple[bool, datetime]] = {}  # id -> (valid, timestamp)

    def add_credential(self, credential: CredentialSet) -> None:
        """Register credential set"""
        self.credentials[credential.credential_id] = credential
        logger.info(f"[AuthAdapter] Added credential: {credential.credential_id} ({credential.privilege_level})")

    def add_credentials_from_dict(self, creds_dict: Dict) -> None:
        """
        Add credentials from dictionary
        
        Format:
        {
            "admin": {
                "username": "admin",
                "password": "admin123",
                "privilege_level": "ADMIN"
            },
            "user": {
                "username": "user1",
                "password": "user123",
                "privilege_level": "USER"
            }
        }
        """
        for cred_id, cred_data in creds_dict.items():
            credential = CredentialSet(
                credential_id=cred_id,
                username=cred_data.get("username"),
                password=cred_data.get("password"),
                api_key=cred_data.get("api_key"),
                bearer_token=cred_data.get("bearer_token"),
                custom_headers=cred_data.get("custom_headers", {}),
                cookies=cred_data.get("cookies", {}),
                privilege_level=cred_data.get("privilege_level", "USER"),
                description=cred_data.get("description", "")
            )
            self.add_credential(credential)

    def add_cookies_from_zap(self, zap_cookies: Dict[str, str], credential_id: str = "zap_session") -> None:
        """
        Import cookies from OWASP ZAP session
        
        Args:
            zap_cookies: Cookie dict from ZAP (e.g., {"JSESSIONID": "ABC123", "token": "XYZ"})
            credential_id: Credential ID to store under
        """
        if credential_id not in self.credentials:
            self.credentials[credential_id] = CredentialSet(
                credential_id=credential_id,
                privilege_level="UNAUTHENTICATED"
            )

        self.credentials[credential_id].cookies.update(zap_cookies)
        logger.info(f"[AuthAdapter] Imported {len(zap_cookies)} cookies into {credential_id}")

    def add_zap_session(self, session_data: Dict) -> None:
        """
        Import full ZAP session
        
        Args:
            session_data: ZAP session dict (from context export)
        """
        # Extract cookies
        cookies = session_data.get("cookies", {})
        if cookies:
            self.add_cookies_from_zap(cookies, "zap_session")

        # Extract authentication info
        auth_info = session_data.get("authentication", {})
        if auth_info:
            credential = CredentialSet(
                credential_id="zap_session",
                custom_headers=auth_info.get("headers", {}),
                privilege_level=auth_info.get("privilege_level", "AUTHENTICATED")
            )
            self.credentials["zap_session"] = credential

    def get_credential(self, credential_id: str) -> Optional[CredentialSet]:
        """Retrieve credential by ID"""
        return self.credentials.get(credential_id)

    def validate_credential(self, credential_id: str, test_url: str) -> bool:
        """
        Validate credential against test URL
        
        Args:
            credential_id: Credential to validate
            test_url: URL to test against (e.g., authenticated user profile)
            
        Returns:
            True if credential is valid
        """
        if credential_id not in self.credentials:
            return False

        # Check cache (valid for 1 hour)
        if credential_id in self.credential_validation:
            is_valid, timestamp = self.credential_validation[credential_id]
            if datetime.now() - timestamp < timedelta(hours=1):
                return is_valid

        try:
            import requests
            credential = self.credentials[credential_id]

            headers = credential.get_auth_headers()
            cookies_header = credential.get_cookies_header()
            if cookies_header:
                headers["Cookie"] = cookies_header

            response = requests.get(test_url, headers=headers, timeout=5, verify=False)
            is_valid = response.status_code < 400

            self.credential_validation[credential_id] = (is_valid, datetime.now())
            logger.info(f"[AuthAdapter] Validated {credential_id}: {is_valid}")

            return is_valid

        except Exception as e:
            logger.warning(f"[AuthAdapter] Validation failed for {credential_id}: {e}")
            self.credential_validation[credential_id] = (False, datetime.now())
            return False

    def get_headers_for_request(
        self,
        credential_id: Optional[str] = None,
        additional_headers: Optional[Dict[str, str]] = None
    ) -> Dict[str, str]:
        """
        Get complete headers for authenticated request
        
        Args:
            credential_id: Which credential to use
            additional_headers: Extra headers to merge
            
        Returns:
            Complete headers dict
        """
        headers = {}

        if credential_id and credential_id in self.credentials:
            credential = self.credentials[credential_id]
            headers.update(credential.get_auth_headers())

            # Add cookies
            cookies_header = credential.get_cookies_header()
            if cookies_header:
                headers["Cookie"] = cookies_header

        if additional_headers:
            headers.update(additional_headers)

        return headers

    def mark_finding_authenticated(
        self,
        endpoint: str,
        parameter: str,
        vulnerability_type: str,
        credential_id: str,
        evidence: str = ""
    ) -> AuthenticatedFinding:
        """Mark finding as discovered with specific authentication"""
        credential = self.credentials.get(credential_id)
        if not credential:
            logger.warning(f"[AuthAdapter] Unknown credential: {credential_id}")
            privilege_level = "UNKNOWN"
        else:
            privilege_level = credential.privilege_level

        finding = AuthenticatedFinding(
            endpoint=endpoint,
            parameter=parameter,
            vulnerability_type=vulnerability_type,
            credential_id=credential_id,
            privilege_level=privilege_level,
            evidence=evidence
        )

        self.authenticated_findings.append(finding)
        logger.info(
            f"[AuthAdapter] Marked {vulnerability_type} on {endpoint}[{parameter}] "
            f"as AUTHENTICATED ({credential_id}/{privilege_level})"
        )

        return finding

    def get_authenticated_findings(
        self,
        credential_id: Optional[str] = None
    ) -> List[AuthenticatedFinding]:
        """Get all findings, optionally filtered by credential"""
        if credential_id:
            return [f for f in self.authenticated_findings if f.credential_id == credential_id]
        return self.authenticated_findings

    def get_privilege_escalation_paths(self) -> Dict[str, List[str]]:
        """
        Identify privilege escalation paths
        
        Returns:
            Dict mapping endpoint -> [privilege levels that can access]
        """
        paths = {}
        for finding in self.authenticated_findings:
            key = (finding.endpoint, finding.parameter, finding.vulnerability_type)
            if key not in paths:
                paths[key] = []
            if finding.privilege_level not in paths[key]:
                paths[key].append(finding.privilege_level)

        # Filter to those accessible by multiple privilege levels
        escalation_paths = {k: v for k, v in paths.items() if len(v) > 1}
        return escalation_paths

    def get_summary(self) -> Dict:
        """Get authentication adapter summary"""
        by_privilege = {}
        for finding in self.authenticated_findings:
            if finding.privilege_level not in by_privilege:
                by_privilege[finding.privilege_level] = 0
            by_privilege[finding.privilege_level] += 1

        escalation_paths = self.get_privilege_escalation_paths()

        return {
            "credentials_registered": len(self.credentials),
            "total_authenticated_findings": len(self.authenticated_findings),
            "findings_by_privilege": by_privilege,
            "privilege_escalation_paths": len(escalation_paths),
            "credentials": {cid: c.to_dict() for cid, c in self.credentials.items()}
        }

    def to_dict(self) -> Dict:
        """Serialize authentication state"""
        return {
            "summary": self.get_summary(),
            "findings": [
                {
                    "endpoint": f.endpoint,
                    "parameter": f.parameter,
                    "vulnerability_type": f.vulnerability_type,
                    "credential_id": f.credential_id,
                    "privilege_level": f.privilege_level,
                    "evidence": f.evidence
                }
                for f in self.authenticated_findings
            ]
        }


# Example usage
"""
auth = AuthAdapter(base_url="https://example.com")

# Add credentials
auth.add_credentials_from_dict({
    "admin": {
        "username": "admin",
        "password": "admin123",
        "privilege_level": "ADMIN"
    },
    "user1": {
        "username": "user1",
        "password": "user123",
        "privilege_level": "USER"
    }
})

# Validate credentials
auth.validate_credential("admin", "https://example.com/profile")

# Get authenticated headers for requests
headers = auth.get_headers_for_request("admin")

# Mark findings as authenticated
auth.mark_finding_authenticated(
    endpoint="/admin/users",
    parameter="id",
    vulnerability_type="SQL_INJECTION",
    credential_id="admin",
    evidence="Injected payload reflected in response"
)

# Get privilege escalation paths
escalation = auth.get_privilege_escalation_paths()

print(auth.get_summary())
"""
