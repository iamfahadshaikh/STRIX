"""
Session Manager - Per-role session lifecycle management
Purpose: Maintain isolated sessions for each role (user, admin, etc)
Handles creation, refreshing, and expiry detection
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class AuthType(Enum):
    """Authentication types"""

    FORM_LOGIN = "form_login"
    JSON_LOGIN = "json_login"
    API_KEY = "api_key"
    BEARER_TOKEN = "bearer_token"
    BASIC_AUTH = "basic_auth"
    CUSTOM_HEADER = "custom_header"


@dataclass
class TokenInfo:
    """Token metadata"""

    token: str
    token_field: str  # JSON path like "data.access_token"
    expires_at: Optional[datetime] = None
    refresh_token: Optional[str] = None
    token_type: str = "Bearer"
    raw_response: Dict = field(default_factory=dict)


@dataclass
class SessionData:
    """Complete session for a role"""

    role: str
    auth_type: AuthType
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    token_info: Optional[TokenInfo] = None
    created_at: datetime = field(default_factory=datetime.now)
    last_activity: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def is_expired(self) -> bool:
        """Check if session expired"""
        if self.expires_at:
            return datetime.now() >= self.expires_at
        # Default: sessions valid for 2 hours
        return datetime.now() - self.created_at > timedelta(hours=2)

    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now()

    def to_dict(self) -> Dict:
        """Export session metadata (no secrets)"""
        return {
            "role": self.role,
            "auth_type": self.auth_type.value,
            "cookies_count": len(self.cookies),
            "has_token": bool(self.token_info),
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "is_expired": self.is_expired(),
            "metadata": self.metadata,
        }


class SessionManager:
    """
    Central session store for all roles

    Features:
    - Per-role isolated sessions
    - Automatic expiry detection
    - Last-activity tracking
    - Thread-safe operations
    """

    def __init__(self, default_session_timeout: int = 7200):
        """
        Args:
            default_session_timeout: Seconds before session expires (default 2 hours)
        """
        self.default_session_timeout = default_session_timeout
        self._sessions: Dict[str, SessionData] = {}
        self._lock = asyncio.Lock()

    async def create_session(
        self, role: str, auth_type: AuthType, expires_in: Optional[int] = None
    ) -> SessionData:
        """
        Create new session for role

        Args:
            role: Role identifier (e.g., "user", "admin")
            auth_type: Authentication method
            expires_in: Custom expiry time in seconds

        Returns:
            SessionData instance
        """
        async with self._lock:
            session = SessionData(
                role=role,
                auth_type=auth_type,
                expires_at=datetime.now()
                + timedelta(seconds=expires_in or self.default_session_timeout),
            )
            self._sessions[role] = session
            logger.info(f"Created session for role: {role}")
            return session

    async def get_session(self, role: str) -> Optional[SessionData]:
        """Get session by role"""
        async with self._lock:
            session = self._sessions.get(role)
            if session and not session.is_expired():
                session.update_activity()
                return session
            return None

    async def update_cookies(self, role: str, cookies: Dict[str, str]):
        """Update session cookies"""
        async with self._lock:
            if role in self._sessions:
                self._sessions[role].cookies.update(cookies)
                self._sessions[role].update_activity()
                logger.debug(f"Updated cookies for role {role}")

    async def update_headers(self, role: str, headers: Dict[str, str]):
        """Update session headers"""
        async with self._lock:
            if role in self._sessions:
                self._sessions[role].headers.update(headers)
                self._sessions[role].update_activity()
                logger.debug(f"Updated headers for role {role}")

    async def set_token(self, role: str, token_info: TokenInfo):
        """Store token for role"""
        async with self._lock:
            if role in self._sessions:
                self._sessions[role].token_info = token_info
                if token_info.expires_at:
                    self._sessions[role].expires_at = token_info.expires_at
                self._sessions[role].update_activity()
                logger.debug(f"Stored token for role {role}")

    async def set_metadata(self, role: str, metadata: Dict[str, Any]):
        """Set custom metadata on session"""
        async with self._lock:
            if role in self._sessions:
                self._sessions[role].metadata.update(metadata)

    async def invalidate_session(self, role: str):
        """Invalidate session for role"""
        async with self._lock:
            if role in self._sessions:
                del self._sessions[role]
                logger.info(f"Invalidated session for role: {role}")

    async def invalidate_all(self):
        """Invalidate all sessions"""
        async with self._lock:
            self._sessions.clear()
            logger.info("Invalidated all sessions")

    async def list_sessions(self) -> Dict[str, Dict]:
        """List all active sessions (metadata only)"""
        async with self._lock:
            return {
                role: session.to_dict()
                for role, session in self._sessions.items()
                if not session.is_expired()
            }

    async def cleanup_expired(self):
        """Remove expired sessions"""
        async with self._lock:
            expired_roles = [
                role for role, session in self._sessions.items() if session.is_expired()
            ]
            for role in expired_roles:
                del self._sessions[role]
                logger.info(f"Cleaned up expired session: {role}")
            return len(expired_roles)

    async def get_auth_context(self, role: str) -> Tuple[Dict[str, str], Optional[str]]:
        """
        Get authentication context for role

        Returns:
            (headers_dict, cookies_header_string)
        """
        session = await self.get_session(role)
        if not session:
            return {}, None

        headers = session.headers.copy()

        # Add token if present
        if session.token_info:
            headers["Authorization"] = (
                f"{session.token_info.token_type} {session.token_info.token}"
            )

        # Format cookies
        cookies_header = None
        if session.cookies:
            cookies_header = "; ".join(f"{k}={v}" for k, v in session.cookies.items())

        return headers, cookies_header
