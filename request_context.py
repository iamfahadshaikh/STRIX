"""
Request context manager for role-aware scanning.

Provides a single place to keep auth headers/cookies per role and attach
consistent metadata to downstream requests.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class RoleRequestContext:
    role: str
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    authenticated: bool = False
    source: str = "manual"
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def cookie_header(self) -> str:
        if not self.cookies:
            return ""
        return "; ".join([f"{k}={v}" for k, v in self.cookies.items()])


class RequestContextManager:
    """Central role-aware request context registry."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._contexts: Dict[str, RoleRequestContext] = {}

    def add_or_update_role(
        self,
        role: str,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        authenticated: bool = True,
        source: str = "auth_engine",
    ) -> None:
        ctx = self._contexts.get(role)
        if not ctx:
            ctx = RoleRequestContext(role=role, source=source)
            self._contexts[role] = ctx

        if headers:
            ctx.headers.update(headers)
        if cookies:
            ctx.cookies.update(cookies)
        ctx.authenticated = authenticated
        ctx.source = source or ctx.source

    def get_context(self, role: str) -> Optional[RoleRequestContext]:
        return self._contexts.get(role)

    def build_headers(self, role: str, extra_headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers: Dict[str, str] = {}
        ctx = self._contexts.get(role)
        if ctx:
            headers.update(ctx.headers)
            cookie_header = ctx.cookie_header()
            if cookie_header and "Cookie" not in headers:
                headers["Cookie"] = cookie_header
        if extra_headers:
            headers.update(extra_headers)
        return headers

    def active_roles(self, include_anonymous: bool = True) -> List[str]:
        roles = sorted([r for r, c in self._contexts.items() if c.authenticated])
        if include_anonymous:
            return ["anonymous"] + roles
        return roles

    def summary(self) -> Dict[str, object]:
        roles = []
        for role, ctx in sorted(self._contexts.items()):
            roles.append(
                {
                    "role": role,
                    "authenticated": ctx.authenticated,
                    "headers": len(ctx.headers),
                    "cookies": len(ctx.cookies),
                    "source": ctx.source,
                }
            )
        return {
            "base_url": self.base_url,
            "roles": roles,
            "authenticated_roles": len([r for r in roles if r["authenticated"]]),
        }
