"""
Authentication Engine - Multi-role session management and automated login
Purpose: Handle login, token extraction, session management, and credential injection
Supports: Form login, JSON login, API keys, JWT, custom headers
"""

import logging
import asyncio
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple, Any
from enum import Enum

from core.request_engine import RequestEngine, HTTPResponse
from core.session_manager import SessionManager, SessionData, AuthType, TokenInfo

logger = logging.getLogger(__name__)


@dataclass
class LoginConfig:
    """Configuration for a login flow"""
    role: str
    auth_type: AuthType
    login_url: str
    username: Optional[str] = None
    password: Optional[str] = None
    api_key: Optional[str] = None
    bearer_token: Optional[str] = None
    custom_headers: Dict[str, str] = field(default_factory=dict)
    login_data: Dict[str, str] = field(default_factory=dict)  # Form fields
    token_extract_field: str = "token"  # JSON path to token in response
    token_field_path: str = "data.access_token"  # Nested JSON path
    expected_status_success: int = 200
    cookie_names: List[str] = field(default_factory=list)  # Session cookies to extract


class AuthEngine:
    """
    Automated authentication engine supporting multiple roles and auth types
    
    Features:
    - Form-based login with automatic token extraction
    - JSON login payloads
    - Session cookie management
    - Bearer token handling
    - API key injection
    - Session expiry detection and reauth
    - Multi-role isolation
    """
    
    def __init__(self, request_engine: RequestEngine, 
                 default_timeout: float = 30.0):
        """
        Args:
            request_engine: RequestEngine instance for HTTP requests
            default_timeout: Default request timeout for login flows
        """
        self.request_engine = request_engine
        self.session_manager = SessionManager()
        self.login_configs: Dict[str, LoginConfig] = {}
        self.default_timeout = default_timeout
    
    async def register_login_flow(self, config: LoginConfig) -> bool:
        """
        Register a login flow for a role
        
        Args:
            config: LoginConfig with credentials and endpoints
        
        Returns:
            True if valid, False otherwise
        """
        # Validation
        if not config.role or not config.login_url:
            logger.error("Role and login_url are required")
            return False
        
        if config.auth_type == AuthType.FORM_LOGIN and not config.login_data:
            logger.error("FORM_LOGIN requires login_data")
            return False
        
        self.login_configs[config.role] = config
        logger.info(f"Registered login flow for role: {config.role}")
        return True
    
    async def authenticate_all_roles(self) -> Dict[str, bool]:
        """
        Authenticate all configured roles
        
        Returns:
            Dict mapping role -> success/failure
        """
        results = {}
        
        for role, config in self.login_configs.items():
            try:
                success = await self.authenticate_role(role)
                results[role] = success
            except Exception as e:
                logger.error(f"Failed to authenticate {role}: {e}")
                results[role] = False
        
        return results
    
    async def authenticate_role(self, role: str) -> bool:
        """
        Authenticate a single role
        
        Args:
            role: Role to authenticate
        
        Returns:
            True if successful
        """
        if role not in self.login_configs:
            logger.error(f"No login config for role: {role}")
            return False
        
        config = self.login_configs[role]
        logger.info(f"Authenticating role: {role}")
        
        try:
            # Create session first
            session = await self.session_manager.create_session(role, config.auth_type)
            
            # Handle different auth types
            if config.auth_type == AuthType.FORM_LOGIN:
                return await self._handle_form_login(role, config, session)
            
            elif config.auth_type == AuthType.JSON_LOGIN:
                return await self._handle_json_login(role, config, session)
            
            elif config.auth_type == AuthType.API_KEY:
                return await self._handle_api_key(role, config, session)
            
            elif config.auth_type == AuthType.BEARER_TOKEN:
                return await self._handle_bearer_token(role, config, session)
            
            else:
                logger.error(f"Unsupported auth type: {config.auth_type}")
                return False
        
        except Exception as e:
            logger.error(f"Authentication failed for {role}: {e}")
            await self.session_manager.invalidate_session(role)
            return False
    
    async def _handle_form_login(self, role: str, config: LoginConfig,
                                session: SessionData) -> bool:
        """Handle form-based login"""
        try:
            response = await self.request_engine.post(
                config.login_url,
                data=config.login_data,
                timeout=self.default_timeout
            )
            
            if response.status_code != config.expected_status_success:
                logger.error(
                    f"Login failed: expected {config.expected_status_success}, "
                    f"got {response.status_code}"
                )
                return False
            
            # Extract cookies
            await self._extract_cookies_from_response(response, config, session)
            
            # Extract token if response is JSON
            if "application/json" in response.headers.get("Content-Type", ""):
                await self._extract_token_from_response(response, config, session)
            
            logger.info(f"Form login successful for {role}")
            return True
        
        except Exception as e:
            logger.error(f"Form login error: {e}")
            return False
    
    async def _handle_json_login(self, role: str, config: LoginConfig,
                                session: SessionData) -> bool:
        """Handle JSON login"""
        try:
            response = await self.request_engine.post(
                config.login_url,
                json_body=config.login_data,
                timeout=self.default_timeout
            )
            
            if response.status_code != config.expected_status_success:
                logger.error(f"JSON login failed: {response.status_code}")
                return False
            
            # Extract token from JSON response
            await self._extract_token_from_response(response, config, session)
            
            # Extract cookies if any
            await self._extract_cookies_from_response(response, config, session)
            
            logger.info(f"JSON login successful for {role}")
            return True
        
        except Exception as e:
            logger.error(f"JSON login error: {e}")
            return False
    
    async def _handle_api_key(self, role: str, config: LoginConfig,
                             session: SessionData) -> bool:
        """Handle API key authentication"""
        try:
            session.headers["X-API-Key"] = config.api_key
            await self.session_manager.update_headers(role, session.headers)
            logger.info(f"API key auth set for {role}")
            return True
        
        except Exception as e:
            logger.error(f"API key setup error: {e}")
            return False
    
    async def _handle_bearer_token(self, role: str, config: LoginConfig,
                                  session: SessionData) -> bool:
        """Handle Bearer token authentication"""
        try:
            token_info = TokenInfo(
                token=config.bearer_token,
                token_field="token",
                token_type="Bearer"
            )
            await self.session_manager.set_token(role, token_info)
            logger.info(f"Bearer token auth set for {role}")
            return True
        
        except Exception as e:
            logger.error(f"Bearer token setup error: {e}")
            return False
    
    async def _extract_token_from_response(self, response: HTTPResponse,
                                          config: LoginConfig,
                                          session: SessionData):
        """Extract token from response JSON and store in session"""
        try:
            response_json = json.loads(response.body)
        except json.JSONDecodeError:
            logger.warning("Response not valid JSON")
            return
        
        # Navigate to token in JSON using path
        token_value = self._get_nested_value(
            response_json, config.token_field_path
        )
        
        if token_value:
            # Check token expiry if present
            expires_at = None
            if "expires_in" in response_json:
                expires_in = response_json["expires_in"]
                expires_at = datetime.now() + timedelta(seconds=expires_in)
            
            token_info = TokenInfo(
                token=token_value,
                token_field=config.token_field_path,
                expires_at=expires_at,
                token_type="Bearer",
                raw_response=response_json
            )
            
            await self.session_manager.set_token(session.role, token_info)
            logger.debug(f"Token extracted for {session.role}")
        else:
            logger.warning(f"Could not extract token using path: {config.token_field_path}")
    
    async def _extract_cookies_from_response(self, response: HTTPResponse,
                                            config: LoginConfig,
                                            session: SessionData):
        """Extract session cookies from Set-Cookie header"""
        set_cookie = response.headers.get("Set-Cookie", "")
        
        if not set_cookie:
            return
        
        cookies_to_extract = config.cookie_names or [
            "session", "sessionid", "JSESSIONID", "PHPSESSID", 
            "session_id", "auth_token", "auth"
        ]
        
        for cookie_def in set_cookie.split(","):
            for cookie_name in cookies_to_extract:
                if cookie_name.lower() in cookie_def.lower():
                    # Parse cookie
                    if "=" in cookie_def:
                        parts = cookie_def.split(";")[0].split("=", 1)
                        name, value = parts[0].strip(), parts[1].strip()
                        
                        cookies = {name: value}
                        await self.session_manager.update_cookies(
                            session.role, cookies
                        )
                        logger.debug(f"Cookie extracted: {name}")
    
    def _get_nested_value(self, obj: Dict, path: str) -> Optional[str]:
        """
        Get value from nested dictionary using dot notation
        
        Args:
            obj: Dictionary
            path: Dot-separated path (e.g., "data.access_token")
        
        Returns:
            Value or None
        """
        parts = path.split(".")
        current = obj
        
        for part in parts:
            try:
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return None
            except (KeyError, TypeError):
                return None
        
        return str(current) if current is not None else None
    
    async def get_authenticated_request(self, role: str, method: str, url: str,
                                       **kwargs) -> HTTPResponse:
        """
        Make authenticated request with role's credentials
        
        Args:
            role: Role to use for authentication
            method: HTTP method
            url: Target URL
            **kwargs: Additional request parameters
        
        Returns:
            HTTP response
        """
        session = await self.session_manager.get_session(role)
        
        if not session:
            logger.error(f"No valid session for role: {role}")
            raise Exception(f"Session expired or not authenticated: {role}")
        
        # Inject authentication
        headers = kwargs.get("headers", {})
        headers.update(session.headers)
        
        if session.token_info:
            headers["Authorization"] = (
                f"{session.token_info.token_type} {session.token_info.token}"
            )
        
        if session.cookies:
            cookies_str = "; ".join(f"{k}={v}" for k, v in session.cookies.items())
            headers["Cookie"] = cookies_str
        
        kwargs["headers"] = headers
        
        # Make request
        request_method = method.upper()
        if request_method == "GET":
            return await self.request_engine.get(url, headers=headers, **kwargs)
        elif request_method == "POST":
            return await self.request_engine.post(url, headers=headers, **kwargs)
        elif request_method == "PUT":
            return await self.request_engine.put(url, headers=headers, **kwargs)
        elif request_method == "DELETE":
            return await self.request_engine.delete(url, headers=headers, **kwargs)
        else:
            raise ValueError(f"Unsupported method: {method}")
    
    async def refresh_session(self, role: str) -> bool:
        """
        Refresh session for role (re-authenticate)
        
        Args:
            role: Role to refresh
        
        Returns:
            True if successful
        """
        logger.info(f"Refreshing session for {role}")
        
        # Invalidate old session
        await self.session_manager.invalidate_session(role)
        
        # Re-authenticate
        return await self.authenticate_role(role)
    
    async def get_auth_for_role(self, role: str) -> Tuple[Dict[str, str], Optional[str]]:
        """
        Get auth headers and cookies for role
        Used by RequestEngine for transparent auth injection
        
        Returns:
            (headers_dict, cookies_header_string)
        """
        return await self.session_manager.get_auth_context(role)
    
    async def check_session_status(self) -> Dict[str, Dict]:
        """Get status of all active sessions"""
        return await self.session_manager.list_sessions()
