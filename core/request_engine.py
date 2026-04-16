"""
Central Request Engine - All HTTP traffic passes through here
Purpose: Unified request handling with auth injection, instrumentation, and logging
"""

import asyncio
import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Dict, Optional, Any, Tuple
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)


class RequestMethod(Enum):
    """HTTP Methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


@dataclass
class HTTPRequest:
    """Instrumented HTTP request"""
    method: RequestMethod
    url: str
    headers: Dict[str, str]
    body: Optional[str] = None
    timeout: float = 10.0
    follow_redirects: bool = True
    verify_ssl: bool = True
    created_at: str = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now().isoformat()


@dataclass
class HTTPResponse:
    """Instrumented HTTP response"""
    request: HTTPRequest
    status_code: int
    headers: Dict[str, str]
    body: str
    response_time: float  # seconds
    captured_at: str = None
    redirects: list = None
    
    def __post_init__(self):
        if self.captured_at is None:
            self.captured_at = datetime.now().isoformat()
        if self.redirects is None:
            self.redirects = []
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300
    
    @property
    def is_client_error(self) -> bool:
        return 400 <= self.status_code < 500
    
    @property
    def is_server_error(self) -> bool:
        return 500 <= self.status_code < 600
    
    @property
    def content_length(self) -> int:
        return len(self.body)


class RequestEngine:
    """
    Central HTTP request handler with:
    - Authentication injection
    - Instrumentation (timing, logging)
    - Retry logic
    - Session management hooks
    """
    
    def __init__(self, auth_engine=None, timeout: float = 10.0, 
                 max_retries: int = 3, verify_ssl: bool = True):
        """
        Args:
            auth_engine: AuthEngine instance for credential injection
            timeout: Default request timeout
            max_retries: Auto-retry on network errors
            verify_ssl: SSL verification (for testing set False)
        """
        self.auth_engine = auth_engine
        self.timeout = timeout
        self.max_retries = max_retries
        self.verify_ssl = verify_ssl
        self.client: Optional[httpx.AsyncClient] = None
        self.request_log = []
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=self.verify_ssl,
            follow_redirects=True
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.client:
            await self.client.aclose()
    
    async def request(self, method: RequestMethod | str, url: str, 
                     role: Optional[str] = None,
                     headers: Optional[Dict[str, str]] = None,
                     data: Optional[Dict | str] = None,
                     json_body: Optional[Dict] = None,
                     **kwargs) -> HTTPResponse:
        """
        Make HTTP request with optional auth injection
        
        Args:
            method: HTTP method (GET, POST, etc)
            url: Target URL
            role: For authenticated request (pulls auth from auth_engine)
            headers: Custom headers
            data: Form data
            json_body: JSON request body
            **kwargs: Additional httpx arguments
        
        Returns:
            HTTPResponse with instrumentation
        """
        if isinstance(method, str):
            method = RequestMethod[method.upper()]
        
        # Build request headers
        req_headers = headers or {}
        
        # Inject authentication if role specified
        if role and self.auth_engine:
            auth_headers, auth_cookies = await self.auth_engine.get_auth_for_role(role)
            req_headers.update(auth_headers)
            if auth_cookies:
                req_headers["Cookie"] = auth_cookies
        
        # Prepare request
        req_kwargs = {
            "headers": req_headers,
            **kwargs
        }
        
        if data:
            req_kwargs["data"] = data
        if json_body:
            req_kwargs["json"] = json_body
        
        # Create request object
        http_request = HTTPRequest(
            method=method,
            url=url,
            headers=req_headers,
            body=str(data or json_body or None)
        )
        
        # Execute with retries
        response = None
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                start_time = time.time()
                
                if not self.client:
                    async with httpx.AsyncClient(
                        timeout=self.timeout,
                        verify=self.verify_ssl
                    ) as client:
                        raw_response = await client.request(
                            method.value, url, **req_kwargs
                        )
                else:
                    raw_response = await self.client.request(
                        method.value, url, **req_kwargs
                    )
                
                response_time = time.time() - start_time
                
                # Create response object
                response = HTTPResponse(
                    request=http_request,
                    status_code=raw_response.status_code,
                    headers=dict(raw_response.headers),
                    body=raw_response.text,
                    response_time=response_time,
                    redirects=list(raw_response.history) if raw_response.history else []
                )
                
                # Log request
                logger.debug(
                    f"[REQ] {method.value} {url} → "
                    f"{response.status_code} ({response_time:.2f}s)"
                )
                
                self.request_log.append({
                    "timestamp": datetime.now().isoformat(),
                    "method": method.value,
                    "url": url,
                    "status": response.status_code,
                    "time": response_time,
                    "role": role
                })
                
                return response
            
            except httpx.RequestError as e:
                last_error = e
                wait_time = 2 ** attempt
                logger.warning(
                    f"Request error (attempt {attempt + 1}/{self.max_retries}): {e}"
                )
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(wait_time)
        
        # All retries exhausted
        raise Exception(f"Request failed after {self.max_retries} attempts: {last_error}")
    
    async def get(self, url: str, role: Optional[str] = None, 
                  headers: Optional[Dict[str, str]] = None, **kwargs) -> HTTPResponse:
        """GET request"""
        return await self.request(RequestMethod.GET, url, role, headers, **kwargs)
    
    async def post(self, url: str, role: Optional[str] = None,
                   headers: Optional[Dict[str, str]] = None,
                   data: Optional[Dict | str] = None,
                   json_body: Optional[Dict] = None, **kwargs) -> HTTPResponse:
        """POST request"""
        return await self.request(
            RequestMethod.POST, url, role, headers, 
            data=data, json_body=json_body, **kwargs
        )
    
    async def put(self, url: str, role: Optional[str] = None,
                  headers: Optional[Dict[str, str]] = None,
                  data: Optional[Dict | str] = None,
                  json_body: Optional[Dict] = None, **kwargs) -> HTTPResponse:
        """PUT request"""
        return await self.request(
            RequestMethod.PUT, url, role, headers,
            data=data, json_body=json_body, **kwargs
        )
    
    async def delete(self, url: str, role: Optional[str] = None,
                     headers: Optional[Dict[str, str]] = None, **kwargs) -> HTTPResponse:
        """DELETE request"""
        return await self.request(RequestMethod.DELETE, url, role, headers, **kwargs)
    
    def get_request_log(self) -> list:
        """Return instrumentation log"""
        return self.request_log
