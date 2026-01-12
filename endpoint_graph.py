"""
Endpoint & Parameter Graph - Phase 2
Purpose: Build normalized graph of endpoints → methods → parameters
Source of truth for payload tool gating

Graph Structure:
  target/
    ├── endpoints/
    │   ├── /api/users
    │   │   ├── method: GET
    │   │   ├── params: {id, filter}
    │   │   ├── sources: [crawler, form]
    │   │   └── dynamic: true
    │   ├── /login
    │   │   ├── method: POST
    │   │   ├── params: {username, password}
    │   │   ├── sources: [form]
    │   │   └── dynamic: false
    │   ...
    └── parameters/
        ├── id: {appears_in: [/api/users, /api/posts], frequency: 2, reflectable: false}
        ├── search: {appears_in: [/api/users], frequency: 1, reflectable: true}
        ...
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from enum import Enum
from collections import defaultdict
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


class ParameterSource(Enum):
    """Where parameter was discovered"""
    URL_QUERY = "url_query"
    FORM_INPUT = "form_input"
    JS_DETECTED = "js_detected"
    API_DOCS = "api_docs"
    CRAWLED = "crawled"


class HTTPMethod(Enum):
    """HTTP methods"""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


@dataclass
class Parameter:
    """Parameter node in graph"""
    name: str
    # Where it was found
    sources: Set[ParameterSource] = field(default_factory=set)
    # Which endpoints have this param
    endpoints: Set[str] = field(default_factory=set)
    # Frequency (lower = unique, higher = common)
    frequency: int = 1
    # Indicators
    reflectable: bool = False
    injectable_sql: bool = False
    injectable_cmd: bool = False
    injectable_ssrf: bool = False
    # Values seen
    sample_values: Set[str] = field(default_factory=set)

    def add_source(self, source: ParameterSource):
        """Add discovery source"""
        self.sources.add(source)

    def add_value(self, value: str):
        """Track sample values"""
        if value and len(value) < 100:  # Only short values
            self.sample_values.add(value[:50])

    def is_dynamic(self) -> bool:
        """Param appears in multiple endpoints or has multiple values"""
        return len(self.endpoints) > 1 or len(self.sample_values) > 1

    def to_dict(self) -> Dict:
        """Serialize"""
        return {
            "name": self.name,
            "sources": [s.value for s in self.sources],
            "endpoints": list(self.endpoints),
            "frequency": self.frequency,
            "reflectable": self.reflectable,
            "injectable_sql": self.injectable_sql,
            "injectable_cmd": self.injectable_cmd,
            "injectable_ssrf": self.injectable_ssrf,
            "sample_values": list(self.sample_values)[:3],
            "dynamic": self.is_dynamic()
        }


@dataclass
class Endpoint:
    """Endpoint node in graph"""
    path: str  # Normalized path like /api/users, /login
    # HTTP methods that reach this endpoint
    methods: Set[HTTPMethod] = field(default_factory=set)
    # Parameters accepted
    parameters: Dict[str, Parameter] = field(default_factory=dict)
    # Discovery sources
    sources: Set[ParameterSource] = field(default_factory=set)
    # Status indicators
    status_code: Optional[int] = None
    is_api: bool = False
    is_form: bool = False
    # Dynamic = uses parameters, likely application logic
    dynamic: bool = False
    # How many distinct values seen
    unique_value_count: int = 0

    def add_method(self, method: HTTPMethod):
        """Add HTTP method"""
        self.methods.add(method)

    def add_parameter(self, param: Parameter):
        """Add parameter to endpoint"""
        if param.name not in self.parameters:
            self.parameters[param.name] = param
        self.parameters[param.name].endpoints.add(self.path)
        self.parameters[param.name].frequency += 1

    def add_source(self, source: ParameterSource):
        """Add discovery source"""
        self.sources.add(source)

    def to_dict(self) -> Dict:
        """Serialize"""
        return {
            "path": self.path,
            "methods": [m.value for m in self.methods],
            "parameters": {name: p.to_dict() for name, p in self.parameters.items()},
            "sources": [s.value for s in self.sources],
            "status_code": self.status_code,
            "is_api": self.is_api,
            "is_form": self.is_form,
            "dynamic": self.dynamic,
            "unique_value_count": self.unique_value_count
        }


class EndpointGraph:
    """
    Lightweight graph: endpoints and parameters
    Built from crawl results, maintains single source of truth
    
    Queries:
    - get_reflectable_endpoints() → endpoints with reflectable params
    - get_parametric_endpoints() → endpoints with any parameters
    - get_dynamic_endpoints() → endpoints with dynamic params
    - get_parameter(name) → Parameter node
    """

    def __init__(self, target: str):
        self.target = target
        self.endpoints: Dict[str, Endpoint] = {}  # path -> Endpoint
        self.parameters: Dict[str, Parameter] = {}  # name -> Parameter
        self._finalized = False

    def add_crawl_result(self, url: str, method: str = "GET", 
                        params: Optional[Dict[str, List[str]]] = None,
                        is_api: bool = False, is_form: bool = False,
                        status_code: Optional[int] = None):
        """
        Add crawled endpoint to graph
        
        Args:
            url: Full or relative URL
            method: HTTP method (GET, POST, etc)
            params: Query/body parameters from crawl
            is_api: Whether looks like API endpoint
            is_form: Whether result of form submission
            status_code: HTTP status (if available)
        """
        # Normalize path
        path = self._normalize_path(url)
        if not path:
            return

        # Get or create endpoint
        if path not in self.endpoints:
            self.endpoints[path] = Endpoint(path=path)

        ep = self.endpoints[path]

        # Add method
        try:
            ep.add_method(HTTPMethod[method.upper()])
        except KeyError:
            ep.add_method(HTTPMethod.GET)

        # Mark source
        ep.add_source(ParameterSource.CRAWLED)
        ep.is_api = is_api
        ep.is_form = is_form
        if status_code:
            ep.status_code = status_code

        # Add parameters
        if params:
            for param_name, values in params.items():
                if param_name not in self.parameters:
                    self.parameters[param_name] = Parameter(name=param_name)

                param = self.parameters[param_name]
                param.add_source(ParameterSource.CRAWLED)
                ep.add_parameter(param)

                # Track sample values
                for val in values[:2]:  # Just first 2
                    param.add_value(val)

        # Mark as dynamic if has params
        if params:
            ep.dynamic = True
            ep.unique_value_count = sum(len(v) for v in params.values())

    def add_form(self, form_path: str, form_action: str, fields: List[Dict]):
        """
        Add form-discovered endpoint
        
        Args:
            form_path: URL where form was found
            form_action: Form action URL
            fields: List of {name, type} dicts
        """
        # Normalize action path
        action_path = self._normalize_path(form_action)
        if not action_path:
            return

        # Get or create endpoint
        if action_path not in self.endpoints:
            self.endpoints[action_path] = Endpoint(path=action_path)

        ep = self.endpoints[action_path]
        ep.add_source(ParameterSource.FORM_INPUT)
        ep.add_method(HTTPMethod.POST)
        ep.is_form = True
        ep.dynamic = True
        
        # Add form fields as parameters with FORM_INPUT provenance
        for field in fields:
            field_name = field.get("name")
            if not field_name:
                continue
            
            if field_name not in self.parameters:
                self.parameters[field_name] = Parameter(name=field_name)
            
            param = self.parameters[field_name]
            param.add_source(ParameterSource.FORM_INPUT)  # PROVENANCE
            ep.add_parameter(param)
    
    def add_js_parameter(self, endpoint_path: str, param_name: str, sample_value: Optional[str] = None):
        """Add parameter discovered via JS analysis with JS_DETECTED provenance"""
        path = self._normalize_path(endpoint_path)
        if not path:
            return
        
        if path not in self.endpoints:
            self.endpoints[path] = Endpoint(path=path)
        
        ep = self.endpoints[path]
        ep.add_source(ParameterSource.JS_DETECTED)
        
        if param_name not in self.parameters:
            self.parameters[param_name] = Parameter(name=param_name)
        
        param = self.parameters[param_name]
        param.add_source(ParameterSource.JS_DETECTED)  # PROVENANCE
        ep.add_parameter(param)
        
        if sample_value:
            param.add_value(sample_value)

        # Add form fields as parameters
        for field in fields:
            field_name = field.get("name", "").strip()
            if not field_name:
                continue

            if field_name not in self.parameters:
                self.parameters[field_name] = Parameter(name=field_name)

            param = self.parameters[field_name]
            param.add_source(ParameterSource.FORM_INPUT)
            ep.add_parameter(param)

    def mark_reflectable(self, param_name: str):
        """Mark parameter as reflectable (XSS candidate)"""
        if param_name in self.parameters:
            self.parameters[param_name].reflectable = True

    def mark_injectable_sql(self, param_name: str):
        """Mark parameter as potentially SQL injectable"""
        if param_name in self.parameters:
            self.parameters[param_name].injectable_sql = True

    def mark_injectable_cmd(self, param_name: str):
        """Mark parameter as potentially command injectable"""
        if param_name in self.parameters:
            self.parameters[param_name].injectable_cmd = True

    def mark_injectable_ssrf(self, param_name: str):
        """Mark parameter as potentially SSRF vulnerable"""
        if param_name in self.parameters:
            self.parameters[param_name].injectable_ssrf = True

    def _normalize_path(self, url: str) -> str:
        """Extract and normalize path from URL or path"""
        if not url:
            return ""

        # Handle full URLs
        if url.startswith('http'):
            parsed = urlparse(url)
            path = parsed.path or "/"
        else:
            path = url if url.startswith('/') else f"/{url}"

        # Normalize
        path = path.strip()
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")

        return path

    # Query Methods (Single Source of Truth)

    def get_reflectable_endpoints(self) -> List[str]:
        """Get endpoints with reflectable parameters"""
        reflectable_endpoints = set()
        for param in self.parameters.values():
            if param.reflectable:
                reflectable_endpoints.update(param.endpoints)
        return sorted(list(reflectable_endpoints))

    def get_parametric_endpoints(self) -> List[str]:
        """Get endpoints with ANY parameters"""
        return sorted([
            path for path, ep in self.endpoints.items()
            if ep.dynamic or len(ep.parameters) > 0
        ])

    def get_dynamic_endpoints(self) -> List[str]:
        """Get endpoints marked as dynamic"""
        return sorted([
            path for path, ep in self.endpoints.items()
            if ep.dynamic
        ])

    def get_form_endpoints(self) -> List[str]:
        """Get endpoints discovered via forms"""
        return sorted([
            path for path, ep in self.endpoints.items()
            if ep.is_form
        ])

    def get_api_endpoints(self) -> List[str]:
        """Get endpoints marked as API"""
        return sorted([
            path for path, ep in self.endpoints.items()
            if ep.is_api
        ])

    def get_injectable_sql_endpoints(self) -> List[str]:
        """Get endpoints with SQL-injectable parameters"""
        sql_endpoints = set()
        for param in self.parameters.values():
            if param.injectable_sql:
                sql_endpoints.update(param.endpoints)
        return sorted(list(sql_endpoints))

    def get_injectable_cmd_endpoints(self) -> List[str]:
        """Get endpoints with command-injectable parameters"""
        cmd_endpoints = set()
        for param in self.parameters.values():
            if param.injectable_cmd:
                cmd_endpoints.update(param.endpoints)
        return sorted(list(cmd_endpoints))

    def get_injectable_ssrf_endpoints(self) -> List[str]:
        """Get endpoints with SSRF-prone parameters"""
        ssrf_endpoints = set()
        for param in self.parameters.values():
            if param.injectable_ssrf:
                ssrf_endpoints.update(param.endpoints)
        return sorted(list(ssrf_endpoints))

    def get_endpoint(self, path: str) -> Optional[Endpoint]:
        """Get single endpoint"""
        norm_path = self._normalize_path(path)
        return self.endpoints.get(norm_path)

    def get_parameter(self, name: str) -> Optional[Parameter]:
        """Get single parameter"""
        return self.parameters.get(name)

    def get_all_parameters(self) -> Dict[str, Parameter]:
        """Get all parameters"""
        return self.parameters.copy()

    def get_all_endpoints(self) -> Dict[str, Endpoint]:
        """Get all endpoints"""
        return self.endpoints.copy()

    def get_summary(self) -> Dict:
        """Get graph summary"""
        return {
            "target": self.target,
            "total_endpoints": len(self.endpoints),
            "total_parameters": len(self.parameters),
            "reflectable_endpoints": len(self.get_reflectable_endpoints()),
            "parametric_endpoints": len(self.get_parametric_endpoints()),
            "dynamic_endpoints": len(self.get_dynamic_endpoints()),
            "form_endpoints": len(self.get_form_endpoints()),
            "api_endpoints": len(self.get_api_endpoints()),
            "sql_injectable_endpoints": len(self.get_injectable_sql_endpoints()),
            "cmd_injectable_endpoints": len(self.get_injectable_cmd_endpoints()),
            "ssrf_endpoints": len(self.get_injectable_ssrf_endpoints()),
        }

    def to_dict(self) -> Dict:
        """Serialize entire graph"""
        return {
            "target": self.target,
            "summary": self.get_summary(),
            "endpoints": {
                path: ep.to_dict() for path, ep in self.endpoints.items()
            },
            "parameters": {
                name: p.to_dict() for name, p in self.parameters.items()
            }
        }

    def finalize(self):
        """Finalize graph (read-only after this)"""
        self._finalized = True
        logger.info(f"[EndpointGraph] Finalized: {self.get_summary()}")

    @property
    def is_finalized(self) -> bool:
        """Check if graph is finalized"""
        return self._finalized


# Example usage
"""
graph = EndpointGraph(target="https://example.com")

# From crawler
graph.add_crawl_result(
    url="/api/users",
    method="GET",
    params={"id": ["123"], "filter": ["admin"]},
    is_api=True,
    status_code=200
)

graph.add_crawl_result(
    url="/login",
    method="POST",
    params={"username": ["test"], "password": ["pass"]},
    is_form=True
)

# From form extraction
graph.add_form(
    form_path="/admin",
    form_action="/admin/login",
    fields=[
        {"name": "username", "type": "text"},
        {"name": "password", "type": "password"}
    ]
)

# Mark detections
graph.mark_reflectable("id")
graph.mark_injectable_sql("filter")
graph.mark_injectable_cmd("command")

graph.finalize()

# Queries for gating
print(graph.get_reflectable_endpoints())  # For dalfox
print(graph.get_parametric_endpoints())   # For sqlmap
print(graph.get_injectable_cmd_endpoints()) # For commix
print(graph.get_summary())
"""
