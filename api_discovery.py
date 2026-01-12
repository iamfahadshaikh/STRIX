"""
API Discovery Layer - Phase 3
Purpose: Detect and parse API endpoints (Swagger, OpenAPI, GraphQL)
Feed discovered endpoints into endpoint graph

Detection Strategy:
  1. Check common paths: /swagger.json, /openapi.json, /v3/api-docs, /graphql
  2. Parse schema (Swagger 2.0, OpenAPI 3.0)
  3. Extract endpoints + methods + parameters
  4. Feed into EndpointGraph
  5. Mark as API-discovered
"""

import logging
import json
import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class APIEndpoint:
    """Discovered API endpoint"""
    path: str
    method: str = "GET"
    parameters: List[Dict] = field(default_factory=list)
    description: str = ""
    requires_auth: bool = False
    security: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "path": self.path,
            "method": self.method,
            "parameters": self.parameters,
            "description": self.description,
            "requires_auth": self.requires_auth,
            "security": self.security
        }


@dataclass
class APISchema:
    """Parsed API schema"""
    name: str
    version: str
    base_path: str = ""
    endpoints: List[APIEndpoint] = field(default_factory=list)
    security_definitions: Dict = field(default_factory=dict)
    schemes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "name": self.name,
            "version": self.version,
            "base_path": self.base_path,
            "endpoints": [ep.to_dict() for ep in self.endpoints],
            "security_definitions": self.security_definitions,
            "schemes": self.schemes
        }


class APIDiscovery:
    """
    Discover and parse API schemas
    
    Supports:
    - Swagger 2.0
    - OpenAPI 3.0.x
    - GraphQL (basic)
    - WADL (basic)
    """

    # Common API documentation paths
    COMMON_PATHS = [
        "/swagger.json",
        "/swagger.yaml",
        "/swagger.yml",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/v3/api-docs",
        "/v2/api-docs",
        "/api-docs",
        "/api/docs",
        "/api/swagger.json",
        "/api/openapi.json",
        "/.well-known/openapi.json",
        "/graphql",
        "/graphql/schema.json",
        "/api/schema.graphql",
        "/api-docs.json",
        "/rest/api/2/swagger.json",  # Jira
        "/api/metadata",
        "/api/v1/docs",
    ]

    def __init__(self, base_url: str, timeout: int = 10):
        """
        Args:
            base_url: Target URL (e.g., https://example.com)
            timeout: HTTP request timeout
        """
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.discovered_schemas: List[APISchema] = []

    def discover(self) -> List[APISchema]:
        """
        Discover API schemas at common paths
        
        Returns:
            List of discovered APISchema objects
        """
        logger.info(f"[APIDiscovery] Scanning {len(self.COMMON_PATHS)} common paths...")

        for path in self.COMMON_PATHS:
            schema = self._try_fetch_schema(path)
            if schema:
                self.discovered_schemas.append(schema)
                logger.info(f"[APIDiscovery] Found: {schema.name} v{schema.version} at {path}")

        logger.info(f"[APIDiscovery] Discovered {len(self.discovered_schemas)} API schemas")
        return self.discovered_schemas

    def _try_fetch_schema(self, path: str) -> Optional[APISchema]:
        """Try to fetch and parse schema at path"""
        url = urljoin(self.base_url, path)

        try:
            # Import here to avoid hard dependency on requests
            import requests
            response = requests.get(url, timeout=self.timeout, verify=False)

            if response.status_code != 200:
                return None

            content_type = response.headers.get("content-type", "").lower()

            # Parse JSON-based schemas
            if "json" in content_type or path.endswith(".json"):
                try:
                    data = response.json()
                    return self._parse_openapi_or_swagger(data, path)
                except json.JSONDecodeError:
                    return None

            # Parse YAML-based schemas
            elif "yaml" in content_type or path.endswith((".yaml", ".yml")):
                try:
                    import yaml
                    data = yaml.safe_load(response.text)
                    return self._parse_openapi_or_swagger(data, path)
                except ImportError:
                    logger.warning("[APIDiscovery] PyYAML not installed, skipping YAML parsing")
                    return None
                except Exception:
                    return None

            # Parse GraphQL schemas
            elif "graphql" in path or "graphql" in content_type:
                return self._parse_graphql_schema(response.text, path)

            return None

        except Exception as e:
            logger.debug(f"[APIDiscovery] Failed to fetch {path}: {e}")
            return None

    def _parse_openapi_or_swagger(self, data: Dict, source_path: str) -> Optional[APISchema]:
        """Parse OpenAPI 3.0 or Swagger 2.0 schema"""
        try:
            # Detect version
            swagger_version = data.get("swagger")  # "2.0"
            openapi_version = data.get("openapi")  # "3.0.x"

            if swagger_version:
                return self._parse_swagger_2(data, source_path)
            elif openapi_version:
                return self._parse_openapi_3(data, source_path)
            else:
                return None

        except Exception as e:
            logger.warning(f"[APIDiscovery] Failed to parse schema from {source_path}: {e}")
            return None

    def _parse_swagger_2(self, data: Dict, source_path: str) -> APISchema:
        """Parse Swagger 2.0 schema"""
        schema = APISchema(
            name=data.get("info", {}).get("title", "Unknown"),
            version=data.get("info", {}).get("version", "unknown"),
            base_path=data.get("basePath", ""),
            schemes=data.get("schemes", ["http", "https"]),
            security_definitions=data.get("securityDefinitions", {})
        )

        # Parse endpoints
        paths = data.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.startswith("x-"):  # Skip extensions
                    continue

                # Extract parameters
                parameters = []
                for param in details.get("parameters", []):
                    parameters.append({
                        "name": param.get("name"),
                        "type": param.get("type", "string"),
                        "in": param.get("in", "query"),  # query, path, header, formData, body
                        "required": param.get("required", False)
                    })

                # Check if requires auth
                requires_auth = bool(details.get("security"))

                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=parameters,
                    description=details.get("description", ""),
                    requires_auth=requires_auth,
                    security=list(details.get("security", []))
                )

                schema.endpoints.append(endpoint)

        return schema

    def _parse_openapi_3(self, data: Dict, source_path: str) -> APISchema:
        """Parse OpenAPI 3.0.x schema"""
        info = data.get("info", {})
        servers = data.get("servers", [{"url": "/"}])
        base_path = servers[0].get("url", "/") if servers else "/"

        schema = APISchema(
            name=info.get("title", "Unknown"),
            version=info.get("version", "unknown"),
            base_path=base_path,
            security_definitions=data.get("components", {}).get("securitySchemes", {})
        )

        # Parse endpoints
        paths = data.get("paths", {})
        for path, methods in paths.items():
            for method, details in methods.items():
                if method.startswith("x-"):  # Skip extensions
                    continue

                # Extract parameters
                parameters = []
                for param in details.get("parameters", []):
                    parameters.append({
                        "name": param.get("name"),
                        "type": param.get("schema", {}).get("type", "string"),
                        "in": param.get("in", "query"),
                        "required": param.get("required", False)
                    })

                # Check request body
                req_body = details.get("requestBody", {})
                if req_body:
                    content_type = list(req_body.get("content", {}).keys())[0] if req_body.get("content") else "application/json"
                    schema_def = req_body.get("content", {}).get(content_type, {}).get("schema", {})
                    
                    if schema_def.get("type") == "object":
                        for prop_name, prop_def in schema_def.get("properties", {}).items():
                            parameters.append({
                                "name": prop_name,
                                "type": prop_def.get("type", "string"),
                                "in": "body",
                                "required": prop_name in schema_def.get("required", [])
                            })

                # Check if requires auth
                requires_auth = bool(details.get("security"))

                endpoint = APIEndpoint(
                    path=path,
                    method=method.upper(),
                    parameters=parameters,
                    description=details.get("description", ""),
                    requires_auth=requires_auth,
                    security=list(details.get("security", []))
                )

                schema.endpoints.append(endpoint)

        return schema

    def _parse_graphql_schema(self, schema_text: str, source_path: str) -> Optional[APISchema]:
        """Parse GraphQL schema (basic)"""
        try:
            schema = APISchema(
                name="GraphQL",
                version="1.0",
                base_path="/graphql"
            )

            # Add GraphQL as single endpoint
            endpoint = APIEndpoint(
                path="/graphql",
                method="POST",
                parameters=[
                    {"name": "query", "type": "string", "in": "body", "required": True},
                    {"name": "variables", "type": "object", "in": "body", "required": False}
                ],
                description="GraphQL API endpoint"
            )
            schema.endpoints.append(endpoint)

            return schema

        except Exception as e:
            logger.warning(f"[APIDiscovery] Failed to parse GraphQL schema: {e}")
            return None

    def get_summary(self) -> Dict:
        """Get discovery summary"""
        total_endpoints = sum(len(s.endpoints) for s in self.discovered_schemas)
        total_params = sum(
            sum(len(ep.parameters) for ep in schema.endpoints)
            for schema in self.discovered_schemas
        )
        auth_required = sum(
            sum(1 for ep in schema.endpoints if ep.requires_auth)
            for schema in self.discovered_schemas
        )

        return {
            "schemas_found": len(self.discovered_schemas),
            "total_endpoints": total_endpoints,
            "total_parameters": total_params,
            "endpoints_requiring_auth": auth_required,
            "schemas": [s.name for s in self.discovered_schemas]
        }

    def feed_to_graph(self, graph) -> int:
        """
        Feed discovered API endpoints into EndpointGraph
        
        Args:
            graph: EndpointGraph instance
            
        Returns:
            Number of endpoints added
        """
        count = 0
        for schema in self.discovered_schemas:
            for endpoint in schema.endpoints:
                # Build full URL
                path = endpoint.path
                if schema.base_path and schema.base_path != "/":
                    path = schema.base_path + path

                # Extract query parameters from path (e.g., /users/{id})
                params = {}
                for param in endpoint.parameters:
                    if param["in"] in ["query", "body", "formData"]:
                        params[param["name"]] = [f"example_{param['type']}"]

                # Add to graph
                graph.add_crawl_result(
                    url=path,
                    method=endpoint.method,
                    params=params if params else None,
                    is_api=True,
                    is_form=False
                )

                count += 1

        logger.info(f"[APIDiscovery] Fed {count} API endpoints to graph")
        return count

    def to_dict(self) -> Dict:
        """Serialize discovered schemas"""
        return {
            "summary": self.get_summary(),
            "schemas": [s.to_dict() for s in self.discovered_schemas]
        }


# Example usage
"""
discovery = APIDiscovery(base_url="https://example.com")

# Discover schemas
schemas = discovery.discover()
for schema in schemas:
    print(f"{schema.name} v{schema.version}")
    print(f"  Endpoints: {len(schema.endpoints)}")
    for ep in schema.endpoints:
        print(f"    {ep.method} {ep.path} ({len(ep.parameters)} params)")

# Feed into graph
from endpoint_graph import EndpointGraph
graph = EndpointGraph(target="https://example.com")
discovery.feed_to_graph(graph)
graph.finalize()

print(discovery.get_summary())
"""
