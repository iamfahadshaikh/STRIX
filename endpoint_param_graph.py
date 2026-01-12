"""
Endpoint/Parameter Graph Builder
Purpose: Map discovered endpoints to parameters for targeted payload tool execution

Data Structure:
  endpoints[url] = {
    "method": "GET",
    "parameters": {
      "search": {"sources": ["url_param"], "reflectable": True},
      "id": {"sources": ["form_field"], "reflectable": True}
    },
    "forms": [{"action": ..., "fields": [...]}]
  }
"""

import logging
from typing import Dict, List, Set, Optional
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger(__name__)


class EndpointParamGraph:
    """
    Maps crawled endpoints to their parameters
    
    Enables targeted payload tool execution:
    - xsstrike only runs on endpoints with reflectable params
    - sqlmap only runs on endpoints with injectable params
    - Tools focus on actual attack surface
    """

    def __init__(self):
        """Initialize graph"""
        self.endpoints: Dict = {}  # url -> {method, parameters, forms}
        self.param_sources: Dict[str, Set[str]] = {}  # param_name -> {endpoints}
        self.reflectable_params: Set[str] = set()
        self.injectable_params: Set[str] = set()

    def build_from_crawl(self, crawl_result: Dict) -> None:
        """
        Build graph from crawler output
        
        Args:
            crawl_result: Dict with structure:
                {
                  "endpoints": [...],
                  "parameters": {param_name: [values]},
                  "forms": [...],
                  "reflections": [reflectable_params]
                }
        """
        logger.info("[Graph] Building endpoint/param graph from crawl...")

        # Extract reflectable params
        self.reflectable_params = set(crawl_result.get("reflections", []))

        # Build endpoint nodes
        for endpoint in crawl_result.get("endpoints", []):
            self._add_endpoint(endpoint)

        # Add parameters discovered in URLs
        for param_name, values in crawl_result.get("parameters", {}).items():
            self._add_parameter(param_name, "url_param")

        # Add parameters from forms
        for form in crawl_result.get("forms", []):
            action = form.get("action", "")
            self._add_endpoint(action)
            
            for field in form.get("fields", []):
                field_name = field.get("name", "")
                self._add_parameter(field_name, "form_field", action)

        logger.info(f"[Graph] Built graph: {len(self.endpoints)} endpoints, "
                   f"{len(self.param_sources)} unique parameters, "
                   f"{len(self.reflectable_params)} reflectable")

    def _add_endpoint(self, url: str) -> None:
        """Add or update endpoint node"""
        if url not in self.endpoints:
            parsed = urlparse(url)
            self.endpoints[url] = {
                "url": url,
                "path": parsed.path,
                "query": parsed.query,
                "method": "GET",
                "parameters": {},
                "forms": [],
                "is_api": "/api/" in url.lower()
            }
            
            # Extract URL parameters
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params.keys():
                    if param not in self.endpoints[url]["parameters"]:
                        self.endpoints[url]["parameters"][param] = {
                            "sources": [],
                            "reflectable": param in self.reflectable_params
                        }
                    self.endpoints[url]["parameters"][param]["sources"].append("url")

    def _add_parameter(self, param_name: str, source: str, endpoint: str = None) -> None:
        """Track parameter discovery"""
        if param_name not in self.param_sources:
            self.param_sources[param_name] = set()

        if endpoint:
            self.param_sources[param_name].add(endpoint)
            if endpoint in self.endpoints:
                if param_name not in self.endpoints[endpoint]["parameters"]:
                    self.endpoints[endpoint]["parameters"][param_name] = {
                        "sources": [],
                        "reflectable": param_name in self.reflectable_params
                    }
                if source not in self.endpoints[endpoint]["parameters"][param_name]["sources"]:
                    self.endpoints[endpoint]["parameters"][param_name]["sources"].append(source)

    def get_endpoints_with_params(self, param_filter: Set[str] = None) -> List[str]:
        """
        Get endpoints that have parameters
        
        Args:
            param_filter: Only endpoints with these params (optional)
            
        Returns:
            List of endpoint URLs
        """
        if not param_filter:
            return [url for url in self.endpoints.keys() if self.endpoints[url]["parameters"]]

        matching = []
        for url, ep_data in self.endpoints.items():
            params = set(ep_data.get("parameters", {}).keys())
            if params & param_filter:  # Intersection
                matching.append(url)

        return matching

    def get_endpoints_with_reflections(self) -> List[str]:
        """Get endpoints with reflectable parameters"""
        matching = []
        for url, ep_data in self.endpoints.items():
            params = ep_data.get("parameters", {})
            for param_name, param_data in params.items():
                if param_data.get("reflectable"):
                    matching.append(url)
                    break

        return matching

    def get_endpoints_with_forms(self) -> List[str]:
        """Get endpoints with forms"""
        return [url for url in self.endpoints.keys() if self.endpoints[url].get("forms")]

    def get_endpoints_for_sqlmap(self) -> List[str]:
        """Get endpoints suitable for sqlmap (have injectable params)"""
        return self.get_endpoints_with_params()

    def get_endpoints_for_xsstrike(self) -> List[str]:
        """Get endpoints suitable for xsstrike (reflectable params or forms)"""
        reflective = set(self.get_endpoints_with_reflections())
        forms = set(self.get_endpoints_with_forms())
        return list(reflective | forms)

    def get_endpoints_for_commix(self) -> List[str]:
        """Get endpoints suitable for commix (command injection params)"""
        # Params like: cmd, command, exec, shell, query, etc.
        cmd_params = {'cmd', 'command', 'exec', 'shell', 'query', 'q', 'search', 'text'}
        return self.get_endpoints_with_params(cmd_params)

    def get_endpoints_for_tool(self, tool_name: str) -> List[str]:
        """
        Get targeted endpoints for a specific tool
        
        Args:
            tool_name: xsstrike, sqlmap, commix, dalfox, etc.
            
        Returns:
            List of endpoint URLs to test
        """
        tool_lower = tool_name.lower()

        if "xss" in tool_lower or tool_lower == "dalfox":
            return self.get_endpoints_for_xsstrike()
        elif "sql" in tool_lower:
            return self.get_endpoints_for_sqlmap()
        elif "commix" in tool_lower:
            return self.get_endpoints_for_commix()
        else:
            return []

    def should_run_tool(self, tool_name: str) -> bool:
        """
        Simple boolean: should this tool run based on graph?
        
        Args:
            tool_name: Tool identifier
            
        Returns:
            bool: True if endpoints exist for this tool
        """
        endpoints = self.get_endpoints_for_tool(tool_name)
        return len(endpoints) > 0

    def get_summary(self) -> Dict:
        """Get graph summary"""
        endpoints_with_params = [url for url in self.endpoints.keys()
                                 if self.endpoints[url].get("parameters")]
        endpoints_with_reflection = self.get_endpoints_with_reflections()
        endpoints_with_forms = self.get_endpoints_with_forms()

        return {
            "total_endpoints": len(self.endpoints),
            "endpoints_with_parameters": len(endpoints_with_params),
            "endpoints_with_reflections": len(endpoints_with_reflection),
            "endpoints_with_forms": len(endpoints_with_forms),
            "unique_parameters": len(self.param_sources),
            "reflectable_parameters": len(self.reflectable_params),
            "tools_available": {
                "xsstrike": self.should_run_tool("xsstrike"),
                "dalfox": self.should_run_tool("dalfox"),
                "sqlmap": self.should_run_tool("sqlmap"),
                "commix": self.should_run_tool("commix"),
            }
        }

    def to_dict(self) -> Dict:
        """Export graph structure"""
        return {
            "endpoints": self.endpoints,
            "param_sources": {k: list(v) for k, v in self.param_sources.items()},
            "reflectable_params": list(self.reflectable_params),
            "summary": self.get_summary()
        }


# Usage Example
"""
from endpoint_param_graph import EndpointParamGraph
from crawl_adapter import CrawlAdapter

# Crawl target
adapter = CrawlAdapter(target, output_dir)
adapter.run()

# Build graph
graph = EndpointParamGraph()
graph.build_from_crawl(adapter.crawl_result)

# Query for tool-specific endpoints
xss_endpoints = graph.get_endpoints_for_tool("xsstrike")
sql_endpoints = graph.get_endpoints_for_tool("sqlmap")

# Gate tools based on graph
if graph.should_run_tool("xsstrike"):
    # Run xsstrike on xss_endpoints
    for endpoint in xss_endpoints:
        pass  # Run xsstrike on endpoint

# Get summary
print(graph.get_summary())
# {
#   "total_endpoints": 20,
#   "endpoints_with_parameters": 15,
#   "endpoints_with_reflections": 8,
#   "endpoints_with_forms": 2,
#   "unique_parameters": 12,
#   "reflectable_parameters": 4,
#   "tools_available": {
#     "xsstrike": True,
#     "dalfox": True,
#     "sqlmap": True,
#     "commix": True
#   }
# }
"""
