"""
Payload Tool Command Builder - Phase 3
Purpose: Wire payload_strategy into actual tool command generation
Enforce crawler-derived inputs only
"""

import logging
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlencode

logger = logging.getLogger(__name__)


class PayloadCommandBuilder:
    """
    Builds actual tool commands using payload_strategy
    
    Rules:
    - NO crawler data = NO commands generated
    - Parameters MUST come from endpoint graph
    - Track all payload attempts
    """
    
    def __init__(self, payload_strategy, endpoint_graph):
        """
        Args:
            payload_strategy: PayloadStrategy instance
            endpoint_graph: EndpointGraph instance with crawled data
        """
        self.strategy = payload_strategy
        self.graph = endpoint_graph
    
    def build_dalfox_commands(self, target_url: str, max_commands: int = 5) -> List[Dict]:
        """
        Build dalfox commands for reflectable endpoints only
        
        Returns:
            List of {command: str, endpoint: str, param: str, payload: str}
        """
        if not self.graph:
            logger.warning("[PayloadBuilder] No endpoint graph - cannot build dalfox commands")
            return []
        
        commands = []
        reflectable_endpoints = self.graph.get_reflectable_endpoints()
        
        if not reflectable_endpoints:
            logger.warning("[PayloadBuilder] No reflectable endpoints - dalfox skipped")
            return []
        
        for endpoint in reflectable_endpoints[:max_commands]:
            ep = self.graph.get_endpoint(endpoint)
            if not ep or not ep.parameters:
                continue
            
            # Get reflectable params
            reflectable_params = [p for p in ep.parameters.values() if p.reflectable]
            if not reflectable_params:
                continue
            
            # Pick first reflectable param
            param = reflectable_params[0]
            method = list(ep.methods)[0].value if ep.methods else "GET"
            
            # Generate payloads using strategy
            payloads = self.strategy.generate_xss_payloads(
                parameter=param.name,
                endpoint=endpoint,
                method=method
            )
            
            # Build dalfox command with baseline payload
            if payloads:
                baseline_payload = payloads[0]["payload"]
                
                # Construct full URL
                full_url = f"{target_url.rstrip('/')}{endpoint}"
                if method == "GET":
                    full_url += f"?{param.name}={baseline_payload}"
                
                cmd = f"dalfox url {full_url}"
                
                # Add method flag
                if method == "POST":
                    cmd += f" --method POST --data \"{param.name}={baseline_payload}\""
                
                commands.append({
                    "command": cmd,
                    "endpoint": endpoint,
                    "param": param.name,
                    "method": method,
                    "payload": baseline_payload,
                    "payload_count": len(payloads)
                })
                
                logger.info(f"[PayloadBuilder] Dalfox command generated: {endpoint}?{param.name}= ({len(payloads)} payloads)")
        
        return commands
    
    def build_sqlmap_commands(self, target_url: str, max_commands: int = 3) -> List[Dict]:
        """
        Build sqlmap commands for injectable endpoints only
        
        Returns:
            List of {command: str, endpoint: str, param: str}
        """
        if not self.graph:
            logger.warning("[PayloadBuilder] No endpoint graph - cannot build sqlmap commands")
            return []
        
        commands = []
        injectable_endpoints = self.graph.get_injectable_sql_endpoints()
        
        if not injectable_endpoints:
            logger.warning("[PayloadBuilder] No SQL-injectable endpoints - sqlmap skipped")
            return []
        
        for endpoint in injectable_endpoints[:max_commands]:
            ep = self.graph.get_endpoint(endpoint)
            if not ep or not ep.parameters:
                continue
            
            # Get injectable params
            injectable_params = [p for p in ep.parameters.values() if p.injectable_sql]
            if not injectable_params:
                continue
            
            # Pick first injectable param
            param = injectable_params[0]
            method = list(ep.methods)[0].value if ep.methods else "GET"
            
            # Generate SQL payloads using strategy
            payloads = self.strategy.generate_sqli_payloads(
                parameter=param.name,
                endpoint=endpoint,
                method=method
            )
            
            # Build sqlmap command
            full_url = f"{target_url.rstrip('/')}{endpoint}"
            if method == "GET":
                full_url += f"?{param.name}=1"  # Placeholder value
            
            cmd = f"sqlmap -u {full_url} --batch --risk 2 --level 2"
            
            # Add parameter flag
            cmd += f" -p {param.name}"
            
            # Add method flag for POST
            if method == "POST":
                cmd += f" --method POST --data \"{param.name}=1\""
            
            commands.append({
                "command": cmd,
                "endpoint": endpoint,
                "param": param.name,
                "method": method,
                "payload_count": len(payloads)
            })
            
            logger.info(f"[PayloadBuilder] SQLMap command generated: {endpoint}?{param.name}=")
        
        return commands
    
    def build_commix_commands(self, target_url: str, max_commands: int = 2) -> List[Dict]:
        """
        Build commix commands for command-injectable endpoints only
        """
        if not self.graph:
            logger.warning("[PayloadBuilder] No endpoint graph - cannot build commix commands")
            return []
        
        commands = []
        # Commix targets parameters that might accept OS commands
        parametric_endpoints = self.graph.get_parametric_endpoints()
        
        for endpoint in parametric_endpoints[:max_commands]:
            ep = self.graph.get_endpoint(endpoint)
            if not ep or not ep.parameters:
                continue
            
            # Look for command-injectable params
            cmd_params = [p for p in ep.parameters.values() if p.injectable_cmd]
            if not cmd_params:
                # Fallback: try any param in dynamic endpoints
                if ep.dynamic:
                    cmd_params = list(ep.parameters.values())[:1]
                else:
                    continue
            
            param = cmd_params[0]
            method = list(ep.methods)[0].value if ep.methods else "GET"
            
            # Generate CMD payloads
            payloads = self.strategy.generate_cmd_payloads(
                parameter=param.name,
                endpoint=endpoint,
                method=method
            )
            
            # Build commix command
            full_url = f"{target_url.rstrip('/')}{endpoint}"
            if method == "GET":
                full_url += f"?{param.name}=test"
            
            cmd = f"commix --url={full_url} --batch"
            
            if method == "POST":
                cmd += f" --data=\"{param.name}=test\""
            
            commands.append({
                "command": cmd,
                "endpoint": endpoint,
                "param": param.name,
                "method": method,
                "payload_count": len(payloads)
            })
            
            logger.info(f"[PayloadBuilder] Commix command generated: {endpoint}?{param.name}=")
        
        return commands
