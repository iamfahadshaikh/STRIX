"""
Scan Profiles Manager - Phase 4 Task 6
Purpose: 5 standardized scanning profiles for different use cases

Profiles:
  1. recon-only: Discovery only, no attacks (safe for reconnaissance)
  2. safe-va: Safe vulnerability assessment (info disclosure, no destruction)
  3. auth-va: Full assessment with authentication (comprehensive inside)
  4. ci-fast: Fast CI/CD scan (30 min limit, critical findings only)
  5. full-va: Complete assessment with all tools and techniques (production deep dive)
"""

import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ProfileType(str, Enum):
    """Scan profile types"""
    RECON_ONLY = "recon-only"
    SAFE_VA = "safe-va"
    AUTH_VA = "auth-va"
    CI_FAST = "ci-fast"
    FULL_VA = "full-va"


@dataclass
class ToolConfig:
    """Configuration for a security tool"""
    name: str
    enabled: bool = True
    max_payloads: int = 100
    timeout_seconds: int = 60
    depth_level: int = 2  # 1=surface, 2=normal, 3=deep
    aggressive: bool = False


@dataclass
class ScanProfile:
    """Complete scan profile configuration"""
    name: str
    profile_type: ProfileType
    description: str
    
    # Scope
    crawl_depth: int = 2
    max_endpoints: int = 500
    max_parameters_per_endpoint: int = 10
    
    # Tools
    enabled_tools: List[str] = field(default_factory=list)
    tool_configs: Dict[str, ToolConfig] = field(default_factory=dict)
    
    # Payloads
    payload_categories: List[str] = field(default_factory=list)
    max_total_payloads: int = 1000
    concurrent_requests: int = 5
    
    # Runtime
    timeout_minutes: int = 60
    max_retries: int = 2
    partial_failure_tolerance: bool = True
    
    # Output
    capture_traffic: bool = True
    export_formats: List[str] = field(default_factory=list)  # json, sarif, junit, har
    
    # Security boundaries (what NOT to do)
    skip_dangerous: bool = False  # Skip file delete, system command execution
    auth_bypass_only: bool = False  # Only test auth bypasses, not data extraction
    information_only: bool = False  # Only collect info, no exploitation
    
    def to_dict(self) -> Dict:
        """Serialize profile"""
        return {
            "name": self.name,
            "profile_type": self.profile_type.value,
            "description": self.description,
            "scope": {
                "crawl_depth": self.crawl_depth,
                "max_endpoints": self.max_endpoints,
                "max_parameters_per_endpoint": self.max_parameters_per_endpoint
            },
            "tools": {
                name: {
                    "enabled": config.enabled,
                    "max_payloads": config.max_payloads,
                    "timeout_seconds": config.timeout_seconds,
                    "depth_level": config.depth_level,
                    "aggressive": config.aggressive
                }
                for name, config in self.tool_configs.items()
            },
            "payloads": {
                "categories": self.payload_categories,
                "max_total": self.max_total_payloads,
                "concurrent_requests": self.concurrent_requests
            },
            "runtime": {
                "timeout_minutes": self.timeout_minutes,
                "max_retries": self.max_retries,
                "partial_failure_tolerance": self.partial_failure_tolerance
            },
            "output": {
                "capture_traffic": self.capture_traffic,
                "export_formats": self.export_formats
            },
            "boundaries": {
                "skip_dangerous": self.skip_dangerous,
                "auth_bypass_only": self.auth_bypass_only,
                "information_only": self.information_only
            }
        }


class ScanProfileManager:
    """
    Manage scan profiles
    
    Usage:
        manager = ScanProfileManager()
        
        # Get profile
        profile = manager.get_profile("ci-fast")
        
        # List profiles
        for profile_name in manager.list_profiles():
            print(profile_name)
        
        # Create custom profile
        custom = manager.create_custom_profile(
            name="custom",
            base_profile="safe-va",
            enabled_tools=["nuclei", "dalfox"],
            timeout_minutes=30
        )
    """

    def __init__(self):
        self.profiles: Dict[str, ScanProfile] = {}
        self._setup_default_profiles()

    def _setup_default_profiles(self) -> None:
        """Initialize default profiles"""
        
        # 1. RECON-ONLY: Discovery only, zero risk
        recon = ScanProfile(
            name="recon-only",
            profile_type=ProfileType.RECON_ONLY,
            description="Discovery and reconnaissance only. Zero active attacks.",
            crawl_depth=1,
            max_endpoints=100,
            max_parameters_per_endpoint=5,
            enabled_tools=["crawling"],
            timeout_minutes=15,
            concurrent_requests=3,
            capture_traffic=True,
            export_formats=["json"],
            information_only=True
        )
        recon.tool_configs["crawling"] = ToolConfig(
            name="crawling",
            enabled=True,
            max_payloads=0,
            timeout_seconds=300,
            depth_level=1,
            aggressive=False
        )
        self.profiles[ProfileType.RECON_ONLY.value] = recon

        # 2. SAFE-VA: Information disclosure only
        safe = ScanProfile(
            name="safe-va",
            profile_type=ProfileType.SAFE_VA,
            description="Safe vulnerability assessment. Information disclosure, no data destruction.",
            crawl_depth=2,
            max_endpoints=200,
            max_parameters_per_endpoint=8,
            enabled_tools=["nuclei", "dalfox"],
            payload_categories=["info-disclosure", "weak-auth", "cors", "headers"],
            max_total_payloads=500,
            timeout_minutes=45,
            concurrent_requests=5,
            capture_traffic=True,
            export_formats=["json", "sarif"],
            information_only=True
        )
        safe.tool_configs["nuclei"] = ToolConfig(
            name="nuclei",
            enabled=True,
            max_payloads=200,
            timeout_seconds=120,
            depth_level=2,
            aggressive=False
        )
        safe.tool_configs["dalfox"] = ToolConfig(
            name="dalfox",
            enabled=True,
            max_payloads=150,
            timeout_seconds=90,
            depth_level=1,
            aggressive=False
        )
        self.profiles[ProfileType.SAFE_VA.value] = safe

        # 3. AUTH-VA: Full authenticated assessment
        auth = ScanProfile(
            name="auth-va",
            profile_type=ProfileType.AUTH_VA,
            description="Full assessment with authentication. Inside-perimeter comprehensive testing.",
            crawl_depth=3,
            max_endpoints=500,
            max_parameters_per_endpoint=15,
            enabled_tools=["nuclei", "dalfox", "sqlmap", "jwt-scanner"],
            payload_categories=[
                "info-disclosure", "weak-auth", "sql-injection", "xss", 
                "auth-bypass", "privilege-escalation", "idor"
            ],
            max_total_payloads=2000,
            timeout_minutes=90,
            concurrent_requests=8,
            capture_traffic=True,
            export_formats=["json", "sarif", "junit"],
            skip_dangerous=True  # Don't delete files or execute commands
        )
        auth.tool_configs["nuclei"] = ToolConfig(
            name="nuclei",
            enabled=True,
            max_payloads=500,
            timeout_seconds=180,
            depth_level=3,
            aggressive=False
        )
        auth.tool_configs["dalfox"] = ToolConfig(
            name="dalfox",
            enabled=True,
            max_payloads=300,
            timeout_seconds=120,
            depth_level=2,
            aggressive=False
        )
        auth.tool_configs["sqlmap"] = ToolConfig(
            name="sqlmap",
            enabled=True,
            max_payloads=500,
            timeout_seconds=180,
            depth_level=2,
            aggressive=False
        )
        auth.tool_configs["jwt-scanner"] = ToolConfig(
            name="jwt-scanner",
            enabled=True,
            max_payloads=100,
            timeout_seconds=120,
            depth_level=2,
            aggressive=False
        )
        self.profiles[ProfileType.AUTH_VA.value] = auth

        # 4. CI-FAST: Rapid CI/CD scan
        ci = ScanProfile(
            name="ci-fast",
            profile_type=ProfileType.CI_FAST,
            description="Fast CI/CD scan. ~30 minutes, critical findings only.",
            crawl_depth=1,
            max_endpoints=100,
            max_parameters_per_endpoint=5,
            enabled_tools=["nuclei"],
            payload_categories=["critical-only"],
            max_total_payloads=200,
            timeout_minutes=30,
            concurrent_requests=10,  # Parallel to speed up
            capture_traffic=True,
            export_formats=["json", "sarif"],
            information_only=True
        )
        ci.tool_configs["nuclei"] = ToolConfig(
            name="nuclei",
            enabled=True,
            max_payloads=200,
            timeout_seconds=60,
            depth_level=1,
            aggressive=False
        )
        self.profiles[ProfileType.CI_FAST.value] = ci

        # 5. FULL-VA: Complete deep assessment
        full = ScanProfile(
            name="full-va",
            profile_type=ProfileType.FULL_VA,
            description="Complete vulnerability assessment. All tools, all categories, production deep dive.",
            crawl_depth=4,
            max_endpoints=1000,
            max_parameters_per_endpoint=30,
            enabled_tools=["nuclei", "dalfox", "sqlmap", "jwt-scanner", "paramspider"],
            payload_categories=[
                "info-disclosure", "weak-auth", "sql-injection", "xss", "xxe",
                "command-injection", "auth-bypass", "privilege-escalation", "idor",
                "weak-crypto", "csrf", "cors", "headers", "cache-poison"
            ],
            max_total_payloads=5000,
            timeout_minutes=180,
            concurrent_requests=12,
            capture_traffic=True,
            export_formats=["json", "sarif", "junit", "har"],
            skip_dangerous=True
        )
        full.tool_configs["nuclei"] = ToolConfig(
            name="nuclei",
            enabled=True,
            max_payloads=1500,
            timeout_seconds=300,
            depth_level=3,
            aggressive=True
        )
        full.tool_configs["dalfox"] = ToolConfig(
            name="dalfox",
            enabled=True,
            max_payloads=800,
            timeout_seconds=240,
            depth_level=3,
            aggressive=True
        )
        full.tool_configs["sqlmap"] = ToolConfig(
            name="sqlmap",
            enabled=True,
            max_payloads=1000,
            timeout_seconds=300,
            depth_level=3,
            aggressive=False
        )
        full.tool_configs["jwt-scanner"] = ToolConfig(
            name="jwt-scanner",
            enabled=True,
            max_payloads=200,
            timeout_seconds=180,
            depth_level=2,
            aggressive=False
        )
        full.tool_configs["paramspider"] = ToolConfig(
            name="paramspider",
            enabled=True,
            max_payloads=500,
            timeout_seconds=120,
            depth_level=2,
            aggressive=False
        )
        self.profiles[ProfileType.FULL_VA.value] = full

        logger.info("[ScanProfiles] Initialized 5 default profiles")

    def get_profile(self, profile_name: str) -> Optional[ScanProfile]:
        """Get profile by name"""
        return self.profiles.get(profile_name)

    def list_profiles(self) -> List[str]:
        """List available profile names"""
        return list(self.profiles.keys())

    def describe_profile(self, profile_name: str) -> str:
        """Get human-readable profile description"""
        profile = self.get_profile(profile_name)
        if not profile:
            return f"Profile '{profile_name}' not found"

        desc = f"""
╔═══════════════════════════════════════════════════════════════╗
║  PROFILE: {profile.name.upper():<55} ║
╠═══════════════════════════════════════════════════════════════╣
║  Type:             {profile.profile_type.value:<45} ║
║  Description:      {profile.description:<45} ║
╠═══════════════════════════════════════════════════════════════╣
║  SCOPE                                                        ║
║    • Crawl Depth:           {profile.crawl_depth:<38} ║
║    • Max Endpoints:         {profile.max_endpoints:<38} ║
║    • Params/Endpoint:       {profile.max_parameters_per_endpoint:<38} ║
╠═══════════════════════════════════════════════════════════════╣
║  TOOLS                                                        ║
"""
        for tool in profile.enabled_tools:
            desc += f"║    • {tool:<59} ║\n"

        desc += f"""╠═══════════════════════════════════════════════════════════════╣
║  RUNTIME                                                      ║
║    • Timeout:              {profile.timeout_minutes} minutes{' '*37} ║
║    • Concurrent Requests:  {profile.concurrent_requests:<38} ║
║    • Max Total Payloads:   {profile.max_total_payloads:<38} ║
╠═══════════════════════════════════════════════════════════════╣
║  BOUNDARIES                                                   ║
║    • Skip Dangerous:       {str(profile.skip_dangerous):<38} ║
║    • Auth Bypass Only:     {str(profile.auth_bypass_only):<38} ║
║    • Information Only:     {str(profile.information_only):<38} ║
╚═══════════════════════════════════════════════════════════════╝
"""
        return desc

    def create_custom_profile(
        self,
        name: str,
        base_profile: str,
        enabled_tools: Optional[List[str]] = None,
        timeout_minutes: Optional[int] = None,
        payload_categories: Optional[List[str]] = None,
        crawl_depth: Optional[int] = None
    ) -> ScanProfile:
        """Create custom profile based on existing one"""
        if base_profile not in self.profiles:
            logger.error(f"[ScanProfiles] Base profile not found: {base_profile}")
            return None

        base = self.profiles[base_profile]

        # Create copy
        custom = ScanProfile(
            name=name,
            profile_type=base.profile_type,
            description=f"Custom profile based on {base_profile}",
            crawl_depth=crawl_depth or base.crawl_depth,
            max_endpoints=base.max_endpoints,
            max_parameters_per_endpoint=base.max_parameters_per_endpoint,
            enabled_tools=enabled_tools or base.enabled_tools,
            payload_categories=payload_categories or base.payload_categories,
            max_total_payloads=base.max_total_payloads,
            timeout_minutes=timeout_minutes or base.timeout_minutes,
            concurrent_requests=base.concurrent_requests,
            capture_traffic=base.capture_traffic,
            export_formats=base.export_formats,
            skip_dangerous=base.skip_dangerous
        )

        # Copy tool configs for enabled tools
        for tool in custom.enabled_tools:
            if tool in base.tool_configs:
                custom.tool_configs[tool] = base.tool_configs[tool]

        self.profiles[name] = custom
        logger.info(f"[ScanProfiles] Created custom profile: {name}")

        return custom

    def validate_profile(self, profile_name: str) -> Tuple[bool, List[str]]:
        """Validate profile configuration"""
        if profile_name not in self.profiles:
            return False, [f"Profile '{profile_name}' not found"]

        profile = self.profiles[profile_name]
        errors = []

        if not profile.enabled_tools:
            errors.append("No tools enabled")

        if profile.timeout_minutes < 1:
            errors.append("Timeout must be at least 1 minute")

        if profile.concurrent_requests < 1:
            errors.append("Concurrent requests must be at least 1")

        if profile.crawl_depth < 1:
            errors.append("Crawl depth must be at least 1")

        # Check tool configs
        for tool in profile.enabled_tools:
            if tool not in profile.tool_configs:
                logger.warning(f"[ScanProfiles] Tool {tool} not configured, using defaults")

        return len(errors) == 0, errors

    def export_profile(self, profile_name: str, filepath: str) -> None:
        """Export profile to JSON"""
        if profile_name not in self.profiles:
            logger.error(f"[ScanProfiles] Profile not found: {profile_name}")
            return

        import json
        with open(filepath, 'w') as f:
            json.dump(self.profiles[profile_name].to_dict(), f, indent=2)

        logger.info(f"[ScanProfiles] Exported profile to {filepath}")


# Example usage
"""
manager = ScanProfileManager()

# List all profiles
for profile_name in manager.list_profiles():
    print(f"• {profile_name}")

# Get profile
profile = manager.get_profile("ci-fast")
print(profile.to_dict())

# Describe profile
print(manager.describe_profile("auth-va"))

# Create custom
custom = manager.create_custom_profile(
    name="custom-fast",
    base_profile="safe-va",
    enabled_tools=["nuclei"],
    timeout_minutes=20
)

# Validate
valid, errors = manager.validate_profile("auth-va")
if not valid:
    print("Errors:", errors)

# Export
manager.export_profile("auth-va", "auth-va-profile.json")
"""
