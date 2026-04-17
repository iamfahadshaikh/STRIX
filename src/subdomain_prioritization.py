"""
Subdomain Prioritization and Attack Surface Ranking Engine
Purpose: Score and prioritize subdomains for intelligent target selection
"""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class SubdomainType(Enum):
    """Subdomain classification"""

    WEB = "web"
    API = "api"
    ADMIN = "admin"
    MAIL = "mail"
    VPN = "vpn"
    INTERNAL = "internal"
    DEV = "dev"
    STAGING = "staging"
    CDN = "cdn"
    UNKNOWN = "unknown"


class ExposureLevel(Enum):
    """How exposed/critical the subdomain is"""

    CRITICAL = "critical"  # Production web, admin panels
    HIGH = "high"  # API, payment related
    MEDIUM = "medium"  # Staging, development
    LOW = "low"  # CDN, analytics


@dataclass
class SubdomainRiskProfile:
    """Scoring profile for a subdomain"""

    subdomain: str
    subdomain_type: SubdomainType
    exposure_level: ExposureLevel
    tech_stack: List[str] = field(default_factory=list)
    parameter_count: int = 0
    has_auth: bool = False
    auth_type: str = ""  # basic, session, oauth, etc
    keywords: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    crawled_endpoints: int = 0
    priority_score: float = 0.0

    def to_dict(self) -> Dict:
        return {
            "subdomain": self.subdomain,
            "type": self.subdomain_type.value,
            "exposure": self.exposure_level.value,
            "tech_stack": self.tech_stack,
            "param_count": self.parameter_count,
            "has_auth": self.has_auth,
            "priority_score": self.priority_score,
        }


class SubdomainPrioritizationEngine:
    """
    Subdomain prioritization and attack surface ranking

    Scoring factors:
    - Subdomain type (admin > api > web > cdn)
    - Exposure level (critical > high > medium > low)
    - Parameter count (more params = larger attack surface)
    - Technology stack (known vulnerable tech)
    - Authentication requirements (or lack thereof)
    - Port diversity (more ports = more complex target)
    """

    # Keywords indicating subdomain type/exposure
    SUBDOMAIN_KEYWORDS = {
        SubdomainType.ADMIN: [
            "admin",
            "administrator",
            "manage",
            "dashboard",
            "control",
            "panel",
        ],
        SubdomainType.API: ["api", "api-", "v1", "v2", "graphql", "rest", "webapi"],
        SubdomainType.VPN: ["vpn", "ssl", "secure", "remote", "access"],
        SubdomainType.MAIL: ["mail", "email", "webmail", "smtp", "imap"],
        SubdomainType.INTERNAL: ["internal", "intra", "corp", "employee"],
        SubdomainType.DEV: ["dev", "develop", "development", "localhost"],
        SubdomainType.STAGING: ["staging", "stage", "test", "qa", "beta"],
        SubdomainType.CDN: ["cdn", "static", "assets", "images", "media"],
    }

    # Technology stack indicators for vulnerability likelihood
    VULNERABLE_TECH = {
        "WordPress": 0.85,  # Commonly vulnerable
        "Joomla": 0.80,  # Often outdated
        "Drupal": 0.70,  # Depends on version
        "Magento": 0.80,  # E-commerce targets
        "OpenCart": 0.75,
        "ColdFusion": 0.85,
        "Struts": 0.80,
        "Spring": 0.60,
        "Rails": 0.65,
        "Express": 0.55,
        "Flask": 0.50,
        "Django": 0.50,
    }

    def __init__(self):
        self.subdomains: Dict[str, SubdomainRiskProfile] = {}

    def classify_subdomain(self, subdomain: str) -> SubdomainType:
        """
        Classify subdomain type based on name analysis

        Args:
            subdomain: Subdomain name

        Returns: SubdomainType enum
        """
        subdomain_lower = subdomain.lower()

        # Check against keywords
        for subdom_type, keywords in self.SUBDOMAIN_KEYWORDS.items():
            for keyword in keywords:
                if keyword in subdomain_lower:
                    return subdom_type

        return SubdomainType.UNKNOWN

    def assess_exposure_level(
        self,
        subdomain: str,
        subdomain_type: SubdomainType,
        has_auth: bool = False,
        tech_stack: Optional[List[str]] = None,
    ) -> ExposureLevel:
        """
        Assess exposure level of subdomain

        Args:
            subdomain: Subdomain name
            subdomain_type: Type classification
            has_auth: Whether authentication is required
            tech_stack: Technology stack detected

        Returns: ExposureLevel enum
        """
        # Critical: Admin/API/VPN panels without auth or on production
        if subdomain_type in [
            SubdomainType.ADMIN,
            SubdomainType.API,
            SubdomainType.VPN,
        ]:
            if not has_auth:
                return ExposureLevel.CRITICAL
            if "prod" in subdomain or "production" in subdomain:
                return ExposureLevel.CRITICAL
            if subdomain_type == SubdomainType.ADMIN:
                return ExposureLevel.HIGH
            return ExposureLevel.HIGH

        # Medium: Dev/Staging environments
        if subdomain_type in [SubdomainType.DEV, SubdomainType.STAGING]:
            return ExposureLevel.MEDIUM

        # Low: CDN, static content
        if subdomain_type == SubdomainType.CDN:
            return ExposureLevel.LOW

        # Medium default for web
        if subdomain_type == SubdomainType.WEB:
            return ExposureLevel.MEDIUM

        return ExposureLevel.LOW

    def calculate_priority_score(self, profile: SubdomainRiskProfile) -> float:
        """
        Calculate overall priority score for subdomain

        Factors:
        - Exposure level: 40%
        - Parameter count: 25%
        - Technology risky-ness: 20%
        - Port diversity: 15%

        Returns: Score 0.0 - 100.0
        """
        score = 0.0

        # 40% for exposure level
        exposure_scores = {
            ExposureLevel.CRITICAL: 40,
            ExposureLevel.HIGH: 35,
            ExposureLevel.MEDIUM: 20,
            ExposureLevel.LOW: 10,
        }
        score += exposure_scores.get(profile.exposure_level, 10)

        # 25% for parameter count
        # 5+ params = max score (25), decreases below 5
        param_score = min(25, (profile.parameter_count / 5) * 25)
        score += param_score

        # 20% for technology vulnerability potential
        tech_score = 0
        if profile.tech_stack:
            tech_scores = []
            for tech in profile.tech_stack:
                tech_scores.append(self.VULNERABLE_TECH.get(tech, 0.3))
            if tech_scores:
                tech_score = (sum(tech_scores) / len(tech_scores)) * 20

        score += tech_score

        # 15% for port diversity
        # More ports = more complex = higher score
        port_score = min(15, (len(profile.open_ports) / 5) * 15)
        score += port_score

        # Bonus if no auth required (increased risk)
        if not profile.has_auth and profile.exposure_level in [
            ExposureLevel.CRITICAL,
            ExposureLevel.HIGH,
        ]:
            score *= 1.1

        return min(100.0, score)

    def add_subdomain(
        self,
        subdomain: str,
        tech_stack: Optional[List[str]] = None,
        parameter_count: int = 0,
        has_auth: bool = False,
        auth_type: str = "",
        open_ports: Optional[List[int]] = None,
        crawled_endpoints: int = 0,
    ) -> SubdomainRiskProfile:
        """
        Add subdomain for analysis

        Args:
            subdomain: Subdomain name
            tech_stack: Technologies detected on subdomain
            parameter_count: Number of injectable parameters found
            has_auth: Whether authentication is required
            auth_type: Type of authentication
            open_ports: Open ports on subdomain
            crawled_endpoints: Number of endpoints discovered

        Returns: SubdomainRiskProfile
        """
        # Classify
        subdom_type = self.classify_subdomain(subdomain)

        # Assess exposure
        exposure = self.assess_exposure_level(
            subdomain, subdom_type, has_auth, tech_stack
        )

        # Create profile
        profile = SubdomainRiskProfile(
            subdomain=subdomain,
            subdomain_type=subdom_type,
            exposure_level=exposure,
            tech_stack=tech_stack or [],
            parameter_count=parameter_count,
            has_auth=has_auth,
            auth_type=auth_type,
            open_ports=open_ports or [],
            crawled_endpoints=crawled_endpoints,
        )

        # Calculate priority score
        profile.priority_score = self.calculate_priority_score(profile)

        self.subdomains[subdomain] = profile
        logger.info(
            f"Added subdomain {subdomain}: type={subdom_type.value}, "
            f"exposure={exposure.value}, score={profile.priority_score:.1f}"
        )

        return profile

    def get_prioritized_list(
        self, limit: Optional[int] = None
    ) -> List[SubdomainRiskProfile]:
        """
        Get subdomains ordered by priority score (highest first)

        Args:
            limit: Optional limit on number of results

        Returns: List of SubdomainRiskProfile ordered by priority
        """
        sorted_list = sorted(
            self.subdomains.values(), key=lambda p: p.priority_score, reverse=True
        )

        if limit:
            return sorted_list[:limit]
        return sorted_list

    def get_top_attack_surface(self, count: int = 10) -> List[Dict]:
        """
        Get top attack surface subdomains

        Returns: List of dicts with subdomain info
        """
        return [p.to_dict() for p in self.get_prioritized_list(count)]

    def recommend_attack_order(self) -> List[Dict]:
        """
        Recommend optimal attack order

        Returns: Ordered list of subdomains with reasoning
        """
        prioritized = self.get_prioritized_list()

        recommendations = []
        for profile in prioritized:
            reason = []

            if profile.exposure_level == ExposureLevel.CRITICAL:
                reason.append("Critical exposure")
            if profile.parameter_count > 5:
                reason.append(f"{profile.parameter_count} parameters")
            if not profile.has_auth:
                reason.append("No authentication")
            if profile.subdomain_type in [SubdomainType.ADMIN, SubdomainType.API]:
                reason.append(f"{profile.subdomain_type.value} panel")

            recommendations.append(
                {
                    "subdomain": profile.subdomain,
                    "score": profile.priority_score,
                    "type": profile.subdomain_type.value,
                    "reason": (
                        "; ".join(reason) if reason else "Potential attack surface"
                    ),
                }
            )

        return recommendations

    def filter_by_type(self, subdom_type: SubdomainType) -> List[SubdomainRiskProfile]:
        """Get all subdomains of specific type"""
        return [p for p in self.subdomains.values() if p.subdomain_type == subdom_type]

    def filter_by_exposure(self, exposure: ExposureLevel) -> List[SubdomainRiskProfile]:
        """Get all subdomains with specific exposure level"""
        return [p for p in self.subdomains.values() if p.exposure_level == exposure]

    def get_critical_targets(self) -> List[SubdomainRiskProfile]:
        """
        Get critical/high-value targets

        Criteria:
        - Critical exposure level
        - Admin/API subdomains
        - No authentication
        - Parameters present
        """
        critical = []
        for profile in self.subdomains.values():
            is_critical = (
                profile.exposure_level == ExposureLevel.CRITICAL
                or (
                    profile.subdomain_type in [SubdomainType.ADMIN, SubdomainType.API]
                    and not profile.has_auth
                )
                or profile.parameter_count > 10
            )

            if is_critical:
                critical.append(profile)

        return sorted(critical, key=lambda p: p.priority_score, reverse=True)
