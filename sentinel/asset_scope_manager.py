"""Asset scope management for reconnaissance targeting."""

from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Set

from shared.logging import get_logger

logger = get_logger(__name__)


class ScopeStatus(str, Enum):
    """Asset scope status."""

    IN_SCOPE = "in_scope"
    OUT_OF_SCOPE = "out_of_scope"
    GRAY_AREA = "gray_area"
    UNKNOWN = "unknown"


class ScopeJustification(str, Enum):
    """Reason for scope status."""

    EXPLICITLY_INCLUDED = "explicitly_included"
    EXPLICITLY_EXCLUDED = "explicitly_excluded"
    WILDCARD_MATCH = "wildcard_match"
    AUTOMATIC_DISCOVERY = "automatic_discovery"
    MANUAL_REVIEW = "manual_review"
    IP_RANGE_MATCH = "ip_range_match"
    SUBDOMAIN_MATCH = "subdomain_match"
    ASSOCIATED_DOMAIN = "associated_domain"


@dataclass
class ScopeRule:
    """Rule for determining scope status of assets."""

    rule_id: str
    pattern: str  # Domain, IP range, or regex pattern
    scope_status: ScopeStatus
    rule_type: str  # "domain", "ip_range", "regex", "wildcard"
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    description: str = ""
    priority: int = 50  # Lower priority = higher precedence

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class ScopedAsset:
    """Asset with scope status determination."""

    asset_value: str
    asset_type: str
    scope_status: ScopeStatus
    justification: ScopeJustification
    matched_rule: Optional[str] = None
    confidence: float = 1.0
    notes: str = ""
    added_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class AssetScopeManager:
    """Manage scope rules and determine asset scoping."""

    def __init__(self):
        """Initialize scope manager."""
        self.scope_rules: dict[str, ScopeRule] = {}
        self.scoped_assets: dict[str, ScopedAsset] = {}
        self.rule_counter = 0

    def add_scope_rule(
        self,
        pattern: str,
        scope_status: ScopeStatus,
        rule_type: str,
        description: str = "",
        rule_id: Optional[str] = None,
        priority: int = 50,
    ) -> ScopeRule:
        """Add a scope determination rule."""
        if rule_id is None:
            self.rule_counter += 1
            rule_id = f"rule-{self.rule_counter:04d}"

        rule = ScopeRule(
            rule_id=rule_id,
            pattern=pattern,
            scope_status=scope_status,
            rule_type=rule_type,
            description=description,
            priority=priority,
        )

        self.scope_rules[rule_id] = rule
        logger.info(f"Added scope rule: {rule_id} - {pattern} -> {scope_status.value}")

        return rule

    def add_in_scope_domain(
        self, domain: str, description: str = "", priority: int = 50
    ) -> ScopeRule:
        """Add domain as in-scope."""
        return self.add_scope_rule(
            pattern=domain,
            scope_status=ScopeStatus.IN_SCOPE,
            rule_type="domain",
            description=description or f"In-scope domain: {domain}",
            priority=priority,
        )

    def add_out_of_scope_domain(
        self, domain: str, description: str = "", priority: int = 50
    ) -> ScopeRule:
        """Add domain as out-of-scope."""
        return self.add_scope_rule(
            pattern=domain,
            scope_status=ScopeStatus.OUT_OF_SCOPE,
            rule_type="domain",
            description=description or f"Out-of-scope domain: {domain}",
            priority=priority,
        )

    def add_wildcard_scope(self, pattern: str, in_scope: bool = True) -> ScopeRule:
        """Add wildcard pattern for scope (e.g., *.example.com)."""
        return self.add_scope_rule(
            pattern=pattern,
            scope_status=ScopeStatus.IN_SCOPE if in_scope else ScopeStatus.OUT_OF_SCOPE,
            rule_type="wildcard",
            description=f"Wildcard pattern: {pattern}",
        )

    def add_ip_range_scope(
        self, ip_range: str, in_scope: bool = True, description: str = ""
    ) -> ScopeRule:
        """Add IP range for scope (CIDR notation)."""
        return self.add_scope_rule(
            pattern=ip_range,
            scope_status=ScopeStatus.IN_SCOPE if in_scope else ScopeStatus.OUT_OF_SCOPE,
            rule_type="ip_range",
            description=description or f"IP range: {ip_range}",
        )

    def determine_scope(
        self, asset_value: str, asset_type: str = "domain"
    ) -> tuple[ScopeStatus, ScopeJustification, Optional[str]]:
        """Determine scope status for an asset."""
        # Sort rules by priority (lower = higher precedence)
        sorted_rules = sorted(self.scope_rules.values(), key=lambda r: r.priority)

        for rule in sorted_rules:
            if self._matches_rule(asset_value, rule):
                justification = self._get_justification(rule.rule_type)
                return rule.scope_status, justification, rule.rule_id

        # Default to unknown if no rules match
        return ScopeStatus.UNKNOWN, ScopeJustification.MANUAL_REVIEW, None

    def _matches_rule(self, asset_value: str, rule: ScopeRule) -> bool:
        """Check if asset matches rule pattern."""
        if rule.rule_type == "domain":
            return self._matches_domain(asset_value, rule.pattern)
        elif rule.rule_type == "wildcard":
            return self._matches_wildcard(asset_value, rule.pattern)
        elif rule.rule_type == "ip_range":
            return self._matches_ip_range(asset_value, rule.pattern)
        elif rule.rule_type == "regex":
            return self._matches_regex(asset_value, rule.pattern)
        return False

    @staticmethod
    def _matches_domain(asset: str, pattern: str) -> bool:
        """Check if asset matches domain pattern."""
        return asset.lower() == pattern.lower()

    @staticmethod
    def _matches_wildcard(asset: str, pattern: str) -> bool:
        """Check if asset matches wildcard pattern."""
        pattern_lower = pattern.lower()
        asset_lower = asset.lower()

        if pattern_lower.startswith("*."):
            suffix = pattern_lower[2:]
            return asset_lower.endswith(suffix)

        return asset_lower == pattern_lower

    @staticmethod
    def _matches_ip_range(asset: str, pattern: str) -> bool:
        """Check if IP matches CIDR range."""
        try:
            import ipaddress

            asset_ip = ipaddress.ip_address(asset)
            network = ipaddress.ip_network(pattern, strict=False)
            return asset_ip in network
        except (ValueError, TypeError):
            return False

    @staticmethod
    def _matches_regex(asset: str, pattern: str) -> bool:
        """Check if asset matches regex pattern."""
        import re

        try:
            return re.search(pattern, asset, re.IGNORECASE) is not None
        except re.error:
            return False

    @staticmethod
    def _get_justification(rule_type: str) -> ScopeJustification:
        """Get justification based on rule type."""
        mapping = {
            "domain": ScopeJustification.EXPLICITLY_INCLUDED,
            "wildcard": ScopeJustification.WILDCARD_MATCH,
            "ip_range": ScopeJustification.IP_RANGE_MATCH,
            "regex": ScopeJustification.AUTOMATIC_DISCOVERY,
        }
        return mapping.get(rule_type, ScopeJustification.MANUAL_REVIEW)

    def classify_asset(self, asset_value: str, asset_type: str = "domain") -> ScopedAsset:
        """Classify an asset and add to scope tracking."""
        scope_status, justification, rule_id = self.determine_scope(asset_value, asset_type)

        scoped_asset = ScopedAsset(
            asset_value=asset_value,
            asset_type=asset_type,
            scope_status=scope_status,
            justification=justification,
            matched_rule=rule_id,
        )

        self.scoped_assets[asset_value] = scoped_asset
        return scoped_asset

    def get_in_scope_assets(self) -> dict[str, ScopedAsset]:
        """Get all in-scope assets."""
        return {
            k: v for k, v in self.scoped_assets.items() if v.scope_status == ScopeStatus.IN_SCOPE
        }

    def get_out_of_scope_assets(self) -> dict[str, ScopedAsset]:
        """Get all out-of-scope assets."""
        return {
            k: v
            for k, v in self.scoped_assets.items()
            if v.scope_status == ScopeStatus.OUT_OF_SCOPE
        }

    def get_gray_area_assets(self) -> dict[str, ScopedAsset]:
        """Get all gray-area assets."""
        return {
            k: v for k, v in self.scoped_assets.items() if v.scope_status == ScopeStatus.GRAY_AREA
        }

    def get_unknown_scope_assets(self) -> dict[str, ScopedAsset]:
        """Get all unknown scope assets."""
        return {
            k: v for k, v in self.scoped_assets.items() if v.scope_status == ScopeStatus.UNKNOWN
        }

    def get_scope_summary(self) -> dict[str, Any]:
        """Get scope classification summary."""
        summary = {
            "total_assets": len(self.scoped_assets),
            "in_scope": len(self.get_in_scope_assets()),
            "out_of_scope": len(self.get_out_of_scope_assets()),
            "gray_area": len(self.get_gray_area_assets()),
            "unknown": len(self.get_unknown_scope_assets()),
            "total_rules": len(self.scope_rules),
        }
        return summary

    def export_scope_report(self) -> dict[str, Any]:
        """Export comprehensive scope report."""
        return {
            "rules": {k: v.to_dict() for k, v in self.scope_rules.items()},
            "assets": {k: v.to_dict() for k, v in self.scoped_assets.items()},
            "summary": self.get_scope_summary(),
            "created_at": datetime.utcnow().isoformat(),
        }
