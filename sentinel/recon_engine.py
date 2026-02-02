"""Reconnaissance engine for security research and target mapping."""

import asyncio
import json
import socket
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional, Set
from urllib.parse import urlparse

from shared.logging import get_logger

logger = get_logger(__name__)


class ScanStatus(str, Enum):
    """Reconnaissance scan status."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial"


class AssetType(str, Enum):
    """Types of assets discovered."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    WEB_APPLICATION = "web_application"
    SERVICE = "service"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    TECHNOLOGY = "technology"


@dataclass
class Asset:
    """Represents a discovered asset."""

    asset_type: AssetType
    value: str
    source: str = ""
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0  # 0.0 to 1.0
    tags: Set[str] = field(default_factory=set)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data["tags"] = list(self.tags)
        return data

    def add_tag(self, tag: str) -> None:
        """Add a tag to the asset."""
        self.tags.add(tag)


@dataclass
class ReconTarget:
    """Target for reconnaissance scanning."""

    target: str  # Domain, URL, IP, or email
    name: str = ""
    description: str = ""
    scope: str = "internal"  # internal, external, any
    additional_domains: Set[str] = field(default_factory=set)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())

    def add_scope_domain(self, domain: str) -> None:
        """Add domain to scope."""
        self.additional_domains.add(domain)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        data = {
            "target": self.target,
            "name": self.name,
            "description": self.description,
            "scope": self.scope,
            "additional_domains": list(self.additional_domains),
            "created_at": self.created_at,
        }
        return data


@dataclass
class ReconScan:
    """Results from reconnaissance scan."""

    scan_id: str
    target: ReconTarget
    status: ScanStatus = ScanStatus.PENDING
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    assets_discovered: list[Asset] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_asset(self, asset: Asset) -> None:
        """Add discovered asset."""
        self.assets_discovered.append(asset)

    def add_error(self, error: str) -> None:
        """Record scan error."""
        self.errors.append(error)

    def get_assets_by_type(self, asset_type: AssetType) -> list[Asset]:
        """Get assets filtered by type."""
        return [a for a in self.assets_discovered if a.asset_type == asset_type]

    def get_assets_by_tag(self, tag: str) -> list[Asset]:
        """Get assets filtered by tag."""
        return [a for a in self.assets_discovered if tag in a.tags]

    def get_unique_values(self, asset_type: AssetType) -> Set[str]:
        """Get unique values for asset type."""
        return {a.value for a in self.get_assets_by_type(asset_type)}

    def mark_started(self) -> None:
        """Mark scan as started."""
        self.status = ScanStatus.IN_PROGRESS
        self.started_at = datetime.utcnow().isoformat()

    def mark_completed(self) -> None:
        """Mark scan as completed."""
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.utcnow().isoformat()

    def mark_failed(self) -> None:
        """Mark scan as failed."""
        self.status = ScanStatus.FAILED
        self.completed_at = datetime.utcnow().isoformat()

    def mark_partial(self) -> None:
        """Mark scan as partially completed."""
        self.status = ScanStatus.PARTIAL
        self.completed_at = datetime.utcnow().isoformat()

    def get_summary(self) -> dict[str, Any]:
        """Get scan summary."""
        summary: dict[str, Any] = {
            "scan_id": self.scan_id,
            "target": self.target.target,
            "status": self.status.value,
            "total_assets": len(self.assets_discovered),
            "asset_types": {},
            "errors": len(self.errors),
            "started_at": self.started_at,
            "completed_at": self.completed_at,
        }

        # Count by type
        for asset_type in AssetType:
            count = len(self.get_assets_by_type(asset_type))
            if count > 0:
                summary["asset_types"][asset_type.value] = count

        return summary

    def export_json(self) -> str:
        """Export scan results as JSON."""
        data = {
            "scan_id": self.scan_id,
            "target": self.target.to_dict(),
            "status": self.status.value,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "assets": [a.to_dict() for a in self.assets_discovered],
            "errors": self.errors,
            "summary": self.get_summary(),
        }
        return json.dumps(data, indent=2)


class ReconEngine:
    """Main reconnaissance engine coordinating multiple scanning modules."""

    def __init__(self):
        """Initialize reconnaissance engine."""
        self.scans: dict[str, ReconScan] = {}
        self.scan_counter = 0

    def create_scan(self, target: ReconTarget, scan_id: Optional[str] = None) -> ReconScan:
        """Create new reconnaissance scan."""
        if scan_id is None:
            self.scan_counter += 1
            scan_id = f"recon-{self.scan_counter:06d}"

        scan = ReconScan(scan_id=scan_id, target=target)
        self.scans[scan_id] = scan
        logger.info(f"Created reconnaissance scan: {scan_id} for target: {target.target}")
        return scan

    def get_scan(self, scan_id: str) -> Optional[ReconScan]:
        """Retrieve scan by ID."""
        return self.scans.get(scan_id)

    async def run_scan(
        self,
        scan: ReconScan,
        enable_subdomain_enum: bool = True,
        enable_tech_fingerprint: bool = True,
        enable_dns_enum: bool = True,
    ) -> ReconScan:
        """Run complete reconnaissance scan."""
        from sentinel.subdomain_enumerator import SubdomainEnumerator
        from sentinel.tech_stack_fingerprinter import TechStackFingerprinter

        scan.mark_started()

        try:
            # Parse target
            target_domain = self._extract_domain(scan.target.target)
            if not target_domain:
                raise ValueError(f"Could not parse domain from: {scan.target.target}")

            # Run enabled reconnaissance modules
            tasks = []

            if enable_subdomain_enum:
                enum = SubdomainEnumerator()
                tasks.append(enum.enumerate(target_domain))

            if enable_tech_fingerprint:
                fingerprinter = TechStackFingerprinter()
                tasks.append(fingerprinter.fingerprint(scan.target.target))

            # Execute all tasks
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Process results
            for result in results:
                if isinstance(result, Exception):
                    error_msg = f"Module error: {str(result)}"
                    scan.add_error(error_msg)
                    logger.error(error_msg)
                elif isinstance(result, list):
                    # Results are assets
                    for asset in result:
                        scan.add_asset(asset)

            if scan.errors and not scan.assets_discovered:
                scan.mark_failed()
            elif scan.errors:
                scan.mark_partial()
            else:
                scan.mark_completed()

        except Exception as e:
            error_msg = f"Scan failed: {str(e)}"
            scan.add_error(error_msg)
            scan.mark_failed()
            logger.error(error_msg, exc_info=True)

        return scan

    @staticmethod
    def _extract_domain(target: str) -> Optional[str]:
        """Extract domain from various target formats."""
        # Remove common prefixes
        if "://" in target:
            target = target.split("://", 1)[1]

        # Remove path
        if "/" in target:
            target = target.split("/", 1)[0]

        # Remove port
        if ":" in target:
            target = target.split(":", 1)[0]

        # Validate it looks like a domain
        if "." in target and not target.startswith("."):
            return target.lower()

        return None

    @staticmethod
    def _extract_ip(target: str) -> Optional[str]:
        """Extract IP address from target."""
        try:
            socket.inet_aton(target)
            return target
        except (socket.error, TypeError):
            return None

    def get_all_domains(self, scan: ReconScan) -> Set[str]:
        """Get all domains from scan (including subdomains)."""
        domains = {scan.target.target}
        domains.update(scan.target.additional_domains)
        domains.update(scan.get_unique_values(AssetType.DOMAIN))
        domains.update(scan.get_unique_values(AssetType.SUBDOMAIN))
        return domains

    def get_all_ips(self, scan: ReconScan) -> Set[str]:
        """Get all IP addresses from scan."""
        return scan.get_unique_values(AssetType.IP_ADDRESS)

    def get_all_technologies(self, scan: ReconScan) -> Set[str]:
        """Get all detected technologies from scan."""
        return scan.get_unique_values(AssetType.TECHNOLOGY)
