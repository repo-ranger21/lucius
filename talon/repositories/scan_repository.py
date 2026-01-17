"""
Scan repository for database operations.

This module implements the repository pattern for managing scan result records
with multi-tenant isolation and audit logging.
"""

from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Query, joinedload

from shared.logging import get_logger
from talon.extensions import db
from talon.models import ScanResult, ScanVulnerability, Vulnerability
from talon.repositories.base import BaseRepository

logger = get_logger(__name__)


class ScanRepository(BaseRepository[ScanResult]):
    """
    Repository for scan result database operations.

    Provides:
    - CRUD operations with tenant isolation
    - Scan status management
    - Vulnerability association queries
    - Statistics and reporting methods

    Example:
        >>> repo = ScanRepository(tenant_id="tenant-123")
        >>> scans = repo.find_by_project("my-project")
        >>> for scan in scans:
        ...     print(f"{scan.project_name}: {scan.vulnerable_count} vulns")
    """

    model_class = ScanResult

    def __init__(self, tenant_id: str) -> None:
        """
        Initialize scan repository.

        Args:
            tenant_id: Tenant identifier for data isolation
        """
        super().__init__(tenant_id)

    def _apply_tenant_filter(self, query: Query) -> Query:
        """
        Apply tenant-specific filtering to scans.

        Scans are filtered by project name prefix convention:
        "{tenant_id}/{project_name}" or direct tenant_id field if present.

        Args:
            query: SQLAlchemy query

        Returns:
            Filtered query
        """
        # If model has tenant_id field, use it directly
        if hasattr(ScanResult, "tenant_id"):
            return query.filter(ScanResult.tenant_id == self._tenant_id)

        # Otherwise, use project name prefix convention
        # Projects are namespaced as "tenant_id/project_name"
        prefix = f"{self._tenant_id}/%"
        return query.filter(
            or_(
                ScanResult.project_name.like(prefix),
                ScanResult.scan_metadata["tenant_id"].astext == self._tenant_id,
            )
        )

    def find_by_project(
        self,
        project_name: str,
        limit: int = 20,
        offset: int = 0,
    ) -> list[ScanResult]:
        """
        Find scans for a specific project.

        Args:
            project_name: Project name (can include tenant prefix)
            limit: Maximum results
            offset: Results offset

        Returns:
            List of scans for the project
        """
        # Normalize project name with tenant prefix if not present
        if not project_name.startswith(f"{self._tenant_id}/"):
            full_project_name = f"{self._tenant_id}/{project_name}"
        else:
            full_project_name = project_name

        return self._base_query().filter(
            or_(
                ScanResult.project_name == full_project_name,
                ScanResult.project_name == project_name,
            )
        ).order_by(
            ScanResult.created_at.desc()
        ).offset(offset).limit(limit).all()

    def find_by_status(
        self,
        status: str,
        limit: int = 50,
    ) -> list[ScanResult]:
        """
        Find scans by status.

        Args:
            status: Scan status (pending, running, completed, failed)
            limit: Maximum results

        Returns:
            List of scans with given status
        """
        status = status.lower().strip()

        return self._base_query().filter(
            ScanResult.status == status
        ).order_by(
            ScanResult.created_at.desc()
        ).limit(limit).all()

    def find_recent(
        self,
        days: int = 7,
        limit: int = 100,
    ) -> list[ScanResult]:
        """
        Find recent scans.

        Args:
            days: Number of days to look back
            limit: Maximum results

        Returns:
            List of recent scans
        """
        cutoff_date = datetime.utcnow() - timedelta(days=max(1, days))

        return self._base_query().filter(
            ScanResult.created_at >= cutoff_date
        ).order_by(
            ScanResult.created_at.desc()
        ).limit(limit).all()

    def find_with_critical_vulns(self, limit: int = 50) -> list[ScanResult]:
        """
        Find scans containing critical vulnerabilities.

        Args:
            limit: Maximum results

        Returns:
            List of scans with critical vulnerabilities
        """
        return self._base_query().filter(
            ScanResult.critical_count > 0
        ).order_by(
            ScanResult.critical_count.desc(),
            ScanResult.created_at.desc(),
        ).limit(limit).all()

    def get_scan_with_vulnerabilities(
        self,
        scan_id: UUID | str,
    ) -> ScanResult | None:
        """
        Get scan with eagerly loaded vulnerability details.

        Args:
            scan_id: Scan identifier

        Returns:
            Scan with loaded vulnerabilities or None
        """
        if isinstance(scan_id, str):
            scan_id = UUID(scan_id)

        return self._base_query().filter(
            ScanResult.id == scan_id
        ).options(
            joinedload(ScanResult.vulnerabilities)
            .joinedload(ScanVulnerability.vulnerability)
        ).first()

    def update_status(
        self,
        scan_id: UUID | str,
        status: str,
        error_message: str | None = None,
    ) -> ScanResult | None:
        """
        Update scan status.

        Args:
            scan_id: Scan identifier
            status: New status
            error_message: Optional error message for failed status

        Returns:
            Updated scan or None if not found
        """
        scan = self.get_by_id(scan_id)
        if not scan:
            return None

        scan.status = status.lower()

        if status.lower() == "completed":
            scan.completed_at = datetime.utcnow()

        if error_message and hasattr(scan, "scan_metadata"):
            scan.scan_metadata = scan.scan_metadata or {}
            scan.scan_metadata["error_message"] = error_message

        self.update(scan)
        self.commit()

        self._logger.info(
            "scan_status_updated",
            scan_id=str(scan_id),
            status=status,
            tenant_id=self._tenant_id,
        )

        return scan

    def add_vulnerability_to_scan(
        self,
        scan_id: UUID | str,
        vulnerability_id: UUID | str,
        package_name: str,
        installed_version: str | None = None,
        fixed_version: str | None = None,
    ) -> ScanVulnerability | None:
        """
        Associate a vulnerability with a scan.

        Args:
            scan_id: Scan identifier
            vulnerability_id: Vulnerability identifier
            package_name: Affected package name
            installed_version: Currently installed version
            fixed_version: Version that fixes the vulnerability

        Returns:
            Created association or None if scan not found
        """
        if isinstance(scan_id, str):
            scan_id = UUID(scan_id)
        if isinstance(vulnerability_id, str):
            vulnerability_id = UUID(vulnerability_id)

        scan = self.get_by_id(scan_id)
        if not scan:
            return None

        scan_vuln = ScanVulnerability(
            scan_id=scan_id,
            vulnerability_id=vulnerability_id,
            package_name=package_name,
            installed_version=installed_version,
            fixed_version=fixed_version,
        )

        db.session.add(scan_vuln)
        db.session.flush()

        self._logger.debug(
            "vulnerability_added_to_scan",
            scan_id=str(scan_id),
            vulnerability_id=str(vulnerability_id),
            package_name=package_name,
            tenant_id=self._tenant_id,
        )

        return scan_vuln

    def get_vulnerability_details_for_scan(
        self,
        scan_id: UUID | str,
    ) -> list[dict[str, Any]]:
        """
        Get detailed vulnerability information for a scan.

        Args:
            scan_id: Scan identifier

        Returns:
            List of vulnerability details with package info
        """
        if isinstance(scan_id, str):
            scan_id = UUID(scan_id)

        results = db.session.query(
            ScanVulnerability.package_name,
            ScanVulnerability.installed_version,
            ScanVulnerability.fixed_version,
            Vulnerability.cve_id,
            Vulnerability.severity,
            Vulnerability.cvss_score,
            Vulnerability.description,
        ).join(
            Vulnerability
        ).filter(
            ScanVulnerability.scan_id == scan_id
        ).order_by(
            Vulnerability.cvss_score.desc().nullslast()
        ).all()

        return [
            {
                "package_name": pkg,
                "installed_version": inst_ver,
                "fixed_version": fix_ver,
                "cve_id": cve,
                "severity": sev,
                "cvss_score": float(cvss) if cvss else None,
                "description": desc[:500] if desc else None,
            }
            for pkg, inst_ver, fix_ver, cve, sev, cvss, desc in results
        ]

    def get_project_statistics(
        self,
        project_name: str,
    ) -> dict[str, Any]:
        """
        Get vulnerability statistics for a project across all scans.

        Args:
            project_name: Project name

        Returns:
            Statistics dictionary
        """
        scans = self.find_by_project(project_name, limit=100)

        if not scans:
            return {
                "project_name": project_name,
                "total_scans": 0,
                "latest_scan": None,
                "total_vulnerabilities": 0,
                "severity_breakdown": {},
            }

        latest_scan = scans[0] if scans else None

        # Aggregate severity counts from latest scan
        severity_breakdown = {}
        if latest_scan:
            severity_breakdown = {
                "critical": latest_scan.critical_count,
                "high": latest_scan.high_count,
                "medium": latest_scan.medium_count,
                "low": latest_scan.low_count,
            }

        return {
            "project_name": project_name,
            "total_scans": len(scans),
            "latest_scan": latest_scan.to_dict() if latest_scan else None,
            "total_vulnerabilities": latest_scan.vulnerable_count if latest_scan else 0,
            "severity_breakdown": severity_breakdown,
        }

    def get_statistics(self) -> dict[str, Any]:
        """
        Get comprehensive scan statistics for tenant.

        Returns:
            Statistics dictionary
        """
        total_scans = self.count()

        # Status breakdown
        status_counts = db.session.query(
            ScanResult.status,
            func.count(ScanResult.id).label("count")
        ).group_by(ScanResult.status).all()

        status_breakdown = {row.status: row.count for row in status_counts}

        # Recent activity
        recent_scans = self.find_recent(days=7, limit=1000)
        critical_scans = self.find_with_critical_vulns(limit=1000)

        # Aggregate vulnerability counts
        total_vulns = sum(s.vulnerable_count for s in recent_scans)
        total_critical = sum(s.critical_count for s in recent_scans)

        return {
            "total_scans": total_scans,
            "status_breakdown": status_breakdown,
            "scans_last_7_days": len(recent_scans),
            "scans_with_critical": len(critical_scans),
            "vulnerabilities_last_7_days": total_vulns,
            "critical_vulnerabilities_last_7_days": total_critical,
        }

    def cleanup_old_scans(
        self,
        days: int = 90,
        keep_latest_per_project: int = 10,
    ) -> int:
        """
        Clean up old scan records while keeping recent history.

        Args:
            days: Delete scans older than this many days
            keep_latest_per_project: Keep at least this many scans per project

        Returns:
            Number of deleted scans
        """
        cutoff_date = datetime.utcnow() - timedelta(days=max(30, days))
        deleted_count = 0

        # Get all projects
        projects = db.session.query(
            ScanResult.project_name
        ).distinct().all()

        for (project_name,) in projects:
            # Get scans to potentially delete
            old_scans = self._base_query().filter(
                and_(
                    ScanResult.project_name == project_name,
                    ScanResult.created_at < cutoff_date,
                )
            ).order_by(
                ScanResult.created_at.desc()
            ).offset(keep_latest_per_project).all()

            for scan in old_scans:
                self.delete(scan.id)
                deleted_count += 1

        self.commit()

        self._logger.info(
            "scan_cleanup_completed",
            deleted_count=deleted_count,
            cutoff_days=days,
            tenant_id=self._tenant_id,
        )

        return deleted_count
