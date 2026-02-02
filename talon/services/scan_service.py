"""Scan service for processing vulnerability scan results."""

from datetime import datetime
from typing import Any

from shared.logging import get_logger
from talon.extensions import db
from talon.models import ScanResult, ScanVulnerability, Vulnerability

logger = get_logger(__name__)


class ScanService:
    """Service for managing vulnerability scans."""

    def create_scan(self, data: dict[str, Any]) -> ScanResult:
        """
        Create a new scan result from incoming data.

        Args:
            data: Scan data from Sentinel

        Returns:
            Created ScanResult instance
        """
        # Create scan result
        scan = ScanResult(
            tenant_id=data.get("tenant_id", "default"),
            project_name=data["project_name"],
            package_manager=data["package_manager"],
            scan_type=data.get("scan_type", "dependency"),
            total_dependencies=data.get("total_dependencies", 0),
            vulnerable_count=data.get("vulnerable_count", 0),
            critical_count=data.get("critical_count", 0),
            high_count=data.get("high_count", 0),
            medium_count=data.get("medium_count", 0),
            low_count=data.get("low_count", 0),
            sbom_path=data.get("sbom_path"),
            scan_metadata=data.get("scan_metadata", {}),
            status="completed",
            completed_at=datetime.utcnow(),
        )

        db.session.add(scan)
        db.session.flush()  # Get scan ID

        # Process vulnerabilities
        vulnerabilities = data.get("vulnerabilities", [])
        for vuln_data in vulnerabilities:
            self._process_vulnerability(scan, vuln_data)

        db.session.commit()

        logger.info(
            f"Created scan {scan.id} for {scan.project_name} "
            f"with {len(vulnerabilities)} vulnerabilities"
        )

        # Trigger notifications if critical vulnerabilities found
        if scan.critical_count > 0:
            self._trigger_critical_alert(scan)

        return scan

    def _process_vulnerability(
        self,
        scan: ScanResult,
        vuln_data: dict[str, Any],
    ) -> None:
        """Process and store a vulnerability."""
        cve_id = vuln_data.get("cve_id")
        if not cve_id:
            return

        # Find or create vulnerability record
        vulnerability = Vulnerability.query.filter_by(cve_id=cve_id).first()

        if not vulnerability:
            vulnerability = Vulnerability(
                cve_id=cve_id,
                description=vuln_data.get("description", "")[:2000],
                severity=vuln_data.get("severity", "UNKNOWN"),
                cvss_score=vuln_data.get("cvss_score"),
                cvss_vector=vuln_data.get("cvss_vector"),
                affected_packages=vuln_data.get("affected_packages", []),
                references=vuln_data.get("references", []),
            )
            db.session.add(vulnerability)
            db.session.flush()

        # Create scan-vulnerability link
        scan_vuln = ScanVulnerability(
            scan_id=scan.id,
            vulnerability_id=vulnerability.id,
            package_name=vuln_data.get("package_name", "unknown"),
            installed_version=vuln_data.get("installed_version"),
            fixed_version=vuln_data.get("fixed_version"),
        )
        db.session.add(scan_vuln)

    def _trigger_critical_alert(self, scan: ScanResult) -> None:
        """Trigger alert for critical vulnerabilities."""
        from talon.tasks.notifications import send_critical_alert

        try:
            send_critical_alert.delay(
                project_name=scan.project_name,
                critical_count=scan.critical_count,
                scan_id=str(scan.id),
            )
        except Exception as e:
            logger.error(f"Failed to trigger critical alert: {e}")

    def get_scan(self, scan_id: str) -> ScanResult | None:
        """Get a scan by ID."""
        return ScanResult.query.get(scan_id)

    def get_scans_for_project(
        self,
        project_name: str,
        limit: int = 10,
    ) -> list[ScanResult]:
        """Get recent scans for a project."""
        return (
            ScanResult.query.filter_by(project_name=project_name)
            .order_by(ScanResult.created_at.desc())
            .limit(limit)
            .all()
        )

    def get_vulnerable_packages(
        self,
        project_name: str | None = None,
        severity: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get list of vulnerable packages across scans."""
        query = (
            db.session.query(
                ScanVulnerability.package_name,
                ScanVulnerability.installed_version,
                Vulnerability.cve_id,
                Vulnerability.severity,
                Vulnerability.cvss_score,
                ScanResult.project_name,
            )
            .join(Vulnerability)
            .join(ScanResult)
        )

        if project_name:
            query = query.filter(ScanResult.project_name == project_name)
        if severity:
            query = query.filter(Vulnerability.severity == severity)

        query = query.order_by(Vulnerability.cvss_score.desc().nullslast())

        return [
            {
                "package_name": pkg,
                "installed_version": ver,
                "cve_id": cve,
                "severity": sev,
                "cvss_score": float(cvss) if cvss else None,
                "project_name": proj,
            }
            for pkg, ver, cve, sev, cvss, proj in query.all()
        ]
