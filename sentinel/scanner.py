"""Vulnerability scanner service."""

import asyncio
from datetime import datetime
from typing import Any

from sentinel.config import config
from sentinel.nvd_client import NVDClient
from sentinel.parsers import Dependency
from shared.logging import get_logger

logger = get_logger(__name__)


class VulnerabilityScanner:
    """Main vulnerability scanning service."""

    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def __init__(self) -> None:
        self.config = config.scan

    async def scan(
        self,
        project_name: str,
        dependencies: list[Dependency],
        severity_threshold: str = "low",
    ) -> dict[str, Any]:
        """
        Scan dependencies for vulnerabilities.

        Args:
            project_name: Name of the project being scanned
            dependencies: List of dependencies to scan
            severity_threshold: Minimum severity to report

        Returns:
            Scan results dictionary
        """
        logger.info(f"Starting scan for {project_name} with {len(dependencies)} dependencies")

        start_time = datetime.utcnow()
        vulnerabilities = []

        async with NVDClient() as nvd_client:
            # Process dependencies in batches
            for i in range(0, len(dependencies), self.config.batch_size):
                batch = dependencies[i : i + self.config.batch_size]
                batch_results = await self._scan_batch(nvd_client, batch)
                vulnerabilities.extend(batch_results)

        # Filter by severity threshold
        filtered_vulns = self._filter_by_severity(vulnerabilities, severity_threshold)

        # Calculate severity counts
        severity_counts = self._count_severities(filtered_vulns)

        # Determine ecosystem
        ecosystems = list({d.ecosystem for d in dependencies})
        ecosystem = ecosystems[0] if len(ecosystems) == 1 else "mixed"

        result = {
            "project_name": project_name,
            "package_manager": ecosystem,
            "scan_type": "dependency",
            "total_dependencies": len(dependencies),
            "vulnerable_count": len({v["package_name"] for v in filtered_vulns}),
            "critical_count": severity_counts.get("CRITICAL", 0),
            "high_count": severity_counts.get("HIGH", 0),
            "medium_count": severity_counts.get("MEDIUM", 0),
            "low_count": severity_counts.get("LOW", 0),
            "vulnerabilities": filtered_vulns,
            "scan_metadata": {
                "start_time": start_time.isoformat(),
                "end_time": datetime.utcnow().isoformat(),
                "severity_threshold": severity_threshold,
                "scanner_version": "1.0.0",
            },
        }

        logger.info(
            f"Scan complete: {len(filtered_vulns)} vulnerabilities found "
            f"({severity_counts.get('CRITICAL', 0)} critical, "
            f"{severity_counts.get('HIGH', 0)} high)"
        )

        return result

    async def _scan_batch(
        self,
        nvd_client: NVDClient,
        dependencies: list[Dependency],
    ) -> list[dict[str, Any]]:
        """Scan a batch of dependencies concurrently."""
        semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)

        async def scan_dep(dep: Dependency) -> list[dict[str, Any]]:
            async with semaphore:
                return await self._scan_dependency(nvd_client, dep)

        tasks = [scan_dep(dep) for dep in dependencies]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        vulnerabilities: list[dict[str, Any]] = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.warning(f"Error scanning {dependencies[i].name}: {result}")
            else:
                vulnerabilities.extend(result)

        return vulnerabilities

    async def _scan_dependency(
        self,
        nvd_client: NVDClient,
        dependency: Dependency,
    ) -> list[dict[str, Any]]:
        """Scan a single dependency for vulnerabilities."""
        try:
            cves = await nvd_client.get_cves_for_package(
                package_name=dependency.name,
                ecosystem=dependency.ecosystem,
                version=dependency.version,
            )

            vulnerabilities = []
            for cve in cves:
                # Check if the installed version is affected
                if self._is_version_affected(dependency, cve):
                    vulnerabilities.append(
                        {
                            "cve_id": cve.get("cve_id"),
                            "package_name": dependency.name,
                            "installed_version": dependency.version,
                            "severity": cve.get("severity", "UNKNOWN"),
                            "cvss_score": cve.get("cvss_score"),
                            "cvss_vector": cve.get("cvss_vector"),
                            "description": cve.get("description", "")[:500],
                            "fixed_version": self._get_fixed_version(cve),
                            "references": cve.get("references", [])[:5],
                        }
                    )

            return vulnerabilities

        except Exception as e:
            logger.debug(f"Error scanning {dependency.name}: {e}")
            return []

    def _is_version_affected(
        self,
        dependency: Dependency,
        cve: dict[str, Any],
    ) -> bool:
        """
        Check if the installed version is affected by the CVE.

        This is a simplified check - a production implementation would
        use proper version comparison logic.
        """
        # For now, if the CVE mentions the package, assume it's affected
        # A proper implementation would compare version ranges
        affected = cve.get("affected_packages", [])

        for pkg in affected:
            if dependency.name.lower() in pkg.get("product", "").lower():
                # Check version range if available
                version_end = pkg.get("version_end")
                if version_end:
                    try:
                        from packaging import version as pkg_version

                        installed = pkg_version.parse(dependency.version)
                        fixed = pkg_version.parse(version_end)
                        return installed < fixed
                    except Exception:
                        pass
                return True

        return True  # Default to reporting if we can't determine

    def _get_fixed_version(self, cve: dict[str, Any]) -> str | None:
        """Extract the fixed version from CVE data."""
        for pkg in cve.get("affected_packages", []):
            version_end = pkg.get("version_end")
            if version_end:
                return version_end
        return None

    def _filter_by_severity(
        self,
        vulnerabilities: list[dict[str, Any]],
        threshold: str,
    ) -> list[dict[str, Any]]:
        """Filter vulnerabilities by severity threshold."""
        threshold_upper = threshold.upper()

        if threshold_upper not in self.SEVERITY_ORDER:
            return vulnerabilities

        threshold_index = self.SEVERITY_ORDER.index(threshold_upper)
        allowed_severities = set(self.SEVERITY_ORDER[: threshold_index + 1])

        # Include LOW and above based on threshold
        allowed_severities = set(self.SEVERITY_ORDER[threshold_index:])

        return [
            v
            for v in vulnerabilities
            if v.get("severity", "UNKNOWN").upper() in allowed_severities
            or v.get("severity", "UNKNOWN").upper() not in self.SEVERITY_ORDER
        ]

    def _count_severities(
        self,
        vulnerabilities: list[dict[str, Any]],
    ) -> dict[str, int]:
        """Count vulnerabilities by severity."""
        counts: dict[str, int] = {}

        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN").upper()
            counts[severity] = counts.get(severity, 0) + 1

        return counts
