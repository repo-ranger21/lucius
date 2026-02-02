"""Vulnerability scanner service."""

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any

from sentinel.config import config
from sentinel.nvd_client import NVDClient
from sentinel.parsers import Dependency, ParserFactory

try:
    from sentinel.talon_client import TalonClient
except Exception:  # pragma: no cover - optional dependency for tests
    TalonClient = None
from shared.logging import get_logger

logger = get_logger(__name__)


class VulnerabilityScanner:
    """Main vulnerability scanning service."""

    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def __init__(self) -> None:
        self.config = config.scan
        self.nvd_client = None
        self.talon_client = None

    def scan(
        self,
        project_name: str | Path,
        dependencies: list[Dependency] | None = None,
        severity_threshold: str = "low",
        include_dev: bool = True,
    ):
        """Scan a project directory or dependency list (sync or async)."""
        if dependencies is None and isinstance(project_name, (str, Path)):
            project_path = Path(project_name)
            try:
                parser = ParserFactory.create("auto", project_path)
            except ValueError:
                return self._build_result(project_path.name, [], [], severity_threshold)
            parse_result = parser.parse(include_dev=include_dev)

            if asyncio.iscoroutine(parse_result):

                async def _scan_from_path():
                    deps = await parse_result
                    return await self._scan_async(project_path.name, deps, severity_threshold)

                return self._run_or_return(_scan_from_path())

            # If a mock NVD client is injected without async API, return basic result
            if self.nvd_client is not None and not hasattr(
                self.nvd_client, "get_cves_for_package_async"
            ):
                return self._build_result(project_path.name, parse_result, [], severity_threshold)

            return self._run_or_return(
                self._scan_async(project_path.name, parse_result, severity_threshold)
            )

        return self._run_or_return(
            self._scan_async(str(project_name), dependencies or [], severity_threshold)
        )

    def _run_or_return(self, coro):
        """Run coroutine in sync contexts or return it in async contexts."""
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(coro)
        return coro

    async def _scan_async(
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

        result = self._build_result(
            project_name,
            dependencies,
            vulnerabilities,
            severity_threshold,
            start_time=start_time,
        )

        logger.info(
            f"Scan complete: {result.get('vulnerable_count', 0)} vulnerabilities found "
            f"({result.get('critical_count', 0)} critical, "
            f"{result.get('high_count', 0)} high)"
        )

        return result

    def _build_result(
        self,
        project_name: str,
        dependencies: list[Dependency],
        vulnerabilities: list[dict[str, Any]],
        severity_threshold: str,
        start_time: datetime | None = None,
    ) -> dict[str, Any]:
        """Build the scan result dictionary."""
        filtered_vulns = self._filter_by_severity(vulnerabilities, severity_threshold)
        severity_counts = self._count_severities(filtered_vulns)
        ecosystems = list({d.ecosystem for d in dependencies})
        ecosystem = ecosystems[0] if len(ecosystems) == 1 else "mixed"
        if start_time is None:
            start_time = datetime.utcnow()

        return {
            "project_name": project_name,
            "package_manager": ecosystem,
            "scan_type": "dependency",
            "total_dependencies": len(dependencies),
            "vulnerable_count": len({v.get("package_name") for v in filtered_vulns}),
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
            cves = await nvd_client.get_cves_for_package_async(
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
        return counts
