"""Lucius Automation Pipeline - orchestrates recon, discovery, scanning, evidence, and reporting."""

import asyncio
import json
import logging
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from sentinel.api_tester import APITestResult, APIVulnerabilityScanner
from sentinel.config import config
from sentinel.cvss_scorer import (
    AttackComplexity,
    AttackVector,
    Availability,
    Confidentiality,
    CVSSv31Scorer,
    Integrity,
    PrivilegesRequired,
    Scope,
    UserInteraction,
)
from sentinel.evidence_manager import EvidenceStorage, EvidenceType
from sentinel.recon_engine import AssetType, ReconEngine, ReconTarget
from sentinel.report_generator import ReportFinding, ReportFormat, ReportGenerator, ReportSeverity

logger = logging.getLogger("LuciusPipeline")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


@dataclass
class PipelineResult:
    """Summary of pipeline execution."""

    session_id: str
    domain: str
    target: Optional[str] = None  # Alias for domain
    report_html: Path = None
    report_json: Path = None
    evidence_dir: Path = None
    findings_count: int = 0
    endpoints_tested: int = 0
    subdomains_found: int = 0
    technologies_detected: int = 0
    endpoints_discovered: int = 0
    vulnerabilities_found: int = 0
    evidence_items: int = 0
    reports_generated: List[Path] = None
    scan_end_time: Optional[str] = None
    duration_seconds: float = 0.0

    def __post_init__(self):
        """Set target to domain if not provided."""
        if self.target is None:
            self.target = self.domain
        if self.reports_generated is None:
            self.reports_generated = []
        if self.scan_end_time is None:
            self.scan_end_time = datetime.utcnow().isoformat()


class CVSSScorer:
    """Adapter for CVSS scoring with a safe default mapping."""

    def calculate_score(self, finding: APITestResult):
        """Calculate CVSS score for a finding using a safe default mapping."""
        impact_map = {
            "sql_injection": (Confidentiality.HIGH, Integrity.HIGH, Availability.LOW),
            "command_injection": (Confidentiality.HIGH, Integrity.HIGH, Availability.HIGH),
            "cross_site_scripting": (Confidentiality.LOW, Integrity.LOW, Availability.NONE),
            "server_side_request_forgery": (Confidentiality.HIGH, Integrity.LOW, Availability.LOW),
            "insecure_direct_object_reference": (
                Confidentiality.HIGH,
                Integrity.LOW,
                Availability.NONE,
            ),
        }

        confidentiality, integrity, availability = impact_map.get(
            finding.vulnerability_type.value,
            (Confidentiality.LOW, Integrity.NONE, Availability.NONE),
        )

        return CVSSv31Scorer.calculate(
            attack_vector=AttackVector.NETWORK.value,
            attack_complexity=AttackComplexity.LOW.value,
            privileges_required=PrivilegesRequired.NONE.value,
            user_interaction=UserInteraction.NONE.value,
            scope=Scope.UNCHANGED.value,
            confidentiality=confidentiality.value,
            integrity=integrity.value,
            availability=availability.value,
        )


class BountyPipeline:
    """Orchestrates the Lucius automation pipeline across all modules."""

    def __init__(self, workspace_dir: str = "./bounty_workspace", created_by: str = "lucius_bot"):
        self.workspace = Path(workspace_dir)
        self.workspace.mkdir(parents=True, exist_ok=True)

        self.created_by = created_by
        self.recon_engine = ReconEngine()
        self.api_scanner = APIVulnerabilityScanner(
            "https://localhost",
            rate_limit_rps=config.scan.max_rps,
            safe_url_allowlist=config.ssrf.safe_url_allowlist,
        )
        self.evidence_storage = EvidenceStorage(self.workspace / "evidence")
        self.report_gen = ReportGenerator()
        self.cvss_scorer = CVSSScorer()

    async def run_target(
        self, domain: str, max_endpoints: int = 5, deep_scan: bool = False, timeout: int = 30
    ) -> PipelineResult:
        """
        Executes the full Lucius defensive chain on a target.

        Args:
            domain: Target domain to scan (e.g., example.com)
            max_endpoints: Safety limit for number of endpoints to test
            deep_scan: Enable deep scanning with real network requests (not mocked)
            timeout: Network request timeout in seconds

        Returns:
            PipelineResult with report and evidence locations
        """
        scan_start = datetime.utcnow()
        session_id = f"scan_{scan_start.strftime('%Y%m%d_%H%M%S')}"
        logger.info("🚀 Starting Scan: %s (deep_scan=%s, timeout=%s)", domain, deep_scan, timeout)

        report = self.report_gen.create_report(
            title=f"Lucius Bounty Report - {domain}",
            target=domain,
            author=self.created_by,
            report_id=session_id,
        )
        report.metadata.scan_start = datetime.utcnow().isoformat()
        report.metadata.methodology = [
            "Reconnaissance (subdomain enumeration, tech fingerprinting)",
            "API discovery and parameter mapping",
            "Safe fuzzing with simulated responses",
            "Evidence collection and PII redaction",
        ]
        report.metadata.tools_used = [
            "Lucius Recon Engine",
            "Lucius API Tester",
            "Lucius CVSS Scorer",
            "Lucius Evidence Manager",
        ]

        # --- PHASE 1: RECONNAISSANCE ---
        logger.info("--- PHASE 1: RECONNAISSANCE ---")
        target = ReconTarget(target=domain)
        scan = self.recon_engine.create_scan(target, scan_id=f"recon-{session_id}")
        scan_result = await self.recon_engine.run_scan(scan)

        subdomains = scan_result.get_assets_by_type(AssetType.SUBDOMAIN)
        technologies = scan_result.get_assets_by_type(AssetType.TECHNOLOGY)
        report.reconnaissance_results = scan_result.get_summary()
        report.metadata.scope = [domain] + [asset.value for asset in subdomains]

        logger.info(
            "✅ Recon complete: Found %s subdomains, %s technologies",
            len(subdomains),
            len(technologies),
        )

        # Store Recon Evidence
        self.evidence_storage.store_evidence(
            content=scan_result.export_json().encode("utf-8"),
            evidence_type=EvidenceType.LOG_FILE,
            created_by=self.created_by,
            tags=["recon", "asset_inventory"],
            description="Reconnaissance scan summary",
        )

        # --- PHASE 2 & 3: API DISCOVERY & TESTING ---
        logger.info("--- PHASE 2: API DISCOVERY & TESTING ---")
        base_url = f"https://{domain}"
        self.api_scanner = APIVulnerabilityScanner(
            base_url,
            deep_scan=deep_scan,
            timeout=timeout,
            rate_limit_rps=config.scan.max_rps,
            safe_url_allowlist=config.ssrf.safe_url_allowlist,
        )

        endpoints = self.api_scanner.discover_endpoints()
        logger.info("🔎 Discovered %s potential API endpoints", len(endpoints))

        # Determine which endpoints to scan based on mode
        if deep_scan:
            logger.info("🔥 DEEP SCAN MODE ENABLED: Testing ALL discovered endpoints.")
            endpoints_to_scan = endpoints
        else:
            logger.info(
                "⚠️ RAPID MODE: Limiting scan to first 5 endpoints (Use --deep for full coverage)."
            )
            endpoints_to_scan = endpoints[:5]

        findings: List[APITestResult] = []
        for endpoint in endpoints_to_scan:
            logger.info("Testing endpoint: %s %s", endpoint.method.value, endpoint.url)
            endpoint_findings = self.api_scanner.scan_endpoint(endpoint)
            findings.extend(endpoint_findings)

        logger.info("✅ Scanning complete: Found %s potential issues", len(findings))

        # --- PHASE 4: SCORING & EVIDENCE ---
        logger.info("--- PHASE 4: SCORING & EVIDENCE ---")

        stored_evidence_ids = []
        for finding in findings:
            score = self.cvss_scorer.calculate_score(finding)
            severity = self._map_severity(score.severity)

            evidence_entries = []
            evidence_id = self._store_finding_evidence(finding)
            stored_evidence_ids.append(evidence_id)
            if evidence_id:
                evidence_entries.append({"evidence_id": evidence_id})

            report.add_finding(
                ReportFinding(
                    title=f"{finding.vulnerability_type.value} at {finding.endpoint.url}",
                    description=finding.evidence or finding.http_response or "",
                    severity=severity,
                    cvss_score=score.score,
                    cvss_vector=score.vector,
                    affected_assets=[finding.endpoint.url],
                    remediation="Ensure proper input validation and output encoding.",
                    evidence=evidence_entries,
                    tags=[finding.vulnerability_type.value],
                )
            )

        report.metadata.scan_end = datetime.utcnow().isoformat()
        report.calculate_risk_summary()

        # --- PHASE 5: REPORTING ---
        logger.info("--- PHASE 5: REPORT GENERATION ---")
        report_path = self.workspace / f"report_{domain}_{session_id}"

        html_report = self.report_gen.export_report(report, format=ReportFormat.HTML)
        json_report = self.report_gen.export_report(report, format=ReportFormat.JSON)

        html_path = report_path.with_suffix(".html")
        json_path = report_path.with_suffix(".json")

        html_path.write_text(html_report, encoding="utf-8")
        json_path.write_text(json_report, encoding="utf-8")

        logger.info("🎉 Pipeline Complete!")
        logger.info("📄 Report generated: %s", html_path)
        logger.info("📊 Evidence stored: %s", self.workspace / "evidence")

        scan_end = datetime.utcnow()
        duration = (scan_end - scan_start).total_seconds()

        return PipelineResult(
            session_id=session_id,
            domain=domain,
            report_html=html_path,
            report_json=json_path,
            evidence_dir=self.workspace / "evidence",
            findings_count=len(findings),
            endpoints_tested=min(len(endpoints), max_endpoints),
            subdomains_found=len(subdomains),
            technologies_detected=len(technologies),
            endpoints_discovered=len(endpoints),
            vulnerabilities_found=len(findings),
            evidence_items=len([e for e in stored_evidence_ids if e]),
            reports_generated=[html_path, json_path],
            scan_end_time=scan_end.isoformat(),
            duration_seconds=duration,
        )

    def _map_severity(self, severity: str) -> ReportSeverity:
        """Map CVSS severity to report severity enum."""
        severity_map = {
            "CRITICAL": ReportSeverity.CRITICAL,
            "HIGH": ReportSeverity.HIGH,
            "MEDIUM": ReportSeverity.MEDIUM,
            "LOW": ReportSeverity.LOW,
            "NONE": ReportSeverity.INFO,
        }
        return severity_map.get(severity, ReportSeverity.INFO)

    def _store_finding_evidence(self, finding: APITestResult) -> Optional[str]:
        """Store evidence for a finding and return stored evidence ID (redacted if needed)."""
        evidence_payload = {
            "http_request": finding.http_request,
            "http_response": finding.http_response,
            "evidence": finding.evidence,
            "endpoint": finding.endpoint.url,
            "parameter": finding.parameter_tested,
        }

        stored_ev = self.evidence_storage.store_evidence(
            content=json.dumps(evidence_payload, indent=2).encode("utf-8"),
            evidence_type=EvidenceType.HTTP_RESPONSE,
            created_by=self.created_by,
            tags=["vulnerability", finding.vulnerability_type.value],
            description=f"Evidence for {finding.vulnerability_type.value}",
        )

        if stored_ev.metadata.contains_pii:
            logger.warning(
                "⚠️ PII detected in evidence %s: %s",
                stored_ev.metadata.evidence_id,
                [p.value for p in stored_ev.metadata.pii_types],
            )
            redacted_ev = self.evidence_storage.redact_evidence_pii(
                stored_ev.metadata.evidence_id,
                self.created_by,
            )
            if redacted_ev:
                return redacted_ev.metadata.evidence_id

        return stored_ev.metadata.evidence_id


if __name__ == "__main__":
    pipeline = BountyPipeline()
    asyncio.run(pipeline.run_target("example.com"))
