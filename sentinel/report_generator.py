"""Professional bug bounty report generation engine."""

import json
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Optional

from shared.logging import get_logger

logger = get_logger(__name__)


class ReportFormat(str, Enum):
    """Report output format."""

    JSON = "json"
    MARKDOWN = "markdown"
    HTML = "html"
    TEXT = "text"


class ReportSeverity(str, Enum):
    """Report severity classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ReportFinding:
    """Individual vulnerability finding for report."""

    title: str
    severity: ReportSeverity
    description: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    affected_assets: list[str] = field(default_factory=list)
    impact: str = ""
    reproduction_steps: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    discovered_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "affected_assets": self.affected_assets,
            "impact": self.impact,
            "reproduction_steps": self.reproduction_steps,
            "remediation": self.remediation,
            "references": self.references,
            "evidence": self.evidence,
            "discovered_at": self.discovered_at,
            "tags": self.tags,
        }


@dataclass
class ReportMetadata:
    """Report metadata and context."""

    report_id: str
    title: str
    author: str = ""
    organization: str = ""
    target: str = ""
    report_date: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    scan_start: Optional[str] = None
    scan_end: Optional[str] = None
    scope: list[str] = field(default_factory=list)
    methodology: list[str] = field(default_factory=list)
    tools_used: list[str] = field(default_factory=list)
    executive_summary: str = ""
    classification: str = "CONFIDENTIAL"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "report_id": self.report_id,
            "title": self.title,
            "author": self.author,
            "organization": self.organization,
            "target": self.target,
            "report_date": self.report_date,
            "scan_start": self.scan_start,
            "scan_end": self.scan_end,
            "scope": self.scope,
            "methodology": self.methodology,
            "tools_used": self.tools_used,
            "executive_summary": self.executive_summary,
            "classification": self.classification,
        }


@dataclass
class BugBountyReport:
    """Complete bug bounty security report."""

    metadata: ReportMetadata
    findings: list[ReportFinding] = field(default_factory=list)
    reconnaissance_results: dict[str, Any] = field(default_factory=dict)
    risk_summary: dict[str, int] = field(default_factory=dict)

    def add_finding(self, finding: ReportFinding) -> None:
        """Add finding to report."""
        self.findings.append(finding)
        logger.info(f"Added finding: {finding.title} ({finding.severity.value})")

    def get_findings_by_severity(self, severity: ReportSeverity) -> list[ReportFinding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_critical_findings(self) -> list[ReportFinding]:
        """Get critical severity findings."""
        return self.get_findings_by_severity(ReportSeverity.CRITICAL)

    def get_high_findings(self) -> list[ReportFinding]:
        """Get high severity findings."""
        return self.get_findings_by_severity(ReportSeverity.HIGH)

    def calculate_risk_summary(self) -> dict[str, int]:
        """Calculate risk summary by severity."""
        summary = {
            "critical": len(self.get_findings_by_severity(ReportSeverity.CRITICAL)),
            "high": len(self.get_findings_by_severity(ReportSeverity.HIGH)),
            "medium": len(self.get_findings_by_severity(ReportSeverity.MEDIUM)),
            "low": len(self.get_findings_by_severity(ReportSeverity.LOW)),
            "info": len(self.get_findings_by_severity(ReportSeverity.INFO)),
            "total": len(self.findings),
        }
        self.risk_summary = summary
        return summary

    def get_affected_assets(self) -> set[str]:
        """Get all affected assets from findings."""
        assets = set()
        for finding in self.findings:
            assets.update(finding.affected_assets)
        return assets

    def sort_findings_by_severity(self) -> None:
        """Sort findings by severity (critical first)."""
        severity_order = {
            ReportSeverity.CRITICAL: 0,
            ReportSeverity.HIGH: 1,
            ReportSeverity.MEDIUM: 2,
            ReportSeverity.LOW: 3,
            ReportSeverity.INFO: 4,
        }
        self.findings.sort(key=lambda f: severity_order.get(f.severity, 99))

    def to_dict(self) -> dict[str, Any]:
        """Convert report to dictionary."""
        self.calculate_risk_summary()
        return {
            "metadata": self.metadata.to_dict(),
            "risk_summary": self.risk_summary,
            "findings": [f.to_dict() for f in self.findings],
            "reconnaissance": self.reconnaissance_results,
            "affected_assets": list(self.get_affected_assets()),
        }


class ReportGenerator:
    """Generate professional bug bounty reports in multiple formats."""

    def __init__(self):
        """Initialize report generator."""
        self.reports: dict[str, BugBountyReport] = {}
        self.report_counter = 0

    def create_report(
        self,
        title: str,
        target: str,
        author: str = "",
        report_id: Optional[str] = None,
    ) -> BugBountyReport:
        """Create a new bug bounty report."""
        if report_id is None:
            self.report_counter += 1
            report_id = f"REPORT-{self.report_counter:06d}"

        metadata = ReportMetadata(
            report_id=report_id,
            title=title,
            author=author,
            target=target,
        )

        report = BugBountyReport(metadata=metadata)
        self.reports[report_id] = report

        logger.info(f"Created report: {report_id} - {title}")
        return report

    def get_report(self, report_id: str) -> Optional[BugBountyReport]:
        """Retrieve report by ID."""
        return self.reports.get(report_id)

    def generate_json(self, report: BugBountyReport, pretty: bool = True) -> str:
        """Generate JSON format report."""
        report.sort_findings_by_severity()
        data = report.to_dict()

        if pretty:
            return json.dumps(data, indent=2)
        return json.dumps(data)

    def generate_markdown(self, report: BugBountyReport) -> str:
        """Generate Markdown format report."""
        report.sort_findings_by_severity()
        report.calculate_risk_summary()

        md_lines = []

        # Header
        md_lines.append(f"# {report.metadata.title}")
        md_lines.append("")
        md_lines.append(f"**Report ID:** {report.metadata.report_id}")
        md_lines.append(f"**Target:** {report.metadata.target}")
        md_lines.append(f"**Date:** {report.metadata.report_date}")

        if report.metadata.author:
            md_lines.append(f"**Author:** {report.metadata.author}")

        md_lines.append(f"**Classification:** {report.metadata.classification}")
        md_lines.append("")
        md_lines.append("---")
        md_lines.append("")

        # Executive Summary
        if report.metadata.executive_summary:
            md_lines.append("## Executive Summary")
            md_lines.append("")
            md_lines.append(report.metadata.executive_summary)
            md_lines.append("")

        # Risk Summary
        md_lines.append("## Risk Summary")
        md_lines.append("")
        md_lines.append("| Severity | Count |")
        md_lines.append("|----------|-------|")
        md_lines.append(f"| Critical | {report.risk_summary.get('critical', 0)} |")
        md_lines.append(f"| High | {report.risk_summary.get('high', 0)} |")
        md_lines.append(f"| Medium | {report.risk_summary.get('medium', 0)} |")
        md_lines.append(f"| Low | {report.risk_summary.get('low', 0)} |")
        md_lines.append(f"| Info | {report.risk_summary.get('info', 0)} |")
        md_lines.append(f"| **Total** | **{report.risk_summary.get('total', 0)}** |")
        md_lines.append("")

        # Scope
        if report.metadata.scope:
            md_lines.append("## Scope")
            md_lines.append("")
            for item in report.metadata.scope:
                md_lines.append(f"- {item}")
            md_lines.append("")

        # Methodology
        if report.metadata.methodology:
            md_lines.append("## Methodology")
            md_lines.append("")
            for method in report.metadata.methodology:
                md_lines.append(f"- {method}")
            md_lines.append("")

        # Findings
        md_lines.append("## Findings")
        md_lines.append("")

        for idx, finding in enumerate(report.findings, 1):
            md_lines.append(f"### {idx}. {finding.title}")
            md_lines.append("")
            md_lines.append(f"**Severity:** {finding.severity.value.upper()}")

            if finding.cvss_score:
                md_lines.append(f"**CVSS Score:** {finding.cvss_score}")

            if finding.cvss_vector:
                md_lines.append(f"**CVSS Vector:** `{finding.cvss_vector}`")

            if finding.cve_id:
                md_lines.append(f"**CVE:** {finding.cve_id}")

            md_lines.append("")

            # Description
            md_lines.append("**Description:**")
            md_lines.append("")
            md_lines.append(finding.description)
            md_lines.append("")

            # Affected Assets
            if finding.affected_assets:
                md_lines.append("**Affected Assets:**")
                md_lines.append("")
                for asset in finding.affected_assets:
                    md_lines.append(f"- {asset}")
                md_lines.append("")

            # Impact
            if finding.impact:
                md_lines.append("**Impact:**")
                md_lines.append("")
                md_lines.append(finding.impact)
                md_lines.append("")

            # Reproduction Steps
            if finding.reproduction_steps:
                md_lines.append("**Reproduction Steps:**")
                md_lines.append("")
                for step_idx, step in enumerate(finding.reproduction_steps, 1):
                    md_lines.append(f"{step_idx}. {step}")
                md_lines.append("")

            # Remediation
            if finding.remediation:
                md_lines.append("**Remediation:**")
                md_lines.append("")
                md_lines.append(finding.remediation)
                md_lines.append("")

            # References
            if finding.references:
                md_lines.append("**References:**")
                md_lines.append("")
                for ref in finding.references:
                    md_lines.append(f"- {ref}")
                md_lines.append("")

            # Evidence
            if finding.evidence:
                md_lines.append("**Evidence:**")
                md_lines.append("")
                md_lines.append(f"- {len(finding.evidence)} piece(s) of evidence attached")
                md_lines.append("")

            md_lines.append("---")
            md_lines.append("")

        # Reconnaissance Results
        if report.reconnaissance_results:
            md_lines.append("## Reconnaissance Summary")
            md_lines.append("")
            if "subdomains_discovered" in report.reconnaissance_results:
                count = report.reconnaissance_results["subdomains_discovered"]
                md_lines.append(f"- Subdomains discovered: {count}")
            if "technologies_detected" in report.reconnaissance_results:
                count = report.reconnaissance_results["technologies_detected"]
                md_lines.append(f"- Technologies detected: {count}")
            md_lines.append("")

        return "\n".join(md_lines)

    def generate_html(self, report: BugBountyReport) -> str:
        """Generate HTML format report."""
        report.sort_findings_by_severity()
        report.calculate_risk_summary()

        html_lines = []

        # HTML header
        html_lines.append("<!DOCTYPE html>")
        html_lines.append("<html>")
        html_lines.append("<head>")
        html_lines.append("<meta charset='UTF-8'>")
        html_lines.append(f"<title>{report.metadata.title}</title>")
        html_lines.append("<style>")
        html_lines.append(self._get_html_styles())
        html_lines.append("</style>")
        html_lines.append("</head>")
        html_lines.append("<body>")

        # Header
        html_lines.append("<div class='header'>")
        html_lines.append(f"<h1>{report.metadata.title}</h1>")
        html_lines.append("<div class='metadata'>")
        html_lines.append(f"<p><strong>Report ID:</strong> {report.metadata.report_id}</p>")
        html_lines.append(f"<p><strong>Target:</strong> {report.metadata.target}</p>")
        html_lines.append(f"<p><strong>Date:</strong> {report.metadata.report_date}</p>")
        if report.metadata.author:
            html_lines.append(f"<p><strong>Author:</strong> {report.metadata.author}</p>")
        html_lines.append(
            f"<p><strong>Classification:</strong> {report.metadata.classification}</p>"
        )
        html_lines.append("</div>")
        html_lines.append("</div>")

        # Executive Summary
        if report.metadata.executive_summary:
            html_lines.append("<div class='section'>")
            html_lines.append("<h2>Executive Summary</h2>")
            html_lines.append(f"<p>{report.metadata.executive_summary}</p>")
            html_lines.append("</div>")

        # Risk Summary
        html_lines.append("<div class='section'>")
        html_lines.append("<h2>Risk Summary</h2>")
        html_lines.append("<table class='risk-table'>")
        html_lines.append("<tr><th>Severity</th><th>Count</th></tr>")
        html_lines.append(
            f"<tr class='critical'><td>Critical</td><td>{report.risk_summary.get('critical', 0)}</td></tr>"
        )
        html_lines.append(
            f"<tr class='high'><td>High</td><td>{report.risk_summary.get('high', 0)}</td></tr>"
        )
        html_lines.append(
            f"<tr class='medium'><td>Medium</td><td>{report.risk_summary.get('medium', 0)}</td></tr>"
        )
        html_lines.append(
            f"<tr class='low'><td>Low</td><td>{report.risk_summary.get('low', 0)}</td></tr>"
        )
        html_lines.append(
            f"<tr class='info'><td>Info</td><td>{report.risk_summary.get('info', 0)}</td></tr>"
        )
        html_lines.append(
            f"<tr class='total'><td><strong>Total</strong></td><td><strong>{report.risk_summary.get('total', 0)}</strong></td></tr>"
        )
        html_lines.append("</table>")
        html_lines.append("</div>")

        # Findings
        html_lines.append("<div class='section'>")
        html_lines.append("<h2>Findings</h2>")

        for idx, finding in enumerate(report.findings, 1):
            severity_class = finding.severity.value
            html_lines.append(f"<div class='finding finding-{severity_class}'>")
            html_lines.append(f"<h3>{idx}. {finding.title}</h3>")
            html_lines.append(
                f"<div class='severity-badge {severity_class}'>{finding.severity.value.upper()}</div>"
            )

            if finding.cvss_score:
                html_lines.append(f"<p><strong>CVSS Score:</strong> {finding.cvss_score}</p>")

            if finding.cve_id:
                html_lines.append(f"<p><strong>CVE:</strong> {finding.cve_id}</p>")

            html_lines.append(f"<p><strong>Description:</strong></p>")
            html_lines.append(f"<p>{finding.description}</p>")

            if finding.affected_assets:
                html_lines.append("<p><strong>Affected Assets:</strong></p>")
                html_lines.append("<ul>")
                for asset in finding.affected_assets:
                    html_lines.append(f"<li>{asset}</li>")
                html_lines.append("</ul>")

            if finding.impact:
                html_lines.append(f"<p><strong>Impact:</strong></p>")
                html_lines.append(f"<p>{finding.impact}</p>")

            if finding.reproduction_steps:
                html_lines.append("<p><strong>Reproduction Steps:</strong></p>")
                html_lines.append("<ol>")
                for step in finding.reproduction_steps:
                    html_lines.append(f"<li>{step}</li>")
                html_lines.append("</ol>")

            if finding.remediation:
                html_lines.append(f"<p><strong>Remediation:</strong></p>")
                html_lines.append(f"<p>{finding.remediation}</p>")

            html_lines.append("</div>")

        html_lines.append("</div>")

        # Close HTML
        html_lines.append("</body>")
        html_lines.append("</html>")

        return "\n".join(html_lines)

    @staticmethod
    def _get_html_styles() -> str:
        """Get CSS styles for HTML report."""
        return """
            body {
                font-family: Arial, sans-serif;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .header {
                background: #2c3e50;
                color: white;
                padding: 30px;
                border-radius: 5px;
                margin-bottom: 30px;
            }
            .header h1 {
                margin: 0 0 20px 0;
            }
            .metadata {
                font-size: 14px;
            }
            .metadata p {
                margin: 5px 0;
            }
            .section {
                background: white;
                padding: 25px;
                margin-bottom: 20px;
                border-radius: 5px;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }
            .section h2 {
                color: #2c3e50;
                border-bottom: 2px solid #3498db;
                padding-bottom: 10px;
                margin-top: 0;
            }
            .risk-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 15px;
            }
            .risk-table th, .risk-table td {
                padding: 12px;
                text-align: left;
                border: 1px solid #ddd;
            }
            .risk-table th {
                background-color: #34495e;
                color: white;
            }
            .risk-table tr.critical { background-color: #ffe6e6; }
            .risk-table tr.high { background-color: #fff3e6; }
            .risk-table tr.medium { background-color: #fff9e6; }
            .risk-table tr.low { background-color: #e6f7ff; }
            .risk-table tr.info { background-color: #f0f0f0; }
            .risk-table tr.total { background-color: #e8e8e8; font-weight: bold; }
            .finding {
                background: white;
                padding: 20px;
                margin-bottom: 20px;
                border-left: 5px solid #ccc;
                border-radius: 3px;
            }
            .finding-critical { border-left-color: #c0392b; }
            .finding-high { border-left-color: #e67e22; }
            .finding-medium { border-left-color: #f39c12; }
            .finding-low { border-left-color: #3498db; }
            .finding-info { border-left-color: #95a5a6; }
            .finding h3 {
                margin-top: 0;
                color: #2c3e50;
            }
            .severity-badge {
                display: inline-block;
                padding: 5px 15px;
                border-radius: 3px;
                color: white;
                font-weight: bold;
                margin-bottom: 15px;
            }
            .severity-badge.critical { background-color: #c0392b; }
            .severity-badge.high { background-color: #e67e22; }
            .severity-badge.medium { background-color: #f39c12; }
            .severity-badge.low { background-color: #3498db; }
            .severity-badge.info { background-color: #95a5a6; }
            ul, ol {
                margin: 10px 0;
            }
        """

    def generate_text(self, report: BugBountyReport) -> str:
        """Generate plain text format report."""
        report.sort_findings_by_severity()
        report.calculate_risk_summary()

        lines = []

        # Header
        lines.append("=" * 80)
        lines.append(report.metadata.title.center(80))
        lines.append("=" * 80)
        lines.append("")
        lines.append(f"Report ID: {report.metadata.report_id}")
        lines.append(f"Target: {report.metadata.target}")
        lines.append(f"Date: {report.metadata.report_date}")
        if report.metadata.author:
            lines.append(f"Author: {report.metadata.author}")
        lines.append(f"Classification: {report.metadata.classification}")
        lines.append("")

        # Risk Summary
        lines.append("RISK SUMMARY")
        lines.append("-" * 80)
        lines.append(f"Critical: {report.risk_summary.get('critical', 0)}")
        lines.append(f"High: {report.risk_summary.get('high', 0)}")
        lines.append(f"Medium: {report.risk_summary.get('medium', 0)}")
        lines.append(f"Low: {report.risk_summary.get('low', 0)}")
        lines.append(f"Info: {report.risk_summary.get('info', 0)}")
        lines.append(f"Total: {report.risk_summary.get('total', 0)}")
        lines.append("")

        # Findings
        lines.append("FINDINGS")
        lines.append("=" * 80)
        lines.append("")

        for idx, finding in enumerate(report.findings, 1):
            lines.append(f"{idx}. {finding.title}")
            lines.append("-" * 80)
            lines.append(f"Severity: {finding.severity.value.upper()}")
            if finding.cvss_score:
                lines.append(f"CVSS Score: {finding.cvss_score}")
            if finding.cve_id:
                lines.append(f"CVE: {finding.cve_id}")
            lines.append("")
            lines.append(f"Description: {finding.description}")
            lines.append("")

            if finding.affected_assets:
                lines.append("Affected Assets:")
                for asset in finding.affected_assets:
                    lines.append(f"  - {asset}")
                lines.append("")

            if finding.remediation:
                lines.append(f"Remediation: {finding.remediation}")
                lines.append("")

            lines.append("")

        return "\n".join(lines)

    def export_report(
        self, report: BugBountyReport, format: ReportFormat = ReportFormat.JSON
    ) -> str:
        """Export report in specified format."""
        if format == ReportFormat.JSON:
            return self.generate_json(report)
        elif format == ReportFormat.MARKDOWN:
            return self.generate_markdown(report)
        elif format == ReportFormat.HTML:
            return self.generate_html(report)
        elif format == ReportFormat.TEXT:
            return self.generate_text(report)
        else:
            raise ValueError(f"Unsupported format: {format}")
