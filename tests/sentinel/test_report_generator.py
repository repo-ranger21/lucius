"""Tests for bug bounty report generation (Step 3)."""

import json

import pytest

from sentinel.report_generator import (
    BugBountyReport,
    ReportFinding,
    ReportFormat,
    ReportGenerator,
    ReportMetadata,
    ReportSeverity,
)


class TestReportFinding:
    """Tests for report findings."""

    def test_create_finding(self):
        """Test creating a report finding."""
        finding = ReportFinding(
            title="SQL Injection in Login Form",
            severity=ReportSeverity.CRITICAL,
            description="SQL injection vulnerability found",
            cve_id="CVE-2024-12345",
            cvss_score=9.8,
        )

        assert finding.title == "SQL Injection in Login Form"
        assert finding.severity == ReportSeverity.CRITICAL
        assert finding.cvss_score == 9.8

    def test_finding_with_evidence(self):
        """Test finding with evidence."""
        finding = ReportFinding(
            title="XSS Vulnerability",
            severity=ReportSeverity.HIGH,
            description="Reflected XSS",
            evidence=[
                {"type": "screenshot", "description": "XSS proof"},
                {"type": "log", "description": "Server logs"},
            ],
        )

        assert len(finding.evidence) == 2

    def test_finding_with_reproduction_steps(self):
        """Test finding with reproduction steps."""
        finding = ReportFinding(
            title="Authentication Bypass",
            severity=ReportSeverity.CRITICAL,
            description="Auth bypass vulnerability",
            reproduction_steps=[
                "Navigate to login page",
                "Enter SQL payload in username",
                "Click login",
                "Bypass authentication",
            ],
        )

        assert len(finding.reproduction_steps) == 4

    def test_finding_to_dict(self):
        """Test finding dictionary conversion."""
        finding = ReportFinding(
            title="Test Vulnerability",
            severity=ReportSeverity.MEDIUM,
            description="Test description",
            affected_assets=["example.com", "api.example.com"],
        )

        finding_dict = finding.to_dict()

        assert finding_dict["title"] == "Test Vulnerability"
        assert finding_dict["severity"] == "medium"
        assert len(finding_dict["affected_assets"]) == 2


class TestReportMetadata:
    """Tests for report metadata."""

    def test_create_metadata(self):
        """Test creating report metadata."""
        metadata = ReportMetadata(
            report_id="REPORT-001",
            title="Security Assessment Report",
            author="Security Researcher",
            target="example.com",
        )

        assert metadata.report_id == "REPORT-001"
        assert metadata.author == "Security Researcher"

    def test_metadata_with_scope(self):
        """Test metadata with scope."""
        metadata = ReportMetadata(
            report_id="REPORT-002",
            title="Penetration Test",
            target="example.com",
            scope=["example.com", "*.example.com", "api.example.com"],
        )

        assert len(metadata.scope) == 3

    def test_metadata_with_methodology(self):
        """Test metadata with methodology."""
        metadata = ReportMetadata(
            report_id="REPORT-003",
            title="Bug Bounty Report",
            target="example.com",
            methodology=[
                "Reconnaissance",
                "Vulnerability Scanning",
                "Manual Testing",
                "Exploitation",
            ],
        )

        assert len(metadata.methodology) == 4

    def test_metadata_to_dict(self):
        """Test metadata dictionary conversion."""
        metadata = ReportMetadata(
            report_id="REPORT-004",
            title="Test Report",
            target="test.com",
        )

        metadata_dict = metadata.to_dict()

        assert metadata_dict["report_id"] == "REPORT-004"
        assert metadata_dict["title"] == "Test Report"


class TestBugBountyReport:
    """Tests for bug bounty report."""

    def test_create_report(self):
        """Test creating report."""
        metadata = ReportMetadata(
            report_id="REPORT-001",
            title="Test Report",
            target="example.com",
        )

        report = BugBountyReport(metadata=metadata)

        assert report.metadata.report_id == "REPORT-001"
        assert len(report.findings) == 0

    def test_add_finding(self):
        """Test adding finding to report."""
        metadata = ReportMetadata(
            report_id="REPORT-001",
            title="Test Report",
            target="example.com",
        )
        report = BugBountyReport(metadata=metadata)

        finding = ReportFinding(
            title="SQL Injection",
            severity=ReportSeverity.CRITICAL,
            description="SQL vulnerability",
        )

        report.add_finding(finding)

        assert len(report.findings) == 1

    def test_get_findings_by_severity(self):
        """Test filtering findings by severity."""
        metadata = ReportMetadata(
            report_id="REPORT-001",
            title="Test Report",
            target="example.com",
        )
        report = BugBountyReport(metadata=metadata)

        report.add_finding(
            ReportFinding(
                title="Critical Issue",
                severity=ReportSeverity.CRITICAL,
                description="Critical",
            )
        )
        report.add_finding(
            ReportFinding(title="High Issue", severity=ReportSeverity.HIGH, description="High")
        )
        report.add_finding(
            ReportFinding(
                title="Another Critical",
                severity=ReportSeverity.CRITICAL,
                description="Critical",
            )
        )

        critical = report.get_critical_findings()

        assert len(critical) == 2

    def test_calculate_risk_summary(self):
        """Test risk summary calculation."""
        metadata = ReportMetadata(
            report_id="REPORT-001",
            title="Test Report",
            target="example.com",
        )
        report = BugBountyReport(metadata=metadata)

        report.add_finding(
            ReportFinding(title="Critical", severity=ReportSeverity.CRITICAL, description="C")
        )
        report.add_finding(
            ReportFinding(title="High", severity=ReportSeverity.HIGH, description="H")
        )
        report.add_finding(
            ReportFinding(title="Medium", severity=ReportSeverity.MEDIUM, description="M")
        )

        summary = report.calculate_risk_summary()

        assert summary["critical"] == 1
        assert summary["high"] == 1
        assert summary["medium"] == 1
        assert summary["total"] == 3

    def test_get_affected_assets(self):
        """Test getting affected assets."""
        metadata = ReportMetadata(
            report_id="REPORT-001",
            title="Test Report",
            target="example.com",
        )
        report = BugBountyReport(metadata=metadata)

        report.add_finding(
            ReportFinding(
                title="Issue 1",
                severity=ReportSeverity.HIGH,
                description="Test",
                affected_assets=["example.com", "api.example.com"],
            )
        )
        report.add_finding(
            ReportFinding(
                title="Issue 2",
                severity=ReportSeverity.MEDIUM,
                description="Test",
                affected_assets=["api.example.com", "staging.example.com"],
            )
        )

        assets = report.get_affected_assets()

        assert len(assets) == 3
        assert "example.com" in assets
        assert "api.example.com" in assets
        assert "staging.example.com" in assets

    def test_sort_findings_by_severity(self):
        """Test sorting findings by severity."""
        metadata = ReportMetadata(
            report_id="REPORT-001",
            title="Test Report",
            target="example.com",
        )
        report = BugBountyReport(metadata=metadata)

        report.add_finding(ReportFinding(title="Low", severity=ReportSeverity.LOW, description="L"))
        report.add_finding(
            ReportFinding(title="Critical", severity=ReportSeverity.CRITICAL, description="C")
        )
        report.add_finding(
            ReportFinding(title="Medium", severity=ReportSeverity.MEDIUM, description="M")
        )

        report.sort_findings_by_severity()

        assert report.findings[0].severity == ReportSeverity.CRITICAL
        assert report.findings[1].severity == ReportSeverity.MEDIUM
        assert report.findings[2].severity == ReportSeverity.LOW

    def test_report_to_dict(self):
        """Test report dictionary conversion."""
        metadata = ReportMetadata(
            report_id="REPORT-001",
            title="Test Report",
            target="example.com",
        )
        report = BugBountyReport(metadata=metadata)

        report.add_finding(
            ReportFinding(
                title="Test Finding",
                severity=ReportSeverity.HIGH,
                description="Test",
            )
        )

        report_dict = report.to_dict()

        assert "metadata" in report_dict
        assert "findings" in report_dict
        assert "risk_summary" in report_dict
        assert report_dict["risk_summary"]["total"] == 1


class TestReportGenerator:
    """Tests for report generator."""

    def test_create_generator(self):
        """Test creating report generator."""
        generator = ReportGenerator()
        assert len(generator.reports) == 0

    def test_create_report(self):
        """Test creating report with generator."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="Security Assessment",
            target="example.com",
            author="Test Researcher",
        )

        assert report.metadata.title == "Security Assessment"
        assert report.metadata.target == "example.com"

    def test_create_report_with_auto_id(self):
        """Test creating report with auto-generated ID."""
        generator = ReportGenerator()

        report1 = generator.create_report(title="Report 1", target="example.com")
        report2 = generator.create_report(title="Report 2", target="test.com")

        assert report1.metadata.report_id.startswith("REPORT-")
        assert report2.metadata.report_id.startswith("REPORT-")
        assert report1.metadata.report_id != report2.metadata.report_id

    def test_create_report_with_custom_id(self):
        """Test creating report with custom ID."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="Custom Report",
            target="example.com",
            report_id="CUSTOM-001",
        )

        assert report.metadata.report_id == "CUSTOM-001"

    def test_get_report(self):
        """Test retrieving report."""
        generator = ReportGenerator()

        created = generator.create_report(
            title="Test Report",
            target="example.com",
            report_id="TEST-001",
        )

        retrieved = generator.get_report("TEST-001")

        assert retrieved is not None
        assert retrieved.metadata.report_id == "TEST-001"

    def test_generate_json(self):
        """Test JSON report generation."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="JSON Test Report",
            target="example.com",
        )

        report.add_finding(
            ReportFinding(
                title="Test Vulnerability",
                severity=ReportSeverity.HIGH,
                description="Test description",
            )
        )

        json_output = generator.generate_json(report)

        # Verify it's valid JSON
        data = json.loads(json_output)
        assert "metadata" in data
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_generate_markdown(self):
        """Test Markdown report generation."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="Markdown Test Report",
            target="example.com",
            author="Test Author",
        )

        report.add_finding(
            ReportFinding(
                title="SQL Injection",
                severity=ReportSeverity.CRITICAL,
                description="SQL injection vulnerability",
                cvss_score=9.8,
                affected_assets=["example.com"],
            )
        )

        md_output = generator.generate_markdown(report)

        # Verify Markdown content
        assert "# Markdown Test Report" in md_output
        assert "SQL Injection" in md_output
        assert "CRITICAL" in md_output
        assert "9.8" in md_output

    def test_generate_html(self):
        """Test HTML report generation."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="HTML Test Report",
            target="example.com",
        )

        report.add_finding(
            ReportFinding(
                title="XSS Vulnerability",
                severity=ReportSeverity.HIGH,
                description="Cross-site scripting",
            )
        )

        html_output = generator.generate_html(report)

        # Verify HTML content
        assert "<!DOCTYPE html>" in html_output
        assert "<html>" in html_output
        assert "HTML Test Report" in html_output
        assert "XSS Vulnerability" in html_output

    def test_generate_text(self):
        """Test plain text report generation."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="Text Test Report",
            target="example.com",
        )

        report.add_finding(
            ReportFinding(
                title="Authentication Bypass",
                severity=ReportSeverity.CRITICAL,
                description="Auth bypass found",
            )
        )

        text_output = generator.generate_text(report)

        # Verify text content
        assert "Text Test Report" in text_output
        assert "Authentication Bypass" in text_output
        assert "CRITICAL" in text_output

    def test_export_report_json_format(self):
        """Test exporting report in JSON format."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="Export Test",
            target="example.com",
        )

        output = generator.export_report(report, ReportFormat.JSON)

        assert isinstance(output, str)
        data = json.loads(output)
        assert "metadata" in data

    def test_export_report_markdown_format(self):
        """Test exporting report in Markdown format."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="Export Test",
            target="example.com",
        )

        output = generator.export_report(report, ReportFormat.MARKDOWN)

        assert isinstance(output, str)
        assert "# Export Test" in output

    def test_export_report_html_format(self):
        """Test exporting report in HTML format."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="Export Test",
            target="example.com",
        )

        output = generator.export_report(report, ReportFormat.HTML)

        assert isinstance(output, str)
        assert "<!DOCTYPE html>" in output

    def test_export_report_text_format(self):
        """Test exporting report in text format."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="Export Test",
            target="example.com",
        )

        output = generator.export_report(report, ReportFormat.TEXT)

        assert isinstance(output, str)
        assert "Export Test" in output

    def test_report_with_multiple_findings(self):
        """Test report with multiple findings of different severities."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="Multi-Finding Report",
            target="example.com",
        )

        report.add_finding(
            ReportFinding(
                title="Critical Issue",
                severity=ReportSeverity.CRITICAL,
                description="Critical",
            )
        )
        report.add_finding(
            ReportFinding(title="High Issue", severity=ReportSeverity.HIGH, description="High")
        )
        report.add_finding(
            ReportFinding(
                title="Medium Issue", severity=ReportSeverity.MEDIUM, description="Medium"
            )
        )
        report.add_finding(
            ReportFinding(title="Low Issue", severity=ReportSeverity.LOW, description="Low")
        )
        report.add_finding(
            ReportFinding(title="Info", severity=ReportSeverity.INFO, description="Info")
        )

        md_output = generator.generate_markdown(report)

        # Verify all severities appear
        assert "Critical Issue" in md_output
        assert "High Issue" in md_output
        assert "Medium Issue" in md_output
        assert "Low Issue" in md_output
        assert "Info" in md_output

    def test_report_with_scope_and_methodology(self):
        """Test report with scope and methodology."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="Comprehensive Report",
            target="example.com",
        )

        report.metadata.scope = ["example.com", "*.example.com"]
        report.metadata.methodology = ["Reconnaissance", "Scanning", "Exploitation"]

        md_output = generator.generate_markdown(report)

        assert "## Scope" in md_output
        assert "## Methodology" in md_output
        assert "example.com" in md_output
        assert "Reconnaissance" in md_output

    def test_report_with_executive_summary(self):
        """Test report with executive summary."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="Executive Summary Report",
            target="example.com",
        )

        report.metadata.executive_summary = (
            "This security assessment identified 3 critical vulnerabilities."
        )

        md_output = generator.generate_markdown(report)

        assert "## Executive Summary" in md_output
        assert "3 critical vulnerabilities" in md_output

    def test_report_risk_summary_in_output(self):
        """Test that risk summary appears in all formats."""
        generator = ReportGenerator()

        report = generator.create_report(
            title="Risk Summary Test",
            target="example.com",
        )

        report.add_finding(
            ReportFinding(title="Critical", severity=ReportSeverity.CRITICAL, description="Test")
        )
        report.add_finding(
            ReportFinding(title="High", severity=ReportSeverity.HIGH, description="Test")
        )

        # Test Markdown
        md_output = generator.generate_markdown(report)
        assert "Risk Summary" in md_output
        assert "Critical | 1" in md_output

        # Test HTML
        html_output = generator.generate_html(report)
        assert "Risk Summary" in html_output

        # Test Text
        text_output = generator.generate_text(report)
        assert "RISK SUMMARY" in text_output
