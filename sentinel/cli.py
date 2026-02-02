"""Sentinel CLI interface."""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from sentinel.bounty_pipeline import BountyPipeline
from sentinel.config import config
from sentinel.cvss_scorer import CVSSv40Scorer
from sentinel.evidence_manager import EvidenceStorage, EvidenceType
from sentinel.parsers import ParserFactory
from sentinel.sbom import SBOMGenerator
from sentinel.scanner import VulnerabilityScanner
from sentinel.talon_client import TalonClient
from sentinel.utils import SafeUrlError, canonicalize_and_validate_url
from talon.middleware import BOLAMiddleware, IdentityMapping

console = Console()


class ComplianceError(RuntimeError):
    """Raised when compliance gatekeeper checks fail."""


def _compliance_gatekeeper() -> None:
    """Validate safe-harbor requirements before executing operations."""
    header_env = os.getenv("HACKERONE_RESEARCH_HEADER", "").strip()
    if header_env and header_env != "[lucius-log]":
        raise ComplianceError("Invalid HACKERONE_RESEARCH_HEADER value")

    if config.scan.max_rps != 50:
        raise ComplianceError("max_rps must be hard-coded to 50")

    if not config.ssrf.safe_url_allowlist:
        raise ComplianceError("safe_url_allowlist must be configured")


class _AuditLedger:
    def __init__(self, mapping: IdentityMapping | None) -> None:
        self._mapping = mapping

    def get_mapping(self, legacy_user_id: str):
        if self._mapping and self._mapping.legacy_user_id == legacy_user_id:
            return self._mapping
        return None


class _AuditOwnershipStore:
    def __init__(self, object_id: str, tenant_id: str) -> None:
        self._object_id = object_id
        self._tenant_id = tenant_id

    def is_owned_by_tenant(self, object_id: str, tenant_id: str) -> bool:
        return object_id == self._object_id and tenant_id == self._tenant_id


class _AuditLogger:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def log(self, event: str, **fields):
        self.events.append({"event": event, **fields})


@click.group()
@click.version_option(version="1.0.0")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Sentinel - Dependency Vulnerability Scanner"""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    if verbose:
        config.log_level = "DEBUG"


@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--package-manager",
    "-p",
    type=click.Choice(["npm", "pip", "composer", "auto"]),
    default="auto",
    help="Package manager to scan",
)
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["json", "table", "cyclonedx", "spdx"]),
    default="table",
    help="Output format",
)
@click.option(
    "--severity",
    "-s",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="low",
    help="Minimum severity to report",
)
@click.option("--include-dev", is_flag=True, help="Include dev dependencies")
@click.option("--post-to-talon", is_flag=True, help="Post results to Talon API")
@click.pass_context
def scan(
    ctx: click.Context,
    path: str,
    package_manager: str,
    output: str | None,
    output_format: str,
    severity: str,
    include_dev: bool,
    post_to_talon: bool,
) -> None:
    """Scan a project for dependency vulnerabilities."""
    project_path = Path(path).resolve()

    console.print(f"\n[bold blue]🔍 Scanning project:[/] {project_path}\n")

    try:
        # Run the async scan
        result = asyncio.run(
            _run_scan(
                project_path=project_path,
                package_manager=package_manager,
                severity=severity,
                include_dev=include_dev,
                post_to_talon=post_to_talon,
            )
        )

        # Output results
        if output_format == "table":
            _display_table(result)
        elif output_format == "json":
            output_data = json.dumps(result, indent=2, default=str)
            if output:
                Path(output).write_text(output_data)
                console.print(f"[green]Results written to {output}[/]")
            else:
                console.print(output_data)
        elif output_format in ("cyclonedx", "spdx"):
            sbom_generator = SBOMGenerator()
            sbom_data = sbom_generator.generate(result, format=output_format)
            if output:
                Path(output).write_text(sbom_data)
                console.print(f"[green]SBOM written to {output}[/]")
            else:
                console.print(sbom_data)

        # Exit with error code if vulnerabilities found
        if result.get("vulnerable_count", 0) > 0:
            critical_high = result.get("critical_count", 0) + result.get("high_count", 0)
            if critical_high > 0:
                sys.exit(1)

    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        if ctx.obj.get("verbose"):
            console.print_exception()
        sys.exit(2)


async def _run_scan(
    project_path: Path,
    package_manager: str,
    severity: str,
    include_dev: bool,
    post_to_talon: bool,
) -> dict:
    """Run the vulnerability scan asynchronously."""
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        # Parse dependencies
        task = progress.add_task("Parsing dependencies...", total=None)
        parser = ParserFactory.create(package_manager, project_path)
        dependencies = await parser.parse(include_dev=include_dev)
        progress.update(task, description=f"Found {len(dependencies)} dependencies")

        # Scan for vulnerabilities
        progress.update(task, description="Scanning for vulnerabilities...")
        scanner = VulnerabilityScanner()
        result = await scanner.scan(
            project_name=project_path.name,
            dependencies=dependencies,
            severity_threshold=severity,
        )
        progress.update(task, description="Scan complete!")

        # Post to Talon if requested
        if post_to_talon:
            progress.update(task, description="Posting results to Talon...")
            talon_client = TalonClient()
            await talon_client.post_scan_result(result)
            progress.update(task, description="Results posted to Talon!")

    return result


def _display_table(result: dict) -> None:
    """Display scan results as a formatted table."""
    # Summary
    console.print("\n[bold]📊 Scan Summary[/]")
    summary_table = Table(show_header=False, box=None)
    summary_table.add_column("Metric", style="cyan")
    summary_table.add_column("Value", style="white")

    summary_table.add_row("Project", result.get("project_name", "Unknown"))
    summary_table.add_row("Package Manager", result.get("package_manager", "Unknown"))
    summary_table.add_row("Total Dependencies", str(result.get("total_dependencies", 0)))
    summary_table.add_row("Vulnerable Packages", str(result.get("vulnerable_count", 0)))

    console.print(summary_table)

    # Severity breakdown
    console.print("\n[bold]⚠️  Severity Breakdown[/]")
    severity_table = Table(show_header=True)
    severity_table.add_column("Severity", style="bold")
    severity_table.add_column("Count", justify="right")

    severities = [
        ("Critical", result.get("critical_count", 0), "red"),
        ("High", result.get("high_count", 0), "orange1"),
        ("Medium", result.get("medium_count", 0), "yellow"),
        ("Low", result.get("low_count", 0), "blue"),
    ]

    for sev_name, count, color in severities:
        severity_table.add_row(f"[{color}]{sev_name}[/]", str(count))

    console.print(severity_table)

    # Vulnerabilities list
    vulnerabilities = result.get("vulnerabilities", [])
    if vulnerabilities:
        console.print("\n[bold]🔒 Vulnerabilities Found[/]")
        vuln_table = Table(show_header=True)
        vuln_table.add_column("CVE ID", style="cyan")
        vuln_table.add_column("Package")
        vuln_table.add_column("Version")
        vuln_table.add_column("Severity")
        vuln_table.add_column("CVSS")
        vuln_table.add_column("Fixed In")

        severity_colors = {
            "CRITICAL": "red",
            "HIGH": "orange1",
            "MEDIUM": "yellow",
            "LOW": "blue",
        }

        for vuln in vulnerabilities[:20]:  # Limit display
            severity = vuln.get("severity", "UNKNOWN")
            color = severity_colors.get(severity, "white")
            vuln_table.add_row(
                vuln.get("cve_id", "N/A"),
                vuln.get("package_name", "N/A"),
                vuln.get("installed_version", "N/A"),
                f"[{color}]{severity}[/]",
                str(vuln.get("cvss_score", "N/A")),
                vuln.get("fixed_version", "N/A"),
            )

        console.print(vuln_table)

        if len(vulnerabilities) > 20:
            console.print(f"\n[dim]... and {len(vulnerabilities) - 20} more vulnerabilities[/]")
    else:
        console.print("\n[bold green]✅ No vulnerabilities found![/]")


@cli.command()
@click.argument("path", type=click.Path(exists=True), default=".")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["cyclonedx", "spdx"]),
    default="cyclonedx",
    help="SBOM format",
)
@click.option("--output", "-o", type=click.Path(), required=True, help="Output file path")
@click.pass_context
def sbom(ctx: click.Context, path: str, output_format: str, output: str) -> None:
    """Generate a Software Bill of Materials (SBOM)."""
    project_path = Path(path).resolve()

    console.print(f"\n[bold blue]📦 Generating SBOM for:[/] {project_path}\n")

    try:
        result = asyncio.run(_generate_sbom(project_path, output_format))
        Path(output).write_text(result)
        console.print(f"[bold green]✅ SBOM generated:[/] {output}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        if ctx.obj.get("verbose"):
            console.print_exception()
        sys.exit(2)


async def _generate_sbom(project_path: Path, output_format: str) -> str:
    """Generate SBOM asynchronously."""
    parser = ParserFactory.create("auto", project_path)
    dependencies = await parser.parse(include_dev=True)

    sbom_generator = SBOMGenerator()
    return sbom_generator.generate(
        {
            "project_name": project_path.name,
            "dependencies": [dep.to_dict() for dep in dependencies],
        },
        format=output_format,
    )


@cli.command()
@click.option("--cve", "-c", required=True, help="CVE ID to lookup")
@click.pass_context
def lookup(ctx: click.Context, cve: str) -> None:
    """Lookup details for a specific CVE."""

    console.print(f"\n[bold blue]🔍 Looking up:[/] {cve}\n")

    try:
        result = asyncio.run(_lookup_cve(cve))
        if result:
            console.print(json.dumps(result, indent=2, default=str))
        else:
            console.print(f"[yellow]CVE {cve} not found[/]")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        if ctx.obj.get("verbose"):
            console.print_exception()
        sys.exit(2)


@cli.command(name="verified-audit")
@click.option(
    "--output",
    type=click.Path(),
    default="./bounty_workspace/verified_findings.json",
    help="Output file for self-test findings",
)
@click.pass_context
def verified_audit(ctx: click.Context, output: str) -> None:
    """Run defensive self-tests for BOLA and SSRF gates.

    This command does not perform external scans.
    """
    console.print("\n[bold blue]🧪 Running defensive self-tests[/]\n")

    findings: list[dict] = []

    try:
        _compliance_gatekeeper()
    except ComplianceError as e:
        console.print(f"[bold red]ComplianceError:[/] {e}")
        sys.exit(2)

    # --- BOLA gate self-test ---
    audit = _AuditLogger()
    mapping = IdentityMapping(
        legacy_user_id="legacy-1",
        gs_global_tenant_id="tenant-1",
        status="active",
    )
    ledger = _AuditLedger(mapping)
    ownership = _AuditOwnershipStore(object_id="obj-1", tenant_id="tenant-1")
    bola_gate = BOLAMiddleware(ledger, ownership, audit)

    class _Request:
        def __init__(self, context: dict):
            self.context = context
            self.id = "audit-request"

    try:
        bola_gate(
            _Request({"legacy_nn_ip_user_id": "legacy-1", "gs_global_tenant_id": "tenant-1"}),
            "obj-1",
        )
    except Exception as e:
        findings.append({"check": "bola_allow", "status": "fail", "error": str(e)})

    try:
        bola_gate(
            _Request({"legacy_nn_ip_user_id": "legacy-1", "gs_global_tenant_id": "tenant-2"}),
            "obj-1",
        )
        findings.append(
            {"check": "bola_block_mismatch", "status": "fail", "error": "mismatch allowed"}
        )
    except PermissionError:
        pass

    # --- SSRF gate self-test ---
    allowlist = {"example.com": ["93.184.216.34"]}
    try:
        canonicalize_and_validate_url("https://example.com/", allowed_hosts=allowlist)
    except SafeUrlError as e:
        findings.append({"check": "ssrf_allow", "status": "fail", "error": str(e)})

    try:
        canonicalize_and_validate_url(
            "http://169.254.169.254/latest/meta-data",
            allowed_hosts=allowlist,
        )
        findings.append(
            {"check": "ssrf_block_metadata", "status": "fail", "error": "metadata allowed"}
        )
    except SafeUrlError:
        pass

    # --- Compliance checks ---
    if config.scan.max_rps > 50:
        findings.append(
            {
                "check": "rate_limit",
                "status": "fail",
                "error": f"max_rps={config.scan.max_rps} exceeds 50",
            }
        )

    if not config.ssrf.safe_url_allowlist:
        findings.append(
            {
                "check": "safe_url_allowlist",
                "status": "fail",
                "error": "safe_url_allowlist not configured",
            }
        )

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "status": "pass" if not findings else "fail",
        "findings": findings,
        "note": "External scans are disabled in verified-audit.",
    }
    output_path.write_text(json.dumps(output_payload, indent=2))

    if findings:
        console.print("[bold red]Self-test failed. See findings export.[/]")
        console.print(f"[dim]Output: {output_path}[/]")
        sys.exit(2)

    console.print("[bold green]✅ Self-tests passed. No external scans executed.[/]")
    console.print(f"[dim]Output: {output_path}[/]")


@cli.command(name="verified-dry-run")
@click.option(
    "--workspace",
    type=click.Path(),
    default="./bounty_workspace",
    help="Workspace directory for artifacts",
)
@click.option(
    "--output",
    type=click.Path(),
    default="./bounty_workspace/verified_findings.json",
    help="Output file for dry-run findings",
)
@click.pass_context
def verified_dry_run(ctx: click.Context, workspace: str, output: str) -> None:
    """Run a controlled dry-run of the full scan lifecycle with local mock data."""
    console.print("\n[bold blue]🧪 Running verified dry-run (no external requests)[/]\n")

    # Compliance checks
    if config.scan.max_rps > 50:
        console.print(f"[bold red]Invalid config:[/] max_rps={config.scan.max_rps} exceeds 50")
        sys.exit(2)

    if not config.ssrf.safe_url_allowlist:
        console.print("[bold red]Invalid config:[/] safe_url_allowlist not configured")
        sys.exit(2)

    workspace_path = Path(workspace)
    workspace_path.mkdir(parents=True, exist_ok=True)

    # Simulated lifecycle data
    mock_target = "https://local.mock"
    mock_endpoint = f"{mock_target}/api/v1/accounts/123"
    mock_request = (
        "GET /api/v1/accounts/123?export=summary HTTP/1.1\n"
        "Host: local.mock\n"
        "X-HackerOne-Research: [lucius-log]\n"
        "User-Agent: Lucius-Dry-Run\n"
    )
    mock_response = (
        "HTTP/1.1 200 OK\n"
        "Content-Type: application/json\n\n"
        '{"account":"123","email":"user@example.com","ip":"192.168.1.10"}'
    )

    # Evidence processing
    evidence_storage = EvidenceStorage(workspace_path / "evidence")
    request_evidence = evidence_storage.store_evidence(
        content=mock_request.encode("utf-8"),
        evidence_type=EvidenceType.HTTP_REQUEST,
        created_by="lucius_dry_run",
        description="Dry-run request evidence",
        tags=["dry-run", "request"],
    )
    response_evidence = evidence_storage.store_evidence(
        content=mock_response.encode("utf-8"),
        evidence_type=EvidenceType.HTTP_RESPONSE,
        created_by="lucius_dry_run",
        description="Dry-run response evidence (contains PII for redaction test)",
        tags=["dry-run", "response"],
    )

    redacted_response = evidence_storage.redact_evidence_pii(
        response_evidence.metadata.evidence_id,
        user="lucius_dry_run",
    )

    # CVSS 4.0 mock scoring (critical)
    cvss = CVSSv40Scorer.calculate(
        attack_vector="N",
        attack_complexity="L",
        privileges_required="N",
        user_interaction="N",
        scope="U",
        confidentiality="H",
        integrity="H",
        availability="H",
    )

    verification_curl = (
        "curl -s -X GET "
        "-H 'X-HackerOne-Research: [lucius-log]' "
        f"'{mock_endpoint}?export=summary'"
    )

    verified_findings = {
        "mode": "dry-run",
        "target": mock_target,
        "timestamp": datetime.utcnow().isoformat(),
        "compliance": {
            "max_rps": config.scan.max_rps,
            "header_required": "X-HackerOne-Research: [lucius-log]",
            "safe_url_allowlist": list(config.ssrf.safe_url_allowlist.keys()),
        },
        "findings": [
            {
                "title": "Dry-Run: Authorization Logic Gate Validation",
                "severity": "critical",
                "description": "Simulated finding to validate reporting pipeline.",
                "cvss": cvss.to_dict(),
                "compliance_risk": {
                    "regulatory_mapping": [
                        {
                            "finding_type": "BOLA",
                            "framework": "GDPR",
                            "control": "Article 32 - Security of Processing",
                        },
                        {
                            "finding_type": "SSRF",
                            "framework": "SFDR",
                            "control": "Data integrity safeguards",
                        },
                    ]
                },
                "reproduction_steps": [
                    "Send a request with a valid tenant context",
                    "Verify object ownership validation is enforced",
                ],
                "remediation": {
                    "hotfix_immediate": (
                        "Enforce strict legacy-to-tenant mapping and deny on mismatch; "
                        "apply header-based origin validation for doc fetchers."
                    ),
                    "architecture_strategic": (
                        "Adopt Talon Identity Bridge enforcement and Sentinel DNS pinning "
                        "with canonical URL validation across all doc endpoints."
                    ),
                },
                "verification_payload": {
                    "curl": verification_curl,
                },
                "evidence": [
                    {
                        "type": "http_request",
                        "evidence_id": request_evidence.metadata.evidence_id,
                        "encrypted": request_evidence.metadata.encryption_status.value,
                    },
                    {
                        "type": "http_response",
                        "evidence_id": (
                            redacted_response.metadata.evidence_id
                            if redacted_response
                            else response_evidence.metadata.evidence_id
                        ),
                        "redacted": bool(redacted_response),
                    },
                ],
            }
        ],
    }

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(verified_findings, indent=2))

    console.print("[bold green]✅ Dry-run complete (no external traffic).[/]")
    console.print(f"[dim]Evidence path: {workspace_path / 'evidence'}[/]")
    console.print(f"[dim]Findings: {output_path}[/]")


@cli.command(name="export-report")
@click.option(
    "--input",
    "input_path",
    type=click.Path(exists=True),
    default="./bounty_workspace/verified_findings.json",
    help="Path to verified findings JSON",
)
@click.option(
    "--output",
    "output_path",
    type=click.Path(),
    default="./bounty_workspace/verified_findings.md",
    help="Output Markdown report path",
)
@click.pass_context
def export_report(ctx: click.Context, input_path: str, output_path: str) -> None:
    """Generate a high-fidelity Markdown report from verified findings JSON."""
    payload = json.loads(Path(input_path).read_text())
    findings = payload.get("findings", [])

    evidence_dir = Path("./bounty_workspace/evidence")
    evidence_storage = EvidenceStorage(evidence_dir) if evidence_dir.exists() else None

    lines: list[str] = []
    lines.append("# Lucius Verified Findings Report")
    lines.append("")
    lines.append(f"**Mode:** {payload.get('mode', 'unknown')}")
    lines.append(f"**Target:** {payload.get('target', 'unknown')}")
    lines.append(f"**Timestamp:** {payload.get('timestamp', 'unknown')}")
    lines.append("")
    lines.append("## Compliance")
    compliance = payload.get("compliance", {})
    lines.append(f"- **Max RPS:** {compliance.get('max_rps', 'unknown')}")
    lines.append(f"- **Header Required:** {compliance.get('header_required', 'unknown')}")
    lines.append(f"- **Safe URL Allowlist:** {', '.join(compliance.get('safe_url_allowlist', []))}")
    lines.append("")

    for idx, finding in enumerate(findings, start=1):
        lines.append(f"## Finding {idx}: {finding.get('title', 'Untitled')}")
        lines.append("")
        lines.append(f"**Severity:** {finding.get('severity', 'unknown')}")
        lines.append(f"**Description:** {finding.get('description', '')}")
        lines.append("")

        cvss = finding.get("cvss", {})
        lines.append("### CVSS 4.0")
        lines.append(f"- **Vector:** {cvss.get('vector', 'unknown')}")
        lines.append(f"- **Score:** {cvss.get('score', 'unknown')}")
        lines.append(f"- **Severity:** {cvss.get('severity', 'unknown')}")
        lines.append("")

        compliance_risk = finding.get("compliance_risk", {})
        lines.append("### Regulatory Impact Mapping")
        for entry in compliance_risk.get("regulatory_mapping", []):
            lines.append(f"- **{entry.get('framework', 'unknown')}**: {entry.get('control', '')}")
        lines.append("")

        lines.append("### Reproduction Steps")
        for step in finding.get("reproduction_steps", []):
            lines.append(f"1. {step}")
        lines.append("")

        remediation = finding.get("remediation", {})
        lines.append("### Remediation")
        lines.append(f"- **Hotfix (Immediate):** {remediation.get('hotfix_immediate', '')}")
        lines.append(
            f"- **Architecture (Strategic):** {remediation.get('architecture_strategic', '')}"
        )
        lines.append("")

        verification = finding.get("verification_payload", {})
        if verification.get("curl"):
            lines.append("### One-Click Verification")
            lines.append(f"`{verification.get('curl')}`")
            lines.append("")

        lines.append("### Evidence Chain")
        for evidence in finding.get("evidence", []):
            lines.append(
                "- "
                + ", ".join(
                    f"{key}: {value}" for key, value in evidence.items() if value is not None
                )
            )
            if evidence_storage and evidence.get("evidence_id"):
                stored = evidence_storage.retrieve_evidence(
                    evidence["evidence_id"], accessed_by="lucius_report"
                )
                if stored:
                    content = stored.get_content_string()
                    snippet = content[:280].replace("\n", " ")
                    lines.append(f"  - Redacted Snippet: {snippet}")
                    lines.append(
                        f"  - Encryption Status: {stored.metadata.encryption_status.value}"
                    )
        lines.append("")

    Path(output_path).write_text("\n".join(lines))
    console.print(f"[bold green]✅ Report exported:[/] {output_path}")


async def _lookup_cve(cve_id: str) -> dict | None:
    """Lookup a CVE from NVD."""
    from sentinel.nvd_client import NVDClient

    async with NVDClient() as client:
        return await client.get_cve_async(cve_id)


@click.group(name="bounty")
def bounty() -> None:
    """Bug bounty automation pipeline commands."""
    pass


@bounty.command(name="scan")
@click.argument("target", type=str, required=True)
@click.option(
    "--workspace",
    type=click.Path(),
    default="./bounty_workspace",
    help="Workspace directory for pipeline artifacts",
)
@click.option(
    "--deep",
    is_flag=True,
    default=False,
    help="Enable deep scanning with real network requests (not mocked)",
)
@click.option(
    "--timeout",
    type=int,
    default=5,
    help="Network request timeout in seconds (for deep scans)",
)
@click.pass_context
def bounty_scan(ctx: click.Context, target: str, workspace: str, deep: bool, timeout: int) -> None:
    """Run automated bug bounty scan on a target.

    TARGET: The target URL or domain to scan (e.g., https://example.com)
    """
    console.print(f"\n[bold blue]🎯 Starting bounty pipeline for:[/] {target}\n")
    console.print(f"[dim]Workspace: {workspace}[/]")
    if deep:
        console.print(f"[dim]Deep Scan: Enabled | Timeout: {timeout}s[/]\n")
    else:
        console.print("[dim]Mode: Lightweight (mocked)[/]\n")

    try:
        # Initialize pipeline
        pipeline = BountyPipeline(workspace_dir=workspace)

        # Run the async pipeline with deep scan options
        result = asyncio.run(pipeline.run_target(target, deep_scan=deep, timeout=timeout))

        # Display summary
        console.print("\n[bold green]✅ Pipeline completed![/]\n")
        console.print("[bold]📊 Summary:[/]")

        summary_table = Table(show_header=False, box=None)
        summary_table.add_column("Metric", style="cyan")
        summary_table.add_column("Value", style="white")

        summary_table.add_row("Target", result.target)
        summary_table.add_row("Subdomains Found", str(result.subdomains_found))
        summary_table.add_row("Technologies Detected", str(result.technologies_detected))
        summary_table.add_row("API Endpoints Discovered", str(result.endpoints_discovered))
        summary_table.add_row("Vulnerabilities Found", str(result.vulnerabilities_found))
        summary_table.add_row("Evidence Items Collected", str(result.evidence_items))

        console.print(summary_table)

        if result.reports_generated:
            console.print("\n[bold]📄 Reports Generated:[/]")
            for report_path in result.reports_generated:
                console.print(f"  • {report_path}")

        console.print(f"\n[dim]Scan completed at: {result.scan_end_time}[/]")
        console.print(f"[dim]Duration: {result.duration_seconds:.2f} seconds[/]\n")

    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")
        if ctx.obj.get("verbose"):
            console.print_exception()
        sys.exit(2)


@cli.command(name="bridge-audit")
@click.option(
    "--output",
    type=click.Path(),
    default="./bounty_workspace/final_verification_payloads.txt",
    help="Output file for verification payloads",
)
@click.pass_context
def bridge_audit(ctx: click.Context, output: str) -> None:
    """Prepare audit-ready payloads without executing external requests."""
    try:
        _compliance_gatekeeper()
    except ComplianceError as e:
        console.print(f"[bold red]ComplianceError:[/] {e}")
        sys.exit(2)

    allowlist = config.ssrf.safe_url_allowlist
    header = "X-HackerOne-Research: [lucius-log]"

    lines = [
        "Lucius Bridge Audit Payloads (No External Requests)",
        f"Max RPS: {config.scan.max_rps}",
        f"Header: {header}",
        "",
    ]

    for host in allowlist.keys():
        url = f"https://{host}/"  # placeholder safe URL
        curl = f"curl -s -H '{header}' '{url}'"
        lines.append(f"Host: {host}")
        lines.append(f"Payload: {curl}")
        lines.append("")

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines))

    console.print("[bold green]✅ Bridge audit payloads prepared (no external requests).[/]")
    console.print(f"[dim]Output: {output_path}[/]")


# Register bounty group with main CLI
cli.add_command(bounty)


def main() -> None:
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
