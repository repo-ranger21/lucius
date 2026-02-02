"""Operations CLI interface."""

import sys
from datetime import datetime
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from operations.database import get_session, init_db
from operations.models import Grant
from operations.services.data_cleaner import DataCleaner
from operations.services.deadline_monitor import DeadlineMonitor
from operations.services.grant_service import GrantService

console = Console()


@click.group()
@click.version_option(version="1.0.0")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx: click.Context, verbose: bool) -> None:
    """Operations - Grant & Data Management CLI"""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


# Grant commands
@cli.group()
def grants() -> None:
    """Grant management commands."""
    pass


def _format_deadline(grant: Grant) -> str:
    if grant.submission_deadline:
        return grant.submission_deadline.strftime("%Y-%m-%d")
    return "N/A"


def _format_days_left(grant: Grant) -> str:
    days_left = grant.days_until_deadline
    if days_left is None:
        return "N/A"
    if days_left < 0:
        return f"[red]{days_left} (overdue)[/]"
    if days_left <= 7:
        return f"[red]{days_left}[/]"
    if days_left <= 30:
        return f"[yellow]{days_left}[/]"
    return str(days_left)


@grants.command("list")
@click.option("--status", "-s", help="Filter by status")
@click.option("--priority", "-p", help="Filter by priority")
@click.option(
    "--upcoming",
    is_flag=True,
    help="Show grants with upcoming deadlines",
)
@click.pass_context
def list_grants(
    ctx: click.Context,
    status: str | None,
    priority: str | None,
    upcoming: bool,
):
    """List all grants."""
    with get_session() as session:
        service = GrantService(session)

        if upcoming:
            grants_list = service.get_upcoming_deadlines(days=30)
        else:
            grants_list = service.list_grants(status=status, priority=priority)

        if not grants_list:
            console.print("[yellow]No grants found[/]")
            return

        table = Table(title="Grants")
        table.add_column("Name", style="cyan", max_width=40)
        table.add_column("Funder", style="white")
        table.add_column("Amount", justify="right")
        table.add_column("Status", style="bold")
        table.add_column("Deadline")
        table.add_column("Days Left", justify="right")

        for grant in grants_list:
            deadline_str = _format_deadline(grant)
            days_str = _format_days_left(grant)
            amount_str = f"${grant.amount:,.2f}" if grant.amount else "N/A"

            table.add_row(
                grant.grant_name[:40],
                grant.funder,
                amount_str,
                grant.status,
                deadline_str,
                days_str,
            )

        console.print(table)


@grants.command("create")
@click.option("--name", "-n", required=True, help="Grant name")
@click.option("--funder", "-f", required=True, help="Funder name")
@click.option("--amount", "-a", type=float, help="Grant amount")
@click.option("--deadline", "-d", help="Submission deadline (YYYY-MM-DD)")
@click.option(
    "--priority",
    "-p",
    type=click.Choice(["low", "medium", "high", "critical"]),
    default="medium",
)
@click.pass_context
def create_grant(
    ctx: click.Context,
    name: str,
    funder: str,
    amount: float | None,
    deadline: str | None,
    priority: str,
):
    """Create a new grant."""
    deadline_dt = None
    if deadline:
        try:
            deadline_dt = datetime.strptime(deadline, "%Y-%m-%d")
        except ValueError:
            console.print("[red]Invalid date format. Use YYYY-MM-DD[/]")
            sys.exit(1)

    with get_session() as session:
        service = GrantService(session)
        grant = service.create_grant(
            grant_name=name,
            funder=funder,
            amount=amount,
            submission_deadline=deadline_dt,
            priority=priority,
        )
        console.print(f"[green]✓ Created grant:[/] {grant.grant_name} (ID: {grant.id})")


@grants.command("update")
@click.argument("grant_id")
@click.option(
    "--status",
    "-s",
    type=click.Choice(Grant.STATUSES),
    help="New status",
)
@click.option(
    "--priority",
    "-p",
    type=click.Choice(Grant.PRIORITIES),
    help="New priority",
)
@click.pass_context
def update_grant(
    ctx: click.Context,
    grant_id: str,
    status: str | None,
    priority: str | None,
):
    """Update a grant."""
    with get_session() as session:
        service = GrantService(session)
        grant = service.update_grant(
            grant_id,
            status=status,
            priority=priority,
        )

        if grant:
            console.print(f"[green]✓ Updated grant:[/] {grant.grant_name}")
        else:
            console.print(f"[red]Grant not found: {grant_id}[/]")
            sys.exit(1)


# Deadline monitoring commands
@cli.group()
def deadlines() -> None:
    """Deadline monitoring commands."""
    pass


def _urgency_icon(days_left: int) -> str:
    if days_left <= 3:
        return "🔴"
    if days_left <= 7:
        return "🟡"
    return "🟢"


@deadlines.command("check")
@click.option("--days", "-d", type=int, default=7, help="Days to look ahead")
@click.option(
    "--send-reminders",
    is_flag=True,
    help="Send SMS reminders",
)
@click.pass_context
def check_deadlines(ctx: click.Context, days: int, send_reminders: bool):
    """Check for upcoming deadlines."""
    with get_session() as session:
        monitor = DeadlineMonitor(session)
        upcoming = monitor.get_upcoming_deadlines(days=days)

        if not upcoming:
            console.print(f"[green]No deadlines in the next {days} days[/]")
            return

        console.print(f"\n[bold]⏰ Upcoming Deadlines ({days} days)[/]\n")

        for grant, days_left in upcoming:
            urgency = _urgency_icon(days_left)
            message = f"{urgency} {grant.grant_name} - " f"{days_left} days ({grant.funder})"
            console.print(message)

        if send_reminders:
            sent = monitor.send_deadline_reminders()
            console.print(f"\n[green]Sent {sent} reminder(s)[/]")


@deadlines.command("start-monitor")
@click.option(
    "--interval",
    "-i",
    type=int,
    default=3600,
    help="Check interval in seconds",
)
@click.pass_context
def start_monitor(ctx: click.Context, interval: int):
    """Start deadline monitoring daemon."""
    console.print(f"[bold]Starting deadline monitor (interval: {interval}s)[/]")

    with get_session() as session:
        monitor = DeadlineMonitor(session)
        monitor.start_monitoring(interval=interval)


# Data cleaning commands
@cli.group()
def data() -> None:
    """Data cleaning commands."""
    pass


@data.command("clean")
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["csv", "json", "excel"]),
    default="csv",
)
@click.pass_context
def clean_data(
    ctx: click.Context,
    input_file: str,
    output: str | None,
    output_format: str,
):
    """Clean nonprofit data from file."""
    input_path = Path(input_file)
    output_path = Path(output) if output else input_path.with_suffix(f".cleaned.{output_format}")

    console.print(f"[bold]Cleaning data from:[/] {input_path}")

    cleaner = DataCleaner()

    try:
        result = cleaner.clean_file(input_path, output_path, output_format)

        console.print(f"\n[green]✓ Cleaned {result['total_records']} records[/]")
        console.print(f"  - Valid: {result['valid_records']}")
        console.print(f"  - Invalid: {result['invalid_records']}")
        console.print(f"  - Output: {output_path}")

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        if ctx.obj.get("verbose"):
            console.print_exception()
        sys.exit(1)


@data.command("import")
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--clean", is_flag=True, help="Clean data before importing")
@click.pass_context
def import_data(ctx: click.Context, input_file: str, clean: bool):
    """Import nonprofit data into database."""
    input_path = Path(input_file)

    console.print(f"[bold]Importing data from:[/] {input_path}")

    cleaner = DataCleaner()

    with get_session() as session:
        try:
            result = cleaner.import_to_database(
                session,
                input_path,
                clean_first=clean,
            )

            console.print(f"\n[green]✓ Imported {result['imported']} records[/]")
            console.print(f"  - Updated: {result['updated']}")
            console.print(f"  - Skipped: {result['skipped']}")

        except Exception as e:
            console.print(f"[red]Error: {e}[/]")
            if ctx.obj.get("verbose"):
                console.print_exception()
            sys.exit(1)


@data.command("validate")
@click.argument("input_file", type=click.Path(exists=True))
@click.pass_context
def validate_data(ctx: click.Context, input_file: str):
    """Validate nonprofit data file."""
    input_path = Path(input_file)

    console.print(f"[bold]Validating data:[/] {input_path}")

    cleaner = DataCleaner()

    try:
        result = cleaner.validate_file(input_path)

        console.print("\n[bold]Validation Results[/]")
        console.print(f"  Total records: {result['total']}")
        console.print(f"  Valid: [green]{result['valid']}[/]")
        console.print(f"  Invalid: [red]{result['invalid']}[/]")
        console.print(f"  Quality score: {result['quality_score']:.1f}%")

        if result["issues"]:
            console.print("\n[yellow]Issues found:[/]")
            for issue in result["issues"][:10]:
                console.print(f"  - {issue}")

            if len(result["issues"]) > 10:
                console.print(f"  ... and {len(result['issues']) - 10} more")

    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
        sys.exit(1)


# Database commands
@cli.command("init-db")
@click.pass_context
def initialize_db(ctx: click.Context):
    """Initialize database tables."""
    console.print("Initializing database...")
    init_db()
    console.print("[green]✓ Database initialized[/]")


@cli.command("scan-domain")
@click.option(
    "--mode",
    type=click.Choice(["ghost-subdomain"]),
    help="Mode of operation.",
)
def scan_domain(mode: str | None) -> None:
    if mode == "ghost-subdomain":
        # Logic to cross-reference historical DNS records for nnip.com
        # Specifically for the years 2015 and 2024
        # Use waybackurls logic to find lost endpoints
        print("Scanning for ghost subdomains...")
        # Implement the scanning logic here


def main() -> None:
    """Main entry point."""
    cli(obj={})


if __name__ == "__main__":
    main()
