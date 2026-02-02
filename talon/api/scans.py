"""Scans API endpoints."""

from typing import Any
from uuid import UUID

from flask import request
from flask_restx import Namespace, Resource, fields

from shared.logging import get_logger
from talon.extensions import db
from talon.models import ScanResult
from talon.services.scan_service import ScanService

logger = get_logger(__name__)

scans_ns = Namespace("scans", description="Vulnerability scan operations")

# API Models
vulnerability_model = scans_ns.model(
    "Vulnerability",
    {
        "cve_id": fields.String(required=True, description="CVE identifier"),
        "package_name": fields.String(required=True, description="Affected package name"),
        "installed_version": fields.String(description="Installed version"),
        "severity": fields.String(description="Severity level"),
        "cvss_score": fields.Float(description="CVSS score"),
        "description": fields.String(description="Vulnerability description"),
        "fixed_version": fields.String(description="Version with fix"),
    },
)

scan_input_model = scans_ns.model(
    "ScanInput",
    {
        "project_name": fields.String(required=True, description="Project name"),
        "package_manager": fields.String(
            required=True, description="Package manager (npm, pip, composer)"
        ),
        "scan_type": fields.String(description="Scan type", default="dependency"),
        "total_dependencies": fields.Integer(description="Total dependencies scanned"),
        "vulnerable_count": fields.Integer(description="Number of vulnerable packages"),
        "critical_count": fields.Integer(description="Critical severity count"),
        "high_count": fields.Integer(description="High severity count"),
        "medium_count": fields.Integer(description="Medium severity count"),
        "low_count": fields.Integer(description="Low severity count"),
        "vulnerabilities": fields.List(fields.Nested(vulnerability_model)),
        "scan_metadata": fields.Raw(description="Additional scan metadata"),
    },
)

scan_output_model = scans_ns.model(
    "ScanOutput",
    {
        "id": fields.String(description="Scan ID"),
        "project_name": fields.String(description="Project name"),
        "package_manager": fields.String(description="Package manager"),
        "scan_type": fields.String(description="Scan type"),
        "total_dependencies": fields.Integer(description="Total dependencies"),
        "vulnerable_count": fields.Integer(description="Vulnerable count"),
        "critical_count": fields.Integer(description="Critical count"),
        "high_count": fields.Integer(description="High count"),
        "medium_count": fields.Integer(description="Medium count"),
        "low_count": fields.Integer(description="Low count"),
        "status": fields.String(description="Scan status"),
        "created_at": fields.DateTime(description="Creation timestamp"),
        "completed_at": fields.DateTime(description="Completion timestamp"),
    },
)


@scans_ns.route("/")
class ScanList(Resource):
    """Scan collection resource."""

    @scans_ns.doc("list_scans")
    @scans_ns.param("project", "Filter by project name")
    @scans_ns.param("status", "Filter by status")
    @scans_ns.param("limit", "Maximum results to return", type=int, default=50)
    @scans_ns.param("offset", "Result offset for pagination", type=int, default=0)
    @scans_ns.marshal_list_with(scan_output_model)
    def get(self) -> list[dict[str, Any]]:
        """List all scans with optional filtering."""
        project = request.args.get("project")
        status = request.args.get("status")
        limit = request.args.get("limit", 50, type=int)
        offset = request.args.get("offset", 0, type=int)

        query = ScanResult.query

        if project:
            query = query.filter(ScanResult.project_name.ilike(f"%{project}%"))
        if status:
            query = query.filter(ScanResult.status == status)

        query = query.order_by(ScanResult.created_at.desc())
        scans = query.offset(offset).limit(limit).all()

        return [scan.to_dict() for scan in scans]

    @scans_ns.doc("create_scan")
    @scans_ns.expect(scan_input_model)
    @scans_ns.marshal_with(scan_output_model, code=201)
    def post(self) -> tuple[dict[str, Any], int]:
        """Create a new scan result."""
        data = request.json

        if "package_manager" not in data:
            ecosystems = {
                dep.get("ecosystem")
                for dep in data.get("dependencies", [])
                if isinstance(dep, dict)
            }
            data["package_manager"] = ecosystems.pop() if len(ecosystems) == 1 else "unknown"

        if "total_dependencies" not in data:
            data["total_dependencies"] = len(data.get("dependencies", []))

        logger.info(f"Received scan result for project: {data.get('project_name')}")

        scan_service = ScanService()
        scan = scan_service.create_scan(data)

        return scan.to_dict(), 201


@scans_ns.route("/<string:scan_id>")
@scans_ns.param("scan_id", "Scan identifier")
class ScanResource(Resource):
    """Single scan resource."""

    @scans_ns.doc("get_scan")
    @scans_ns.marshal_with(scan_output_model)
    def get(self, scan_id: str) -> dict[str, Any]:
        """Get scan details by ID."""
        try:
            uuid_id = UUID(scan_id)
        except ValueError:
            scans_ns.abort(400, "Invalid scan ID format")

        scan = ScanResult.query.get(uuid_id)
        if not scan:
            scans_ns.abort(404, "Scan not found")

        return scan.to_dict(include_vulnerabilities=True)

    @scans_ns.doc("delete_scan")
    @scans_ns.response(204, "Scan deleted")
    def delete(self, scan_id: str) -> tuple[str, int]:
        """Delete a scan result."""
        try:
            uuid_id = UUID(scan_id)
        except ValueError:
            scans_ns.abort(400, "Invalid scan ID format")

        scan = ScanResult.query.get(uuid_id)
        if not scan:
            scans_ns.abort(404, "Scan not found")

        db.session.delete(scan)
        db.session.commit()

        logger.info(f"Deleted scan: {scan_id}")
        return "", 204


@scans_ns.route("/<string:scan_id>/vulnerabilities")
@scans_ns.param("scan_id", "Scan identifier")
class ScanVulnerabilities(Resource):
    """Scan vulnerabilities resource."""

    @scans_ns.doc("get_scan_vulnerabilities")
    def get(self, scan_id: str) -> list[dict[str, Any]]:
        """Get vulnerabilities for a specific scan."""
        try:
            uuid_id = UUID(scan_id)
        except ValueError:
            scans_ns.abort(400, "Invalid scan ID format")

        scan = ScanResult.query.get(uuid_id)
        if not scan:
            scans_ns.abort(404, "Scan not found")

        return [sv.to_dict() for sv in scan.vulnerabilities]


@scans_ns.route("/stats")
class ScanStats(Resource):
    """Scan statistics resource."""

    @scans_ns.doc("get_scan_stats")
    def get(self) -> dict[str, Any]:
        """Get overall scan statistics."""
        from sqlalchemy import func

        total_scans = ScanResult.query.count()

        severity_stats = db.session.query(
            func.sum(ScanResult.critical_count).label("critical"),
            func.sum(ScanResult.high_count).label("high"),
            func.sum(ScanResult.medium_count).label("medium"),
            func.sum(ScanResult.low_count).label("low"),
        ).first()

        recent_scans = ScanResult.query.order_by(ScanResult.created_at.desc()).limit(5).all()

        return {
            "total_scans": total_scans,
            "total_vulnerabilities": {
                "critical": int(severity_stats.critical or 0),
                "high": int(severity_stats.high or 0),
                "medium": int(severity_stats.medium or 0),
                "low": int(severity_stats.low or 0),
            },
            "recent_scans": [s.to_dict() for s in recent_scans],
        }
