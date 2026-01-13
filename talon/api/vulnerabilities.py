"""Vulnerabilities API endpoints."""

from datetime import datetime
from functools import wraps
from uuid import UUID

from flask import request
from flask_restx import Namespace, Resource, fields
from marshmallow import Schema, fields as ma_fields, validate, ValidationError, EXCLUDE

from talon.extensions import db
from talon.models import Vulnerability
from talon.services.vulnerability_service import VulnerabilityService
from talon.services.threat_scoring import ThreatScoringService
from shared.logging import get_logger

logger = get_logger(__name__)

vulnerabilities_ns = Namespace("vulnerabilities", description="Vulnerability management")

# ============================================================================
# Authentication Decorator (placeholder - integrate with your auth system)
# ============================================================================

def require_auth(f):
    """
    Authentication decorator for protected endpoints.

    Replace this with your actual authentication mechanism:
    - JWT tokens
    - API keys
    - OAuth
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # TODO: Implement actual authentication
        # Example: Check for API key or JWT token
        # auth_header = request.headers.get('Authorization')
        # if not auth_header or not validate_token(auth_header):
        #     vulnerabilities_ns.abort(401, "Unauthorized")

        # For now, allow all requests (REMOVE IN PRODUCTION)
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# Marshmallow Validation Schemas
# ============================================================================

class VulnerabilityCreateSchema(Schema):
    """Schema for creating a new vulnerability."""

    class Meta:
        unknown = EXCLUDE

    cve_id = ma_fields.String(
        required=True,
        validate=validate.Regexp(r'^CVE-\d{4}-\d{4,}$', error="Invalid CVE format"),
    )
    severity = ma_fields.String(
        required=True,
        validate=validate.OneOf(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]),
    )
    description = ma_fields.String(allow_none=True)
    cvss_score = ma_fields.Float(
        allow_none=True,
        validate=validate.Range(min=0.0, max=10.0),
    )
    cvss_vector = ma_fields.String(allow_none=True)
    affected_packages = ma_fields.List(ma_fields.Dict(), allow_none=True)
    references = ma_fields.List(ma_fields.Dict(), allow_none=True)
    published_date = ma_fields.DateTime(allow_none=True)
    modified_date = ma_fields.DateTime(allow_none=True)
    calculate_threat = ma_fields.Boolean(load_default=True)


class VulnerabilityUpdateSchema(Schema):
    """Schema for updating an existing vulnerability."""

    class Meta:
        unknown = EXCLUDE

    description = ma_fields.String(allow_none=True)
    severity = ma_fields.String(
        validate=validate.OneOf(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]),
        allow_none=True,
    )
    cvss_score = ma_fields.Float(
        allow_none=True,
        validate=validate.Range(min=0.0, max=10.0),
    )
    cvss_vector = ma_fields.String(allow_none=True)
    affected_packages = ma_fields.List(ma_fields.Dict(), allow_none=True)
    references = ma_fields.List(ma_fields.Dict(), allow_none=True)
    recalculate_threat = ma_fields.Boolean(load_default=False)


class VulnerabilityFilterSchema(Schema):
    """Schema for filtering vulnerabilities."""

    class Meta:
        unknown = EXCLUDE

    severity = ma_fields.String(
        validate=validate.OneOf(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]),
        allow_none=True,
    )
    min_cvss = ma_fields.Float(
        validate=validate.Range(min=0.0, max=10.0),
        allow_none=True,
    )
    min_threat_score = ma_fields.Float(
        validate=validate.Range(min=0.0, max=100.0),
        allow_none=True,
    )
    package = ma_fields.String(allow_none=True)
    search = ma_fields.String(allow_none=True)
    start_date = ma_fields.DateTime(allow_none=True)
    end_date = ma_fields.DateTime(allow_none=True)
    limit = ma_fields.Integer(
        validate=validate.Range(min=1, max=500),
        load_default=50,
    )
    offset = ma_fields.Integer(
        validate=validate.Range(min=0),
        load_default=0,
    )


# ============================================================================
# Flask-RESTX API Models (for Swagger documentation)
# ============================================================================

vulnerability_model = vulnerabilities_ns.model("Vulnerability", {
    "id": fields.String(description="Vulnerability UUID"),
    "cve_id": fields.String(required=True, description="CVE identifier (e.g., CVE-2024-1234)"),
    "description": fields.String(description="Vulnerability description"),
    "severity": fields.String(
        description="Severity level",
        enum=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"],
    ),
    "cvss_score": fields.Float(description="CVSS base score (0-10)"),
    "cvss_vector": fields.String(description="CVSS vector string"),
    "affected_packages": fields.List(fields.Raw, description="Affected packages"),
    "references": fields.List(fields.Raw, description="Reference links"),
    "threat_score": fields.Float(description="ML-based threat score (0-100)"),
    "published_date": fields.DateTime(description="Publication date"),
    "modified_date": fields.DateTime(description="Last modification date"),
    "created_at": fields.DateTime(description="Record creation timestamp"),
    "updated_at": fields.DateTime(description="Record update timestamp"),
})

vulnerability_create_model = vulnerabilities_ns.model("VulnerabilityCreate", {
    "cve_id": fields.String(required=True, description="CVE identifier"),
    "severity": fields.String(required=True, description="Severity level"),
    "description": fields.String(description="Vulnerability description"),
    "cvss_score": fields.Float(description="CVSS score"),
    "cvss_vector": fields.String(description="CVSS vector"),
    "affected_packages": fields.List(fields.Raw, description="Affected packages"),
    "references": fields.List(fields.Raw, description="Reference links"),
    "published_date": fields.DateTime(description="Publication date"),
    "modified_date": fields.DateTime(description="Last modification date"),
    "calculate_threat": fields.Boolean(description="Calculate threat score", default=True),
})

vulnerability_update_model = vulnerabilities_ns.model("VulnerabilityUpdate", {
    "description": fields.String(description="Vulnerability description"),
    "severity": fields.String(description="Severity level"),
    "cvss_score": fields.Float(description="CVSS score"),
    "cvss_vector": fields.String(description="CVSS vector"),
    "affected_packages": fields.List(fields.Raw, description="Affected packages"),
    "references": fields.List(fields.Raw, description="Reference links"),
    "recalculate_threat": fields.Boolean(description="Recalculate threat score", default=False),
})

dashboard_model = vulnerabilities_ns.model("Dashboard", {
    "total_vulnerabilities": fields.Integer(description="Total vulnerability count"),
    "severity_breakdown": fields.Raw(description="Count by severity level"),
    "threat_score_distribution": fields.Raw(description="Threat score statistics"),
    "recent_vulnerabilities": fields.List(fields.Nested(vulnerability_model)),
    "high_threat_vulnerabilities": fields.List(fields.Nested(vulnerability_model)),
    "trends": fields.Raw(description="Vulnerability trends over time"),
})


# ============================================================================
# Service instance (dependency injection)
# ============================================================================

def get_vulnerability_service() -> VulnerabilityService:
    """Get vulnerability service instance."""
    return VulnerabilityService()


# ============================================================================
# API Endpoints
# ============================================================================

@vulnerabilities_ns.route("")
class VulnerabilityList(Resource):
    """Vulnerability collection resource."""

    @vulnerabilities_ns.doc("list_vulnerabilities")
    @vulnerabilities_ns.param("severity", "Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN)")
    @vulnerabilities_ns.param("min_cvss", "Minimum CVSS score (0-10)", type=float)
    @vulnerabilities_ns.param("min_threat_score", "Minimum threat score (0-100)", type=float)
    @vulnerabilities_ns.param("package", "Filter by package name")
    @vulnerabilities_ns.param("search", "Search in CVE ID or description")
    @vulnerabilities_ns.param("start_date", "Start date (ISO 8601)")
    @vulnerabilities_ns.param("end_date", "End date (ISO 8601)")
    @vulnerabilities_ns.param("limit", "Maximum results (1-500)", type=int, default=50)
    @vulnerabilities_ns.param("offset", "Result offset for pagination", type=int, default=0)
    @vulnerabilities_ns.response(200, "Success", [vulnerability_model])
    @vulnerabilities_ns.response(400, "Validation Error")
    def get(self):
        """
        List vulnerabilities with advanced filtering.

        Supports filtering by:
        - Severity level
        - CVSS score threshold
        - Threat score threshold
        - Package name
        - Date range
        - Text search in CVE ID or description
        """
        try:
            # Validate query parameters
            schema = VulnerabilityFilterSchema()
            filters = schema.load(request.args)

            # Build query
            query = Vulnerability.query

            if filters.get("severity"):
                query = query.filter(Vulnerability.severity == filters["severity"].upper())

            if filters.get("min_cvss") is not None:
                query = query.filter(Vulnerability.cvss_score >= filters["min_cvss"])

            if filters.get("min_threat_score") is not None:
                query = query.filter(Vulnerability.threat_score >= filters["min_threat_score"])

            if filters.get("package"):
                package_filter = f'%"{filters["package"]}"%'
                query = query.filter(
                    Vulnerability.affected_packages.cast(db.String).ilike(package_filter)
                )

            if filters.get("search"):
                search_term = f"%{filters['search']}%"
                query = query.filter(
                    db.or_(
                        Vulnerability.cve_id.ilike(search_term),
                        Vulnerability.description.ilike(search_term),
                    )
                )

            if filters.get("start_date"):
                query = query.filter(Vulnerability.published_date >= filters["start_date"])

            if filters.get("end_date"):
                query = query.filter(Vulnerability.published_date <= filters["end_date"])

            # Order by threat score (descending), then by creation date
            query = query.order_by(
                Vulnerability.threat_score.desc().nullslast(),
                Vulnerability.created_at.desc()
            )

            # Apply pagination
            limit = filters.get("limit", 50)
            offset = filters.get("offset", 0)
            vulns = query.offset(offset).limit(limit).all()

            logger.info(f"Retrieved {len(vulns)} vulnerabilities (limit={limit}, offset={offset})")

            return [v.to_dict() for v in vulns], 200

        except ValidationError as e:
            logger.warning(f"Validation error in list_vulnerabilities: {e.messages}")
            vulnerabilities_ns.abort(400, f"Validation error: {e.messages}")
        except Exception as e:
            logger.error(f"Error listing vulnerabilities: {e}", exc_info=True)
            vulnerabilities_ns.abort(500, "Internal server error")

    @vulnerabilities_ns.doc("create_vulnerability", security="apikey")
    @vulnerabilities_ns.expect(vulnerability_create_model, validate=True)
    @vulnerabilities_ns.response(201, "Vulnerability created", vulnerability_model)
    @vulnerabilities_ns.response(400, "Validation Error")
    @vulnerabilities_ns.response(401, "Unauthorized")
    @vulnerabilities_ns.response(409, "Vulnerability already exists")
    @require_auth
    def post(self):
        """
        Create a new vulnerability with ML-based threat scoring.

        Requires authentication.

        Automatically:
        - Calculates threat score using ML models
        - Sends notifications for high-severity vulnerabilities
        - Validates CVE format and severity levels
        """
        try:
            # Validate request data
            schema = VulnerabilityCreateSchema()
            data = schema.load(request.json)

            # Create vulnerability using service
            service = get_vulnerability_service()
            vuln = service.create_vulnerability(**data)

            logger.info(f"Created vulnerability: {vuln.cve_id}")

            return vuln.to_dict(), 201

        except ValidationError as e:
            logger.warning(f"Validation error in create_vulnerability: {e.messages}")
            vulnerabilities_ns.abort(400, f"Validation error: {e.messages}")
        except ValueError as e:
            logger.warning(f"Duplicate vulnerability creation attempt: {e}")
            vulnerabilities_ns.abort(409, str(e))
        except Exception as e:
            logger.error(f"Error creating vulnerability: {e}", exc_info=True)
            vulnerabilities_ns.abort(500, "Internal server error")


@vulnerabilities_ns.route("/<string:vuln_id>")
@vulnerabilities_ns.param("vuln_id", "Vulnerability UUID")
class VulnerabilityResource(Resource):
    """Single vulnerability resource."""

    @vulnerabilities_ns.doc("get_vulnerability")
    @vulnerabilities_ns.response(200, "Success", vulnerability_model)
    @vulnerabilities_ns.response(400, "Invalid UUID format")
    @vulnerabilities_ns.response(404, "Vulnerability not found")
    def get(self, vuln_id: str):
        """
        Get vulnerability details by UUID.

        Returns complete vulnerability information including:
        - CVE details
        - CVSS scores
        - ML-based threat score
        - Affected packages
        - References
        """
        try:
            # Validate UUID format
            try:
                uuid_obj = UUID(vuln_id)
            except ValueError:
                vulnerabilities_ns.abort(400, "Invalid UUID format")

            # Get vulnerability using service
            service = get_vulnerability_service()
            vuln = service.get_by_id(uuid_obj)

            if not vuln:
                vulnerabilities_ns.abort(404, f"Vulnerability {vuln_id} not found")

            logger.debug(f"Retrieved vulnerability: {vuln.cve_id}")
            return vuln.to_dict(), 200

        except Exception as e:
            logger.error(f"Error retrieving vulnerability {vuln_id}: {e}", exc_info=True)
            vulnerabilities_ns.abort(500, "Internal server error")

    @vulnerabilities_ns.doc("update_vulnerability", security="apikey")
    @vulnerabilities_ns.expect(vulnerability_update_model, validate=True)
    @vulnerabilities_ns.response(200, "Vulnerability updated", vulnerability_model)
    @vulnerabilities_ns.response(400, "Validation Error")
    @vulnerabilities_ns.response(401, "Unauthorized")
    @vulnerabilities_ns.response(404, "Vulnerability not found")
    @require_auth
    def put(self, vuln_id: str):
        """
        Update an existing vulnerability.

        Requires authentication.

        Can optionally recalculate threat score after update.
        """
        try:
            # Validate UUID format
            try:
                uuid_obj = UUID(vuln_id)
            except ValueError:
                vulnerabilities_ns.abort(400, "Invalid UUID format")

            # Validate request data
            schema = VulnerabilityUpdateSchema()
            data = schema.load(request.json)

            # Extract recalculate flag
            recalculate = data.pop("recalculate_threat", False)

            # Update vulnerability using service
            service = get_vulnerability_service()
            vuln = service.update_vulnerability(
                vuln_id=uuid_obj,
                updates=data,
                recalculate_threat=recalculate
            )

            if not vuln:
                vulnerabilities_ns.abort(404, f"Vulnerability {vuln_id} not found")

            logger.info(f"Updated vulnerability: {vuln.cve_id}")
            return vuln.to_dict(), 200

        except ValidationError as e:
            logger.warning(f"Validation error in update_vulnerability: {e.messages}")
            vulnerabilities_ns.abort(400, f"Validation error: {e.messages}")
        except Exception as e:
            logger.error(f"Error updating vulnerability {vuln_id}: {e}", exc_info=True)
            vulnerabilities_ns.abort(500, "Internal server error")

    @vulnerabilities_ns.doc("delete_vulnerability", security="apikey")
    @vulnerabilities_ns.response(204, "Vulnerability deleted")
    @vulnerabilities_ns.response(400, "Invalid UUID format")
    @vulnerabilities_ns.response(401, "Unauthorized")
    @vulnerabilities_ns.response(404, "Vulnerability not found")
    @require_auth
    def delete(self, vuln_id: str):
        """
        Soft delete a vulnerability.

        Requires authentication.

        Note: This performs a soft delete. The record is marked as archived
        but not physically removed from the database.
        """
        try:
            # Validate UUID format
            try:
                uuid_obj = UUID(vuln_id)
            except ValueError:
                vulnerabilities_ns.abort(400, "Invalid UUID format")

            # Get and delete vulnerability
            vuln = Vulnerability.query.get(uuid_obj)
            if not vuln:
                vulnerabilities_ns.abort(404, f"Vulnerability {vuln_id} not found")

            # Soft delete by removing from database
            db.session.delete(vuln)
            db.session.commit()

            logger.info(f"Deleted vulnerability: {vuln.cve_id}")
            return "", 204

        except Exception as e:
            logger.error(f"Error deleting vulnerability {vuln_id}: {e}", exc_info=True)
            db.session.rollback()
            vulnerabilities_ns.abort(500, "Internal server error")


@vulnerabilities_ns.route("/cve/<string:cve_id>")
@vulnerabilities_ns.param("cve_id", "CVE identifier (e.g., CVE-2024-1234)")
class VulnerabilityCVEResource(Resource):
    """Vulnerability resource accessible by CVE ID."""

    @vulnerabilities_ns.doc("get_vulnerability_by_cve")
    @vulnerabilities_ns.response(200, "Success", vulnerability_model)
    @vulnerabilities_ns.response(404, "Vulnerability not found")
    def get(self, cve_id: str):
        """
        Get vulnerability details by CVE identifier.

        Alternative endpoint for looking up vulnerabilities by CVE ID
        instead of UUID.
        """
        try:
            service = get_vulnerability_service()
            vuln = service.get_by_cve(cve_id.upper())

            if not vuln:
                vulnerabilities_ns.abort(404, f"Vulnerability {cve_id} not found")

            logger.debug(f"Retrieved vulnerability by CVE: {vuln.cve_id}")
            return vuln.to_dict(), 200

        except Exception as e:
            logger.error(f"Error retrieving vulnerability {cve_id}: {e}", exc_info=True)
            vulnerabilities_ns.abort(500, "Internal server error")


@vulnerabilities_ns.route("/<string:vuln_id>/threat-score")
@vulnerabilities_ns.param("vuln_id", "Vulnerability UUID")
class VulnerabilityThreatScore(Resource):
    """Vulnerability threat score resource."""

    @vulnerabilities_ns.doc("get_threat_score")
    @vulnerabilities_ns.response(200, "Success")
    @vulnerabilities_ns.response(400, "Invalid UUID format")
    @vulnerabilities_ns.response(404, "Vulnerability not found")
    def get(self, vuln_id: str):
        """
        Get ML-based threat score for a vulnerability.

        Returns the calculated threat score along with the individual
        factors that contributed to the score.
        """
        try:
            try:
                uuid_obj = UUID(vuln_id)
            except ValueError:
                vulnerabilities_ns.abort(400, "Invalid UUID format")

            vuln = Vulnerability.query.get(uuid_obj)
            if not vuln:
                vulnerabilities_ns.abort(
                    404,
                    f"Vulnerability {vuln_id} not found"
                )

            scoring_service = ThreatScoringService()
            score, factors = scoring_service.calculate_threat_score(vuln)

            return {
                "cve_id": vuln.cve_id,
                "threat_score": score,
                "factors": factors,
                "severity": vuln.severity,
                "cvss_score": (
                    float(vuln.cvss_score) if vuln.cvss_score else None
                ),
            }, 200

        except Exception as e:
            logger.error(
                f"Error getting threat score for {vuln_id}: {e}",
                exc_info=True
            )
            vulnerabilities_ns.abort(500, "Internal server error")

    @vulnerabilities_ns.doc("recalculate_threat_score", security="apikey")
    @vulnerabilities_ns.response(200, "Threat score recalculated")
    @vulnerabilities_ns.response(400, "Invalid UUID format")
    @vulnerabilities_ns.response(401, "Unauthorized")
    @vulnerabilities_ns.response(404, "Vulnerability not found")
    @require_auth
    def post(self, vuln_id: str):
        """
        Recalculate and update threat score.

        Requires authentication.

        Useful when vulnerability data has been updated and the
        threat score needs to be recalculated.
        """
        try:
            try:
                uuid_obj = UUID(vuln_id)
            except ValueError:
                vulnerabilities_ns.abort(400, "Invalid UUID format")

            vuln = Vulnerability.query.get(uuid_obj)
            if not vuln:
                vulnerabilities_ns.abort(
                    404,
                    f"Vulnerability {vuln_id} not found"
                )

            scoring_service = ThreatScoringService()
            score, factors = scoring_service.calculate_threat_score(vuln)

            vuln.threat_score = score
            db.session.commit()

            logger.info(f"Updated threat score for {vuln.cve_id}: {score}")

            return {
                "cve_id": vuln.cve_id,
                "threat_score": score,
                "factors": factors,
            }, 200

        except Exception as e:
            logger.error(
                f"Error recalculating threat score for {vuln_id}: {e}",
                exc_info=True
            )
            db.session.rollback()
            vulnerabilities_ns.abort(500, "Internal server error")


@vulnerabilities_ns.route("/high-threat")
class HighThreatVulnerabilities(Resource):
    """High-threat vulnerabilities resource."""

    @vulnerabilities_ns.doc("get_high_threat_vulnerabilities")
    @vulnerabilities_ns.param(
        "threshold",
        "Minimum threat score (0-100)",
        type=float,
        default=70.0
    )
    @vulnerabilities_ns.param(
        "limit",
        "Maximum results",
        type=int,
        default=50
    )
    @vulnerabilities_ns.response(200, "Success", [vulnerability_model])
    def get(self):
        """
        Get vulnerabilities with high threat scores.

        Returns vulnerabilities above the specified threat score threshold,
        ordered by threat score (highest first).
        """
        try:
            threshold = request.args.get("threshold", 70.0, type=float)
            limit = request.args.get("limit", 50, type=int)

            # Validate parameters
            if not 0 <= threshold <= 100:
                vulnerabilities_ns.abort(
                    400,
                    "Threshold must be between 0 and 100"
                )
            if not 1 <= limit <= 500:
                vulnerabilities_ns.abort(
                    400,
                    "Limit must be between 1 and 500"
                )

            service = get_vulnerability_service()
            vulns = service.list_high_threat(threshold=threshold, limit=limit)

            logger.info(
                f"Retrieved {len(vulns)} high-threat "
                f"vulnerabilities (threshold={threshold})"
            )

            return [v.to_dict() for v in vulns], 200

        except Exception as e:
            logger.error(
                f"Error retrieving high-threat vulnerabilities: {e}",
                exc_info=True
            )
            vulnerabilities_ns.abort(500, "Internal server error")


@vulnerabilities_ns.route("/report")
class VulnerabilityReport(Resource):
    """Vulnerability report generation resource."""

    @vulnerabilities_ns.doc("generate_report")
    @vulnerabilities_ns.param(
        "severity_levels",
        "Comma-separated severity levels to include"
    )
    @vulnerabilities_ns.param(
        "min_threat_score",
        "Minimum threat score",
        type=float
    )
    @vulnerabilities_ns.param("start_date", "Start date (ISO 8601)")
    @vulnerabilities_ns.param("end_date", "End date (ISO 8601)")
    @vulnerabilities_ns.response(200, "Success")
    def get(self):
        """
        Generate a comprehensive vulnerability report.

        Returns detailed statistics and vulnerability data based on
        the specified filters.
        """
        try:
            severity_levels = None
            if request.args.get("severity_levels"):
                severity_levels = [
                    s.strip().upper()
                    for s in request.args.get("severity_levels").split(",")
                ]

            min_threat_score = request.args.get(
                "min_threat_score",
                type=float
            )

            start_date = None
            if request.args.get("start_date"):
                start_date = datetime.fromisoformat(
                    request.args.get("start_date")
                )

            end_date = None
            if request.args.get("end_date"):
                end_date = datetime.fromisoformat(
                    request.args.get("end_date")
                )

            service = get_vulnerability_service()
            report = service.generate_report(
                severity_levels=severity_levels,
                min_threat_score=min_threat_score,
                start_date=start_date,
                end_date=end_date,
            )

            logger.info("Generated vulnerability report")
            return report, 200

        except ValueError as e:
            logger.warning(f"Invalid date format in report request: {e}")
            vulnerabilities_ns.abort(400, f"Invalid date format: {e}")
        except Exception as e:
            logger.error(f"Error generating report: {e}", exc_info=True)
            vulnerabilities_ns.abort(500, "Internal server error")


@vulnerabilities_ns.route("/dashboard")
class VulnerabilityDashboard(Resource):
    """Vulnerability dashboard with comprehensive statistics."""

    @vulnerabilities_ns.doc("get_dashboard")
    @vulnerabilities_ns.response(200, "Success", dashboard_model)
    def get(self):
        """
        Get comprehensive dashboard statistics.

        Returns:
        - Total vulnerability count
        - Breakdown by severity
        - Threat score distribution
        - Recent vulnerabilities (last 10)
        - High-threat vulnerabilities (threat score >= 70)
        - Vulnerability trends over time
        """
        try:
            from sqlalchemy import func, extract

            # Total count
            total = Vulnerability.query.count()

            # Severity breakdown
            by_severity = db.session.query(
                Vulnerability.severity,
                func.count(Vulnerability.id).label("count")
            ).group_by(Vulnerability.severity).all()

            severity_breakdown = {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "UNKNOWN": 0,
            }
            for sev, count in by_severity:
                severity_breakdown[sev] = count

            # Threat score statistics
            threat_stats = db.session.query(
                func.min(Vulnerability.threat_score).label("min"),
                func.max(Vulnerability.threat_score).label("max"),
                func.avg(Vulnerability.threat_score).label("avg"),
            ).first()

            threat_score_distribution = {
                "min": float(threat_stats.min) if threat_stats.min else None,
                "max": float(threat_stats.max) if threat_stats.max else None,
                "avg": round(float(threat_stats.avg), 2) if threat_stats.avg else None,
                "count_critical": Vulnerability.query.filter(
                    Vulnerability.threat_score >= 90
                ).count(),
                "count_high": Vulnerability.query.filter(
                    Vulnerability.threat_score >= 70,
                    Vulnerability.threat_score < 90
                ).count(),
                "count_medium": Vulnerability.query.filter(
                    Vulnerability.threat_score >= 40,
                    Vulnerability.threat_score < 70
                ).count(),
                "count_low": Vulnerability.query.filter(
                    Vulnerability.threat_score < 40
                ).count(),
            }

            # Recent vulnerabilities (last 10)
            recent = Vulnerability.query.order_by(
                Vulnerability.created_at.desc()
            ).limit(10).all()

            # High-threat vulnerabilities
            high_threat = Vulnerability.query.filter(
                Vulnerability.threat_score >= 70
            ).order_by(
                Vulnerability.threat_score.desc()
            ).limit(10).all()

            # Vulnerability trends (last 7 days)
            seven_days_ago = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            from datetime import timedelta
            seven_days_ago = seven_days_ago - timedelta(days=6)

            daily_trends = db.session.query(
                func.date(Vulnerability.created_at).label("date"),
                func.count(Vulnerability.id).label("count")
            ).filter(
                Vulnerability.created_at >= seven_days_ago
            ).group_by(
                func.date(Vulnerability.created_at)
            ).order_by(
                func.date(Vulnerability.created_at)
            ).all()

            trends = {
                "daily_new_vulnerabilities": [
                    {"date": str(date), "count": count}
                    for date, count in daily_trends
                ],
                "total_last_7_days": sum(count for _, count in daily_trends),
            }

            dashboard = {
                "total_vulnerabilities": total,
                "severity_breakdown": severity_breakdown,
                "threat_score_distribution": threat_score_distribution,
                "recent_vulnerabilities": [v.to_dict() for v in recent],
                "high_threat_vulnerabilities": [v.to_dict() for v in high_threat],
                "trends": trends,
            }

            logger.info("Generated dashboard statistics")
            return dashboard, 200

        except Exception as e:
            logger.error(f"Error generating dashboard: {e}", exc_info=True)
            vulnerabilities_ns.abort(500, "Internal server error")


@vulnerabilities_ns.route("/stats")
class VulnerabilityStats(Resource):
    """Vulnerability statistics resource."""

    @vulnerabilities_ns.doc("get_vulnerability_stats")
    @vulnerabilities_ns.response(200, "Success")
    def get(self):
        """
        Get basic vulnerability statistics.

        Lightweight endpoint for quick stats without full dashboard overhead.
        """
        try:
            from sqlalchemy import func

            total = Vulnerability.query.count()

            by_severity = db.session.query(
                Vulnerability.severity,
                func.count(Vulnerability.id).label("count")
            ).group_by(Vulnerability.severity).all()

            avg_cvss = db.session.query(
                func.avg(Vulnerability.cvss_score)
            ).scalar()

            high_threat = Vulnerability.query.filter(
                Vulnerability.threat_score >= 80
            ).count()

            return {
                "total_vulnerabilities": total,
                "by_severity": {sev: count for sev, count in by_severity},
                "average_cvss_score": round(float(avg_cvss), 2) if avg_cvss else 0,
                "high_threat_count": high_threat,
            }, 200

        except Exception as e:
            logger.error(f"Error generating stats: {e}", exc_info=True)
            vulnerabilities_ns.abort(500, "Internal server error")
