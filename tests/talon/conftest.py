"""Test fixtures and configuration for Talon tests."""

import os
import sys
from collections.abc import Generator
from datetime import datetime, timedelta
from decimal import Decimal

import pytest
from flask import Flask

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from talon.extensions import db
from talon.models import ScanResult, ScanVulnerability, Vulnerability


def create_test_app() -> Flask:
    """Create Flask app configured for testing."""
    app = Flask(__name__)
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
        "TEST_DATABASE_URL",
        "sqlite:///:memory:"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["SQLALCHEMY_ECHO"] = False

    db.init_app(app)
    return app


@pytest.fixture(scope="session")
def app() -> Flask:
    """Create application for testing session."""
    return create_test_app()


@pytest.fixture(scope="function")
def client(app: Flask) -> Generator:
    """Create test client."""
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
            yield client
            db.drop_all()


@pytest.fixture(scope="function")
def db_session(app: Flask) -> Generator:
    """Create database session for testing."""
    with app.app_context():
        db.create_all()
        yield db.session
        db.session.rollback()
        db.drop_all()


@pytest.fixture
def tenant_id() -> str:
    """Default test tenant ID."""
    return "test-tenant-001"


@pytest.fixture
def other_tenant_id() -> str:
    """Secondary test tenant ID for isolation tests."""
    return "test-tenant-002"


@pytest.fixture
def sample_vulnerability_data() -> dict:
    """Sample vulnerability data for testing."""
    return {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "affected_packages": [
            {"name": "log4j-core", "ecosystem": "maven", "version_range": ">=2.0-beta9,<2.16.0"}
        ],
        "references": [
            {"url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", "source": "NVD"},
            {"url": "https://logging.apache.org/log4j/2.x/security.html", "source": "Apache"},
        ],
        "published_date": datetime(2021, 12, 10, 10, 15, 0),
        "modified_date": datetime(2023, 4, 3, 17, 24, 23),
    }


@pytest.fixture
def sample_vulnerability(db_session, sample_vulnerability_data) -> Vulnerability:
    """Create and return a sample vulnerability."""
    vuln = Vulnerability(**sample_vulnerability_data)
    db_session.add(vuln)
    db_session.commit()
    return vuln


@pytest.fixture
def sample_vulnerabilities(db_session) -> list[Vulnerability]:
    """Create multiple vulnerabilities for testing."""
    vulns_data = [
        {
            "cve_id": "CVE-2023-0001",
            "description": "Critical vulnerability in test package",
            "severity": "CRITICAL",
            "cvss_score": Decimal("9.8"),
            "affected_packages": [{"name": "test-pkg", "ecosystem": "npm"}],
            "published_date": datetime.utcnow() - timedelta(days=5),
        },
        {
            "cve_id": "CVE-2023-0002",
            "description": "High severity issue in another package",
            "severity": "HIGH",
            "cvss_score": Decimal("7.5"),
            "affected_packages": [{"name": "another-pkg", "ecosystem": "pypi"}],
            "published_date": datetime.utcnow() - timedelta(days=10),
        },
        {
            "cve_id": "CVE-2023-0003",
            "description": "Medium vulnerability",
            "severity": "MEDIUM",
            "cvss_score": Decimal("5.3"),
            "affected_packages": [{"name": "medium-pkg", "ecosystem": "npm"}],
            "published_date": datetime.utcnow() - timedelta(days=30),
        },
        {
            "cve_id": "CVE-2023-0004",
            "description": "Low severity advisory",
            "severity": "LOW",
            "cvss_score": Decimal("2.1"),
            "affected_packages": [{"name": "low-pkg", "ecosystem": "composer"}],
            "published_date": datetime.utcnow() - timedelta(days=60),
        },
        {
            "cve_id": "CVE-2022-0001",
            "description": "Old critical vulnerability",
            "severity": "CRITICAL",
            "cvss_score": Decimal("9.1"),
            "affected_packages": [{"name": "old-pkg", "ecosystem": "maven"}],
            "published_date": datetime.utcnow() - timedelta(days=365),
        },
    ]

    vulns = []
    for data in vulns_data:
        vuln = Vulnerability(**data)
        db_session.add(vuln)
        vulns.append(vuln)

    db_session.commit()
    return vulns


@pytest.fixture
def sample_scan_data(tenant_id: str) -> dict:
    """Sample scan result data."""
    return {
        "tenant_id": tenant_id,
        "project_name": "test-project",
        "scan_type": "dependency",
        "package_manager": "npm",
        "total_dependencies": 150,
        "vulnerable_count": 5,
        "critical_count": 1,
        "high_count": 2,
        "medium_count": 1,
        "low_count": 1,
        "status": "completed",
        "scan_metadata": {"scanner_version": "1.0.0"},
        "completed_at": datetime.utcnow(),
    }


@pytest.fixture
def sample_scan(db_session, sample_scan_data) -> ScanResult:
    """Create and return a sample scan result."""
    scan = ScanResult(**sample_scan_data)
    db_session.add(scan)
    db_session.commit()
    return scan


@pytest.fixture
def sample_scan_with_vulns(
    db_session,
    sample_scan_data,
    sample_vulnerabilities,
) -> ScanResult:
    """Create scan with associated vulnerabilities."""
    scan = ScanResult(**sample_scan_data)
    db_session.add(scan)
    db_session.flush()

    # Associate vulnerabilities
    for i, vuln in enumerate(sample_vulnerabilities[:3]):
        scan_vuln = ScanVulnerability(
            scan_id=scan.id,
            vulnerability_id=vuln.id,
            package_name=f"package-{i}",
            installed_version="1.0.0",
            fixed_version="1.0.1",
        )
        db_session.add(scan_vuln)

    db_session.commit()
    return scan


@pytest.fixture
def multiple_tenant_scans(db_session, tenant_id, other_tenant_id) -> dict:
    """Create scans for multiple tenants."""
    scans = {"tenant_1": [], "tenant_2": []}

    # Tenant 1 scans
    for i in range(3):
        scan = ScanResult(
            tenant_id=tenant_id,
            project_name=f"project-{i}",
            scan_type="dependency",
            package_manager="npm",
            total_dependencies=100 + i * 10,
            vulnerable_count=i,
            critical_count=1 if i > 0 else 0,
            status="completed",
        )
        db_session.add(scan)
        scans["tenant_1"].append(scan)

    # Tenant 2 scans
    for i in range(2):
        scan = ScanResult(
            tenant_id=other_tenant_id,
            project_name=f"other-project-{i}",
            scan_type="dependency",
            package_manager="pip",
            total_dependencies=50 + i * 5,
            vulnerable_count=i * 2,
            critical_count=0,
            status="completed",
        )
        db_session.add(scan)
        scans["tenant_2"].append(scan)

    db_session.commit()
    return scans


# ============================================================================
# Edge Case Fixtures
# ============================================================================


@pytest.fixture
def malformed_cve_ids() -> list[str]:
    """Malformed CVE IDs for edge case testing."""
    return [
        "",
        "   ",
        "CVE",
        "CVE-",
        "CVE-2021",
        "cve-2021-44228",  # lowercase
        "CVE_2021_44228",  # underscores
        "CVE-202144228",   # no second dash
        "NOTACVE-2021-44228",
        "CVE-99999-99999999999",  # extremely long
        "CVE-2021-44228; DROP TABLE vulnerabilities;--",  # SQL injection attempt
        "<script>alert('xss')</script>",  # XSS attempt
    ]


@pytest.fixture
def empty_scan_data(tenant_id: str) -> dict:
    """Scan with no vulnerabilities."""
    return {
        "tenant_id": tenant_id,
        "project_name": "empty-project",
        "scan_type": "dependency",
        "package_manager": "npm",
        "total_dependencies": 0,
        "vulnerable_count": 0,
        "status": "completed",
    }


@pytest.fixture
def large_vulnerability_count() -> int:
    """Large number for stress testing."""
    return 1000


# ============================================================================
# Utility Functions
# ============================================================================


def create_vulnerability(
    db_session,
    cve_id: str,
    severity: str = "HIGH",
    cvss_score: float = 7.5,
) -> Vulnerability:
    """Helper to create a vulnerability."""
    vuln = Vulnerability(
        cve_id=cve_id,
        description=f"Description for {cve_id}",
        severity=severity,
        cvss_score=Decimal(str(cvss_score)),
        published_date=datetime.utcnow(),
    )
    db_session.add(vuln)
    db_session.flush()
    return vuln


def create_scan(
    db_session,
    tenant_id: str,
    project_name: str = "test-project",
    **kwargs,
) -> ScanResult:
    """Helper to create a scan result."""
    scan = ScanResult(
        tenant_id=tenant_id,
        project_name=project_name,
        scan_type=kwargs.get("scan_type", "dependency"),
        package_manager=kwargs.get("package_manager", "npm"),
        total_dependencies=kwargs.get("total_dependencies", 100),
        vulnerable_count=kwargs.get("vulnerable_count", 0),
        status=kwargs.get("status", "completed"),
    )
    db_session.add(scan)
    db_session.flush()
    return scan
