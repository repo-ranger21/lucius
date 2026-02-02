"""Tests for reconnaissance module (Step 2)."""

import pytest

from sentinel.asset_scope_manager import (
    AssetScopeManager,
    ScopedAsset,
    ScopeJustification,
    ScopeRule,
    ScopeStatus,
)
from sentinel.recon_engine import Asset, AssetType, ReconEngine, ReconScan, ReconTarget, ScanStatus
from sentinel.subdomain_enumerator import SubdomainEnumerator
from sentinel.tech_stack_fingerprinter import TechStackFingerprinter


class TestReconTarget:
    """Tests for reconnaissance target."""

    def test_create_recon_target(self):
        """Test creating reconnaissance target."""
        target = ReconTarget(
            target="example.com",
            name="Example Target",
            description="Test organization",
        )

        assert target.target == "example.com"
        assert target.name == "Example Target"
        assert target.description == "Test organization"

    def test_add_scope_domain(self):
        """Test adding domain to scope."""
        target = ReconTarget(target="example.com")
        target.add_scope_domain("api.example.com")
        target.add_scope_domain("staging.example.com")

        assert len(target.additional_domains) == 2
        assert "api.example.com" in target.additional_domains

    def test_recon_target_to_dict(self):
        """Test target dictionary conversion."""
        target = ReconTarget(target="example.com", name="Test")
        target.add_scope_domain("sub.example.com")

        target_dict = target.to_dict()

        assert target_dict["target"] == "example.com"
        assert "sub.example.com" in target_dict["additional_domains"]


class TestReconAsset:
    """Tests for reconnaissance asset."""

    def test_create_asset(self):
        """Test creating asset."""
        asset = Asset(
            asset_type=AssetType.SUBDOMAIN,
            value="api.example.com",
            source="subdomain_enumerator",
        )

        assert asset.asset_type == AssetType.SUBDOMAIN
        assert asset.value == "api.example.com"

    def test_asset_confidence(self):
        """Test asset confidence level."""
        asset = Asset(
            asset_type=AssetType.DOMAIN,
            value="example.com",
            confidence=0.95,
        )

        assert asset.confidence == 0.95

    def test_add_asset_tags(self):
        """Test adding tags to asset."""
        asset = Asset(asset_type=AssetType.SUBDOMAIN, value="api.example.com")

        asset.add_tag("in-scope")
        asset.add_tag("api")

        assert "in-scope" in asset.tags
        assert "api" in asset.tags

    def test_asset_to_dict(self):
        """Test asset dictionary conversion."""
        asset = Asset(
            asset_type=AssetType.SUBDOMAIN,
            value="sub.example.com",
            source="test",
        )
        asset.add_tag("in-scope")

        asset_dict = asset.to_dict()

        assert asset_dict["value"] == "sub.example.com"
        assert "in-scope" in asset_dict["tags"]


class TestReconScan:
    """Tests for reconnaissance scan."""

    def test_create_scan(self):
        """Test creating scan."""
        target = ReconTarget(target="example.com")
        scan = ReconScan(scan_id="test-001", target=target)

        assert scan.scan_id == "test-001"
        assert scan.status == ScanStatus.PENDING

    def test_add_asset_to_scan(self):
        """Test adding asset to scan."""
        target = ReconTarget(target="example.com")
        scan = ReconScan(scan_id="test-001", target=target)

        asset = Asset(
            asset_type=AssetType.SUBDOMAIN,
            value="api.example.com",
            source="enum",
        )
        scan.add_asset(asset)

        assert len(scan.assets_discovered) == 1

    def test_add_error_to_scan(self):
        """Test adding error to scan."""
        target = ReconTarget(target="example.com")
        scan = ReconScan(scan_id="test-001", target=target)

        scan.add_error("Enumeration failed")

        assert len(scan.errors) == 1
        assert "Enumeration failed" in scan.errors

    def test_scan_status_transitions(self):
        """Test scan status transitions."""
        target = ReconTarget(target="example.com")
        scan = ReconScan(scan_id="test-001", target=target)

        assert scan.status == ScanStatus.PENDING

        scan.mark_started()
        assert scan.status == ScanStatus.IN_PROGRESS

        scan.mark_completed()
        assert scan.status == ScanStatus.COMPLETED

    def test_get_assets_by_type(self):
        """Test filtering assets by type."""
        target = ReconTarget(target="example.com")
        scan = ReconScan(scan_id="test-001", target=target)

        scan.add_asset(Asset(asset_type=AssetType.SUBDOMAIN, value="api.example.com"))
        scan.add_asset(Asset(asset_type=AssetType.SUBDOMAIN, value="www.example.com"))
        scan.add_asset(Asset(asset_type=AssetType.TECHNOLOGY, value="nginx"))

        subdomains = scan.get_assets_by_type(AssetType.SUBDOMAIN)

        assert len(subdomains) == 2

    def test_get_unique_values(self):
        """Test getting unique asset values."""
        target = ReconTarget(target="example.com")
        scan = ReconScan(scan_id="test-001", target=target)

        scan.add_asset(Asset(asset_type=AssetType.SUBDOMAIN, value="api.example.com"))
        scan.add_asset(Asset(asset_type=AssetType.SUBDOMAIN, value="www.example.com"))
        scan.add_asset(Asset(asset_type=AssetType.SUBDOMAIN, value="api.example.com"))

        unique = scan.get_unique_values(AssetType.SUBDOMAIN)

        assert len(unique) == 2

    def test_scan_summary(self):
        """Test scan summary."""
        target = ReconTarget(target="example.com")
        scan = ReconScan(scan_id="test-001", target=target)

        scan.add_asset(Asset(asset_type=AssetType.SUBDOMAIN, value="api.example.com"))
        scan.add_asset(Asset(asset_type=AssetType.TECHNOLOGY, value="nginx"))
        scan.mark_completed()

        summary = scan.get_summary()

        assert summary["total_assets"] == 2
        assert summary["status"] == "completed"
        assert summary["asset_types"]["subdomain"] == 1


class TestReconEngine:
    """Tests for reconnaissance engine."""

    def test_create_recon_engine(self):
        """Test creating engine."""
        engine = ReconEngine()
        assert len(engine.scans) == 0

    def test_create_scan_with_auto_id(self):
        """Test creating scan with auto-generated ID."""
        engine = ReconEngine()
        target = ReconTarget(target="example.com")

        scan = engine.create_scan(target)

        assert scan.scan_id.startswith("recon-")
        assert scan.scan_id in engine.scans

    def test_create_scan_with_custom_id(self):
        """Test creating scan with custom ID."""
        engine = ReconEngine()
        target = ReconTarget(target="example.com")

        scan = engine.create_scan(target, scan_id="custom-001")

        assert scan.scan_id == "custom-001"

    def test_get_scan(self):
        """Test retrieving scan."""
        engine = ReconEngine()
        target = ReconTarget(target="example.com")
        scan = engine.create_scan(target, scan_id="test-001")

        retrieved = engine.get_scan("test-001")

        assert retrieved.scan_id == "test-001"

    def test_extract_domain(self):
        """Test domain extraction from various formats."""
        assert ReconEngine._extract_domain("example.com") == "example.com"
        assert ReconEngine._extract_domain("https://example.com") == "example.com"
        assert ReconEngine._extract_domain("http://example.com/path") == "example.com"
        assert ReconEngine._extract_domain("example.com:8080") == "example.com"
        assert ReconEngine._extract_domain("EXAMPLE.COM") == "example.com"

    def test_extract_ip(self):
        """Test IP address extraction."""
        assert ReconEngine._extract_ip("192.168.1.1") == "192.168.1.1"
        assert ReconEngine._extract_ip("invalid") is None
        assert ReconEngine._extract_ip("example.com") is None

    def test_get_all_domains(self):
        """Test getting all domains from scan."""
        engine = ReconEngine()
        target = ReconTarget(target="example.com")
        target.add_scope_domain("api.example.com")

        scan = engine.create_scan(target)
        scan.add_asset(Asset(asset_type=AssetType.SUBDOMAIN, value="www.example.com"))

        domains = engine.get_all_domains(scan)

        assert "example.com" in domains
        assert "api.example.com" in domains
        assert "www.example.com" in domains


class TestSubdomainEnumerator:
    """Tests for subdomain enumeration."""

    @pytest.mark.asyncio
    async def test_enumerate_subdomains(self):
        """Test subdomain enumeration."""
        enumerator = SubdomainEnumerator()
        assets = await enumerator.enumerate("example.com")

        assert len(assets) > 0
        assert all(a.asset_type == AssetType.SUBDOMAIN for a in assets)

    @pytest.mark.asyncio
    async def test_subdomain_tagging(self):
        """Test subdomain asset tagging."""
        enumerator = SubdomainEnumerator()
        assets = await enumerator.enumerate("example.com")

        assert all("in-scope" in a.tags for a in assets)
        assert all("subdomain" in a.tags for a in assets)

    def test_common_subdomain_count(self):
        """Test common subdomain patterns."""
        enumerator = SubdomainEnumerator()
        assert len(enumerator.COMMON_SUBDOMAINS) > 50

    @pytest.mark.asyncio
    async def test_enumerate_returns_assets(self):
        """Test that enumeration returns Asset objects."""
        enumerator = SubdomainEnumerator()
        assets = await enumerator.enumerate("example.com")

        for asset in assets:
            assert isinstance(asset, Asset)
            assert asset.asset_type == AssetType.SUBDOMAIN


class TestTechStackFingerprinter:
    """Tests for technology stack fingerprinting."""

    @pytest.mark.asyncio
    async def test_fingerprint_target(self):
        """Test fingerprinting target."""
        fingerprinter = TechStackFingerprinter()
        assets = await fingerprinter.fingerprint("example.com")

        # Should detect at least some technologies
        assert isinstance(assets, list)
        assert all(a.asset_type == AssetType.TECHNOLOGY for a in assets)

    @pytest.mark.asyncio
    async def test_technology_confidence(self):
        """Test technology confidence scores."""
        fingerprinter = TechStackFingerprinter()
        assets = await fingerprinter.fingerprint("example.com")

        for asset in assets:
            assert 0 <= asset.confidence <= 1.0

    @pytest.mark.asyncio
    async def test_technology_metadata(self):
        """Test technology asset metadata."""
        fingerprinter = TechStackFingerprinter()
        assets = await fingerprinter.fingerprint("example.com")

        for asset in assets:
            assert "category" in asset.metadata
            assert "detection_sources" in asset.metadata

    def test_technology_signatures(self):
        """Test technology signature count."""
        fingerprinter = TechStackFingerprinter()
        assert len(fingerprinter.TECHNOLOGY_SIGNATURES) >= 25

    @pytest.mark.asyncio
    async def test_fingerprint_with_url(self):
        """Test fingerprinting with full URL."""
        fingerprinter = TechStackFingerprinter()
        assets = await fingerprinter.fingerprint("https://example.com/path")

        assert isinstance(assets, list)


class TestAssetScopeManager:
    """Tests for asset scope management."""

    def test_create_scope_manager(self):
        """Test creating scope manager."""
        manager = AssetScopeManager()
        assert len(manager.scope_rules) == 0

    def test_add_in_scope_domain(self):
        """Test adding in-scope domain."""
        manager = AssetScopeManager()
        rule = manager.add_in_scope_domain("example.com")

        assert rule.scope_status == ScopeStatus.IN_SCOPE
        assert rule.pattern == "example.com"

    def test_add_out_of_scope_domain(self):
        """Test adding out-of-scope domain."""
        manager = AssetScopeManager()
        rule = manager.add_out_of_scope_domain("example.org")

        assert rule.scope_status == ScopeStatus.OUT_OF_SCOPE

    def test_add_wildcard_scope(self):
        """Test adding wildcard scope pattern."""
        manager = AssetScopeManager()
        rule = manager.add_wildcard_scope("*.example.com", in_scope=True)

        assert rule.pattern == "*.example.com"
        assert rule.rule_type == "wildcard"

    def test_determine_exact_match(self):
        """Test scope determination with exact match."""
        manager = AssetScopeManager()
        manager.add_in_scope_domain("example.com")

        status, _, _ = manager.determine_scope("example.com", "domain")

        assert status == ScopeStatus.IN_SCOPE

    def test_determine_wildcard_match(self):
        """Test scope determination with wildcard."""
        manager = AssetScopeManager()
        manager.add_wildcard_scope("*.example.com", in_scope=True)

        status, _, _ = manager.determine_scope("api.example.com", "domain")

        assert status == ScopeStatus.IN_SCOPE

    def test_determine_no_match(self):
        """Test scope determination with no matching rules."""
        manager = AssetScopeManager()

        status, _, _ = manager.determine_scope("unknown.com", "domain")

        assert status == ScopeStatus.UNKNOWN

    def test_classify_asset(self):
        """Test classifying asset."""
        manager = AssetScopeManager()
        manager.add_in_scope_domain("example.com")

        scoped = manager.classify_asset("example.com")

        assert scoped.scope_status == ScopeStatus.IN_SCOPE
        assert scoped.asset_value == "example.com"

    def test_get_in_scope_assets(self):
        """Test getting in-scope assets."""
        manager = AssetScopeManager()
        manager.add_in_scope_domain("example.com")
        manager.classify_asset("example.com")
        manager.classify_asset("other.com")

        in_scope = manager.get_in_scope_assets()

        assert len(in_scope) == 1
        assert "example.com" in in_scope

    def test_get_out_of_scope_assets(self):
        """Test getting out-of-scope assets."""
        manager = AssetScopeManager()
        manager.add_out_of_scope_domain("example.com")
        manager.classify_asset("example.com")

        out_scope = manager.get_out_of_scope_assets()

        assert len(out_scope) == 1

    def test_scope_summary(self):
        """Test scope summary."""
        manager = AssetScopeManager()
        manager.add_in_scope_domain("example.com")
        manager.classify_asset("example.com")
        manager.classify_asset("other.com")

        summary = manager.get_scope_summary()

        assert summary["total_assets"] == 2
        assert summary["in_scope"] == 1
        assert summary["unknown"] == 1
        assert summary["total_rules"] == 1

    def test_scope_priority(self):
        """Test rule priority matching."""
        manager = AssetScopeManager()

        # Add rules with different priorities
        manager.add_in_scope_domain("example.com", priority=10)
        manager.add_out_of_scope_domain("example.com", priority=50)

        status, _, rule_id = manager.determine_scope("example.com")

        # Lower priority (10) should match first
        assert status == ScopeStatus.IN_SCOPE

    def test_export_scope_report(self):
        """Test exporting scope report."""
        manager = AssetScopeManager()
        manager.add_in_scope_domain("example.com")
        manager.classify_asset("example.com")

        report = manager.export_scope_report()

        assert "rules" in report
        assert "assets" in report
        assert "summary" in report
        assert report["summary"]["total_assets"] == 1

    def test_add_ip_range_scope(self):
        """Test adding IP range scope."""
        manager = AssetScopeManager()
        manager.add_ip_range_scope("192.168.0.0/24", in_scope=True)

        assert len(manager.scope_rules) == 1
