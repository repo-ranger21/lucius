"""Tests for Sentinel parsers."""

import json
from pathlib import Path

import pytest

from sentinel.parsers import ComposerParser, Dependency, NPMParser, ParserFactory, PipParser


class TestNPMParser:
    """Tests for NPM package-lock.json parser."""

    def test_parse_package_lock(self, sample_package_lock, tmp_path):
        """Test parsing package-lock.json."""
        lock_path = tmp_path / "package-lock.json"
        lock_path.write_text(json.dumps(sample_package_lock))

        parser = NPMParser(tmp_path)
        dependencies = parser.parse()

        assert len(dependencies) == 2
        assert any(d.name == "lodash" and d.version == "4.17.21" for d in dependencies)
        assert any(d.name == "express" and d.version == "4.18.2" for d in dependencies)

    def test_parse_empty_file(self, tmp_path):
        """Test parsing empty package-lock.json."""
        lock_path = tmp_path / "package-lock.json"
        lock_path.write_text(json.dumps({"packages": {}}))

        parser = NPMParser(tmp_path)
        dependencies = parser.parse()

        assert len(dependencies) == 0

    def test_ecosystem_name(self):
        """Test ecosystem property."""
        parser = NPMParser(Path("."))
        assert parser.ecosystem == "npm"


class TestPipParser:
    """Tests for Pip requirements.txt parser."""

    def test_parse_requirements(self, sample_requirements, tmp_path):
        """Test parsing requirements.txt."""
        req_path = tmp_path / "requirements.txt"
        req_path.write_text(sample_requirements)

        parser = PipParser(tmp_path)
        dependencies = parser.parse()

        assert len(dependencies) == 4

        flask_dep = next(d for d in dependencies if d.name == "flask")
        assert flask_dep.version == "2.3.0"

        requests_dep = next(d for d in dependencies if d.name == "requests")
        assert requests_dep.version == "2.28.0"

    def test_parse_pinned_version(self, tmp_path):
        """Test parsing pinned version."""
        content = "package==1.2.3"
        req_path = tmp_path / "requirements.txt"
        req_path.write_text(content)

        parser = PipParser(tmp_path)
        dependencies = parser.parse()

        assert len(dependencies) == 1
        assert dependencies[0].version == "1.2.3"

    def test_ecosystem_name(self):
        """Test ecosystem property."""
        parser = PipParser(Path("."))
        assert parser.ecosystem == "pypi"


class TestComposerParser:
    """Tests for Composer composer.lock parser."""

    def test_parse_composer_lock(self, sample_composer_lock, tmp_path):
        """Test parsing composer.lock."""
        lock_path = tmp_path / "composer.lock"
        lock_path.write_text(json.dumps(sample_composer_lock))

        parser = ComposerParser(tmp_path)
        dependencies = parser.parse()

        assert len(dependencies) == 3

    def test_parse_production_only(self, sample_composer_lock, tmp_path):
        """Test parsing only production dependencies."""
        # Modify to only have packages
        sample_composer_lock.pop("packages-dev")

        lock_path = tmp_path / "composer.lock"
        lock_path.write_text(json.dumps(sample_composer_lock))

        parser = ComposerParser(tmp_path)
        dependencies = parser.parse()

        assert len(dependencies) == 2

    def test_ecosystem_name(self):
        """Test ecosystem property."""
        parser = ComposerParser(Path("."))
        assert parser.ecosystem == "packagist"


class TestParserFactory:
    """Tests for parser factory."""

    def test_get_npm_parser(self):
        """Test getting NPM parser."""
        parser = ParserFactory.create("npm", Path("."))
        assert isinstance(parser, NPMParser)

    def test_get_pip_parser(self):
        """Test getting Pip parser."""
        parser = ParserFactory.create("pip", Path("."))
        assert isinstance(parser, PipParser)

    def test_get_composer_parser(self):
        """Test getting Composer parser."""
        parser = ParserFactory.create("composer", Path("."))
        assert isinstance(parser, ComposerParser)

    def test_unsupported_file(self):
        """Test unsupported file type."""
        with pytest.raises(ValueError, match="Unsupported package manager"):
            ParserFactory.create("unknown", Path("."))


class TestDependency:
    """Tests for Dependency dataclass."""

    def test_dependency_creation(self):
        """Test creating a dependency."""
        dep = Dependency(name="test-package", version="1.0.0", ecosystem="npm")
        assert dep.name == "test-package"
        assert dep.version == "1.0.0"
        assert dep.ecosystem == "npm"

    def test_dependency_equality(self):
        """Test dependency equality."""
        dep1 = Dependency(name="pkg", version="1.0.0", ecosystem="npm")
        dep2 = Dependency(name="pkg", version="1.0.0", ecosystem="npm")
        assert dep1 == dep2
        assert dep1 == dep2
        assert dep1 == dep2
