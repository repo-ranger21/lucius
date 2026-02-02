"""Tests for polyglot dependency parsers (Ruby, Java, Go, Rust)."""

import tempfile
from pathlib import Path

import pytest

from sentinel.parsers import (
    GoModParser,
    IncrementalScanCache,
    JavaMavenParser,
    RubyGemParser,
    RustCargoParser,
)


class TestRubyGemParser:
    """Tests for RubyGemParser."""

    def test_can_parse_with_gemfile_lock(self):
        """Test detection of Gemfile.lock."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir)
            (project_path / "Gemfile.lock").write_text("")

            parser = RubyGemParser(project_path)
            assert parser.can_parse()

    def test_parse_gemfile_lock(self):
        """Test parsing a Gemfile.lock."""
        gemfile_lock_content = """GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.0.4)
    actionmailer (7.0.4)
    bundler (2.3.26)
    rails (7.0.4)
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir)
            (project_path / "Gemfile.lock").write_text(gemfile_lock_content)

            parser = RubyGemParser(project_path)
            deps = parser.parse(include_dev=False)

            assert len(deps) > 0
            assert deps[0].ecosystem == "ruby"
            assert all(dep.name for dep in deps)

    def test_ecosystem_name(self):
        """Test that ecosystem name is correct."""
        with tempfile.TemporaryDirectory() as tmpdir:
            parser = RubyGemParser(Path(tmpdir))
            assert parser.ecosystem == "ruby"


class TestJavaMavenParser:
    """Tests for JavaMavenParser."""

    def test_can_parse_with_pom_xml(self):
        """Test detection of pom.xml."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir)
            (project_path / "pom.xml").write_text("")

            parser = JavaMavenParser(project_path)
            assert parser.can_parse()

    def test_ecosystem_name(self):
        """Test that ecosystem name is correct."""
        with tempfile.TemporaryDirectory() as tmpdir:
            parser = JavaMavenParser(Path(tmpdir))
            assert parser.ecosystem == "maven"

    def test_parse_pom_xml_simple(self):
        """Test parsing simple pom.xml without namespaces."""
        pom_content = """<?xml version="1.0"?>
<project>
  <dependencies>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
  </dependencies>
</project>
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir)
            (project_path / "pom.xml").write_text(pom_content)

            parser = JavaMavenParser(project_path)
            deps = parser.parse(include_dev=False)

            assert isinstance(deps, list)
            assert all(d.ecosystem == "maven" for d in deps)


class TestGoModParser:
    """Tests for GoModParser."""

    def test_can_parse_with_go_mod(self):
        """Test detection of go.mod."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir)
            (project_path / "go.mod").write_text("")

            parser = GoModParser(project_path)
            assert parser.can_parse()

    def test_parse_go_mod_single_line(self):
        """Test parsing go.mod with single-line require."""
        go_mod_content = """module github.com/example/app

go 1.19

require github.com/gorilla/mux v1.8.0
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir)
            (project_path / "go.mod").write_text(go_mod_content)

            parser = GoModParser(project_path)
            deps = parser.parse(include_dev=False)

            assert len(deps) == 1
            assert deps[0].name == "github.com/gorilla/mux"
            assert deps[0].version == "v1.8.0"
            assert deps[0].ecosystem == "go"

    def test_parse_go_mod_with_require_block(self):
        """Test parsing go.mod with require block."""
        go_mod_content = """module github.com/example/app

go 1.19

require (
    github.com/gorilla/mux v1.8.0
    github.com/lib/pq v1.10.9
)
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir)
            (project_path / "go.mod").write_text(go_mod_content)

            parser = GoModParser(project_path)
            deps = parser.parse(include_dev=False)

            assert len(deps) == 2
            names = {d.name for d in deps}
            assert "github.com/gorilla/mux" in names
            assert "github.com/lib/pq" in names

    def test_ecosystem_name(self):
        """Test that ecosystem name is correct."""
        with tempfile.TemporaryDirectory() as tmpdir:
            parser = GoModParser(Path(tmpdir))
            assert parser.ecosystem == "go"


class TestRustCargoParser:
    """Tests for RustCargoParser."""

    def test_can_parse_with_cargo_lock(self):
        """Test detection of Cargo.lock."""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir)
            (project_path / "Cargo.lock").write_text("")

            parser = RustCargoParser(project_path)
            assert parser.can_parse()

    def test_parse_cargo_lock(self):
        """Test parsing Cargo.lock."""
        cargo_lock_content = """# This file is automatically @generated by Cargo.
version = 3

[[package]]
name = "serde"
version = "1.0.152"

[[package]]
name = "tokio"
version = "1.25.0"

[[package]]
name = "my-app"
version = "0.1.0"
"""
        with tempfile.TemporaryDirectory() as tmpdir:
            project_path = Path(tmpdir)
            (project_path / "Cargo.lock").write_text(cargo_lock_content)

            parser = RustCargoParser(project_path)
            deps = parser.parse(include_dev=False)

            assert len(deps) >= 2
            names = {d.name for d in deps}
            assert "serde" in names
            assert "tokio" in names

    def test_ecosystem_name(self):
        """Test that ecosystem name is correct."""
        with tempfile.TemporaryDirectory() as tmpdir:
            parser = RustCargoParser(Path(tmpdir))
            assert parser.ecosystem == "rust"


class TestIncrementalScanCache:
    """Tests for IncrementalScanCache."""

    def test_cache_initialization(self):
        """Test cache directory creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            cache = IncrementalScanCache(cache_dir=Path(tmpdir) / ".lucius_cache")
            assert cache.cache_dir.exists()
            assert cache.manifest_file.name == "manifest.json"

    def test_file_hash_computation(self):
        """Test that file hashes are computed correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("test content")

            cache = IncrementalScanCache(cache_dir=Path(tmpdir) / ".cache")
            hash1 = cache._compute_file_hash(test_file)

            # Same content should produce same hash
            hash2 = cache._compute_file_hash(test_file)
            assert hash1 == hash2

            # Different content should produce different hash
            test_file.write_text("different content")
            hash3 = cache._compute_file_hash(test_file)
            assert hash1 != hash3

    def test_has_changed_new_file(self):
        """Test detection of new files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("content")

            cache = IncrementalScanCache(cache_dir=Path(tmpdir) / ".cache")

            # New file should be detected as changed
            assert cache.has_changed(test_file)

    def test_has_changed_unchanged_file(self):
        """Test that unchanged files are detected correctly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("content")

            cache = IncrementalScanCache(cache_dir=Path(tmpdir) / ".cache")

            # First scan
            assert cache.has_changed(test_file)

            # Second scan with same content
            assert not cache.has_changed(test_file)

    def test_has_changed_modified_file(self):
        """Test detection of modified files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("original content")

            cache = IncrementalScanCache(cache_dir=Path(tmpdir) / ".cache")

            # First scan
            assert cache.has_changed(test_file)

            # Modify file
            test_file.write_text("modified content")

            # Should detect change
            assert cache.has_changed(test_file)

    def test_manifest_persistence(self):
        """Test that manifest is persisted across cache instances."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = Path(tmpdir) / "test.txt"
            test_file.write_text("content")
            cache_dir = Path(tmpdir) / ".cache"

            # First instance
            cache1 = IncrementalScanCache(cache_dir=cache_dir)
            assert cache1.has_changed(test_file)

            # Second instance (should remember the hash)
            cache2 = IncrementalScanCache(cache_dir=cache_dir)
            assert not cache2.has_changed(test_file)

            # After modification
            test_file.write_text("new content")
            assert cache2.has_changed(test_file)
