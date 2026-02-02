"""Tests for secure credential management."""

import os
import tempfile
from pathlib import Path

import pytest

from shared.credentials import Credential, CredentialError, CredentialManager


class TestCredential:
    """Tests for Credential dataclass."""

    def test_credential_creation(self):
        """Test creating a credential."""
        cred = Credential(name="TEST_KEY", value="secret123", source="env")

        assert cred.name == "TEST_KEY"
        assert cred.value == "secret123"
        assert cred.source == "env"

    def test_credential_masking_short(self):
        """Test masking of short credentials."""
        cred = Credential(name="SHORT", value="abc", source="env")

        assert cred.masked_value == "***"

    def test_credential_masking_long(self):
        """Test masking of long credentials."""
        cred = Credential(
            name="LONG", value="pPwxyKMkHzHCeR4bBkBjp00yJkD32j6pDoyI6bBH1NI=", source="env"
        )

        # Should show first 3 and last 3 characters
        assert cred.masked_value.startswith("pPw")
        assert cred.masked_value.endswith("NI=")
        assert "..." in cred.masked_value

    def test_credential_string_representation(self):
        """Test string representation returns masked value."""
        cred = Credential(name="API_KEY", value="secret_value_here", source="file")

        assert str(cred) == cred.masked_value


class TestCredentialManager:
    """Tests for CredentialManager."""

    def test_init_without_env_file(self):
        """Test initialization when .env doesn't exist."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CredentialManager(env_file=Path(tmpdir) / ".env")
            assert manager.credentials == {}

    def test_load_env_file(self):
        """Test loading credentials from .env file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text(
                """
NVD_API_KEY=nvd_test_key
TALON_API_KEY=talon_test_key
EMPTY_KEY=
# Comment line
COMMENTED_KEY=should_not_load
"""
            )

            manager = CredentialManager(env_file=env_file)

            assert "NVD_API_KEY" in manager.credentials
            assert manager.get_secret("NVD_API_KEY") == "nvd_test_key"
            assert "TALON_API_KEY" in manager.credentials
            assert "EMPTY_KEY" not in manager.credentials

    def test_env_overrides_file(self):
        """Test that environment variables override .env file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("NVD_API_KEY=file_value")

            # Set environment variable
            os.environ["NVD_API_KEY"] = "env_value"

            try:
                manager = CredentialManager(env_file=env_file)
                # Environment should override file
                assert manager.get_secret("NVD_API_KEY") == "env_value"
            finally:
                del os.environ["NVD_API_KEY"]

    def test_get_secret_found(self):
        """Test retrieving an existing secret."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("API_KEY=secret_value")

            manager = CredentialManager(env_file=env_file)
            assert manager.get_secret("API_KEY") == "secret_value"

    def test_get_secret_not_found_optional(self):
        """Test retrieving a missing optional secret."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CredentialManager(env_file=Path(tmpdir) / ".env")

            result = manager.get_secret("MISSING_KEY", required=False)
            assert result is None

    def test_get_secret_not_found_required(self):
        """Test retrieving a missing required secret raises error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CredentialManager(env_file=Path(tmpdir) / ".env")

            with pytest.raises(CredentialError) as exc_info:
                manager.get_secret("MISSING_KEY", required=True)

            assert "MISSING_KEY" in str(exc_info.value)

    def test_get_secret_with_default(self):
        """Test retrieving secret with default value."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CredentialManager(env_file=Path(tmpdir) / ".env")

            result = manager.get_secret("MISSING_KEY", default="default_value")
            assert result == "default_value"

    def test_get_secrets_for_component(self):
        """Test retrieving all secrets for a component."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text(
                """
NVD_API_KEY=nvd_key
TALON_API_URL=http://localhost:5000
TALON_API_KEY=talon_key
"""
            )

            manager = CredentialManager(env_file=env_file)
            nvd_secrets = manager.get_secrets("nvd")

            assert "NVD_API_KEY" in nvd_secrets
            assert nvd_secrets["NVD_API_KEY"] == "nvd_key"

    def test_validate_required_all_present(self):
        """Test validation when all required credentials are present."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text(
                """
NVD_API_KEY=nvd_key
TALON_API_URL=http://localhost:5000
TALON_API_KEY=talon_key
HACKERONE_API_KEY=h1_key
GITHUB_TOKEN=github_token
"""
            )

            manager = CredentialManager(env_file=env_file)
            missing = manager.validate_required()

            # All required should be present, so list should be short
            assert len(missing) == 0

    def test_validate_required_missing(self):
        """Test validation detects missing required credentials."""
        with tempfile.TemporaryDirectory() as tmpdir:
            manager = CredentialManager(env_file=Path(tmpdir) / ".env")
            missing = manager.validate_required()

            # Should have missing credentials
            assert len(missing) > 0
            assert any("NVD_API_KEY" in m for m in missing)

    def test_audit_log_masked(self):
        """Test audit log contains masked credentials."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("API_KEY=pPwxyKMkHzHCeR4bBkBjp00yJkD32j6pDoyI6bBH1NI=")

            manager = CredentialManager(env_file=env_file)
            audit = manager.audit_log()

            assert "API_KEY" in audit
            assert "pPw...NI=" in audit["API_KEY"]["masked"]
            assert "source" in audit["API_KEY"]
            assert "hash" in audit["API_KEY"]

    def test_audit_log_no_plain_values(self):
        """Test audit log never contains plain credential values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            secret_value = "super_secret_password_12345"
            env_file.write_text(f"SECRET={secret_value}")

            manager = CredentialManager(env_file=env_file)
            audit_str = str(manager.audit_log())

            # Plain value should not appear in audit
            assert secret_value not in audit_str

    def test_repr_masked(self):
        """Test __repr__ doesn't expose secrets."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text("SECRET_API_KEY=super_secret_value")

            manager = CredentialManager(env_file=env_file)
            repr_str = repr(manager)

            # Should not contain plain secret
            assert "super_secret_value" not in repr_str
            # Should indicate credentials were loaded
            assert "CredentialManager" in repr_str

    def test_strip_quotes_from_env_values(self):
        """Test that quotes are stripped from .env values."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text(
                """
DOUBLE_QUOTED="value_with_quotes"
SINGLE_QUOTED='value_with_single'
NO_QUOTES=plain_value
"""
            )

            manager = CredentialManager(env_file=env_file)

            assert manager.get_secret("DOUBLE_QUOTED") == "value_with_quotes"
            assert manager.get_secret("SINGLE_QUOTED") == "value_with_single"
            assert manager.get_secret("NO_QUOTES") == "plain_value"

    def test_multiline_env_file(self):
        """Test handling of multiline .env file with comments."""
        with tempfile.TemporaryDirectory() as tmpdir:
            env_file = Path(tmpdir) / ".env"
            env_file.write_text(
                """
# Database Configuration
DATABASE_URL=postgresql://localhost/db

# API Keys
NVD_API_KEY=nvd_key
GITHUB_TOKEN=gh_token

# Comments should be ignored
# COMMENTED_KEY=ignored

VALID_KEY=kept
"""
            )

            manager = CredentialManager(env_file=env_file)

            assert manager.get_secret("DATABASE_URL") == "postgresql://localhost/db"
            assert manager.get_secret("NVD_API_KEY") == "nvd_key"
            assert "COMMENTED_KEY" not in manager.credentials
            assert manager.get_secret("VALID_KEY") == "kept"
