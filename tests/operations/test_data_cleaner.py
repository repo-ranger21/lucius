"""Tests for data cleaner service."""

import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class TestDataCleaner:
    """Test cases for DataCleaner."""

    @pytest.fixture
    def cleaner(self):
        """Create data cleaner instance."""
        ops_pkg = types.ModuleType("operations")
        ops_pkg.__path__ = [str(ROOT / "operations")]
        sys.modules["operations"] = ops_pkg
        from operations.services.data_cleaner import DataCleaner

        return DataCleaner()

    def test_clean_ein_valid(self, cleaner):
        """Test EIN cleaning with valid formats."""
        # Standard format
        assert cleaner._clean_ein("12-3456789") == "12-3456789"

        # No hyphen
        assert cleaner._clean_ein("123456789") == "12-3456789"

        # With spaces
        assert cleaner._clean_ein("12 3456789") == "12-3456789"

    def test_clean_ein_invalid(self, cleaner):
        """Test EIN cleaning with invalid formats."""
        # Too short
        assert cleaner._clean_ein("12345") is None

        # Too long
        assert cleaner._clean_ein("1234567890") is None

        # Empty
        assert cleaner._clean_ein("") is None

        # Non-numeric
        assert cleaner._clean_ein("AB-CDEFGHI") is None

    def test_clean_phone_valid(self, cleaner):
        """Test phone cleaning with valid formats."""
        # 10 digits
        assert cleaner._clean_phone("5551234567") == "(555) 123-4567"

        # With country code
        assert cleaner._clean_phone("15551234567") == "(555) 123-4567"

        # Formatted
        assert cleaner._clean_phone("(555) 123-4567") == "(555) 123-4567"

        # Dashes
        assert cleaner._clean_phone("555-123-4567") == "(555) 123-4567"

    def test_clean_phone_invalid(self, cleaner):
        """Test phone cleaning with invalid formats."""
        # Too short
        assert cleaner._clean_phone("123456") is None

        # Empty
        assert cleaner._clean_phone("") is None

    def test_clean_email_valid(self, cleaner):
        """Test email cleaning with valid formats."""
        assert cleaner._clean_email("test@example.com") == "test@example.com"
        assert cleaner._clean_email("TEST@EXAMPLE.COM") == "test@example.com"
        assert cleaner._clean_email("  test@example.com  ") == "test@example.com"

    def test_clean_email_invalid(self, cleaner):
        """Test email cleaning with invalid formats."""
        assert cleaner._clean_email("notanemail") is None
        assert cleaner._clean_email("missing@domain") is None
        assert cleaner._clean_email("") is None

    def test_clean_url_valid(self, cleaner):
        """Test URL cleaning with valid formats."""
        assert cleaner._clean_url("https://example.com") == "https://example.com"
        assert cleaner._clean_url("http://example.com") == "http://example.com"
        assert cleaner._clean_url("example.com") == "https://example.com"

    def test_clean_url_invalid(self, cleaner):
        """Test URL cleaning with invalid formats."""
        assert cleaner._clean_url("") is None
        assert cleaner._clean_url("not a url") is None

    def test_clean_name(self, cleaner):
        """Test organization name cleaning."""
        assert cleaner._clean_name("example nonprofit inc") == "Example Nonprofit Inc"
        assert cleaner._clean_name("  extra   spaces  ") == "Extra Spaces"
        assert cleaner._clean_name("ABC CORP") == "Abc Corp"

    def test_standardize_column_name(self, cleaner):
        """Test column name standardization."""
        assert cleaner._standardize_column_name("Organization Name") == "organization_name"
        assert cleaner._standardize_column_name("EIN/Tax ID") == "ein/tax_id"
        assert cleaner._standardize_column_name("Phone Number") == "phone_number"

    def test_calculate_quality_score(self, cleaner):
        """Test data quality score calculation."""
        import pandas as pd

        # High quality row
        high_quality = pd.Series(
            {
                "organization_name": "Test Org",
                "ein": "12-3456789",
                "email": "test@example.com",
                "phone": "(555) 123-4567",
                "website": "https://example.com",
                "street": "123 Main St",
                "city": "New York",
                "state": "NY",
                "zip": "10001",
                "mission_statement": "Our mission is to help.",
            }
        )

        score = cleaner._calculate_quality_score(high_quality)
        assert score > 80  # Should be high quality

    def test_validate_row_valid(self, cleaner):
        """Test row validation with valid data."""
        import pandas as pd

        valid_row = pd.Series(
            {
                "ein": "12-3456789",
                "organization_name": "Valid Organization",
                "email": "valid@example.com",
                "phone": "(555) 123-4567",
                "website": "https://example.com",
            }
        )

        # _validate_row returns bool and uses idx parameter
        assert cleaner._validate_row(valid_row.to_dict(), 0) is True

    def test_validate_row_invalid(self, cleaner):
        """Test row validation with invalid data."""
        import pandas as pd

        invalid_row = pd.Series(
            {
                "ein": "invalid",
                "organization_name": "",
                "email": "bademail",
                "phone": "123",
                "website": "not a url",
            }
        )

        # _validate_row returns bool and uses idx parameter
        assert cleaner._validate_row(invalid_row.to_dict(), 0) is False


class TestFileOperations:
    """Test file reading and writing operations."""

    def test_read_csv(self):
        """Test reading CSV files."""
        pass  # Would test actual file operations with fixtures

    def test_read_json(self):
        """Test reading JSON files."""
        pass

    def test_read_excel(self):
        """Test reading Excel files."""
        pass

    def test_write_csv(self):
        """Test writing CSV files."""
        pass

    def test_write_json(self):
        """Test writing JSON files."""
        pass
