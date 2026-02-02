"""Data cleaning service for nonprofit data."""

import re
from datetime import datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

try:
    import pandas as pd
except ModuleNotFoundError:  # pragma: no cover - optional dependency for tests
    pd = None
try:
    from email_validator import EmailNotValidError, validate_email
except ModuleNotFoundError:  # pragma: no cover - optional dependency for tests

    class EmailNotValidError(ValueError):
        """Fallback error when email_validator is unavailable."""

    def validate_email(email: str, *args, **kwargs):
        """Minimal fallback email validation."""
        if not isinstance(email, str):
            raise EmailNotValidError("Invalid email")
        if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email.strip()):
            raise EmailNotValidError("Invalid email")
        return {"email": email.strip()}


from shared.logging import get_logger

try:
    from ..models import NonprofitData
except ModuleNotFoundError:  # pragma: no cover - optional dependency for tests
    NonprofitData = None

logger = get_logger(__name__)


class DataCleaner:
    """Service for cleaning and validating nonprofit data."""

    # Common fields mapping
    FIELD_MAPPINGS = {
        "ein": ["ein", "tax_id", "taxid", "employer_id", "irs_ein"],
        "organization_name": [
            "name",
            "org_name",
            "organization",
            "legal_name",
            "organization_name",
        ],
        "dba_name": ["dba", "dba_name", "doing_business_as", "trade_name"],
        "phone": ["phone", "telephone", "phone_number", "contact_phone"],
        "email": ["email", "contact_email", "email_address"],
        "website": ["website", "url", "web", "homepage"],
        "address_line1": ["address", "street", "address1", "street_address", "address_line1"],
        "city": ["city", "locality"],
        "state": ["state", "province", "region"],
        "zip_code": ["zip", "zipcode", "zip_code", "postal_code", "postal"],
        "mission_statement": ["mission", "mission_statement", "purpose"],
        "ntee_code": ["ntee", "ntee_code", "classification"],
        "asset_amount": ["assets", "total_assets", "asset_amount"],
        "income_amount": ["income", "gross_income", "income_amount"],
        "revenue_amount": ["revenue", "gross_revenue", "total_revenue", "revenue_amount"],
    }

    def __init__(self):
        self.issues: list[str] = []

    def clean_file(
        self,
        input_path: Path,
        output_path: Path,
        output_format: str = "csv",
    ) -> dict[str, Any]:
        """
        Clean a data file and save results.

        Args:
            input_path: Path to input file
            output_path: Path to output file
            output_format: Output format (csv, json, excel)

        Returns:
            Cleaning summary
        """
        self.issues = []

        # Read input file
        df = self._read_file(input_path)
        original_count = len(df)

        # Normalize column names
        df = self._normalize_columns(df)

        # Clean each row
        cleaned_rows = []
        invalid_rows = []

        for idx, row in df.iterrows():
            cleaned = self._clean_row(row.to_dict(), idx)
            if cleaned:
                cleaned_rows.append(cleaned)
            else:
                invalid_rows.append(idx)

        # Create output DataFrame
        cleaned_df = pd.DataFrame(cleaned_rows)

        # Save output
        self._save_file(cleaned_df, output_path, output_format)

        return {
            "total_records": original_count,
            "valid_records": len(cleaned_rows),
            "invalid_records": len(invalid_rows),
            "issues": self.issues,
        }

    def validate_file(self, input_path: Path) -> dict[str, Any]:
        """
        Validate a data file without modifying.

        Args:
            input_path: Path to input file

        Returns:
            Validation results
        """
        self.issues = []

        df = self._read_file(input_path)
        df = self._normalize_columns(df)

        valid = 0
        invalid = 0

        for idx, row in df.iterrows():
            if self._validate_row(row.to_dict(), idx):
                valid += 1
            else:
                invalid += 1

        total = valid + invalid
        quality_score = (valid / total * 100) if total > 0 else 0

        return {
            "total": total,
            "valid": valid,
            "invalid": invalid,
            "quality_score": quality_score,
            "issues": self.issues,
        }

    def import_to_database(
        self,
        session,
        input_path: Path,
        clean_first: bool = True,
    ) -> dict[str, Any]:
        """
        Import data into database.

        Args:
            session: Database session
            input_path: Path to input file
            clean_first: Whether to clean data before importing

        Returns:
            Import summary
        """
        self.issues = []

        df = self._read_file(input_path)
        df = self._normalize_columns(df)

        imported = 0
        updated = 0
        skipped = 0

        for idx, row in df.iterrows():
            row_dict = row.to_dict()

            if clean_first:
                row_dict = self._clean_row(row_dict, idx)
                if not row_dict:
                    skipped += 1
                    continue

            # Check if EIN already exists
            ein = row_dict.get("ein")
            existing = None
            if ein:
                existing = session.query(NonprofitData).filter_by(ein=ein).first()

            if existing:
                # Update existing record
                self._update_nonprofit(existing, row_dict)
                updated += 1
            else:
                # Create new record
                nonprofit = self._create_nonprofit(row_dict)
                session.add(nonprofit)
                imported += 1

        session.flush()

        return {
            "imported": imported,
            "updated": updated,
            "skipped": skipped,
            "issues": self.issues,
        }

    def _read_file(self, path: Path):
        """Read data from various file formats."""
        if pd is None:
            raise ImportError("pandas is required to read input files")
        suffix = path.suffix.lower()

        if suffix == ".csv":
            return pd.read_csv(path, dtype=str, na_values=["", "N/A", "n/a", "null"])
        elif suffix in (".xlsx", ".xls"):
            return pd.read_excel(path, dtype=str, na_values=["", "N/A", "n/a", "null"])
        elif suffix == ".json":
            return pd.read_json(path, dtype=str)
        else:
            raise ValueError(f"Unsupported file format: {suffix}")

    def _save_file(self, df, path: Path, format: str) -> None:
        """Save DataFrame to file."""
        if pd is None:
            raise ImportError("pandas is required to save output files")
        if format == "csv":
            df.to_csv(path, index=False)
        elif format == "json":
            df.to_json(path, orient="records", indent=2)
        elif format == "excel":
            df.to_excel(path, index=False)

    def _normalize_columns(self, df):
        """Normalize column names to standard format."""
        # Lowercase and strip whitespace
        df.columns = df.columns.str.lower().str.strip().str.replace(" ", "_")

        # Map to standard names
        column_map = {}
        for standard_name, aliases in self.FIELD_MAPPINGS.items():
            for alias in aliases:
                if alias in df.columns:
                    column_map[alias] = standard_name
                    break

        return df.rename(columns=column_map)

    def _clean_row(self, row: dict[str, Any], idx: int) -> dict[str, Any] | None:
        """Clean a single row of data."""
        cleaned = {}

        # Clean EIN
        ein = self._clean_ein(row.get("ein"))
        if ein:
            cleaned["ein"] = ein

        # Organization name (required)
        org_name = self._clean_text(row.get("organization_name"))
        if not org_name:
            self.issues.append(f"Row {idx}: Missing organization name")
            return None
        cleaned["organization_name"] = org_name

        # DBA name
        dba = self._clean_text(row.get("dba_name"))
        if dba:
            cleaned["dba_name"] = dba

        # Phone
        phone = self._clean_phone(row.get("phone"))
        if phone:
            cleaned["phone"] = phone

        # Email
        email = self._clean_email(row.get("email"))
        if email:
            cleaned["email"] = email
        elif row.get("email"):
            self.issues.append(f"Row {idx}: Invalid email: {row.get('email')}")

        # Website
        website = self._clean_url(row.get("website"))
        if website:
            cleaned["website"] = website

        # Address
        address = self._clean_address(row)
        if address:
            cleaned["address"] = address

        # Mission statement
        mission = self._clean_text(row.get("mission_statement"))
        if mission:
            cleaned["mission_statement"] = mission[:2000]  # Limit length

        # NTEE code
        ntee = self._clean_text(row.get("ntee_code"))
        if ntee:
            cleaned["ntee_code"] = ntee[:10]

        # Financial amounts
        for field in ["asset_amount", "income_amount", "revenue_amount"]:
            amount = self._clean_amount(row.get(field))
            if amount is not None:
                cleaned[field] = amount

        # Quality score
        cleaned["data_quality_score"] = self._calculate_quality_score(cleaned)
        cleaned["cleaned_at"] = datetime.utcnow()
        cleaned["raw_data"] = {k: str(v) for k, v in row.items() if v}

        return cleaned

    def _validate_row(self, row: dict[str, Any], idx: int) -> bool:
        """Validate a row without cleaning."""
        valid = True

        # Check required fields
        if not row.get("organization_name"):
            self.issues.append(f"Row {idx}: Missing organization name")
            valid = False

        # Validate email if present
        email = row.get("email")
        if email and not self._is_valid_email(email):
            self.issues.append(f"Row {idx}: Invalid email: {email}")
            valid = False

        # Validate EIN if present
        ein = row.get("ein")
        if ein and not self._is_valid_ein(ein):
            self.issues.append(f"Row {idx}: Invalid EIN: {ein}")
            valid = False

        return valid

    def _clean_ein(self, value: Any) -> str | None:
        """Clean and validate EIN."""
        if not value:
            return None

        # Remove non-digits
        ein = re.sub(r"[^\d]", "", str(value))

        # EIN should be 9 digits
        if len(ein) == 9:
            return f"{ein[:2]}-{ein[2:]}"

        return None

    def _is_valid_ein(self, value: str) -> bool:
        """Check if EIN is valid."""
        ein = re.sub(r"[^\d]", "", str(value))
        return len(ein) == 9

    def _clean_text(self, value: Any) -> str | None:
        """Clean text field."""
        if not value or (pd is not None and pd.isna(value)):
            return None

        text = str(value).strip()

        # Remove excessive whitespace
        text = re.sub(r"\s+", " ", text)

        return text if text else None

    def _clean_name(self, name: str | None) -> str:
        """Clean organization name by capitalizing properly."""
        if not name or not isinstance(name, str):
            return ""
        # Clean whitespace first
        cleaned = self._clean_text(name)
        if not cleaned:
            return ""
        # Capitalize each word
        return " ".join(word.capitalize() for word in cleaned.split())

    def _standardize_column_name(self, column_name: str) -> str:
        """Convert column name to lowercase snake_case format.

        Example: "Organization Name" -> "organization_name"
        """
        if not column_name:
            return ""
        # Replace spaces with underscores and convert to lowercase
        return column_name.strip().replace(" ", "_").lower()

    def _clean_phone(self, value: Any) -> str | None:
        """Clean and format phone number."""
        if not value or (pd is not None and pd.isna(value)):
            return None

        try:
            import phonenumbers

            # Try to parse as US number
            phone = phonenumbers.parse(str(value), "US")

            if phonenumbers.is_valid_number(phone):
                return phonenumbers.format_number(phone, phonenumbers.PhoneNumberFormat.NATIONAL)
        except Exception:
            pass

        # Fallback: just extract digits
        digits = re.sub(r"[^\d]", "", str(value))
        if len(digits) == 10:
            return f"({digits[:3]}) {digits[3:6]}-{digits[6:]}"
        elif len(digits) == 11 and digits.startswith("1"):
            return f"({digits[1:4]}) {digits[4:7]}-{digits[7:]}"

        return None

    def _clean_email(self, value: Any) -> str | None:
        """Clean and validate email."""
        if not value or (pd is not None and pd.isna(value)):
            return None

        email = str(value).strip().lower()

        try:
            valid = validate_email(email, check_deliverability=False)
            if isinstance(valid, dict):
                return valid.get("email") or email
            return getattr(valid, "email", None) or email
        except EmailNotValidError:
            return None

    def _is_valid_email(self, value: str) -> bool:
        """Check if email is valid."""
        try:
            validate_email(value.strip(), check_deliverability=False)
            return True
        except EmailNotValidError:
            return False

    def _clean_url(self, value: Any) -> str | None:
        """Clean and validate URL."""
        if not value or (pd is not None and pd.isna(value)):
            return None

        url = str(value).strip().lower()

        # Add protocol if missing
        if url and not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        # Basic URL validation
        url_pattern = re.compile(
            r"^https?://"
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|"
            r"localhost|"
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
            r"(?::\d+)?"
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )

        return url if url_pattern.match(url) else None

    def _clean_address(self, row: dict[str, Any]) -> dict[str, str] | None:
        """Clean and structure address."""
        address = {}

        line1 = self._clean_text(row.get("address_line1"))
        if line1:
            address["line1"] = line1

        city = self._clean_text(row.get("city"))
        if city:
            address["city"] = city.title()

        state = self._clean_text(row.get("state"))
        if state:
            # Normalize state to abbreviation
            address["state"] = state.upper()[:2]

        zip_code = self._clean_text(row.get("zip_code"))
        if zip_code:
            # Extract 5-digit zip
            match = re.search(r"\d{5}", str(zip_code))
            if match:
                address["zip_code"] = match.group()

        return address if address else None

    def _clean_amount(self, value: Any) -> Decimal | None:
        """Clean monetary amount."""
        if not value or pd.isna(value):
            return None

        # Remove currency symbols and commas
        cleaned = re.sub(r"[^\d.-]", "", str(value))

        try:
            amount = Decimal(cleaned)
            return amount if amount >= 0 else None
        except Exception:
            return None

    def _calculate_quality_score(self, data: dict[str, Any]) -> float:
        """Calculate data quality score (0-100)."""
        fields = [
            "ein",
            "organization_name",
            "phone",
            "email",
            "website",
            "mission_statement",
            "ntee_code",
        ]

        address_present = any(
            data.get(key)
            for key in (
                "address",
                "address_line1",
                "street",
                "city",
                "state",
                "zip",
                "zip_code",
            )
        )

        present = sum(1 for f in fields if data.get(f))
        if address_present:
            present += 1
        total_fields = len(fields) + 1
        return round((present / total_fields) * 100, 2)

    def _create_nonprofit(self, data: dict[str, Any]) -> NonprofitData:
        """Create NonprofitData instance from cleaned data."""
        if NonprofitData is None:
            raise ImportError("operations.models is required to create nonprofit records")
        return NonprofitData(
            ein=data.get("ein"),
            organization_name=data["organization_name"],
            dba_name=data.get("dba_name"),
            address=data.get("address", {}),
            phone=data.get("phone"),
            email=data.get("email"),
            website=data.get("website"),
            mission_statement=data.get("mission_statement"),
            ntee_code=data.get("ntee_code"),
            asset_amount=data.get("asset_amount"),
            income_amount=data.get("income_amount"),
            revenue_amount=data.get("revenue_amount"),
            data_quality_score=data.get("data_quality_score"),
            raw_data=data.get("raw_data", {}),
            cleaned_at=data.get("cleaned_at"),
        )

    def _update_nonprofit(self, nonprofit: NonprofitData, data: dict[str, Any]) -> None:
        """Update existing nonprofit with new data."""
        if NonprofitData is None:
            raise ImportError("operations.models is required to update nonprofit records")
        for field in [
            "dba_name",
            "phone",
            "email",
            "website",
            "mission_statement",
            "ntee_code",
            "asset_amount",
            "income_amount",
            "revenue_amount",
        ]:
            if data.get(field):
                setattr(nonprofit, field, data[field])

        if data.get("address"):
            nonprofit.address = data["address"]

        nonprofit.data_quality_score = data.get("data_quality_score")
        nonprofit.cleaned_at = datetime.utcnow()
        nonprofit.cleaned_at = datetime.utcnow()
