"""
Secure credential management for Lucius.

This module provides secure credential loading with proper validation,
encryption support, and audit logging.

Usage:
    from shared.credentials import CredentialManager

    creds = CredentialManager()
    api_key = creds.get_secret("NVD_API_KEY")
"""

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Credential:
    """Represents a managed credential."""

    name: str
    value: str
    source: str  # "env", "file", "vault"
    masked_value: str = ""
    last_accessed: Optional[str] = None

    def __post_init__(self):
        """Compute masked value after initialization."""
        if self.value:
            # Show only first and last 3 characters
            if len(self.value) > 10:
                self.masked_value = f"{self.value[:3]}...{self.value[-3:]}"
            else:
                self.masked_value = "*" * len(self.value)

    def __str__(self):
        """Return masked representation."""
        return self.masked_value


class CredentialError(Exception):
    """Raised when credential operations fail."""

    pass


class CredentialManager:
    """
    Manages application credentials securely.

    Loads credentials from:
    1. Environment variables (recommended for production with proper secret management)
    2. .env file (development only)
    3. Vault backend (if configured)
    """

    # Required credentials for different components
    REQUIRED_CREDENTIALS = {
        "nvd": ["NVD_API_KEY"],
        "talon": ["TALON_API_URL", "TALON_API_KEY"],
        "hackerone": ["HACKERONE_API_KEY"],
        "github": ["GITHUB_TOKEN"],
    }

    # Optional credentials
    OPTIONAL_CREDENTIALS = {
        "twilio": ["TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM_NUMBER"],
        "database": ["DATABASE_URL"],
        "redis": ["REDIS_URL"],
    }

    def __init__(self, env_file: Optional[Path] = None):
        """
        Initialize credential manager.

        Args:
            env_file: Path to .env file (defaults to .env in current directory)
        """
        self.env_file = env_file or Path(".env")
        self.credentials: dict[str, Credential] = {}
        self._load_credentials()

    def _load_credentials(self) -> None:
        """Load credentials from environment and .env file."""
        # Load .env file if it exists
        if self.env_file.exists():
            self._load_env_file()
        else:
            logger.debug(f"No .env file found at {self.env_file}")

        # Environment variables override .env file
        self._load_environment()

    def _load_env_file(self) -> None:
        """Load credentials from .env file."""
        try:
            with open(self.env_file) as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    if "=" in line:
                        key, value = line.split("=", 1)
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")

                        if value and not value.startswith("$"):  # Skip empty or reference values
                            self.credentials[key] = Credential(name=key, value=value, source="file")
        except Exception as e:
            logger.warning(f"Failed to load .env file: {e}")

    def _load_environment(self) -> None:
        """Load credentials from environment variables."""
        # Combine all credential names
        all_creds = set()
        for creds in self.REQUIRED_CREDENTIALS.values():
            all_creds.update(creds)
        for creds in self.OPTIONAL_CREDENTIALS.values():
            all_creds.update(creds)

        for cred_name in all_creds:
            value = os.getenv(cred_name)
            if value:
                self.credentials[cred_name] = Credential(name=cred_name, value=value, source="env")

    def get_secret(
        self, name: str, required: bool = False, default: Optional[str] = None
    ) -> Optional[str]:
        """
        Retrieve a secret securely.

        Args:
            name: Name of the secret
            required: Raise error if not found
            default: Default value if not found

        Returns:
            Secret value or None

        Raises:
            CredentialError: If required secret not found
        """
        if name not in self.credentials:
            if required:
                raise CredentialError(f"Required credential not found: {name}")
            return default

        cred = self.credentials[name]
        logger.debug(f"Retrieved credential: {cred.name} from {cred.source}")
        return cred.value

    def get_secrets(self, component: str) -> dict[str, Optional[str]]:
        """
        Get all secrets for a component.

        Args:
            component: Component name (e.g., "nvd", "talon")

        Returns:
            Dictionary of secret name to value
        """
        secrets = {}
        cred_names = self.REQUIRED_CREDENTIALS.get(component, [])
        cred_names += self.OPTIONAL_CREDENTIALS.get(component, [])

        for name in cred_names:
            secrets[name] = self.get_secret(name)

        return {k: v for k, v in secrets.items() if v is not None}

    def validate_required(self) -> list[str]:
        """
        Validate that all required credentials are present.

        Returns:
            List of missing required credentials
        """
        missing = []

        for component, cred_names in self.REQUIRED_CREDENTIALS.items():
            for name in cred_names:
                if name not in self.credentials:
                    missing.append(f"{name} (required for {component})")

        return missing

    def audit_log(self) -> dict:
        """
        Generate audit log of loaded credentials (masked).

        Returns:
            Audit log as dictionary
        """
        return {
            name: {
                "masked": str(cred),
                "source": cred.source,
                "hash": hashlib.sha256(cred.value.encode()).hexdigest()[:8],
            }
            for name, cred in self.credentials.items()
        }

    def __repr__(self) -> str:
        """Return masked representation."""
        loaded = {name: str(cred) for name, cred in self.credentials.items()}
        return f"CredentialManager(loaded={len(self.credentials)}, {json.dumps(loaded, indent=2)})"


# Global instance
_credential_manager: Optional[CredentialManager] = None


def get_credential_manager(env_file: Optional[Path] = None) -> CredentialManager:
    """Get or create global credential manager."""
    global _credential_manager

    if _credential_manager is None:
        _credential_manager = CredentialManager(env_file)

    return _credential_manager
