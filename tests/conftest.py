"""Pytest configuration and fixtures."""

import os
import sys
from pathlib import Path

import pytest

# Add project root to path
PROJECT_ROOT = Path(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, str(PROJECT_ROOT))


@pytest.fixture
def sample_package_lock():
    """Sample package-lock.json content."""
    return {
        "name": "test-app",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "test-app", "version": "1.0.0"},
            "node_modules/lodash": {
                "version": "4.17.21",
                "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz",
            },
            "node_modules/express": {
                "version": "4.18.2",
                "resolved": "https://registry.npmjs.org/express/-/express-4.18.2.tgz",
            },
        },
    }


@pytest.fixture
def sample_requirements():
    """Sample requirements.txt content."""
    return """# Requirements
flask==2.3.0
requests>=2.28.0,<3.0.0
sqlalchemy[asyncio]==2.0.0
# Comment
pytest  # inline comment
"""


@pytest.fixture
def sample_composer_lock():
    """Sample composer.lock content."""
    return {
        "packages": [
            {"name": "vendor/package1", "version": "1.0.0"},
            {"name": "vendor/package2", "version": "2.1.0"},
        ],
        "packages-dev": [{"name": "vendor/dev-package", "version": "3.0.0"}],
    }


@pytest.fixture
def sample_vulnerability():
    """Sample NVD vulnerability response."""
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2023-12345",
                    "sourceIdentifier": "security@example.com",
                    "published": "2023-01-15T10:00:00.000",
                    "lastModified": "2023-01-20T15:30:00.000",
                    "descriptions": [{"lang": "en", "value": "Test vulnerability description"}],
                    "metrics": {
                        "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}}]
                    },
                    "references": [{"url": "https://example.com/advisory", "source": "example"}],
                }
            }
        ]
    }
