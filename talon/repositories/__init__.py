"""Repository layer for Talon data access."""

from talon.repositories.base import BaseRepository
from talon.repositories.scan_repository import ScanRepository
from talon.repositories.vulnerability_repository import VulnerabilityRepository

__all__ = [
    "BaseRepository",
    "VulnerabilityRepository",
    "ScanRepository",
]
