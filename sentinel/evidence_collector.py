"""Evidence collection and management for security findings."""

import hashlib
import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Optional

from shared.logging import get_logger

logger = get_logger(__name__)


class EvidenceType(str, Enum):
    """Types of security evidence."""

    SCREENSHOT = "screenshot"
    LOG_FILE = "log_file"
    NETWORK_TRAFFIC = "network_traffic"
    SOURCE_CODE = "source_code"
    API_RESPONSE = "api_response"
    ERROR_MESSAGE = "error_message"
    CONFIGURATION = "configuration"
    EXPLOIT_RESULT = "exploit_result"
    TOOL_OUTPUT = "tool_output"
    METADATA = "metadata"


class EvidenceSensitivity(str, Enum):
    """Sensitivity level of evidence."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class Evidence:
    """Represents a single piece of evidence for a finding."""

    def __init__(
        self,
        evidence_type: EvidenceType,
        content: str | bytes,
        description: str = "",
        sensitivity: EvidenceSensitivity = EvidenceSensitivity.INTERNAL,
        source: str = "",
        timestamp: Optional[datetime] = None,
        tags: Optional[list[str]] = None,
    ):
        """
        Initialize evidence.

        Args:
            evidence_type: Type of evidence
            content: Evidence content (text or binary)
            description: Human-readable description
            sensitivity: Sensitivity level
            source: Source of evidence (tool, URL, etc.)
            timestamp: When evidence was collected
            tags: Tags for categorization
        """
        self.evidence_type = evidence_type
        self.content = content if isinstance(content, bytes) else content.encode("utf-8")
        self.description = description
        self.sensitivity = sensitivity
        self.source = source
        self.timestamp = timestamp or datetime.utcnow()
        self.tags = tags or []
        self.hash = self._compute_hash()

    def _compute_hash(self) -> str:
        """Compute SHA256 hash of evidence content."""
        return hashlib.sha256(self.content).hexdigest()

    def to_dict(self, include_content: bool = False) -> dict[str, Any]:
        """Convert to dictionary (optionally including content)."""
        return {
            "type": self.evidence_type.value,
            "description": self.description,
            "sensitivity": self.sensitivity.value,
            "source": self.source,
            "timestamp": self.timestamp.isoformat(),
            "tags": self.tags,
            "hash": self.hash,
            "size_bytes": len(self.content),
            "content": (
                self.content.decode("utf-8", errors="replace") if include_content else None
            ),
        }

    def redact_pii(self, patterns: Optional[list[str]] = None) -> "Evidence":
        """
        Create a redacted copy of evidence with PII removed.

        Args:
            patterns: List of regex patterns to redact

        Returns:
            New Evidence object with redacted content
        """
        import re

        content = self.content.decode("utf-8", errors="replace")

        # Default PII patterns
        if patterns is None:
            patterns = [
                r"\b\d{3}-\d{2}-\d{4}\b",  # SSN
                r"\b\d{16}\b",  # Credit card
                r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",  # Email
                r"\b(?:\d{1,3}\.){3}\d{1,3}\b",  # IP address
                r"password['\"]?\s*[:=]\s*['\"]?[^\s'\"]+",  # Password assignment
                r"api[_-]?key['\"]?\s*[:=]\s*['\"]?[^\s'\"]+",  # API key
                r"token['\"]?\s*[:=]\s*['\"]?[^\s'\"]+",  # Token
            ]

        for pattern in patterns:
            content = re.sub(pattern, "[REDACTED]", content, flags=re.IGNORECASE)

        redacted = Evidence(
            evidence_type=self.evidence_type,
            content=content,
            description=self.description + " [PII REDACTED]",
            sensitivity=EvidenceSensitivity.PUBLIC,
            source=self.source,
            timestamp=self.timestamp,
            tags=self.tags,
        )

        return redacted


class EvidenceCollection:
    """Manages a collection of evidence for a finding."""

    def __init__(
        self,
        finding_id: str,
        cve_id: str,
        description: str = "",
    ):
        """
        Initialize evidence collection.

        Args:
            finding_id: Unique identifier for the finding
            cve_id: Associated CVE ID
            description: Finding description
        """
        self.finding_id = finding_id
        self.cve_id = cve_id
        self.description = description
        self.evidence_list: list[Evidence] = []
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def add_evidence(self, evidence: Evidence) -> None:
        """Add evidence to collection."""
        self.evidence_list.append(evidence)
        self.updated_at = datetime.utcnow()
        logger.debug(f"Added {evidence.evidence_type.value} evidence to {self.finding_id}")

    def add_screenshot(
        self,
        content: bytes,
        description: str = "",
        tags: Optional[list[str]] = None,
    ) -> None:
        """Add a screenshot."""
        evidence = Evidence(
            evidence_type=EvidenceType.SCREENSHOT,
            content=content,
            description=description,
            tags=tags or [],
        )
        self.add_evidence(evidence)

    def add_log_file(
        self,
        content: str,
        description: str = "",
        source: str = "",
        tags: Optional[list[str]] = None,
    ) -> None:
        """Add a log file."""
        evidence = Evidence(
            evidence_type=EvidenceType.LOG_FILE,
            content=content,
            description=description,
            source=source,
            tags=tags or [],
        )
        self.add_evidence(evidence)

    def add_api_response(
        self,
        response_data: dict | str,
        description: str = "",
        url: str = "",
        tags: Optional[list[str]] = None,
    ) -> None:
        """Add an API response."""
        content = (
            json.dumps(response_data, indent=2)
            if isinstance(response_data, dict)
            else response_data
        )
        evidence = Evidence(
            evidence_type=EvidenceType.API_RESPONSE,
            content=content,
            description=description,
            source=url,
            tags=tags or [],
        )
        self.add_evidence(evidence)

    def add_error_message(
        self,
        error_text: str,
        description: str = "",
        source: str = "",
        tags: Optional[list[str]] = None,
    ) -> None:
        """Add an error message."""
        evidence = Evidence(
            evidence_type=EvidenceType.ERROR_MESSAGE,
            content=error_text,
            description=description,
            source=source,
            tags=tags or ["error-disclosure"],
        )
        self.add_evidence(evidence)

    def add_source_code(
        self,
        code: str,
        language: str = "",
        description: str = "",
        file_path: str = "",
        tags: Optional[list[str]] = None,
    ) -> None:
        """Add source code."""
        evidence = Evidence(
            evidence_type=EvidenceType.SOURCE_CODE,
            content=code,
            description=description or f"Source code ({language})",
            source=file_path,
            tags=tags or [language] if language else [],
        )
        self.add_evidence(evidence)

    def add_tool_output(
        self,
        output: str,
        tool_name: str = "",
        description: str = "",
        tags: Optional[list[str]] = None,
    ) -> None:
        """Add tool output."""
        evidence = Evidence(
            evidence_type=EvidenceType.TOOL_OUTPUT,
            content=output,
            description=description or f"Output from {tool_name}",
            source=tool_name,
            tags=tags or [],
        )
        self.add_evidence(evidence)

    def get_evidence_by_type(self, evidence_type: EvidenceType) -> list[Evidence]:
        """Get all evidence of a specific type."""
        return [e for e in self.evidence_list if e.evidence_type == evidence_type]

    def get_evidence_by_tag(self, tag: str) -> list[Evidence]:
        """Get all evidence with a specific tag."""
        return [e for e in self.evidence_list if tag in e.tags]

    def has_sensitive_evidence(self) -> bool:
        """Check if collection contains sensitive evidence."""
        return any(
            e.sensitivity in [EvidenceSensitivity.CONFIDENTIAL, EvidenceSensitivity.RESTRICTED]
            for e in self.evidence_list
        )

    def redact_all_pii(self) -> "EvidenceCollection":
        """Create a redacted copy with all PII removed."""
        redacted = EvidenceCollection(
            finding_id=self.finding_id,
            cve_id=self.cve_id,
            description=self.description,
        )

        for evidence in self.evidence_list:
            if evidence.sensitivity in [
                EvidenceSensitivity.INTERNAL,
                EvidenceSensitivity.CONFIDENTIAL,
                EvidenceSensitivity.RESTRICTED,
            ]:
                redacted_evidence = evidence.redact_pii()
            else:
                redacted_evidence = evidence

            redacted.add_evidence(redacted_evidence)

        return redacted

    def export_for_report(self, include_sensitive: bool = False) -> dict[str, Any]:
        """Export evidence for bug bounty report."""
        evidence_list = []

        for evidence in self.evidence_list:
            if not include_sensitive and evidence.sensitivity != EvidenceSensitivity.PUBLIC:
                continue

            evidence_dict = evidence.to_dict(include_content=True)
            evidence_list.append(evidence_dict)

        return {
            "finding_id": self.finding_id,
            "cve_id": self.cve_id,
            "description": self.description,
            "evidence_count": len(evidence_list),
            "has_sensitive": self.has_sensitive_evidence(),
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "evidence": evidence_list,
        }

    def to_dict(self, include_sensitive: bool = True) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "cve_id": self.cve_id,
            "description": self.description,
            "evidence_count": len(self.evidence_list),
            "evidence_types": {
                etype.value: len(self.get_evidence_by_type(etype)) for etype in EvidenceType
            },
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "evidence": [
                e.to_dict(include_content=True)
                for e in self.evidence_list
                if include_sensitive or e.sensitivity == EvidenceSensitivity.PUBLIC
            ],
        }
