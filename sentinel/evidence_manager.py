"""
Evidence Manager Module for Bug Bounty Testing

This module provides comprehensive evidence management capabilities including:
- Secure evidence storage with encryption
- PII detection and redaction
- Compliance audit logging
- Evidence import/export
- Chain of custody tracking

Designed for ethical security testing with privacy and compliance focus.
"""

import base64
import hashlib
import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from shared.logging import get_logger

logger = get_logger(__name__)


class EvidenceType(Enum):
    """Types of evidence that can be stored"""

    SCREENSHOT = "screenshot"
    HTTP_REQUEST = "http_request"
    HTTP_RESPONSE = "http_response"
    LOG_FILE = "log_file"
    PROOF_OF_CONCEPT = "proof_of_concept"
    VIDEO = "video"
    NETWORK_CAPTURE = "network_capture"
    SOURCE_CODE = "source_code"
    BINARY = "binary"
    DOCUMENT = "document"
    OTHER = "other"


class PIIType(Enum):
    """Types of PII that need to be detected and redacted"""

    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CREDIT_CARD = "credit_card"
    IP_ADDRESS = "ip_address"
    API_KEY = "api_key"
    PASSWORD = "password"
    TOKEN = "token"
    NAME = "name"
    ADDRESS = "address"
    CUSTOM = "custom"


class EncryptionStatus(Enum):
    """Encryption status of evidence"""

    UNENCRYPTED = "unencrypted"
    ENCRYPTED = "encrypted"
    FAILED = "failed"


class AuditAction(Enum):
    """Actions that trigger audit log entries"""

    CREATED = "created"
    ACCESSED = "accessed"
    MODIFIED = "modified"
    DELETED = "deleted"
    EXPORTED = "exported"
    IMPORTED = "imported"
    ENCRYPTED = "encrypted"
    DECRYPTED = "decrypted"
    REDACTED = "redacted"


@dataclass
class PIIPattern:
    """Pattern for detecting PII in content"""

    pii_type: PIIType
    pattern: str
    replacement: str
    description: str
    severity: str = "high"  # high, medium, low


@dataclass
class EvidenceMetadata:
    """Metadata about a piece of evidence"""

    evidence_id: str
    evidence_type: EvidenceType
    created_at: datetime
    created_by: str
    file_size: int
    file_hash: str  # SHA-256 hash
    encryption_status: EncryptionStatus
    contains_pii: bool
    pii_types: List[PIIType] = field(default_factory=list)
    redaction_applied: bool = False
    tags: List[str] = field(default_factory=list)
    description: Optional[str] = None
    related_vulnerability_id: Optional[str] = None
    chain_of_custody: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type.value,
            "created_at": self.created_at.isoformat(),
            "created_by": self.created_by,
            "file_size": self.file_size,
            "file_hash": self.file_hash,
            "encryption_status": self.encryption_status.value,
            "contains_pii": self.contains_pii,
            "pii_types": [p.value for p in self.pii_types],
            "redaction_applied": self.redaction_applied,
            "tags": self.tags,
            "description": self.description,
            "related_vulnerability_id": self.related_vulnerability_id,
            "chain_of_custody": self.chain_of_custody,
        }


@dataclass
class AuditLogEntry:
    """Audit log entry for compliance tracking"""

    log_id: str
    timestamp: datetime
    action: AuditAction
    evidence_id: str
    user: str
    ip_address: Optional[str] = None
    details: Optional[str] = None
    success: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "log_id": self.log_id,
            "timestamp": self.timestamp.isoformat(),
            "action": self.action.value,
            "evidence_id": self.evidence_id,
            "user": self.user,
            "ip_address": self.ip_address,
            "details": self.details,
            "success": self.success,
        }


@dataclass
class Evidence:
    """Complete evidence object with content and metadata"""

    metadata: EvidenceMetadata
    content: bytes
    original_filename: Optional[str] = None

    def get_content_string(self) -> str:
        """Get content as string (if text-based evidence)"""
        try:
            return self.content.decode("utf-8")
        except UnicodeDecodeError:
            return base64.b64encode(self.content).decode("utf-8")


class PIIDetector:
    """
    Detects and redacts PII from evidence content
    """

    # Pre-defined PII patterns
    PATTERNS = [
        PIIPattern(
            pii_type=PIIType.EMAIL,
            pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            replacement="[REDACTED_EMAIL]",
            description="Email address",
            severity="medium",
        ),
        PIIPattern(
            pii_type=PIIType.PHONE,
            pattern=r"\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b",
            replacement="[REDACTED_PHONE]",
            description="Phone number",
            severity="medium",
        ),
        PIIPattern(
            pii_type=PIIType.SSN,
            pattern=r"\b\d{3}-\d{2}-\d{4}\b",
            replacement="[REDACTED_SSN]",
            description="Social Security Number",
            severity="high",
        ),
        PIIPattern(
            pii_type=PIIType.CREDIT_CARD,
            pattern=r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
            replacement="[REDACTED_CC]",
            description="Credit card number",
            severity="high",
        ),
        PIIPattern(
            pii_type=PIIType.IP_ADDRESS,
            pattern=r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            replacement="[REDACTED_IP]",
            description="IP address",
            severity="low",
        ),
        PIIPattern(
            pii_type=PIIType.API_KEY,
            pattern=r'api[_-]?key[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-]{20,})',
            replacement='api_key="[REDACTED_API_KEY]"',
            description="API key",
            severity="high",
        ),
        PIIPattern(
            pii_type=PIIType.PASSWORD,
            pattern=r'password[\'"]?\s*[:=]\s*[\'"]?([^\'"&\s]{8,})',
            replacement='password="[REDACTED_PASSWORD]"',
            description="Password",
            severity="high",
        ),
        PIIPattern(
            pii_type=PIIType.TOKEN,
            pattern=r'(?:bearer|token)[\'"]?\s*[:=]\s*[\'"]?([a-zA-Z0-9_\-\.]{20,})',
            replacement='token="[REDACTED_TOKEN]"',
            description="Authentication token",
            severity="high",
        ),
    ]

    def __init__(self):
        """Initialize PII detector"""
        self.compiled_patterns = [
            (pattern.pii_type, re.compile(pattern.pattern, re.IGNORECASE), pattern.replacement)
            for pattern in self.PATTERNS
        ]

    def detect_pii(self, content: str) -> Tuple[bool, List[PIIType]]:
        """
        Detect PII in content

        Args:
            content: Text content to scan

        Returns:
            Tuple of (contains_pii: bool, pii_types: List[PIIType])
        """
        found_pii_types = []

        for pii_type, pattern, _ in self.compiled_patterns:
            if pattern.search(content):
                found_pii_types.append(pii_type)

        contains_pii = len(found_pii_types) > 0
        return contains_pii, found_pii_types

    def redact_pii(self, content: str) -> Tuple[str, List[PIIType]]:
        """
        Redact PII from content

        Args:
            content: Text content to redact

        Returns:
            Tuple of (redacted_content: str, redacted_types: List[PIIType])
        """
        redacted_content = content
        redacted_types = []

        for pii_type, pattern, replacement in self.compiled_patterns:
            if pattern.search(redacted_content):
                redacted_content = pattern.sub(replacement, redacted_content)
                redacted_types.append(pii_type)

        return redacted_content, redacted_types


class EncryptionManager:
    """
    Manages encryption and decryption of evidence

    Note: This is a simplified implementation for demonstration.
    In production, use proper key management systems (KMS) and
    established encryption libraries like cryptography.fernet or AWS KMS.
    """

    def __init__(self, encryption_key: Optional[str] = None):
        """
        Initialize encryption manager

        Args:
            encryption_key: Encryption key (base64 encoded)
                          If None, generates a new key
        """
        if encryption_key:
            self.key = encryption_key.encode("utf-8")
        else:
            # Generate a simple key (in production, use proper key generation)
            self.key = base64.b64encode(os.urandom(32))

    def encrypt(self, content: bytes) -> bytes:
        """
        Encrypt content

        Args:
            content: Content to encrypt

        Returns:
            Encrypted content

        Note: This is a simplified XOR implementation for demonstration.
        In production, use proper encryption like AES-256-GCM via cryptography.fernet
        """
        # Simple XOR encryption for demonstration
        # In production, use: fernet = Fernet(self.key); return fernet.encrypt(content)
        key_bytes = base64.b64decode(self.key)
        encrypted = bytearray()
        for i, byte in enumerate(content):
            encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
        return bytes(encrypted)

    def decrypt(self, encrypted_content: bytes) -> bytes:
        """
        Decrypt content

        Args:
            encrypted_content: Encrypted content

        Returns:
            Decrypted content
        """
        # XOR is symmetric, so encryption = decryption
        return self.encrypt(encrypted_content)

    def get_key(self) -> str:
        """Get encryption key as string"""
        return self.key.decode("utf-8")


class AuditLogger:
    """
    Manages compliance audit logging
    """

    def __init__(self, log_file: Optional[Path] = None):
        """
        Initialize audit logger

        Args:
            log_file: Path to audit log file
        """
        self.log_file = log_file or Path("evidence_audit.log")
        self.log_entries: List[AuditLogEntry] = []

    def log_action(
        self,
        action: AuditAction,
        evidence_id: str,
        user: str,
        ip_address: Optional[str] = None,
        details: Optional[str] = None,
        success: bool = True,
    ) -> AuditLogEntry:
        """
        Log an action for audit compliance

        Args:
            action: Type of action performed
            evidence_id: ID of evidence affected
            user: User who performed action
            ip_address: IP address of user
            details: Additional details about action
            success: Whether action succeeded

        Returns:
            Created audit log entry
        """
        entry = AuditLogEntry(
            log_id=str(uuid.uuid4()),
            timestamp=datetime.now(),
            action=action,
            evidence_id=evidence_id,
            user=user,
            ip_address=ip_address,
            details=details,
            success=success,
        )

        self.log_entries.append(entry)
        self._write_to_file(entry)

        logger.info(
            f"Audit: {action.value} on {evidence_id} by {user}",
            extra={"audit_log_id": entry.log_id},
        )

        return entry

    def _write_to_file(self, entry: AuditLogEntry):
        """Write audit entry to file"""
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(entry.to_dict()) + "\n")
        except Exception as e:
            logger.error(f"Failed to write audit log: {e}")

    def get_logs_for_evidence(self, evidence_id: str) -> List[AuditLogEntry]:
        """Get all audit logs for specific evidence"""
        return [entry for entry in self.log_entries if entry.evidence_id == evidence_id]

    def get_logs_by_action(self, action: AuditAction) -> List[AuditLogEntry]:
        """Get all audit logs for specific action type"""
        return [entry for entry in self.log_entries if entry.action == action]

    def get_logs_by_user(self, user: str) -> List[AuditLogEntry]:
        """Get all audit logs for specific user"""
        return [entry for entry in self.log_entries if entry.user == user]


class EvidenceStorage:
    """
    Manages secure storage of evidence with encryption and PII handling
    """

    def __init__(
        self,
        storage_path: Path,
        encryption_key: Optional[str] = None,
        enable_encryption: bool = True,
        enable_pii_detection: bool = True,
    ):
        """
        Initialize evidence storage

        Args:
            storage_path: Directory to store evidence files
            encryption_key: Encryption key for securing evidence
            enable_encryption: Whether to encrypt evidence by default
            enable_pii_detection: Whether to detect PII in evidence
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

        self.enable_encryption = enable_encryption
        self.enable_pii_detection = enable_pii_detection

        self.encryption_manager = EncryptionManager(encryption_key)
        self.pii_detector = PIIDetector()
        self.audit_logger = AuditLogger(self.storage_path / "audit.log")

        self.evidence_metadata: Dict[str, EvidenceMetadata] = {}
        self._load_metadata()

    def _load_metadata(self):
        """Load metadata from storage"""
        metadata_file = self.storage_path / "metadata.json"
        if metadata_file.exists():
            try:
                with open(metadata_file, "r") as f:
                    data = json.load(f)
                    for evidence_id, meta_dict in data.items():
                        self.evidence_metadata[evidence_id] = self._dict_to_metadata(meta_dict)
                logger.info(f"Loaded {len(self.evidence_metadata)} evidence metadata entries")
            except Exception as e:
                logger.error(f"Failed to load metadata: {e}")

    def _save_metadata(self):
        """Save metadata to storage"""
        metadata_file = self.storage_path / "metadata.json"
        try:
            data = {eid: meta.to_dict() for eid, meta in self.evidence_metadata.items()}
            with open(metadata_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save metadata: {e}")

    def _dict_to_metadata(self, data: Dict[str, Any]) -> EvidenceMetadata:
        """Convert dictionary to EvidenceMetadata"""
        return EvidenceMetadata(
            evidence_id=data["evidence_id"],
            evidence_type=EvidenceType(data["evidence_type"]),
            created_at=datetime.fromisoformat(data["created_at"]),
            created_by=data["created_by"],
            file_size=data["file_size"],
            file_hash=data["file_hash"],
            encryption_status=EncryptionStatus(data["encryption_status"]),
            contains_pii=data["contains_pii"],
            pii_types=[PIIType(p) for p in data["pii_types"]],
            redaction_applied=data["redaction_applied"],
            tags=data["tags"],
            description=data.get("description"),
            related_vulnerability_id=data.get("related_vulnerability_id"),
            chain_of_custody=data["chain_of_custody"],
        )

    def _calculate_hash(self, content: bytes) -> str:
        """Calculate SHA-256 hash of content"""
        return hashlib.sha256(content).hexdigest()

    def _get_evidence_path(self, evidence_id: str) -> Path:
        """Get file path for evidence"""
        return self.storage_path / f"{evidence_id}.bin"

    def store_evidence(
        self,
        content: bytes,
        evidence_type: EvidenceType,
        created_by: str,
        description: Optional[str] = None,
        tags: Optional[List[str]] = None,
        original_filename: Optional[str] = None,
        related_vulnerability_id: Optional[str] = None,
    ) -> Evidence:
        """
        Store evidence securely

        Args:
            content: Evidence content
            evidence_type: Type of evidence
            created_by: User storing the evidence
            description: Optional description
            tags: Optional tags for categorization
            original_filename: Original filename if applicable
            related_vulnerability_id: Related vulnerability ID

        Returns:
            Evidence object with metadata
        """
        evidence_id = str(uuid.uuid4())

        # Detect PII if enabled
        contains_pii = False
        pii_types = []
        if self.enable_pii_detection:
            try:
                content_str = content.decode("utf-8")
                contains_pii, pii_types = self.pii_detector.detect_pii(content_str)
            except UnicodeDecodeError:
                # Binary content, skip PII detection
                pass

        # Calculate hash before encryption
        file_hash = self._calculate_hash(content)

        # Encrypt if enabled
        encryption_status = EncryptionStatus.UNENCRYPTED
        stored_content = content
        if self.enable_encryption:
            try:
                stored_content = self.encryption_manager.encrypt(content)
                encryption_status = EncryptionStatus.ENCRYPTED
            except Exception as e:
                logger.error(f"Encryption failed: {e}")
                encryption_status = EncryptionStatus.FAILED

        # Create metadata
        metadata = EvidenceMetadata(
            evidence_id=evidence_id,
            evidence_type=evidence_type,
            created_at=datetime.now(),
            created_by=created_by,
            file_size=len(content),
            file_hash=file_hash,
            encryption_status=encryption_status,
            contains_pii=contains_pii,
            pii_types=pii_types,
            redaction_applied=False,
            tags=tags or [],
            description=description,
            related_vulnerability_id=related_vulnerability_id,
            chain_of_custody=[created_by],
        )

        # Store file
        evidence_path = self._get_evidence_path(evidence_id)
        with open(evidence_path, "wb") as f:
            f.write(stored_content)

        # Save metadata
        self.evidence_metadata[evidence_id] = metadata
        self._save_metadata()

        # Audit log
        self.audit_logger.log_action(
            AuditAction.CREATED,
            evidence_id,
            created_by,
            details=f"Type: {evidence_type.value}, Size: {len(content)} bytes",
        )

        if contains_pii:
            logger.warning(f"Evidence {evidence_id} contains PII: {[p.value for p in pii_types]}")

        logger.info(f"Stored evidence {evidence_id} ({evidence_type.value})")

        return Evidence(metadata=metadata, content=content, original_filename=original_filename)

    def retrieve_evidence(
        self, evidence_id: str, accessed_by: str, decrypt: bool = True
    ) -> Optional[Evidence]:
        """
        Retrieve evidence from storage

        Args:
            evidence_id: ID of evidence to retrieve
            accessed_by: User accessing the evidence
            decrypt: Whether to decrypt if encrypted

        Returns:
            Evidence object or None if not found
        """
        if evidence_id not in self.evidence_metadata:
            logger.warning(f"Evidence {evidence_id} not found")
            return None

        metadata = self.evidence_metadata[evidence_id]
        evidence_path = self._get_evidence_path(evidence_id)

        if not evidence_path.exists():
            logger.error(f"Evidence file {evidence_id} missing")
            return None

        # Read file
        with open(evidence_path, "rb") as f:
            content = f.read()

        # Decrypt if encrypted and requested
        if decrypt and metadata.encryption_status == EncryptionStatus.ENCRYPTED:
            try:
                content = self.encryption_manager.decrypt(content)
            except Exception as e:
                logger.error(f"Decryption failed: {e}")
                return None

        # Update chain of custody
        if accessed_by not in metadata.chain_of_custody:
            metadata.chain_of_custody.append(accessed_by)
            self._save_metadata()

        # Audit log
        self.audit_logger.log_action(AuditAction.ACCESSED, evidence_id, accessed_by)

        return Evidence(metadata=metadata, content=content)

    def redact_evidence_pii(self, evidence_id: str, user: str) -> Optional[Evidence]:
        """
        Redact PII from evidence

        Args:
            evidence_id: ID of evidence to redact
            user: User performing redaction

        Returns:
            Evidence with PII redacted
        """
        evidence = self.retrieve_evidence(evidence_id, user)
        if not evidence:
            return None

        try:
            content_str = evidence.content.decode("utf-8")
            redacted_content, redacted_types = self.pii_detector.redact_pii(content_str)
            redacted_bytes = redacted_content.encode("utf-8")

            # Update metadata
            evidence.metadata.redaction_applied = True
            evidence.content = redacted_bytes

            # Re-store with redacted content
            self.delete_evidence(evidence_id, user, audit=False)
            return self.store_evidence(
                redacted_bytes,
                evidence.metadata.evidence_type,
                user,
                description=f"Redacted from {evidence_id}",
                tags=evidence.metadata.tags + ["redacted"],
                related_vulnerability_id=evidence.metadata.related_vulnerability_id,
            )

        except UnicodeDecodeError:
            logger.error(f"Cannot redact binary evidence {evidence_id}")
            return None

    def delete_evidence(self, evidence_id: str, deleted_by: str, audit: bool = True) -> bool:
        """
        Delete evidence from storage

        Args:
            evidence_id: ID of evidence to delete
            deleted_by: User deleting the evidence
            audit: Whether to create audit log

        Returns:
            True if deleted successfully
        """
        if evidence_id not in self.evidence_metadata:
            return False

        evidence_path = self._get_evidence_path(evidence_id)

        try:
            if evidence_path.exists():
                evidence_path.unlink()

            del self.evidence_metadata[evidence_id]
            self._save_metadata()

            if audit:
                self.audit_logger.log_action(AuditAction.DELETED, evidence_id, deleted_by)

            logger.info(f"Deleted evidence {evidence_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete evidence {evidence_id}: {e}")
            return False

    def export_evidence(
        self, evidence_id: str, export_path: Path, exported_by: str, include_metadata: bool = True
    ) -> bool:
        """
        Export evidence to external location

        Args:
            evidence_id: ID of evidence to export
            export_path: Path to export to
            exported_by: User exporting the evidence
            include_metadata: Whether to include metadata file

        Returns:
            True if exported successfully
        """
        evidence = self.retrieve_evidence(evidence_id, exported_by)
        if not evidence:
            return False

        try:
            # Export content
            with open(export_path, "wb") as f:
                f.write(evidence.content)

            # Export metadata if requested
            if include_metadata:
                metadata_path = export_path.with_suffix(export_path.suffix + ".meta.json")
                with open(metadata_path, "w") as f:
                    json.dump(evidence.metadata.to_dict(), f, indent=2)

            # Audit log
            self.audit_logger.log_action(
                AuditAction.EXPORTED, evidence_id, exported_by, details=f"Exported to {export_path}"
            )

            logger.info(f"Exported evidence {evidence_id} to {export_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to export evidence {evidence_id}: {e}")
            return False

    def import_evidence(
        self,
        import_path: Path,
        evidence_type: EvidenceType,
        imported_by: str,
        metadata_path: Optional[Path] = None,
    ) -> Optional[Evidence]:
        """
        Import evidence from external location

        Args:
            import_path: Path to import from
            evidence_type: Type of evidence
            imported_by: User importing the evidence
            metadata_path: Optional path to metadata file

        Returns:
            Imported Evidence object
        """
        if not import_path.exists():
            logger.error(f"Import path {import_path} does not exist")
            return None

        try:
            # Read content
            with open(import_path, "rb") as f:
                content = f.read()

            # Load metadata if provided
            description = f"Imported from {import_path.name}"
            tags = ["imported"]

            if metadata_path and metadata_path.exists():
                with open(metadata_path, "r") as f:
                    meta_dict = json.load(f)
                    description = meta_dict.get("description", description)
                    tags = meta_dict.get("tags", tags)

            # Store evidence
            evidence = self.store_evidence(
                content,
                evidence_type,
                imported_by,
                description=description,
                tags=tags,
                original_filename=import_path.name,
            )

            # Audit log
            self.audit_logger.log_action(
                AuditAction.IMPORTED,
                evidence.metadata.evidence_id,
                imported_by,
                details=f"Imported from {import_path}",
            )

            logger.info(f"Imported evidence from {import_path}")
            return evidence

        except Exception as e:
            logger.error(f"Failed to import evidence from {import_path}: {e}")
            return None

    def list_evidence(
        self,
        evidence_type: Optional[EvidenceType] = None,
        contains_pii: Optional[bool] = None,
        tags: Optional[List[str]] = None,
    ) -> List[EvidenceMetadata]:
        """
        List evidence with optional filtering

        Args:
            evidence_type: Filter by evidence type
            contains_pii: Filter by PII presence
            tags: Filter by tags (any match)

        Returns:
            List of matching evidence metadata
        """
        results = list(self.evidence_metadata.values())

        if evidence_type:
            results = [m for m in results if m.evidence_type == evidence_type]

        if contains_pii is not None:
            results = [m for m in results if m.contains_pii == contains_pii]

        if tags:
            results = [m for m in results if any(tag in m.tags for tag in tags)]

        return results

    def get_audit_logs(self, evidence_id: Optional[str] = None) -> List[AuditLogEntry]:
        """
        Get audit logs

        Args:
            evidence_id: Optional filter by evidence ID

        Returns:
            List of audit log entries
        """
        if evidence_id:
            return self.audit_logger.get_logs_for_evidence(evidence_id)
        return self.audit_logger.log_entries
