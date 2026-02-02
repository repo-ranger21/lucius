"""
Comprehensive tests for Evidence Manager module
"""

import json
import tempfile
from datetime import datetime
from pathlib import Path

import pytest

from sentinel.evidence_manager import (
    AuditAction,
    AuditLogEntry,
    AuditLogger,
    EncryptionManager,
    EncryptionStatus,
    Evidence,
    EvidenceMetadata,
    EvidenceStorage,
    EvidenceType,
    PIIDetector,
    PIIPattern,
    PIIType,
)


class TestEnums:
    """Test enum definitions"""

    def test_evidence_type_enum(self):
        """Test EvidenceType enum values"""
        assert EvidenceType.SCREENSHOT.value == "screenshot"
        assert EvidenceType.HTTP_REQUEST.value == "http_request"
        assert EvidenceType.HTTP_RESPONSE.value == "http_response"
        assert EvidenceType.PROOF_OF_CONCEPT.value == "proof_of_concept"

    def test_pii_type_enum(self):
        """Test PIIType enum values"""
        assert PIIType.EMAIL.value == "email"
        assert PIIType.PHONE.value == "phone"
        assert PIIType.SSN.value == "ssn"
        assert PIIType.CREDIT_CARD.value == "credit_card"
        assert PIIType.API_KEY.value == "api_key"

    def test_encryption_status_enum(self):
        """Test EncryptionStatus enum values"""
        assert EncryptionStatus.UNENCRYPTED.value == "unencrypted"
        assert EncryptionStatus.ENCRYPTED.value == "encrypted"
        assert EncryptionStatus.FAILED.value == "failed"

    def test_audit_action_enum(self):
        """Test AuditAction enum values"""
        assert AuditAction.CREATED.value == "created"
        assert AuditAction.ACCESSED.value == "accessed"
        assert AuditAction.MODIFIED.value == "modified"
        assert AuditAction.DELETED.value == "deleted"


class TestPIIPattern:
    """Test PIIPattern dataclass"""

    def test_create_pii_pattern(self):
        """Test creating a PII pattern"""
        pattern = PIIPattern(
            pii_type=PIIType.EMAIL,
            pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            replacement="[REDACTED_EMAIL]",
            description="Email address",
        )

        assert pattern.pii_type == PIIType.EMAIL
        assert "[REDACTED_EMAIL]" in pattern.replacement
        assert pattern.severity == "high"  # default


class TestEvidenceMetadata:
    """Test EvidenceMetadata dataclass"""

    def test_create_evidence_metadata(self):
        """Test creating evidence metadata"""
        metadata = EvidenceMetadata(
            evidence_id="test-123",
            evidence_type=EvidenceType.SCREENSHOT,
            created_at=datetime.now(),
            created_by="tester",
            file_size=1024,
            file_hash="abc123",
            encryption_status=EncryptionStatus.ENCRYPTED,
            contains_pii=True,
            pii_types=[PIIType.EMAIL, PIIType.PHONE],
        )

        assert metadata.evidence_id == "test-123"
        assert metadata.evidence_type == EvidenceType.SCREENSHOT
        assert metadata.file_size == 1024
        assert metadata.contains_pii is True
        assert len(metadata.pii_types) == 2

    def test_metadata_to_dict(self):
        """Test converting metadata to dictionary"""
        metadata = EvidenceMetadata(
            evidence_id="test-456",
            evidence_type=EvidenceType.HTTP_REQUEST,
            created_at=datetime.now(),
            created_by="user1",
            file_size=512,
            file_hash="def456",
            encryption_status=EncryptionStatus.UNENCRYPTED,
            contains_pii=False,
            tags=["test", "example"],
        )

        meta_dict = metadata.to_dict()

        assert meta_dict["evidence_id"] == "test-456"
        assert meta_dict["evidence_type"] == "http_request"
        assert meta_dict["file_size"] == 512
        assert "test" in meta_dict["tags"]


class TestAuditLogEntry:
    """Test AuditLogEntry dataclass"""

    def test_create_audit_log_entry(self):
        """Test creating an audit log entry"""
        entry = AuditLogEntry(
            log_id="log-123",
            timestamp=datetime.now(),
            action=AuditAction.CREATED,
            evidence_id="ev-456",
            user="admin",
            ip_address="192.168.1.1",
        )

        assert entry.log_id == "log-123"
        assert entry.action == AuditAction.CREATED
        assert entry.user == "admin"
        assert entry.success is True

    def test_audit_log_to_dict(self):
        """Test converting audit log to dictionary"""
        entry = AuditLogEntry(
            log_id="log-789",
            timestamp=datetime.now(),
            action=AuditAction.ACCESSED,
            evidence_id="ev-123",
            user="user1",
            details="Accessed for review",
        )

        log_dict = entry.to_dict()

        assert log_dict["log_id"] == "log-789"
        assert log_dict["action"] == "accessed"
        assert log_dict["details"] == "Accessed for review"


class TestEvidence:
    """Test Evidence dataclass"""

    def test_create_evidence(self):
        """Test creating evidence object"""
        metadata = EvidenceMetadata(
            evidence_id="ev-001",
            evidence_type=EvidenceType.LOG_FILE,
            created_at=datetime.now(),
            created_by="tester",
            file_size=100,
            file_hash="hash123",
            encryption_status=EncryptionStatus.UNENCRYPTED,
            contains_pii=False,
        )

        content = b"This is test content"
        evidence = Evidence(metadata=metadata, content=content)

        assert evidence.metadata.evidence_id == "ev-001"
        assert evidence.content == b"This is test content"

    def test_get_content_string(self):
        """Test getting content as string"""
        metadata = EvidenceMetadata(
            evidence_id="ev-002",
            evidence_type=EvidenceType.DOCUMENT,
            created_at=datetime.now(),
            created_by="user",
            file_size=50,
            file_hash="hash456",
            encryption_status=EncryptionStatus.UNENCRYPTED,
            contains_pii=False,
        )

        content = b"Text content here"
        evidence = Evidence(metadata=metadata, content=content)

        content_str = evidence.get_content_string()
        assert content_str == "Text content here"


class TestPIIDetector:
    """Test PIIDetector class"""

    def test_detector_initialization(self):
        """Test PII detector initialization"""
        detector = PIIDetector()

        assert len(detector.compiled_patterns) > 0

    def test_detect_email(self):
        """Test detecting email addresses"""
        detector = PIIDetector()

        content = "Contact me at test@example.com for details"
        contains_pii, pii_types = detector.detect_pii(content)

        assert contains_pii is True
        assert PIIType.EMAIL in pii_types

    def test_detect_phone(self):
        """Test detecting phone numbers"""
        detector = PIIDetector()

        content = "Call me at 555-123-4567"
        contains_pii, pii_types = detector.detect_pii(content)

        assert contains_pii is True
        assert PIIType.PHONE in pii_types

    def test_detect_ssn(self):
        """Test detecting SSN"""
        detector = PIIDetector()

        content = "SSN: 123-45-6789"
        contains_pii, pii_types = detector.detect_pii(content)

        assert contains_pii is True
        assert PIIType.SSN in pii_types

    def test_detect_credit_card(self):
        """Test detecting credit card numbers"""
        detector = PIIDetector()

        content = "Card: 4532-1234-5678-9010"
        contains_pii, pii_types = detector.detect_pii(content)

        assert contains_pii is True
        assert PIIType.CREDIT_CARD in pii_types

    def test_detect_api_key(self):
        """Test detecting API keys"""
        detector = PIIDetector()

        content = 'api_key="sk_live_1234567890abcdefghijk"'
        contains_pii, pii_types = detector.detect_pii(content)

        assert contains_pii is True
        assert PIIType.API_KEY in pii_types

    def test_detect_multiple_pii_types(self):
        """Test detecting multiple PII types"""
        detector = PIIDetector()

        content = """
        Email: user@example.com
        Phone: 555-867-5309
        SSN: 987-65-4321
        """

        contains_pii, pii_types = detector.detect_pii(content)

        assert contains_pii is True
        assert len(pii_types) >= 3
        assert PIIType.EMAIL in pii_types
        assert PIIType.PHONE in pii_types
        assert PIIType.SSN in pii_types

    def test_no_pii_detected(self):
        """Test when no PII is present"""
        detector = PIIDetector()

        content = "This is clean content with no sensitive data"
        contains_pii, pii_types = detector.detect_pii(content)

        assert contains_pii is False
        assert len(pii_types) == 0

    def test_redact_email(self):
        """Test redacting email addresses"""
        detector = PIIDetector()

        content = "Contact test@example.com"
        redacted, types = detector.redact_pii(content)

        assert "[REDACTED_EMAIL]" in redacted
        assert "test@example.com" not in redacted
        assert PIIType.EMAIL in types

    def test_redact_multiple_pii(self):
        """Test redacting multiple PII types"""
        detector = PIIDetector()

        content = "Email: user@test.com, Phone: 555-123-4567"
        redacted, types = detector.redact_pii(content)

        assert "[REDACTED_EMAIL]" in redacted
        assert "[REDACTED_PHONE]" in redacted
        assert "user@test.com" not in redacted
        assert "555-123-4567" not in redacted
        assert len(types) >= 2


class TestEncryptionManager:
    """Test EncryptionManager class"""

    def test_encryption_manager_init_with_key(self):
        """Test initializing with custom key"""
        key = "dGVzdGtleTE="  # base64 encoded "testkey1"
        manager = EncryptionManager(key)

        assert manager.get_key() == key

    def test_encryption_manager_init_without_key(self):
        """Test initializing without key (generates one)"""
        manager = EncryptionManager()

        assert manager.get_key() is not None
        assert len(manager.get_key()) > 0

    def test_encrypt_decrypt_roundtrip(self):
        """Test encryption and decryption"""
        manager = EncryptionManager()

        original = b"This is secret content"
        encrypted = manager.encrypt(original)
        decrypted = manager.decrypt(encrypted)

        assert encrypted != original  # Should be different when encrypted
        assert decrypted == original  # Should match after decryption

    def test_encrypt_empty_content(self):
        """Test encrypting empty content"""
        manager = EncryptionManager()

        original = b""
        encrypted = manager.encrypt(original)
        decrypted = manager.decrypt(encrypted)

        assert decrypted == original


class TestAuditLogger:
    """Test AuditLogger class"""

    def test_audit_logger_initialization(self):
        """Test audit logger initialization"""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test_audit.log"
            logger = AuditLogger(log_file)

            assert logger.log_file == log_file
            assert len(logger.log_entries) == 0

    def test_log_action(self):
        """Test logging an action"""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test_audit.log"
            logger = AuditLogger(log_file)

            entry = logger.log_action(
                AuditAction.CREATED,
                "ev-123",
                "user1",
                ip_address="192.168.1.1",
                details="Created new evidence",
            )

            assert entry.action == AuditAction.CREATED
            assert entry.evidence_id == "ev-123"
            assert entry.user == "user1"
            assert len(logger.log_entries) == 1

    def test_get_logs_for_evidence(self):
        """Test getting logs for specific evidence"""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test_audit.log"
            logger = AuditLogger(log_file)

            logger.log_action(AuditAction.CREATED, "ev-001", "user1")
            logger.log_action(AuditAction.ACCESSED, "ev-001", "user2")
            logger.log_action(AuditAction.CREATED, "ev-002", "user1")

            logs = logger.get_logs_for_evidence("ev-001")

            assert len(logs) == 2
            assert all(log.evidence_id == "ev-001" for log in logs)

    def test_get_logs_by_action(self):
        """Test getting logs by action type"""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test_audit.log"
            logger = AuditLogger(log_file)

            logger.log_action(AuditAction.CREATED, "ev-001", "user1")
            logger.log_action(AuditAction.CREATED, "ev-002", "user1")
            logger.log_action(AuditAction.ACCESSED, "ev-001", "user2")

            created_logs = logger.get_logs_by_action(AuditAction.CREATED)

            assert len(created_logs) == 2
            assert all(log.action == AuditAction.CREATED for log in created_logs)

    def test_get_logs_by_user(self):
        """Test getting logs by user"""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_file = Path(tmpdir) / "test_audit.log"
            logger = AuditLogger(log_file)

            logger.log_action(AuditAction.CREATED, "ev-001", "user1")
            logger.log_action(AuditAction.ACCESSED, "ev-001", "user2")
            logger.log_action(AuditAction.CREATED, "ev-002", "user1")

            user1_logs = logger.get_logs_by_user("user1")

            assert len(user1_logs) == 2
            assert all(log.user == "user1" for log in user1_logs)


class TestEvidenceStorage:
    """Test EvidenceStorage class"""

    def test_storage_initialization(self):
        """Test evidence storage initialization"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            assert storage.storage_path.exists()
            assert storage.enable_encryption is True
            assert storage.enable_pii_detection is True

    def test_store_evidence(self):
        """Test storing evidence"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            content = b"Test evidence content"
            evidence = storage.store_evidence(
                content, EvidenceType.LOG_FILE, "tester", description="Test evidence"
            )

            assert evidence.metadata.evidence_id is not None
            assert evidence.metadata.evidence_type == EvidenceType.LOG_FILE
            assert evidence.metadata.created_by == "tester"
            assert evidence.metadata.file_size == len(content)

    def test_store_evidence_with_pii(self):
        """Test storing evidence containing PII"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            content = b"Contact: test@example.com, Phone: 555-123-4567"
            evidence = storage.store_evidence(content, EvidenceType.DOCUMENT, "user1")

            assert evidence.metadata.contains_pii is True
            assert len(evidence.metadata.pii_types) > 0
            assert PIIType.EMAIL in evidence.metadata.pii_types

    def test_retrieve_evidence(self):
        """Test retrieving stored evidence"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            original_content = b"Original evidence"
            stored = storage.store_evidence(original_content, EvidenceType.SCREENSHOT, "user1")

            retrieved = storage.retrieve_evidence(stored.metadata.evidence_id, "user2")

            assert retrieved is not None
            assert retrieved.content == original_content
            assert "user2" in retrieved.metadata.chain_of_custody

    def test_retrieve_nonexistent_evidence(self):
        """Test retrieving evidence that doesn't exist"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            retrieved = storage.retrieve_evidence("nonexistent", "user1")

            assert retrieved is None

    def test_delete_evidence(self):
        """Test deleting evidence"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            content = b"To be deleted"
            evidence = storage.store_evidence(content, EvidenceType.OTHER, "user1")

            evidence_id = evidence.metadata.evidence_id
            deleted = storage.delete_evidence(evidence_id, "user1")

            assert deleted is True
            assert evidence_id not in storage.evidence_metadata

    def test_redact_evidence_pii(self):
        """Test redacting PII from evidence"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            content = b"Email: sensitive@example.com"
            original = storage.store_evidence(content, EvidenceType.DOCUMENT, "user1")

            redacted = storage.redact_evidence_pii(original.metadata.evidence_id, "user1")

            assert redacted is not None
            assert b"[REDACTED_EMAIL]" in redacted.content
            assert b"sensitive@example.com" not in redacted.content

    def test_export_evidence(self):
        """Test exporting evidence"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))
            export_path = Path(tmpdir) / "exported.bin"

            content = b"Export this content"
            evidence = storage.store_evidence(content, EvidenceType.BINARY, "user1")

            success = storage.export_evidence(
                evidence.metadata.evidence_id, export_path, "user1", include_metadata=True
            )

            assert success is True
            assert export_path.exists()

            # Check metadata file was created
            metadata_path = export_path.with_suffix(export_path.suffix + ".meta.json")
            assert metadata_path.exists()

    def test_import_evidence(self):
        """Test importing evidence"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))
            import_path = Path(tmpdir) / "import.txt"

            # Create file to import
            content = b"Imported content"
            with open(import_path, "wb") as f:
                f.write(content)

            imported = storage.import_evidence(import_path, EvidenceType.DOCUMENT, "user1")

            assert imported is not None
            assert imported.content == content
            assert imported.metadata.evidence_type == EvidenceType.DOCUMENT

    def test_list_evidence_all(self):
        """Test listing all evidence"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            storage.store_evidence(b"Content 1", EvidenceType.LOG_FILE, "user1")
            storage.store_evidence(b"Content 2", EvidenceType.SCREENSHOT, "user1")
            storage.store_evidence(b"Content 3", EvidenceType.DOCUMENT, "user1")

            all_evidence = storage.list_evidence()

            assert len(all_evidence) == 3

    def test_list_evidence_by_type(self):
        """Test listing evidence filtered by type"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            storage.store_evidence(b"Log 1", EvidenceType.LOG_FILE, "user1")
            storage.store_evidence(b"Screen 1", EvidenceType.SCREENSHOT, "user1")
            storage.store_evidence(b"Log 2", EvidenceType.LOG_FILE, "user1")

            logs = storage.list_evidence(evidence_type=EvidenceType.LOG_FILE)

            assert len(logs) == 2
            assert all(m.evidence_type == EvidenceType.LOG_FILE for m in logs)

    def test_list_evidence_by_pii(self):
        """Test listing evidence filtered by PII presence"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            storage.store_evidence(b"Clean content", EvidenceType.DOCUMENT, "user1")
            storage.store_evidence(b"Email: test@example.com", EvidenceType.DOCUMENT, "user1")

            with_pii = storage.list_evidence(contains_pii=True)
            without_pii = storage.list_evidence(contains_pii=False)

            assert len(with_pii) >= 1
            assert len(without_pii) >= 1

    def test_list_evidence_by_tags(self):
        """Test listing evidence filtered by tags"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            storage.store_evidence(
                b"Content 1", EvidenceType.DOCUMENT, "user1", tags=["important", "review"]
            )
            storage.store_evidence(b"Content 2", EvidenceType.DOCUMENT, "user1", tags=["draft"])

            important = storage.list_evidence(tags=["important"])

            assert len(important) == 1
            assert "important" in important[0].tags

    def test_get_audit_logs(self):
        """Test getting audit logs"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            evidence = storage.store_evidence(b"Test content", EvidenceType.LOG_FILE, "user1")

            logs = storage.get_audit_logs(evidence.metadata.evidence_id)

            assert len(logs) >= 1
            assert logs[0].action == AuditAction.CREATED

    def test_chain_of_custody(self):
        """Test chain of custody tracking"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir))

            evidence = storage.store_evidence(b"Evidence", EvidenceType.PROOF_OF_CONCEPT, "user1")

            evidence_id = evidence.metadata.evidence_id

            # Multiple users access
            storage.retrieve_evidence(evidence_id, "user2")
            storage.retrieve_evidence(evidence_id, "user3")

            final = storage.retrieve_evidence(evidence_id, "user1")

            assert "user1" in final.metadata.chain_of_custody
            assert "user2" in final.metadata.chain_of_custody
            assert "user3" in final.metadata.chain_of_custody

    def test_encryption_enabled(self):
        """Test that encryption is applied when enabled"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir), enable_encryption=True)

            content = b"Sensitive data"
            evidence = storage.store_evidence(content, EvidenceType.DOCUMENT, "user1")

            assert evidence.metadata.encryption_status == EncryptionStatus.ENCRYPTED

    def test_encryption_disabled(self):
        """Test storing without encryption"""
        with tempfile.TemporaryDirectory() as tmpdir:
            storage = EvidenceStorage(Path(tmpdir), enable_encryption=False)

            content = b"Public data"
            evidence = storage.store_evidence(content, EvidenceType.DOCUMENT, "user1")

            assert evidence.metadata.encryption_status == EncryptionStatus.UNENCRYPTED
