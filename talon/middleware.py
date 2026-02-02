"""
Talon Middleware: BOLA Bridge Validation Gate

Defensive middleware enforcing positive identity mapping for legacy NNIP IDs
before accessing GS global tenant objects.
"""

from dataclasses import dataclass
from typing import Any, Dict, Optional, Protocol

try:
    from flask import abort, request

    FLASK_AVAILABLE = True
except Exception:  # pragma: no cover - optional Flask import
    FLASK_AVAILABLE = False


@dataclass(frozen=True)
class IdentityMapping:
    legacy_user_id: str
    gs_global_tenant_id: str
    status: str


class MappingLedger(Protocol):
    """Interface for immutable migration ledger access."""

    def get_mapping(self, legacy_user_id: str) -> Optional[IdentityMapping]:
        raise NotImplementedError

    def verify_mapping(self, legacy_user_id: str) -> Optional[IdentityMapping]:
        """Verify a cryptographically signed mapping if supported."""
        return self.get_mapping(legacy_user_id)


class ObjectOwnershipStore(Protocol):
    """Interface for object ownership validation."""

    def is_owned_by_tenant(self, object_id: str, tenant_id: str) -> bool:
        raise NotImplementedError


class AuditLogger(Protocol):
    """Interface for audit logging."""

    def log(self, event: str, **fields: Any) -> None:
        raise NotImplementedError


class BOLAMiddleware:
    """Positive identity mapping gate to prevent BOLA during migration."""

    def __init__(
        self,
        ledger: MappingLedger,
        ownership_store: ObjectOwnershipStore,
        audit: AuditLogger,
    ) -> None:
        self.ledger = ledger
        self.ownership_store = ownership_store
        self.audit = audit

    def __call__(self, request: Any, object_id: str) -> None:
        """
        Validate legacy-to-tenant mapping and object ownership.

        Expects request.context to contain:
        - legacy_nn_ip_user_id
        - gs_global_tenant_id
        """
        context: Dict[str, Any] = getattr(request, "context", {}) or {}
        legacy_id = context.get("legacy_nn_ip_user_id")
        tenant_id = context.get("gs_global_tenant_id")

        if not legacy_id or not tenant_id or not object_id:
            self.audit.log(
                "BOLA_GATE_DENY",
                reason="missing_context",
                request_id=getattr(request, "id", None),
            )
            raise PermissionError("Missing identity context")

        mapping = (
            self.ledger.verify_mapping(legacy_id)
            if hasattr(self.ledger, "verify_mapping")
            else self.ledger.get_mapping(legacy_id)
        )
        if not mapping or mapping.status.lower() != "active":
            self.audit.log(
                "BOLA_GATE_DENY",
                reason="no_active_mapping",
                legacy_id=legacy_id,
            )
            raise PermissionError("No active legacy mapping")

        if mapping.gs_global_tenant_id != tenant_id:
            self.audit.log(
                "BOLA_GATE_DENY",
                reason="tenant_mismatch",
                legacy_id=legacy_id,
                mapped_tenant=mapping.gs_global_tenant_id,
                request_tenant=tenant_id,
            )
            raise PermissionError("Tenant mismatch")

        if not self.ownership_store.is_owned_by_tenant(object_id, tenant_id):
            self.audit.log(
                "BOLA_GATE_DENY",
                reason="owner_mismatch",
                object_id=object_id,
                tenant_id=tenant_id,
            )
            raise PermissionError("Object owner mismatch")

        self.audit.log(
            "BOLA_GATE_ALLOW",
            legacy_id=legacy_id,
            tenant_id=tenant_id,
            object_id=object_id,
        )


def bola_mapping_middleware(
    ledger: MappingLedger,
    ownership_store: ObjectOwnershipStore,
    audit: AuditLogger,
) -> None:
    """Flask middleware wrapper for BOLA enforcement."""
    if not FLASK_AVAILABLE:
        raise RuntimeError("Flask not available for middleware registration")

    legacy_id = request.headers.get("X-NNIP-Legacy-ID")
    target_obj_id = None
    if request.view_args:
        target_obj_id = request.view_args.get("object_id")
    if not target_obj_id:
        target_obj_id = request.args.get("object_id")

    if legacy_id and target_obj_id:
        mapping = (
            ledger.verify_mapping(legacy_id)
            if hasattr(ledger, "verify_mapping")
            else ledger.get_mapping(legacy_id)
        )
        if not mapping or mapping.status.upper() != "ACTIVE":
            audit.log("BOLA_GATE_DENY", reason="no_active_mapping", legacy_id=legacy_id)
            abort(403, "Legacy ID mapping not found or inactive.")

        authorized_tenant = mapping.gs_global_tenant_id
        obj_metadata = getattr(request, "db", None)
        if obj_metadata and hasattr(obj_metadata, "get_metadata"):
            metadata = obj_metadata.get_metadata(target_obj_id)
            if metadata.get("tenant_id") != authorized_tenant:
                audit.log(
                    "BOLA_GATE_DENY",
                    reason="tenant_mismatch",
                    legacy_id=legacy_id,
                    object_id=target_obj_id,
                )
                abort(403, "Tenant mismatch: Object does not belong to authorized scope.")
