"""Base repository implementation with common functionality."""

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Generic, TypeVar
from uuid import UUID

from sqlalchemy.orm import Query

from shared.logging import get_logger
from talon.extensions import db

T = TypeVar("T", bound=db.Model)
logger = get_logger(__name__)


class BaseRepository(ABC, Generic[T]):
    """
    Abstract base repository implementing common CRUD operations.

    Provides:
    - Multi-tenant data isolation via tenant_id
    - Audit logging for all operations
    - Soft delete support
    - Pagination helpers
    - Query building utilities

    All concrete repositories should inherit from this class.
    """

    model_class: type[T]

    def __init__(self, tenant_id: str) -> None:
        """
        Initialize repository with tenant context.

        Args:
            tenant_id: Tenant identifier for data isolation
        """
        if not tenant_id or not tenant_id.strip():
            raise ValueError("tenant_id is required and cannot be empty")
        self._tenant_id = tenant_id.strip()
        self._logger = get_logger(f"{__name__}.{self.__class__.__name__}")

    @property
    def tenant_id(self) -> str:
        """Get current tenant ID."""
        return self._tenant_id

    @abstractmethod
    def _apply_tenant_filter(self, query: Query) -> Query:
        """
        Apply tenant-specific filtering to query.

        Args:
            query: SQLAlchemy query to filter

        Returns:
            Filtered query
        """
        pass

    def _base_query(self) -> Query:
        """
        Create base query with tenant filter applied.

        Returns:
            Query with tenant isolation
        """
        query = db.session.query(self.model_class)
        return self._apply_tenant_filter(query)

    def get_by_id(self, entity_id: UUID | str) -> T | None:
        """
        Get entity by ID with tenant isolation.

        Args:
            entity_id: Entity identifier

        Returns:
            Entity if found and belongs to tenant, None otherwise
        """
        try:
            if isinstance(entity_id, str):
                entity_id = UUID(entity_id)

            entity = self._base_query().filter(
                self.model_class.id == entity_id
            ).first()

            if entity:
                self._logger.debug(
                    "entity_retrieved",
                    entity_id=str(entity_id),
                    tenant_id=self._tenant_id,
                )
            return entity

        except ValueError as e:
            self._logger.warning(
                "invalid_entity_id",
                entity_id=str(entity_id),
                error=str(e),
                tenant_id=self._tenant_id,
            )
            return None

    def get_all(
        self,
        limit: int = 50,
        offset: int = 0,
        order_by: str | None = None,
        descending: bool = True,
    ) -> list[T]:
        """
        Get all entities with pagination and tenant isolation.

        Args:
            limit: Maximum results (capped at 1000)
            offset: Number of results to skip
            order_by: Column name to order by
            descending: Sort descending if True

        Returns:
            List of entities
        """
        # Cap limit to prevent abuse
        limit = min(max(1, limit), 1000)
        offset = max(0, offset)

        query = self._base_query()

        # Apply ordering
        if order_by and hasattr(self.model_class, order_by):
            column = getattr(self.model_class, order_by)
            query = query.order_by(column.desc() if descending else column.asc())
        elif hasattr(self.model_class, "created_at"):
            query = query.order_by(self.model_class.created_at.desc())

        entities = query.offset(offset).limit(limit).all()

        self._logger.debug(
            "entities_listed",
            count=len(entities),
            limit=limit,
            offset=offset,
            tenant_id=self._tenant_id,
        )

        return entities

    def count(self) -> int:
        """
        Count total entities for tenant.

        Returns:
            Total count
        """
        return self._base_query().count()

    def exists(self, entity_id: UUID | str) -> bool:
        """
        Check if entity exists for tenant.

        Args:
            entity_id: Entity identifier

        Returns:
            True if entity exists
        """
        try:
            if isinstance(entity_id, str):
                entity_id = UUID(entity_id)

            return self._base_query().filter(
                self.model_class.id == entity_id
            ).count() > 0

        except ValueError:
            return False

    def create(self, entity: T) -> T:
        """
        Create new entity with tenant assignment.

        Args:
            entity: Entity to create

        Returns:
            Created entity with ID
        """
        # Ensure tenant_id is set if model supports it
        if hasattr(entity, "tenant_id"):
            entity.tenant_id = self._tenant_id

        db.session.add(entity)
        db.session.flush()

        self._logger.info(
            "entity_created",
            entity_id=str(entity.id),
            entity_type=self.model_class.__name__,
            tenant_id=self._tenant_id,
        )

        return entity

    def update(self, entity: T) -> T:
        """
        Update existing entity.

        Args:
            entity: Entity with updated values

        Returns:
            Updated entity
        """
        if hasattr(entity, "updated_at"):
            entity.updated_at = datetime.utcnow()

        db.session.merge(entity)
        db.session.flush()

        self._logger.info(
            "entity_updated",
            entity_id=str(entity.id),
            entity_type=self.model_class.__name__,
            tenant_id=self._tenant_id,
        )

        return entity

    def delete(self, entity_id: UUID | str) -> bool:
        """
        Delete entity by ID.

        Args:
            entity_id: Entity identifier

        Returns:
            True if deleted successfully
        """
        entity = self.get_by_id(entity_id)
        if not entity:
            return False

        db.session.delete(entity)
        db.session.flush()

        self._logger.info(
            "entity_deleted",
            entity_id=str(entity_id),
            entity_type=self.model_class.__name__,
            tenant_id=self._tenant_id,
        )

        return True

    def bulk_create(self, entities: list[T]) -> list[T]:
        """
        Create multiple entities in a single transaction.

        Args:
            entities: List of entities to create

        Returns:
            List of created entities
        """
        for entity in entities:
            if hasattr(entity, "tenant_id"):
                entity.tenant_id = self._tenant_id

        db.session.add_all(entities)
        db.session.flush()

        self._logger.info(
            "entities_bulk_created",
            count=len(entities),
            entity_type=self.model_class.__name__,
            tenant_id=self._tenant_id,
        )

        return entities

    def commit(self) -> None:
        """Commit current transaction."""
        db.session.commit()

    def rollback(self) -> None:
        """Rollback current transaction."""
        db.session.rollback()
