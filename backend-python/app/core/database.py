"""
Database configuration and models using SQLAlchemy with async support
"""

import enum
from contextlib import asynccontextmanager
from datetime import timedelta
from typing import Any, Dict, Optional

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy import (
    Enum as SQLEnum,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy.pool import StaticPool

from app.core.config import settings
from app.core.logging import logger
from app.core.timeutils import utcnow

# Create async engine.
# SQLite's async driver uses a non-queue pool, which rejects pool sizing args,
# so those are only passed for server-backed databases such as PostgreSQL.
_engine_options: Dict[str, Any] = {"echo": settings.DATABASE_ECHO}

if settings.DATABASE_URL.startswith("sqlite"):
    if ":memory:" in settings.DATABASE_URL:
        # Every new connection to an in-memory SQLite database gets its own
        # blank copy. StaticPool reuses a single connection so the schema
        # survives between sessions.
        _engine_options["poolclass"] = StaticPool
        _engine_options["connect_args"] = {"check_same_thread": False}
else:
    _engine_options.update(
        pool_size=settings.DATABASE_POOL_SIZE,
        max_overflow=settings.DATABASE_MAX_OVERFLOW,
        pool_pre_ping=True,
        pool_recycle=1800,
    )

engine = create_async_engine(settings.DATABASE_URL, **_engine_options)

# Backwards-compatible alias used by the test fixtures.
async_engine = engine

# Create session factory
AsyncSessionLocal = async_sessionmaker(
    engine, class_=AsyncSession, expire_on_commit=False
)

# Base class for all models
Base = declarative_base()


def _enum_values(enum_cls):
    """Store enum *values* in the database instead of member names."""
    return SQLEnum(
        enum_cls,
        values_callable=lambda e: [member.value for member in e],
        native_enum=False,
        length=32,
    )


class RiskLevel(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class InteractionType(str, enum.Enum):
    PROMPT = "prompt"
    RESPONSE = "response"


class ConsentScope(str, enum.Enum):
    """Granular consent scopes tracked per data subject."""

    MONITORING = "monitoring"
    RISK_ANALYSIS = "risk_analysis"
    ANALYTICS = "analytics"
    ALERTING = "alerting"


# Alert severity reuses the risk scale; exported under its domain name so alert
# code can read `AlertSeverity.CRITICAL` without importing `RiskLevel`.
AlertSeverity = RiskLevel


class UserSession(Base):
    """User session tracking"""

    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True)
    session_id = Column(String(100), unique=True, nullable=False, index=True)
    user_id = Column(String(100), nullable=True, index=True)

    # Browser information
    extension_version = Column(String(20))
    browser_name = Column(String(50))
    browser_version = Column(String(20))
    operating_system = Column(String(50))
    user_agent = Column(Text)

    # Session tracking
    session_started_at = Column(DateTime, default=utcnow)
    last_activity_at = Column(DateTime, default=utcnow)
    session_ended_at = Column(DateTime, nullable=True)

    # Statistics
    total_interactions = Column(Integer, default=0)
    total_alerts = Column(Integer, default=0)
    platforms_used = Column(JSON, default=list)
    duration_minutes = Column(Integer, default=0)

    # Privacy settings
    monitoring_enabled = Column(Boolean, default=True)
    data_collection_consent = Column(Boolean, default=False)
    consent_updated_at = Column(DateTime, nullable=True)

    # Relationships
    interactions = relationship(
        "AIInteraction", back_populates="session", cascade="all, delete-orphan"
    )

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    # Indexes
    __table_args__ = (
        Index("idx_session_user_activity", "user_id", "last_activity_at"),
        Index("idx_session_monitoring", "monitoring_enabled", "data_collection_consent"),
    )

    def is_active(self) -> bool:
        """Check if session is currently active"""
        if self.session_ended_at:
            return False

        cutoff = utcnow() - timedelta(hours=4)
        return self.last_activity_at > cutoff

    def calculate_risk_score(self) -> float:
        """Calculate user risk score based on alerts and interactions"""
        if self.total_interactions == 0:
            return 0.0

        return min((self.total_alerts / self.total_interactions) * 100, 100.0)


class AIInteraction(Base):
    """AI platform interaction tracking"""

    __tablename__ = "ai_interactions"

    id = Column(Integer, primary_key=True)

    # Session tracking
    session_id = Column(
        String(100), ForeignKey("user_sessions.session_id"), nullable=False, index=True
    )
    user_id = Column(String(100), nullable=True, index=True)

    # Platform information
    platform = Column(String(50), nullable=False, index=True)
    platform_url = Column(String(500))
    page_title = Column(String(200))

    # Interaction data
    interaction_type = Column(_enum_values(InteractionType), nullable=False)
    content_hash = Column(String(64))  # SHA-256 hash
    content_length = Column(Integer, default=0)
    content_language = Column(String(10))  # Language detection

    # Risk analysis
    risk_level = Column(_enum_values(RiskLevel), default=RiskLevel.LOW, index=True)
    risk_score = Column(Float, default=0.0, index=True)
    risk_flags = Column(JSON, default=list)
    confidence_score = Column(Float, default=0.0)

    # ML analysis results
    ml_predictions = Column(JSON)  # Store ML model predictions
    anomaly_score = Column(Float, default=0.0)
    sentiment_score = Column(Float, default=0.0)

    # Metadata. The attribute cannot be called `metadata`: SQLAlchemy's
    # declarative base reserves that name, so the column keeps the DB name
    # `metadata` while the Python attribute is `interaction_metadata`.
    interaction_metadata = Column("metadata", JSON)
    user_agent = Column(Text)
    ip_address = Column(String(45))  # IPv6 support

    # Privacy compliance
    user_consent = Column(Boolean, default=False)
    consent_timestamp = Column(DateTime)
    data_processed = Column(Boolean, default=False)
    anonymized = Column(Boolean, default=False)

    # Timestamps
    interaction_timestamp = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    deleted_at = Column(DateTime, nullable=True)  # Soft delete

    # Relationships
    session = relationship("UserSession", back_populates="interactions")
    security_alerts = relationship(
        "SecurityAlert", back_populates="interaction", cascade="all, delete-orphan"
    )

    # Indexes
    __table_args__ = (
        Index("idx_interaction_platform_time", "platform", "created_at"),
        Index("idx_interaction_risk", "risk_level", "risk_score"),
        Index("idx_interaction_user_time", "user_id", "created_at"),
        Index("idx_interaction_consent", "user_consent", "data_processed"),
    )

    def is_high_risk(self) -> bool:
        """Check if interaction is high risk"""
        return (
            self.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]
            or self.risk_score >= 70
        )

    def has_risk_flag(self, flag: str) -> bool:
        """Check if interaction has specific risk flag"""
        return flag in (self.risk_flags or [])


class SecurityAlert(Base):
    """Security alerts generated from interactions"""

    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True)

    # Reference to interaction
    interaction_id = Column(Integer, ForeignKey("ai_interactions.id"), nullable=True)

    # Alert information
    alert_type = Column(String(100), nullable=False, index=True)
    severity = Column(_enum_values(RiskLevel), nullable=False, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text)

    # Detection details
    detection_rules = Column(JSON)  # Rules that triggered alert
    evidence = Column(JSON)  # Evidence data (anonymized)
    confidence_score = Column(Float, default=0.0)
    ml_confidence = Column(Float, default=0.0)  # ML model confidence

    # Status tracking
    status = Column(_enum_values(AlertStatus), default=AlertStatus.OPEN, index=True)
    assigned_to = Column(String(100), nullable=True, index=True)
    priority = Column(Integer, default=5)  # 1-10 scale

    # Resolution
    resolution_notes = Column(Text)
    resolved_at = Column(DateTime, nullable=True)
    resolved_by = Column(String(100))

    # Notification tracking
    notification_sent = Column(Boolean, default=False)
    notification_channels = Column(JSON)  # Which channels were notified
    notification_sent_at = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    # Relationships
    interaction = relationship("AIInteraction", back_populates="security_alerts")

    # Indexes
    __table_args__ = (
        Index("idx_alert_severity_status", "severity", "status"),
        Index("idx_alert_type_created", "alert_type", "created_at"),
        Index("idx_alert_assigned", "assigned_to", "status"),
    )

    def is_critical(self) -> bool:
        """Check if alert is critical"""
        return self.severity == RiskLevel.CRITICAL

    def is_open(self) -> bool:
        """Check if alert is open"""
        return self.status == AlertStatus.OPEN

    def days_open(self) -> int:
        """Calculate days since alert was created"""
        return (utcnow() - self.created_at).days


class MLModel(Base):
    """ML model metadata and versioning"""

    __tablename__ = "ml_models"

    id = Column(Integer, primary_key=True)
    model_name = Column(String(100), nullable=False)
    model_type = Column(String(50))  # sklearn, tensorflow, transformers
    version = Column(String(20))

    # Model metadata
    model_path = Column(String(500))
    model_config = Column(JSON)
    training_data_hash = Column(String(64))

    # Performance metrics
    accuracy = Column(Float)
    precision = Column(Float)
    recall = Column(Float)
    f1_score = Column(Float)

    # Status
    is_active = Column(Boolean, default=False)
    is_trained = Column(Boolean, default=False)

    # Training information
    training_started_at = Column(DateTime)
    training_completed_at = Column(DateTime)
    training_duration_minutes = Column(Integer)
    training_samples = Column(Integer)

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class AuditLog(Base):
    """Comprehensive audit logging"""

    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)

    # Event information
    event_type = Column(String(100), nullable=False, index=True)
    event_category = Column(String(50), index=True)  # security, privacy, admin
    event_description = Column(Text)

    # Actor information
    user_id = Column(String(100), index=True)
    session_id = Column(String(100))
    ip_address = Column(String(45))
    user_agent = Column(Text)

    # Target information
    target_type = Column(String(100))  # user, interaction, alert
    target_id = Column(String(100))

    # Event data
    event_data = Column(JSON)
    changes = Column(JSON)  # Before/after for modifications

    # Risk assessment
    risk_level = Column(_enum_values(RiskLevel), default=RiskLevel.LOW)

    created_at = Column(DateTime, default=utcnow, index=True)

    # Indexes
    __table_args__ = (
        Index("idx_audit_user_time", "user_id", "created_at"),
        Index("idx_audit_type_category", "event_type", "event_category"),
        Index("idx_audit_risk_time", "risk_level", "created_at"),
    )


class SystemMetrics(Base):
    """System performance and usage metrics"""

    __tablename__ = "system_metrics"

    id = Column(Integer, primary_key=True)

    # Metric information
    metric_name = Column(String(100), nullable=False, index=True)
    metric_type = Column(String(50))  # counter, gauge, histogram
    metric_value = Column(Float, nullable=False)

    # Dimensions/Tags
    tags = Column(JSON)  # Additional metric dimensions

    # Timestamps
    recorded_at = Column(DateTime, default=utcnow, index=True)

    # Indexes
    __table_args__ = (Index("idx_metrics_name_time", "metric_name", "recorded_at"),)


class UserConsent(Base):
    """GDPR/CCPA consent records, versioned and independently auditable."""

    __tablename__ = "user_consents"

    id = Column(Integer, primary_key=True)

    # Data subject
    session_id = Column(String(100), nullable=False, index=True)
    user_id = Column(String(100), nullable=True, index=True)

    # What was consented to
    scope = Column(
        _enum_values(ConsentScope), default=ConsentScope.MONITORING, index=True
    )
    granted = Column(Boolean, default=False, nullable=False, index=True)
    policy_version = Column(String(20), default="1.0")

    # Provenance - required to prove consent was freely given
    consent_text_hash = Column(String(64))
    collection_method = Column(String(50), default="extension_popup")
    ip_address = Column(String(45))
    user_agent = Column(Text)

    # Lifecycle
    granted_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    withdrawn_at = Column(DateTime, nullable=True)
    withdrawal_reason = Column(Text)

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    __table_args__ = (
        Index("idx_consent_session_scope", "session_id", "scope"),
        Index("idx_consent_active", "granted", "expires_at"),
    )

    def is_active(self) -> bool:
        """Consent is active when granted, not withdrawn and not expired."""
        if not self.granted or self.withdrawn_at is not None:
            return False
        if self.expires_at is not None and self.expires_at <= utcnow():
            return False
        return True

    def is_expired(self) -> bool:
        """Check whether the consent has passed its expiry date."""
        return self.expires_at is not None and self.expires_at <= utcnow()


# Database session management
@asynccontextmanager
async def get_db_session():
    """Get database session with proper cleanup"""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def get_db() -> AsyncSession:
    """FastAPI dependency yielding a database session.

    `get_db_session` is an async context manager for use in scripts, Celery
    tasks and background jobs. FastAPI needs a plain async generator, which is
    what this provides - use `Depends(get_db)` in route signatures.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db():
    """Initialize database tables"""
    try:
        async with engine.begin() as conn:
            # Create all tables
            await conn.run_sync(Base.metadata.create_all)

        logger.info("Database tables initialized successfully")

    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise


async def cleanup_old_data():
    """Clean up old data based on the configured retention policies."""
    try:
        now = utcnow()
        cutoff_date = now - timedelta(days=settings.DATA_RETENTION_DAYS)
        hard_delete_cutoff = now - timedelta(days=settings.DATA_RETENTION_DAYS + 90)
        audit_cutoff = now - timedelta(days=settings.DATA_RETENTION_DAYS * 2)

        async with get_db_session() as db:
            # Soft delete interactions past the retention window
            soft_deleted = await db.execute(
                text(
                    "UPDATE ai_interactions SET deleted_at = :now "
                    "WHERE created_at < :cutoff AND deleted_at IS NULL"
                ),
                {"now": now, "cutoff": cutoff_date},
            )

            # Hard delete records that have been soft-deleted long enough
            hard_deleted = await db.execute(
                text("DELETE FROM ai_interactions WHERE deleted_at < :cutoff"),
                {"cutoff": hard_delete_cutoff},
            )

            # Remove stale sessions
            sessions_removed = await db.execute(
                text(
                    "DELETE FROM user_sessions WHERE session_ended_at < :cutoff "
                    "OR (last_activity_at < :cutoff AND session_ended_at IS NULL)"
                ),
                {"cutoff": cutoff_date},
            )

            # Audit logs are kept twice as long for compliance purposes
            audit_removed = await db.execute(
                text("DELETE FROM audit_logs WHERE created_at < :cutoff"),
                {"cutoff": audit_cutoff},
            )

        logger.info(
            "Data retention cleanup completed: "
            f"{soft_deleted.rowcount} interactions soft-deleted, "
            f"{hard_deleted.rowcount} purged, "
            f"{sessions_removed.rowcount} sessions removed, "
            f"{audit_removed.rowcount} audit records removed"
        )

    except Exception as e:
        logger.error(f"Data cleanup failed: {str(e)}")


# Utility functions
async def record_audit_event(
    event_type: str,
    event_category: str,
    description: str,
    user_id: Optional[str] = None,
    event_data: Optional[Dict[str, Any]] = None,
    risk_level: RiskLevel = RiskLevel.LOW,
):
    """Record audit event"""
    try:
        async with get_db_session() as db:
            audit_log = AuditLog(
                event_type=event_type,
                event_category=event_category,
                event_description=description,
                user_id=user_id,
                event_data=event_data or {},
                risk_level=risk_level,
            )
            db.add(audit_log)
            await db.commit()

    except Exception as e:
        logger.error(f"Failed to record audit event: {str(e)}")


async def record_metric(
    metric_name: str, value: float, tags: Optional[Dict[str, Any]] = None
):
    """Record system metric"""
    try:
        async with get_db_session() as db:
            metric = SystemMetrics(
                metric_name=metric_name, metric_value=value, tags=tags or {}
            )
            db.add(metric)
            await db.commit()

    except Exception as e:
        logger.error(f"Failed to record metric {metric_name}: {str(e)}")
