"""
Shared test fixtures.

The suite runs entirely against an in-memory-style SQLite file (configured by
`ENVIRONMENT=testing`), so no PostgreSQL, Redis or Celery broker is needed.
Each test gets a fresh schema.
"""

import time
from datetime import datetime, timedelta
from typing import Any, AsyncGenerator, Dict
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import (
    AIInteraction,
    AlertStatus,
    AsyncSessionLocal,
    Base,
    InteractionType,
    RiskLevel,
    SecurityAlert,
    UserConsent,
    UserSession,
    async_engine,
    get_db,
)
from app.core.security import create_access_token, sign_extension_payload
from app.core.timeutils import utcnow
from app.main import app
from app.services.ml_service import MLRiskAnalyzer
from app.services.websocket_manager import WebSocketManager

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def db_session() -> AsyncGenerator[AsyncSession, None]:
    """Yield a session against a freshly created schema."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    session = AsyncSessionLocal()
    try:
        yield session
    finally:
        await session.rollback()
        await session.close()
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def client(db_session: AsyncSession) -> AsyncGenerator[AsyncClient, None]:
    """HTTP client bound to the ASGI app with the test session injected.

    The app's lifespan is deliberately not run: it would try to load ML models
    and start background loops, neither of which a request-level test needs.
    """

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://localhost") as http:
        yield http

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def analyst_token() -> str:
    """Bearer token for a user who may read and triage alerts."""
    return create_access_token(subject="analyst@example.com", role="analyst")


@pytest.fixture
def admin_token() -> str:
    """Bearer token for a user with every permission."""
    return create_access_token(subject="admin@example.com", role="admin")


@pytest.fixture
def viewer_token() -> str:
    """Bearer token for a read-only user."""
    return create_access_token(subject="viewer@example.com", role="viewer")


@pytest.fixture
def auth_headers(analyst_token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {analyst_token}"}


@pytest.fixture
def admin_headers(admin_token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def sign_extension_request():
    """Build the signed headers the extension endpoints require."""

    def _sign(body: str, extension_id: str = "test-extension") -> Dict[str, str]:
        timestamp = str(int(time.time()))
        return {
            "X-Extension-Id": extension_id,
            "X-Extension-Timestamp": timestamp,
            "X-Extension-Signature": sign_extension_payload(body, timestamp),
            "X-Extension-Version": "1.0.0",
            "Content-Type": "application/json",
        }

    return _sign


# ---------------------------------------------------------------------------
# Data factories
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def make_session(db_session: AsyncSession):
    """Insert a UserSession row."""

    async def _make(
        session_id: str = "test-session-1",
        user_id: str = "user-1",
        consent: bool = True,
        **kwargs: Any,
    ) -> UserSession:
        session = UserSession(
            session_id=session_id,
            user_id=user_id,
            data_collection_consent=consent,
            consent_updated_at=utcnow() if consent else None,
            monitoring_enabled=True,
            session_started_at=utcnow(),
            last_activity_at=utcnow(),
            browser_name=kwargs.pop("browser_name", "Chrome"),
            extension_version=kwargs.pop("extension_version", "1.0.0"),
            **kwargs,
        )
        db_session.add(session)
        await db_session.flush()
        return session

    return _make


@pytest_asyncio.fixture
async def make_interaction(db_session: AsyncSession, make_session):
    """Insert an AIInteraction row, creating its parent session on demand."""

    async def _make(
        session_id: str = "test-session-1",
        platform: str = "chatgpt",
        risk_level: RiskLevel = RiskLevel.LOW,
        risk_score: float = 10.0,
        created_at: datetime = None,
        **kwargs: Any,
    ) -> AIInteraction:
        # The FK targets `session_id`, not the surrogate key, so look it up by
        # that column rather than with `Session.get`, which searches by PK.
        existing = await db_session.scalar(
            select(UserSession).where(UserSession.session_id == session_id)
        )
        if existing is None:
            await make_session(session_id=session_id)

        moment = created_at or utcnow()
        interaction = AIInteraction(
            session_id=session_id,
            user_id=kwargs.pop("user_id", "user-1"),
            platform=platform,
            platform_url=kwargs.pop("platform_url", f"https://{platform}.com/chat"),
            interaction_type=kwargs.pop("interaction_type", InteractionType.PROMPT),
            content_hash=kwargs.pop("content_hash", "a" * 64),
            content_length=kwargs.pop("content_length", 128),
            risk_level=risk_level,
            risk_score=risk_score,
            risk_flags=kwargs.pop("risk_flags", []),
            confidence_score=kwargs.pop("confidence_score", 80.0),
            user_consent=True,
            interaction_timestamp=moment,
            created_at=moment,
            **kwargs,
        )
        db_session.add(interaction)
        await db_session.flush()
        return interaction

    return _make


@pytest_asyncio.fixture
async def make_alert(db_session: AsyncSession):
    """Insert a SecurityAlert row."""

    async def _make(
        interaction_id: int = None,
        severity: RiskLevel = RiskLevel.HIGH,
        status: AlertStatus = AlertStatus.OPEN,
        alert_type: str = "sensitive_data",
        created_at: datetime = None,
        **kwargs: Any,
    ) -> SecurityAlert:
        alert = SecurityAlert(
            interaction_id=interaction_id,
            alert_type=alert_type,
            severity=severity,
            status=status,
            title=kwargs.pop("title", "Sensitive data detected in prompt"),
            description=kwargs.pop("description", "An API key pattern was matched."),
            confidence_score=kwargs.pop("confidence_score", 92.0),
            priority=kwargs.pop("priority", 8),
            created_at=created_at or utcnow(),
            **kwargs,
        )
        db_session.add(alert)
        await db_session.flush()
        return alert

    return _make


@pytest_asyncio.fixture
async def make_consent(db_session: AsyncSession):
    """Insert a UserConsent row."""

    async def _make(
        session_id: str = "test-session-1",
        granted: bool = True,
        expires_in_days: int = 180,
        **kwargs: Any,
    ) -> UserConsent:
        consent = UserConsent(
            session_id=session_id,
            user_id=kwargs.pop("user_id", "user-1"),
            granted=granted,
            granted_at=utcnow() if granted else None,
            expires_at=utcnow() + timedelta(days=expires_in_days),
            **kwargs,
        )
        db_session.add(consent)
        await db_session.flush()
        return consent

    return _make


# ---------------------------------------------------------------------------
# Doubles
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_websocket():
    """A WebSocket double that records what was sent to it."""
    websocket = MagicMock()
    websocket.accept = AsyncMock()
    websocket.send_text = AsyncMock()
    websocket.send_json = AsyncMock()
    websocket.close = AsyncMock()
    websocket.client = MagicMock(host="127.0.0.1")
    websocket.headers = {}
    return websocket


@pytest.fixture
def ml_analyzer() -> MLRiskAnalyzer:
    """A real analyzer using only the pattern pipeline (no model downloads)."""
    return MLRiskAnalyzer()


@pytest_asyncio.fixture
async def ws_manager() -> AsyncGenerator[WebSocketManager, None]:
    """A fresh manager so tests never share connection state.

    Shut down on teardown so per-connection heartbeat tasks are cancelled
    rather than outliving the test's event loop.
    """
    manager = WebSocketManager()
    try:
        yield manager
    finally:
        await manager.shutdown()


@pytest.fixture
def sample_interaction_payload() -> Dict[str, Any]:
    """A well-formed /api/v1/collect body."""
    return {
        "session_id": "test-session-1",
        "platform": "chatgpt",
        "url": "https://chatgpt.com/c/abc",
        "interaction_type": "prompt",
        "timestamp": int(utcnow().timestamp()),
        "content_hash": "b" * 64,
        "content_length": 256,
        "risk_indicators": {"flags": ["email"], "score": 12},
        "metadata": {"pageTitle": "New chat"},
    }
