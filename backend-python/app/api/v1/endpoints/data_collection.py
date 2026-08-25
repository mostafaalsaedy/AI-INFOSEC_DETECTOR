"""
Data Collection API Endpoints
High-performance FastAPI endpoints for browser extension data collection
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import (
    AIInteraction,
    InteractionType,
    RiskLevel,
    SecurityAlert,
    UserSession,
    get_db,
    record_audit_event,
    record_metric,
)
from app.core.docs import get_endpoint_docs
from app.core.logging import logger
from app.core.security import rate_limiter, verify_extension_auth
from app.core.timeutils import utc_from_timestamp, utcnow
from app.services.ml_service import MLRiskAnalyzer
from app.services.notification_service import NotificationService
from app.services.privacy_service import PrivacyService
from app.services.websocket_manager import WebSocketManager

router = APIRouter()


# Request/Response Models
class DataCollectionRequest(BaseModel):
    """Request model for data collection"""

    session_id: str = Field(
        ..., min_length=10, max_length=100, description="Unique session identifier"
    )
    interaction_type: str = Field(
        ..., pattern="^(prompt|response)$", description="Type of interaction"
    )
    platform: str = Field(
        ..., min_length=1, max_length=50, description="AI platform name"
    )
    url: str = Field(..., max_length=500, description="Platform URL")
    timestamp: int = Field(..., description="Interaction timestamp (Unix)")

    # Content data (hashed for privacy)
    content_hash: Optional[str] = Field(
        None, min_length=64, max_length=64, description="SHA-256 hash of content"
    )
    content_length: Optional[int] = Field(
        None, ge=0, le=1000000, description="Content length in characters"
    )
    content_language: Optional[str] = Field(
        None, pattern="^[a-z]{2}$", description="Detected language code"
    )

    # Risk indicators from client-side analysis
    risk_indicators: Optional[Dict[str, Any]] = Field(
        None, description="Client-side risk analysis"
    )
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")

    @field_validator("timestamp")
    @classmethod
    def validate_timestamp(cls, v):
        # Ensure timestamp is within reasonable bounds (not too old or too far in future)
        now = utcnow().timestamp()
        if v < now - 3600 or v > now + 300:  # 1 hour past to 5 minutes future
            raise ValueError("Timestamp out of acceptable range")
        return v


class SecurityAlertRequest(BaseModel):
    """Request model for real-time security alerts"""

    alert_type: str = Field(..., description="Type of security alert")
    severity: str = Field(
        ..., pattern="^(low|medium|high|critical)$", description="Alert severity"
    )
    session_id: str = Field(..., description="Associated session ID")
    platform: str = Field(..., description="AI platform")
    evidence: Dict[str, Any] = Field(..., description="Alert evidence (anonymized)")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Detection confidence")
    timestamp: int = Field(..., description="Alert timestamp")


class ConsentRequest(BaseModel):
    """Request model for user consent management"""

    session_id: str = Field(..., description="Session identifier")
    consent: bool = Field(..., description="Consent status")
    consent_timestamp: int = Field(..., description="Consent timestamp")
    consent_version: str = Field("1.0", description="Privacy policy version")


class DataCollectionResponse(BaseModel):
    """Response model for data collection"""

    success: bool
    interaction_id: Optional[int] = None
    risk_level: str
    risk_score: float
    alerts_generated: int = 0
    message: str = "Data collected successfully"


class HealthCheckResponse(BaseModel):
    """Health check response"""

    status: str
    timestamp: float
    version: str
    services: Dict[str, str]


# Dependency injection
async def get_ml_analyzer() -> MLRiskAnalyzer:
    """Get ML analyzer instance"""
    return MLRiskAnalyzer()


async def get_notification_service() -> NotificationService:
    """Get notification service instance"""
    return NotificationService()


async def get_websocket_manager() -> WebSocketManager:
    """Get WebSocket manager instance"""
    return WebSocketManager()


async def get_privacy_service() -> PrivacyService:
    """Get privacy service instance"""
    return PrivacyService()


# Main data collection endpoint
@router.post(
    "/collect",
    response_model=DataCollectionResponse,
    summary="Collect AI Interaction Data",
    description="""
    Collect and analyze AI platform interaction data from browser extensions.

    This endpoint:
    - Receives interaction data from browser extensions
    - Performs real-time ML-powered risk analysis
    - Generates security alerts for high-risk activities
    - Ensures GDPR/CCPA compliance through consent validation
    - Provides immediate risk feedback to the extension

    **Rate Limits**: 5000 requests per hour per API key

    **Privacy**: Only content hashes are processed, never plain text content
    """,
    **get_endpoint_docs("Data Collection", "create"),
)
async def collect_interaction_data(
    request: DataCollectionRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    ml_analyzer: MLRiskAnalyzer = Depends(get_ml_analyzer),
    notification_service: NotificationService = Depends(get_notification_service),
    websocket_manager: WebSocketManager = Depends(get_websocket_manager),
    privacy_service: PrivacyService = Depends(get_privacy_service),
    auth_data: dict = Depends(verify_extension_auth),
    _rate_limit: None = Depends(rate_limiter),
):
    """
    Collect and process AI interaction data with ML-powered risk analysis
    """
    try:
        # Record metrics
        await record_metric(
            "api_requests_total",
            1,
            {"endpoint": "collect", "platform": request.platform},
        )

        # Get or create user session
        session = await get_or_create_session(
            db, request.session_id, http_request, auth_data
        )

        # Verify consent
        if not session.data_collection_consent:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "consent_required",
                    "message": "Data collection consent is required",
                    "consent_url": "/api/v1/consent",
                },
            )

        # Check consent expiry
        if privacy_service.is_consent_expired(session):
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "consent_expired",
                    "message": "Data collection consent has expired",
                    "consent_url": "/api/v1/consent",
                },
            )

        # Create interaction record
        interaction = await create_interaction_record(
            db, request, session, http_request, ml_analyzer
        )

        # Perform ML risk analysis
        ml_results = await ml_analyzer.analyze_interaction_async(interaction)

        # Update interaction with ML results
        interaction.ml_predictions = ml_results.predictions
        interaction.confidence_score = ml_results.confidence
        interaction.anomaly_score = ml_results.anomaly_score

        # Update risk assessment based on ML results
        if ml_results.risk_level.value != interaction.risk_level.value:
            interaction.risk_level = ml_results.risk_level
            interaction.risk_score = max(interaction.risk_score, ml_results.risk_score)

        await db.commit()

        # Generate security alerts if high risk
        alerts_generated = 0
        if interaction.is_high_risk() or ml_results.should_alert:
            alert = await create_security_alert(db, interaction, ml_results)
            alerts_generated = 1

            # Send notifications in background
            background_tasks.add_task(
                notification_service.send_alert_notifications, alert
            )

            # Broadcast to WebSocket clients
            background_tasks.add_task(
                websocket_manager.broadcast_alert,
                {
                    "alert_id": alert.id,
                    "severity": alert.severity.value,
                    "platform": request.platform,
                    "risk_score": interaction.risk_score,
                },
            )

        # Update session statistics
        await update_session_stats(db, session, request.platform)

        # Record audit event
        await record_audit_event(
            event_type="interaction_collected",
            event_category="data_collection",
            description=f"AI interaction collected from {request.platform}",
            user_id=session.user_id,
            event_data={
                "platform": request.platform,
                "risk_level": interaction.risk_level.value,
                "risk_score": interaction.risk_score,
                "alerts_generated": alerts_generated,
            },
        )

        # Record performance metrics
        await record_metric(
            "interactions_processed",
            1,
            {"platform": request.platform, "risk_level": interaction.risk_level.value},
        )

        return DataCollectionResponse(
            success=True,
            interaction_id=interaction.id,
            risk_level=interaction.risk_level.value,
            risk_score=interaction.risk_score,
            alerts_generated=alerts_generated,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Data collection error: {str(e)}", exc_info=True)
        await record_metric(
            "api_errors_total", 1, {"endpoint": "collect", "error": type(e).__name__}
        )

        raise HTTPException(
            status_code=500,
            detail={
                "error": "processing_failed",
                "message": "Failed to process interaction data",
            },
        )


@router.post("/alert")
async def receive_security_alert(
    request: SecurityAlertRequest,
    http_request: Request,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    notification_service: NotificationService = Depends(get_notification_service),
    websocket_manager: WebSocketManager = Depends(get_websocket_manager),
    privacy_service: PrivacyService = Depends(get_privacy_service),
    auth_data: dict = Depends(verify_extension_auth),
    _rate_limit: None = Depends(rate_limiter),
):
    """
    Receive real-time security alerts from browser extension
    """
    try:
        await record_metric(
            "security_alerts_received",
            1,
            {"platform": request.platform, "severity": request.severity},
        )

        # Find associated interaction
        result = await db.execute(
            select(AIInteraction)
            .where(AIInteraction.session_id == request.session_id)
            .order_by(AIInteraction.created_at.desc())
            .limit(1)
        )
        interaction = result.scalars().first()

        # Create security alert
        alert = SecurityAlert(
            interaction_id=interaction.id if interaction else None,
            alert_type=request.alert_type,
            severity=RiskLevel(request.severity),
            title=f"Real-time {request.severity.title()} Risk Detection",
            description=f"High-risk activity detected on {request.platform}",
            detection_rules=["real_time_client_analysis"],
            evidence=privacy_service.sanitize_evidence(request.evidence),
            confidence_score=request.confidence,
            ml_confidence=request.confidence,
        )

        db.add(alert)
        await db.commit()

        # Send notifications for critical/high alerts
        if alert.severity in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            background_tasks.add_task(
                notification_service.send_alert_notifications, alert
            )

        # Broadcast to WebSocket clients
        background_tasks.add_task(
            websocket_manager.broadcast_alert,
            {
                "alert_id": alert.id,
                "severity": alert.severity.value,
                "platform": request.platform,
                "timestamp": request.timestamp,
            },
        )

        # Record audit event
        await record_audit_event(
            event_type="security_alert_received",
            event_category="security",
            description=f"Real-time security alert from {request.platform}",
            event_data={
                "alert_type": request.alert_type,
                "severity": request.severity,
                "platform": request.platform,
                "confidence": request.confidence,
            },
        )

        return {
            "success": True,
            "alert_id": alert.id,
            "message": "Security alert recorded successfully",
        }

    except Exception as e:
        logger.error(f"Security alert processing error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to process security alert")


@router.post("/consent")
async def manage_user_consent(
    request: ConsentRequest,
    http_request: Request,
    db: AsyncSession = Depends(get_db),
    privacy_service: PrivacyService = Depends(get_privacy_service),
    auth_data: dict = Depends(verify_extension_auth),
    _rate_limit: None = Depends(rate_limiter),
):
    """
    Manage user data collection consent
    """
    try:
        # Get or create session
        session = await get_or_create_session(
            db, request.session_id, http_request, auth_data
        )

        # Update consent
        session.data_collection_consent = request.consent
        session.consent_updated_at = utc_from_timestamp(request.consent_timestamp)

        await db.commit()

        # Record audit event
        await record_audit_event(
            event_type="consent_updated",
            event_category="privacy",
            description=f"User consent {'granted' if request.consent else 'revoked'}",
            user_id=session.user_id,
            event_data={
                "consent_status": request.consent,
                "consent_version": request.consent_version,
                "session_id": request.session_id,
            },
        )

        # If consent is revoked, trigger data anonymization
        if not request.consent:
            await privacy_service.anonymize_user_data(session.session_id)

        return {
            "success": True,
            "consent_recorded": request.consent,
            "message": "Consent preferences updated successfully",
        }

    except Exception as e:
        logger.error(f"Consent management error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to update consent preferences"
        )


@router.get("/health", response_model=HealthCheckResponse)
async def health_check(
    db: AsyncSession = Depends(get_db),
    ml_analyzer: MLRiskAnalyzer = Depends(get_ml_analyzer),
):
    """
    Comprehensive health check for data collection service
    """
    try:
        services = {}

        # Check database
        try:
            await db.execute("SELECT 1")
            services["database"] = "healthy"
        except Exception:
            services["database"] = "unhealthy"

        # Check ML analyzer
        try:
            ml_health = await ml_analyzer.health_check()
            services["ml_analyzer"] = "healthy" if ml_health else "degraded"
        except Exception:
            services["ml_analyzer"] = "unhealthy"

        # Check Redis (via record_metric)
        try:
            await record_metric("health_check", 1)
            services["redis"] = "healthy"
        except Exception:
            services["redis"] = "unhealthy"

        overall_status = (
            "healthy"
            if all(status == "healthy" for status in services.values())
            else "degraded"
        )

        return HealthCheckResponse(
            status=overall_status,
            timestamp=utcnow().timestamp(),
            version=settings.VERSION,
            services=services,
        )

    except Exception as e:
        logger.error(f"Health check error: {str(e)}")
        raise HTTPException(status_code=503, detail="Health check failed")


# Helper functions
async def get_or_create_session(
    db: AsyncSession, session_id: str, request: Request, auth_data: dict
) -> UserSession:
    """Get existing session or create new one"""

    # Try to find existing session
    result = await db.execute(
        select(UserSession).where(UserSession.session_id == session_id)
    )
    session = result.scalars().first()

    if session:
        # Update last activity
        session.last_activity_at = utcnow()
        return session

    # Create new session
    user_agent = request.headers.get("user-agent", "")
    browser_info = parse_user_agent(user_agent)

    session = UserSession(
        session_id=session_id,
        user_id=auth_data.get("user_id"),
        extension_version=request.headers.get("x-extension-version"),
        browser_name=browser_info.get("browser"),
        browser_version=browser_info.get("version"),
        operating_system=browser_info.get("os"),
        user_agent=user_agent,
        session_started_at=utcnow(),
        last_activity_at=utcnow(),
    )

    db.add(session)
    await db.commit()

    return session


async def create_interaction_record(
    db: AsyncSession,
    request: DataCollectionRequest,
    session: UserSession,
    http_request: Request,
    ml_analyzer: MLRiskAnalyzer,
) -> AIInteraction:
    """Create new interaction record with risk analysis"""

    # Perform initial risk analysis
    risk_analysis = await ml_analyzer.analyze_risk_indicators(
        request.risk_indicators or {}
    )

    interaction = AIInteraction(
        session_id=request.session_id,
        user_id=session.user_id,
        platform=request.platform,
        platform_url=request.url,
        interaction_type=InteractionType(request.interaction_type),
        content_hash=request.content_hash,
        content_length=request.content_length or 0,
        content_language=request.content_language,
        risk_level=risk_analysis.risk_level,
        risk_score=risk_analysis.risk_score,
        risk_flags=risk_analysis.flags,
        interaction_metadata=request.metadata or {},
        user_agent=http_request.headers.get("user-agent"),
        ip_address=http_request.client.host,
        user_consent=session.data_collection_consent,
        consent_timestamp=session.consent_updated_at,
        interaction_timestamp=utc_from_timestamp(request.timestamp),
    )

    db.add(interaction)
    await db.commit()

    return interaction


async def create_security_alert(
    db: AsyncSession, interaction: AIInteraction, ml_results
) -> SecurityAlert:
    """Create security alert for high-risk interaction"""

    alert = SecurityAlert(
        interaction_id=interaction.id,
        alert_type="ml_risk_detection",
        severity=interaction.risk_level,
        title=f"{interaction.risk_level.value.title()} Risk AI Interaction",
        description=f"ML analysis detected {interaction.risk_level.value} risk activity",
        detection_rules=ml_results.triggered_rules,
        evidence={
            "risk_score": interaction.risk_score,
            "confidence": ml_results.confidence,
            "risk_flags": interaction.risk_flags,
            "platform": interaction.platform,
            "anomaly_score": ml_results.anomaly_score,
        },
        confidence_score=ml_results.confidence,
        ml_confidence=ml_results.confidence,
    )

    db.add(alert)
    await db.commit()

    return alert


async def update_session_stats(db: AsyncSession, session: UserSession, platform: str):
    """Update session statistics"""

    session.total_interactions += 1

    # Add platform to used platforms list
    platforms = session.platforms_used or []
    if platform not in platforms:
        platforms.append(platform)
        session.platforms_used = platforms

    # Calculate session duration
    if session.session_started_at:
        duration = utcnow() - session.session_started_at
        session.duration_minutes = int(duration.total_seconds() / 60)

    await db.commit()


def parse_user_agent(user_agent: str) -> Dict[str, str]:
    """Parse user agent string to extract browser information"""
    # Simple user agent parsing - could be enhanced with a proper library
    result = {"browser": "Unknown", "version": "Unknown", "os": "Unknown"}

    if "Chrome" in user_agent:
        result["browser"] = "Chrome"
        # Extract version if needed
    elif "Firefox" in user_agent:
        result["browser"] = "Firefox"
    elif "Edge" in user_agent:
        result["browser"] = "Edge"
    elif "Safari" in user_agent and "Chrome" not in user_agent:
        result["browser"] = "Safari"

    if "Windows" in user_agent:
        result["os"] = "Windows"
    elif "Macintosh" in user_agent or "Mac OS" in user_agent:
        result["os"] = "macOS"
    elif "Linux" in user_agent:
        result["os"] = "Linux"

    return result
