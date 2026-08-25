"""
Analytics API Endpoints with Comprehensive Documentation
Advanced analytics and reporting endpoints for InfoSec AI Monitor
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field, model_validator
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.docs import get_endpoint_docs
from app.core.logging import logger
from app.core.security import rate_limiter, verify_api_auth
from app.core.timeutils import utcnow
from app.services.analytics_service import AnalyticsService
from app.services.export_service import ExportService

router = APIRouter()


# Enums for API parameters
class TimeRangeType(str, Enum):
    """Time range options for analytics queries"""

    hour = "1h"
    day = "24h"
    week = "7d"
    month = "30d"
    quarter = "90d"
    year = "365d"
    custom = "custom"


class ExportFormat(str, Enum):
    """Export format options"""

    json = "json"
    csv = "csv"
    excel = "xlsx"
    pdf = "pdf"


class GroupByOption(str, Enum):
    """Group by options for analytics"""

    hour = "hour"
    day = "day"
    week = "week"
    month = "month"
    platform = "platform"
    risk_level = "risk_level"
    user = "user"


# Request/Response Models
class AnalyticsQueryRequest(BaseModel):
    """Base analytics query parameters"""

    time_range: TimeRangeType = Field(
        TimeRangeType.week, description="Predefined time range"
    )
    start_date: Optional[datetime] = Field(
        None, description="Custom start date (required if time_range=custom)"
    )
    end_date: Optional[datetime] = Field(
        None, description="Custom end date (required if time_range=custom)"
    )
    platforms: Optional[List[str]] = Field(
        None, description="Filter by specific platforms"
    )
    risk_levels: Optional[List[str]] = Field(None, description="Filter by risk levels")
    group_by: Optional[GroupByOption] = Field(
        None, description="Group results by specified dimension"
    )
    limit: Optional[int] = Field(
        100, ge=1, le=10000, description="Maximum number of results"
    )

    @model_validator(mode="after")
    def validate_date_range(self):
        if self.time_range == TimeRangeType.custom:
            if not self.start_date or not self.end_date:
                raise ValueError(
                    "start_date and end_date are required for custom time range"
                )
            if self.end_date <= self.start_date:
                raise ValueError("end_date must be after start_date")
        return self


class RiskAnalyticsResponse(BaseModel):
    """Risk analytics response model"""

    total_interactions: int = Field(..., description="Total interactions in time period")
    risk_distribution: Dict[str, int] = Field(..., description="Count by risk level")
    platform_breakdown: Dict[str, int] = Field(..., description="Count by platform")
    trend_data: List[Dict[str, Any]] = Field(..., description="Time series trend data")
    top_risk_patterns: List[Dict[str, Any]] = Field(
        ..., description="Most common risk patterns"
    )
    summary_stats: Dict[str, float] = Field(..., description="Summary statistics")


class PlatformAnalyticsResponse(BaseModel):
    """Platform usage analytics response"""

    total_usage: Dict[str, int] = Field(..., description="Total usage by platform")
    usage_trends: List[Dict[str, Any]] = Field(..., description="Usage trends over time")
    risk_correlation: Dict[str, float] = Field(
        ..., description="Risk correlation by platform"
    )
    popular_features: Dict[str, List[str]] = Field(
        ..., description="Popular features by platform"
    )
    user_adoption: Dict[str, Dict[str, int]] = Field(
        ..., description="User adoption metrics"
    )


class AlertAnalyticsResponse(BaseModel):
    """Security alert analytics response"""

    total_alerts: int = Field(..., description="Total alerts generated")
    alerts_by_severity: Dict[str, int] = Field(..., description="Alert count by severity")
    alert_trends: List[Dict[str, Any]] = Field(..., description="Alert trends over time")
    resolution_metrics: Dict[str, Any] = Field(
        ..., description="Alert resolution statistics"
    )
    false_positive_rate: float = Field(..., description="False positive rate percentage")
    top_alert_types: List[Dict[str, Any]] = Field(
        ..., description="Most common alert types"
    )


class ExportRequest(BaseModel):
    """Data export request model"""

    export_type: str = Field(..., pattern="^(interactions|alerts|analytics)$")
    format: ExportFormat = Field(ExportFormat.csv, description="Export format")
    time_range: TimeRangeType = Field(
        TimeRangeType.month, description="Time range for export"
    )
    filters: Optional[Dict[str, Any]] = Field(None, description="Additional filters")
    include_pii: bool = Field(
        False,
        description="Include personally identifiable information (requires special permission)",
    )


class ExportResponse(BaseModel):
    """Data export response model"""

    success: bool = Field(..., description="Export success status")
    export_id: str = Field(..., description="Unique export identifier")
    download_url: str = Field(..., description="URL to download the export file")
    expires_at: datetime = Field(..., description="Export file expiration time")
    file_size_mb: float = Field(..., description="Estimated file size in MB")
    record_count: int = Field(..., description="Number of records in export")


# Analytics Endpoints
@router.get(
    "/risk",
    response_model=RiskAnalyticsResponse,
    summary="Get Risk Analytics",
    description="""
    Retrieve comprehensive risk analytics and insights.

    This endpoint provides:
    - Overall risk distribution across different levels
    - Risk trends over time with customizable time periods
    - Platform-specific risk analysis
    - Top risk patterns and their frequencies
    - Statistical summaries and key metrics

    **Use Cases**:
    - Security dashboard visualization
    - Risk trend monitoring
    - Compliance reporting
    - Executive summaries

    **Performance**: Results are cached for 5 minutes for faster response times.
    """,
    **get_endpoint_docs("Analytics", "read"),
)
async def get_risk_analytics(
    query: AnalyticsQueryRequest = Depends(),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(),
    auth_data: dict = Depends(verify_api_auth),
    _rate_limit: None = Depends(rate_limiter),
):
    """Get comprehensive risk analytics"""
    try:
        logger.info(f"Risk analytics request from {auth_data.get('client_id')}")

        # Calculate date range
        if query.time_range == TimeRangeType.custom:
            start_date = query.start_date
            end_date = query.end_date
        else:
            end_date = utcnow()
            days_map = {
                TimeRangeType.hour: 0,
                TimeRangeType.day: 1,
                TimeRangeType.week: 7,
                TimeRangeType.month: 30,
                TimeRangeType.quarter: 90,
                TimeRangeType.year: 365,
            }
            hours = 1 if query.time_range == TimeRangeType.hour else 0
            start_date = end_date - timedelta(
                days=days_map.get(query.time_range, 7), hours=hours
            )

        # Get risk analytics
        analytics_data = await analytics_service.get_risk_analytics(
            db=db,
            start_date=start_date,
            end_date=end_date,
            platforms=query.platforms,
            risk_levels=query.risk_levels,
            group_by=query.group_by,
            limit=query.limit,
        )

        return RiskAnalyticsResponse(**analytics_data)

    except Exception as e:
        logger.error(f"Risk analytics error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve risk analytics")


@router.get(
    "/platforms",
    response_model=PlatformAnalyticsResponse,
    summary="Get Platform Usage Analytics",
    description="""
    Analyze usage patterns across different AI platforms.

    Provides insights into:
    - Platform adoption and usage volume
    - Risk correlation by platform
    - Feature usage patterns
    - User engagement metrics
    - Platform-specific trends over time

    **Business Value**:
    - Understand which AI platforms are most used
    - Identify platforms with higher security risks
    - Guide policy decisions and training needs
    - Track compliance across different tools
    """,
    **get_endpoint_docs("Analytics", "read"),
)
async def get_platform_analytics(
    time_range: TimeRangeType = Query(
        TimeRangeType.month, description="Time range for analysis"
    ),
    platforms: Optional[List[str]] = Query(
        None, description="Filter by specific platforms"
    ),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(),
    auth_data: dict = Depends(verify_api_auth),
    _rate_limit: None = Depends(rate_limiter),
):
    """Get platform usage analytics"""
    try:
        analytics_data = await analytics_service.get_platform_analytics(
            db=db, time_range=time_range, platforms=platforms
        )

        return PlatformAnalyticsResponse(**analytics_data)

    except Exception as e:
        logger.error(f"Platform analytics error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to retrieve platform analytics"
        )


@router.get(
    "/alerts",
    response_model=AlertAnalyticsResponse,
    summary="Get Security Alert Analytics",
    description="""
    Comprehensive analytics on security alerts and their resolution.

    Key metrics include:
    - Alert volume and severity distribution
    - Alert resolution time and success rates
    - False positive analysis and trends
    - Top alert types and their patterns
    - Response team performance metrics

    **Operational Value**:
    - Monitor security team performance
    - Identify alert tuning opportunities
    - Track false positive rates
    - Measure incident response effectiveness
    """,
    **get_endpoint_docs("Analytics", "read"),
)
async def get_alert_analytics(
    time_range: TimeRangeType = Query(
        TimeRangeType.month, description="Time range for analysis"
    ),
    severity_levels: Optional[List[str]] = Query(
        None, description="Filter by alert severity"
    ),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(),
    auth_data: dict = Depends(verify_api_auth),
):
    """Get security alert analytics"""
    try:
        analytics_data = await analytics_service.get_alert_analytics(
            db=db, time_range=time_range, severity_levels=severity_levels
        )

        return AlertAnalyticsResponse(**analytics_data)

    except Exception as e:
        logger.error(f"Alert analytics error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve alert analytics")


@router.get(
    "/users/{user_id}",
    summary="Get User-Specific Analytics",
    description="""
    Retrieve analytics for a specific user (subject to privacy controls).

    **Privacy Notes**:
    - Requires appropriate permissions to access user-specific data
    - Data is automatically anonymized based on privacy settings
    - Respects user consent preferences and data retention policies
    - Audit logged for compliance purposes

    **GDPR/CCPA Compliance**:
    - Only authorized personnel can access this endpoint
    - User data is pseudonymized when possible
    - Access is logged for audit trails
    """,
    **get_endpoint_docs("Analytics", "read"),
)
async def get_user_analytics(
    user_id: str = Path(..., description="User ID (hashed or pseudonymized)"),
    time_range: TimeRangeType = Query(TimeRangeType.month, description="Time range"),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(),
    auth_data: dict = Depends(verify_api_auth),
):
    """Get user-specific analytics with privacy controls"""
    try:
        # Check user access permissions
        if not auth_data.get("permissions", {}).get("user_analytics", False):
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions for user-specific analytics",
            )

        # Get user analytics with privacy filtering
        analytics_data = await analytics_service.get_user_analytics(
            db=db,
            user_id=user_id,
            time_range=time_range,
            requester_permissions=auth_data.get("permissions", {}),
        )

        return analytics_data

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"User analytics error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve user analytics")


@router.post(
    "/export",
    response_model=ExportResponse,
    summary="Export Analytics Data",
    description="""
    Export analytics data in various formats for external analysis.

    **Supported Formats**:
    - CSV: Comma-separated values for spreadsheet analysis
    - JSON: Structured data for programmatic processing
    - Excel: Microsoft Excel format with multiple sheets
    - PDF: Formatted report for executive presentations

    **Export Types**:
    - `interactions`: Raw interaction data (anonymized)
    - `alerts`: Security alert data with resolution status
    - `analytics`: Pre-computed analytics and insights

    **Security & Privacy**:
    - All exports are automatically sanitized
    - PII inclusion requires special permissions
    - Export files expire after 24 hours
    - Download links are single-use for security
    """,
    **get_endpoint_docs("Analytics", "create"),
)
async def export_analytics_data(
    export_request: ExportRequest,
    db: AsyncSession = Depends(get_db),
    export_service: ExportService = Depends(),
    auth_data: dict = Depends(verify_api_auth),
):
    """Export analytics data for external analysis"""
    try:
        # Validate permissions for PII inclusion
        if export_request.include_pii and not auth_data.get("permissions", {}).get(
            "export_pii", False
        ):
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions to export data with PII",
            )

        # Generate export
        export_result = await export_service.create_export(
            db=db,
            export_type=export_request.export_type,
            format=export_request.format,
            time_range=export_request.time_range,
            filters=export_request.filters,
            include_pii=export_request.include_pii,
            requester_id=auth_data.get("client_id"),
        )

        return ExportResponse(**export_result)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Export error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to create data export")


@router.get(
    "/dashboard",
    summary="Get Dashboard Summary",
    description="""
    Get a comprehensive dashboard summary with key metrics and trends.

    **Perfect for**:
    - Executive dashboards
    - Security operations centers (SOC)
    - Compliance reporting
    - Real-time monitoring displays

    **Includes**:
    - Current system status and health
    - Key performance indicators (KPIs)
    - Recent alert summaries
    - Usage trends and patterns
    - System capacity and performance metrics
    """,
    **get_endpoint_docs("Analytics", "read"),
)
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(),
    auth_data: dict = Depends(verify_api_auth),
):
    """Get dashboard summary with key metrics"""
    try:
        dashboard_data = await analytics_service.get_dashboard_summary(db)
        return dashboard_data

    except Exception as e:
        logger.error(f"Dashboard summary error: {str(e)}", exc_info=True)
        raise HTTPException(
            status_code=500, detail="Failed to retrieve dashboard summary"
        )


@router.get(
    "/trends",
    summary="Get Trend Analysis",
    description="""
    Advanced trend analysis with predictive insights.

    **Features**:
    - Historical trend analysis
    - Seasonal pattern detection
    - Anomaly identification in trends
    - Predictive forecasting (where applicable)
    - Comparative analysis across time periods

    **Use Cases**:
    - Capacity planning
    - Risk trend monitoring
    - Budget forecasting
    - Strategic planning support
    """,
    **get_endpoint_docs("Analytics", "read"),
)
async def get_trend_analysis(
    metric: str = Query(
        ..., description="Metric to analyze (interactions, risk_score, alerts)"
    ),
    time_range: TimeRangeType = Query(
        TimeRangeType.quarter, description="Time range for analysis"
    ),
    granularity: GroupByOption = Query(GroupByOption.day, description="Data granularity"),
    forecast_days: Optional[int] = Query(
        None, ge=1, le=90, description="Days to forecast (optional)"
    ),
    db: AsyncSession = Depends(get_db),
    analytics_service: AnalyticsService = Depends(),
    auth_data: dict = Depends(verify_api_auth),
):
    """Get advanced trend analysis with forecasting"""
    try:
        trend_data = await analytics_service.get_trend_analysis(
            db=db,
            metric=metric,
            time_range=time_range,
            granularity=granularity,
            forecast_days=forecast_days,
        )

        return trend_data

    except Exception as e:
        logger.error(f"Trend analysis error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve trend analysis")
