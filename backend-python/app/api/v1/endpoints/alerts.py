"""
Security Alerts API Endpoints
Comprehensive alert management with full documentation
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.docs import get_endpoint_docs
from app.core.logging import logger
from app.core.security import rate_limiter, verify_api_auth
from app.core.timeutils import utcnow
from app.services.alert_service import AlertService
from app.services.notification_service import NotificationService
from app.services.websocket_manager import WebSocketManager, websocket_manager

router = APIRouter()


async def get_websocket_manager() -> WebSocketManager:
    """Return the process-wide manager holding the live connections.

    Constructing a new manager per request would broadcast into an empty
    connection set, so the singleton is injected instead.
    """
    return websocket_manager


# Enums for API parameters
class AlertStatusFilter(str, Enum):
    """Alert status filter options"""

    active = "active"
    acknowledged = "acknowledged"
    resolved = "resolved"
    false_positive = "false_positive"
    all = "all"


class AlertSeverityFilter(str, Enum):
    """Alert severity filter options"""

    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
    all = "all"


class SortOption(str, Enum):
    """Sorting options for alerts"""

    created_desc = "created_desc"
    created_asc = "created_asc"
    severity_desc = "severity_desc"
    severity_asc = "severity_asc"
    risk_score_desc = "risk_score_desc"
    risk_score_asc = "risk_score_asc"


# Request/Response Models
class AlertListResponse(BaseModel):
    """Alert list response with pagination"""

    alerts: List[Dict[str, Any]] = Field(..., description="List of alerts")
    pagination: Dict[str, int] = Field(..., description="Pagination metadata")
    filters_applied: Dict[str, Any] = Field(..., description="Applied filters")
    total_count: int = Field(..., description="Total number of alerts")


class AlertDetailResponse(BaseModel):
    """Detailed alert response"""

    id: int = Field(..., description="Alert ID")
    title: str = Field(..., description="Alert title")
    description: str = Field(..., description="Alert description")
    severity: str = Field(..., description="Alert severity")
    status: str = Field(..., description="Alert status")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    confidence_score: float = Field(..., description="Confidence score (0-100)")
    risk_score: Optional[float] = Field(None, description="Associated risk score")
    platform: Optional[str] = Field(None, description="Related platform")
    evidence: Optional[Dict[str, Any]] = Field(None, description="Supporting evidence")
    related_interactions: List[int] = Field(..., description="Related interaction IDs")
    resolution_notes: Optional[str] = Field(None, description="Resolution notes")
    assigned_to: Optional[str] = Field(None, description="Assigned analyst")


class AlertUpdateRequest(BaseModel):
    """Alert update request"""

    status: Optional[AlertStatusFilter] = Field(None, description="New alert status")
    assigned_to: Optional[str] = Field(None, description="Assign to analyst")
    resolution_notes: Optional[str] = Field(
        None, max_length=2000, description="Resolution notes"
    )
    priority: Optional[int] = Field(None, ge=1, le=5, description="Priority level (1-5)")


class BulkAlertActionRequest(BaseModel):
    """Bulk alert action request"""

    alert_ids: List[int] = Field(
        ..., min_length=1, max_length=100, description="Alert IDs to update"
    )
    action: str = Field(
        ...,
        pattern="^(acknowledge|resolve|false_positive|assign)$",
        description="Action to perform",
    )
    parameters: Optional[Dict[str, Any]] = Field(None, description="Action parameters")


class AlertStatsResponse(BaseModel):
    """Alert statistics response"""

    total_alerts: int = Field(..., description="Total number of alerts")
    by_status: Dict[str, int] = Field(..., description="Count by status")
    by_severity: Dict[str, int] = Field(..., description="Count by severity")
    by_platform: Dict[str, int] = Field(..., description="Count by platform")
    resolution_metrics: Dict[str, float] = Field(
        ..., description="Resolution time metrics"
    )
    trend_data: List[Dict[str, Any]] = Field(..., description="Trend data over time")


# Alert Management Endpoints
@router.get(
    "/",
    response_model=AlertListResponse,
    summary="List Security Alerts",
    description="""
    Retrieve a paginated list of security alerts with comprehensive filtering options.

    **Features**:
    - Advanced filtering by status, severity, platform, and date range
    - Flexible sorting options
    - Pagination support for large datasets
    - Real-time data with optional auto-refresh

    **Filtering Options**:
    - `status`: Filter by alert status (active, acknowledged, resolved, false_positive)
    - `severity`: Filter by severity level (low, medium, high, critical)
    - `platform`: Filter by AI platform (chatgpt, claude, bard, etc.)
    - `date_range`: Filter by creation or update date ranges
    - `assigned_to`: Filter by assigned analyst

    **Sorting Options**:
    - By creation date (newest/oldest first)
    - By severity level (highest/lowest first)
    - By risk score (highest/lowest first)
    - By last update time

    **Use Cases**:
    - Security dashboard alert feeds
    - Analyst workload management
    - Alert trend analysis
    - Compliance reporting
    """,
    **get_endpoint_docs("Alerts", "read"),
)
async def list_alerts(
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page"),
    status: AlertStatusFilter = Query(
        AlertStatusFilter.all, description="Filter by alert status"
    ),
    severity: AlertSeverityFilter = Query(
        AlertSeverityFilter.all, description="Filter by severity"
    ),
    platform: Optional[str] = Query(None, description="Filter by AI platform"),
    created_after: Optional[datetime] = Query(
        None, description="Filter alerts created after this date"
    ),
    created_before: Optional[datetime] = Query(
        None, description="Filter alerts created before this date"
    ),
    assigned_to: Optional[str] = Query(None, description="Filter by assigned analyst"),
    sort: SortOption = Query(SortOption.created_desc, description="Sort order"),
    search: Optional[str] = Query(
        None, max_length=200, description="Search in title and description"
    ),
    db: AsyncSession = Depends(get_db),
    alert_service: AlertService = Depends(),
    auth_data: dict = Depends(verify_api_auth),
    _rate_limit: None = Depends(rate_limiter),
):
    """List security alerts with filtering and pagination"""
    try:
        logger.info(f"Alert list request from {auth_data.get('client_id')}")

        # Build filters
        filters = {
            "status": status if status != AlertStatusFilter.all else None,
            "severity": severity if severity != AlertSeverityFilter.all else None,
            "platform": platform,
            "created_after": created_after,
            "created_before": created_before,
            "assigned_to": assigned_to,
            "search": search,
        }

        # Get alerts with pagination
        alerts_data = await alert_service.list_alerts(
            db=db,
            page=page,
            per_page=per_page,
            filters=filters,
            sort=sort,
            user_permissions=auth_data.get("permissions", {}),
        )

        return AlertListResponse(**alerts_data)

    except Exception as e:
        logger.error(f"Alert list error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve alerts")


# NOTE: literal paths must be registered before `/{alert_id}`. FastAPI
# matches routes in declaration order, so with the parameterised route
# first, GET /alerts/stats would bind alert_id="stats" and 422.


@router.post(
    "/bulk-action",
    summary="Bulk Alert Actions",
    description="""
    Perform bulk actions on multiple alerts simultaneously.

    **Supported Actions**:
    - `acknowledge`: Acknowledge multiple alerts
    - `resolve`: Mark multiple alerts as resolved
    - `false_positive`: Mark alerts as false positives
    - `assign`: Bulk assign alerts to an analyst

    **Features**:
    - Batch processing for efficiency
    - Atomic operations (all succeed or all fail)
    - Comprehensive audit logging
    - Real-time notifications for all changes
    - Permission validation for each alert

    **Limits**:
    - Maximum 100 alerts per bulk operation
    - Rate limited to prevent system overload
    - Requires appropriate permissions for all target alerts
    """,
    **get_endpoint_docs("Alerts", "update"),
)
async def bulk_alert_action(
    bulk_request: BulkAlertActionRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    alert_service: AlertService = Depends(),
    notification_service: NotificationService = Depends(),
    websocket_manager: WebSocketManager = Depends(get_websocket_manager),
    auth_data: dict = Depends(verify_api_auth),
):
    """Perform bulk actions on multiple alerts"""
    try:
        # Validate permissions for all alerts
        permission_check = await alert_service.validate_bulk_permissions(
            db=db,
            alert_ids=bulk_request.alert_ids,
            action=bulk_request.action,
            user_permissions=auth_data.get("permissions", {}),
            user_id=auth_data.get("user_id"),
        )

        if not permission_check["all_permitted"]:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions for {len(permission_check['denied'])} alerts",
            )

        # Perform bulk action
        result = await alert_service.bulk_update_alerts(
            db=db,
            alert_ids=bulk_request.alert_ids,
            action=bulk_request.action,
            parameters=bulk_request.parameters or {},
            updated_by=auth_data.get("user_id"),
        )

        # Send bulk notifications
        background_tasks.add_task(
            notification_service.send_bulk_alert_notification,
            action=bulk_request.action,
            alert_count=len(bulk_request.alert_ids),
            updated_by=auth_data.get("user_id"),
        )

        # Broadcast bulk update
        await websocket_manager.broadcast_bulk_alert_update(
            {
                "action": bulk_request.action,
                "alert_count": len(bulk_request.alert_ids),
                "updated_by": auth_data.get("user_id"),
                "timestamp": utcnow(),
            }
        )

        return {
            "success": True,
            "action": bulk_request.action,
            "processed_count": result["processed_count"],
            "failed_count": result["failed_count"],
            "details": result["details"],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Bulk alert action error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to perform bulk action")


@router.get(
    "/stats",
    response_model=AlertStatsResponse,
    summary="Get Alert Statistics",
    description="""
    Comprehensive statistics and metrics about security alerts.

    **Metrics Included**:
    - Total alert counts with breakdowns by status and severity
    - Platform-specific alert distributions
    - Resolution time statistics (mean, median, 95th percentile)
    - Trend analysis over customizable time periods
    - False positive rates and accuracy metrics
    - Analyst performance and workload statistics

    **Use Cases**:
    - Executive dashboards and KPI monitoring
    - Performance analysis and optimization
    - Capacity planning and resource allocation
    - Compliance reporting and audit preparation
    - Trend analysis and predictive insights
    """,
    **get_endpoint_docs("Alerts", "read"),
)
async def get_alert_statistics(
    time_range_days: int = Query(30, ge=1, le=365, description="Time range in days"),
    include_trends: bool = Query(True, description="Include trend data"),
    group_by: Optional[str] = Query(
        None, pattern="^(day|week|month)$", description="Trend grouping"
    ),
    db: AsyncSession = Depends(get_db),
    alert_service: AlertService = Depends(),
    auth_data: dict = Depends(verify_api_auth),
):
    """Get comprehensive alert statistics"""
    try:
        stats_data = await alert_service.get_alert_statistics(
            db=db,
            time_range_days=time_range_days,
            include_trends=include_trends,
            group_by=group_by,
            user_permissions=auth_data.get("permissions", {}),
        )

        return AlertStatsResponse(**stats_data)

    except Exception as e:
        logger.error(f"Alert statistics error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve alert statistics")


@router.get(
    "/export",
    summary="Export Alert Data",
    description="""
    Export alert data for external analysis and reporting.

    **Export Formats**:
    - CSV: For spreadsheet analysis
    - JSON: For programmatic processing
    - PDF: For formatted reports

    **Customization Options**:
    - Date range filtering
    - Status and severity filtering
    - Field selection for focused exports
    - Anonymization levels for privacy compliance

    **Security & Privacy**:
    - Automatic data sanitization
    - Audit logging of all exports
    - Time-limited download links
    - Access control based on user permissions
    """,
    **get_endpoint_docs("Alerts", "read"),
)
async def export_alert_data(
    format: str = Query("csv", pattern="^(csv|json|pdf)$", description="Export format"),
    start_date: Optional[datetime] = Query(None, description="Start date for export"),
    end_date: Optional[datetime] = Query(None, description="End date for export"),
    status_filter: Optional[str] = Query(None, description="Status filter"),
    severity_filter: Optional[str] = Query(None, description="Severity filter"),
    fields: Optional[List[str]] = Query(None, description="Specific fields to include"),
    db: AsyncSession = Depends(get_db),
    alert_service: AlertService = Depends(),
    auth_data: dict = Depends(verify_api_auth),
):
    """Export alert data in various formats"""
    try:
        # Check export permissions
        if not auth_data.get("permissions", {}).get("export_data", False):
            raise HTTPException(
                status_code=403, detail="Insufficient permissions to export alert data"
            )

        export_result = await alert_service.export_alerts(
            db=db,
            format=format,
            start_date=start_date,
            end_date=end_date,
            filters={"status": status_filter, "severity": severity_filter},
            fields=fields,
            user_permissions=auth_data.get("permissions", {}),
            requester_id=auth_data.get("user_id"),
        )

        return export_result

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Alert export error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to export alert data")


@router.get(
    "/{alert_id}",
    response_model=AlertDetailResponse,
    summary="Get Alert Details",
    description="""
    Retrieve detailed information about a specific security alert.

    **Includes**:
    - Complete alert metadata and status
    - Associated interaction data and evidence
    - Resolution history and notes
    - Analyst assignments and actions taken
    - Related alerts and patterns

    **Privacy & Security**:
    - Sensitive data is automatically filtered based on user permissions
    - Access is logged for audit purposes
    - Data retention policies are applied automatically

    **Use Cases**:
    - Alert investigation workflows
    - Incident response coordination
    - Forensic analysis
    - Training and documentation
    """,
    **get_endpoint_docs("Alerts", "read"),
)
async def get_alert_details(
    alert_id: int = Path(..., description="Alert ID"),
    include_related: bool = Query(
        False, description="Include related alerts and interactions"
    ),
    db: AsyncSession = Depends(get_db),
    alert_service: AlertService = Depends(),
    auth_data: dict = Depends(verify_api_auth),
):
    """Get detailed information about a specific alert"""
    try:
        alert_details = await alert_service.get_alert_details(
            db=db,
            alert_id=alert_id,
            include_related=include_related,
            user_permissions=auth_data.get("permissions", {}),
        )

        if not alert_details:
            raise HTTPException(status_code=404, detail="Alert not found")

        return AlertDetailResponse(**alert_details)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Alert detail error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to retrieve alert details")


@router.patch(
    "/{alert_id}",
    response_model=AlertDetailResponse,
    summary="Update Alert",
    description="""
    Update an existing security alert with new status, assignments, or notes.

    **Updatable Fields**:
    - `status`: Change alert status (acknowledge, resolve, mark as false positive)
    - `assigned_to`: Assign alert to specific analyst
    - `resolution_notes`: Add resolution notes and documentation
    - `priority`: Adjust alert priority level

    **Workflow Integration**:
    - Status changes trigger notifications to relevant stakeholders
    - Assignment changes notify the new assignee
    - Resolution triggers automated workflow actions
    - All changes are audit logged for compliance

    **Permissions**:
    - Analysts can update alerts assigned to them
    - Supervisors can update any alert
    - Some status changes require elevated permissions
    """,
    **get_endpoint_docs("Alerts", "update"),
)
async def update_alert(
    alert_id: int = Path(..., description="Alert ID"),
    update_request: AlertUpdateRequest = ...,
    background_tasks: BackgroundTasks = ...,
    db: AsyncSession = Depends(get_db),
    alert_service: AlertService = Depends(),
    notification_service: NotificationService = Depends(),
    websocket_manager: WebSocketManager = Depends(get_websocket_manager),
    auth_data: dict = Depends(verify_api_auth),
):
    """Update an existing alert"""
    try:
        # Check permissions for alert update
        can_update = await alert_service.can_update_alert(
            db=db,
            alert_id=alert_id,
            user_id=auth_data.get("user_id"),
            user_permissions=auth_data.get("permissions", {}),
        )

        if not can_update:
            raise HTTPException(
                status_code=403, detail="Insufficient permissions to update this alert"
            )

        # Update alert
        updated_alert = await alert_service.update_alert(
            db=db,
            alert_id=alert_id,
            update_data=update_request.dict(exclude_unset=True),
            updated_by=auth_data.get("user_id"),
        )

        if not updated_alert:
            raise HTTPException(status_code=404, detail="Alert not found")

        # Send notifications for status changes
        if update_request.status:
            background_tasks.add_task(
                notification_service.send_alert_update_notification,
                alert_id=alert_id,
                old_status=updated_alert["previous_status"],
                new_status=update_request.status,
                updated_by=auth_data.get("user_id"),
            )

        # Broadcast real-time update
        await websocket_manager.broadcast_alert_update(
            {
                "alert_id": alert_id,
                "update_type": "status_change" if update_request.status else "update",
                "new_status": update_request.status,
                "updated_by": auth_data.get("user_id"),
                "timestamp": utcnow(),
            }
        )

        return AlertDetailResponse(**updated_alert)

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Alert update error: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to update alert")
