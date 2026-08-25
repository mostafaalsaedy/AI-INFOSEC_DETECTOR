"""
Alert triage service.

Owns every read/write path the alerts API exposes: listing and filtering,
single-alert detail, status transitions, bulk actions, statistics and exports.
All methods take the request-scoped ``AsyncSession`` so they participate in the
caller's transaction.
"""

import csv
import io
import json
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, desc, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.database import (
    AIInteraction,
    AlertStatus,
    RiskLevel,
    SecurityAlert,
    record_audit_event,
)
from app.core.timeutils import utcnow

# The public API speaks in triage terms ("active", "acknowledged"); the storage
# layer uses the AlertStatus enum. These maps translate between the two.
API_TO_DB_STATUS: Dict[str, AlertStatus] = {
    "active": AlertStatus.OPEN,
    "acknowledged": AlertStatus.INVESTIGATING,
    "resolved": AlertStatus.RESOLVED,
    "false_positive": AlertStatus.FALSE_POSITIVE,
}

DB_TO_API_STATUS: Dict[AlertStatus, str] = {
    db_status: api_status for api_status, db_status in API_TO_DB_STATUS.items()
}

SEVERITY_ORDER: Dict[RiskLevel, int] = {
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}

# Fields an export is allowed to contain. Anything outside this set is dropped
# rather than silently leaking columns that were never meant to leave the system.
EXPORTABLE_FIELDS = [
    "id",
    "alert_type",
    "severity",
    "status",
    "title",
    "description",
    "confidence_score",
    "ml_confidence",
    "priority",
    "assigned_to",
    "resolution_notes",
    "resolved_at",
    "resolved_by",
    "created_at",
    "updated_at",
]


def _as_api_status(status: Optional[AlertStatus]) -> Optional[str]:
    if status is None:
        return None
    return DB_TO_API_STATUS.get(status, status.value)


def _coerce_status(value: Any) -> Optional[AlertStatus]:
    """Accept an AlertStatus, an API status string or a raw enum value."""
    if value is None:
        return None
    if isinstance(value, AlertStatus):
        return value

    raw = getattr(value, "value", value)
    if raw in API_TO_DB_STATUS:
        return API_TO_DB_STATUS[raw]
    try:
        return AlertStatus(raw)
    except ValueError:
        return None


def _coerce_severity(value: Any) -> Optional[RiskLevel]:
    if value is None:
        return None
    if isinstance(value, RiskLevel):
        return value
    try:
        return RiskLevel(getattr(value, "value", value))
    except ValueError:
        return None


class AlertService:
    """Business logic for security-alert management."""

    # -- Reads --------------------------------------------------------------

    async def list_alerts(
        self,
        db: AsyncSession,
        page: int = 1,
        per_page: int = 20,
        filters: Optional[Dict[str, Any]] = None,
        sort: Any = "created_desc",
        user_permissions: Optional[Dict[str, bool]] = None,
    ) -> Dict[str, Any]:
        """Return one page of alerts plus pagination metadata."""
        filters = filters or {}
        conditions = self._build_conditions(filters)

        base = select(SecurityAlert)
        if filters.get("platform"):
            base = base.join(
                AIInteraction, SecurityAlert.interaction_id == AIInteraction.id
            )
        if conditions:
            base = base.where(and_(*conditions))

        total_count = await self._count(db, filters, conditions)

        query = (
            base.options(selectinload(SecurityAlert.interaction))
            .order_by(*self._sort_clause(sort))
            .offset((page - 1) * per_page)
            .limit(per_page)
        )

        result = await db.execute(query)
        alerts = result.scalars().unique().all()

        total_pages = (total_count + per_page - 1) // per_page if per_page else 0

        return {
            "alerts": [self._serialise(alert) for alert in alerts],
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total_pages": total_pages,
                "total_items": total_count,
            },
            "filters_applied": {
                key: (value.value if hasattr(value, "value") else value)
                for key, value in filters.items()
                if value is not None
            },
            "total_count": total_count,
        }

    async def get_alert_details(
        self,
        db: AsyncSession,
        alert_id: int,
        include_related: bool = False,
        user_permissions: Optional[Dict[str, bool]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Return one alert with its related interaction, or None.

        With ``include_related`` the response also lists other alerts raised
        from the same interaction, which is what an analyst needs to judge
        whether a finding is part of a wider pattern.
        """
        result = await db.execute(
            select(SecurityAlert)
            .options(selectinload(SecurityAlert.interaction))
            .where(SecurityAlert.id == alert_id)
        )
        alert = result.scalar_one_or_none()
        if alert is None:
            return None

        payload = self._serialise(alert, include_evidence=True)

        if include_related and alert.interaction_id is not None:
            siblings = await db.execute(
                select(SecurityAlert.id)
                .where(
                    and_(
                        SecurityAlert.interaction_id == alert.interaction_id,
                        SecurityAlert.id != alert.id,
                    )
                )
                .limit(50)
            )
            payload["related_alerts"] = list(siblings.scalars().all())

        return payload

    async def get_alert_statistics(
        self,
        db: AsyncSession,
        time_range_days: int = 30,
        include_trends: bool = True,
        group_by: Optional[str] = None,
        user_permissions: Optional[Dict[str, bool]] = None,
    ) -> Dict[str, Any]:
        """Aggregate alert counts, resolution timings and optional trend data."""
        since = utcnow() - timedelta(days=time_range_days)
        window = SecurityAlert.created_at >= since

        total_alerts = (
            await db.execute(
                select(func.count()).select_from(SecurityAlert).where(window)
            )
        ).scalar_one()

        by_status_rows = await db.execute(
            select(SecurityAlert.status, func.count())
            .where(window)
            .group_by(SecurityAlert.status)
        )
        by_status = {
            _as_api_status(status) or "unknown": count
            for status, count in by_status_rows.all()
        }

        by_severity_rows = await db.execute(
            select(SecurityAlert.severity, func.count())
            .where(window)
            .group_by(SecurityAlert.severity)
        )
        by_severity = {
            (severity.value if severity else "unknown"): count
            for severity, count in by_severity_rows.all()
        }

        by_platform_rows = await db.execute(
            select(AIInteraction.platform, func.count())
            .join(SecurityAlert, SecurityAlert.interaction_id == AIInteraction.id)
            .where(window)
            .group_by(AIInteraction.platform)
        )
        by_platform = {
            (platform or "unknown"): count for platform, count in by_platform_rows.all()
        }

        resolution_metrics = await self._resolution_metrics(db, since, total_alerts)

        trend_data: List[Dict[str, Any]] = []
        if include_trends:
            trend_data = await self._alert_trend(db, since, group_by or "day")

        return {
            "total_alerts": total_alerts,
            "by_status": by_status,
            "by_severity": by_severity,
            "by_platform": by_platform,
            "resolution_metrics": resolution_metrics,
            "trend_data": trend_data,
        }

    # -- Writes -------------------------------------------------------------

    async def can_update_alert(
        self,
        db: AsyncSession,
        alert_id: int,
        user_id: Optional[str],
        user_permissions: Optional[Dict[str, bool]] = None,
    ) -> bool:
        """Check whether the caller may modify this specific alert.

        Analysts and admins may update any alert; everyone else may only update
        alerts explicitly assigned to them.
        """
        permissions = user_permissions or {}
        if permissions.get("admin") or permissions.get("update_alerts"):
            return True

        result = await db.execute(
            select(SecurityAlert.assigned_to).where(SecurityAlert.id == alert_id)
        )
        assigned_to = result.scalar_one_or_none()
        return assigned_to is not None and assigned_to == user_id

    async def update_alert(
        self,
        db: AsyncSession,
        alert_id: int,
        update_data: Dict[str, Any],
        updated_by: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Apply a partial update, returning the alert plus its previous status."""
        result = await db.execute(
            select(SecurityAlert)
            .options(selectinload(SecurityAlert.interaction))
            .where(SecurityAlert.id == alert_id)
        )
        alert = result.scalar_one_or_none()
        if alert is None:
            return None

        previous_status = _as_api_status(alert.status)
        changes: Dict[str, Any] = {}

        if "status" in update_data:
            new_status = _coerce_status(update_data["status"])
            if new_status is not None and new_status != alert.status:
                changes["status"] = {"from": previous_status, "to": new_status.value}
                alert.status = new_status

                if new_status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
                    alert.resolved_at = utcnow()
                    alert.resolved_by = updated_by
                else:
                    alert.resolved_at = None
                    alert.resolved_by = None

        if "assigned_to" in update_data:
            changes["assigned_to"] = {
                "from": alert.assigned_to,
                "to": update_data["assigned_to"],
            }
            alert.assigned_to = update_data["assigned_to"]

        if "resolution_notes" in update_data:
            alert.resolution_notes = update_data["resolution_notes"]
            changes["resolution_notes"] = "updated"

        if "priority" in update_data and update_data["priority"] is not None:
            changes["priority"] = {
                "from": alert.priority,
                "to": update_data["priority"],
            }
            alert.priority = update_data["priority"]

        alert.updated_at = utcnow()

        await db.flush()
        await db.refresh(alert)

        await record_audit_event(
            event_type="alert_updated",
            event_category="security",
            description=f"Alert {alert_id} updated by {updated_by or 'unknown'}",
            user_id=updated_by,
            event_data={"alert_id": alert_id, "changes": changes},
        )

        payload = self._serialise(alert, include_evidence=True)
        payload["previous_status"] = previous_status
        return payload

    async def validate_bulk_permissions(
        self,
        db: AsyncSession,
        alert_ids: List[int],
        action: str,
        user_permissions: Optional[Dict[str, bool]] = None,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Split the requested IDs into permitted and denied buckets."""
        permissions = user_permissions or {}

        if permissions.get("admin") or permissions.get("bulk_update_alerts"):
            return {"all_permitted": True, "permitted": list(alert_ids), "denied": []}

        result = await db.execute(
            select(SecurityAlert.id, SecurityAlert.assigned_to).where(
                SecurityAlert.id.in_(alert_ids)
            )
        )
        rows = dict(result.all())

        permitted = [aid for aid in alert_ids if rows.get(aid) == user_id and user_id]
        denied = [aid for aid in alert_ids if aid not in permitted]

        return {
            "all_permitted": not denied,
            "permitted": permitted,
            "denied": denied,
        }

    async def bulk_update_alerts(
        self,
        db: AsyncSession,
        alert_ids: List[int],
        action: str,
        parameters: Optional[Dict[str, Any]] = None,
        updated_by: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Apply one action to many alerts, reporting per-alert outcomes."""
        parameters = parameters or {}
        now = utcnow()

        action_map = {
            "acknowledge": AlertStatus.INVESTIGATING,
            "resolve": AlertStatus.RESOLVED,
            "false_positive": AlertStatus.FALSE_POSITIVE,
        }

        values: Dict[str, Any] = {"updated_at": now}
        if action == "assign":
            assignee = parameters.get("assigned_to")
            if not assignee:
                return {
                    "processed_count": 0,
                    "failed_count": len(alert_ids),
                    "details": [
                        {
                            "alert_id": aid,
                            "success": False,
                            "error": "assign requires an 'assigned_to' parameter",
                        }
                        for aid in alert_ids
                    ],
                }
            values["assigned_to"] = assignee
        else:
            new_status = action_map.get(action)
            if new_status is None:
                return {
                    "processed_count": 0,
                    "failed_count": len(alert_ids),
                    "details": [
                        {
                            "alert_id": aid,
                            "success": False,
                            "error": f"Unknown action: {action}",
                        }
                        for aid in alert_ids
                    ],
                }
            values["status"] = new_status
            if new_status in (AlertStatus.RESOLVED, AlertStatus.FALSE_POSITIVE):
                values["resolved_at"] = now
                values["resolved_by"] = updated_by
            if parameters.get("resolution_notes"):
                values["resolution_notes"] = parameters["resolution_notes"]

        # Only IDs that actually exist can be updated; the rest are reported back
        # as failures so the caller learns about stale IDs.
        existing = (
            (
                await db.execute(
                    select(SecurityAlert.id).where(SecurityAlert.id.in_(alert_ids))
                )
            )
            .scalars()
            .all()
        )
        existing_set = set(existing)

        if existing_set:
            await db.execute(
                update(SecurityAlert)
                .where(SecurityAlert.id.in_(existing_set))
                .values(**values)
            )
            await db.flush()

        details = [
            {
                "alert_id": aid,
                "success": aid in existing_set,
                "error": None if aid in existing_set else "Alert not found",
            }
            for aid in alert_ids
        ]

        await record_audit_event(
            event_type="alert_bulk_update",
            event_category="security",
            description=f"Bulk '{action}' on {len(existing_set)} alerts",
            user_id=updated_by,
            event_data={"action": action, "alert_ids": list(existing_set)},
        )

        return {
            "processed_count": len(existing_set),
            "failed_count": len(alert_ids) - len(existing_set),
            "details": details,
        }

    # -- Export -------------------------------------------------------------

    async def export_alerts(
        self,
        db: AsyncSession,
        format: str = "csv",
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
        filters: Optional[Dict[str, Any]] = None,
        fields: Optional[List[str]] = None,
        user_permissions: Optional[Dict[str, bool]] = None,
        requester_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Serialise matching alerts to CSV or JSON.

        PDF is accepted by the API surface but not rendered server-side; the
        response tells the caller to request JSON and render client-side rather
        than silently returning the wrong format.
        """
        filters = dict(filters or {})
        conditions = self._build_conditions(filters)

        if start_date:
            conditions.append(SecurityAlert.created_at >= start_date)
        if end_date:
            conditions.append(SecurityAlert.created_at <= end_date)

        query = select(SecurityAlert).options(selectinload(SecurityAlert.interaction))
        if conditions:
            query = query.where(and_(*conditions))
        query = query.order_by(desc(SecurityAlert.created_at)).limit(50_000)

        alerts = (await db.execute(query)).scalars().unique().all()

        selected_fields = [
            f for f in (fields or EXPORTABLE_FIELDS) if f in EXPORTABLE_FIELDS
        ]
        if not selected_fields:
            selected_fields = list(EXPORTABLE_FIELDS)

        rows = [
            {field: self._export_value(alert, field) for field in selected_fields}
            for alert in alerts
        ]

        export_id = f"alerts-{uuid.uuid4().hex[:12]}"

        await record_audit_event(
            event_type="alert_export",
            event_category="privacy",
            description=f"{len(rows)} alerts exported as {format}",
            user_id=requester_id,
            event_data={"export_id": export_id, "format": format, "count": len(rows)},
        )

        if format == "json":
            content = json.dumps(rows, default=str, indent=2)
            media_type = "application/json"
        elif format == "csv":
            buffer = io.StringIO()
            writer = csv.DictWriter(buffer, fieldnames=selected_fields)
            writer.writeheader()
            for row in rows:
                writer.writerow(row)
            content = buffer.getvalue()
            media_type = "text/csv"
        else:
            return {
                "success": False,
                "export_id": export_id,
                "record_count": len(rows),
                "error": (
                    "PDF rendering is handled by the dashboard. Request format=json "
                    "and render the report client-side."
                ),
            }

        return {
            "success": True,
            "export_id": export_id,
            "format": format,
            "media_type": media_type,
            "record_count": len(rows),
            "fields": selected_fields,
            "generated_at": utcnow(),
            "content": content,
        }

    # -- Internals ----------------------------------------------------------

    def _build_conditions(self, filters: Dict[str, Any]) -> List[Any]:
        """Translate the API filter dict into SQLAlchemy predicates."""
        conditions: List[Any] = []

        status = _coerce_status(filters.get("status"))
        if status is not None:
            conditions.append(SecurityAlert.status == status)

        severity = _coerce_severity(filters.get("severity"))
        if severity is not None:
            conditions.append(SecurityAlert.severity == severity)

        if filters.get("platform"):
            conditions.append(AIInteraction.platform == filters["platform"])

        if filters.get("created_after"):
            conditions.append(SecurityAlert.created_at >= filters["created_after"])

        if filters.get("created_before"):
            conditions.append(SecurityAlert.created_at <= filters["created_before"])

        if filters.get("assigned_to"):
            conditions.append(SecurityAlert.assigned_to == filters["assigned_to"])

        if filters.get("search"):
            term = f"%{filters['search']}%"
            conditions.append(
                or_(
                    SecurityAlert.title.ilike(term),
                    SecurityAlert.description.ilike(term),
                    SecurityAlert.alert_type.ilike(term),
                )
            )

        return conditions

    async def _count(
        self, db: AsyncSession, filters: Dict[str, Any], conditions: List[Any]
    ) -> int:
        count_query = select(func.count(SecurityAlert.id)).select_from(SecurityAlert)
        if filters.get("platform"):
            count_query = count_query.join(
                AIInteraction, SecurityAlert.interaction_id == AIInteraction.id
            )
        if conditions:
            count_query = count_query.where(and_(*conditions))
        return (await db.execute(count_query)).scalar_one()

    def _sort_clause(self, sort: Any) -> List[Any]:
        """Map the API sort option onto ORDER BY columns."""
        key = getattr(sort, "value", sort) or "created_desc"

        clauses = {
            "created_desc": [desc(SecurityAlert.created_at)],
            "created_asc": [SecurityAlert.created_at],
            "severity_desc": [
                desc(SecurityAlert.priority),
                desc(SecurityAlert.created_at),
            ],
            "severity_asc": [SecurityAlert.priority, SecurityAlert.created_at],
            "risk_score_desc": [desc(SecurityAlert.confidence_score)],
            "risk_score_asc": [SecurityAlert.confidence_score],
        }
        return clauses.get(key, [desc(SecurityAlert.created_at)])

    async def _resolution_metrics(
        self, db: AsyncSession, since: datetime, total_alerts: int
    ) -> Dict[str, float]:
        """Mean/median time-to-resolution plus resolution and false-positive rates."""
        result = await db.execute(
            select(SecurityAlert.created_at, SecurityAlert.resolved_at).where(
                and_(
                    SecurityAlert.created_at >= since,
                    SecurityAlert.resolved_at.isnot(None),
                )
            )
        )
        durations = [
            (resolved_at - created_at).total_seconds() / 3600
            for created_at, resolved_at in result.all()
            if created_at and resolved_at
        ]

        false_positives = (
            await db.execute(
                select(func.count())
                .select_from(SecurityAlert)
                .where(
                    and_(
                        SecurityAlert.created_at >= since,
                        SecurityAlert.status == AlertStatus.FALSE_POSITIVE,
                    )
                )
            )
        ).scalar_one()

        if durations:
            ordered = sorted(durations)
            mid = len(ordered) // 2
            median = (
                ordered[mid]
                if len(ordered) % 2
                else (ordered[mid - 1] + ordered[mid]) / 2
            )
        else:
            median = 0.0

        return {
            "resolved_count": float(len(durations)),
            "mean_resolution_hours": (
                round(sum(durations) / len(durations), 2) if durations else 0.0
            ),
            "median_resolution_hours": round(median, 2),
            "max_resolution_hours": round(max(durations), 2) if durations else 0.0,
            "resolution_rate": (
                round(len(durations) / total_alerts * 100, 2) if total_alerts else 0.0
            ),
            "false_positive_rate": (
                round(false_positives / total_alerts * 100, 2) if total_alerts else 0.0
            ),
        }

    async def _alert_trend(
        self, db: AsyncSession, since: datetime, group_by: str
    ) -> List[Dict[str, Any]]:
        """Bucket alert counts over time.

        Bucketing is done in Python rather than with database-specific date
        functions, so the same code path works on PostgreSQL and SQLite.
        """
        result = await db.execute(
            select(SecurityAlert.created_at, SecurityAlert.severity).where(
                SecurityAlert.created_at >= since
            )
        )

        buckets: Dict[str, Dict[str, Any]] = {}
        for created_at, severity in result.all():
            if created_at is None:
                continue
            key = self._bucket_key(created_at, group_by)
            bucket = buckets.setdefault(
                key, {"period": key, "count": 0, "by_severity": {}}
            )
            bucket["count"] += 1
            name = severity.value if severity else "unknown"
            bucket["by_severity"][name] = bucket["by_severity"].get(name, 0) + 1

        return [buckets[key] for key in sorted(buckets)]

    @staticmethod
    def _bucket_key(moment: datetime, group_by: str) -> str:
        if group_by == "month":
            return moment.strftime("%Y-%m")
        if group_by == "week":
            iso_year, iso_week, _ = moment.isocalendar()
            return f"{iso_year}-W{iso_week:02d}"
        if group_by == "hour":
            return moment.strftime("%Y-%m-%dT%H:00")
        return moment.strftime("%Y-%m-%d")

    @staticmethod
    def _export_value(alert: SecurityAlert, field: str) -> Any:
        value = getattr(alert, field, None)
        if hasattr(value, "value"):
            return value.value
        if isinstance(value, datetime):
            return value.isoformat()
        return value

    @staticmethod
    def _serialise(
        alert: SecurityAlert, include_evidence: bool = False
    ) -> Dict[str, Any]:
        """Convert an alert row into the shape the API contract promises."""
        interaction = alert.interaction

        payload: Dict[str, Any] = {
            "id": alert.id,
            "title": alert.title,
            "description": alert.description or "",
            "alert_type": alert.alert_type,
            "severity": alert.severity.value if alert.severity else RiskLevel.LOW.value,
            "status": _as_api_status(alert.status) or "active",
            "created_at": alert.created_at,
            "updated_at": alert.updated_at,
            "confidence_score": alert.confidence_score or 0.0,
            "ml_confidence": alert.ml_confidence or 0.0,
            "priority": alert.priority,
            "assigned_to": alert.assigned_to,
            "resolution_notes": alert.resolution_notes,
            "resolved_at": alert.resolved_at,
            "resolved_by": alert.resolved_by,
            "risk_score": interaction.risk_score if interaction else None,
            "platform": interaction.platform if interaction else None,
            "related_interactions": [interaction.id] if interaction else [],
        }

        if include_evidence:
            payload["evidence"] = alert.evidence or {}
            payload["detection_rules"] = alert.detection_rules or {}

        return payload
