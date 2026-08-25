"""
Data export service.

Materialises interaction, alert and analytics extracts to disk and hands back a
time-limited download reference. Every export is audit logged, and PII is
stripped unless the caller was explicitly granted the `export_pii` permission.
"""

import csv
import json
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlalchemy import and_, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import (
    AIInteraction,
    RiskLevel,
    SecurityAlert,
    record_audit_event,
)
from app.core.logging import logger
from app.core.timeutils import utc_from_timestamp, utcnow
from app.services.analytics_service import AnalyticsService, resolve_time_range

# Columns that identify a person. Removed unless `include_pii` is granted.
PII_FIELDS = {"user_id", "ip_address", "user_agent", "session_id", "content_hash"}

# How long a generated export stays on disk before the cleanup pass removes it.
EXPORT_TTL_HOURS = 24

# Guard rail so a single export cannot exhaust disk or memory.
MAX_EXPORT_ROWS = 100_000


class ExportService:
    """Builds downloadable extracts of the monitoring data."""

    def __init__(self, export_dir: Optional[str] = None) -> None:
        self.export_dir = Path(export_dir or os.getenv("EXPORT_PATH", "exports"))
        self.analytics = AnalyticsService()

    # -- Public API ---------------------------------------------------------

    async def create_export(
        self,
        db: AsyncSession,
        export_type: str,
        format: Any = "csv",
        time_range: Any = "30d",
        filters: Optional[Dict[str, Any]] = None,
        include_pii: bool = False,
        requester_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate an export file and return its download metadata."""
        fmt = getattr(format, "value", format) or "csv"
        start_date, end_date = resolve_time_range(time_range)
        filters = filters or {}

        if export_type == "interactions":
            rows = await self._interaction_rows(db, start_date, end_date, filters)
        elif export_type == "alerts":
            rows = await self._alert_rows(db, start_date, end_date, filters)
        elif export_type == "analytics":
            rows = await self._analytics_rows(db, start_date, end_date)
        else:
            raise ValueError(
                f"Unsupported export type '{export_type}'. Expected one of: "
                "interactions, alerts, analytics"
            )

        if not include_pii:
            rows = [self._strip_pii(row) for row in rows]

        export_id = f"{export_type}-{uuid.uuid4().hex[:12]}"
        path = self._write(export_id, fmt, rows)
        size_mb = round(path.stat().st_size / (1024 * 1024), 4)
        expires_at = utcnow() + timedelta(hours=EXPORT_TTL_HOURS)

        await record_audit_event(
            event_type="data_export_created",
            event_category="privacy",
            description=(
                f"{len(rows)} {export_type} records exported as {fmt} "
                f"(PII {'included' if include_pii else 'stripped'})"
            ),
            user_id=requester_id,
            event_data={
                "export_id": export_id,
                "export_type": export_type,
                "format": fmt,
                "record_count": len(rows),
                "include_pii": include_pii,
            },
            risk_level=RiskLevel.HIGH if include_pii else RiskLevel.LOW,
        )

        logger.info(f"Export {export_id} created with {len(rows)} records ({size_mb} MB)")

        return {
            "success": True,
            "export_id": export_id,
            "download_url": f"/api/v1/analytics/exports/{export_id}",
            "expires_at": expires_at,
            "file_size_mb": size_mb,
            "record_count": len(rows),
        }

    def resolve_export_path(self, export_id: str) -> Optional[Path]:
        """Look up a previously generated export by ID.

        The ID is matched against a strict pattern before touching the file
        system so a crafted value cannot escape the export directory.
        """
        if not self._is_valid_export_id(export_id):
            logger.warning(f"Rejected malformed export id: {export_id!r}")
            return None

        for candidate in self.export_dir.glob(f"{export_id}.*"):
            if candidate.is_file():
                return candidate
        return None

    def cleanup_expired_exports(self) -> int:
        """Delete export files past their TTL. Returns the number removed."""
        if not self.export_dir.exists():
            return 0

        cutoff = utcnow() - timedelta(hours=EXPORT_TTL_HOURS)
        removed = 0

        for path in self.export_dir.iterdir():
            if not path.is_file():
                continue
            modified = utc_from_timestamp(path.stat().st_mtime)
            if modified < cutoff:
                try:
                    path.unlink()
                    removed += 1
                except OSError as exc:
                    logger.error(f"Could not remove expired export {path.name}: {exc}")

        if removed:
            logger.info(f"Removed {removed} expired export file(s)")
        return removed

    # -- Row builders -------------------------------------------------------

    async def _interaction_rows(
        self,
        db: AsyncSession,
        start_date: datetime,
        end_date: datetime,
        filters: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        conditions = [
            AIInteraction.created_at >= start_date,
            AIInteraction.created_at <= end_date,
            AIInteraction.deleted_at.is_(None),
        ]
        if filters.get("platform"):
            conditions.append(AIInteraction.platform == filters["platform"])
        if filters.get("risk_level"):
            try:
                conditions.append(
                    AIInteraction.risk_level == RiskLevel(filters["risk_level"])
                )
            except ValueError:
                logger.warning(
                    f"Ignoring unknown risk_level filter: {filters['risk_level']}"
                )
        if filters.get("min_risk_score") is not None:
            conditions.append(
                AIInteraction.risk_score >= float(filters["min_risk_score"])
            )

        result = await db.execute(
            select(AIInteraction)
            .where(and_(*conditions))
            .order_by(desc(AIInteraction.created_at))
            .limit(MAX_EXPORT_ROWS)
        )

        return [
            {
                "id": row.id,
                "session_id": row.session_id,
                "user_id": row.user_id,
                "platform": row.platform,
                "page_title": row.page_title,
                "interaction_type": self._enum_value(row.interaction_type),
                "content_hash": row.content_hash,
                "content_length": row.content_length,
                "content_language": row.content_language,
                "risk_level": self._enum_value(row.risk_level),
                "risk_score": row.risk_score,
                "risk_flags": row.risk_flags,
                "confidence_score": row.confidence_score,
                "anomaly_score": row.anomaly_score,
                "sentiment_score": row.sentiment_score,
                "user_consent": row.user_consent,
                "anonymized": row.anonymized,
                "ip_address": row.ip_address,
                "user_agent": row.user_agent,
                "interaction_timestamp": self._iso(row.interaction_timestamp),
                "created_at": self._iso(row.created_at),
            }
            for row in result.scalars().all()
        ]

    async def _alert_rows(
        self,
        db: AsyncSession,
        start_date: datetime,
        end_date: datetime,
        filters: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        conditions = [
            SecurityAlert.created_at >= start_date,
            SecurityAlert.created_at <= end_date,
        ]
        if filters.get("severity"):
            try:
                conditions.append(
                    SecurityAlert.severity == RiskLevel(filters["severity"])
                )
            except ValueError:
                logger.warning(f"Ignoring unknown severity filter: {filters['severity']}")
        if filters.get("alert_type"):
            conditions.append(SecurityAlert.alert_type == filters["alert_type"])
        if filters.get("assigned_to"):
            conditions.append(SecurityAlert.assigned_to == filters["assigned_to"])

        result = await db.execute(
            select(SecurityAlert)
            .where(and_(*conditions))
            .order_by(desc(SecurityAlert.created_at))
            .limit(MAX_EXPORT_ROWS)
        )

        return [
            {
                "id": row.id,
                "interaction_id": row.interaction_id,
                "alert_type": row.alert_type,
                "severity": self._enum_value(row.severity),
                "status": self._enum_value(row.status),
                "title": row.title,
                "description": row.description,
                "confidence_score": row.confidence_score,
                "ml_confidence": row.ml_confidence,
                "priority": row.priority,
                "assigned_to": row.assigned_to,
                "resolution_notes": row.resolution_notes,
                "resolved_at": self._iso(row.resolved_at),
                "resolved_by": row.resolved_by,
                "notification_sent": row.notification_sent,
                "created_at": self._iso(row.created_at),
                "updated_at": self._iso(row.updated_at),
            }
            for row in result.scalars().all()
        ]

    async def _analytics_rows(
        self, db: AsyncSession, start_date: datetime, end_date: datetime
    ) -> List[Dict[str, Any]]:
        """Flatten the risk-analytics trend series into exportable rows."""
        analytics = await self.analytics.get_risk_analytics(
            db=db, start_date=start_date, end_date=end_date, limit=1000
        )

        rows: List[Dict[str, Any]] = []
        for point in analytics.get("trend_data", []):
            rows.append(
                {
                    "record_type": "trend",
                    "period": point.get("period"),
                    "interactions": point.get("interactions"),
                    "mean_risk_score": point.get("mean_risk_score"),
                    "high_risk_count": point.get("high_risk_count"),
                }
            )

        for level, count in analytics.get("risk_distribution", {}).items():
            rows.append(
                {"record_type": "risk_distribution", "key": level, "value": count}
            )

        for platform, count in analytics.get("platform_breakdown", {}).items():
            rows.append(
                {"record_type": "platform_breakdown", "key": platform, "value": count}
            )

        for pattern in analytics.get("top_risk_patterns", []):
            rows.append(
                {
                    "record_type": "risk_pattern",
                    "key": pattern.get("pattern"),
                    "value": pattern.get("count"),
                    "mean_risk_score": pattern.get("mean_risk_score"),
                }
            )

        return rows

    # -- Serialisation ------------------------------------------------------

    def _write(self, export_id: str, fmt: str, rows: List[Dict[str, Any]]) -> Path:
        """Write rows to disk in the requested format and return the path."""
        self.export_dir.mkdir(parents=True, exist_ok=True)

        if fmt == "json":
            path = self.export_dir / f"{export_id}.json"
            path.write_text(json.dumps(rows, default=str, indent=2), encoding="utf-8")
            return path

        if fmt in ("csv", "xlsx"):
            # xlsx is served as CSV: it opens natively in Excel and avoids
            # pulling in a spreadsheet writer for a format nothing parses
            # programmatically.
            path = self.export_dir / f"{export_id}.csv"
            fieldnames = self._union_fieldnames(rows)
            with path.open("w", newline="", encoding="utf-8") as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=fieldnames, extrasaction="ignore"
                )
                writer.writeheader()
                for row in rows:
                    writer.writerow(
                        {
                            key: (
                                json.dumps(value, default=str)
                                if isinstance(value, (dict, list))
                                else value
                            )
                            for key, value in row.items()
                        }
                    )
            return path

        if fmt == "pdf":
            # PDF rendering lives in the dashboard; the API emits the JSON the
            # report is built from so the two never drift apart.
            path = self.export_dir / f"{export_id}.json"
            path.write_text(
                json.dumps(
                    {
                        "note": "Render this payload as PDF in the dashboard",
                        "generated_at": utcnow().isoformat(),
                        "records": rows,
                    },
                    default=str,
                    indent=2,
                ),
                encoding="utf-8",
            )
            return path

        raise ValueError(f"Unsupported export format: {fmt}")

    @staticmethod
    def _union_fieldnames(rows: List[Dict[str, Any]]) -> List[str]:
        """Collect every key across rows, preserving first-seen order."""
        fieldnames: List[str] = []
        for row in rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
        return fieldnames or ["record_type"]

    @staticmethod
    def _strip_pii(row: Dict[str, Any]) -> Dict[str, Any]:
        return {key: value for key, value in row.items() if key not in PII_FIELDS}

    @staticmethod
    def _is_valid_export_id(export_id: str) -> bool:
        """Export IDs are `<type>-<12 hex chars>` and nothing else."""
        if not export_id or len(export_id) > 64:
            return False
        prefix, _, suffix = export_id.rpartition("-")
        return (
            prefix in {"interactions", "alerts", "analytics"}
            and len(suffix) == 12
            and all(char in "0123456789abcdef" for char in suffix)
        )

    @staticmethod
    def _enum_value(value: Any) -> Any:
        return getattr(value, "value", value)

    @staticmethod
    def _iso(value: Any) -> Optional[str]:
        return value.isoformat() if isinstance(value, datetime) else None
