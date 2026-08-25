"""
Analytics service.

Aggregates interactions, alerts and sessions into the shapes the analytics API
returns. Time bucketing is done in Python rather than with vendor-specific SQL
date functions so the same queries run on PostgreSQL and on the SQLite database
used by the test suite.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import AI_PLATFORMS
from app.core.database import (
    AIInteraction,
    AlertStatus,
    RiskLevel,
    SecurityAlert,
    UserSession,
)
from app.core.timeutils import utcnow

# Maps the API's TimeRangeType values onto concrete durations.
TIME_RANGE_DELTAS: Dict[str, timedelta] = {
    "1h": timedelta(hours=1),
    "24h": timedelta(days=1),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
    "365d": timedelta(days=365),
}

RISK_WEIGHTS: Dict[RiskLevel, int] = {
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def resolve_time_range(time_range: Any) -> Tuple[datetime, datetime]:
    """Turn a TimeRangeType (or its raw value) into a concrete window."""
    key = getattr(time_range, "value", time_range) or "30d"
    end = utcnow()
    start = end - TIME_RANGE_DELTAS.get(key, timedelta(days=30))
    return start, end


def bucket_key(moment: datetime, granularity: str) -> str:
    """Format a timestamp as a sortable bucket label."""
    if granularity == "hour":
        return moment.strftime("%Y-%m-%dT%H:00")
    if granularity == "week":
        iso_year, iso_week, _ = moment.isocalendar()
        return f"{iso_year}-W{iso_week:02d}"
    if granularity == "month":
        return moment.strftime("%Y-%m")
    return moment.strftime("%Y-%m-%d")


class AnalyticsService:
    """Read-only aggregation queries backing the analytics endpoints."""

    # -- Risk ---------------------------------------------------------------

    async def get_risk_analytics(
        self,
        db: AsyncSession,
        start_date: datetime,
        end_date: datetime,
        platforms: Optional[List[str]] = None,
        risk_levels: Optional[List[str]] = None,
        group_by: Any = None,
        limit: Optional[int] = 100,
    ) -> Dict[str, Any]:
        """Risk distribution, platform breakdown, trend and top risk patterns."""
        conditions = [
            AIInteraction.created_at >= start_date,
            AIInteraction.created_at <= end_date,
            AIInteraction.deleted_at.is_(None),
        ]
        if platforms:
            conditions.append(AIInteraction.platform.in_(platforms))
        if risk_levels:
            levels = [
                RiskLevel(level)
                for level in risk_levels
                if level in RiskLevel._value2member_map_
            ]
            if levels:
                conditions.append(AIInteraction.risk_level.in_(levels))

        window = and_(*conditions)

        total_interactions = (
            await db.execute(
                select(func.count()).select_from(AIInteraction).where(window)
            )
        ).scalar_one()

        risk_rows = await db.execute(
            select(AIInteraction.risk_level, func.count())
            .where(window)
            .group_by(AIInteraction.risk_level)
        )
        risk_distribution = {
            (level.value if level else "unknown"): count
            for level, count in risk_rows.all()
        }
        for level in RiskLevel:
            risk_distribution.setdefault(level.value, 0)

        platform_rows = await db.execute(
            select(AIInteraction.platform, func.count())
            .where(window)
            .group_by(AIInteraction.platform)
            .order_by(desc(func.count()))
        )
        platform_breakdown = {
            (platform or "unknown"): count for platform, count in platform_rows.all()
        }

        granularity = getattr(group_by, "value", group_by)
        if granularity not in ("hour", "day", "week", "month"):
            granularity = self._auto_granularity(start_date, end_date)

        trend_data = await self._risk_trend(db, window, granularity)
        top_risk_patterns = await self._top_risk_patterns(db, window, limit or 10)
        summary_stats = await self._risk_summary(db, window, total_interactions)

        return {
            "total_interactions": total_interactions,
            "risk_distribution": risk_distribution,
            "platform_breakdown": platform_breakdown,
            "trend_data": trend_data,
            "top_risk_patterns": top_risk_patterns,
            "summary_stats": summary_stats,
        }

    # -- Platforms ----------------------------------------------------------

    async def get_platform_analytics(
        self,
        db: AsyncSession,
        time_range: Any = "30d",
        platforms: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Usage volume, trends, risk correlation and adoption per platform."""
        start_date, end_date = resolve_time_range(time_range)
        conditions = [
            AIInteraction.created_at >= start_date,
            AIInteraction.created_at <= end_date,
            AIInteraction.deleted_at.is_(None),
        ]
        if platforms:
            conditions.append(AIInteraction.platform.in_(platforms))
        window = and_(*conditions)

        usage_rows = await db.execute(
            select(AIInteraction.platform, func.count())
            .where(window)
            .group_by(AIInteraction.platform)
            .order_by(desc(func.count()))
        )
        total_usage = {
            (platform or "unknown"): count for platform, count in usage_rows.all()
        }

        risk_rows = await db.execute(
            select(
                AIInteraction.platform,
                func.avg(AIInteraction.risk_score),
                func.count(),
            )
            .where(window)
            .group_by(AIInteraction.platform)
        )
        risk_correlation = {
            (platform or "unknown"): round(float(avg_score or 0.0), 2)
            for platform, avg_score, _ in risk_rows.all()
        }

        granularity = self._auto_granularity(start_date, end_date)
        trend_rows = await db.execute(
            select(AIInteraction.created_at, AIInteraction.platform).where(window)
        )
        buckets: Dict[str, Dict[str, Any]] = {}
        for created_at, platform in trend_rows.all():
            if created_at is None:
                continue
            key = bucket_key(created_at, granularity)
            bucket = buckets.setdefault(key, {"period": key, "total": 0, "platforms": {}})
            name = platform or "unknown"
            bucket["total"] += 1
            bucket["platforms"][name] = bucket["platforms"].get(name, 0) + 1
        usage_trends = [buckets[key] for key in sorted(buckets)]

        adoption_rows = await db.execute(
            select(
                AIInteraction.platform,
                func.count(func.distinct(AIInteraction.session_id)),
                func.count(func.distinct(AIInteraction.user_id)),
            )
            .where(window)
            .group_by(AIInteraction.platform)
        )
        user_adoption = {
            (platform or "unknown"): {
                "sessions": sessions or 0,
                "users": users or 0,
            }
            for platform, sessions, users in adoption_rows.all()
        }

        # "Popular features" is derived from the risk categories observed per
        # platform - the closest signal available without storing content.
        popular_features = await self._platform_risk_flags(db, window)

        return {
            "total_usage": total_usage,
            "usage_trends": usage_trends,
            "risk_correlation": risk_correlation,
            "popular_features": popular_features,
            "user_adoption": user_adoption,
        }

    # -- Alerts -------------------------------------------------------------

    async def get_alert_analytics(
        self,
        db: AsyncSession,
        time_range: Any = "30d",
        severity_levels: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Alert volume, severity split, trends, resolution and top alert types."""
        start_date, end_date = resolve_time_range(time_range)
        conditions = [
            SecurityAlert.created_at >= start_date,
            SecurityAlert.created_at <= end_date,
        ]
        if severity_levels:
            levels = [
                RiskLevel(level)
                for level in severity_levels
                if level in RiskLevel._value2member_map_
            ]
            if levels:
                conditions.append(SecurityAlert.severity.in_(levels))
        window = and_(*conditions)

        total_alerts = (
            await db.execute(
                select(func.count()).select_from(SecurityAlert).where(window)
            )
        ).scalar_one()

        severity_rows = await db.execute(
            select(SecurityAlert.severity, func.count())
            .where(window)
            .group_by(SecurityAlert.severity)
        )
        alerts_by_severity = {
            (severity.value if severity else "unknown"): count
            for severity, count in severity_rows.all()
        }
        for level in RiskLevel:
            alerts_by_severity.setdefault(level.value, 0)

        granularity = self._auto_granularity(start_date, end_date)
        trend_rows = await db.execute(
            select(SecurityAlert.created_at, SecurityAlert.severity).where(window)
        )
        buckets: Dict[str, Dict[str, Any]] = {}
        for created_at, severity in trend_rows.all():
            if created_at is None:
                continue
            key = bucket_key(created_at, granularity)
            bucket = buckets.setdefault(
                key, {"period": key, "count": 0, "by_severity": {}}
            )
            bucket["count"] += 1
            name = severity.value if severity else "unknown"
            bucket["by_severity"][name] = bucket["by_severity"].get(name, 0) + 1
        alert_trends = [buckets[key] for key in sorted(buckets)]

        resolution_rows = await db.execute(
            select(SecurityAlert.created_at, SecurityAlert.resolved_at).where(
                and_(window, SecurityAlert.resolved_at.isnot(None))
            )
        )
        durations = [
            (resolved - created).total_seconds() / 3600
            for created, resolved in resolution_rows.all()
            if created and resolved
        ]

        false_positives = (
            await db.execute(
                select(func.count())
                .select_from(SecurityAlert)
                .where(and_(window, SecurityAlert.status == AlertStatus.FALSE_POSITIVE))
            )
        ).scalar_one()

        open_alerts = (
            await db.execute(
                select(func.count())
                .select_from(SecurityAlert)
                .where(and_(window, SecurityAlert.status == AlertStatus.OPEN))
            )
        ).scalar_one()

        type_rows = await db.execute(
            select(
                SecurityAlert.alert_type,
                func.count(),
                func.avg(SecurityAlert.confidence_score),
            )
            .where(window)
            .group_by(SecurityAlert.alert_type)
            .order_by(desc(func.count()))
            .limit(10)
        )
        top_alert_types = [
            {
                "alert_type": alert_type or "unknown",
                "count": count,
                "share_percent": (
                    round(count / total_alerts * 100, 2) if total_alerts else 0.0
                ),
                "mean_confidence": round(float(confidence or 0.0), 2),
            }
            for alert_type, count, confidence in type_rows.all()
        ]

        return {
            "total_alerts": total_alerts,
            "alerts_by_severity": alerts_by_severity,
            "alert_trends": alert_trends,
            "resolution_metrics": {
                "resolved_count": len(durations),
                "open_count": open_alerts,
                "mean_resolution_hours": (
                    round(sum(durations) / len(durations), 2) if durations else 0.0
                ),
                "fastest_resolution_hours": (
                    round(min(durations), 2) if durations else 0.0
                ),
                "slowest_resolution_hours": (
                    round(max(durations), 2) if durations else 0.0
                ),
                "resolution_rate": (
                    round(len(durations) / total_alerts * 100, 2) if total_alerts else 0.0
                ),
            },
            "false_positive_rate": (
                round(false_positives / total_alerts * 100, 2) if total_alerts else 0.0
            ),
            "top_alert_types": top_alert_types,
        }

    # -- Users --------------------------------------------------------------

    async def get_user_analytics(
        self,
        db: AsyncSession,
        user_id: str,
        time_range: Any = "30d",
        requester_permissions: Optional[Dict[str, bool]] = None,
    ) -> Dict[str, Any]:
        """Per-user activity summary.

        Returns aggregates only - never content hashes or raw metadata - so the
        response stays within what the privacy policy allows analysts to see.
        """
        start_date, end_date = resolve_time_range(time_range)
        window = and_(
            AIInteraction.user_id == user_id,
            AIInteraction.created_at >= start_date,
            AIInteraction.created_at <= end_date,
            AIInteraction.deleted_at.is_(None),
        )

        totals = (
            await db.execute(
                select(
                    func.count(),
                    func.avg(AIInteraction.risk_score),
                    func.max(AIInteraction.risk_score),
                    func.count(func.distinct(AIInteraction.session_id)),
                ).where(window)
            )
        ).one()
        interaction_count, avg_risk, max_risk, session_count = totals

        platform_rows = await db.execute(
            select(AIInteraction.platform, func.count())
            .where(window)
            .group_by(AIInteraction.platform)
            .order_by(desc(func.count()))
        )
        platforms_used = {
            (platform or "unknown"): count for platform, count in platform_rows.all()
        }

        risk_rows = await db.execute(
            select(AIInteraction.risk_level, func.count())
            .where(window)
            .group_by(AIInteraction.risk_level)
        )
        risk_distribution = {
            (level.value if level else "unknown"): count
            for level, count in risk_rows.all()
        }

        alert_count = (
            await db.execute(
                select(func.count())
                .select_from(SecurityAlert)
                .join(AIInteraction, SecurityAlert.interaction_id == AIInteraction.id)
                .where(window)
            )
        ).scalar_one()

        granularity = self._auto_granularity(start_date, end_date)
        activity_rows = await db.execute(
            select(AIInteraction.created_at, AIInteraction.risk_score).where(window)
        )
        buckets: Dict[str, Dict[str, Any]] = {}
        for created_at, risk_score in activity_rows.all():
            if created_at is None:
                continue
            key = bucket_key(created_at, granularity)
            bucket = buckets.setdefault(
                key, {"period": key, "count": 0, "risk_total": 0.0}
            )
            bucket["count"] += 1
            bucket["risk_total"] += float(risk_score or 0.0)

        activity_timeline = [
            {
                "period": buckets[key]["period"],
                "interactions": buckets[key]["count"],
                "mean_risk_score": round(
                    buckets[key]["risk_total"] / buckets[key]["count"], 2
                ),
            }
            for key in sorted(buckets)
        ]

        return {
            "user_id": user_id,
            "time_range": getattr(time_range, "value", time_range),
            "period": {"start": start_date, "end": end_date},
            "total_interactions": interaction_count or 0,
            "total_sessions": session_count or 0,
            "total_alerts": alert_count,
            "mean_risk_score": round(float(avg_risk or 0.0), 2),
            "peak_risk_score": round(float(max_risk or 0.0), 2),
            "platforms_used": platforms_used,
            "risk_distribution": risk_distribution,
            "activity_timeline": activity_timeline,
            "alert_ratio": (
                round(alert_count / interaction_count * 100, 2)
                if interaction_count
                else 0.0
            ),
        }

    # -- Dashboard ----------------------------------------------------------

    async def get_dashboard_summary(self, db: AsyncSession) -> Dict[str, Any]:
        """Headline KPIs for the dashboard landing page."""
        now = utcnow()
        last_24h = now - timedelta(days=1)
        last_7d = now - timedelta(days=7)

        interactions_24h = (
            await db.execute(
                select(func.count())
                .select_from(AIInteraction)
                .where(
                    and_(
                        AIInteraction.created_at >= last_24h,
                        AIInteraction.deleted_at.is_(None),
                    )
                )
            )
        ).scalar_one()

        interactions_7d = (
            await db.execute(
                select(func.count())
                .select_from(AIInteraction)
                .where(
                    and_(
                        AIInteraction.created_at >= last_7d,
                        AIInteraction.deleted_at.is_(None),
                    )
                )
            )
        ).scalar_one()

        open_alerts = (
            await db.execute(
                select(func.count())
                .select_from(SecurityAlert)
                .where(SecurityAlert.status == AlertStatus.OPEN)
            )
        ).scalar_one()

        critical_alerts = (
            await db.execute(
                select(func.count())
                .select_from(SecurityAlert)
                .where(
                    and_(
                        SecurityAlert.severity == RiskLevel.CRITICAL,
                        SecurityAlert.status == AlertStatus.OPEN,
                    )
                )
            )
        ).scalar_one()

        active_sessions = (
            await db.execute(
                select(func.count())
                .select_from(UserSession)
                .where(
                    and_(
                        UserSession.session_ended_at.is_(None),
                        UserSession.last_activity_at >= now - timedelta(hours=4),
                    )
                )
            )
        ).scalar_one()

        mean_risk = (
            await db.execute(
                select(func.avg(AIInteraction.risk_score)).where(
                    and_(
                        AIInteraction.created_at >= last_7d,
                        AIInteraction.deleted_at.is_(None),
                    )
                )
            )
        ).scalar_one()

        recent_alert_rows = await db.execute(
            select(SecurityAlert).order_by(desc(SecurityAlert.created_at)).limit(5)
        )
        recent_alerts = [
            {
                "id": alert.id,
                "title": alert.title,
                "severity": alert.severity.value if alert.severity else "low",
                "status": alert.status.value if alert.status else "open",
                "created_at": alert.created_at,
            }
            for alert in recent_alert_rows.scalars().all()
        ]

        top_platform_rows = await db.execute(
            select(AIInteraction.platform, func.count())
            .where(
                and_(
                    AIInteraction.created_at >= last_7d,
                    AIInteraction.deleted_at.is_(None),
                )
            )
            .group_by(AIInteraction.platform)
            .order_by(desc(func.count()))
            .limit(5)
        )

        return {
            "generated_at": now,
            "kpis": {
                "interactions_last_24h": interactions_24h,
                "interactions_last_7d": interactions_7d,
                "open_alerts": open_alerts,
                "critical_open_alerts": critical_alerts,
                "active_sessions": active_sessions,
                "mean_risk_score_7d": round(float(mean_risk or 0.0), 2),
            },
            "recent_alerts": recent_alerts,
            "top_platforms": [
                {"platform": platform or "unknown", "interactions": count}
                for platform, count in top_platform_rows.all()
            ],
            "monitored_platforms": len(AI_PLATFORMS),
        }

    # -- Trends -------------------------------------------------------------

    async def get_trend_analysis(
        self,
        db: AsyncSession,
        metric: str,
        time_range: Any = "90d",
        granularity: Any = "day",
        forecast_days: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Historical series for one metric, with an optional linear forecast."""
        start_date, end_date = resolve_time_range(time_range)
        grain = getattr(granularity, "value", granularity) or "day"
        if grain not in ("hour", "day", "week", "month"):
            grain = "day"

        if metric == "alerts":
            rows = (
                await db.execute(
                    select(SecurityAlert.created_at).where(
                        and_(
                            SecurityAlert.created_at >= start_date,
                            SecurityAlert.created_at <= end_date,
                        )
                    )
                )
            ).all()
            points = [(row[0], 1.0) for row in rows]
            aggregation = "count"
        elif metric == "risk_score":
            rows = (
                await db.execute(
                    select(AIInteraction.created_at, AIInteraction.risk_score).where(
                        and_(
                            AIInteraction.created_at >= start_date,
                            AIInteraction.created_at <= end_date,
                            AIInteraction.deleted_at.is_(None),
                        )
                    )
                )
            ).all()
            points = [(created_at, float(score or 0.0)) for created_at, score in rows]
            aggregation = "mean"
        elif metric == "interactions":
            rows = (
                await db.execute(
                    select(AIInteraction.created_at).where(
                        and_(
                            AIInteraction.created_at >= start_date,
                            AIInteraction.created_at <= end_date,
                            AIInteraction.deleted_at.is_(None),
                        )
                    )
                )
            ).all()
            points = [(row[0], 1.0) for row in rows]
            aggregation = "count"
        else:
            raise ValueError(
                f"Unsupported metric '{metric}'. Expected one of: "
                "interactions, risk_score, alerts"
            )

        buckets: Dict[str, List[float]] = {}
        for moment, value in points:
            if moment is None:
                continue
            buckets.setdefault(bucket_key(moment, grain), []).append(value)

        series = [
            {
                "period": key,
                "value": round(
                    (
                        sum(values)
                        if aggregation == "count"
                        else sum(values) / len(values)
                    ),
                    2,
                ),
                "samples": len(values),
            }
            for key, values in sorted(buckets.items())
        ]

        return {
            "metric": metric,
            "aggregation": aggregation,
            "granularity": grain,
            "period": {"start": start_date, "end": end_date},
            "series": series,
            "summary": self._series_summary(series),
            "forecast": self._forecast(series, forecast_days) if forecast_days else [],
        }

    # -- Internals ----------------------------------------------------------

    @staticmethod
    def _auto_granularity(start_date: datetime, end_date: datetime) -> str:
        """Pick a bucket size that keeps the series readable."""
        span_days = max((end_date - start_date).days, 0)
        if span_days <= 2:
            return "hour"
        if span_days <= 60:
            return "day"
        if span_days <= 365:
            return "week"
        return "month"

    async def _risk_trend(
        self, db: AsyncSession, window: Any, granularity: str
    ) -> List[Dict[str, Any]]:
        rows = await db.execute(
            select(
                AIInteraction.created_at,
                AIInteraction.risk_score,
                AIInteraction.risk_level,
            ).where(window)
        )

        buckets: Dict[str, Dict[str, Any]] = {}
        for created_at, risk_score, risk_level in rows.all():
            if created_at is None:
                continue
            key = bucket_key(created_at, granularity)
            bucket = buckets.setdefault(
                key,
                {"period": key, "interactions": 0, "risk_total": 0.0, "high_risk": 0},
            )
            bucket["interactions"] += 1
            bucket["risk_total"] += float(risk_score or 0.0)
            if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                bucket["high_risk"] += 1

        return [
            {
                "period": buckets[key]["period"],
                "interactions": buckets[key]["interactions"],
                "mean_risk_score": round(
                    buckets[key]["risk_total"] / buckets[key]["interactions"], 2
                ),
                "high_risk_count": buckets[key]["high_risk"],
            }
            for key in sorted(buckets)
        ]

    async def _top_risk_patterns(
        self, db: AsyncSession, window: Any, limit: int
    ) -> List[Dict[str, Any]]:
        """Count how often each risk flag fired.

        `risk_flags` is a JSON array, so it is unrolled in Python; the query is
        bounded to keep memory predictable on large windows.
        """
        rows = await db.execute(
            select(AIInteraction.risk_flags, AIInteraction.risk_score)
            .where(window)
            .limit(50_000)
        )

        counts: Dict[str, Dict[str, Any]] = {}
        for flags, risk_score in rows.all():
            for flag in flags or []:
                entry = counts.setdefault(
                    flag, {"pattern": flag, "count": 0, "risk_total": 0.0}
                )
                entry["count"] += 1
                entry["risk_total"] += float(risk_score or 0.0)

        ranked = sorted(counts.values(), key=lambda item: item["count"], reverse=True)
        return [
            {
                "pattern": entry["pattern"],
                "count": entry["count"],
                "mean_risk_score": round(entry["risk_total"] / entry["count"], 2),
            }
            for entry in ranked[: max(limit, 1)]
        ]

    async def _risk_summary(
        self, db: AsyncSession, window: Any, total_interactions: int
    ) -> Dict[str, float]:
        row = (
            await db.execute(
                select(
                    func.avg(AIInteraction.risk_score),
                    func.max(AIInteraction.risk_score),
                    func.avg(AIInteraction.confidence_score),
                    func.avg(AIInteraction.anomaly_score),
                ).where(window)
            )
        ).one()
        mean_risk, peak_risk, mean_confidence, mean_anomaly = row

        high_risk = (
            await db.execute(
                select(func.count())
                .select_from(AIInteraction)
                .where(
                    and_(
                        window,
                        AIInteraction.risk_level.in_(
                            [RiskLevel.HIGH, RiskLevel.CRITICAL]
                        ),
                    )
                )
            )
        ).scalar_one()

        return {
            "mean_risk_score": round(float(mean_risk or 0.0), 2),
            "peak_risk_score": round(float(peak_risk or 0.0), 2),
            "mean_confidence": round(float(mean_confidence or 0.0), 2),
            "mean_anomaly_score": round(float(mean_anomaly or 0.0), 2),
            "high_risk_count": float(high_risk),
            "high_risk_percentage": (
                round(high_risk / total_interactions * 100, 2)
                if total_interactions
                else 0.0
            ),
        }

    async def _platform_risk_flags(
        self, db: AsyncSession, window: Any
    ) -> Dict[str, List[str]]:
        rows = await db.execute(
            select(AIInteraction.platform, AIInteraction.risk_flags)
            .where(window)
            .limit(50_000)
        )

        per_platform: Dict[str, Dict[str, int]] = {}
        for platform, flags in rows.all():
            name = platform or "unknown"
            counter = per_platform.setdefault(name, {})
            for flag in flags or []:
                counter[flag] = counter.get(flag, 0) + 1

        return {
            platform: [
                flag
                for flag, _ in sorted(
                    counter.items(), key=lambda kv: kv[1], reverse=True
                )[:5]
            ]
            for platform, counter in per_platform.items()
        }

    @staticmethod
    def _series_summary(series: List[Dict[str, Any]]) -> Dict[str, Any]:
        values = [point["value"] for point in series]
        if not values:
            return {
                "mean": 0.0,
                "min": 0.0,
                "max": 0.0,
                "change_percent": 0.0,
                "direction": "flat",
            }

        first, last = values[0], values[-1]
        change = ((last - first) / first * 100) if first else 0.0

        return {
            "mean": round(sum(values) / len(values), 2),
            "min": round(min(values), 2),
            "max": round(max(values), 2),
            "change_percent": round(change, 2),
            "direction": "up" if change > 5 else "down" if change < -5 else "flat",
        }

    @staticmethod
    def _forecast(series: List[Dict[str, Any]], days: int) -> List[Dict[str, Any]]:
        """Project the series forward with ordinary least squares.

        A deliberately simple linear fit: enough to show direction on a chart,
        and honest about it via the `method` field in the response.
        """
        values = [point["value"] for point in series]
        n = len(values)
        if n < 3:
            return []

        mean_x = (n - 1) / 2
        mean_y = sum(values) / n
        denominator = sum((i - mean_x) ** 2 for i in range(n))
        if denominator == 0:
            return []

        slope = sum((i - mean_x) * (values[i] - mean_y) for i in range(n)) / denominator
        intercept = mean_y - slope * mean_x

        return [
            {
                "offset": step,
                "value": round(max(intercept + slope * (n - 1 + step), 0.0), 2),
                "method": "linear_least_squares",
            }
            for step in range(1, days + 1)
        ]
