"""
Tests for AnalyticsService aggregations, bucketing and forecasting.
"""

from datetime import timedelta

import pytest

from app.core.database import AlertStatus, RiskLevel
from app.core.timeutils import utcnow
from app.services.analytics_service import (
    AnalyticsService,
    bucket_key,
    resolve_time_range,
)


@pytest.fixture
def service() -> AnalyticsService:
    return AnalyticsService()


class TestTimeHelpers:
    @pytest.mark.parametrize(
        "time_range,expected_days",
        [("24h", 1), ("7d", 7), ("30d", 30), ("90d", 90), ("365d", 365)],
    )
    def test_known_ranges_resolve_to_their_duration(self, time_range, expected_days):
        start, end = resolve_time_range(time_range)
        assert (end - start).days == expected_days

    def test_unknown_range_falls_back_to_30_days(self):
        start, end = resolve_time_range("nonsense")
        assert (end - start).days == 30

    def test_bucket_keys_sort_chronologically(self):
        moments = [utcnow() - timedelta(days=offset) for offset in range(5)]
        keys = sorted(bucket_key(moment, "day") for moment in moments)
        assert keys == sorted(keys)

    def test_hour_bucket_includes_the_hour(self):
        key = bucket_key(utcnow().replace(hour=13), "hour")
        assert key.endswith("T13:00")

    def test_month_bucket_drops_the_day(self):
        assert len(bucket_key(utcnow(), "month")) == 7


class TestRiskAnalytics:
    async def test_counts_and_distribution(self, service, db_session, make_interaction):
        await make_interaction(risk_level=RiskLevel.LOW, risk_score=5)
        await make_interaction(risk_level=RiskLevel.HIGH, risk_score=75)
        await make_interaction(risk_level=RiskLevel.HIGH, risk_score=85)

        start, end = resolve_time_range("30d")
        result = await service.get_risk_analytics(db_session, start, end)

        assert result["total_interactions"] == 3
        assert result["risk_distribution"]["high"] == 2
        assert result["risk_distribution"]["critical"] == 0

    async def test_platform_filter_narrows_the_result(
        self, service, db_session, make_interaction
    ):
        await make_interaction(platform="chatgpt")
        await make_interaction(platform="claude")

        start, end = resolve_time_range("30d")
        result = await service.get_risk_analytics(
            db_session, start, end, platforms=["claude"]
        )

        assert result["total_interactions"] == 1
        assert list(result["platform_breakdown"]) == ["claude"]

    async def test_soft_deleted_interactions_are_excluded(
        self, service, db_session, make_interaction
    ):
        await make_interaction()
        await make_interaction(deleted_at=utcnow())

        start, end = resolve_time_range("30d")
        result = await service.get_risk_analytics(db_session, start, end)

        assert result["total_interactions"] == 1

    async def test_top_risk_patterns_rank_by_frequency(
        self, service, db_session, make_interaction
    ):
        await make_interaction(risk_flags=["api_key", "email"])
        await make_interaction(risk_flags=["api_key"])
        await make_interaction(risk_flags=["ssn"])

        start, end = resolve_time_range("30d")
        result = await service.get_risk_analytics(db_session, start, end)

        patterns = result["top_risk_patterns"]
        assert patterns[0]["pattern"] == "api_key"
        assert patterns[0]["count"] == 2

    async def test_summary_reports_high_risk_percentage(
        self, service, db_session, make_interaction
    ):
        await make_interaction(risk_level=RiskLevel.CRITICAL, risk_score=95)
        await make_interaction(risk_level=RiskLevel.LOW, risk_score=5)

        start, end = resolve_time_range("30d")
        result = await service.get_risk_analytics(db_session, start, end)

        assert result["summary_stats"]["high_risk_percentage"] == 50.0
        assert result["summary_stats"]["peak_risk_score"] == 95.0

    async def test_empty_window_returns_zeroed_stats(self, service, db_session):
        start, end = resolve_time_range("30d")
        result = await service.get_risk_analytics(db_session, start, end)

        assert result["total_interactions"] == 0
        assert result["summary_stats"]["high_risk_percentage"] == 0.0
        assert result["trend_data"] == []


class TestPlatformAnalytics:
    async def test_usage_is_ordered_by_volume(
        self, service, db_session, make_interaction
    ):
        for _ in range(3):
            await make_interaction(platform="chatgpt")
        await make_interaction(platform="claude")

        result = await service.get_platform_analytics(db_session, "30d")

        assert list(result["total_usage"]) == ["chatgpt", "claude"]
        assert result["total_usage"]["chatgpt"] == 3

    async def test_risk_correlation_averages_per_platform(
        self, service, db_session, make_interaction
    ):
        await make_interaction(platform="chatgpt", risk_score=20)
        await make_interaction(platform="chatgpt", risk_score=40)

        result = await service.get_platform_analytics(db_session, "30d")

        assert result["risk_correlation"]["chatgpt"] == 30.0

    async def test_adoption_counts_distinct_sessions(
        self, service, db_session, make_interaction, make_session
    ):
        await make_session(session_id="session-a")
        await make_session(session_id="session-b")
        await make_interaction(session_id="session-a", platform="claude")
        await make_interaction(session_id="session-a", platform="claude")
        await make_interaction(session_id="session-b", platform="claude")

        result = await service.get_platform_analytics(db_session, "30d")

        assert result["user_adoption"]["claude"]["sessions"] == 2


class TestAlertAnalytics:
    async def test_severity_buckets_are_always_present(
        self, service, db_session, make_alert
    ):
        await make_alert(severity=RiskLevel.HIGH)

        result = await service.get_alert_analytics(db_session, "30d")

        assert set(result["alerts_by_severity"]) >= {
            "low",
            "medium",
            "high",
            "critical",
        }
        assert result["alerts_by_severity"]["high"] == 1
        assert result["alerts_by_severity"]["low"] == 0

    async def test_resolution_metrics_use_elapsed_hours(
        self, service, db_session, make_alert
    ):
        created = utcnow() - timedelta(hours=6)
        await make_alert(
            created_at=created,
            status=AlertStatus.RESOLVED,
            resolved_at=created + timedelta(hours=3),
        )

        result = await service.get_alert_analytics(db_session, "30d")

        assert result["resolution_metrics"]["mean_resolution_hours"] == pytest.approx(
            3.0, abs=0.1
        )

    async def test_top_alert_types_include_share(self, service, db_session, make_alert):
        await make_alert(alert_type="api_key")
        await make_alert(alert_type="api_key")
        await make_alert(alert_type="ssn")

        result = await service.get_alert_analytics(db_session, "30d")

        top = result["top_alert_types"][0]
        assert top["alert_type"] == "api_key"
        assert top["share_percent"] == pytest.approx(66.67, abs=0.01)

    async def test_severity_filter_is_applied(self, service, db_session, make_alert):
        await make_alert(severity=RiskLevel.CRITICAL)
        await make_alert(severity=RiskLevel.LOW)

        result = await service.get_alert_analytics(
            db_session, "30d", severity_levels=["critical"]
        )

        assert result["total_alerts"] == 1


class TestUserAnalytics:
    async def test_aggregates_a_single_user(self, service, db_session, make_interaction):
        await make_interaction(user_id="target", risk_score=40)
        await make_interaction(user_id="target", risk_score=60)
        await make_interaction(user_id="someone-else", risk_score=90)

        result = await service.get_user_analytics(db_session, "target", "30d")

        assert result["total_interactions"] == 2
        assert result["mean_risk_score"] == 50.0
        assert result["peak_risk_score"] == 60.0

    async def test_never_returns_content_hashes(
        self, service, db_session, make_interaction
    ):
        """User analytics is aggregate-only; per-record identifiers must not leak."""
        await make_interaction(user_id="target", content_hash="c" * 64)

        result = await service.get_user_analytics(db_session, "target", "30d")

        assert "c" * 64 not in str(result)

    async def test_unknown_user_returns_zeroes_not_an_error(self, service, db_session):
        result = await service.get_user_analytics(db_session, "ghost", "30d")

        assert result["total_interactions"] == 0
        assert result["alert_ratio"] == 0.0


class TestDashboardSummary:
    async def test_kpis_reflect_stored_data(
        self, service, db_session, make_interaction, make_alert
    ):
        await make_interaction()
        await make_alert(severity=RiskLevel.CRITICAL, status=AlertStatus.OPEN)

        summary = await service.get_dashboard_summary(db_session)

        assert summary["kpis"]["interactions_last_24h"] == 1
        assert summary["kpis"]["open_alerts"] == 1
        assert summary["kpis"]["critical_open_alerts"] == 1

    async def test_recent_alerts_are_capped_at_five(
        self, service, db_session, make_alert
    ):
        for index in range(8):
            await make_alert(title=f"Alert {index}")

        summary = await service.get_dashboard_summary(db_session)

        assert len(summary["recent_alerts"]) == 5

    async def test_works_on_an_empty_database(self, service, db_session):
        summary = await service.get_dashboard_summary(db_session)

        assert summary["kpis"]["interactions_last_24h"] == 0
        assert summary["recent_alerts"] == []


class TestTrendAnalysis:
    async def test_interactions_metric_counts_per_bucket(
        self, service, db_session, make_interaction
    ):
        today = utcnow()
        await make_interaction(created_at=today)
        await make_interaction(created_at=today)
        await make_interaction(created_at=today - timedelta(days=1))

        result = await service.get_trend_analysis(
            db_session, "interactions", "30d", "day"
        )

        assert result["aggregation"] == "count"
        assert sum(point["value"] for point in result["series"]) == 3

    async def test_risk_score_metric_averages_per_bucket(
        self, service, db_session, make_interaction
    ):
        today = utcnow()
        await make_interaction(created_at=today, risk_score=20)
        await make_interaction(created_at=today, risk_score=40)

        result = await service.get_trend_analysis(db_session, "risk_score", "30d", "day")

        assert result["aggregation"] == "mean"
        assert result["series"][-1]["value"] == 30.0

    async def test_unsupported_metric_raises(self, service, db_session):
        with pytest.raises(ValueError, match="Unsupported metric"):
            await service.get_trend_analysis(db_session, "vibes", "30d", "day")

    async def test_forecast_is_empty_without_enough_history(self, service, db_session):
        result = await service.get_trend_analysis(
            db_session, "interactions", "30d", "day", forecast_days=7
        )

        assert result["forecast"] == []

    def test_forecast_projects_a_rising_series_upward(self, service):
        series = [{"period": f"d{i}", "value": float(i), "samples": 1} for i in range(6)]

        forecast = service._forecast(series, days=3)

        assert len(forecast) == 3
        assert forecast[0]["value"] > series[-1]["value"]

    def test_forecast_never_goes_negative(self, service):
        """A steeply falling series must floor at zero, not predict -40 alerts."""
        series = [
            {"period": f"d{i}", "value": float(50 - i * 10), "samples": 1}
            for i in range(6)
        ]

        forecast = service._forecast(series, days=5)

        assert all(point["value"] >= 0 for point in forecast)

    def test_series_summary_reports_direction(self, service):
        rising = [{"period": "a", "value": 10.0}, {"period": "b", "value": 30.0}]
        falling = [{"period": "a", "value": 30.0}, {"period": "b", "value": 10.0}]
        flat = [{"period": "a", "value": 10.0}, {"period": "b", "value": 10.2}]

        assert service._series_summary(rising)["direction"] == "up"
        assert service._series_summary(falling)["direction"] == "down"
        assert service._series_summary(flat)["direction"] == "flat"

    def test_series_summary_handles_an_empty_series(self, service):
        assert service._series_summary([])["direction"] == "flat"


class TestGranularity:
    @pytest.mark.parametrize(
        "days,expected",
        [(1, "hour"), (30, "day"), (200, "week"), (500, "month")],
    )
    def test_auto_granularity_scales_with_the_window(self, service, days, expected):
        end = utcnow()
        start = end - timedelta(days=days)

        assert service._auto_granularity(start, end) == expected
