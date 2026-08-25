"""
Tests for the export, notification, websocket and ML services.
"""

import csv
import json
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest

from app.core.config import settings
from app.core.database import RiskLevel
from app.core.timeutils import utcnow
from app.services.export_service import PII_FIELDS, ExportService
from app.services.notification_service import NotificationResult, NotificationService

# ---------------------------------------------------------------------------
# Export service
# ---------------------------------------------------------------------------


@pytest.fixture
def export_service(tmp_path) -> ExportService:
    return ExportService(export_dir=str(tmp_path / "exports"))


class TestExportService:
    async def test_interactions_export_writes_a_csv(
        self, export_service, db_session, make_interaction
    ):
        await make_interaction(platform="chatgpt")
        await make_interaction(platform="claude")

        result = await export_service.create_export(
            db_session, "interactions", format="csv"
        )

        assert result["success"]
        assert result["record_count"] == 2

        path = export_service.resolve_export_path(result["export_id"])
        rows = list(csv.DictReader(path.read_text(encoding="utf-8").splitlines()))
        assert len(rows) == 2

    async def test_pii_is_stripped_by_default(
        self, export_service, db_session, make_interaction
    ):
        await make_interaction(user_id="alice", ip_address="203.0.113.9")

        result = await export_service.create_export(
            db_session, "interactions", format="json"
        )
        path = export_service.resolve_export_path(result["export_id"])
        rows = json.loads(path.read_text(encoding="utf-8"))

        assert not (set(rows[0]) & PII_FIELDS)
        assert "203.0.113.9" not in path.read_text(encoding="utf-8")

    async def test_pii_is_retained_when_explicitly_requested(
        self, export_service, db_session, make_interaction
    ):
        await make_interaction(user_id="alice")

        result = await export_service.create_export(
            db_session, "interactions", format="json", include_pii=True
        )
        path = export_service.resolve_export_path(result["export_id"])
        rows = json.loads(path.read_text(encoding="utf-8"))

        assert rows[0]["user_id"] == "alice"

    async def test_alerts_export(self, export_service, db_session, make_alert):
        await make_alert(title="Key leaked")

        result = await export_service.create_export(db_session, "alerts", format="json")
        path = export_service.resolve_export_path(result["export_id"])

        assert json.loads(path.read_text(encoding="utf-8"))[0]["title"] == "Key leaked"

    async def test_analytics_export_flattens_the_series(
        self, export_service, db_session, make_interaction
    ):
        await make_interaction(risk_flags=["api_key"])

        result = await export_service.create_export(
            db_session, "analytics", format="json"
        )
        path = export_service.resolve_export_path(result["export_id"])
        rows = json.loads(path.read_text(encoding="utf-8"))

        assert {row["record_type"] for row in rows} >= {"trend", "risk_distribution"}

    async def test_unknown_export_type_raises(self, export_service, db_session):
        with pytest.raises(ValueError, match="Unsupported export type"):
            await export_service.create_export(db_session, "secrets")

    @pytest.mark.parametrize(
        "malicious",
        [
            "../../../../etc/passwd",
            "alerts-../../secret",
            "alerts-zzzzzzzzzzzz",
            "",
            "alerts-abc",
        ],
    )
    def test_export_ids_that_are_not_well_formed_are_refused(
        self, export_service, malicious
    ):
        """A crafted id must never resolve to a path outside the export dir."""
        assert export_service.resolve_export_path(malicious) is None

    def test_valid_looking_id_for_a_missing_file_returns_none(self, export_service):
        assert export_service.resolve_export_path("alerts-0123456789ab") is None

    async def test_cleanup_removes_files_past_their_ttl(
        self, export_service, db_session, make_alert
    ):
        import os

        await make_alert()
        result = await export_service.create_export(db_session, "alerts", format="json")
        path = export_service.resolve_export_path(result["export_id"])

        stale = (utcnow() - timedelta(hours=48)).timestamp()
        os.utime(path, (stale, stale))

        assert export_service.cleanup_expired_exports() == 1
        assert not path.exists()

    async def test_cleanup_keeps_fresh_files(
        self, export_service, db_session, make_alert
    ):
        await make_alert()
        await export_service.create_export(db_session, "alerts", format="json")

        assert export_service.cleanup_expired_exports() == 0


# ---------------------------------------------------------------------------
# Notification service
# ---------------------------------------------------------------------------


class TestNotificationPolicy:
    def test_critical_always_notifies(self):
        assert NotificationService._should_notify(RiskLevel.CRITICAL)

    def test_low_never_notifies(self):
        """Low-severity findings would drown the on-call rotation in noise."""
        assert not NotificationService._should_notify(RiskLevel.LOW)

    def test_recipients_escalate_with_severity(self):
        low = NotificationService._recipients_for(RiskLevel.MEDIUM)
        high = NotificationService._recipients_for(RiskLevel.HIGH)
        critical = NotificationService._recipients_for(RiskLevel.CRITICAL)

        assert set(low) <= set(high) <= set(critical)

    def test_recipients_are_deduplicated(self, monkeypatch):
        monkeypatch.setattr(settings, "ALERT_RECIPIENTS_DEFAULT", ["a@example.com"])
        monkeypatch.setattr(settings, "ALERT_RECIPIENTS_HIGH", ["a@example.com"])
        monkeypatch.setattr(settings, "ALERT_RECIPIENTS_CRITICAL", ["b@example.com"])

        recipients = NotificationService._recipients_for(RiskLevel.CRITICAL)

        assert recipients == ["a@example.com", "b@example.com"]

    def test_webhook_urls_are_logged_by_host_only(self):
        """The path of a Slack webhook is a secret; only the host may be logged."""
        safe = NotificationService._safe_url(
            "https://hooks.slack.com/services/T000/B000/XXXXSECRET"
        )

        assert safe == "hooks.slack.com"
        assert "SECRET" not in safe

    def test_safe_url_handles_none(self):
        assert NotificationService._safe_url(None) == "unset"


class TestNotificationRendering:
    def test_text_email_states_no_content_is_included(self, make_alert):
        class _Alert:
            id = 7
            alert_type = "api_key"
            title = "API key in prompt"
            description = "A token pattern matched."
            confidence_score = 91.0
            created_at = utcnow()

        body = NotificationService._render_text_email(
            _Alert(), RiskLevel.CRITICAL, "chatgpt"
        )

        assert "CRITICAL" in body
        assert "metadata only" in body.lower()

    def test_html_email_contains_the_title(self):
        class _Alert:
            id = 7
            alert_type = "api_key"
            title = "API key in prompt"
            description = "A token pattern matched."
            confidence_score = 91.0
            created_at = utcnow()

        html = NotificationService._render_html_email(_Alert(), RiskLevel.HIGH, "chatgpt")

        assert "API key in prompt" in html
        assert html.startswith("<!doctype html>")


class TestNotificationDispatch:
    async def test_suppressed_severity_sends_nothing(self, make_alert, db_session):
        alert = await make_alert(severity=RiskLevel.LOW)

        result = await NotificationService().send_alert_notifications(alert)

        assert result["channels"] == {}
        assert not result["delivered"]

    async def test_all_channels_disabled_delivers_nothing(
        self, make_alert, db_session, monkeypatch
    ):
        monkeypatch.setattr(settings, "ALERT_EMAIL_ENABLED", False)
        monkeypatch.setattr(settings, "ALERT_SLACK_ENABLED", False)
        monkeypatch.setattr(settings, "ALERT_WEBHOOK_ENABLED", False)

        alert = await make_alert(severity=RiskLevel.CRITICAL)
        result = await NotificationService().send_alert_notifications(alert)

        assert not result["delivered"]

    async def test_one_failing_channel_does_not_block_the_others(
        self, make_alert, db_session, monkeypatch
    ):
        monkeypatch.setattr(settings, "ALERT_EMAIL_ENABLED", True)
        monkeypatch.setattr(settings, "ALERT_SLACK_ENABLED", True)
        monkeypatch.setattr(settings, "ALERT_WEBHOOK_ENABLED", False)
        monkeypatch.setattr(settings, "SLACK_WEBHOOK_URL", "https://hooks.example/x")

        alert = await make_alert(severity=RiskLevel.CRITICAL)
        service = NotificationService()

        with (
            patch.object(
                service, "_send_email", AsyncMock(side_effect=RuntimeError("smtp down"))
            ),
            patch.object(service, "_send_slack", AsyncMock(return_value=True)),
        ):
            result = await service.send_alert_notifications(alert)

        assert result["channels"]["slack"] is True
        assert result["channels"]["email"] is False
        assert "smtp down" in result["errors"]["email"]

    def test_result_reports_delivered_when_any_channel_succeeded(self):
        result = NotificationResult(alert_id=1, channels={"email": False, "slack": True})

        assert result.delivered


# ---------------------------------------------------------------------------
# WebSocket manager
# ---------------------------------------------------------------------------


class TestWebSocketManager:
    async def test_connect_accepts_and_registers(
        self, ws_manager, mock_websocket, db_session
    ):
        connection_id = await ws_manager.connect(mock_websocket)

        mock_websocket.accept.assert_awaited_once()
        assert connection_id in ws_manager.connections

    async def test_disconnect_removes_the_connection(
        self, ws_manager, mock_websocket, db_session
    ):
        connection_id = await ws_manager.connect(mock_websocket)
        ws_manager.disconnect(connection_id)

        assert connection_id not in ws_manager.connections

    async def test_disconnecting_an_unknown_id_is_harmless(self, ws_manager):
        ws_manager.disconnect("never-existed")

    @staticmethod
    def _last_broadcast(mock_websocket) -> dict:
        """Broadcasts go out as JSON text frames; decode the most recent one."""
        return json.loads(mock_websocket.send_text.await_args[0][0])

    async def test_subscribe_then_receive_a_broadcast(
        self, ws_manager, mock_websocket, db_session
    ):
        connection_id = await ws_manager.connect(mock_websocket)
        await ws_manager.subscribe(connection_id, "security_alerts")
        mock_websocket.send_text.reset_mock()

        await ws_manager.broadcast_alert({"severity": "critical", "title": "Leak"})

        assert mock_websocket.send_text.await_count == 1
        assert self._last_broadcast(mock_websocket)["data"]["title"] == "Leak"

    async def test_unsubscribed_connections_receive_nothing(
        self, ws_manager, mock_websocket, db_session
    ):
        await ws_manager.connect(mock_websocket)
        mock_websocket.send_text.reset_mock()

        await ws_manager.broadcast_alert({"severity": "critical", "title": "Leak"})

        assert mock_websocket.send_text.await_count == 0

    async def test_alert_update_broadcast_is_tagged(
        self, ws_manager, mock_websocket, db_session
    ):
        connection_id = await ws_manager.connect(mock_websocket)
        await ws_manager.subscribe(connection_id, "security_alerts")
        mock_websocket.send_text.reset_mock()

        await ws_manager.broadcast_alert_update({"alert_id": 5, "new_status": "resolved"})

        assert self._last_broadcast(mock_websocket)["data"]["event"] == "alert_updated"

    async def test_bulk_update_broadcast_is_tagged(
        self, ws_manager, mock_websocket, db_session
    ):
        connection_id = await ws_manager.connect(mock_websocket)
        await ws_manager.subscribe(connection_id, "security_alerts")
        mock_websocket.send_text.reset_mock()

        await ws_manager.broadcast_bulk_alert_update(
            {"action": "resolve", "alert_count": 3}
        )

        assert (
            self._last_broadcast(mock_websocket)["data"]["event"] == "alerts_bulk_updated"
        )

    async def test_connection_stats_track_the_count(
        self, ws_manager, mock_websocket, db_session
    ):
        await ws_manager.connect(mock_websocket)

        stats = ws_manager.get_connection_stats()

        assert stats["total_connections"] >= 1

    async def test_shutdown_closes_connections(
        self, ws_manager, mock_websocket, db_session
    ):
        await ws_manager.connect(mock_websocket)
        await ws_manager.shutdown()

        assert ws_manager.connections == {}


# ---------------------------------------------------------------------------
# ML analyzer (pattern pipeline only - no model downloads)
# ---------------------------------------------------------------------------


class TestMLRiskAnalyzer:
    def test_patterns_compile_on_construction(self, ml_analyzer):
        assert ml_analyzer.pattern_cache

    def test_pattern_analysis_returns_a_dict(self, ml_analyzer):
        result = ml_analyzer._analyze_patterns({"flags": ["api_key", "email"]})

        assert isinstance(result, dict)

    def test_feature_vector_has_the_requested_width(self, ml_analyzer):
        vector = ml_analyzer._features_to_vector({"content_length": 120}, size=50)

        assert len(vector) == 50

    @pytest.mark.parametrize(
        "score,expected",
        [
            (5.0, RiskLevel.LOW),
            (45.0, RiskLevel.MEDIUM),
            (70.0, RiskLevel.HIGH),
            (95.0, RiskLevel.CRITICAL),
        ],
    )
    def test_score_maps_to_a_risk_level(self, ml_analyzer, score, expected):
        assert ml_analyzer._calculate_risk_level(score) == expected

    def test_risk_levels_are_ordered(self, ml_analyzer):
        priorities = [
            ml_analyzer._risk_level_priority(level)
            for level in (
                RiskLevel.LOW,
                RiskLevel.MEDIUM,
                RiskLevel.HIGH,
                RiskLevel.CRITICAL,
            )
        ]

        assert priorities == sorted(priorities)

    async def test_health_check_is_false_before_initialisation(self, ml_analyzer):
        assert await ml_analyzer.health_check() is False

    async def test_analysis_works_without_the_optional_ml_stack(self, ml_analyzer):
        """The deterministic pipeline must still classify when torch is absent."""
        result = await ml_analyzer.analyze_risk_indicators(
            {"flags": ["api_key", "password"], "score": 80}
        )

        assert result.risk_score >= 0
        assert result.risk_level in list(RiskLevel)
