"""
Tests for AlertService: filtering, pagination, triage transitions, bulk
actions, statistics and exports.
"""

import csv
import io
import json
from datetime import timedelta

import pytest

from app.core.database import AlertStatus, RiskLevel
from app.core.timeutils import utcnow
from app.services.alert_service import AlertService


@pytest.fixture
def service() -> AlertService:
    return AlertService()


class TestListAlerts:
    async def test_returns_pagination_metadata(self, service, db_session, make_alert):
        for index in range(5):
            await make_alert(title=f"Alert {index}")

        result = await service.list_alerts(db_session, page=1, per_page=2)

        assert result["total_count"] == 5
        assert len(result["alerts"]) == 2
        assert result["pagination"] == {
            "page": 1,
            "per_page": 2,
            "total_pages": 3,
            "total_items": 5,
        }

    async def test_second_page_returns_the_remainder(
        self, service, db_session, make_alert
    ):
        for index in range(5):
            await make_alert(title=f"Alert {index}")

        result = await service.list_alerts(db_session, page=3, per_page=2)

        assert len(result["alerts"]) == 1

    async def test_filters_by_severity(self, service, db_session, make_alert):
        await make_alert(severity=RiskLevel.CRITICAL)
        await make_alert(severity=RiskLevel.LOW)

        result = await service.list_alerts(db_session, filters={"severity": "critical"})

        assert result["total_count"] == 1
        assert result["alerts"][0]["severity"] == "critical"

    async def test_filters_by_api_status_name(self, service, db_session, make_alert):
        """The API says 'acknowledged'; storage says INVESTIGATING."""
        await make_alert(status=AlertStatus.INVESTIGATING)
        await make_alert(status=AlertStatus.OPEN)

        result = await service.list_alerts(db_session, filters={"status": "acknowledged"})

        assert result["total_count"] == 1
        assert result["alerts"][0]["status"] == "acknowledged"

    async def test_filters_by_platform_via_the_related_interaction(
        self, service, db_session, make_alert, make_interaction
    ):
        chatgpt = await make_interaction(platform="chatgpt")
        claude = await make_interaction(platform="claude", session_id="test-session-1")
        await make_alert(interaction_id=chatgpt.id)
        await make_alert(interaction_id=claude.id)

        result = await service.list_alerts(db_session, filters={"platform": "claude"})

        assert result["total_count"] == 1
        assert result["alerts"][0]["platform"] == "claude"

    async def test_search_matches_title_and_description(
        self, service, db_session, make_alert
    ):
        await make_alert(title="Credit card in prompt")
        await make_alert(title="Unrelated", description="mentions credit card")
        await make_alert(title="Nothing relevant", description="clean")

        result = await service.list_alerts(db_session, filters={"search": "credit card"})

        assert result["total_count"] == 2

    async def test_sort_created_asc_reverses_the_order(
        self, service, db_session, make_alert
    ):
        older = await make_alert(title="older", created_at=utcnow() - timedelta(days=2))
        newer = await make_alert(title="newer")

        ascending = await service.list_alerts(db_session, sort="created_asc")
        descending = await service.list_alerts(db_session, sort="created_desc")

        assert ascending["alerts"][0]["id"] == older.id
        assert descending["alerts"][0]["id"] == newer.id

    async def test_empty_result_is_well_formed(self, service, db_session):
        result = await service.list_alerts(db_session)

        assert result["total_count"] == 0
        assert result["alerts"] == []
        assert result["pagination"]["total_pages"] == 0


class TestAlertDetails:
    async def test_includes_evidence_and_related_interaction(
        self, service, db_session, make_alert, make_interaction
    ):
        interaction = await make_interaction(platform="claude", risk_score=71.5)
        alert = await make_alert(
            interaction_id=interaction.id, evidence={"pattern": "api_key"}
        )

        details = await service.get_alert_details(db_session, alert.id)

        assert details["evidence"] == {"pattern": "api_key"}
        assert details["platform"] == "claude"
        assert details["risk_score"] == 71.5
        assert details["related_interactions"] == [interaction.id]

    async def test_missing_alert_returns_none(self, service, db_session):
        assert await service.get_alert_details(db_session, 999_999) is None


class TestPermissions:
    async def test_analyst_may_update_any_alert(self, service, db_session, make_alert):
        alert = await make_alert(assigned_to="someone-else")

        assert await service.can_update_alert(
            db_session, alert.id, "me", {"update_alerts": True}
        )

    async def test_viewer_may_only_update_their_own_alerts(
        self, service, db_session, make_alert
    ):
        mine = await make_alert(assigned_to="me")
        theirs = await make_alert(assigned_to="someone-else")

        assert await service.can_update_alert(db_session, mine.id, "me", {})
        assert not await service.can_update_alert(db_session, theirs.id, "me", {})

    async def test_unassigned_alert_is_not_updatable_by_a_viewer(
        self, service, db_session, make_alert
    ):
        alert = await make_alert(assigned_to=None)

        assert not await service.can_update_alert(db_session, alert.id, "me", {})


class TestUpdateAlert:
    async def test_status_change_records_the_previous_status(
        self, service, db_session, make_alert
    ):
        alert = await make_alert(status=AlertStatus.OPEN)

        updated = await service.update_alert(
            db_session, alert.id, {"status": "resolved"}, updated_by="analyst"
        )

        assert updated["previous_status"] == "active"
        assert updated["status"] == "resolved"

    async def test_resolving_stamps_the_resolver(self, service, db_session, make_alert):
        alert = await make_alert(status=AlertStatus.OPEN)

        updated = await service.update_alert(
            db_session, alert.id, {"status": "resolved"}, updated_by="analyst"
        )

        assert updated["resolved_by"] == "analyst"
        assert updated["resolved_at"] is not None

    async def test_reopening_clears_the_resolution_stamp(
        self, service, db_session, make_alert
    ):
        alert = await make_alert(status=AlertStatus.RESOLVED)

        updated = await service.update_alert(
            db_session, alert.id, {"status": "active"}, updated_by="analyst"
        )

        assert updated["resolved_at"] is None
        assert updated["resolved_by"] is None

    async def test_partial_update_leaves_other_fields_alone(
        self, service, db_session, make_alert
    ):
        alert = await make_alert(assigned_to="original", priority=3)

        updated = await service.update_alert(
            db_session, alert.id, {"priority": 9}, updated_by="analyst"
        )

        assert updated["priority"] == 9
        assert updated["assigned_to"] == "original"

    async def test_missing_alert_returns_none(self, service, db_session):
        assert await service.update_alert(db_session, 999_999, {"priority": 1}) is None


class TestBulkActions:
    async def test_admin_is_permitted_for_everything(
        self, service, db_session, make_alert
    ):
        alerts = [await make_alert() for _ in range(3)]
        ids = [alert.id for alert in alerts]

        check = await service.validate_bulk_permissions(
            db_session, ids, "resolve", {"admin": True}, "admin"
        )

        assert check["all_permitted"]
        assert check["denied"] == []

    async def test_viewer_is_denied_alerts_they_do_not_own(
        self, service, db_session, make_alert
    ):
        mine = await make_alert(assigned_to="me")
        theirs = await make_alert(assigned_to="them")

        check = await service.validate_bulk_permissions(
            db_session, [mine.id, theirs.id], "resolve", {}, "me"
        )

        assert not check["all_permitted"]
        assert check["denied"] == [theirs.id]

    async def test_resolve_applies_to_every_existing_alert(
        self, service, db_session, make_alert
    ):
        alerts = [await make_alert(status=AlertStatus.OPEN) for _ in range(3)]
        ids = [alert.id for alert in alerts]

        result = await service.bulk_update_alerts(
            db_session, ids, "resolve", updated_by="analyst"
        )

        assert result["processed_count"] == 3
        assert result["failed_count"] == 0

        refreshed = await service.list_alerts(db_session, filters={"status": "resolved"})
        assert refreshed["total_count"] == 3

    async def test_unknown_ids_are_reported_as_failures(
        self, service, db_session, make_alert
    ):
        alert = await make_alert()

        result = await service.bulk_update_alerts(
            db_session, [alert.id, 999_999], "acknowledge", updated_by="analyst"
        )

        assert result["processed_count"] == 1
        assert result["failed_count"] == 1
        assert any(detail["error"] == "Alert not found" for detail in result["details"])

    async def test_assign_requires_an_assignee(self, service, db_session, make_alert):
        alert = await make_alert()

        result = await service.bulk_update_alerts(db_session, [alert.id], "assign", {})

        assert result["processed_count"] == 0
        assert "assigned_to" in result["details"][0]["error"]

    async def test_unknown_action_is_rejected(self, service, db_session, make_alert):
        alert = await make_alert()

        result = await service.bulk_update_alerts(db_session, [alert.id], "detonate")

        assert result["processed_count"] == 0
        assert "Unknown action" in result["details"][0]["error"]


class TestStatistics:
    async def test_counts_group_by_status_and_severity(
        self, service, db_session, make_alert
    ):
        await make_alert(severity=RiskLevel.CRITICAL, status=AlertStatus.OPEN)
        await make_alert(severity=RiskLevel.CRITICAL, status=AlertStatus.RESOLVED)
        await make_alert(severity=RiskLevel.LOW, status=AlertStatus.OPEN)

        stats = await service.get_alert_statistics(db_session, time_range_days=30)

        assert stats["total_alerts"] == 3
        assert stats["by_severity"]["critical"] == 2
        assert stats["by_status"]["active"] == 2

    async def test_resolution_metrics_measure_elapsed_hours(
        self, service, db_session, make_alert
    ):
        created = utcnow() - timedelta(hours=4)
        await make_alert(
            created_at=created,
            status=AlertStatus.RESOLVED,
            resolved_at=created + timedelta(hours=2),
        )

        stats = await service.get_alert_statistics(db_session)

        assert stats["resolution_metrics"]["resolved_count"] == 1.0
        assert stats["resolution_metrics"]["mean_resolution_hours"] == pytest.approx(
            2.0, abs=0.1
        )

    async def test_false_positive_rate_is_a_percentage(
        self, service, db_session, make_alert
    ):
        await make_alert(status=AlertStatus.FALSE_POSITIVE)
        await make_alert(status=AlertStatus.OPEN)
        await make_alert(status=AlertStatus.OPEN)
        await make_alert(status=AlertStatus.OPEN)

        stats = await service.get_alert_statistics(db_session)

        assert stats["resolution_metrics"]["false_positive_rate"] == 25.0

    async def test_trends_can_be_disabled(self, service, db_session, make_alert):
        await make_alert()

        stats = await service.get_alert_statistics(db_session, include_trends=False)

        assert stats["trend_data"] == []

    async def test_alerts_outside_the_window_are_excluded(
        self, service, db_session, make_alert
    ):
        await make_alert(created_at=utcnow() - timedelta(days=90))
        await make_alert()

        stats = await service.get_alert_statistics(db_session, time_range_days=7)

        assert stats["total_alerts"] == 1

    async def test_empty_dataset_does_not_divide_by_zero(self, service, db_session):
        stats = await service.get_alert_statistics(db_session)

        assert stats["total_alerts"] == 0
        assert stats["resolution_metrics"]["resolution_rate"] == 0.0


class TestExport:
    async def test_csv_export_has_a_header_and_one_row_per_alert(
        self, service, db_session, make_alert
    ):
        await make_alert(title="First")
        await make_alert(title="Second")

        result = await service.export_alerts(db_session, format="csv")

        rows = list(csv.DictReader(io.StringIO(result["content"])))
        assert result["success"]
        assert result["record_count"] == 2
        assert len(rows) == 2
        assert "severity" in rows[0]

    async def test_json_export_parses(self, service, db_session, make_alert):
        await make_alert(title="First")

        result = await service.export_alerts(db_session, format="json")
        parsed = json.loads(result["content"])

        assert len(parsed) == 1
        assert parsed[0]["title"] == "First"

    async def test_field_selection_is_restricted_to_the_allow_list(
        self, service, db_session, make_alert
    ):
        """A caller must not be able to name an arbitrary column."""
        await make_alert()

        result = await service.export_alerts(
            db_session, format="json", fields=["id", "title", "evidence"]
        )
        parsed = json.loads(result["content"])

        assert set(parsed[0]) == {"id", "title"}

    async def test_pdf_is_refused_with_an_explanation(
        self, service, db_session, make_alert
    ):
        await make_alert()

        result = await service.export_alerts(db_session, format="pdf")

        assert not result["success"]
        assert "json" in result["error"].lower()

    async def test_date_range_narrows_the_export(self, service, db_session, make_alert):
        await make_alert(created_at=utcnow() - timedelta(days=40))
        await make_alert()

        result = await service.export_alerts(
            db_session,
            format="json",
            start_date=utcnow() - timedelta(days=7),
        )

        assert result["record_count"] == 1
