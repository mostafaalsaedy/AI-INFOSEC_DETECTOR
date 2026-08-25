"""
HTTP-level tests: routing, authentication, validation and response shapes.

These drive the real ASGI app through httpx, so they cover the dependency
wiring (auth, rate limiting, database session) as well as the handlers.
"""

import json
import time

from app.core.database import AlertStatus, RiskLevel
from app.core.security import create_access_token


class TestPublicEndpoints:
    async def test_root_describes_the_service(self, client):
        response = await client.get("/")

        assert response.status_code == 200
        body = response.json()
        assert body["service"] == "InfoSec AI Monitor API"
        assert "features" in body

    async def test_unknown_path_returns_404(self, client):
        assert (await client.get("/no-such-endpoint")).status_code == 404

    async def test_wrong_method_returns_405(self, client):
        assert (await client.delete("/")).status_code == 405


class TestAlertAuthentication:
    async def test_missing_token_is_rejected(self, client):
        response = await client.get("/api/v1/alerts/")

        assert response.status_code == 401
        assert "WWW-Authenticate" in response.headers

    async def test_garbage_token_is_rejected(self, client):
        response = await client.get(
            "/api/v1/alerts/", headers={"Authorization": "Bearer not-a-jwt"}
        )

        assert response.status_code == 401

    async def test_expired_token_is_rejected(self, client):
        from datetime import timedelta

        token = create_access_token("x@example.com", expires_delta=timedelta(seconds=-5))
        response = await client.get(
            "/api/v1/alerts/", headers={"Authorization": f"Bearer {token}"}
        )

        assert response.status_code == 401

    async def test_valid_token_is_accepted(self, client, auth_headers):
        response = await client.get("/api/v1/alerts/", headers=auth_headers)

        assert response.status_code == 200


class TestAlertEndpoints:
    async def test_list_returns_the_documented_shape(
        self, client, auth_headers, make_alert
    ):
        await make_alert(title="Leaked key")

        response = await client.get("/api/v1/alerts/", headers=auth_headers)
        body = response.json()

        assert response.status_code == 200
        assert set(body) == {"alerts", "pagination", "filters_applied", "total_count"}
        assert body["total_count"] == 1

    async def test_pagination_parameters_are_validated(self, client, auth_headers):
        response = await client.get("/api/v1/alerts/?per_page=5000", headers=auth_headers)

        assert response.status_code == 422

    async def test_severity_filter_is_applied(self, client, auth_headers, make_alert):
        await make_alert(severity=RiskLevel.CRITICAL)
        await make_alert(severity=RiskLevel.LOW)

        response = await client.get(
            "/api/v1/alerts/?severity=critical", headers=auth_headers
        )

        assert response.json()["total_count"] == 1

    async def test_invalid_severity_is_rejected(self, client, auth_headers):
        response = await client.get(
            "/api/v1/alerts/?severity=catastrophic", headers=auth_headers
        )

        assert response.status_code == 422

    async def test_detail_returns_the_alert(self, client, auth_headers, make_alert):
        alert = await make_alert(title="Leaked key")

        response = await client.get(f"/api/v1/alerts/{alert.id}", headers=auth_headers)

        assert response.status_code == 200
        assert response.json()["title"] == "Leaked key"

    async def test_detail_of_a_missing_alert_returns_404(self, client, auth_headers):
        response = await client.get("/api/v1/alerts/999999", headers=auth_headers)

        assert response.status_code == 404

    async def test_statistics_endpoint_aggregates(self, client, auth_headers, make_alert):
        await make_alert(severity=RiskLevel.HIGH)

        response = await client.get("/api/v1/alerts/stats", headers=auth_headers)
        body = response.json()

        assert response.status_code == 200
        assert body["total_alerts"] == 1
        assert "resolution_metrics" in body

    async def test_export_requires_the_export_permission(
        self, client, viewer_token, make_alert
    ):
        await make_alert()

        response = await client.get(
            "/api/v1/alerts/export?format=csv",
            headers={"Authorization": f"Bearer {viewer_token}"},
        )

        assert response.status_code == 403

    async def test_analyst_may_export(self, client, auth_headers, make_alert):
        await make_alert()

        response = await client.get(
            "/api/v1/alerts/export?format=json", headers=auth_headers
        )

        assert response.status_code == 200
        assert response.json()["record_count"] == 1

    async def test_bulk_action_rejects_an_unknown_action(
        self, client, auth_headers, make_alert
    ):
        alert = await make_alert()

        response = await client.post(
            "/api/v1/alerts/bulk-action",
            headers=auth_headers,
            json={"alert_ids": [alert.id], "action": "detonate"},
        )

        assert response.status_code == 422

    async def test_bulk_action_requires_at_least_one_id(self, client, auth_headers):
        response = await client.post(
            "/api/v1/alerts/bulk-action",
            headers=auth_headers,
            json={"alert_ids": [], "action": "resolve"},
        )

        assert response.status_code == 422

    async def test_bulk_resolve_updates_the_alerts(
        self, client, auth_headers, make_alert
    ):
        alerts = [await make_alert(status=AlertStatus.OPEN) for _ in range(2)]

        response = await client.post(
            "/api/v1/alerts/bulk-action",
            headers=auth_headers,
            json={"alert_ids": [a.id for a in alerts], "action": "resolve"},
        )
        body = response.json()

        assert response.status_code == 200
        assert body["processed_count"] == 2
        assert body["failed_count"] == 0


class TestAnalyticsEndpoints:
    async def test_risk_analytics_returns_the_documented_shape(
        self, client, auth_headers, make_interaction
    ):
        await make_interaction(risk_level=RiskLevel.HIGH, risk_score=80)

        response = await client.get("/api/v1/analytics/risk", headers=auth_headers)
        body = response.json()

        assert response.status_code == 200
        assert body["total_interactions"] == 1
        assert set(body) == {
            "total_interactions",
            "risk_distribution",
            "platform_breakdown",
            "trend_data",
            "top_risk_patterns",
            "summary_stats",
        }

    async def test_platform_analytics_responds(
        self, client, auth_headers, make_interaction
    ):
        await make_interaction(platform="claude")

        response = await client.get("/api/v1/analytics/platforms", headers=auth_headers)

        assert response.status_code == 200
        assert response.json()["total_usage"]["claude"] == 1

    async def test_alert_analytics_responds(self, client, auth_headers, make_alert):
        await make_alert()

        response = await client.get("/api/v1/analytics/alerts", headers=auth_headers)

        assert response.status_code == 200
        assert response.json()["total_alerts"] == 1

    async def test_dashboard_summary_responds(self, client, auth_headers):
        response = await client.get("/api/v1/analytics/dashboard", headers=auth_headers)

        assert response.status_code == 200
        assert "kpis" in response.json()

    async def test_user_analytics_requires_elevated_permission(
        self, client, auth_headers
    ):
        """An analyst must not be able to profile an individual user."""
        response = await client.get(
            "/api/v1/analytics/users/target", headers=auth_headers
        )

        assert response.status_code == 403

    async def test_admin_may_read_user_analytics(
        self, client, admin_headers, make_interaction
    ):
        await make_interaction(user_id="target")

        response = await client.get(
            "/api/v1/analytics/users/target", headers=admin_headers
        )

        assert response.status_code == 200
        assert response.json()["total_interactions"] == 1

    async def test_trend_endpoint_rejects_an_unknown_metric(self, client, auth_headers):
        response = await client.get(
            "/api/v1/analytics/trends?metric=vibes", headers=auth_headers
        )

        assert response.status_code == 500

    async def test_trend_endpoint_returns_a_series(
        self, client, auth_headers, make_interaction
    ):
        await make_interaction()

        response = await client.get(
            "/api/v1/analytics/trends?metric=interactions", headers=auth_headers
        )

        assert response.status_code == 200
        assert response.json()["metric"] == "interactions"

    async def test_pii_export_requires_permission(self, client, auth_headers):
        response = await client.post(
            "/api/v1/analytics/export",
            headers=auth_headers,
            json={"export_type": "alerts", "format": "json", "include_pii": True},
        )

        assert response.status_code == 403

    async def test_export_type_is_validated(self, client, auth_headers):
        response = await client.post(
            "/api/v1/analytics/export",
            headers=auth_headers,
            json={"export_type": "everything", "format": "json"},
        )

        assert response.status_code == 422


class TestExtensionEndpoints:
    async def test_unsigned_request_is_rejected(self, client, sample_interaction_payload):
        response = await client.post("/api/v1/collect", json=sample_interaction_payload)

        assert response.status_code == 401

    async def test_bad_signature_is_rejected(self, client, sample_interaction_payload):
        body = json.dumps(sample_interaction_payload)
        headers = {
            "X-Extension-Id": "test-extension",
            "X-Extension-Timestamp": str(int(time.time())),
            "X-Extension-Signature": "0" * 64,
            "Content-Type": "application/json",
        }

        response = await client.post("/api/v1/collect", content=body, headers=headers)

        assert response.status_code == 401

    async def test_stale_timestamp_is_rejected(
        self, client, sample_interaction_payload, sign_extension_request
    ):
        from app.core.security import sign_extension_payload

        body = json.dumps(sample_interaction_payload)
        stale = str(int(time.time()) - 5000)
        headers = {
            "X-Extension-Id": "test-extension",
            "X-Extension-Timestamp": stale,
            "X-Extension-Signature": sign_extension_payload(body, stale),
            "Content-Type": "application/json",
        }

        response = await client.post("/api/v1/collect", content=body, headers=headers)

        assert response.status_code == 401

    async def test_health_endpoint_is_reachable(self, client):
        response = await client.get("/api/v1/health")

        # Degrades to 503 when the ML analyzer has not been initialised, which
        # is the case here because the lifespan does not run under test.
        assert response.status_code in (200, 503)


class TestErrorHandling:
    async def test_malformed_json_is_a_422(self, client, auth_headers):
        response = await client.post(
            "/api/v1/alerts/bulk-action",
            headers={**auth_headers, "Content-Type": "application/json"},
            content="{not json",
        )

        assert response.status_code == 422

    async def test_error_responses_are_json(self, client):
        response = await client.get("/api/v1/alerts/")

        assert response.headers["content-type"].startswith("application/json")
        assert "error" in response.json() or "detail" in response.json()
