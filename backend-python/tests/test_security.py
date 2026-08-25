"""
Tests for authentication, request signing, roles and rate limiting.
"""

import time
from datetime import timedelta

import pytest
from fastapi import HTTPException
from jose import JWTError

from app.core.security import (
    RateLimiter,
    SecurityManager,
    create_access_token,
    decode_access_token,
    hash_password,
    permissions_for_role,
    sign_extension_payload,
    verify_extension_signature,
    verify_password,
)


class TestPasswordHashing:
    def test_round_trip(self):
        hashed = hash_password("correct horse battery staple")
        assert hashed != "correct horse battery staple"
        assert verify_password("correct horse battery staple", hashed)

    def test_wrong_password_is_rejected(self):
        hashed = hash_password("correct horse battery staple")
        assert not verify_password("Tr0ub4dor&3", hashed)

    def test_same_password_hashes_differently(self):
        """A per-hash salt means identical passwords must not collide."""
        assert hash_password("same") != hash_password("same")


class TestAccessTokens:
    def test_round_trip_preserves_subject_and_role(self):
        token = create_access_token(subject="analyst@example.com", role="analyst")
        claims = decode_access_token(token)

        assert claims["sub"] == "analyst@example.com"
        assert claims["role"] == "analyst"
        assert claims["jti"]

    def test_expired_token_is_rejected(self):
        token = create_access_token(
            subject="analyst@example.com", expires_delta=timedelta(seconds=-10)
        )
        with pytest.raises(JWTError):
            decode_access_token(token)

    def test_tampered_token_is_rejected(self):
        token = create_access_token(subject="analyst@example.com")
        header, payload, signature = token.split(".")
        forged = f"{header}.{payload}.{signature[:-4]}AAAA"

        with pytest.raises(JWTError):
            decode_access_token(forged)

    def test_extra_claims_are_carried(self):
        token = create_access_token(
            subject="svc", role="admin", extra_claims={"tenant": "acme"}
        )
        assert decode_access_token(token)["tenant"] == "acme"


class TestRolePermissions:
    def test_viewer_cannot_write(self):
        permissions = permissions_for_role("viewer")
        assert permissions["read_alerts"]
        assert not permissions["update_alerts"]
        assert not permissions["export_data"]

    def test_analyst_can_triage_but_not_read_user_analytics(self):
        permissions = permissions_for_role("analyst")
        assert permissions["update_alerts"]
        assert permissions["bulk_update_alerts"]
        assert not permissions["user_analytics"]

    def test_admin_has_everything(self):
        assert all(permissions_for_role("admin").values())

    def test_unknown_role_falls_back_to_viewer(self):
        assert permissions_for_role("wizard") == permissions_for_role("viewer")

    def test_returned_map_is_a_copy(self):
        """Callers must not be able to mutate the shared role table."""
        permissions = permissions_for_role("viewer")
        permissions["admin"] = True
        assert not permissions_for_role("viewer")["admin"]


class TestExtensionSigning:
    def test_valid_signature_is_accepted(self):
        body = '{"session_id":"abc"}'
        timestamp = str(int(time.time()))
        signature = sign_extension_payload(body, timestamp)

        assert verify_extension_signature(body, timestamp, signature)

    def test_modified_body_is_rejected(self):
        timestamp = str(int(time.time()))
        signature = sign_extension_payload('{"session_id":"abc"}', timestamp)

        assert not verify_extension_signature(
            '{"session_id":"attacker"}', timestamp, signature
        )

    def test_stale_timestamp_is_rejected(self):
        """Replaying a captured request must fail once the window closes."""
        old = str(int(time.time()) - 4000)
        signature = sign_extension_payload("{}", old)

        assert not verify_extension_signature("{}", old, signature)

    def test_non_numeric_timestamp_is_rejected(self):
        assert not verify_extension_signature("{}", "not-a-timestamp", "deadbeef")

    def test_missing_signature_is_rejected(self):
        timestamp = str(int(time.time()))
        assert not verify_extension_signature("{}", timestamp, "")


class _FakeRequest:
    """Minimal stand-in for starlette's Request in limiter tests."""

    def __init__(self, headers=None, host="10.0.0.1"):
        self.headers = headers or {}
        self.client = type("Client", (), {"host": host})()


class TestRateLimiter:
    async def test_requests_under_the_limit_pass(self):
        limiter = RateLimiter(requests_per_minute=5, burst=5)
        request = _FakeRequest()

        for _ in range(4):
            await limiter.check(request)

    async def test_exceeding_the_minute_quota_raises_429(self):
        limiter = RateLimiter(requests_per_minute=3, burst=100)
        request = _FakeRequest()

        for _ in range(3):
            await limiter.check(request)

        with pytest.raises(HTTPException) as excinfo:
            await limiter.check(request)

        assert excinfo.value.status_code == 429
        assert "Retry-After" in excinfo.value.headers

    async def test_burst_limit_is_enforced_separately(self):
        limiter = RateLimiter(requests_per_minute=1000, burst=2)
        request = _FakeRequest()

        await limiter.check(request)
        await limiter.check(request)

        with pytest.raises(HTTPException) as excinfo:
            await limiter.check(request)

        assert excinfo.value.status_code == 429

    async def test_different_clients_have_independent_budgets(self):
        limiter = RateLimiter(requests_per_minute=2, burst=100)

        first = _FakeRequest(host="10.0.0.1")
        second = _FakeRequest(host="10.0.0.2")

        await limiter.check(first)
        await limiter.check(first)
        await limiter.check(second)  # must not be blocked by `first`

    async def test_authenticated_callers_are_keyed_by_token(self):
        limiter = RateLimiter(requests_per_minute=2, burst=100)

        # Same source IP, different tokens - budgets must not be shared.
        one = _FakeRequest(headers={"authorization": "Bearer aaa"})
        two = _FakeRequest(headers={"authorization": "Bearer bbb"})

        await limiter.check(one)
        await limiter.check(one)
        await limiter.check(two)

    async def test_forwarded_for_takes_the_first_hop(self):
        limiter = RateLimiter(requests_per_minute=1, burst=100)
        request = _FakeRequest(headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1"})

        assert limiter._client_key(request) == "ip:203.0.113.7"


class TestSecurityManager:
    def test_generated_secrets_are_unique_and_long(self):
        first = SecurityManager.generate_secret()
        second = SecurityManager.generate_secret()

        assert first != second
        assert len(first) >= 32

    def test_stop_clears_the_running_flag(self):
        manager = SecurityManager()
        manager._running = True
        manager.stop()

        assert manager._running is False
