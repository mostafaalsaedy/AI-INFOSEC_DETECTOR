"""
Authentication, authorisation and rate limiting.

Two independent credentials exist:

* **Extension credentials** - a shared HMAC secret used by the browser
  extension. Requests are signed, so a stolen bearer token alone is not enough
  to forge a payload.
* **API credentials** - short lived JWTs used by the dashboard and by any
  service integrating with the API.
"""

import asyncio
import hashlib
import hmac
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from app.core.config import settings
from app.core.logging import logger

bearer_scheme = HTTPBearer(auto_error=False)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# --------------------------------------------------------------------------
# Roles and permissions
# --------------------------------------------------------------------------

ROLE_PERMISSIONS: Dict[str, Dict[str, bool]] = {
    "viewer": {
        "read_alerts": True,
        "read_analytics": True,
        "update_alerts": False,
        "bulk_update_alerts": False,
        "export_data": False,
        "user_analytics": False,
        "export_pii": False,
        "admin": False,
    },
    "analyst": {
        "read_alerts": True,
        "read_analytics": True,
        "update_alerts": True,
        "bulk_update_alerts": True,
        "export_data": True,
        "user_analytics": False,
        "export_pii": False,
        "admin": False,
    },
    "admin": {
        "read_alerts": True,
        "read_analytics": True,
        "update_alerts": True,
        "bulk_update_alerts": True,
        "export_data": True,
        "user_analytics": True,
        "export_pii": True,
        "admin": True,
    },
    "extension": {
        "submit_interactions": True,
        "submit_alerts": True,
        "manage_consent": True,
    },
}


def permissions_for_role(role: str) -> Dict[str, bool]:
    """Resolve the permission map for a role, defaulting to the viewer role."""
    return dict(ROLE_PERMISSIONS.get(role, ROLE_PERMISSIONS["viewer"]))


# --------------------------------------------------------------------------
# Password and token helpers
# --------------------------------------------------------------------------


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its bcrypt hash."""
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except ValueError:
        return False


def create_access_token(
    subject: str,
    role: str = "viewer",
    expires_delta: Optional[timedelta] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Mint a signed JWT access token."""
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    claims: Dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": datetime.now(timezone.utc),
        "exp": expire,
        "jti": secrets.token_urlsafe(16),
        "iss": settings.APP_NAME,
    }
    if extra_claims:
        claims.update(extra_claims)

    return jwt.encode(claims, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT, raising ``JWTError`` when invalid."""
    return jwt.decode(
        token,
        settings.SECRET_KEY,
        algorithms=[settings.ALGORITHM],
        issuer=settings.APP_NAME,
    )


# --------------------------------------------------------------------------
# Extension request signing
# --------------------------------------------------------------------------


def sign_extension_payload(payload: str, timestamp: str) -> str:
    """Produce the HMAC-SHA256 signature the extension is expected to send."""
    message = f"{timestamp}.{payload}".encode("utf-8")
    return hmac.new(
        settings.EXTENSION_SECRET.encode("utf-8"), message, hashlib.sha256
    ).hexdigest()


def verify_extension_signature(
    payload: str, timestamp: str, signature: str, max_skew_seconds: int = 300
) -> bool:
    """Verify a signed extension payload, rejecting stale timestamps.

    The timestamp check bounds replay attacks: a captured request is only
    reusable for ``max_skew_seconds``.
    """
    try:
        sent_at = int(timestamp)
    except (TypeError, ValueError):
        return False

    if abs(int(time.time()) - sent_at) > max_skew_seconds:
        logger.warning("Rejected extension request with stale timestamp")
        return False

    expected = sign_extension_payload(payload, timestamp)
    return hmac.compare_digest(expected, signature or "")


# --------------------------------------------------------------------------
# Rate limiting
# --------------------------------------------------------------------------


class RateLimiter:
    """In-process sliding-window rate limiter.

    Suitable for a single API instance or for development. Multi-replica
    deployments should point ``REDIS_URL`` at a shared Redis and swap this for a
    distributed limiter - the FastAPI dependency signature stays the same.
    """

    def __init__(
        self,
        requests_per_minute: Optional[int] = None,
        burst: Optional[int] = None,
    ) -> None:
        self.requests_per_minute = requests_per_minute or settings.RATE_LIMIT_PER_MINUTE
        self.burst = burst or settings.RATE_LIMIT_BURST
        self._hits: Dict[str, List[float]] = {}
        self._lock = asyncio.Lock()
        self._last_sweep = time.monotonic()

    @staticmethod
    def _client_key(request: Request) -> str:
        """Identify the caller, preferring the authenticated subject."""
        auth = request.headers.get("authorization", "")
        if auth:
            return "token:" + hashlib.sha256(auth.encode()).hexdigest()[:32]

        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded:
            return "ip:" + forwarded.split(",")[0].strip()

        return "ip:" + (request.client.host if request.client else "unknown")

    def _sweep(self, now: float) -> None:
        """Drop windows that have fully expired to bound memory use."""
        if now - self._last_sweep < 60:
            return
        cutoff = now - 60
        self._hits = {
            key: kept
            for key, times in self._hits.items()
            if (kept := [t for t in times if t > cutoff])
        }
        self._last_sweep = now

    async def check(self, request: Request) -> None:
        """Raise HTTP 429 when the caller exceeded their quota."""
        key = self._client_key(request)
        now = time.monotonic()
        window_start = now - 60

        async with self._lock:
            self._sweep(now)
            timestamps = [t for t in self._hits.get(key, []) if t > window_start]

            # Burst check: no more than `burst` requests in any single second.
            recent = [t for t in timestamps if t > now - 1]
            if len(recent) >= self.burst:
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Burst rate limit exceeded, slow down",
                    headers={"Retry-After": "1"},
                )

            if len(timestamps) >= self.requests_per_minute:
                oldest = min(timestamps)
                retry_after = max(1, int(60 - (now - oldest)))
                logger.warning(f"Rate limit exceeded for {key}")
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Rate limit exceeded",
                    headers={"Retry-After": str(retry_after)},
                )

            timestamps.append(now)
            self._hits[key] = timestamps

    async def __call__(self, request: Request) -> None:
        """FastAPI dependency entry point."""
        await self.check(request)


# Shared limiter instance used as `Depends(rate_limiter)`.
rate_limiter = RateLimiter()


# --------------------------------------------------------------------------
# FastAPI authentication dependencies
# --------------------------------------------------------------------------


def _unauthorised(detail: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def verify_api_auth(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
) -> Dict[str, Any]:
    """Authenticate a dashboard/API caller from its bearer JWT.

    Returns the auth context consumed by the endpoints: ``client_id``, ``role``
    and a resolved ``permissions`` map.
    """
    if credentials is None or not credentials.credentials:
        raise _unauthorised("Missing bearer token")

    try:
        claims = decode_access_token(credentials.credentials)
    except JWTError as exc:
        logger.warning(f"Rejected API token: {exc}")
        raise _unauthorised("Invalid or expired token")

    subject = claims.get("sub")
    if not subject:
        raise _unauthorised("Token is missing a subject")

    role = claims.get("role", "viewer")
    auth_data = {
        "client_id": subject,
        "user_id": subject,
        "role": role,
        "permissions": permissions_for_role(role),
        "token_id": claims.get("jti"),
        "issued_at": claims.get("iat"),
    }

    # Expose the caller on the request so logging middleware can pick it up.
    request.state.auth = auth_data
    return auth_data


async def verify_extension_auth(request: Request) -> Dict[str, Any]:
    """Authenticate a browser-extension request.

    Requires ``X-Extension-Id``, ``X-Extension-Timestamp`` and
    ``X-Extension-Signature`` headers. The signature covers the raw request
    body, so payloads cannot be tampered with in transit.
    """
    extension_id = request.headers.get("x-extension-id")
    timestamp = request.headers.get("x-extension-timestamp")
    signature = request.headers.get("x-extension-signature")

    if not all([extension_id, timestamp, signature]):
        raise _unauthorised(
            "Extension requests must include X-Extension-Id, "
            "X-Extension-Timestamp and X-Extension-Signature"
        )

    body = await request.body()
    if not verify_extension_signature(body.decode("utf-8"), timestamp, signature):
        logger.warning(f"Invalid extension signature from {extension_id}")
        raise _unauthorised("Invalid extension signature")

    auth_data = {
        "client_id": extension_id,
        "extension_id": extension_id,
        "role": "extension",
        "permissions": permissions_for_role("extension"),
        "extension_version": request.headers.get("x-extension-version"),
    }
    request.state.auth = auth_data
    return auth_data


def require_permission(permission: str):
    """Build a dependency that enforces a single named permission."""

    async def _dependency(
        auth_data: Dict[str, Any] = Depends(verify_api_auth),
    ) -> Dict[str, Any]:
        if not auth_data.get("permissions", {}).get(permission, False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Missing required permission: {permission}",
            )
        return auth_data

    return _dependency


# --------------------------------------------------------------------------
# Background security housekeeping
# --------------------------------------------------------------------------


class SecurityManager:
    """Owns the periodic security and retention housekeeping tasks."""

    def __init__(self, cleanup_interval_hours: int = 24) -> None:
        self.cleanup_interval_hours = cleanup_interval_hours
        self._running = False

    async def cleanup_old_data(self) -> None:
        """Enforce the data-retention policy on a fixed interval.

        Runs forever as a background task; a failure in one pass is logged and
        retried after a short backoff rather than killing the loop.
        """
        self._running = True
        # Imported lazily: `app.core.database` imports config/logging, and this
        # avoids a circular import at module load time.
        from app.core.database import cleanup_old_data as purge_expired_records

        while self._running:
            try:
                await purge_expired_records()
                await asyncio.sleep(self.cleanup_interval_hours * 3600)
            except asyncio.CancelledError:
                self._running = False
                raise
            except Exception as exc:
                logger.error(f"Retention cleanup pass failed: {exc}", exc_info=True)
                await asyncio.sleep(300)

    def stop(self) -> None:
        """Signal the housekeeping loop to exit after its current sleep."""
        self._running = False

    @staticmethod
    def generate_secret(length: int = 48) -> str:
        """Generate a URL-safe secret suitable for SECRET_KEY or salts."""
        return secrets.token_urlsafe(length)
