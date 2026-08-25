"""
API v1 router.

Aggregates every v1 endpoint module behind a single router that `app.main`
mounts at `/api/v1`.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import alerts, analytics, data_collection

api_router = APIRouter()

# Extension-facing collection endpoints (/api/v1/collect, /alert, /consent...)
api_router.include_router(
    data_collection.router,
    tags=["Data Collection"],
)

# Alert triage and management (/api/v1/alerts/...)
api_router.include_router(
    alerts.router,
    prefix="/alerts",
    tags=["Alerts"],
)

# Reporting and analytics (/api/v1/analytics/...)
api_router.include_router(
    analytics.router,
    prefix="/analytics",
    tags=["Analytics"],
)

__all__ = ["api_router"]
