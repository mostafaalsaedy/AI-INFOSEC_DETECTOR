"""
InfoSec AI Monitor - FastAPI Backend
Main application entry point with advanced AI/ML capabilities
"""

import asyncio
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import List

import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import JSONResponse
from prometheus_client import make_asgi_app
from sqlalchemy import text

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.database import engine, get_db_session, init_db
from app.core.docs import API_TAGS_METADATA, custom_openapi
from app.core.logging import logger, setup_logging
from app.core.security import SecurityManager
from app.services.celery_app import celery_app
from app.services.ml_service import MLRiskAnalyzer
from app.services.websocket_manager import WebSocketManager

# Global instances
websocket_manager = WebSocketManager()
ml_analyzer = MLRiskAnalyzer()
security_manager = SecurityManager()


# Background tasks are tracked so shutdown can cancel them deterministically
# rather than leaving orphaned coroutines behind.
background_tasks: List[asyncio.Task] = []


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    logger.info("Starting InfoSec AI Monitor API...")

    setup_logging()

    # Initialize database
    await init_db()

    # Initialize ML models
    await ml_analyzer.initialize()

    # Start background tasks
    background_tasks.extend(
        [
            asyncio.create_task(
                security_manager.cleanup_old_data(), name="retention-cleanup"
            ),
            asyncio.create_task(ml_analyzer.periodic_retraining(), name="ml-retraining"),
            asyncio.create_task(monitor_system_health(), name="health-monitor"),
            asyncio.create_task(
                websocket_manager.start_background_tasks(), name="ws-heartbeat"
            ),
        ]
    )
    logger.info(f"Started {len(background_tasks)} background tasks")

    logger.info("Application startup complete")

    yield

    # Shutdown
    logger.info("Shutting down application...")

    security_manager.stop()
    for task in background_tasks:
        task.cancel()
    await asyncio.gather(*background_tasks, return_exceptions=True)
    background_tasks.clear()

    await websocket_manager.shutdown()
    await ml_analyzer.cleanup()
    await engine.dispose()

    logger.info("Application shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="InfoSec AI Monitor API",
    description="Advanced AI platform monitoring with ML-powered security analysis",
    version="1.0.0",
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
    openapi_tags=API_TAGS_METADATA,
    lifespan=lifespan,
)

# Set custom OpenAPI schema
app.openapi = lambda: custom_openapi(app)

# Security middleware
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.ALLOWED_HOSTS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
)

# Add Prometheus metrics
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Include API routers
app.include_router(api_router, prefix="/api/v1")


@app.get("/")
async def root():
    """Root endpoint with system information"""
    return {
        "service": "InfoSec AI Monitor API",
        "version": "1.0.0",
        "status": "healthy",
        "features": [
            "Real-time AI monitoring",
            "ML-powered risk analysis",
            "GDPR compliant data handling",
            "WebSocket real-time updates",
            "Advanced security alerts",
        ],
    }


@app.get("/health")
async def health_check():
    """Comprehensive health check"""
    try:
        # Check database
        async with get_db_session() as db:
            await db.execute(text("SELECT 1"))

        # Check ML service
        ml_status = await ml_analyzer.health_check()

        # Celery lives in a separate process; a broker outage must not block the
        # health endpoint, so the ping runs off the event loop with a timeout.
        try:
            celery_status = await asyncio.wait_for(
                asyncio.to_thread(lambda: celery_app.control.inspect().ping()),
                timeout=3.0,
            )
        except Exception as exc:  # includes asyncio.TimeoutError and broker errors
            logger.warning(f"Celery health probe failed: {exc}")
            celery_status = None

        return {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "services": {
                "database": "healthy",
                "ml_analyzer": "healthy" if ml_status else "degraded",
                "celery": "healthy" if celery_status else "degraded",
                "websocket": "healthy",
            },
            "version": "1.0.0",
        }

    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )


@app.websocket("/ws/monitor")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time monitoring"""
    connection_id = await websocket_manager.connect(websocket)

    try:
        while True:
            data = await websocket.receive_text()

            if data == "ping":
                await websocket.send_text("pong")
                continue

            # Anything else is treated as a JSON command (subscribe, filter...)
            try:
                message = json.loads(data)
            except json.JSONDecodeError:
                await websocket.send_json({"error": "Expected a JSON message or 'ping'"})
                continue

            await websocket_manager.handle_client_message(connection_id, message)

    except WebSocketDisconnect:
        logger.info(f"WebSocket {connection_id} disconnected")
    except Exception as e:
        logger.error(f"WebSocket error on {connection_id}: {str(e)}")
    finally:
        websocket_manager.disconnect(connection_id)


@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    """Custom HTTP exception handler.

    `exc.headers` is forwarded because it carries protocol-significant values -
    `WWW-Authenticate` on a 401 and `Retry-After` on a 429 - which clients rely
    on to know how to recover.
    """
    logger.warning(f"HTTP {exc.status_code}: {exc.detail}")
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc):
    """General exception handler"""
    logger.error(f"Unhandled exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "status_code": 500,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
    )


async def monitor_system_health():
    """Background task to monitor system health"""
    while True:
        try:
            await asyncio.sleep(300)  # Check every 5 minutes

            # Perform health checks
            health_status = await health_check()

            # Alert if any service is unhealthy
            if any(
                status != "healthy"
                for status in health_status.get("services", {}).values()
            ):
                await websocket_manager.broadcast_system_alert(
                    {
                        "type": "system_health_alert",
                        "status": health_status,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )

        except Exception as e:
            logger.error(f"System health monitoring error: {str(e)}")
            await asyncio.sleep(60)  # Wait 1 minute before retrying


if __name__ == "__main__":
    # Setup logging
    setup_logging()

    # Run application
    uvicorn.run(
        "app.main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG,
        log_config=None,  # Use our custom logging
        access_log=False,  # We handle access logging separately
    )
