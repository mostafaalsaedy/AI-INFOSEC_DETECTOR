"""
Celery Configuration for Async Task Processing
High-performance background task processing with Redis/RabbitMQ
"""

import asyncio

from celery import Celery, Task
from celery.schedules import crontab
from kombu import Queue

from app.core.config import settings
from app.core.logging import logger
from app.core.timeutils import utcnow

# Create Celery app
celery_app = Celery(
    "infosec_ai_monitor",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.services.celery_tasks.ml_tasks",
        "app.services.celery_tasks.notification_tasks",
        "app.services.celery_tasks.privacy_tasks",
        "app.services.celery_tasks.analytics_tasks",
    ],
)


# Celery configuration
celery_app.conf.update(
    # Task settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Task routing
    task_routes={
        "app.services.celery_tasks.ml_tasks.*": {"queue": "ml_processing"},
        "app.services.celery_tasks.notification_tasks.*": {"queue": "notifications"},
        "app.services.celery_tasks.privacy_tasks.*": {"queue": "privacy"},
        "app.services.celery_tasks.analytics_tasks.*": {"queue": "analytics"},
    },
    # Queue configuration
    task_default_queue="default",
    task_queues=(
        Queue("default", routing_key="default"),
        Queue("ml_processing", routing_key="ml_processing"),
        Queue("notifications", routing_key="notifications"),
        Queue("privacy", routing_key="privacy"),
        Queue("analytics", routing_key="analytics"),
        Queue("high_priority", routing_key="high_priority"),
    ),
    # Worker configuration
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=1000,
    # Task execution settings
    task_soft_time_limit=300,  # 5 minutes
    task_time_limit=600,  # 10 minutes
    task_track_started=True,
    task_reject_on_worker_lost=True,
    # Result backend settings
    result_expires=3600,  # 1 hour
    result_persistent=True,
    # Beat schedule for periodic tasks
    beat_schedule={
        # ML model retraining
        "retrain-ml-models": {
            "task": "app.services.celery_tasks.ml_tasks.retrain_models",
            "schedule": crontab(hour=2, minute=0),  # Daily at 2 AM
        },
        # Privacy compliance tasks
        "cleanup-expired-consents": {
            "task": "app.services.celery_tasks.privacy_tasks.cleanup_expired_consents",
            "schedule": crontab(hour=1, minute=0),  # Daily at 1 AM
        },
        "data-retention-cleanup": {
            "task": "app.services.celery_tasks.privacy_tasks.data_retention_cleanup",
            "schedule": crontab(hour=3, minute=0),  # Daily at 3 AM
        },
        # Analytics and reporting
        "generate-daily-reports": {
            "task": "app.services.celery_tasks.analytics_tasks.generate_daily_reports",
            "schedule": crontab(hour=6, minute=0),  # Daily at 6 AM
        },
        # System maintenance
        "health-check-alerts": {
            "task": "app.services.celery_tasks.system_tasks.system_health_check",
            "schedule": crontab(minute="*/15"),  # Every 15 minutes
        },
        # Weekly privacy reports
        "weekly-privacy-report": {
            "task": "app.services.celery_tasks.privacy_tasks.generate_weekly_privacy_report",
            "schedule": crontab(hour=5, minute=0, day_of_week=1),  # Monday at 5 AM
        },
    },
    beat_schedule_filename="celerybeat-schedule",
)


# Custom Task base class for async support
class AsyncTask(Task):
    """Custom task class with async support"""

    def __call__(self, *args, **kwargs):
        """Execute task with proper async handling"""
        try:
            # Check if we're in an async context
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # Create new event loop for task execution
                new_loop = asyncio.new_event_loop()
                asyncio.set_event_loop(new_loop)
                try:
                    return new_loop.run_until_complete(self.run(*args, **kwargs))
                finally:
                    new_loop.close()
            else:
                return loop.run_until_complete(self.run(*args, **kwargs))
        except Exception as e:
            logger.error(f"Task execution failed: {str(e)}", exc_info=True)
            raise

    async def run(self, *args, **kwargs):
        """Override this method in async tasks"""
        raise NotImplementedError("Async tasks must implement run() method")


# Configure Celery to use custom task class
celery_app.Task = AsyncTask


# Task monitoring and error handling
@celery_app.task(bind=True)
def debug_task(self):
    """Debug task for testing Celery setup"""
    logger.info(f"Request: {self.request!r}")
    return {"status": "success", "worker": self.request.hostname}


# Celery signals for monitoring
@celery_app.task(bind=True, base=AsyncTask)
async def async_debug_task(self):
    """Async debug task"""
    logger.info("Executing async debug task")
    await asyncio.sleep(1)
    return {"status": "async_success", "timestamp": utcnow().isoformat()}


# Error handling
@celery_app.task(
    bind=True,
    autoretry_for=(Exception,),
    retry_kwargs={"max_retries": 3, "countdown": 60},
)
def example_retry_task(self, data):
    """Example task with retry logic"""
    try:
        # Simulate processing
        if not data.get("valid"):
            raise ValueError("Invalid data provided")

        return {"processed": True, "data": data}

    except Exception as exc:
        logger.error(f"Task failed: {exc}")
        raise self.retry(exc=exc)


# Task monitoring functions
def get_task_stats():
    """Get Celery task statistics"""
    inspect = celery_app.control.inspect()

    stats = {
        "active_tasks": inspect.active(),
        "scheduled_tasks": inspect.scheduled(),
        "reserved_tasks": inspect.reserved(),
        "registered_tasks": inspect.registered(),
        "worker_stats": inspect.stats(),
    }

    return stats


def get_queue_lengths():
    """Get queue length information"""
    inspect = celery_app.control.inspect()
    return inspect.reserved()


# Task result utilities
def get_task_result(task_id: str):
    """Get task result by ID"""
    result = celery_app.AsyncResult(task_id)

    return {
        "task_id": task_id,
        "status": result.status,
        "result": result.result if result.successful() else None,
        "error": str(result.result) if result.failed() else None,
        "traceback": result.traceback,
        "date_done": result.date_done,
    }


# Task cleanup utilities
def purge_all_tasks():
    """Purge all tasks from queues (use with caution)"""
    celery_app.control.purge()
    logger.warning("All tasks purged from queues")


def revoke_task(task_id: str, terminate: bool = False):
    """Revoke a specific task"""
    celery_app.control.revoke(task_id, terminate=terminate)
    logger.info(f"Task {task_id} revoked (terminate={terminate})")


# Health check function
@celery_app.task(bind=True)
def celery_health_check(self):
    """Health check task for monitoring"""
    try:
        from app.core.database import get_db_session

        # Test database connectivity
        async def test_db():
            async with get_db_session() as db:
                await db.execute("SELECT 1")
                return True

        # Run async test
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            db_healthy = loop.run_until_complete(test_db())
        finally:
            loop.close()

        # Test Redis connectivity
        redis_healthy = True
        try:
            from redis import Redis

            r = Redis.from_url(settings.REDIS_URL)
            r.ping()
        except Exception:
            redis_healthy = False

        health_status = {
            "timestamp": utcnow().isoformat(),
            "worker_id": self.request.hostname,
            "database": "healthy" if db_healthy else "unhealthy",
            "redis": "healthy" if redis_healthy else "unhealthy",
            "overall": "healthy" if (db_healthy and redis_healthy) else "unhealthy",
        }

        return health_status

    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return {
            "timestamp": utcnow().isoformat(),
            "worker_id": (
                self.request.hostname if hasattr(self, "request") else "unknown"
            ),
            "status": "error",
            "error": str(e),
        }


# Configuration validation
def validate_celery_config():
    """Validate Celery configuration"""
    issues = []

    # Check broker connectivity
    try:
        celery_app.control.inspect().ping()
    except Exception as e:
        issues.append(f"Broker connection failed: {e}")

    # Check result backend
    try:
        # Raises when the result backend is not configured or unreachable.
        celery_app.AsyncResult("test")
    except Exception as e:
        issues.append(f"Result backend issue: {e}")

    # Check required queues
    required_queues = [
        "default",
        "ml_processing",
        "notifications",
        "privacy",
        "analytics",
    ]
    # Every queue a task routes to must be declared, or those tasks are
    # published to a queue no worker consumes and silently never run.
    declared_queues = {queue.name for queue in celery_app.conf.task_queues or ()}
    for queue_name in required_queues:
        if queue_name not in declared_queues:
            issues.append(f"Queue '{queue_name}' is not declared in task_queues")

    routed_queues = {
        route["queue"]
        for route in (celery_app.conf.task_routes or {}).values()
        if isinstance(route, dict) and "queue" in route
    }
    for queue_name in routed_queues - declared_queues:
        issues.append(f"Tasks route to undeclared queue '{queue_name}'")

    return {
        "valid": len(issues) == 0,
        "issues": issues,
        "broker_url": settings.CELERY_BROKER_URL,
        "result_backend": settings.CELERY_RESULT_BACKEND,
    }


if __name__ == "__main__":
    # CLI interface for Celery management
    import sys

    if len(sys.argv) > 1:
        command = sys.argv[1]

        if command == "validate":
            config = validate_celery_config()
            print(f"Configuration valid: {config['valid']}")
            if config["issues"]:
                print("Issues found:")
                for issue in config["issues"]:
                    print(f"  - {issue}")

        elif command == "stats":
            stats = get_task_stats()
            print("Celery Task Statistics:")
            for key, value in stats.items():
                print(f"  {key}: {value}")

        elif command == "health":
            health = celery_health_check.delay()
            result = health.get(timeout=30)
            print(f"Health Check Result: {result}")

        else:
            print(f"Unknown command: {command}")
            print("Available commands: validate, stats, health")
    else:
        print("Celery app configured successfully")
        print(f"Broker: {settings.CELERY_BROKER_URL}")
        print(f"Backend: {settings.CELERY_RESULT_BACKEND}")
        print("Use 'celery -A app.services.celery_app worker' to start worker")
