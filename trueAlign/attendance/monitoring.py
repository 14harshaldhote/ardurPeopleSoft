# attendance/monitoring.py
"""
Attendance Monitoring Utilities

Provides performance monitoring, error tracking, and health checks
for the attendance module.
"""

import time
import logging
import functools
from datetime import datetime
from typing import Callable, Any, Dict, Optional

from django.db import connection
from django.core.cache import cache
from django.conf import settings

try:
    import sentry_sdk

    SENTRY_AVAILABLE = True
except ImportError:
    SENTRY_AVAILABLE = False
    sentry_sdk = None

logger = logging.getLogger(__name__)


# Performance thresholds (in seconds)
SLOW_QUERY_THRESHOLD = 0.5
SLOW_VIEW_THRESHOLD = 1.0
SLOW_SERVICE_THRESHOLD = 2.0


class PerformanceMetrics:
    """Collect and report performance metrics."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.metrics = {}
        return cls._instance

    def record(self, name: str, duration: float, success: bool = True):
        """Record a metric."""
        if name not in self.metrics:
            self.metrics[name] = {
                "count": 0,
                "total_time": 0,
                "min_time": float("inf"),
                "max_time": 0,
                "errors": 0,
            }

        self.metrics[name]["count"] += 1
        self.metrics[name]["total_time"] += duration
        self.metrics[name]["min_time"] = min(self.metrics[name]["min_time"], duration)
        self.metrics[name]["max_time"] = max(self.metrics[name]["max_time"], duration)

        if not success:
            self.metrics[name]["errors"] += 1

    def get_summary(self) -> Dict:
        """Get metrics summary."""
        summary = {}
        for name, data in self.metrics.items():
            avg_time = data["total_time"] / data["count"] if data["count"] > 0 else 0
            summary[name] = {
                "count": data["count"],
                "avg_time_ms": round(avg_time * 1000, 2),
                "min_time_ms": (
                    round(data["min_time"] * 1000, 2) if data["min_time"] != float("inf") else 0
                ),
                "max_time_ms": round(data["max_time"] * 1000, 2),
                "error_rate": (
                    round(data["errors"] / data["count"] * 100, 2) if data["count"] > 0 else 0
                ),
            }
        return summary

    def reset(self):
        """Reset all metrics."""
        self.metrics = {}


def monitor_performance(name: str = None, threshold: float = SLOW_SERVICE_THRESHOLD):
    """Decorator to monitor function performance."""

    def decorator(func: Callable) -> Callable:
        metric_name = name or func.__name__

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            success = True

            try:
                result = func(*args, **kwargs)
                return result
            except Exception as e:
                success = False
                raise
            finally:
                duration = time.time() - start_time
                PerformanceMetrics().record(metric_name, duration, success)

                if duration > threshold:
                    logger.warning(f"Slow operation: {metric_name} took {duration:.2f}s")

        return wrapper

    return decorator


def get_health_status() -> Dict:
    """Get comprehensive health status for the attendance module."""
    status = {"status": "healthy", "timestamp": datetime.now().isoformat(), "components": {}}

    # Check database
    try:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        status["components"]["database"] = {"status": "healthy"}
    except Exception as e:
        status["components"]["database"] = {"status": "unhealthy", "error": str(e)}
        status["status"] = "degraded"

    # Check cache
    try:
        cache.set("health_check", "ok", 10)
        if cache.get("health_check") == "ok":
            status["components"]["cache"] = {"status": "healthy"}
        else:
            status["components"]["cache"] = {"status": "degraded"}
    except Exception as e:
        status["components"]["cache"] = {"status": "unhealthy", "error": str(e)}

    status["metrics"] = PerformanceMetrics().get_summary()
    return status


def init_sentry(dsn: Optional[str] = None):
    """Initialize Sentry error tracking."""
    if not SENTRY_AVAILABLE:
        logger.warning("sentry-sdk not installed")
        return

    import os

    sentry_dsn = dsn or os.environ.get("SENTRY_DSN")

    if not sentry_dsn:
        logger.info("No Sentry DSN configured")
        return

    sentry_sdk.init(
        dsn=sentry_dsn,
        traces_sample_rate=0.1,
        profiles_sample_rate=0.1,
        environment=os.environ.get("DJANGO_ENV", "development"),
    )
    logger.info("Sentry initialized")


def capture_error(error: Exception, context: Optional[Dict] = None):
    """Capture an error and send to Sentry."""
    if SENTRY_AVAILABLE and sentry_sdk:
        with sentry_sdk.push_scope() as scope:
            scope.set_tag("module", "attendance")
            if context:
                for key, value in context.items():
                    scope.set_extra(key, value)
            sentry_sdk.capture_exception(error)
    logger.exception(f"Error captured: {error}")
