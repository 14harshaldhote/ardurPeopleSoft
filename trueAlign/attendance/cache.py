# attendance/cache.py
"""
Attendance Caching Utilities

Provides caching decorators, cache invalidation, and cache warming
for the attendance module.
"""

import functools
import hashlib
import logging
from datetime import date, timedelta
from typing import Optional, List, Callable, Any

from django.core.cache import cache
from django.conf import settings

logger = logging.getLogger(__name__)

# Cache key prefixes
CACHE_PREFIX = "attendance"
DASHBOARD_PREFIX = f"{CACHE_PREFIX}:dashboard"
REPORT_PREFIX = f"{CACHE_PREFIX}:report"
ANALYTICS_PREFIX = f"{CACHE_PREFIX}:analytics"
USER_PREFIX = f"{CACHE_PREFIX}:user"

# Default timeouts (in seconds)
DASHBOARD_TIMEOUT = 300  # 5 minutes
REPORT_TIMEOUT = 900  # 15 minutes
ANALYTICS_TIMEOUT = 600  # 10 minutes
USER_TIMEOUT = 180  # 3 minutes


def get_cache_key(*args, **kwargs) -> str:
    """Generate a consistent cache key from arguments."""
    key_parts = [str(arg) for arg in args]
    key_parts.extend(f"{k}:{v}" for k, v in sorted(kwargs.items()))
    key_string = ":".join(key_parts)

    # Use hash for long keys
    if len(key_string) > 200:
        return hashlib.md5(key_string.encode()).hexdigest()
    return key_string


def cache_dashboard(timeout: int = DASHBOARD_TIMEOUT):
    """
    Decorator to cache dashboard data.

    Usage:
        @cache_dashboard(timeout=300)
        def get_dashboard_data(user_id):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Extract user_id from args or kwargs
            user_id = kwargs.get("user_id") or (args[0] if args else "global")
            cache_key = f"{DASHBOARD_PREFIX}:{user_id}:{func.__name__}"

            # Try to get from cache
            cached_result = cache.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache HIT: {cache_key}")
                return cached_result

            # Execute function and cache result
            logger.debug(f"Cache MISS: {cache_key}")
            result = func(*args, **kwargs)
            cache.set(cache_key, result, timeout)
            return result

        return wrapper

    return decorator


def cache_report(timeout: int = REPORT_TIMEOUT):
    """
    Decorator to cache report data.

    Usage:
        @cache_report(timeout=900)
        def generate_report(start_date, end_date):
            ...
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Generate cache key from all arguments
            cache_key = f"{REPORT_PREFIX}:{func.__name__}:{get_cache_key(*args, **kwargs)}"

            cached_result = cache.get(cache_key)
            if cached_result is not None:
                logger.debug(f"Cache HIT: {cache_key}")
                return cached_result

            logger.debug(f"Cache MISS: {cache_key}")
            result = func(*args, **kwargs)
            cache.set(cache_key, result, timeout)
            return result

        return wrapper

    return decorator


def cache_analytics(timeout: int = ANALYTICS_TIMEOUT):
    """Decorator to cache analytics data."""

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = f"{ANALYTICS_PREFIX}:{func.__name__}:{get_cache_key(*args, **kwargs)}"

            cached_result = cache.get(cache_key)
            if cached_result is not None:
                return cached_result

            result = func(*args, **kwargs)
            cache.set(cache_key, result, timeout)
            return result

        return wrapper

    return decorator


def invalidate_user_cache(user_id: int) -> None:
    """
    Invalidate all cache entries for a specific user.
    Called when user's attendance data changes.
    """
    patterns = [
        f"{DASHBOARD_PREFIX}:{user_id}:*",
        f"{USER_PREFIX}:{user_id}:*",
    ]

    for pattern in patterns:
        try:
            # Use delete_pattern if available (django-redis)
            if hasattr(cache, "delete_pattern"):
                cache.delete_pattern(pattern)
                logger.info(f"Invalidated cache pattern: {pattern}")
            else:
                # Fallback: delete known keys
                cache.delete(pattern.replace("*", "dashboard"))
                cache.delete(pattern.replace("*", "summary"))
        except Exception as e:
            logger.warning(f"Cache invalidation failed for {pattern}: {e}")


def invalidate_date_cache(target_date: date) -> None:
    """
    Invalidate all cache entries for a specific date.
    Called when attendance data for a date changes.
    """
    date_str = target_date.isoformat()
    patterns = [
        f"{REPORT_PREFIX}:*:{date_str}:*",
        f"{ANALYTICS_PREFIX}:*:{date_str}:*",
    ]

    for pattern in patterns:
        try:
            if hasattr(cache, "delete_pattern"):
                cache.delete_pattern(pattern)
                logger.info(f"Invalidated cache pattern: {pattern}")
        except Exception as e:
            logger.warning(f"Cache invalidation failed for {pattern}: {e}")


def invalidate_all_attendance_cache() -> None:
    """Invalidate all attendance-related cache entries."""
    try:
        if hasattr(cache, "delete_pattern"):
            cache.delete_pattern(f"{CACHE_PREFIX}:*")
            logger.info("Invalidated all attendance cache")
        else:
            # Clear entire cache as fallback
            cache.clear()
            logger.info("Cleared entire cache (fallback)")
    except Exception as e:
        logger.error(f"Failed to invalidate all cache: {e}")


def warm_cache(user_ids: Optional[List[int]] = None) -> dict:
    """
    Pre-warm cache with commonly accessed data.

    Args:
        user_ids: Optional list of user IDs to warm cache for.
                 If None, warms for all active users.

    Returns:
        Dict with warming statistics.
    """
    from django.contrib.auth import get_user_model
    from .services.analytics import AttendanceAnalyticsService
    from .services.reports import AttendanceReportService

    User = get_user_model()
    stats = {"users_warmed": 0, "reports_warmed": 0, "errors": 0}

    try:
        # Get users to warm
        if user_ids:
            users = User.objects.filter(id__in=user_ids, is_active=True)
        else:
            users = User.objects.filter(is_active=True)[:100]  # Limit to 100 users

        analytics_service = AttendanceAnalyticsService()
        report_service = AttendanceReportService()

        # Warm today's analytics
        today = date.today()
        try:
            analytics_service.get_status_analytics(today)
            stats["reports_warmed"] += 1
        except Exception as e:
            logger.warning(f"Failed to warm analytics: {e}")
            stats["errors"] += 1

        # Warm monthly summary
        try:
            analytics_service.get_monthly_summary(today.year, today.month)
            stats["reports_warmed"] += 1
        except Exception as e:
            logger.warning(f"Failed to warm monthly summary: {e}")
            stats["errors"] += 1

        # Warm user summaries
        start_date = today - timedelta(days=30)
        for user in users:
            try:
                report_service.generate_user_summary(user, start_date, today)
                stats["users_warmed"] += 1
            except Exception as e:
                logger.warning(f"Failed to warm cache for user {user.id}: {e}")
                stats["errors"] += 1

        logger.info(f"Cache warming complete: {stats}")
        return stats

    except Exception as e:
        logger.error(f"Cache warming failed: {e}")
        stats["errors"] += 1
        return stats


class CacheMiddleware:
    """
    Middleware to add cache control headers to attendance responses.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        response = self.get_response(request)

        # Add cache headers for attendance API endpoints
        if "/api/v1/attendance/" in request.path:
            if request.method == "GET":
                # Allow caching for GET requests
                response["Cache-Control"] = "private, max-age=60"
            else:
                # No cache for mutations
                response["Cache-Control"] = "no-cache, no-store, must-revalidate"

        return response


# Signal handlers for automatic cache invalidation
def invalidate_on_attendance_save(sender, instance, **kwargs):
    """Signal handler to invalidate cache when attendance is saved."""
    invalidate_user_cache(instance.user_id)
    invalidate_date_cache(instance.date)


def invalidate_on_attendance_delete(sender, instance, **kwargs):
    """Signal handler to invalidate cache when attendance is deleted."""
    invalidate_user_cache(instance.user_id)
    invalidate_date_cache(instance.date)


def register_cache_signals():
    """Register cache invalidation signals. Call from apps.py ready()."""
    from django.db.models.signals import post_save, post_delete
    from trueAlign.models import Attendance

    post_save.connect(invalidate_on_attendance_save, sender=Attendance)
    post_delete.connect(invalidate_on_attendance_delete, sender=Attendance)
    logger.info("Attendance cache signals registered")
