"""
Enhanced Middleware for Smart Ticketing System
Provides security, logging, and performance monitoring capabilities
"""

import time
import json
import logging
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional

from django.http import HttpRequest, HttpResponse
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import User
from django.core.cache import cache
from django.conf import settings
from django.urls import resolve, reverse
from django.shortcuts import redirect
from django.contrib import messages

from .logging_system import ticket_logger, AuditLog
from .utils import PermissionManager


class TicketSecurityMiddleware(MiddlewareMixin):
    """
    Enhanced security middleware for ticket operations
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger(__name__)

    def __call__(self, request):
        # Pre-process request
        self.process_request(request)

        # Get response
        response = self.get_response(request)

        # Post-process response
        self.process_response(request, response)

        return response

    def process_request(self, request):
        """
        Process incoming request for security checks
        """
        # Generate unique request ID
        request.request_id = str(uuid.uuid4())

        # Check for suspicious activity
        if self._is_suspicious_request(request):
            self.logger.warning(f"Suspicious request detected: {request.path}")

        # Rate limiting for API endpoints
        if request.path.startswith('/support/api/'):
            if not self._check_rate_limit(request):
                self.logger.warning(f"Rate limit exceeded for {request.user}")
                return redirect('support:dashboard')

        # Log request for audit
        if request.user.is_authenticated and self._should_log_request(request):
            self._log_request(request)

    def process_response(self, request, response):
        """
        Process outgoing response
        """
        # Log response for audit
        if hasattr(request, 'user') and request.user.is_authenticated:
            if self._should_log_response(request, response):
                self._log_response(request, response)

        return response

    def _is_suspicious_request(self, request) -> bool:
        """
        Check if request shows suspicious patterns
        """
        # Check for SQL injection attempts
        suspicious_patterns = [
            'union select', 'drop table', 'delete from',
            'insert into', 'update set', '<script',
            'javascript:', 'onload=', 'onerror='
        ]

        query_string = request.GET.urlencode().lower()
        post_data = str(request.POST).lower()

        for pattern in suspicious_patterns:
            if pattern in query_string or pattern in post_data:
                return True

        return False

    def _check_rate_limit(self, request) -> bool:
        """
        Check rate limiting for API requests
        """
        if not request.user.is_authenticated:
            return True

        # Different limits for different user types
        user_roles = PermissionManager.get_user_roles(request.user)
        if user_roles['is_admin']:
            limit = 1000  # 1000 requests per minute
        elif user_roles['is_manager']:
            limit = 500   # 500 requests per minute
        else:
            limit = 100   # 100 requests per minute

        # Check cache for current request count
        cache_key = f"rate_limit:{request.user.id}:{timezone.now().minute}"
        current_count = cache.get(cache_key, 0)

        if current_count >= limit:
            return False

        # Increment counter
        cache.set(cache_key, current_count + 1, 60)  # 60 second expiry
        return True

    def _should_log_request(self, request) -> bool:
        """
        Determine if request should be logged
        """
        # Log all POST requests (modifications)
        if request.method == 'POST':
            return True

        # Log access to sensitive endpoints
        sensitive_paths = [
            '/support/analytics/',
            '/support/sla-monitoring/',
            '/support/export/',
        ]

        return any(request.path.startswith(path) for path in sensitive_paths)

    def _should_log_response(self, request, response) -> bool:
        """
        Determine if response should be logged
        """
        # Log error responses
        if response.status_code >= 400:
            return True

        # Log for POST requests
        if request.method == 'POST':
            return True

        return False

    def _log_request(self, request):
        """
        Log request details for audit
        """
        try:
            log_data = {
                'request_id': getattr(request, 'request_id', 'unknown'),
                'method': request.method,
                'path': request.path,
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'ip_address': self._get_client_ip(request),
                'query_params': dict(request.GET),
                'timestamp': timezone.now().isoformat()
            }

            # Add POST data for relevant requests (excluding sensitive data)
            if request.method == 'POST':
                post_data = dict(request.POST)
                # Remove sensitive fields
                sensitive_fields = ['password', 'token', 'secret']
                for field in sensitive_fields:
                    if field in post_data:
                        post_data[field] = '[REDACTED]'
                log_data['post_data'] = post_data

            ticket_logger.log_user_activity(
                request.user,
                'REQUEST',
                log_data,
                request.request_id
            )

        except Exception as e:
            self.logger.error(f"Failed to log request: {str(e)}")

    def _log_response(self, request, response):
        """
        Log response details for audit
        """
        try:
            log_data = {
                'request_id': getattr(request, 'request_id', 'unknown'),
                'status_code': response.status_code,
                'content_type': response.get('Content-Type', ''),
                'response_size': len(response.content) if hasattr(response, 'content') else 0,
                'timestamp': timezone.now().isoformat()
            }

            # Add error details for failed requests
            if response.status_code >= 400:
                log_data['error'] = True
                log_data['error_code'] = response.status_code

            ticket_logger.log_user_activity(
                request.user,
                'RESPONSE',
                log_data,
                request.request_id
            )

        except Exception as e:
            self.logger.error(f"Failed to log response: {str(e)}")

    def _get_client_ip(self, request) -> str:
        """
        Get client IP address
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class TicketPerformanceMiddleware(MiddlewareMixin):
    """
    Performance monitoring middleware for ticket operations
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger(__name__)

    def __call__(self, request):
        # Start timing
        start_time = time.time()

        # Process request
        response = self.get_response(request)

        # Calculate processing time
        processing_time = time.time() - start_time

        # Log performance metrics
        self._log_performance(request, response, processing_time)

        # Add performance headers for debugging
        if settings.DEBUG:
            response['X-Processing-Time'] = f"{processing_time:.3f}s"

        return response

    def _log_performance(self, request, response, processing_time):
        """
        Log performance metrics
        """
        try:
            # Only log authenticated requests to support URLs
            if (not request.user.is_authenticated or
                not request.path.startswith('/support/')):
                return

            # Log slow requests (>2 seconds)
            if processing_time > 2.0:
                self.logger.warning(
                    f"Slow request detected: {request.path} "
                    f"took {processing_time:.3f}s for user {request.user.username}"
                )

            # Store performance metrics in cache for analytics
            self._store_performance_metrics(request, processing_time)

        except Exception as e:
            self.logger.error(f"Failed to log performance: {str(e)}")

    def _store_performance_metrics(self, request, processing_time):
        """
        Store performance metrics for analytics
        """
        try:
            # Get current hour for grouping
            current_hour = timezone.now().replace(minute=0, second=0, microsecond=0)
            cache_key = f"performance_metrics:{current_hour.isoformat()}"

            # Get existing metrics
            metrics = cache.get(cache_key, {
                'total_requests': 0,
                'total_time': 0,
                'slow_requests': 0,
                'endpoints': {}
            })

            # Update metrics
            metrics['total_requests'] += 1
            metrics['total_time'] += processing_time

            if processing_time > 2.0:
                metrics['slow_requests'] += 1

            # Track per-endpoint metrics
            endpoint = request.path
            if endpoint not in metrics['endpoints']:
                metrics['endpoints'][endpoint] = {
                    'count': 0,
                    'total_time': 0,
                    'max_time': 0
                }

            endpoint_metrics = metrics['endpoints'][endpoint]
            endpoint_metrics['count'] += 1
            endpoint_metrics['total_time'] += processing_time
            endpoint_metrics['max_time'] = max(endpoint_metrics['max_time'], processing_time)

            # Store back in cache (expire after 2 hours)
            cache.set(cache_key, metrics, 7200)

        except Exception as e:
            self.logger.error(f"Failed to store performance metrics: {str(e)}")


class TicketAccessControlMiddleware(MiddlewareMixin):
    """
    Role-based access control middleware
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger(__name__)

        # Define protected endpoints and required roles
        self.protected_endpoints = {
            '/support/analytics/': ['admin', 'manager'],
            '/support/sla-monitoring/': ['admin', 'manager'],
            '/support/sla-check/': ['admin'],
            '/support/tickets/bulk-actions/': ['admin', 'manager'],
            '/support/export/': ['admin', 'manager'],
        }

    def __call__(self, request):
        # Check access control
        if not self._check_access_control(request):
            return redirect('support:dashboard')

        response = self.get_response(request)
        return response

    def _check_access_control(self, request) -> bool:
        """
        Check if user has access to requested endpoint
        """
        if not request.user.is_authenticated:
            return True  # Let Django's login_required handle this

        # Check if endpoint is protected
        for endpoint, required_roles in self.protected_endpoints.items():
            if request.path.startswith(endpoint):
                user_roles = PermissionManager.get_user_roles(request.user)

                # Check if user has required role
                has_access = False
                for role in required_roles:
                    if user_roles.get(f'is_{role}', False):
                        has_access = True
                        break

                if not has_access:
                    self.logger.warning(
                        f"Access denied for user {request.user.username} "
                        f"to endpoint {request.path}"
                    )
                    messages.error(
                        request,
                        "You don't have permission to access this page."
                    )
                    return False

        return True


class TicketCacheMiddleware(MiddlewareMixin):
    """
    Caching middleware for improved performance
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger(__name__)

        # Define cacheable endpoints
        self.cacheable_endpoints = {
            '/support/api/stats/': 300,  # 5 minutes
            '/support/analytics/': 600,  # 10 minutes
        }

    def __call__(self, request):
        # Check if response can be served from cache
        if request.method == 'GET':
            cached_response = self._get_cached_response(request)
            if cached_response:
                return cached_response

        response = self.get_response(request)

        # Cache response if applicable
        if request.method == 'GET' and response.status_code == 200:
            self._cache_response(request, response)

        return response

    def _get_cached_response(self, request):
        """
        Get cached response if available
        """
        try:
            cache_key = self._get_cache_key(request)
            if cache_key:
                cached_data = cache.get(cache_key)
                if cached_data:
                    self.logger.debug(f"Cache hit for {request.path}")
                    return cached_data

        except Exception as e:
            self.logger.error(f"Failed to get cached response: {str(e)}")

        return None

    def _cache_response(self, request, response):
        """
        Cache response if applicable
        """
        try:
            cache_key = self._get_cache_key(request)
            if cache_key:
                # Get cache timeout for this endpoint
                for endpoint, timeout in self.cacheable_endpoints.items():
                    if request.path.startswith(endpoint):
                        cache.set(cache_key, response, timeout)
                        self.logger.debug(f"Cached response for {request.path}")
                        break

        except Exception as e:
            self.logger.error(f"Failed to cache response: {str(e)}")

    def _get_cache_key(self, request) -> Optional[str]:
        """
        Generate cache key for request
        """
        # Check if endpoint is cacheable
        for endpoint in self.cacheable_endpoints.keys():
            if request.path.startswith(endpoint):
                # Include user ID in cache key for user-specific data
                user_id = request.user.id if request.user.is_authenticated else 'anonymous'
                query_string = request.GET.urlencode()
                return f"ticket_cache:{user_id}:{request.path}:{query_string}"

        return None


class TicketMaintenanceMiddleware(MiddlewareMixin):
    """
    Maintenance and cleanup middleware
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.logger = logging.getLogger(__name__)
        self.last_cleanup = cache.get('last_cleanup', timezone.now())

    def __call__(self, request):
        # Run periodic maintenance
        self._run_maintenance()

        response = self.get_response(request)
        return response

    def _run_maintenance(self):
        """
        Run periodic maintenance tasks
        """
        try:
            now = timezone.now()

            # Run cleanup every hour
            if now - self.last_cleanup > timedelta(hours=1):
                self._cleanup_old_logs()
                self._cleanup_cache()
                self.last_cleanup = now
                cache.set('last_cleanup', now, 3600)

        except Exception as e:
            self.logger.error(f"Maintenance task failed: {str(e)}")

    def _cleanup_old_logs(self):
        """
        Clean up old audit logs
        """
        try:
            # Delete logs older than 90 days
            cutoff_date = timezone.now() - timedelta(days=90)
            old_logs = AuditLog.objects.filter(timestamp__lt=cutoff_date)
            count = old_logs.count()

            if count > 0:
                old_logs.delete()
                self.logger.info(f"Cleaned up {count} old audit logs")

        except Exception as e:
            self.logger.error(f"Failed to cleanup old logs: {str(e)}")

    def _cleanup_cache(self):
        """
        Clean up expired cache entries
        """
        try:
            # This is handled automatically by most cache backends
            # but we can log the activity
            self.logger.debug("Cache cleanup completed")

        except Exception as e:
            self.logger.error(f"Failed to cleanup cache: {str(e)}")
