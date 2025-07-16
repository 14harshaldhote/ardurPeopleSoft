import json
import time
import hashlib
from datetime import datetime, timedelta
from django.core.cache import cache
from django.utils import timezone
from django.conf import settings
from django.contrib.sessions.models import Session
from django.contrib.auth.models import User
from django.db import transaction
from django.core.exceptions import ObjectDoesNotExist
from ..models import UserSession, SessionActivity
from ..utils import (
    get_client_ip, get_location_from_ip, parse_user_agent,
    detect_suspicious_activity, IST_TIMEZONE, to_ist, to_utc
)
import logging

logger = logging.getLogger(__name__)

class OptimizedSessionTrackingMiddleware:
    """
    Optimized session tracking middleware with cache-based throttling
    Reduces database writes while maintaining comprehensive session data collection
    """

    def __init__(self, get_response):
        self.get_response = get_response

        # Configuration
        self.DB_WRITE_INTERVAL = getattr(settings, 'SESSION_DB_WRITE_INTERVAL', 600)  # 10 minutes
        self.BATCH_SIZE = getattr(settings, 'SESSION_BATCH_SIZE', 50)  # Max activities per batch
        self.CACHE_TIMEOUT = getattr(settings, 'SESSION_CACHE_TIMEOUT', 3600)  # 1 hour
        self.SESSION_KEY_PREFIX = 'session_tracking_'
        self.LAST_WRITE_KEY_PREFIX = 'last_db_write_'

        # Rate limiting
        self.RATE_LIMIT_WINDOW = 60  # 1 minute
        self.RATE_LIMIT_MAX_REQUESTS = 100

        logger.info("OptimizedSessionTrackingMiddleware initialized")

    def __call__(self, request):
        # Skip for certain paths
        if self._should_skip(request):
            return self.get_response(request)

        # Process request
        self._process_request(request)

        # Get response
        response = self.get_response(request)

        # Process response
        self._process_response(request, response)

        return response

    def _should_skip(self, request):
        """Check if request should be skipped"""
        skip_paths = [
            '/static/', '/media/', '/favicon.ico', '/robots.txt',
            '/admin/jsi18n/', '/session/heartbeat/', '/session/update-activity/'
        ]

        skip_extensions = ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg']

        path = request.path.lower()

        # Skip static files and admin JS
        if any(path.startswith(skip_path) for skip_path in skip_paths):
            return True

        # Skip by extension
        if any(path.endswith(ext) for ext in skip_extensions):
            return True

        # Skip AJAX heartbeat calls more aggressively
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            ajax_skip_paths = ['/session/', '/api/session/']
            if any(path.startswith(ajax_path) for ajax_path in ajax_skip_paths):
                return True

        return False

    def _process_request(self, request):
        """Process incoming request"""
        if not request.user.is_authenticated:
            return

        # Rate limiting check
        if not self._check_rate_limit(request):
            return

        # Get or create session tracking data
        session_data = self._get_session_data(request)

        # Update request info
        self._update_request_info(request, session_data)

        # Store in cache
        self._store_session_data(request, session_data)

    def _process_response(self, request, response):
        """Process response"""
        if not request.user.is_authenticated:
            return

        # Get session data
        session_data = self._get_session_data(request)

        # Update response info
        self._update_response_info(request, response, session_data)

        # Check if we need to write to database
        if self._should_write_to_database(request, session_data):
            self._write_to_database(request, session_data)

        # Store updated data
        self._store_session_data(request, session_data)

    def _check_rate_limit(self, request):
        """Check rate limiting"""
        user_id = request.user.id
        ip = get_client_ip(request)

        # Create rate limit key
        rate_key = f"rate_limit_{user_id}_{ip}"

        # Get current count
        current_count = cache.get(rate_key, 0)

        if current_count >= self.RATE_LIMIT_MAX_REQUESTS:
            logger.warning(f"Rate limit exceeded for user {user_id} from IP {ip}")
            return False

        # Increment counter
        cache.set(rate_key, current_count + 1, self.RATE_LIMIT_WINDOW)

        return True

    def _get_session_data(self, request):
        """Get session data from cache or create new"""
        user_id = request.user.id
        session_key = f"{self.SESSION_KEY_PREFIX}{user_id}"

        # Try to get from cache first
        session_data = cache.get(session_key)

        if session_data is None:
            # Create new session data
            session_data = self._create_new_session_data(request)

        return session_data

    def _create_new_session_data(self, request):
        """Create new session data structure"""
        now = timezone.now()

        return {
            'user_id': request.user.id,
            'session_id': request.session.session_key,
            'created_at': now.isoformat(),
            'last_activity': now.isoformat(),
            'ip_address': get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'device_info': parse_user_agent(request.META.get('HTTP_USER_AGENT', '')),
            'location': get_location_from_ip(get_client_ip(request)),

            # Activity counters
            'page_views': 0,
            'total_requests': 0,
            'ajax_requests': 0,
            'idle_time': 0,
            'active_time': 0,
            'background_time': 0,

            # Activity buffer (stores activities until DB write)
            'activities': [],
            'page_visits': [],
            'security_events': [],

            # Performance metrics
            'avg_response_time': 0,
            'total_response_time': 0,
            'slow_requests': 0,

            # Flags
            'is_active': True,
            'is_idle': False,
            'needs_db_write': False,
            'last_db_write': now.isoformat(),
        }

    def _update_request_info(self, request, session_data):
        """Update request information"""
        now = timezone.now()

        # Update counters
        session_data['total_requests'] += 1
        session_data['last_activity'] = now.isoformat()

        # Check if it's an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            session_data['ajax_requests'] += 1
        else:
            session_data['page_views'] += 1

            # Add page visit to buffer
            page_visit = {
                'url': request.build_absolute_uri(),
                'path': request.path,
                'method': request.method,
                'timestamp': now.isoformat(),
                'referrer': request.META.get('HTTP_REFERER', ''),
                'query_params': dict(request.GET),
            }
            session_data['page_visits'].append(page_visit)

        # Security checks
        suspicious_activities = detect_suspicious_activity(
            type('obj', (object,), {
                'ip_address': session_data['ip_address'],
                'user_agent': session_data['user_agent'],
                'location_history': session_data.get('location_history', [])
            })(),
            request
        )

        if suspicious_activities:
            session_data['security_events'].extend(suspicious_activities)

        # Mark as needing database write if buffer is getting full
        if (len(session_data['activities']) >= self.BATCH_SIZE or
            len(session_data['page_visits']) >= self.BATCH_SIZE):
            session_data['needs_db_write'] = True

    def _update_response_info(self, request, response, session_data):
        """Update response information"""
        # Calculate response time (if available)
        if hasattr(request, '_start_time'):
            response_time = (time.time() - request._start_time) * 1000  # ms

            # Update performance metrics
            session_data['total_response_time'] += response_time
            session_data['avg_response_time'] = (
                session_data['total_response_time'] / session_data['total_requests']
            )

            # Track slow requests
            if response_time > 2000:  # 2 seconds
                session_data['slow_requests'] += 1

        # Add activity to buffer
        activity = {
            'type': 'page_view' if request.method == 'GET' else 'action',
            'url': request.build_absolute_uri(),
            'path': request.path,
            'method': request.method,
            'status_code': response.status_code,
            'timestamp': timezone.now().isoformat(),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'ip_address': get_client_ip(request),
            'response_time': getattr(request, '_start_time', None) and (time
