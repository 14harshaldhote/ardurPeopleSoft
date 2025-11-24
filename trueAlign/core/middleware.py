import time
import threading
import json
import logging
from datetime import datetime, timedelta
from collections import defaultdict
from django.utils import timezone
from django.core.cache import cache
from django.contrib.auth.models import AnonymousUser
from django.http import JsonResponse
from django.urls import reverse
from django.conf import settings
from django.db import transaction

# Try to import enhanced components, fall back to None if not available
try:
    from . import get_batch_writer, get_session_manager, get_session_logger
    ENHANCED_COMPONENTS_AVAILABLE = True
except ImportError as e:
    # Logger will be declared below
    get_batch_writer = lambda: None
    get_session_manager = lambda: None
    get_session_logger = lambda: None
    ENHANCED_COMPONENTS_AVAILABLE = False
from .utils import (
    get_client_ip, parse_user_agent, get_location_from_ip,
    detect_suspicious_activity, calculate_productivity_score,
    to_ist, get_current_time_ist
)
from .session_config import CONFIG
from .signals import (
    trigger_maintenance_if_needed, handle_suspicious_activity,
    get_cached_session, cache_session, invalidate_user_caches
)

# Module-level configuration constants
THROTTLE_INTERVAL = 10 * 60  # 10 minutes in seconds
MAX_BUFFER_SIZE = 100  # Maximum activities to buffer
HEARTBEAT_INTERVAL = 30  # seconds

logger = logging.getLogger(__name__)

# Log warning if enhanced components are not available
if not ENHANCED_COMPONENTS_AVAILABLE:
    logger.warning("Enhanced session components not available, using fallback implementations")

class OptimizedSessionTrackingMiddleware:
    """
    Optimized middleware that reduces database writes through:
    1. Throttled session updates (configurable interval)
    2. In-memory activity buffering
    3. Batch database operations
    4. Smart conditional saves
    """

    # Class-level configuration
    THROTTLE_INTERVAL = 10 * 60  # 10 minutes in seconds
    MAX_BUFFER_SIZE = 100  # Maximum activities to buffer
    HEARTBEAT_INTERVAL = 30  # seconds

    # Thread-local storage for session data
    _local = threading.local()

    # Class-level activity buffer
    _activity_buffer = defaultdict(lambda: {
        'clicks': [],
        'scrolls': [],
        'keyboard_events': [],
        'mouse_movements': 0,
        'page_views': [],
        'tab_visibility_log': [],
        'idle_state_changes': [],
        'performance_metrics': {},
        'last_flush': time.time(),
        'session_id': None,
        'user_id': None,
        'pending_updates': {}
    })

    def __init__(self, get_response):
        self.get_response = get_response
        self.exempt_paths = [
            '/admin/', '/static/', '/media/', '/favicon.ico',
            '/robots.txt', '/sitemap.xml'
        ]
        self.api_paths = [
            '/api/', '/session/heartbeat/', '/session/update-activity/',
            '/session/log-activity/'
        ]

        # Initialize cleanup thread
        self._start_cleanup_thread()

    def __call__(self, request):
        # Skip processing for exempt paths
        if self._should_skip_request(request):
            return self.get_response(request)

        # Process authenticated requests only
        if request.user.is_authenticated:
            self._process_authenticated_request(request)

            # Trigger maintenance if needed (Django-native cleanup)
            trigger_maintenance_if_needed()

        response = self.get_response(request)

        # Add session headers if needed
        if request.user.is_authenticated:
            self._add_session_headers(request, response)

        return response


    def _get_or_create_session_throttled(self, request, user):
        """Get or create session with throttling"""
        # Import here to avoid circular imports
        from trueAlign.models import UserSession

        tab_id = request.headers.get('X-Tab-ID') or request.GET.get('tab_id')
        cache_key = f"session_lookup_{user.id}_{tab_id or 'default'}"

        # Check cache first
        cached_session = cache.get(cache_key)
        if cached_session:
            return cached_session

        # Look for existing active session
        try:
            if tab_id:
                session = UserSession.objects.select_related('user').get(
                    user=user, tab_id=tab_id, is_active=True
                )
            else:
                session = UserSession.objects.select_related('user').filter(
                    user=user, is_active=True
                ).first()

            if session:
                # Cache the session for 5 minutes
                cache.set(cache_key, session, 300)
                return session
        except UserSession.DoesNotExist:
            pass

        # Create new session only if none exists
        session = self._create_new_session_throttled(request, user, tab_id)
        if session:
            cache.set(cache_key, session, 300)

        return session

    def _should_skip_request(self, request):
        """Check if request should be skipped"""
        path = request.path_info

        # Skip exempt paths
        for exempt_path in self.exempt_paths:
            if path.startswith(exempt_path):
                return True

        # Skip if user is not authenticated
        if not request.user.is_authenticated:
            return True

        # Skip if this is a heartbeat request (handled separately)
        if path in ['/session/heartbeat/', '/session/update-activity/']:
            return True

        return False

    def _process_authenticated_request(self, request):
        """Process authenticated request with optimized session tracking"""
        user = request.user
        session_key = f"session_{user.id}"

        # Get or create session with throttling
        session = self._get_or_create_session_throttled(request, user)

        if session:
            # Update last activity (lightweight)
            self._update_last_activity_throttled(session, user.id)

            # Collect activity data without immediate save
            self._collect_activity_data(request, session, user.id)

            # Check if we need to flush buffered data
            self._check_and_flush_buffer(user.id, session)

    def _create_new_session_throttled(self, request, user, tab_id):
        """Create new session with minimal data and security checks using improved session management"""
        # Import here to avoid circular imports
        from trueAlign.models import UserSession

        try:
            client_info = self._extract_client_info(request)

            # Extract session identifiers from headers or generate new ones
            parent_session_id = request.headers.get('X-Parent-Session-ID')
            session_fingerprint = request.headers.get('X-Session-Fingerprint') or client_info.get('browser_fingerprint')

            # If no parent_session_id provided, check if we can derive it from existing sessions
            if not parent_session_id and session_fingerprint:
                recent_session = UserSession.objects.filter(
                    user=user,
                    session_fingerprint=session_fingerprint,
                    is_active=True,
                    last_activity__gte=timezone.now() - timezone.timedelta(minutes=30)
                ).first()
                if recent_session:
                    parent_session_id = str(recent_session.parent_session_id)

            # Check for suspicious activity
            if CONFIG.ENABLE_SECURITY_CHECKS:
                existing_session = UserSession.objects.filter(
                    user=user, is_active=True
                ).first()

                if existing_session:
                    suspicious_indicators = detect_suspicious_activity(existing_session, request)
                    if suspicious_indicators:
                        handle_suspicious_activity(user, existing_session, suspicious_indicators)

            # Extract location information if available
            location_info = None
            if client_info.get('ip_address'):
                try:
                    location_info = get_location_from_ip(client_info.get('ip_address'))
                except Exception as loc_error:
                    logger.warning(f"Error getting location: {loc_error}")

            # Prepare client data for session creation
            client_data = {
                'ip_address': client_info.get('ip_address'),
                'user_agent': client_info.get('user_agent'),
                'device_type': client_info.get('device_type'),
                'browser_fingerprint': session_fingerprint,
                'session_fingerprint': session_fingerprint,
                'browser': client_info.get('browser'),
                'os': client_info.get('os'),
                'screen_resolution': request.headers.get('X-Screen-Resolution'),
                'timezone_offset': request.headers.get('X-Timezone-Offset'),
                'language': request.headers.get('X-Language'),
            }

            # Add location data if available
            if location_info:
                client_data['location_data'] = location_info

            # Use the improved get_or_create_session method
            session, created = UserSession.get_or_create_session(
                user=user,
                tab_id=tab_id,
                parent_session_id=parent_session_id,
                client_data=client_data,
                session_key=UserSession.generate_session_key()
            )

            if session:
                # Initialize buffer for the session (whether new or existing)
                buffer_key = f"activity_{user.id}_{session.id}"
                if buffer_key not in self._activity_buffer:
                    self._activity_buffer[buffer_key] = {
                        'clicks': [],
                        'scrolls': [],
                        'keyboard_events': [],
                        'mouse_movements': 0,
                        'tab_visibility_log': [],
                        'idle_state_changes': [],
                        'performance_metrics': {},
                        'page_views': [],
                        'pending_updates': {},
                        'last_activity': timezone.now(),
                        'last_flush': time.time(),
                        'user_id': user.id
                    }

                # Only log if it was actually created or if it's a significant reuse event
                if created:
                    if CONFIG.should_log_category('session_creation'):
                        logger.info(f"Created session {session.id} for user {user.username} (tab: {tab_id}, parent: {parent_session_id})", 
                                   extra={'event_type': 'session_creation', 'was_created': True})
                else:
                    # Log reuse at debug level to reduce noise, unless specific conditions met
                    logger.debug(f"Reused existing session {session.id} for user {user.username}", 
                                extra={'event_type': 'session_creation', 'was_created': False})

            return session
        except Exception as e:
            logger.error(f"Error creating/getting session: {e}")
            return None



    def _extract_client_info(self, request):
        """Extract client information from request"""
        ip_address = get_client_ip(request)

        # Generate browser fingerprint from user agent and other headers
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        accept_language = request.META.get('HTTP_ACCEPT_LANGUAGE', '')
        accept_encoding = request.META.get('HTTP_ACCEPT_ENCODING', '')

        # Create a simple fingerprint
        import hashlib
        fingerprint_data = f"{user_agent}|{accept_language}|{accept_encoding}|{ip_address}"
        browser_fingerprint = hashlib.md5(fingerprint_data.encode()).hexdigest()[:16]
        device_info = parse_user_agent(user_agent)

        return {
            'ip_address': ip_address,
            'user_agent': user_agent,
            'browser_fingerprint': browser_fingerprint,
            'device_type': device_info.get('device', 'unknown'),
            'browser': device_info.get('browser', 'unknown'),
            'os': device_info.get('os', 'unknown'),
        }

    def _update_last_activity_throttled(self, session, user_id):
        """Update last activity with throttling"""
        current_time = time.time()
        buffer_key = f"activity_{user_id}_{session.id}"

        # Store in buffer
        self._activity_buffer[buffer_key]['last_activity'] = timezone.now()
        self._activity_buffer[buffer_key]['session_id'] = session.id
        self._activity_buffer[buffer_key]['user_id'] = user_id

        # Only update database if throttle interval has passed
        last_db_update = getattr(session, '_last_db_update', 0)
        if current_time - last_db_update >= self.THROTTLE_INTERVAL:
            try:
                session.last_activity = timezone.now()
                session.save(update_fields=['last_activity'])
                session._last_db_update = current_time

                # Update cache
                cache_key = f"session_lookup_{user_id}_{session.tab_id or 'default'}"
                cache.set(cache_key, session, 300)

            except Exception as e:
                logger.error(f"Error updating last activity: {e}")

    def _collect_activity_data(self, request, session, user_id):
        """Collect activity data in memory buffer"""
        buffer_key = f"activity_{user_id}_{session.id}"

        # Ensure buffer exists with proper initialization
        if buffer_key not in self._activity_buffer:
            self._activity_buffer[buffer_key] = {
                'clicks': [],
                'scrolls': [],
                'keyboard_events': [],
                'mouse_movements': 0,
                'tab_visibility_log': [],
                'idle_state_changes': [],
                'performance_metrics': {},
                'page_views': [],
                'pending_updates': {},
                'last_activity': timezone.now(),
                'last_flush': time.time(),
                'user_id': user_id
            }

        buffer = self._activity_buffer[buffer_key]

        # Ensure all required keys exist (defensive programming)
        buffer.setdefault('clicks', [])
        buffer.setdefault('scrolls', [])
        buffer.setdefault('keyboard_events', [])
        buffer.setdefault('mouse_movements', 0)
        buffer.setdefault('tab_visibility_log', [])
        buffer.setdefault('idle_state_changes', [])
        buffer.setdefault('performance_metrics', {})
        buffer.setdefault('page_views', [])
        buffer.setdefault('pending_updates', {})
        buffer.setdefault('last_activity', timezone.now())
        buffer.setdefault('last_flush', time.time())
        buffer.setdefault('user_id', user_id)

        # Collect page view data
        if request.method == 'GET':
            page_view = {
                'url': request.get_full_path(),
                'title': request.META.get('HTTP_REFERER', ''),
                'timestamp': timezone.now().isoformat(),
                'method': request.method
            }
            buffer['page_views'].append(page_view)

        # Collect request metadata - now safe to access
        buffer['pending_updates'].update({
            'url': request.get_full_path(),
            'method': request.method,
            'timestamp': timezone.now().isoformat()
        })

        # Limit buffer size
        self.__class__._limit_buffer_size(buffer)

    @classmethod
    def _limit_buffer_size(cls, buffer):
        """Limit buffer size to prevent memory issues"""
        for key in ['clicks', 'scrolls', 'keyboard_events', 'page_views',
                   'tab_visibility_log', 'idle_state_changes']:
            if key in buffer and len(buffer[key]) > cls.MAX_BUFFER_SIZE:
                buffer[key] = buffer[key][-cls.MAX_BUFFER_SIZE:]

    def _check_and_flush_buffer(self, user_id, session):
        """Check if buffer should be flushed and do so if needed"""
        buffer_key = f"activity_{user_id}_{session.id}"
        buffer = self._activity_buffer[buffer_key]

        current_time = time.time()
        last_flush = buffer.get('last_flush', 0)

        # Flush if throttle interval has passed or buffer is full
        should_flush = (
            current_time - last_flush >= self.THROTTLE_INTERVAL or
            len(buffer.get('page_views', [])) >= self.MAX_BUFFER_SIZE or
            len(buffer.get('clicks', [])) >= self.MAX_BUFFER_SIZE
        )

        if should_flush:
            self._flush_buffer_to_database(buffer_key, session)

    @classmethod
    def _flush_buffer_to_database(cls, buffer_key, session):
        """Flush buffered data to database"""
        if buffer_key not in cls._activity_buffer:
            return

        buffer = cls._activity_buffer[buffer_key]

        try:
            with transaction.atomic():
                update_fields = []

                # Update page views
                if buffer.get('page_views'):
                    existing_views = list(session.page_views) if session.page_views else []
                    existing_views.extend(buffer['page_views'])
                    session.page_views = existing_views[-1000:]  # Keep last 1000
                    update_fields.append('page_views')

                # Update clicks
                if buffer.get('clicks'):
                    existing_clicks = list(session.clicks) if session.clicks else []
                    existing_clicks.extend(buffer['clicks'])
                    session.clicks = existing_clicks[-1000:]  # Keep last 1000
                    update_fields.append('clicks')

                # Update scrolls
                if buffer.get('scrolls'):
                    existing_scrolls = list(session.scrolls) if session.scrolls else []
                    existing_scrolls.extend(buffer['scrolls'])
                    session.scrolls = existing_scrolls[-500:]  # Keep last 500
                    update_fields.append('scrolls')

                # Update keyboard events
                if buffer.get('keyboard_events'):
                    existing_keyboard = list(session.keyboard_events) if session.keyboard_events else []
                    existing_keyboard.extend(buffer['keyboard_events'])
                    session.keyboard_events = existing_keyboard[-500:]  # Keep last 500
                    update_fields.append('keyboard_events')

                # Update mouse movements
                if buffer.get('mouse_movements'):
                    session.mouse_movements += buffer['mouse_movements']
                    update_fields.append('mouse_movements')

                # Update tab visibility log
                if buffer.get('tab_visibility_log'):
                    existing_visibility = list(session.tab_visibility_log) if session.tab_visibility_log else []
                    existing_visibility.extend(buffer['tab_visibility_log'])
                    session.tab_visibility_log = existing_visibility[-100:]  # Keep last 100
                    update_fields.append('tab_visibility_log')

                # Update idle state changes
                if buffer.get('idle_state_changes'):
                    existing_idle = list(session.idle_state_changes) if session.idle_state_changes else []
                    existing_idle.extend(buffer['idle_state_changes'])
                    session.idle_state_changes = existing_idle[-50:]  # Keep last 50
                    update_fields.append('idle_state_changes')

                # Update performance metrics
                if buffer.get('performance_metrics'):
                    existing_metrics = session.performance_metrics or {}
                    existing_metrics.update(buffer['performance_metrics'])
                    session.performance_metrics = existing_metrics
                    update_fields.append('performance_metrics')

                # Update last activity
                if buffer.get('last_activity'):
                    session.last_activity = buffer['last_activity']
                    update_fields.append('last_activity')

                # Save to database
                if update_fields:
                    session.save(update_fields=update_fields)

                    # Update cache after successful save
                    cache_session(buffer.get('user_id'), session)

                # Clear buffer
                buffer.clear()
                buffer['last_flush'] = time.time()

                if CONFIG.should_log_category('buffer_flushes'):
                    logger.info(f"Flushed buffer for session {session.id}")

        except Exception as e:
            logger.error(f"Error flushing buffer: {e}")



    def _add_session_headers(self, request, response):
        """Add session-related headers to response"""
        if hasattr(request, 'session_warning'):
            response['X-Session-Warning'] = 'true'
            response['X-Session-Remaining'] = str(request.session_remaining_time)

    def _start_cleanup_thread(self):
        """Start background thread for cleanup tasks"""
        def cleanup_worker():
            while True:
                try:
                    time.sleep(300)  # Run every 5 minutes
                    self._cleanup_old_buffers()
                except Exception as e:
                    logger.error(f"Error in cleanup thread: {e}")

        cleanup_thread = threading.Thread(target=cleanup_worker, daemon=True)
        cleanup_thread.start()

    @classmethod
    def _cleanup_old_buffers(cls):
        """Clean up old buffers to prevent memory leaks"""
        current_time = time.time()
        keys_to_remove = []

        for key, buffer in cls._activity_buffer.items():
            last_flush = buffer.get('last_flush', 0)

            # Remove buffers that haven't been used for 1 hour
            if current_time - last_flush > 3600:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del cls._activity_buffer[key]

        if keys_to_remove and CONFIG.should_log_category('cleanup'):
            logger.info(f"Cleaned up {len(keys_to_remove)} old buffers")

    @classmethod
    def force_flush_user_buffer(cls, user_id, session_id):
        """Force flush buffer for specific user session"""
        # Import here to avoid circular imports
        from trueAlign.models import UserSession

        buffer_key = f"activity_{user_id}_{session_id}"

        if buffer_key in cls._activity_buffer:
            try:
                session = UserSession.objects.get(id=session_id)
                cls._flush_buffer_to_database(buffer_key, session)
            except UserSession.DoesNotExist:
                logger.warning(f"Session {session_id} does not exist for flush")
                pass

    @classmethod
    def log_activity(cls, user_id, session_id, activity_type, activity_data):
        """Static method to log activity from frontend"""
        if not user_id or not session_id:
            return

        buffer_key = f"activity_{user_id}_{session_id}"

        # Initialize buffer if it doesn't exist
        if buffer_key not in cls._activity_buffer:
            cls._activity_buffer[buffer_key] = {
                'clicks': [],
                'scrolls': [],
                'keyboard_events': [],
                'mouse_movements': 0,
                'tab_visibility_log': [],
                'idle_state_changes': [],
                'performance_metrics': {},
                'page_views': [],
                'pending_updates': {},
                'last_activity': timezone.now(),
                'last_flush': time.time(),
                'user_id': user_id
            }

        buffer = cls._activity_buffer[buffer_key]

        # Add activity to appropriate buffer
        if activity_type == 'click':
            buffer['clicks'].append(activity_data)
        elif activity_type == 'scroll':
            buffer['scrolls'].append(activity_data)
        elif activity_type == 'keyboard':
            buffer['keyboard_events'].append(activity_data)
        elif activity_type == 'mouse_move':
            buffer['mouse_movements'] += 1
        elif activity_type == 'tab_visibility':
            buffer['tab_visibility_log'].append(activity_data)
        elif activity_type == 'idle_state':
            buffer['idle_state_changes'].append(activity_data)
        elif activity_type == 'performance':
            buffer['performance_metrics'].update(activity_data)

        # Limit buffer size if buffer exists
        if buffer and isinstance(buffer, dict):
            cls._limit_buffer_size(buffer)

        # Update last activity
        buffer['last_activity'] = timezone.now()

        # Force flush if buffer is getting full
        if len(buffer.get('clicks', [])) >= cls.MAX_BUFFER_SIZE:
            try:
                # Import here to avoid circular imports
                from trueAlign.models import UserSession
                session = UserSession.objects.get(id=session_id)
                cls._flush_buffer_to_database(buffer_key, session)
            except UserSession.DoesNotExist:
                logger.warning(f"Session {session_id} does not exist for flush")
                pass


class OptimizedGlobalAuthenticationMiddleware:
    """
    Optimized authentication middleware with reduced database queries
    """

    def __init__(self, get_response):
        self.get_response = get_response
        self.exempt_paths = [
            '/login/', '/logout/', '/password-reset/', '/admin/login/',
            '/static/', '/media/', '/favicon.ico', '/robots.txt'
        ]

    def __call__(self, request):
        # Check if path is exempt
        if self._is_exempt_path(request.path_info):
            return self.get_response(request)

        # Check authentication with caching
        if not self._is_authenticated_cached(request):
            return self._handle_unauthenticated_request(request)

        # Check session expiry with throttling
        if self._should_check_session_expiry(request):
            expired_response = self._check_session_expiry(request)
            if expired_response:
                return expired_response

        response = self.get_response(request)
        return response

    def _is_exempt_path(self, path):
        """Check if path is exempt from authentication"""
        return any(path.startswith(exempt) for exempt in self.exempt_paths)

    def _is_authenticated_cached(self, request):
        """Check if user is authenticated with caching"""
        if not hasattr(request, 'user') or isinstance(request.user, AnonymousUser):
            return False

        # Cache authentication status
        cache_key = f"auth_status_{request.user.id}"
        auth_status = cache.get(cache_key)

        if auth_status is None:
            auth_status = request.user.is_authenticated
            cache.set(cache_key, auth_status, CONFIG.AUTH_STATUS_CACHE_TIMEOUT)

        return auth_status

    def _should_check_session_expiry(self, request):
        """Check if we should verify session expiry (throttled)"""
        if not hasattr(request, 'user') or not request.user.is_authenticated:
            return False

        # Only check expiry every 2 minutes per user
        cache_key = f"session_check_{request.user.id}"
        last_check = cache.get(cache_key)

        if last_check is None:
            cache.set(cache_key, time.time(), 120)
            return True

        return False

    def _check_session_expiry(self, request):
        """Check session expiry with optimized queries"""
        # Import here to avoid circular imports
        from trueAlign.models import UserSession

        user = request.user

        try:
            # Get active session with minimal fields
            session = UserSession.objects.only(
                'id', 'last_activity', 'is_active', 'is_idle', 'idle_start_time'
            ).filter(user=user, is_active=True).first()

            if not session:
                return self._handle_expired_session(request)

            # Check if session is expired
            now = timezone.now()
            idle_threshold = timedelta(minutes=30)

            if session.is_idle and session.idle_start_time:
                idle_time = now - session.idle_start_time
                if idle_time > idle_threshold:
                    return self._handle_expired_session(request)

            # Check for inactivity warning
            if session.last_activity:
                inactive_time = now - session.last_activity
                if inactive_time > timedelta(minutes=25):
                    self._add_session_warning_headers(request, session)

        except Exception as e:
            logger.error(f"Error checking session expiry: {e}")

        return None

    def _handle_unauthenticated_request(self, request):
        """Handle unauthenticated request"""
        if request.path_info.startswith('/api/'):
            return JsonResponse({'error': 'Authentication required'}, status=401)

        from django.shortcuts import redirect
        return redirect('core:login')

    def _handle_expired_session(self, request):
        """Handle expired session"""
        # Import here to avoid circular imports
        from trueAlign.models import UserSession

        # Mark session as inactive and clear caches
        if hasattr(request, 'user') and request.user.is_authenticated:
            UserSession.objects.filter(
                user=request.user, is_active=True
            ).update(is_active=False, session_end_time=timezone.now(), end_reason='timeout')

            # Clear user caches
            invalidate_user_caches(request.user.id)

        if request.path_info.startswith('/api/'):
            return JsonResponse({'error': 'Session expired'}, status=401)

        from django.shortcuts import redirect
        return redirect('core:login')


    def _add_session_warning_headers(self, request, session):
        """Add session warning headers"""
        request.session_warning = True

        if session.is_idle and session.idle_start_time:
            remaining = 30 - (timezone.now() - session.idle_start_time).total_seconds() / 60
            request.session_remaining_time = max(0, remaining)
        else:
            request.session_remaining_time = 5
