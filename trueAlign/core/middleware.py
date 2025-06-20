import time
import json
import logging
import ipaddress
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import AnonymousUser
from django.urls import resolve, Resolver404
from trueAlign.models import UserSession
from .utils import get_client_ip, parse_user_agent, get_location_from_ip, detect_suspicious_activity, calculate_productivity_score, to_ist, to_utc, get_current_time_ist

# Set up logging
logger = logging.getLogger(__name__)

class SessionTrackingMiddleware:
    """Middleware for tracking user sessions with enhanced security and analytics"""
    
    def __init__(self, get_response):
        self.get_response = get_response
        # Load settings
        self.idle_threshold = getattr(settings, 'ENHANCED_SESSION_CONFIG', {}).get('IDLE_THRESHOLD_MINUTES', 15)
        self.auto_logout = getattr(settings, 'ENHANCED_SESSION_CONFIG', {}).get('AUTO_LOGOUT_MINUTES', 30)
        self.heartbeat_interval = getattr(settings, 'ENHANCED_SESSION_CONFIG', {}).get('HEARTBEAT_INTERVAL_SECONDS', 60)
        
        # Paths to skip tracking
        self.skip_paths = [
            '/static/',
            '/media/',
            '/favicon.ico',
            '/session/heartbeat/',
            '/session/update-activity/',
            '/api/health/',
            '/__debug__/',
        ]
        
        # Rate limiting settings
        self.rate_limit_window = 60  # seconds
        self.rate_limit_max_requests = 100  # max requests per window
        self.rate_limits = {}  # Store rate limit data
    
    def __call__(self, request):
        # Skip tracking for certain paths
        if self._should_skip(request):
            return self.get_response(request)
        
        # Start timing for performance metrics
        start_time = time.time()
        
        # Process request
        if request.user.is_authenticated:
            self._process_authenticated_request(request)
        
        # Get response
        response = self.get_response(request)
        
        # Process response
        if request.user.is_authenticated:
            self._process_authenticated_response(request, response, start_time)
        
        return response
    
    def _should_skip(self, request):
        """Check if tracking should be skipped for this request"""
        path = request.path
        
        # Skip static files and other non-tracked paths
        for skip_path in self.skip_paths:
            if path.startswith(skip_path):
                return True
        
        # Skip OPTIONS requests (CORS preflight)
        if request.method == 'OPTIONS':
            return True
        
        return False
    
    def _process_authenticated_request(self, request):
        """Process request for authenticated users"""
        try:
            # Extract client information
            client_info = self._extract_client_info(request)
            
            # Check rate limiting
            if not self._check_rate_limit(request.user.id, client_info['ip_address']):
                logger.warning(f"Rate limit exceeded for user {request.user.username} from IP {client_info['ip_address']}")
                return
            
            # Get or create session
            session = self._get_or_create_session(request, client_info)
            
            # Store session in request for later use
            request.user_session = session
            
            # Perform security checks
            self._perform_security_checks(request, session, client_info)
            
            # Check for auto-logout
            if session.last_activity:
                idle_time = timezone.now() - session.last_activity
                idle_minutes = idle_time.total_seconds() / 60
                
                if idle_minutes > self.auto_logout:
                    # Auto-logout due to inactivity
                    session.end_session(is_idle=True)
                    logger.info(f"Auto-logout for user {request.user.username} due to inactivity")
                    
                    # Create a new session
                    session = self._get_or_create_session(request, client_info, force_new=True)
                    request.user_session = session
        
        except Exception as e:
            logger.error(f"Error in session tracking middleware: {e}")
    
    def _extract_client_info(self, request):
        """Extract client information from request"""
        # Get IP address
        ip_address = get_client_ip(request)
        
        # Get user agent
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Get custom headers
        tab_id = request.META.get('HTTP_X_TAB_ID', '')
        parent_session_id = request.META.get('HTTP_X_PARENT_SESSION_ID', '')
        device_fingerprint = request.META.get('HTTP_X_DEVICE_FINGERPRINT', '')
        
        # Parse user agent
        ua_data = parse_user_agent(user_agent)
        
        # Get location data
        location_data = get_location_from_ip(ip_address)
        
        return {
            'ip_address': ip_address,
            'user_agent': user_agent,
            'tab_id': tab_id,
            'parent_session_id': parent_session_id,
            'device_fingerprint': device_fingerprint,
            'ua_data': ua_data,
            'location_data': location_data,
            'request_time': timezone.now(),
            'path': request.path,
            'method': request.method,
            'is_ajax': request.headers.get('X-Requested-With') == 'XMLHttpRequest',
            'is_mobile': ua_data.get('is_mobile', False),
            'is_tablet': ua_data.get('is_tablet', False),
            'is_bot': ua_data.get('is_bot', False)
        }
    
    def _check_rate_limit(self, user_id, ip_address):
        """Check if request exceeds rate limit"""
        current_time = time.time()
        key = f"{user_id}:{ip_address}"
        
        # Initialize rate limit data if not exists
        if key not in self.rate_limits:
            self.rate_limits[key] = {
                'requests': 0,
                'window_start': current_time
            }
        
        # Reset window if expired
        if current_time - self.rate_limits[key]['window_start'] > self.rate_limit_window:
            self.rate_limits[key] = {
                'requests': 0,
                'window_start': current_time
            }
        
        # Increment request count
        self.rate_limits[key]['requests'] += 1
        
        # Check if limit exceeded
        return self.rate_limits[key]['requests'] <= self.rate_limit_max_requests
    
    def _get_or_create_session(self, request, client_info, force_new=False):
        """Get existing session or create a new one"""
        user = request.user
        tab_id = client_info.get('tab_id')
        parent_session_id = client_info.get('parent_session_id')
        
        # Try to get existing session
        if not force_new and tab_id:
            session = UserSession.objects.filter(
                user=user,
                tab_id=tab_id,
                is_active=True
            ).first()
            
            if session:
                # Update existing session
                return self._update_existing_session(session, request, client_info)
        
        # Try to get session by parent_session_id
        if not force_new and parent_session_id:
            session = UserSession.objects.filter(
                user=user,
                parent_session_id=parent_session_id,
                is_active=True
            ).first()
            
            if session:
                # Update existing session
                return self._update_existing_session(session, request, client_info)
        
        # Create new session
        return self._create_new_session(request, client_info)
    
    def _update_existing_session(self, session, request, client_info):
        """Update existing session with new activity"""
        # Calculate idle time
        current_time = timezone.now()
        if session.last_activity:
            idle_time = current_time - session.last_activity
            idle_seconds = idle_time.total_seconds()
            
            # Update idle time if user was idle
            if idle_seconds > (self.idle_threshold * 60):
                session.idle_time += idle_time
        
        # Update session data
        session.last_activity = current_time
        session.ip_address = client_info.get('ip_address')
        
        # Update device info if changed
        if client_info.get('ua_data'):
            ua_data = client_info.get('ua_data')
            session.browser = ua_data.get('browser')
            session.browser_version = ua_data.get('browser_version')
            session.os = ua_data.get('os')
            session.os_version = ua_data.get('os_version')
            session.device_type = ua_data.get('device')
        
        # Update tab info
        if hasattr(request, 'path_info'):
            session.tab_url = request.path_info
        
        # Update location if changed
        if client_info.get('location_data'):
            location_data = client_info.get('location_data')
            
            # Update location fields if they exist in the model
            if hasattr(session, 'location_country') and location_data.get('country'):
                session.location_country = location_data.get('country')
            
            if hasattr(session, 'location_city') and location_data.get('city'):
                session.location_city = location_data.get('city')
            
            if hasattr(session, 'location_region') and location_data.get('region'):
                session.location_region = location_data.get('region')
            
            if hasattr(session, 'location_latitude') and location_data.get('latitude'):
                session.location_latitude = location_data.get('latitude')
            
            if hasattr(session, 'location_longitude') and location_data.get('longitude'):
                session.location_longitude = location_data.get('longitude')
            
            # Add to location history if the field exists
            if hasattr(session, 'location_history'):
                if not session.location_history:
                    session.location_history = []
                
                session.location_history.append({
                    'timestamp': current_time.isoformat(),
                    'country': location_data.get('country'),
                    'city': location_data.get('city'),
                    'ip_address': client_info.get('ip_address'),
                    'latitude': location_data.get('latitude'),
                    'longitude': location_data.get('longitude')
                })
        
        session.save()
        return session
    
    def _create_new_session(self, request, client_info):
        """Create a new session"""
        user = request.user
        current_time = timezone.now()
        
        # Extract data
        tab_id = client_info.get('tab_id')
        parent_session_id = client_info.get('parent_session_id')
        ip_address = client_info.get('ip_address')
        user_agent = client_info.get('user_agent')
        device_fingerprint = client_info.get('device_fingerprint')
        
        # Parse user agent
        ua_data = client_info.get('ua_data', {})
        
        # Get location data
        location_data = client_info.get('location_data', {})
        
        # Create session data
        session_data = {
            'user': user,
            'session_key': request.session.session_key,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'login_time': current_time,
            'last_activity': current_time,
            'tab_id': tab_id,
            'parent_session_id': parent_session_id,
            'device_fingerprint': device_fingerprint,
            'browser': ua_data.get('browser'),
            'browser_version': ua_data.get('browser_version'),
            'os': ua_data.get('os'),
            'os_version': ua_data.get('os_version'),
            'device_type': ua_data.get('device'),
            'is_mobile': ua_data.get('is_mobile', False),
            'is_tablet': ua_data.get('is_tablet', False),
            'is_bot': ua_data.get('is_bot', False),
            'tab_url': request.path_info if hasattr(request, 'path_info') else '',
            'tab_title': '',  # Will be updated by client
            'tab_opened_time': current_time,
            'is_primary_tab': not parent_session_id,  # Primary if no parent
            'location_history': [{
                'timestamp': current_time.isoformat(),
                'ip_address': ip_address,
                'country': location_data.get('country'),
                'city': location_data.get('city'),
                'latitude': location_data.get('latitude'),
                'longitude': location_data.get('longitude')
            }] if location_data else []
        }
        
        # Add location data if fields exist in the model
        from trueAlign.models import UserSession
        session_model_fields = [field.name for field in UserSession._meta.get_fields()]
        
        if 'location_country' in session_model_fields and location_data.get('country'):
            session_data['location_country'] = location_data.get('country')
            
        if 'location_city' in session_model_fields and location_data.get('city'):
            session_data['location_city'] = location_data.get('city')
            
        if 'location_region' in session_model_fields and location_data.get('region'):
            session_data['location_region'] = location_data.get('region')
            
        if 'location_latitude' in session_model_fields and location_data.get('latitude'):
            session_data['location_latitude'] = location_data.get('latitude')
            
        if 'location_longitude' in session_model_fields and location_data.get('longitude'):
            session_data['location_longitude'] = location_data.get('longitude')
                # This section is no longer needed as we've already updated the location_history format above
        
        
        # Create session
        session = UserSession.objects.create(**session_data)
        logger.info(f"New session created for user {user.username}, session ID: {session.id}")
        
        return session
    
    def _perform_security_checks(self, request, session, client_info):
        """Perform security checks on the session"""
        # Check for suspicious activity
        suspicious_indicators = detect_suspicious_activity(session, request)
        
        if suspicious_indicators:
            # Log suspicious activity
            for indicator in suspicious_indicators:
                logger.warning(f"Suspicious activity detected: {indicator['type']} (Severity: {indicator['severity']}) - User: {request.user.username}, Session: {session.id}")
                
                # Add to security log
                if not session.security_events:
                    session.security_events = []
                
                session.security_events.append({
                    'timestamp': timezone.now().isoformat(),
                    'type': indicator['type'],
                    'severity': indicator['severity'],
                    'details': indicator['details'],
                    'path': request.path,
                    'method': request.method
                })
            
            # Save session with security events
            session.save(update_fields=['security_events'])
    
    def _process_authenticated_response(self, request, response, start_time):
        """Process response for authenticated users"""
        try:
            if hasattr(request, 'user_session'):
                session = request.user_session
                
                # Update page views
                if request.method == 'GET' and response.status_code == 200:
                    # Skip AJAX requests
                    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
                    if not is_ajax:
                        self._update_page_views(request, session)
                
                # Add session headers to response
                self._add_session_headers(request, response, session)
                
                # Add performance metrics
                self._add_performance_metrics(request, response, session, start_time)
        
        except Exception as e:
            logger.error(f"Error processing response in session tracking middleware: {e}")
    
    def _update_page_views(self, request, session):
        """Update page views for the session"""
        try:
            # Get current URL and title
            current_url = request.path
            
            # Skip if this is the same as the last page view (avoid duplicates)
            if session.page_views and len(session.page_views) > 0:
                last_view = session.page_views[-1]
                if last_view.get('url') == current_url:
                    return
            
            # Add page view
            if not session.page_views:
                session.page_views = []
            
            session.page_views.append({
                'url': current_url,
                'title': '',  # Will be updated by client
                'timestamp': timezone.now().isoformat(),
                'referrer': request.META.get('HTTP_REFERER', '')
            })
            
            # Save session
            session.save(update_fields=['page_views'])
            
        except Exception as e:
            logger.error(f"Error updating page views: {e}")
    
    def _add_session_headers(self, request, response, session):
        """Add session-related headers to response"""
        # Add session ID header
        response['X-Session-ID'] = str(session.id)
        
        # Add tab ID header if available
        if session.tab_id:
            response['X-Tab-ID'] = session.tab_id
        
        # Add primary tab indicator
        response['X-Is-Primary-Tab'] = 'true' if session.is_primary_tab else 'false'
        
        # Add inactivity warning if needed
        if session.last_activity:
            idle_time = timezone.now() - session.last_activity
            idle_minutes = idle_time.total_seconds() / 60
            
            if idle_minutes >= self.idle_threshold:
                response['X-Inactivity-Warning'] = 'true'
                response['X-Remaining-Minutes'] = str(int(self.auto_logout - idle_minutes))
    
    def _add_performance_metrics(self, request, response, session, start_time):
        """Add performance metrics to session"""
        try:
            # Calculate response time
            response_time = time.time() - start_time
            
            # Create metrics entry
            metrics = {
                'timestamp': timezone.now().isoformat(),
                'url': request.path,
                'method': request.method,
                'status_code': response.status_code,
                'response_time': response_time,
                'is_ajax': request.headers.get('X-Requested-With') == 'XMLHttpRequest'
            }
            
            # Add to session metrics
            if not session.performance_metrics:
                session.performance_metrics = []
            
            # Keep only the last 50 entries
            session.performance_metrics.append(metrics)
            if len(session.performance_metrics) > 50:
                session.performance_metrics = session.performance_metrics[-50:]
            
            # Save session
            session.save(update_fields=['performance_metrics'])
            
        except Exception as e:
            logger.error(f"Error adding performance metrics: {e}")


class SessionAnalyticsMiddleware:
    """Middleware for collecting session analytics"""
    
    def __init__(self, get_response):
        self.get_response = get_response
    
    def __call__(self, request):
        # Start timing
        start_time = time.time()
        
        # Process request
        response = self.get_response(request)
        
        # Process response for authenticated users
        if request.user.is_authenticated and hasattr(request, 'user_session'):
            self._collect_analytics(request, response, start_time)
        
        return response
    
    def _collect_analytics(self, request, response, start_time):
        """Collect analytics data for the session"""
        try:
            session = request.user_session
            
            # Calculate response time
            response_time = time.time() - start_time
            
            # Create analytics entry
            analytics = {
                'timestamp': timezone.now().isoformat(),
                'url': request.path,
                'method': request.method,
                'status_code': response.status_code,
                'response_time': response_time,
                'is_ajax': request.headers.get('X-Requested-With') == 'XMLHttpRequest',
                'content_type': response.get('Content-Type', ''),
                'content_length': response.get('Content-Length', 0)
            }
            
            # Add to session analytics
            if not session.performance_metrics:
                session.performance_metrics = []
            
            # Keep only the last 50 entries
            session.performance_metrics.append(analytics)
            if len(session.performance_metrics) > 50:
                session.performance_metrics = session.performance_metrics[-50:]
            
            # Save session
            session.save(update_fields=['performance_metrics'])
            
        except Exception as e:
            logger.error(f"Error collecting analytics: {e}")