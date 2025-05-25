from django.utils import timezone
from datetime import timedelta
from .models import UserSession
import logging
import json
import uuid
import pytz
from django.http import JsonResponse
from django.contrib.auth import logout
from django.core.cache import cache

# Set up logging
logger = logging.getLogger(__name__)

# Asia/Kolkata timezone
IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

def get_current_time_ist():
    """Get current time in Asia/Kolkata timezone"""
    return timezone.now().astimezone(IST_TIMEZONE)

def to_ist(dt):
    """Convert a datetime to Asia/Kolkata timezone"""
    if dt is None:
        return None
    if timezone.is_naive(dt):
        return IST_TIMEZONE.localize(dt)
    return dt.astimezone(IST_TIMEZONE)

def to_utc(dt_ist):
    """Convert IST datetime to UTC for database storage"""
    if dt_ist is None:
        return None
    if timezone.is_naive(dt_ist):
        dt_ist = IST_TIMEZONE.localize(dt_ist)
    return dt_ist.astimezone(timezone.utc)

class EnhancedSessionTrackingMiddleware:
    """
    Enhanced middleware for comprehensive multi-tab session tracking
    with security features and analytics without WebSockets/Celery
    """
    
    def __init__(self, get_response):
        self.get_response = get_response
        
        # Paths to skip processing
        self.skip_paths = [
            '/static/', '/media/', '/favicon.ico',
            '/update-activity/', '/end-session/', '/log-activity/',
            '/session-heartbeat/', '/admin/jsi18n/'
        ]
        
        # Cache keys for rate limiting
        self.rate_limit_cache_prefix = 'session_rate_limit_'
        self.max_requests_per_minute = 60

    def __call__(self, request):
        # Only process authenticated users
        if request.user.is_authenticated and not self._should_skip_path(request.path):
            try:
                # Extract client information
                client_info = self._extract_client_info(request)
                
                # Check rate limiting
                if not self._check_rate_limit(request.user.id, client_info['ip_address']):
                    logger.warning(f"Rate limit exceeded for user {request.user.id} from {client_info['ip_address']}")
                    return JsonResponse({'error': 'Rate limit exceeded'}, status=429)
                
                # Get or create session
                user_session = self._get_or_create_session(request.user, client_info)
                
                # Check for security anomalies
                self._check_security(user_session, client_info)
                
                # Check for auto-logout
                if user_session.should_auto_logout():
                    logger.info(f"Auto-logout triggered for user {request.user.username}")
                    user_session.end_session()
                    logout(request)
                    
                    # For AJAX requests, return JSON
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return JsonResponse({
                            'status': 'expired',
                            'message': 'Your session has expired due to inactivity.',
                            'redirect': '/login/'
                        })
                
                # Store session info in request for views to access
                request.user_session = user_session
                
            except Exception as e:
                logger.error(f"Error in enhanced session tracking middleware: {str(e)}")

        response = self.get_response(request)
        
        # Post-process response if needed
        if hasattr(request, 'user_session') and request.user_session:
            self._post_process_session(request, response)
        
        return response

    def _should_skip_path(self, path):
        """Check if path should be skipped"""
        return any(skip_path in path for skip_path in self.skip_paths)

    def _extract_client_info(self, request):
        """Extract comprehensive client information"""
        # Get client IP
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')
        
        # Extract browser information
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        accept_language = request.META.get('HTTP_ACCEPT_LANGUAGE', '')
        
        # Extract custom headers for enhanced tracking
        tab_id = request.headers.get('X-Tab-ID')
        parent_session_id = request.headers.get('X-Parent-Session-ID')
        device_fingerprint = request.headers.get('X-Device-Fingerprint')
        screen_resolution = request.headers.get('X-Screen-Resolution')
        timezone_offset = request.headers.get('X-Timezone-Offset')
        
        return {
            'ip_address': ip_address,
            'user_agent': user_agent,
            'accept_language': accept_language,
            'tab_id': tab_id,
            'parent_session_id': parent_session_id,
            'device_fingerprint': device_fingerprint,
            'screen_resolution': screen_resolution,
            'timezone_offset': timezone_offset,
            'referrer': request.META.get('HTTP_REFERER', ''),
            'request_path': request.path,
            'request_method': request.method
        }

    def _check_rate_limit(self, user_id, ip_address):
        """Implement rate limiting to prevent abuse"""
        cache_key = f"{self.rate_limit_cache_prefix}{user_id}_{ip_address}"
        current_count = cache.get(cache_key, 0)
        
        if current_count >= self.max_requests_per_minute:
            return False
        
        # Increment counter
        cache.set(cache_key, current_count + 1, 60)  # 60 seconds TTL
        return True

    def _get_or_create_session(self, user, client_info):
        """Get existing session or create new one with enhanced tracking"""
        from django.db import transaction
        
        with transaction.atomic():
            current_time_ist = get_current_time_ist()
            current_time = to_utc(current_time_ist)
            
            # Look for existing active session with same tab_id
            existing_session = None
            if client_info['tab_id']:
                existing_session = UserSession.objects.filter(
                    user=user,
                    tab_id=client_info['tab_id'],
                    is_active=True
                ).select_for_update().first()
            
            # If no specific tab session, look for any active session
            if not existing_session:
                # Look for sessions in the same parent session
                if client_info['parent_session_id']:
                    existing_session = UserSession.objects.filter(
                        user=user,
                        parent_session_id=client_info['parent_session_id'],
                        is_active=True,
                        is_primary_tab=True
                    ).select_for_update().first()
                
                # If still no session, look for any active session
                if not existing_session:
                    existing_session = UserSession.objects.filter(
                        user=user,
                        is_active=True
                    ).select_for_update().first()

            if existing_session:
                # Check if session has expired using IST time comparison
                last_activity_ist = to_ist(existing_session.last_activity)
                inactive_duration = (current_time_ist - last_activity_ist).total_seconds() / 60
                timeout_threshold = existing_session.custom_timeout or existing_session.AUTO_LOGOUT_MINUTES
                
                if inactive_duration > timeout_threshold:
                    # End expired session
                    existing_session.end_session()
                    existing_session = None
                else:
                    # Update existing session
                    self._update_existing_session(existing_session, client_info, current_time, current_time_ist)
                    return existing_session
            
            # Create new session if none exists or expired
            return self._create_new_session(user, client_info, current_time, current_time_ist)

    def _update_existing_session(self, session, client_info, current_time, current_time_ist):
        """Update existing session with new activity"""
        # Calculate time since last activity using IST
        last_activity_ist = to_ist(session.last_activity)
        time_since_last = (current_time_ist - last_activity_ist).total_seconds() / 60
        
        # Only count as idle time if over threshold
        if time_since_last > session.IDLE_THRESHOLD_MINUTES:
            # Add to idle time
            idle_duration = timedelta(minutes=time_since_last)
            session.idle_time += idle_duration
        
        # Update basic fields
        session.last_activity = current_time
        
        # Update IP if changed
        if session.ip_address != client_info['ip_address']:
            session.ip_address = client_info['ip_address']
            session.location = session.determine_location()
        
        # Update device info if provided
        if client_info['screen_resolution'] and session.screen_resolution != client_info['screen_resolution']:
            session.screen_resolution = client_info['screen_resolution']
        
        if client_info['timezone_offset'] and session.timezone_offset != int(client_info['timezone_offset'] or 0):
            session.timezone_offset = int(client_info['timezone_offset'] or 0)
        
        # Update tab information
        if client_info['tab_id'] and not session.tab_id:
            session.tab_id = client_info['tab_id']
        
        session.save(update_fields=[
            'last_activity', 'idle_time', 'ip_address', 'location',
            'screen_resolution', 'timezone_offset', 'tab_id'
        ])

    def _create_new_session(self, user, client_info, current_time, current_time_ist):
        """Create a new session with comprehensive tracking"""
        # Generate IDs if not provided
        tab_id = client_info['tab_id'] or str(uuid.uuid4())
        parent_session_id = client_info['parent_session_id']
        
        if not parent_session_id:
            parent_session_id = f"{user.id}_{current_time_ist.strftime('%Y%m%d_%H%M%S')}"
        
        # Check if this is the first tab in the session
        existing_tabs_count = UserSession.objects.filter(
            user=user,
            parent_session_id=parent_session_id,
            is_active=True
        ).count()
        
        is_primary_tab = existing_tabs_count == 0
        
        # Detect device type
        device_type = self._detect_device_type(client_info['user_agent'])
        
        # Create session
        session = UserSession.objects.create(
            user=user,
            session_key=client_info.get('session_key') or UserSession.generate_session_key(),
            ip_address=client_info['ip_address'],
            user_agent=client_info['user_agent'],
            login_time=current_time,
            last_activity=current_time,
            tab_id=tab_id,
            tab_opened_time=current_time,
            tab_last_focus=current_time,
            is_primary_tab=is_primary_tab,
            parent_session_id=parent_session_id,
            session_fingerprint=client_info['device_fingerprint'],
            device_type=device_type,
            screen_resolution=client_info['screen_resolution'],
            timezone_offset=int(client_info['timezone_offset'] or 0),
            language=self._extract_language(client_info['accept_language']),
            tab_url=client_info['request_path'],
            is_active=True
        )
        
        # Set location
        session.location = session.determine_location()
        session.save(update_fields=['location'])
        
        logger.info(f"Created new session for user {user.username}, tab_id: {tab_id}, primary: {is_primary_tab}")
        
        return session

    def _detect_device_type(self, user_agent):
        """Detect device type from user agent"""
        user_agent_lower = user_agent.lower()
        
        if any(mobile in user_agent_lower for mobile in ['mobile', 'android', 'iphone', 'ipod']):
            return 'mobile'
        elif any(tablet in user_agent_lower for tablet in ['ipad', 'tablet']):
            return 'tablet'
        else:
            return 'desktop'

    def _extract_language(self, accept_language):
        """Extract primary language from Accept-Language header"""
        if not accept_language:
            return 'en'
        
        # Parse Accept-Language header
        languages = accept_language.split(',')
        if languages:
            primary_lang = languages[0].split(';')[0].strip()
            return primary_lang[:10]  # Limit length
        
        return 'en'

    def _check_security(self, session, client_info):
        """Perform security checks"""
        try:
            # Check for fingerprint changes
            if client_info['device_fingerprint'] and session.session_fingerprint:
                if client_info['device_fingerprint'] != session.session_fingerprint:
                    logger.warning(f"Device fingerprint mismatch for user {session.user.username}")
                    
                    # Record security incident
                    if not session.security_incidents:
                        session.security_incidents = {}
                    
                    current_time_ist = get_current_time_ist()
                    incident_key = f"fingerprint_mismatch_{current_time_ist.strftime('%Y%m%d_%H%M%S')}"
                    session.security_incidents[incident_key] = {
                        'type': 'fingerprint_mismatch',
                        'old_fingerprint': session.session_fingerprint,
                        'new_fingerprint': client_info['device_fingerprint'],
                        'timestamp': current_time_ist.isoformat(),
                        'ip_address': client_info['ip_address'],
                        'user_agent': client_info['user_agent']
                    }
                    
                    session.save(update_fields=['security_incidents'])
            
            # Check for unusual IP changes
            if session.ip_address and client_info['ip_address']:
                if session.ip_address != client_info['ip_address']:
                    # Log IP change
                    logger.info(f"IP address changed for user {session.user.username}: {session.ip_address} -> {client_info['ip_address']}")
            
            # Check for rapid requests (potential bot behavior)
            cache_key = f"rapid_requests_{session.user.id}_{session.tab_id}"
            request_count = cache.get(cache_key, 0)
            
            if request_count > 30:  # More than 30 requests per minute from same tab
                logger.warning(f"Rapid requests detected for user {session.user.username}, tab {session.tab_id}")
                
                if not session.security_incidents:
                    session.security_incidents = {}
                
                incident_key = f"rapid_requests_{timezone.now().strftime('%Y%m%d_%H%M%S')}"
                session.security_incidents[incident_key] = {
                    'type': 'rapid_requests',
                    'request_count': request_count,
                    'timestamp': timezone.now().isoformat(),
                    'tab_id': session.tab_id
                }
                
                session.save(update_fields=['security_incidents'])
            
            cache.set(cache_key, request_count + 1, 60)  # 60 seconds TTL
            
        except Exception as e:
            logger.error(f"Error in security checks: {str(e)}")

    def _post_process_session(self, request, response):
        """Post-process session after response"""
        try:
            session = request.user_session
            
            # Update page view if this was a page request
            if request.method == 'GET' and not request.headers.get('X-Requested-With'):
                if not session.page_views:
                    session.page_views = []
                
                # Avoid duplicate consecutive page views
                current_url = request.get_full_path()
                if not session.page_views or session.page_views[-1].get('url') != current_url:
                    session.page_views.append({
                        'url': current_url,
                        'timestamp': timezone.now().isoformat(),
                        'referrer': request.META.get('HTTP_REFERER', ''),
                        'method': request.method
                    })
                    
                    # Keep only last 100 page views to avoid excessive data
                    if len(session.page_views) > 100:
                        session.page_views = session.page_views[-100:]
                    
                    session.save(update_fields=['page_views'])
            
            # Add session info to response headers for client-side tracking
            if hasattr(response, '__setitem__'):
                response['X-Session-ID'] = session.parent_session_id
                response['X-Tab-ID'] = session.tab_id
                response['X-Is-Primary-Tab'] = str(session.is_primary_tab).lower()
                
                # Add warning if approaching timeout
                if session.should_show_inactivity_warning():
                    response['X-Inactivity-Warning'] = 'true'
                    current_time_ist = get_current_time_ist()
                    last_activity_ist = to_ist(session.last_activity)
                    inactive_minutes = (current_time_ist - last_activity_ist).total_seconds() / 60
                    timeout_threshold = session.custom_timeout or session.AUTO_LOGOUT_MINUTES
                    remaining_minutes = max(0, timeout_threshold - inactive_minutes)
                    response['X-Remaining-Minutes'] = str(int(remaining_minutes))
        
        except Exception as e:
            logger.error(f"Error in post-processing session: {str(e)}")


class SessionAnalyticsMiddleware:
    """
    Middleware for collecting session analytics without impacting performance
    """
    
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Process request
        response = self.get_response(request)
        
        # Collect analytics asynchronously (in production, use a queue)
        if hasattr(request, 'user_session') and request.user_session:
            try:
                self._collect_analytics(request, response)
            except Exception as e:
                logger.error(f"Error collecting analytics: {str(e)}")
        
        return response

    def _collect_analytics(self, request, response):
        """Collect analytics data"""
        session = request.user_session
        
        # Performance metrics
        if hasattr(request, 'session') and 'performance_start' in request.session:
            current_time_ist = get_current_time_ist()
            response_time = current_time_ist - request.session['performance_start']
            
            if not session.performance_metrics:
                session.performance_metrics = {}
            
            if 'response_times' not in session.performance_metrics:
                session.performance_metrics['response_times'] = []
            
            session.performance_metrics['response_times'].append({
                'url': request.path,
                'method': request.method,
                'response_time_ms': response_time.total_seconds() * 1000,
                'status_code': response.status_code,
                'timestamp': current_time_ist.isoformat()
            })
            
            # Keep only last 50 response times
            if len(session.performance_metrics['response_times']) > 50:
                session.performance_metrics['response_times'] = session.performance_metrics['response_times'][-50:]
            
            session.save(update_fields=['performance_metrics'])