import json
import time
import logging
import uuid
from datetime import datetime, timedelta
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.views import (
    PasswordResetView, PasswordResetDoneView,
    PasswordResetConfirmView, PasswordResetCompleteView
)
from django.contrib.auth.forms import AuthenticationForm
from django.shortcuts import render, redirect
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.core.cache import cache
from django.db import transaction
from django.conf import settings
from django.contrib import messages
from django.urls import reverse_lazy
from trueAlign.models import UserSession
from .middleware import OptimizedSessionTrackingMiddleware
from .session_config import CONFIG
from .signals import (
    get_cached_session, cache_session, invalidate_user_caches,
    handle_suspicious_activity, trigger_maintenance_if_needed
)
from .utils import (
    get_client_ip, parse_user_agent, calculate_productivity_score,
    to_ist, get_current_time_ist, format_duration, detect_suspicious_activity
)

logger = logging.getLogger(__name__)

# =============================================================================
# AUTHENTICATION VIEWS
# =============================================================================

def home_view(request):
    """Home page view - redirects to dashboard if authenticated"""
    if request.user.is_authenticated:
        return redirect('core:dashboard')
    return redirect('core:login')

def login_view(request):
    """Optimized login view with session tracking"""
    if request.user.is_authenticated:
        return redirect('core:dashboard')

    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)

            if user is not None:
                login(request, user)

                # Clear any existing session caches
                invalidate_user_caches(user.id)

                # Log successful login
                logger.info(f"User {user.username} logged in successfully")

                # Redirect to dashboard
                next_url = request.GET.get('next', 'core:dashboard')
                return redirect(next_url)
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = AuthenticationForm()

    return render(request, 'login.html', {'form': form})

def logout_view(request):
    """Optimized logout view with session cleanup"""
    if request.user.is_authenticated:
        user = request.user

        # Get all active sessions before ending them
        active_sessions = UserSession.objects.filter(
            user=user, is_active=True
        )

        # End all active sessions
        active_sessions.update(
            is_active=False,
            session_end_time=timezone.now(),
            ended_at=timezone.now(),  # Update both fields for compatibility
            end_reason='logout'
        )

        # Clear user caches
        invalidate_user_caches(user.id)

        # Force flush any remaining buffers
        if hasattr(OptimizedSessionTrackingMiddleware, 'force_flush_user_buffer'):
            # We already have the active_sessions that were just updated to inactive
            for session in active_sessions:
                try:
                    OptimizedSessionTrackingMiddleware.force_flush_user_buffer(user.id, session.id)
                except Exception as e:
                    logger.error(f"Error flushing buffer for session {session.id}: {str(e)}")

        logger.info(f"User {user.username} logged out")

        # Django logout
        logout(request)
        messages.success(request, 'You have been logged out successfully.')

    return redirect('core:login')

# =============================================================================
# PASSWORD RESET VIEWS
# =============================================================================

class CustomPasswordResetView(PasswordResetView):
    template_name = 'auth/password_reset.html'
    email_template_name = 'auth/password_reset_email.html'
    subject_template_name = 'auth/password_reset_subject.txt'
    success_url = reverse_lazy('core:password_reset_done')

    def form_valid(self, form):
        messages.success(self.request, 'Password reset email sent successfully.')
        return super().form_valid(form)

class CustomPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'auth/password_reset_done.html'

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'auth/password_reset_confirm.html'
    success_url = reverse_lazy('core:password_reset_complete')

    def form_valid(self, form):
        messages.success(self.request, 'Password reset successfully.')
        return super().form_valid(form)

class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'auth/password_reset_complete.html'

# =============================================================================
# OPTIMIZED SESSION TRACKING VIEWS
# =============================================================================

@csrf_exempt
@require_http_methods(["POST"])
@login_required
def optimized_session_heartbeat(request):
    """
    Optimized heartbeat endpoint with throttling and batching
    Enhanced with better data validation and error handling
    """
    try:
        # Parse request data with better error handling
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            data = {}
        except Exception as e:
            logger.warning(f"Error parsing request body: {e}")
            data = {}

        # Extract and validate identifiers
        tab_id = data.get('tab_id') or request.headers.get('X-Tab-ID')
        parent_session_id = data.get('parent_session_id') or request.headers.get('X-Parent-Session-ID')
        session_fingerprint = data.get('session_fingerprint') or request.headers.get('X-Session-Fingerprint')

        # Validate tab_id (generate if missing)
        if not tab_id:
            tab_id = str(uuid.uuid4())
            logger.info(f"Generated missing tab_id: {tab_id}")

        user_id = request.user.id
        current_time = time.time()

        # Check throttle with better validation
        throttle_key = f"heartbeat_throttle_{user_id}_{tab_id}"
        last_heartbeat = cache.get(throttle_key)
        throttle_interval = getattr(CONFIG, 'HEARTBEAT_THROTTLE_INTERVAL', 30)

        if last_heartbeat and (current_time - last_heartbeat) < throttle_interval:
            # Return cached response but ensure we still have valid data
            cached_response = cache.get(f"heartbeat_response_{user_id}_{tab_id}")
            if cached_response and isinstance(cached_response, dict):
                # Update timestamp
                cached_response['timestamp'] = timezone.now().isoformat()
                return JsonResponse(cached_response)

        # Get or create session using improved logic
        from trueAlign.models import UserSession, SessionActivity

        # Prepare comprehensive client data with validation
        client_data = {
            'ip_address': get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'session_fingerprint': session_fingerprint or '',
            'browser_fingerprint': session_fingerprint or '',
            'device_type': data.get('device_type', 'unknown'),
            'screen_resolution': request.headers.get('X-Screen-Resolution') or data.get('screen_resolution'),
            'timezone_offset': request.headers.get('X-Timezone-Offset') or data.get('timezone_offset'),
            'language': request.headers.get('X-Language') or data.get('language'),
            'url': data.get('url', ''),
            'title': data.get('title', ''),
        }

        # Validate and convert numeric fields
        try:
            if client_data['timezone_offset']:
                client_data['timezone_offset'] = int(client_data['timezone_offset'])
        except (ValueError, TypeError):
            client_data['timezone_offset'] = None

        # Add location data if provided with validation
        location_data = data.get('location')
        if location_data or data.get('location_latitude'):
            client_data['location_data'] = {
                'latitude': data.get('location_latitude') or (location_data.get('latitude') if location_data else None),
                'longitude': data.get('location_longitude') or (location_data.get('longitude') if location_data else None),
                'accuracy': data.get('location_accuracy') or (location_data.get('accuracy') if location_data else None),
            }

        session, created = UserSession.get_or_create_session(
            user=request.user,
            tab_id=tab_id,
            parent_session_id=parent_session_id,
            client_data=client_data,
            session_key=UserSession.generate_session_key()
        )

        if not session:
            logger.error("Failed to get or create session")
            return JsonResponse({'error': 'Could not create session'}, status=500)

        # Record heartbeat activity
        try:
            SessionActivity.record_activity(
                session=session,
                activity_type='heartbeat',
                activity_data={
                    'is_idle': data.get('is_idle', False),
                    'is_visible': data.get('is_visible', True),
                    'productivity_score': data.get('productivity_score'),
                    'engagement_score': data.get('engagement_score'),
                    'browser': data.get('browser'),
                    'os': data.get('os'),
                    'fingerprint': session_fingerprint,
                },
                url=data.get('url'),
                title=data.get('title'),
                location_data=client_data.get('location_data')
            )
        except Exception as activity_error:
            logger.warning(f"Error recording heartbeat activity: {activity_error}")

        # Update session status based on heartbeat data
        is_idle = data.get('is_idle', False)
        session.update_idle_status(is_idle)

        # Update last activity (already done in get_or_create_session, but ensure it's current)
        session.last_activity = timezone.now()
        session.save(update_fields=['last_activity'])

        # Get recent activity summary
        activity_summary = SessionActivity.get_activity_summary(session)

        # Calculate session status
        session_status = _calculate_session_status(session)

        # Prepare response
        response_data = {
            'status': 'success',
            'session_id': str(session.id),
            'parent_session_id': str(session.parent_session_id) if session.parent_session_id else None,
            'is_active': session.is_active,
            'is_idle': session.is_idle,
            'session_status': session_status,
            'activity_summary': activity_summary,
            'last_activity': session.last_activity.isoformat() if session.last_activity else None,
            'session_duration': session.get_session_duration(),
            'working_time': session.get_working_time_minutes(),
            'idle_time': session.get_idle_time(),
            'created': created,
            'timestamp': timezone.now().isoformat()
        }

        # Cache response and throttle
        cache.set(f"heartbeat_response_{user_id}_{tab_id}", response_data, getattr(CONFIG, 'HEARTBEAT_CACHE_TIMEOUT', 300))
        cache.set(throttle_key, current_time, getattr(CONFIG, 'HEARTBEAT_THROTTLE_INTERVAL', 30))

        return JsonResponse(response_data)

    except Exception as e:
        logger.error(f"Error in optimized heartbeat: {str(e)}", exc_info=True)
        return JsonResponse({'error': 'Internal server error'}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
@login_required
def optimized_batch_activity_update(request):
    """
    Optimized batch activity update endpoint
    """
    try:
        # Handle both JSON and form data
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            # Try to get from POST data
            data = request.POST.dict()
            # Convert any string representations of lists/dicts to actual objects
            for key, value in data.items():
                if isinstance(value, str) and (value.startswith('[') or value.startswith('{')):
                    try:
                        data[key] = json.loads(value)
                    except json.JSONDecodeError:
                        pass

        tab_id = data.get('tab_id') or request.headers.get('X-Tab-ID')
        activities = data.get('activities', [])

        # If activities is a string (from form data), try to parse it
        if isinstance(activities, str):
            try:
                activities = json.loads(activities)
            except json.JSONDecodeError:
                activities = []

        # Allow empty activities for heartbeat/ping purposes
        if activities is None:
            activities = []

        user_id = request.user.id

        # Check throttle
        throttle_key = f"batch_update_throttle_{user_id}_{tab_id}"
        last_update = cache.get(throttle_key)
        current_time = time.time()

        if last_update and (current_time - last_update) < getattr(CONFIG, 'ACTIVITY_THROTTLE_INTERVAL', 60):
            return JsonResponse({'status': 'throttled', 'retry_after': getattr(CONFIG, 'ACTIVITY_THROTTLE_INTERVAL', 60)})

        # Extract session identifiers
        parent_session_id = data.get('parent_session_id') or request.headers.get('X-Parent-Session-ID')
        session_fingerprint = data.get('session_fingerprint') or request.headers.get('X-Session-Fingerprint')

        # Prepare client data
        client_data = {
            'ip_address': request.META.get('REMOTE_ADDR'),
            'user_agent': request.META.get('HTTP_USER_AGENT'),
            'session_fingerprint': session_fingerprint,
            'browser_fingerprint': session_fingerprint,
            'device_type': data.get('device_type'),
            'screen_resolution': request.headers.get('X-Screen-Resolution'),
            'timezone_offset': request.headers.get('X-Timezone-Offset'),
            'language': request.headers.get('X-Language'),
        }

        # Get or create session
        from trueAlign.models import UserSession, SessionActivity
        session, created = UserSession.get_or_create_session(
            user=request.user,
            tab_id=tab_id,
            parent_session_id=parent_session_id,
            client_data=client_data,
            session_key=UserSession.generate_session_key()
        )

        if not session:
            logger.error("Failed to get or create session")
            return JsonResponse({'error': 'Could not create session'}, status=500)

        # Process batch activities using SessionActivity model
        processed_count = 0
        for activity in activities:
            try:
                activity_type = activity.get('type', 'unknown')
                activity_data = activity.get('data', {})
                url = activity.get('url')
                title = activity.get('title')
                location_data = activity.get('location')

                SessionActivity.record_activity(
                    session=session,
                    activity_type=activity_type,
                    activity_data=activity_data,
                    url=url,
                    title=title,
                    location_data=location_data
                )
                processed_count += 1
            except Exception as activity_error:
                logger.warning(f"Error recording activity: {activity_error}")

        # Update session last activity
        session.last_activity = timezone.now()
        session.save(update_fields=['last_activity'])

        # Set throttle
        cache.set(throttle_key, current_time, getattr(CONFIG, 'ACTIVITY_THROTTLE_INTERVAL', 60))

        return JsonResponse({
            'status': 'success',
            'processed_count': processed_count,
            'session_id': str(session.id),
            'parent_session_id': str(session.parent_session_id) if session.parent_session_id else None,
            'created': created,
            'timestamp': timezone.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error in batch activity update: {str(e)}", exc_info=True)
        return JsonResponse({'error': 'Internal server error'}, status=500)

@csrf_exempt
@require_http_methods(["GET", "POST"])
@login_required
def optimized_session_status(request):
    """
    Get current session status with caching
    """
    try:
        # Handle both GET and POST methods
        if request.method == 'GET':
            tab_id = request.GET.get('tab_id') or request.headers.get('X-Tab-ID')
        else:  # POST
            try:
                data = json.loads(request.body)
                tab_id = data.get('tab_id')
            except json.JSONDecodeError:
                tab_id = request.POST.get('tab_id')

        tab_id = tab_id or request.headers.get('X-Tab-ID')
        user_id = request.user.id

        # Check cache first
        cache_key = f"session_status_{user_id}_{tab_id}"
        cached_status = cache.get(cache_key)

        if cached_status:
            return JsonResponse(cached_status)

        # Extract session identifiers
        parent_session_id = request.headers.get('X-Parent-Session-ID')
        session_fingerprint = request.headers.get('X-Session-Fingerprint')

        # Prepare minimal client data for session lookup
        client_data = {
            'ip_address': request.META.get('REMOTE_ADDR'),
            'user_agent': request.META.get('HTTP_USER_AGENT'),
            'session_fingerprint': session_fingerprint,
            'browser_fingerprint': session_fingerprint,
        }

        # Get or create session
        from trueAlign.models import UserSession, SessionActivity
        session, created = UserSession.get_or_create_session(
            user=request.user,
            tab_id=tab_id,
            parent_session_id=parent_session_id,
            client_data=client_data,
            session_key=UserSession.generate_session_key()
        )
        if not session:
            return JsonResponse({'error': 'No active session found'}, status=404)

        # Calculate comprehensive status
        status_data = _calculate_session_status(session)

        # Cache the status
        cache.set(cache_key, status_data, CONFIG.STATUS_CACHE_TIMEOUT)

        return JsonResponse(status_data)

    except Exception as e:
        logger.error(f"Error getting session status: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
@login_required
def optimized_end_session(request):
    """
    End current session with cleanup
    """
    try:
        data = json.loads(request.body)
        tab_id = data.get('tab_id') or request.headers.get('X-Tab-ID')
        end_reason = data.get('reason', 'manual')

        # Get session
        session = _get_session_optimized(request.user, tab_id)
        if not session:
            return JsonResponse({'error': 'No active session found'}, status=404)

        # Force flush any remaining buffer data
        OptimizedSessionTrackingMiddleware.force_flush_user_buffer(request.user.id, session.id)

        # End session
        session.is_active = False
        session.session_end_time = timezone.now()
        session.end_reason = end_reason
        session.save(update_fields=['is_active', 'session_end_time', 'end_reason'])

        # Clear caches
        _clear_session_caches(request.user.id, tab_id)

        return JsonResponse({
            'status': 'success',
            'session_id': session.id,
            'end_time': session.session_end_time.isoformat(),
            'reason': end_reason
        })

    except Exception as e:
        logger.error(f"Error ending session: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
@login_required
def optimized_force_sync(request):
    """
    Force synchronization of buffered data
    """
    try:
        data = json.loads(request.body)
        tab_id = data.get('tab_id') or request.headers.get('X-Tab-ID')

        # Get session
        session = _get_session_optimized(request.user, tab_id)
        if not session:
            return JsonResponse({'error': 'No active session found'}, status=404)

        # Force flush buffer
        OptimizedSessionTrackingMiddleware.force_flush_user_buffer(request.user.id, session.id)

        # Clear caches to force fresh data
        _clear_session_caches(request.user.id, tab_id)

        return JsonResponse({
            'status': 'success',
            'session_id': session.id,
            'sync_time': timezone.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error in force sync: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

# =============================================================================
# SESSION ANALYTICS VIEWS
# =============================================================================

@csrf_exempt
@require_http_methods(["GET"])
@login_required
def optimized_session_analytics(request):
    """
    Get session analytics with caching
    """
    try:
        user_id = request.user.id

        # Check cache first
        cache_key = f"session_analytics_{user_id}"
        cached_analytics = cache.get(cache_key)

        if cached_analytics:
            return JsonResponse(cached_analytics)

        # Calculate analytics
        analytics_data = _calculate_analytics(request.user)

        # Cache analytics
        cache.set(cache_key, analytics_data, CONFIG.ANALYTICS_CACHE_TIMEOUT)

        return JsonResponse(analytics_data)

    except Exception as e:
        logger.error(f"Error getting session analytics: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
@login_required
def optimized_bulk_session_update(request):
    """
    Process bulk session updates in a single transaction
    """
    try:
        # Try to parse JSON body, fallback to POST data
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            data = request.POST.dict()
            # Try to parse updates if it's a string
            if 'updates' in data and isinstance(data['updates'], str):
                try:
                    data['updates'] = json.loads(data['updates'])
                except json.JSONDecodeError:
                    data['updates'] = []

        updates = data.get('updates', [])

        if not updates:
            return JsonResponse({'error': 'No updates provided'}, status=400)

        # Only allow for superusers
        if not request.user.is_superuser:
            return JsonResponse({'error': 'Permission denied'}, status=403)

        results = []

        with transaction.atomic():
            for update in updates:
                session_id = update.get('session_id')
                fields = update.get('fields', {})

                try:
                    session = UserSession.objects.get(id=session_id)

                    # Update fields
                    for field, value in fields.items():
                        if hasattr(session, field):
                            setattr(session, field, value)

                    session.save()
                    results.append({'session_id': session_id, 'status': 'success'})

                except UserSession.DoesNotExist:
                    results.append({'session_id': session_id, 'status': 'not_found'})
                except Exception as e:
                    results.append({'session_id': session_id, 'status': 'error', 'error': str(e)})

        return JsonResponse({
            'status': 'completed',
            'results': results,
            'updated_count': len([r for r in results if r['status'] == 'success'])
        })

    except Exception as e:
        logger.error(f"Error in bulk session update: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

# =============================================================================
# DASHBOARD VIEW
# =============================================================================

@login_required
def dashboard_view(request):
    """
    Optimized dashboard view with session analytics
    """
    try:
        user = request.user

        # Trigger maintenance if needed
        trigger_maintenance_if_needed()

        # Get current session
        current_session = UserSession.objects.filter(
            user=user, is_active=True
        ).first()

        # Get session analytics - wrap in try/except to handle any field errors
        try:
            analytics_data = _calculate_analytics(user)
        except Exception as analytics_error:
            logger.error(f"Error calculating analytics: {analytics_error}")
            # Provide safe default values
            analytics_data = {
                'total_sessions': 0,
                'active_sessions': 0,
                'avg_session_duration': 0,
                'productivity_score': 0,
                'engagement_score': 0,
                'last_week_sessions': 0,
                'session_trend': 'stable',
                'error': str(analytics_error)
            }

        # Get today's activity
        today = timezone.now().date()
        todays_sessions = UserSession.objects.filter(
            user=user,
            login_time__date=today
        ).order_by('-login_time')

        # Calculate session statistics
        session_stats = {
            'total_sessions': UserSession.objects.filter(user=user).count(),
            'active_sessions': UserSession.objects.filter(user=user, is_active=True).count(),
            'todays_sessions': todays_sessions.count(),
            'avg_session_duration': _calculate_average_session_duration(user),
            'productivity_score': analytics_data.get('productivity_score', 0),
            'engagement_score': analytics_data.get('engagement_score', 0)
        }

        # Get conference booking context
        # conference_context = {}
        # try:
        #     from trueAlign.conf_booking.views import conference_booking_context
        #     conference_context = conference_booking_context(user)
        # except Exception as conf_error:
        #     logger.warning(f"Error loading conference booking context: {conf_error}")
        #     conference_context = {
        #         'conference_form': None,
        #         'user_bookings': [],
        #         'user_analytics': None,
        #         'available_rooms': [],
        #     }

        # Get user role information
        user_groups = user.groups.all()
        is_admin = user.is_superuser or user_groups.filter(name='Admin').exists()
        is_manager = user_groups.filter(name='Manager').exists()
        is_hr = user_groups.filter(name='HR').exists()
        is_employee = user_groups.filter(name__in=['Employee', 'User']).exists()
        is_client = user_groups.filter(name='Client').exists()

        context = {
            'user': user,
            'current_session': current_session,
            'session_stats': session_stats,
            'analytics': analytics_data,
            'todays_sessions': todays_sessions[:5],  # Last 5 sessions
            'timezone': CONFIG.IST_TIMEZONE if hasattr(CONFIG, 'IST_TIMEZONE') else 'UTC',
            # Role-based flags
            'is_admin': is_admin,
            'is_manager': is_manager,
            'is_hr': is_hr,
            'is_employee': is_employee,
            'is_client': is_client,
            # Conference booking context
            # **conference_context
        }

        return render(request, 'dashboard.html', context)

    except Exception as e:
        logger.error(f"Error in dashboard view: {str(e)}")
        messages.error(request, 'Error loading dashboard. Please try again.')
        return render(request, 'dashboard.html', {
            'user': request.user,
            'error': 'Dashboard temporarily unavailable'
        })

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _get_session_optimized(user, tab_id):
    """
    Get session with optimized caching
    """
    try:
        # Check cache first
        cached_session = get_cached_session(user.id)
        if cached_session and (not tab_id or cached_session.tab_id == tab_id):
            return cached_session

        # Query database
        if tab_id:
            session = UserSession.objects.select_related('user').filter(
                user=user, tab_id=tab_id, is_active=True
            ).first()
        else:
            session = UserSession.objects.select_related('user').filter(
                user=user, is_active=True
            ).first()

        if session:
            cache_session(user.id, session)
            return session

        return None

    except Exception as e:
        logger.error(f"Error getting session: {str(e)}")
        return None

def _process_heartbeat_data(data, session):
    """
    Process heartbeat data and return activity data
    """
    try:
        heartbeat_data = {
            'timestamp': timezone.now().isoformat(),
            'is_idle': data.get('is_idle', False),
            'is_visible': data.get('is_visible', True),
            'url': data.get('url', ''),
            'title': data.get('title', ''),
            'tab_id': data.get('tab_id', ''),
        }

        # Process location data if provided
        location_data = data.get('location')
        if location_data or data.get('location_latitude'):
            try:
                # Update session with location information
                session.location_latitude = data.get('location_latitude') or (location_data.get('latitude') if location_data else None)
                session.location_longitude = data.get('location_longitude') or (location_data.get('longitude') if location_data else None)
                session.location_accuracy = data.get('location_accuracy') or (location_data.get('accuracy') if location_data else None)

                # Determine location type based on coordinates
                if session.location_latitude and session.location_longitude:
                    session.location_type = 'geo_location'

                    # You can add office location checking here
                    # For example, check if coordinates are within office boundaries
                    # office_lat, office_lng = 19.0760, 72.8777  # Mumbai office example
                    # if abs(float(session.location_latitude) - office_lat) < 0.01 and abs(float(session.location_longitude) - office_lng) < 0.01:
                    #     session.location_type = 'office'
                    # else:
                    #     session.location_type = 'remote'

                logger.info(f"Location data updated for session {session.id}: lat={session.location_latitude}, lng={session.location_longitude}")
            except Exception as loc_error:
                logger.error(f"Error processing location data: {loc_error}")

        # Update session idle state
        if data.get('is_idle') and not session.is_idle:
            session.is_idle = True
            session.idle_start_time = timezone.now()
            session.save(update_fields=['is_idle', 'idle_start_time'])
        elif not data.get('is_idle') and session.is_idle:
            session.is_idle = False
            session.idle_start_time = None
            session.save(update_fields=['is_idle', 'idle_start_time'])

        return heartbeat_data

    except Exception as e:
        logger.error(f"Error processing heartbeat data: {str(e)}")
        return None

def _process_batch_activities(activities, session, user_id):
    """
    Process batch activities and buffer them
    """
    try:
        processed_count = 0

        for activity in activities:
            activity_type = activity.get('type')
            activity_data = activity.get('data', {})

            if activity_type and activity_data:
                # Add timestamp if not present
                if 'timestamp' not in activity_data:
                    activity_data['timestamp'] = timezone.now().isoformat()

                # Handle location updates specially
                if activity_type == 'location_update':
                    try:
                        # Update session with location data
                        if 'location_latitude' in activity_data and 'location_longitude' in activity_data:
                            session.location_latitude = activity_data['location_latitude']
                            session.location_longitude = activity_data['location_longitude']
                            session.location_accuracy = activity_data.get('location_accuracy')
                            session.location_type = 'geo_location'
                            session.save(update_fields=['location_latitude', 'location_longitude', 'location_accuracy', 'location_type'])
                            logger.info(f"Location updated for session {session.id}: lat={session.location_latitude}, lng={session.location_longitude}")
                    except Exception as loc_error:
                        logger.error(f"Error updating location in batch activity: {loc_error}")

                # Buffer the activity
                OptimizedSessionTrackingMiddleware.log_activity(
                    user_id, session.id, activity_type, activity_data
                )
                processed_count += 1

        return processed_count

    except Exception as e:
        logger.error(f"Error processing batch activities: {str(e)}")
        return 0

def _calculate_session_status(session):
    """
    Calculate comprehensive session status
    """
    try:
        now = timezone.now()

        # Calculate session duration
        if session.login_time:
            duration = now - session.login_time
            duration_minutes = duration.total_seconds() / 60
        else:
            duration_minutes = 0

        # Calculate idle time
        idle_time = 0
        if session.is_idle and session.idle_start_time:
            idle_time = (now - session.idle_start_time).total_seconds() / 60

        # Calculate productivity score
        productivity_score = calculate_productivity_score({
            'session_duration': duration_minutes,
            'idle_time': idle_time,
            'page_views': session.page_views or [],
            'clicks': session.clicks or [],
            'keyboard_events': session.keyboard_events or [],
        })

        # Check for session warning
        warning = False
        remaining_minutes = 0
        if session.last_activity:
            inactive_time = now - session.last_activity
            if inactive_time > timedelta(minutes=CONFIG.SESSION_WARNING_MINUTES):
                warning = True
                remaining_minutes = max(0, CONFIG.SESSION_TIMEOUT_MINUTES - (inactive_time.total_seconds() / 60))

        return {
            'session_id': session.id,
            'is_active': session.is_active,
            'is_idle': session.is_idle,
            'duration_minutes': duration_minutes,
            'idle_time_minutes': idle_time,
            'productivity_score': productivity_score,
            'warning': warning,
            'remaining_minutes': remaining_minutes,
            'last_activity': session.last_activity.isoformat() if session.last_activity else None,
            'page_views_count': len(session.page_views or []),
            'clicks_count': len(session.clicks or []),
            'keyboard_events_count': len(session.keyboard_events or [])
        }

    except Exception as e:
        logger.error(f"Error calculating session status: {str(e)}")
        return {'error': 'Unable to calculate session status'}

def _clear_session_caches(user_id, tab_id):
    """
    Clear session-related caches
    """
    try:
        cache_keys = [
            f"session_status_{user_id}_{tab_id}",
            f"heartbeat_response_{user_id}_{tab_id}",
            f"session_analytics_{user_id}",
            f"session_lookup_{user_id}_{tab_id}",
        ]

        for key in cache_keys:
            cache.delete(key)

    except Exception as e:
        logger.error(f"Error clearing session caches: {str(e)}")

def _calculate_analytics(user):
    """
    Calculate comprehensive analytics for user
    """
    try:
        # Get recent sessions
        recent_sessions = UserSession.objects.filter(
            user=user,
            login_time__gte=timezone.now() - timedelta(days=7)
        ).order_by('-login_time')

        # Calculate metrics
        total_sessions = recent_sessions.count()
        active_sessions = recent_sessions.filter(is_active=True).count()

        # Calculate average session duration
        total_duration = 0
        session_count = 0
        productivity_scores = []

        for session in recent_sessions:
            if session.login_time:
                # Check for any of the end time fields available
                if session.session_end_time:
                    duration = session.session_end_time - session.login_time
                elif session.ended_at:
                    duration = session.ended_at - session.login_time
                elif session.logout_time:
                    duration = session.logout_time - session.login_time
                else:
                    duration = timezone.now() - session.login_time

                total_duration += duration.total_seconds()
                session_count += 1

                # Calculate productivity score
                try:
                    # First, normalize the input data to ensure consistent types
                    idle_time_value = 0
                    if session.idle_time:
                        if isinstance(session.idle_time, timedelta):
                            idle_time_value = session.idle_time.total_seconds() / 60
                        elif isinstance(session.idle_time, (int, float)):
                            idle_time_value = session.idle_time / 60

                    page_views = []
                    if session.page_views:
                        if isinstance(session.page_views, list):
                            page_views = session.page_views
                        elif isinstance(session.page_views, str):
                            try:
                                page_views = json.loads(session.page_views)
                            except:
                                page_views = []

                    clicks = []
                    if session.clicks:
                        if isinstance(session.clicks, list):
                            clicks = session.clicks
                        elif isinstance(session.clicks, str):
                            try:
                                clicks = json.loads(session.clicks)
                            except:
                                clicks = []

                    keyboard_events = []
                    if session.keyboard_events:
                        if isinstance(session.keyboard_events, list):
                            keyboard_events = session.keyboard_events
                        elif isinstance(session.keyboard_events, str):
                            try:
                                keyboard_events = json.loads(session.keyboard_events)
                            except:
                                keyboard_events = []

                    productivity_score = calculate_productivity_score({
                        'session_duration': duration.total_seconds() / 60,
                        'idle_time': idle_time_value,
                        'page_views': page_views,
                        'click_events': clicks,
                        'keyboard_events': keyboard_events,
                    })
                except Exception as score_error:
                    logger.warning(f"Error calculating productivity score: {score_error}")
                    productivity_score = 50  # Default value
                productivity_scores.append(productivity_score)

        avg_duration = total_duration / session_count if session_count > 0 else 0
        avg_productivity = sum(productivity_scores) / len(productivity_scores) if productivity_scores else 0

        return {
            'total_sessions': total_sessions,
            'active_sessions': active_sessions,
            'avg_session_duration': avg_duration / 60,  # Convert to minutes
            'productivity_score': avg_productivity,
            'engagement_score': min(100, avg_productivity * 1.1),  # Derived from productivity
            'last_week_sessions': total_sessions,
            'session_trend': 'up' if total_sessions > 5 else 'stable'
        }

    except Exception as e:
        logger.error(f"Error calculating analytics: {str(e)}")
        return {
            'total_sessions': 0,
            'active_sessions': 0,
            'avg_session_duration': 0,
            'productivity_score': 0,
            'engagement_score': 0,
            'last_week_sessions': 0,
            'session_trend': 'stable',
            'error': str(e)
        }

def _calculate_average_session_duration(user):
    """
    Calculate average session duration for user
    """
    try:
        sessions = UserSession.objects.filter(
            user=user,
            session_end_time__isnull=False
        ).order_by('-login_time')[:10]  # Last 10 completed sessions

        if not sessions:
            return 0

        total_duration = 0
        for session in sessions:
            if session.login_time and session.session_end_time:
                duration = session.session_end_time - session.login_time
                total_duration += duration.total_seconds()

        return total_duration / len(sessions) / 60  # Return in minutes

    except Exception as e:
        logger.error(f"Error calculating average session duration: {str(e)}")
        return 0

# =============================================================================
# LEGACY COMPATIBILITY VIEWS
# =============================================================================

# Create aliases for backward compatibility
session_heartbeat = optimized_session_heartbeat
update_last_activity = optimized_batch_activity_update
get_session_status = optimized_session_status
end_session = optimized_end_session
session_analytics = optimized_session_analytics

# Additional compatibility functions
@csrf_exempt
@require_http_methods(["POST"])
@login_required
def log_activity(request):
    """Legacy activity logging endpoint"""
    return optimized_batch_activity_update(request)

@csrf_exempt
@require_http_methods(["GET"])
@login_required
def session_status(request):
    """Legacy session status endpoint"""
    return optimized_session_status(request)

# =============================================================================
# LEGACY ENDPOINT COMPATIBILITY FUNCTIONS
# =============================================================================

@csrf_exempt
@require_http_methods(["GET"])
@login_required
def get_session_status(request):
    """Legacy session status endpoint"""
    return optimized_session_status(request)

@csrf_exempt
@require_http_methods(["POST"])
@login_required
def update_last_activity(request):
    """Legacy last activity update endpoint"""
    return optimized_batch_activity_update(request)

@csrf_exempt
@require_http_methods(["GET"])
@login_required
def session_analytics(request):
    """Legacy session analytics endpoint"""
    return optimized_session_analytics(request)

@csrf_exempt
@require_http_methods(["POST"])
@login_required
def end_session(request):
    """Legacy end session endpoint"""
    return optimized_end_session(request)

@csrf_exempt
@require_http_methods(["POST"])
@login_required
def session_heartbeat(request):
    """Legacy session heartbeat endpoint"""
    return optimized_session_heartbeat(request)

# =============================================================================
# API ENDPOINTS FOR EXTERNAL INTEGRATIONS
# =============================================================================

@csrf_exempt
@require_http_methods(["POST"])
@login_required
def create_session(request):
    """Create a new session (API endpoint)"""
    try:
        data = json.loads(request.body)
        tab_id = data.get('tab_id')

        # Check if session already exists
        existing_session = UserSession.objects.filter(
            user=request.user,
            tab_id=tab_id,
            is_active=True
        ).first()

        if existing_session:
            return JsonResponse({
                'status': 'exists',
                'session_id': existing_session.id,
                'message': 'Session already exists'
            })

        # Create new session
        client_info = {
            'ip_address': get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
        }

        device_info = parse_user_agent(client_info['user_agent'])

        session = UserSession.objects.create(
            user=request.user,
            tab_id=tab_id,
            session_key=UserSession.generate_session_key(),
            ip_address=client_info['ip_address'],
            user_agent=client_info['user_agent'],
            device_type=device_info.get('device', 'unknown'),
            login_time=timezone.now(),
            last_activity=timezone.now(),
            is_active=True
        )

        return JsonResponse({
            'status': 'created',
            'session_id': session.id,
            'message': 'Session created successfully'
        })

    except Exception as e:
        logger.error(f"Error creating session: {str(e)}")
        return JsonResponse({'error': 'Failed to create session'}, status=500)

@csrf_exempt
@require_http_methods(["POST"])
@login_required
def update_session(request):
    """Update existing session (API endpoint)"""
    try:
        data = json.loads(request.body)
        session_id = data.get('session_id')

        if not session_id:
            return JsonResponse({'error': 'session_id required'}, status=400)

        session = UserSession.objects.get(id=session_id, user=request.user)

        # Update fields
        update_fields = []
        if 'is_active' in data:
            session.is_active = data['is_active']
            update_fields.append('is_active')

        if 'is_idle' in data:
            session.is_idle = data['is_idle']
            update_fields.append('is_idle')

        if 'last_activity' in data:
            session.last_activity = timezone.now()
            update_fields.append('last_activity')

        if update_fields:
            session.save(update_fields=update_fields)

        return JsonResponse({
            'status': 'updated',
            'session_id': session.id,
            'message': 'Session updated successfully'
        })

    except UserSession.DoesNotExist:
        return JsonResponse({'error': 'Session not found'}, status=404)
    except Exception as e:
        logger.error(f"Error updating session: {e}")
        return JsonResponse({'error': 'Internal server error'}, status=500)


# =============================================================================
# CONFIGURATIONS VIEW
# =============================================================================

@login_required
def configurations_view(request):
    """
    Central configurations access point - navigation only.
    Shows configuration options for different apps based on user permissions.
    """
    # Check if user is admin/superuser
    user_groups = request.user.groups.all()
    is_admin = request.user.is_superuser or user_groups.filter(name='Admin').exists()

    if not is_admin:
        messages.error(request, 'You do not have permission to access configurations.')
        return redirect('core:dashboard')

    # Configuration sections available to admin users
    config_sections = [
        {
            'name': 'Conference Room Settings',
            'description': 'Manage office locations, conference rooms, and booking settings',
            'icon': 'ri-building-line',
            'url': 'conf_booking:manage_locations',
            'color': 'bg-blue-500',
            'hover_color': 'hover:bg-blue-600'
        },
        {
            'name': 'Conference Room Management',
            'description': 'Add, edit, and manage conference rooms across all locations',
            'icon': 'ri-door-open-line',
            'url': 'conf_booking:manage_rooms',
            'color': 'bg-purple-500',
            'hover_color': 'hover:bg-purple-600'
        },
        {
            'name': 'Attendance Dashboard',
            'description': 'View and manage employee attendance tracking',
            'icon': 'ri-time-line',
            'url': 'attendance:dashboard',
            'color': 'bg-green-500',
            'hover_color': 'hover:bg-green-600'
        },
        {
            'name': 'Support Dashboard',
            'description': 'Manage support tickets and customer service',
            'icon': 'ri-customer-service-line',
            'url': 'support:dashboard',
            'color': 'bg-orange-500',
            'hover_color': 'hover:bg-orange-600'
        },
        {
            'name': 'Conference Room Booking',
            'description': 'Book and manage conference room reservations',
            'icon': 'ri-calendar-line',
            'url': 'conf_booking:booking_room',
            'color': 'bg-indigo-500',
            'hover_color': 'hover:bg-indigo-600'
        }
    ]

    context = {
        'config_sections': config_sections,
        'page_title': 'System Configurations',
        'is_admin': is_admin,
    }

    return render(request, 'configurations.html', context)
