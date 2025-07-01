from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.contrib.auth.views import PasswordResetView, PasswordResetDoneView, PasswordResetConfirmView, PasswordResetCompleteView
from django.urls import reverse_lazy
from django.db import transaction
from django.db.models import Q, Count, Avg, Sum, F
from datetime import datetime, timedelta, date
from decimal import Decimal
import pytz
import json
import logging
import ipaddress
import uuid
from trueAlign.models import UserSession
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm
from .utils import get_client_ip, parse_user_agent, get_location_from_ip, detect_suspicious_activity, calculate_productivity_score, to_ist, to_utc, get_current_time_ist
from trueAlign.conf_booking.views import get_upcoming_booking_for_room,conference_booking_context

# Set up logging
logger = logging.getLogger(__name__)

# Asia/Kolkata timezone
IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

# Helper functions for timezone conversion
def get_current_time_ist():
    """Get current time in IST timezone"""
    return timezone.now().astimezone(IST_TIMEZONE)

def to_ist(utc_time):
    """Convert UTC time to IST timezone"""
    if utc_time is None:
        return None
    return utc_time.astimezone(IST_TIMEZONE)

def to_utc(ist_time):
    """Convert IST time to UTC for database storage"""
    if ist_time is None:
        return None
    if timezone.is_naive(ist_time):
        ist_time = IST_TIMEZONE.localize(ist_time)
    return ist_time.astimezone(pytz.UTC)

# Process attendance function (placeholder - implement based on your requirements)
def process_login_attendance(user):
    """Process attendance when user logs in"""
    # Implement your attendance logic here
    # This is a placeholder function
    return {'status': 'success', 'clock_in': get_current_time_ist()}

def login_view(request):
    """Login view with session tracking and session expiry handling"""
    # Check for session expiry messages
    session_expired = request.GET.get('expired') == '1'
    session_expiry_reason = request.session.pop('session_expiry_reason', None)

    # Add appropriate messages for session expiry
    if session_expired and session_expiry_reason:
        if session_expiry_reason == 'inactivity_timeout':
            messages.warning(request, 'Your session expired due to inactivity. Please log in again.')
        elif session_expiry_reason == 'no_active_session':
            messages.info(request, 'Your session was not found. Please log in again.')
        else:
            messages.info(request, 'Your session expired. Please log in again.')

    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)

            # Create initial session record
            current_time_ist = get_current_time_ist()
            current_time_utc = to_utc(current_time_ist)

            # Debug logging
            logger.debug(f"Current UTC time: {timezone.now()}")
            logger.debug(f"Current IST time: {current_time_ist}")

            x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
            ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

            try:
                session, created = UserSession.get_or_create_session(
                    user=user,
                    session_key=request.session.session_key,
                    ip_address=ip_address,
                    user_agent=request.META.get('HTTP_USER_AGENT', '')
                )
                if created:
                    logger.debug(f"New session created: {session}")
                else:
                    logger.debug(f"Existing session found: {session}")
                logger.debug(f"Session login time (UTC): {session.login_time}")
                logger.debug(f"Session login time (IST): {to_ist(session.login_time)}")

            except Exception as e:
                logger.error(f"Error creating session: {e}")


            # Process attendance if applicable
            try:
                attendance_status = process_login_attendance(user)
                if attendance_status:
                    logger.debug(f"Login processed - User: {user.username}, Status: {attendance_status['status']}, Clock in: {attendance_status.get('clock_in')}")
            except Exception as e:
                logger.error(f"Error processing attendance: {e}")

            messages.success(request, f'Welcome back, {user.get_full_name() or user.username}!')

            # Handle redirect to next URL if provided
            next_url = request.GET.get('next') or request.POST.get('next')
            if next_url:
                # Validate the next URL to prevent redirect attacks
                from django.utils.http import url_has_allowed_host_and_scheme
                if url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}):
                    return redirect(next_url)

            return redirect('core:dashboard')
        else:
            messages.error(request, 'Invalid username or password.')

    return render(request, 'login.html', {
        'session_expired': session_expired,
        'next': request.GET.get('next', '')
    })


@login_required
def logout_view(request):
    """Logout view with proper session ending"""
    try:
        # End all active sessions for this user
        active_sessions = UserSession.objects.filter(
            user=request.user,
            is_active=True
        )

        for session in active_sessions:
            session.end_session()
            logger.info(f"Session ended for user {request.user.username}, session ID: {session.id}")
    except Exception as e:
        logger.error(f"Error ending session during logout: {e}")

    # Perform Django logout
    logout(request)
    messages.success(request, 'You have been successfully logged out.')
    return redirect('core:login')

@login_required
@csrf_exempt
def update_last_activity(request):
    """
    View to handle activity updates from the client.
    Updates the user's last activity timestamp and tracks idle time.
    """
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            is_idle = data.get('is_idle', False)
            tab_id = data.get('tab_id')
            parent_session_id = data.get('parent_session_id')

            # Get the user's session
            session = _get_or_create_session(request.user, tab_id, parent_session_id, request, data)

            if not session:
                return JsonResponse({'status': 'error', 'message': 'Could not create session'}, status=500)

            # Update last activity using the method
            current_time_utc = timezone.now()
            session.update_activity(current_time_utc, is_idle)

            # Process any additional activities
            if 'activities' in data and isinstance(data['activities'], list):
                _process_activities(session, data['activities'])

            return JsonResponse({
                'status': 'success',
                'last_activity': to_ist(session.last_activity).isoformat(),
                'session_active': session.is_active
            })

        except Exception as e:
            logger.error(f"Error updating activity: {e}")
            return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

    return JsonResponse({'status': 'error', 'message': 'Invalid request method'}, status=405)

def _process_activities(user_session, activities):
    """Process batch activities from client"""
    try:
        for activity in activities:
            activity_type = activity.get('type')

            if activity_type == 'page_view':
                # Process page view
                if not user_session.page_views:
                    user_session.page_views = []

                user_session.page_views.append({
                    'url': activity.get('url', ''),
                    'title': activity.get('title', ''),
                    'timestamp': activity.get('timestamp', timezone.now().isoformat()),
                    'referrer': activity.get('referrer', '')
                })

            elif activity_type == 'click':
                # Process click event
                if not user_session.click_events:
                    user_session.click_events = []

                user_session.click_events.append({
                    'timestamp': activity.get('timestamp', timezone.now().isoformat()),
                    'element': activity.get('element_info', {}),
                    'coordinates': activity.get('coordinates', {})
                })

            elif activity_type == 'tab_visibility':
                # Process tab visibility change
                if not user_session.tab_visibility_log:
                    user_session.tab_visibility_log = []

                user_session.tab_visibility_log.append({
                    'timestamp': activity.get('timestamp', timezone.now().isoformat()),
                    'action': activity.get('action', 'unknown'),
                    'url': activity.get('url', '')
                })

                # Update tab focus time
                if activity.get('action') == 'focus_gained':
                    user_session.tab_last_focus = to_utc(timezone.now())
                    user_session.tab_switches += 1

        # Save all changes
        user_session.save()

    except Exception as e:
        logger.error(f"Error processing activities: {e}")

def _get_or_create_session(user, tab_id, parent_session_id, request, data):
    """
    Get existing session or create new one with enhanced tracking
    All times handled in Asia/Kolkata timezone
    """
    try:
        # Try to get existing session by tab_id
        if tab_id:
            session = UserSession.objects.filter(
                user=user,
                tab_id=tab_id,
                is_active=True
            ).first()

            if session:
                return session

        # Try to get session by parent_session_id
        if parent_session_id:
            session = UserSession.objects.filter(
                user=user,
                parent_session_id=parent_session_id,
                is_active=True
            ).first()

            if session:
                return session

        # If no session found, create a new session
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

        # Prepare client data for get_or_create_session
        client_data = {
            'tab_id': tab_id,
            'browser_fingerprint': data.get('fingerprint', ''),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'device_type': data.get('device_type', ''),
            'screen_resolution': data.get('screen_resolution', ''),
            'timezone_offset': data.get('timezone_offset', 0),
            'language': request.META.get('HTTP_ACCEPT_LANGUAGE', '').split(',')[0] if request.META.get('HTTP_ACCEPT_LANGUAGE') else 'en',
            'url': data.get('url', request.path),
            'title': data.get('title', ''),
            'referrer': data.get('referrer', ''),
            'ip_address': ip_address
        }

        # Create a new session using the get_or_create_session method
        session, created = UserSession.get_or_create_session(
            user=user,
            tab_id=tab_id,
            parent_session_id=parent_session_id,
            client_data=client_data,
            session_key=request.session.session_key
        )

        return session

    except Exception as e:
        logger.error(f"Error getting or creating session: {e}")
        # Fallback to creating a basic session
        session, created = UserSession.get_or_create_session(
            user=user,
            session_key=request.session.session_key
        )
        return session

@login_required
def get_session_status(request):
    """Get the current session status. All times are returned in Asia/Kolkata (IST) timezone."""
    try:
        # Check if user is authenticated
        if not request.user.is_authenticated:
            return JsonResponse({
                'status': 'error',
                'message': 'User not authenticated'
            }, status=401)

        # Get tab_id from request parameters
        tab_id = request.GET.get('tab_id')

        # Get active sessions for this user
        active_sessions = UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).order_by('-login_time')

        # If tab_id is provided, try to find specific session first
        if tab_id:
            try:
                # Try to find session with this tab_id
                tab_session = active_sessions.filter(
                    tab_id=tab_id
                ).first()

                if tab_session:
                    session = tab_session
                else:
                    # Fallback to most recent session
                    session = active_sessions.first()
            except Exception as e:
                logger.error(f"Error filtering by tab_id {tab_id}: {e}")
                session = active_sessions.first()
        else:
            session = active_sessions.first()

        if not session:
            return JsonResponse({
                'status': 'no_active_session',
                'message': 'No active session found.'
            })

        # Calculate session duration with error handling
        try:
            current_time_ist = get_current_time_ist()
            login_time_ist = to_ist(session.login_time)
            session_duration = current_time_ist - login_time_ist

            # Calculate idle time
            last_activity_ist = to_ist(session.last_activity)
            idle_duration = current_time_ist - last_activity_ist

            # Check if session is about to expire
            timeout_threshold = getattr(session, 'custom_timeout', None) or getattr(session, 'AUTO_LOGOUT_MINUTES', 30)
            idle_minutes = idle_duration.total_seconds() / 60
            warning_threshold = getattr(session, 'WARNING_THRESHOLD_MINUTES', 25)

            is_warning = idle_minutes >= warning_threshold
            remaining_minutes = max(0, timeout_threshold - idle_minutes)

            return JsonResponse({
                'status': 'active',
                'session_id': str(session.id),
                'tab_id': tab_id,
                'login_time': login_time_ist.isoformat(),
                'last_activity': last_activity_ist.isoformat(),
                'session_duration': {
                    'hours': int(session_duration.total_seconds() // 3600),
                    'minutes': int((session_duration.total_seconds() % 3600) // 60),
                    'seconds': int(session_duration.total_seconds() % 60)
                },
                'idle_time': {
                    'minutes': int(idle_minutes),
                    'seconds': int(idle_duration.total_seconds() % 60)
                },
                'warning': is_warning,
                'remaining_minutes': int(remaining_minutes),
                'location': getattr(session, 'location', 'Unknown'),
                'device': getattr(session, 'device_type', 'Unknown')
            })

        except Exception as time_error:
            logger.error(f"Error calculating session times: {time_error}")
            return JsonResponse({
                'status': 'active',
                'session_id': str(session.id),
                'tab_id': tab_id,
                'warning': False,
                'remaining_minutes': 30,
                'message': 'Session active but time calculation failed'
            })

    except Exception as e:
        logger.error(f"Error getting session status for user {request.user.id}: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")
        return JsonResponse({
            'status': 'error',
            'message': f'Internal server error: {str(e)}'
        }, status=500)


@login_required
@require_GET
def session_analytics(request):
    """
    Get comprehensive session analytics
    All times handled in Asia/Kolkata timezone
    """
    try:
        # Get all sessions for this user
        sessions = UserSession.objects.filter(user=request.user).order_by('-login_time')

        # Calculate analytics
        total_sessions = sessions.count()
        active_sessions = sessions.filter(is_active=True).count()

        # Calculate total working hours
        total_working_seconds = 0
        for session in sessions:
            if session.working_hours:
                total_working_seconds += session.working_hours.total_seconds()
            elif session.is_active:
                # For active sessions, calculate current working hours
                current_time = timezone.now()
                duration = current_time - session.login_time
                working_duration = duration - session.idle_time
                total_working_seconds += working_duration.total_seconds()

        total_working_hours = total_working_seconds / 3600

        # Get location breakdown
        location_data = {}
        for session in sessions:
            location = session.location or 'Unknown'
            if location not in location_data:
                location_data[location] = 0

            # Add session duration to location
            if session.session_duration:
                location_data[location] += session.session_duration / 60  # Convert to hours
            elif session.is_active:
                # For active sessions, calculate current duration
                current_time = timezone.now()
                duration = (current_time - session.login_time).total_seconds() / 3600
                location_data[location] += duration

        # Format response
        return JsonResponse({
            'total_sessions': total_sessions,
            'active_sessions': active_sessions,
            'total_working_hours': round(total_working_hours, 2),
            'location_breakdown': location_data,
            'recent_sessions': [
                {
                    'id': session.id,
                    'login_time': to_ist(session.login_time).isoformat(),
                    'logout_time': to_ist(session.logout_time).isoformat() if session.logout_time else None,
                    'duration': session.get_session_duration_display(),
                    'working_hours': session.get_total_working_hours_display(),
                    'location': session.location or 'Unknown',
                    'device': session.device_type or 'Unknown',
                    'is_active': session.is_active
                }
                for session in sessions[:10]  # Get 10 most recent sessions
            ]
        })

    except Exception as e:
        logger.error(f"Error getting session analytics: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
@require_GET
def session_status(request):
    """
    Get current session status and analytics
    All times returned in Asia/Kolkata timezone
    """
    try:
        # Get tab_id from request
        tab_id = request.GET.get('tab_id')

        # Get the session
        if tab_id:
            session = UserSession.objects.filter(
                user=request.user,
                tab_id=tab_id,
                is_active=True
            ).first()
        else:
            session = UserSession.objects.filter(
                user=request.user,
                is_active=True
            ).order_by('-login_time').first()

        if not session:
            return JsonResponse({
                'status': 'no_active_session',
                'message': 'No active session found.'
            })

        # Calculate times
        current_time_ist = get_current_time_ist()
        login_time_ist = to_ist(session.login_time)
        last_activity_ist = to_ist(session.last_activity)

        # Calculate durations
        session_duration = current_time_ist - login_time_ist
        idle_duration = current_time_ist - last_activity_ist
        idle_minutes = idle_duration.total_seconds() / 60

        # Check timeout status
        timeout_threshold = session.custom_timeout or session.AUTO_LOGOUT_MINUTES
        warning_threshold = session.WARNING_THRESHOLD_MINUTES

        is_warning = idle_minutes >= warning_threshold
        remaining_minutes = max(0, timeout_threshold - idle_minutes)

        # Get tab information
        tab_info = None
        if session.tab_id:
            tab_info = {
                'tab_id': session.tab_id,
                'title': session.tab_title,
                'url': session.tab_url,
                'opened_time': to_ist(session.tab_opened_time).isoformat() if session.tab_opened_time else None,
                'is_primary': session.is_primary_tab
            }

        # Get all tabs in this session
        related_tabs = []
        if session.parent_session_id:
            related_tabs = [
                {
                    'tab_id': tab.tab_id,
                    'title': tab.tab_title,
                    'url': tab.tab_url,
                    'is_primary': tab.is_primary_tab,
                    'last_activity': to_ist(tab.last_activity).isoformat()
                }
                for tab in UserSession.objects.filter(
                    user=request.user,
                    parent_session_id=session.parent_session_id,
                    is_active=True
                ).exclude(id=session.id)
            ]

        return JsonResponse({
            'status': 'active',
            'session_id': session.id,
            'parent_session_id': session.parent_session_id,
            'login_time': login_time_ist.isoformat(),
            'last_activity': last_activity_ist.isoformat(),
            'session_duration': {
                'hours': int(session_duration.total_seconds() // 3600),
                'minutes': int((session_duration.total_seconds() % 3600) // 60),
                'seconds': int(session_duration.total_seconds() % 60)
            },
            'idle_time': {
                'minutes': int(idle_minutes),
                'seconds': int(idle_duration.total_seconds() % 60)
            },
            'warning': is_warning,
            'remaining_minutes': int(remaining_minutes),
            'location': session.location or 'Unknown',
            'device': session.device_type or 'Unknown',
            'tab': tab_info,
            'related_tabs': related_tabs,
            'productivity_score': session.productivity_score
        })

    except Exception as e:
        logger.error(f"Error getting session status: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
@require_POST
def end_session(request):
    """
    End user session properly
    All times handled in Asia/Kolkata timezone
    """
    try:
        data = json.loads(request.body) if request.body else {}
        tab_id = data.get('tab_id')
        end_all_tabs = data.get('end_all_tabs', False)
        is_idle = data.get('is_idle', False)

        if end_all_tabs:
            # End all active sessions for this user
            active_sessions = UserSession.objects.filter(
                user=request.user,
                is_active=True
            )

            for session in active_sessions:
                session.end_session(is_idle=is_idle)

            return JsonResponse({
                'status': 'success',
                'message': 'All sessions ended successfully.',
                'sessions_ended': active_sessions.count()
            })

        elif tab_id:
            # End specific tab session
            session = UserSession.objects.filter(
                user=request.user,
                tab_id=tab_id,
                is_active=True
            ).first()

            if session:
                session.end_session(is_idle=is_idle)
                return JsonResponse({
                    'status': 'success',
                    'message': 'Tab session ended successfully.',
                    'session_id': session.id
                })
            else:
                return JsonResponse({
                    'status': 'error',
                    'message': 'No active session found for this tab.'
                }, status=404)

        else:
            # End the most recent session
            session = UserSession.objects.filter(
                user=request.user,
                is_active=True
            ).order_by('-login_time').first()

            if session:
                session.end_session(is_idle=is_idle)
                return JsonResponse({
                    'status': 'success',
                    'message': 'Session ended successfully.',
                    'session_id': session.id
                })
            else:
                return JsonResponse({
                    'status': 'error',
                    'message': 'No active session found.'
                }, status=404)

    except Exception as e:
        logger.error(f"Error ending session: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
@require_POST
def log_activity(request):
    """
    Log user activities from client-side buffer
    All times handled in Asia/Kolkata timezone
    """
    try:
        data = json.loads(request.body)
        tab_id = data.get('tab_id')
        parent_session_id = data.get('parent_session_id')
        activities = data.get('activities', [])

        if not activities:
            return JsonResponse({
                'status': 'error',
                'message': 'No activities provided.'
            }, status=400)

        # Get the session
        session = _get_or_create_session(request.user, tab_id, parent_session_id, request, data)

        # Process activities
        _process_activities(session, activities)

        return JsonResponse({
            'status': 'success',
            'message': f'{len(activities)} activities logged successfully.',
            'session_id': session.id
        })

    except Exception as e:
        logger.error(f"Error logging activities: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
@require_POST
def session_heartbeat(request):
    """
    Handle session heartbeat with comprehensive tracking
    All times handled in Asia/Kolkata timezone
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST method allowed'}, status=405)

    try:
        # Parse JSON data
        if request.content_type == 'application/json':
            data = json.loads(request.body)
        else:
            return JsonResponse({'status': 'error', 'message': 'Content-Type must be application/json'}, status=400)

        # Extract required data with defaults
        tab_id = data.get('tab_id')
        parent_session_id = data.get('parent_session_id')
        is_idle = data.get('is_idle', False)
        is_visible = data.get('is_visible', True)

        # Validate required fields
        if not tab_id:
            return JsonResponse({'status': 'error', 'message': 'tab_id is required'}, status=400)

        # Additional data with defaults
        battery_level = data.get('battery_level')
        connection_type = data.get('connection_type')
        performance_data = data.get('performance_data', {})

        # Get the session (this function should handle creation if needed)
        try:
            session = _get_or_create_session(request.user, tab_id, parent_session_id, request, data)
        except Exception as e:
            logger.error(f"Error getting/creating session: {e}")
            return JsonResponse({'status': 'error', 'message': 'Failed to get or create session'}, status=500)

        # Update activity data with safe defaults
        activity_data = {
            'gained_focus': data.get('gained_focus', False),
            'page_change': data.get('page_change', False),
            'url': data.get('url', ''),
            'title': data.get('title', ''),
            'referrer': data.get('referrer', ''),
            'interaction_type': data.get('interaction_type'),
            'element_info': data.get('element_info', {}),
            'coordinates': data.get('coordinates', {}),
            'scroll_position': data.get('scroll_position'),
            'scroll_direction': data.get('scroll_direction'),
            'key_count': data.get('key_count'),
            'input_type': data.get('input_type'),
            'performance_data': performance_data,
            'battery_level': battery_level,
            'connection_type': connection_type,
            'broadcast_sent': data.get('broadcast_sent', False),
            'broadcast_received': data.get('broadcast_received', False)
        }

        # Update tab activity with error handling
        try:
            session.update_tab_activity(activity_data)
        except Exception as e:
            logger.error(f"Error updating tab activity: {e}")
            # Continue processing even if tab activity update fails

        # Update last activity
        current_time_ist = get_current_time_ist()
        current_time_utc = to_utc(current_time_ist)

        try:
            session.update_activity(current_time_utc, is_idle)
        except Exception as e:
            logger.error(f"Error updating session activity: {e}")
            # Continue processing

        # Calculate productivity score if enough data is available
        try:
            if hasattr(session, 'page_views') and hasattr(session, 'click_events') and hasattr(session, 'keyboard_events'):
                if session.page_views or session.click_events or session.keyboard_events:
                    session.calculate_productivity_score()
                    session.save(update_fields=['productivity_score'])
        except Exception as e:
            logger.error(f"Error calculating productivity score: {e}")
            # Continue processing

        # Check timeout status
        last_activity_ist = to_ist(session.last_activity)
        idle_duration = current_time_ist - last_activity_ist
        idle_minutes = idle_duration.total_seconds() / 60

        timeout_threshold = getattr(session, 'custom_timeout', None) or getattr(session, 'AUTO_LOGOUT_MINUTES', 30)
        warning_threshold = getattr(session, 'WARNING_THRESHOLD_MINUTES', 25)

        is_warning = idle_minutes >= warning_threshold
        remaining_minutes = max(0, timeout_threshold - idle_minutes)

        return JsonResponse({
            'status': 'success',
            'session_id': str(session.id),
            'last_activity': last_activity_ist.isoformat(),
            'idle_minutes': round(idle_minutes, 1),
            'warning': is_warning,
            'remaining_minutes': int(remaining_minutes),
            'productivity_score': getattr(session, 'productivity_score', 0)
        })

    except json.JSONDecodeError as e:
        logger.error(f"JSON decode error in heartbeat: {e}")
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error processing heartbeat: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


# Password Reset Views
class CustomPasswordResetView(PasswordResetView):
    template_name = 'core/password_reset.html'
    email_template_name = 'core/password_reset_email.html'
    subject_template_name = 'core/password_reset_subject.txt'
    success_url = reverse_lazy('core:password_reset_done')
    form_class = PasswordResetForm

    def form_valid(self, form):
        # Log the password reset request
        email = form.cleaned_data['email']
        logger.info(f"Password reset requested for email: {email}")

        # Get the IP address
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else self.request.META.get('REMOTE_ADDR')

        # Log additional information
        logger.info(f"Password reset request from IP: {ip_address}, User-Agent: {self.request.META.get('HTTP_USER_AGENT', '')}")

        return super().form_valid(form)

class CustomPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'core/password_reset_done.html'

class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'core/password_reset_confirm.html'
    success_url = reverse_lazy('core:password_reset_complete')
    form_class = SetPasswordForm

    def form_valid(self, form):
        # Log the successful password reset
        user = form.user
        logger.info(f"Password reset successful for user: {user.username}")

        # Get the IP address
        x_forwarded_for = self.request.META.get('HTTP_X_FORWARDED_FOR')
        ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else self.request.META.get('REMOTE_ADDR')

        # Log additional information
        logger.info(f"Password reset completed from IP: {ip_address}, User-Agent: {self.request.META.get('HTTP_USER_AGENT', '')}")

        # End any active sessions for this user
        try:
            active_sessions = UserSession.objects.filter(
                user=user,
                is_active=True
            )

            for session in active_sessions:
                session.end_session()
                logger.info(f"Session ended for user {user.username} after password reset, session ID: {session.id}")
        except Exception as e:
            logger.error(f"Error ending sessions after password reset: {e}")

        return super().form_valid(form)

class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'core/password_reset_complete.html'


@login_required
def dashboard_view(request):
    # Get current time in timezone
    time = timezone.now()
    today = timezone.now().date()

    user = request.user

    # Get user's current session status
    user_session = UserSession.objects.filter(
        user=user,
        session_key=request.session.session_key,
        logout_time__isnull=True
    ).last()

    # Helper function to format timedelta
    def format_timedelta(td):
        """Helper function to format timedelta into a readable string"""
        total_seconds = int(td.total_seconds())
        hours = total_seconds // 3600
        minutes = (total_seconds % 3600) // 60

        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"

    # Calculate user status
    user_status = {
        'status': 'offline',
        'color': 'gray',
        'idle_time': None,
        'working_hours': None,
        'formatted_idle_time': None
    }

    if user_session:
        current_time = timezone.now()
        time_since_last_activity = current_time - user_session.last_activity

        # If last activity was less than 1 minute ago - user is active
        if time_since_last_activity < timedelta(minutes=1):
            user_status['status'] = 'active'
            user_status['color'] = 'green'
        # If last activity was between 1-5 minutes ago - user is idle
        elif time_since_last_activity < timedelta(minutes=5):
            user_status['status'] = 'idle'
            user_status['color'] = 'yellow'
        else:
            user_status['status'] = 'inactive'
            user_status['color'] = 'red'

        user_status['idle_time'] = user_session.idle_time
        user_status['working_hours'] = user_session.working_hours
        user_status['last_activity'] = user_session.last_activity if user_session.last_activity else None

        # Format idle time as readable string
        if user_status['idle_time']:
            user_status['formatted_idle_time'] = format_timedelta(user_status['idle_time'])


    upcoming_booking = get_upcoming_booking_for_room("Conference Room A")
    conf_context = conference_booking_context(user)



    context = {
        'user': user,
        'user_status': user_status,
        'current_time': time,
        'today': today,
        'upcoming_booking': upcoming_booking,
        **conf_context # Unpack the conference context here


    }

    return render(request, 'dashboard.html', context)

import json
import logging
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.utils import timezone
from django.views.decorators.http import require_POST
def safe_isoformat(dt):
    """
    Safely convert a datetime to ISO format string, handling None values.

    Args:
        dt: A datetime object or None

    Returns:
        ISO formatted string or None if dt is None
    """
    return dt.isoformat() if dt is not None else None

logger = logging.getLogger(__name__)


@login_required
@require_POST
def create_session(request):
    """
    Create a new session from API request
    All times handled in Asia/Kolkata timezone
    """
    try:
        data = json.loads(request.body)

        client_data = data.get('client_data', {})

        tab_id = client_data.get('tab_id')
        parent_session_id = client_data.get('parent_session_id')

        session = _get_or_create_session(request.user, tab_id, parent_session_id, request, data)

        return JsonResponse({
            'success': True,
            'session_id': str(session.id),
            'is_new_session': True,
            'tab_id': session.tab_id,
            'login_time': to_ist(session.login_time).isoformat(),
            'last_activity': to_ist(session.last_activity).isoformat()
        })

    except Exception as e:
        logger.error(f"Error creating session: {e}")
        return JsonResponse({'success': False, 'message': str(e)}, status=500)

@login_required
@require_POST
def update_session(request):
    """
    Update an existing session from API request
    All times handled in Asia/Kolkata timezone
    """
    try:
        # Read request body once and completely before any processing
        body_unicode = request.body.decode('utf-8')
        data = json.loads(body_unicode)

        session_id = data.get('session_id')
        client_data = data.get('client_data', {})
        is_idle = data.get('is_idle', False)

        if session_id:
            try:
                session = UserSession.objects.get(id=session_id, user=request.user, is_active=True)
            except UserSession.DoesNotExist:
                tab_id = client_data.get('tab_id')
                parent_session_id = client_data.get('parent_session_id')
                session = _get_or_create_session(request.user, tab_id, parent_session_id, request, data)
        else:
            tab_id = client_data.get('tab_id')
            parent_session_id = client_data.get('parent_session_id')
            session = _get_or_create_session(request.user, tab_id, parent_session_id, request, data)

        if client_data.get('url'):
            if not session.page_views:
                session.page_views = []
            session.page_views.append({
                'url': client_data.get('url'),
                'title': client_data.get('title', ''),
                'timestamp': timezone.now().isoformat(),
                'referrer': client_data.get('referrer', '')
            })

        device_info = data.get('device_info', {})
        if device_info:
            session.update_device_info(device_info)

        session.update_last_activity()
        if is_idle is not None:
            session.update_idle_status(is_idle)

        return JsonResponse({
            'success': True,
            'session_id': str(session.id),
            'last_activity': safe_isoformat(to_ist(session.last_activity))
        })

    except Exception as e:
        logger.error(f"Error updating session: {e}")
        return JsonResponse({'success': False, 'message': str(e)}, status=500)
