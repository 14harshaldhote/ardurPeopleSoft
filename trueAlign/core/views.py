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
from trueAlign.models import Room, ConferenceBooking, Attendance
from trueAlign.attendance.views import get_attendance_context_for_user
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
    """
    Login view with enhanced session tracking
    All times handled in Asia/Kolkata timezone
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username and password:
            user = authenticate(request, username=username, password=password)

            if user is not None and user.is_active:
                # Process attendance for the user
                attendance_result = process_login_attendance(user)

                # Log in the user
                login(request, user)

                # Collect client information
                x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
                ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

                # Create user session with enhanced tracking
                try:
                    with transaction.atomic():
                        # End any existing active sessions for this user
                        UserSession.objects.filter(
                            user=user,
                            is_active=True
                        ).update(
                            is_active=False,
                            ended_at=timezone.now(),
                            logout_time=timezone.now()
                        )

                        # Create new session
                        session = UserSession.objects.create(
                            user=user,
                            login_time=timezone.now(),
                            session_key=request.session.session_key or '',
                            ip_address=ip_address,
                            user_agent=request.META.get('HTTP_USER_AGENT', ''),
                            is_active=True
                        )

                        # Set location information if IP is available
                        if ip_address:
                            session.update_location_from_ip(ip_address)

                        messages.success(request, f'Welcome back, {user.get_full_name() or user.username}!')

                        # Handle redirection
                        next_url = request.GET.get('next')
                        if next_url:
                            return redirect(next_url)
                        return redirect('core:dashboard')

                except Exception as e:
                    logger.error(f"Error creating session for user {username}: {e}")
                    messages.success(request, f'Welcome back, {user.get_full_name() or user.username}!')
                    return redirect('core:dashboard')

            else:
                messages.error(request, 'Invalid username or password. Please try again.')
        else:
            messages.error(request, 'Please enter both username and password.')

    return render(request, 'login.html', {
        'title': 'Login - TrueAlign'
    })


@login_required
def logout_view(request):
    """
    Logout view with proper session cleanup
    All times handled in Asia/Kolkata timezone
    """
    try:
        # End all active sessions for this user
        active_sessions = UserSession.objects.filter(
            user=request.user,
            is_active=True
        )

        for session in active_sessions:
            session.end_session()
            logger.info(f"Session {session.id} ended for user {request.user.username}")

        logout(request)
        messages.success(request, 'You have been logged out successfully.')

    except Exception as e:
        logger.error(f"Error during logout for user {request.user.username}: {e}")
        logout(request)
        messages.success(request, 'You have been logged out successfully.')

    return redirect('core:login')


@login_required
@csrf_exempt
def update_last_activity(request):
    """
    Update last activity timestamp for user session
    All times handled in Asia/Kolkata timezone
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST method allowed'}, status=405)

    try:
        # Get the most recent active session for this user
        session = UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).order_by('-login_time').first()

        if session:
            session.update_last_activity()
            return JsonResponse({
                'status': 'success',
                'last_activity': to_ist(session.last_activity).isoformat()
            })
        else:
            return JsonResponse({
                'status': 'error',
                'message': 'No active session found'
            }, status=404)

    except Exception as e:
        logger.error(f"Error updating last activity: {e}")
        return JsonResponse({
            'status': 'error',
            'message': 'Internal server error'
        }, status=500)


def _process_activities(session, activity_data):
    """Process various activity types for a session"""
    try:
        activity_type = activity_data.get('type')

        if activity_type == 'click':
            session.update_click({
                'timestamp': timezone.now().isoformat(),
                'coordinates': activity_data.get('coordinates', {}),
                'element_info': activity_data.get('element_info', {}),
                'interaction_type': activity_data.get('interaction_type', 'click')
            })

        elif activity_type == 'scroll':
            session.update_scroll({
                'timestamp': timezone.now().isoformat(),
                'scroll_position': activity_data.get('scroll_position', 0),
                'scroll_direction': activity_data.get('scroll_direction', 'down')
            })

        elif activity_type == 'keyboard':
            session.update_keyboard({
                'timestamp': timezone.now().isoformat(),
                'key_count': activity_data.get('key_count', 1),
                'input_type': activity_data.get('input_type', 'text')
            })

        elif activity_type == 'mouse_move':
            session.update_mouse_move({
                'timestamp': timezone.now().isoformat(),
                'coordinates': activity_data.get('coordinates', {})
            })

        elif activity_type == 'tab_visibility':
            session.update_tab_visibility({
                'timestamp': timezone.now().isoformat(),
                'action': activity_data.get('action', 'focus_gained'),
                'previous_url': activity_data.get('previous_url'),
                'current_url': activity_data.get('current_url')
            })

        elif activity_type == 'page_view':
            session.update_page_view({
                'timestamp': timezone.now().isoformat(),
                'url': activity_data.get('url', ''),
                'title': activity_data.get('title', ''),
                'referrer': activity_data.get('referrer', ''),
                'load_time': activity_data.get('load_time')
            })

    except Exception as e:
        logger.error(f"Error processing activity {activity_type}: {e}")


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
@csrf_exempt
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
            timeout_threshold = getattr(session, 'custom_timeout', None) or 30  # Default 30 minutes
            idle_minutes = idle_duration.total_seconds() / 60
            warning_threshold = 25  # Default warning threshold

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
                'location': session.location_city or 'Unknown',
                'device': session.device_type or 'Unknown'
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
@csrf_exempt
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

        # Calculate total working hours using working_time field
        total_working_seconds = 0
        for session in sessions:
            if session.working_time:
                total_working_seconds += session.working_time.total_seconds()
            elif session.is_active:
                # For active sessions, calculate current working hours
                current_time = timezone.now()
                duration = current_time - session.login_time
                # Use total_idle_time instead of idle_time
                idle_time = session.total_idle_time or timedelta(0)
                working_duration = duration - idle_time
                total_working_seconds += working_duration.total_seconds()

        total_working_hours = total_working_seconds / 3600

        # Get location breakdown
        location_data = {}
        for session in sessions:
            location = session.location_city or 'Unknown'
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

        # Helper method to get session duration display
        def get_session_duration_display(session):
            if session.ended_at:
                duration = session.ended_at - session.login_time
            else:
                duration = timezone.now() - session.login_time

            hours = int(duration.total_seconds() // 3600)
            minutes = int((duration.total_seconds() % 3600) // 60)
            return f"{hours}h {minutes}m"

        # Helper method to get working hours display
        def get_working_hours_display(session):
            if session.working_time:
                hours = int(session.working_time.total_seconds() // 3600)
                minutes = int((session.working_time.total_seconds() % 3600) // 60)
                return f"{hours}h {minutes}m"
            return "0h 0m"

        # Format response
        return JsonResponse({
            'total_sessions': total_sessions,
            'active_sessions': active_sessions,
            'total_working_hours': round(total_working_hours, 2),
            'location_breakdown': location_data,
            'recent_sessions': [
                {
                    'id': str(session.id),
                    'login_time': to_ist(session.login_time).isoformat(),
                    'logout_time': to_ist(session.logout_time).isoformat() if session.logout_time else None,
                    'duration': get_session_duration_display(session),
                    'working_hours': get_working_hours_display(session),
                    'location': session.location_city or 'Unknown',
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
@csrf_exempt
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
        timeout_threshold = session.custom_timeout or 30  # Default 30 minutes
        warning_threshold = 25  # Default warning threshold

        is_warning = idle_minutes >= warning_threshold
        remaining_minutes = max(0, timeout_threshold - idle_minutes)

        # Get tab information
        tab_info = None
        if session.tab_id:
            tab_info = {
                'tab_id': session.tab_id,
                'title': session.tab_title if isinstance(session.tab_title, str) else session.tab_title[0] if isinstance(session.tab_title, list) and session.tab_title else '',
                'url': session.tab_url if isinstance(session.tab_url, str) else session.tab_url[0] if isinstance(session.tab_url, list) and session.tab_url else '',
                'opened_time': to_ist(session.tab_opened_time).isoformat() if session.tab_opened_time else None,
                'is_primary': session.is_primary_tab
            }

        # Get all tabs in this session
        related_tabs = []
        if session.parent_session_id:
            related_sessions = UserSession.objects.filter(
                user=request.user,
                parent_session_id=session.parent_session_id,
                is_active=True
            ).exclude(id=session.id)

            for tab in related_sessions:
                related_tabs.append({
                    'tab_id': tab.tab_id,
                    'title': tab.tab_title if isinstance(tab.tab_title, str) else tab.tab_title[0] if isinstance(tab.tab_title, list) and tab.tab_title else '',
                    'url': tab.tab_url if isinstance(tab.tab_url, str) else tab.tab_url[0] if isinstance(tab.tab_url, list) and tab.tab_url else '',
                    'is_primary': tab.is_primary_tab,
                    'last_activity': to_ist(tab.last_activity).isoformat()
                })

        return JsonResponse({
            'status': 'active',
            'session_id': str(session.id),
            'parent_session_id': str(session.parent_session_id) if session.parent_session_id else None,
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
            'location': session.location_city or 'Unknown',
            'device': session.device_type or 'Unknown',
            'tab': tab_info,
            'related_tabs': related_tabs,
            'productivity_score': session.productivity_score
        })

    except Exception as e:
        logger.error(f"Error getting session status: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@csrf_exempt
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

            sessions_ended = 0
            for session in active_sessions:
                session.end_session(is_idle=is_idle)
                sessions_ended += 1

            return JsonResponse({
                'status': 'success',
                'message': 'All sessions ended successfully.',
                'sessions_ended': sessions_ended
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
                    'session_id': str(session.id)
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
                    'session_id': str(session.id)
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
@csrf_exempt
def log_activity(request):
    """
    Log various user activities
    All times handled in Asia/Kolkata timezone
    """
    if request.method != 'POST':
        return JsonResponse({'status': 'error', 'message': 'Only POST method allowed'}, status=405)

    try:
        data = json.loads(request.body)
        activity_type = data.get('type')
        tab_id = data.get('tab_id')

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
            return JsonResponse({'status': 'error', 'message': 'No active session found'}, status=404)

        # Process the activity
        _process_activities(session, data)

        # Update last activity
        session.update_last_activity()

        return JsonResponse({'status': 'success', 'message': 'Activity logged successfully'})

    except json.JSONDecodeError:
        return JsonResponse({'status': 'error', 'message': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error logging activity: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@csrf_exempt
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
            if hasattr(session, 'page_views') and hasattr(session, 'clicks') and hasattr(session, 'keyboard_events'):
                if session.page_views or session.clicks or session.keyboard_events:
                    session.calculate_productivity_score()
                    session.save(update_fields=['productivity_score'])
        except Exception as e:
            logger.error(f"Error calculating productivity score: {e}")

        # Check timeout status
        last_activity_ist = to_ist(session.last_activity)
        idle_duration = current_time_ist - last_activity_ist
        idle_minutes = idle_duration.total_seconds() / 60

        timeout_threshold = getattr(session, 'custom_timeout', None) or 30  # Default 30 minutes
        warning_threshold = 25  # Default warning threshold

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


# Custom Password Reset Views
class CustomPasswordResetView(PasswordResetView):
    template_name = 'registration/password_reset_form.html'
    email_template_name = 'registration/password_reset_email.html'
    subject_template_name = 'registration/password_reset_subject.txt'
    success_url = reverse_lazy('password_reset_done')
    form_class = PasswordResetForm

    def form_valid(self, form):
        """
        Custom form validation for password reset
        """
        try:
            response = super().form_valid(form)
            messages.success(
                self.request,
                'Password reset instructions have been sent to your email address.'
            )
            return response
        except Exception as e:
            logger.error(f"Error in password reset: {e}")
            messages.error(
                self.request,
                'There was an error sending the password reset email. Please try again.'
            )
            return self.form_invalid(form)


class CustomPasswordResetDoneView(PasswordResetDoneView):
    template_name = 'registration/password_reset_done.html'


class CustomPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = 'registration/password_reset_confirm.html'
    success_url = reverse_lazy('password_reset_complete')
    form_class = SetPasswordForm

    def form_valid(self, form):
        """
        Custom form validation for password reset confirmation
        """
        try:
            response = super().form_valid(form)

            # End all active sessions for this user when password is reset
            user = form.user
            active_sessions = UserSession.objects.filter(
                user=user,
                is_active=True
            )

            for session in active_sessions:
                session.end_session()
                logger.info(f"Session {session.id} ended due to password reset for user {user.username}")

            messages.success(
                self.request,
                'Your password has been set successfully. All active sessions have been terminated for security.'
            )
            return response
        except Exception as e:
            logger.error(f"Error in password reset confirm: {e}")
            messages.error(
                self.request,
                'There was an error setting your password. Please try again.'
            )
            return self.form_invalid(form)


class CustomPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = 'registration/password_reset_complete.html'


from trueAlign.conf_booking.views import get_upcoming_booking_for_room, conference_booking_context
from datetime import timedelta
from django.utils import timezone

@login_required
def dashboard_view(request):
    """
    Dashboard view with session information and conference room data
    All times handled in Asia/Kolkata timezone
    """
    try:
        # Get current user's active session
        user_session = UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).order_by('-login_time').first()

        # Helper function to format timedelta
        def format_timedelta(td):
            if not td:
                return "0 minutes"

            total_seconds = int(td.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, _ = divmod(remainder, 60)

            if hours > 0:
                return f"{hours}h {minutes}m"
            else:
                return f"{minutes}m"

        # Initialize user status
        user_status = {
            'status': 'offline',
            'color': 'gray',
            'total_idle_time': None,
            'working_time': None,
            'formatted_idle_time': None
        }

        if user_session:
            # Calculate current idle time
            current_time_ist = get_current_time_ist()
            last_activity_ist = to_ist(user_session.last_activity)
            current_idle = current_time_ist - last_activity_ist
            current_idle_minutes = current_idle.total_seconds() / 60

            # Determine status
            if current_idle_minutes < 5:
                user_status['status'] = 'active'
                user_status['color'] = 'green'
            elif current_idle_minutes < 15:
                user_status['status'] = 'idle'
                user_status['color'] = 'yellow'
            else:
                user_status['status'] = 'away'
                user_status['color'] = 'red'

            user_status['total_idle_time'] = user_session.total_idle_time
            user_status['working_time'] = user_session.working_time
            user_status['last_activity'] = user_session.last_activity if user_session.last_activity else None

            # Format idle time as readable string
            if user_status['total_idle_time']:
                user_status['formatted_idle_time'] = format_timedelta(user_status['total_idle_time'])

        # Get recent sessions for analytics
        recent_sessions = UserSession.objects.filter(
            user=request.user
        ).order_by('-login_time')[:10]

        # Calculate session statistics
        total_sessions = UserSession.objects.filter(user=request.user).count()
        active_sessions = UserSession.objects.filter(user=request.user, is_active=True).count()

        # Get conference booking context with the correct parameter
        try:
            # Pass the user, not the request, to conference_booking_context
            booking_context = conference_booking_context(user=request.user)

            # The context already includes available_rooms and user_bookings
            available_rooms = booking_context.get('available_rooms', [])
            user_bookings = booking_context.get('user_bookings', [])

            # Enhance available_rooms with upcoming booking details
            enhanced_rooms = []
            for room in available_rooms:
                # Get upcoming booking for this specific room
                upcoming_booking = get_upcoming_booking_for_room(room.name)

                # Create enhanced room object with all needed properties
                enhanced_room = {
                    'id': room.id,
                    'name': room.name,
                    'capacity': room.capacity,
                    'location': room.location,
                    'room_type': getattr(room, 'room_type', 'Conference'),
                    'facilities': getattr(room, 'facilities', []),
                    'status': room.status,
                    'is_available': room.is_available,
                    'is_occupied': room.is_occupied,
                    'current_booking': room.current_booking,
                    'next_booking': room.next_booking or upcoming_booking,
                }

                # Convert to object-like structure for template compatibility
                enhanced_room_obj = type('Room', (), enhanced_room)()
                enhanced_rooms.append(enhanced_room_obj)

            available_rooms = enhanced_rooms

            # Add additional properties needed by the template for user bookings
            enhanced_bookings = []
            current_time = timezone.now()

            for booking in user_bookings:
                # Check if user can check in (15 minutes before to 5 minutes after start)
                can_check_in = (
                    not getattr(booking, 'checked_in', False) and
                    current_time >= booking.start_time - timedelta(minutes=15) and
                    current_time <= booking.start_time + timedelta(minutes=5) and
                    booking.status == 'confirmed'
                )

                # Check if booking can be cancelled (at least 30 minutes before start)
                can_be_cancelled = (
                    booking.status == 'confirmed' and
                    booking.start_time > current_time + timedelta(minutes=30)
                )

                # Create enhanced booking object
                enhanced_booking = {
                    'id': booking.id,
                    'room': booking.room,
                    'purpose': booking.purpose,
                    'start_time': booking.start_time,
                    'end_time': booking.end_time,
                    'attendees_count': getattr(booking, 'attendees_count', 1),
                    'checked_in': getattr(booking, 'checked_in', False),
                    'status': booking.status,
                    'can_check_in': can_check_in,
                    'can_be_cancelled': can_be_cancelled,
                    'booked_by': booking.booked_by,
                }

                # Convert to object-like structure for template compatibility
                enhanced_booking_obj = type('Booking', (), enhanced_booking)()
                enhanced_bookings.append(enhanced_booking_obj)

            user_bookings = enhanced_bookings

            # Get additional upcoming bookings for all rooms (for better dashboard overview)
            all_upcoming_bookings = get_all_upcoming_bookings()

        except Exception as booking_error:
            logger.error(f"Error getting booking data: {booking_error}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            available_rooms = []
            user_bookings = []
            booking_context = {}
            all_upcoming_bookings = []

        attendance_context = get_attendance_context_for_dashboard(request.user)

        context = {
            'user_session': user_session,
            'user_status': user_status,
            'recent_sessions': recent_sessions,
            'total_sessions': total_sessions,
            'active_sessions': active_sessions,
            'available_rooms': available_rooms,
            'user_bookings': user_bookings,
            'all_upcoming_bookings': all_upcoming_bookings,
            **attendance_context,
            **booking_context  # Merge booking context (this includes conference_form, user_analytics)
        }

        logger.info(f"Dashboard context - available_rooms count: {len(available_rooms)}, user_bookings count: {len(user_bookings)}")

        return render(request, 'dashboard.html', context)

    except Exception as e:
        logger.error(f"Error in dashboard view: {e}")
        import traceback
        logger.error(f"Full traceback: {traceback.format_exc()}")

        # Fallback context in case of error
        context = {
            'user_session': None,
            'user_status': {'status': 'offline', 'color': 'gray'},
            'recent_sessions': [],
            'total_sessions': 0,
            'active_sessions': 0,
            'available_rooms': [],
            'user_bookings': [],
            'all_upcoming_bookings': [],
        }
        return render(request, 'dashboard.html', context)


def get_all_upcoming_bookings():
    """
    Get all upcoming bookings for today across all rooms
    """
    try:
        from django.utils import timezone

        current_time = timezone.now()
        today_end = current_time.replace(hour=23, minute=59, second=59, microsecond=999999)

        # Get all confirmed bookings for today that haven't started yet
        upcoming_bookings = ConferenceBooking.objects.filter(
            start_time__gte=current_time,
            start_time__lte=today_end,
            status='confirmed'
        ).select_related('room', 'booked_by').order_by('start_time')[:10]  # Limit to 10

        return [
            {
                'id': booking.id,
                'room_name': booking.room.name,
                'purpose': booking.purpose,
                'start_time': booking.start_time,
                'end_time': booking.end_time,
                'booked_by': booking.booked_by.get_full_name() or booking.booked_by.username,
                'attendees_count': getattr(booking, 'attendees_count', 1),
            }
            for booking in upcoming_bookings
        ]

    except Exception as e:
        logger.error(f"Error getting all upcoming bookings: {e}")
        return []


def get_room_upcoming_bookings(room_names=None):
    """
    Get upcoming bookings for specific rooms or all rooms
    """
    try:

        if room_names:
            rooms = Room.objects.filter(name__in=room_names, status=Room.RoomStatus.ACTIVE)
        else:
            rooms = Room.objects.filter(status=Room.RoomStatus.ACTIVE)

        room_bookings = {}

        for room in rooms:
            upcoming_booking = get_upcoming_booking_for_room(room.name)
            if upcoming_booking:
                room_bookings[room.name] = {
                    'room_id': room.id,
                    'room_name': room.name,
                    'booking': {
                        'id': upcoming_booking.id,
                        'purpose': upcoming_booking.purpose,
                        'start_time': upcoming_booking.start_time,
                        'end_time': upcoming_booking.end_time,
                        'booked_by': upcoming_booking.booked_by.get_full_name() or upcoming_booking.booked_by.username,
                        'status': upcoming_booking.status,
                    }
                }

        return room_bookings

    except Exception as e:
        logger.error(f"Error getting room upcoming bookings: {e}")
        return {}



# Helper function for safe ISO format conversion
def safe_isoformat(dt):
    """
    Safely convert datetime to ISO format string
    """
    try:
        if dt is None:
            return None
        return dt.isoformat()
    except Exception as e:
        logger.error(f"Error converting datetime to ISO format: {e}")
        return None


@login_required
@csrf_exempt
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
@csrf_exempt
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

        # Update page views if URL is provided
        if client_data.get('url'):
            if not session.page_views:
                session.page_views = []
            session.page_views.append({
                'url': client_data.get('url'),
                'title': client_data.get('title', ''),
                'timestamp': timezone.now().isoformat(),
                'referrer': client_data.get('referrer', '')
            })

        # Update device info if provided
        device_info = data.get('device_info', {})
        if device_info:
            session.update_device_info(device_info)

        # Update last activity and idle status
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

def get_attendance_context_for_dashboard(user):
    """Get attendance context for dashboard"""
    IST = pytz.timezone('Asia/Kolkata')
    today = timezone.now().astimezone(IST).date()

    try:
        # Get or create today's attendance
        attendance_today, created = Attendance.objects.get_or_create_today_attendance(user, today)

        # Calculate monthly stats
        this_month_start = today.replace(day=1)
        monthly_attendance = Attendance.objects.get_user_attendance_for_period(
            user, this_month_start, today
        )

        # Count different status types
        present_count = monthly_attendance.filter(
            status__in=['Present', 'Present & Late', 'Work From Home']
        ).count()

        late_count = monthly_attendance.filter(
            status__in=['Late', 'Present & Late']
        ).count()

        leave_count = monthly_attendance.filter(
            status__in=['On Leave', 'Absent', 'Half Day']
        ).count()

        # Calculate working days (exclude weekends and holidays)
        working_days_count = monthly_attendance.exclude(
            status__in=['Weekend', 'Holiday']
        ).count()

        # Calculate attendance percentage based on working days
        if working_days_count > 0:
            attendance_percentage = round((present_count / working_days_count) * 100, 1)
        else:
            attendance_percentage = 0

        monthly_stats = {
            'present_count': present_count,
            'late_count': late_count,
            'leave_count': leave_count,
            'total_days': monthly_attendance.count(),
            'working_days': working_days_count,
            'attendance_percentage': attendance_percentage,
        }

        return {
            'today_attendance': attendance_today,
            'monthly_stats': monthly_stats,
        }
    except Exception as e:
        logger.error(f"Error getting attendance context for dashboard: {e}")
        return {
            'today_attendance': None,
            'monthly_stats': {
                'present_count': 0,
                'late_count': 0,
                'leave_count': 0,
                'total_days': 0,
                'working_days': 0,
                'attendance_percentage': 0,
            },
        }
