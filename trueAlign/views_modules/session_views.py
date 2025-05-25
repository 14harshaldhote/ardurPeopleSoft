from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.models import User, Group
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required, user_passes_test
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST, require_GET
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.db import transaction
from django.db.models import Q, Count, Avg, Sum, F
from datetime import datetime, timedelta, date
from decimal import Decimal
import json
import logging
import pytz
from ..models import UserSession

# Set up logging
logger = logging.getLogger(__name__)

# Asia/Kolkata timezone
IST = pytz.timezone('Asia/Kolkata')

def get_current_time_ist():
    """Return current time in Asia/Kolkata timezone (aware)."""
    return timezone.now().astimezone(IST)

def to_ist(dt):
    """Convert a datetime to Asia/Kolkata timezone (aware)."""
    if dt is None:
        return None
    if timezone.is_naive(dt):
        return timezone.make_aware(dt, IST)
    return dt.astimezone(IST)

def to_utc(dt_ist):
    """Convert IST datetime to UTC for database storage."""
    if dt_ist is None:
        return None
    if timezone.is_naive(dt_ist):
        dt_ist = IST.localize(dt_ist)
    return dt_ist.astimezone(timezone.utc)

@login_required
@require_POST
def session_heartbeat(request):
    """
    Handle session heartbeat with comprehensive tracking
    All times handled in Asia/Kolkata timezone
    """
    try:
        data = json.loads(request.body)

        # Extract session information
        tab_id = data.get('tabId') or request.headers.get('X-Tab-ID')
        parent_session_id = data.get('parentSessionId') or request.headers.get('X-Parent-Session-ID')
        device_fingerprint = data.get('deviceFingerprint') or request.headers.get('X-Device-Fingerprint')

        if not tab_id:
            return JsonResponse({'error': 'Tab ID required'}, status=400)

        # Get or create session
        user_session = _get_or_create_session(request.user, tab_id, parent_session_id, request, data)

        # Check for auto-logout
        if user_session.should_auto_logout():
            logger.info(f"Auto-logout triggered for user {request.user.username}")
            user_session.end_session()
            logout(request)
            return JsonResponse({
                'status': 'expired',
                'message': 'Your session has expired due to inactivity.',
                'redirect': '/login/?reason=timeout'
            })

        # Update session activity
        current_time_ist = get_current_time_ist()
        activity_data = {
            'is_idle': data.get('isIdle', False),
            'is_focused': data.get('isFocused', True),
            'is_online': data.get('isOnline', True),
            'url': data.get('url', request.get_full_path()),
            'performance_data': data.get('performanceMetrics', {}),
            'battery_level': data.get('batteryInfo', {}).get('level'),
            'connection_type': data.get('connectionInfo', {}).get('effectiveType'),
            'activity_count': data.get('activityCount', 0),
            'current_time_ist': current_time_ist
        }

        user_session.update_tab_activity(activity_data)

        # Check security anomalies
        warnings = []
        if device_fingerprint:
            anomalies = user_session.check_security_anomalies(device_fingerprint)
            if anomalies:
                warnings.extend([{
                    'type': 'security_anomaly',
                    'details': anomaly
                } for anomaly in anomalies])

        # Check for inactivity warning
        show_warning = user_session.should_show_inactivity_warning()
        if show_warning:
            user_session.record_inactivity_warning()
            warnings.append({
                'type': 'inactivity_warning',
                'message': 'Your session will expire soon due to inactivity'
            })

        # Get session summary
        summary = user_session.get_session_summary()

        return JsonResponse({
            'status': 'active',
            'session_id': user_session.parent_session_id,
            'tab_id': user_session.tab_id,
            'is_primary_tab': user_session.is_primary_tab,
            'idle': user_session.is_idle(),
            'productivity_score': user_session.productivity_score,
            'engagement_score': user_session.engagement_score,
            'warnings': warnings,
            'summary': summary,
            'server_time': current_time_ist.isoformat()
        })

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error in session heartbeat: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

@login_required
@require_POST
def log_activity(request):
    """
    Log user activities from client-side buffer
    All times handled in Asia/Kolkata timezone
    """
    try:
        data = json.loads(request.body)

        tab_id = data.get('tabId') or request.headers.get('X-Tab-ID')
        parent_session_id = data.get('parentSessionId') or request.headers.get('X-Parent-Session-ID')
        activities = data.get('activities', [])

        if not tab_id:
            return JsonResponse({'error': 'Tab ID required'}, status=400)

        # Get session
        user_session = UserSession.objects.filter(
            user=request.user,
            tab_id=tab_id,
            is_active=True
        ).first()

        if not user_session:
            # Try to find by parent session
            user_session = UserSession.objects.filter(
                user=request.user,
                parent_session_id=parent_session_id,
                is_active=True
            ).first()

        if not user_session:
            return JsonResponse({'error': 'Session not found'}, status=404)

        # Check if session expired
        if user_session.should_auto_logout():
            user_session.end_session()
            logout(request)
            return JsonResponse({
                'status': 'expired',
                'message': 'Your session has expired.',
                'redirect': '/login/'
            })

        # Process activities
        _process_activities(user_session, activities)

        # Update performance metrics if provided
        if data.get('performanceMetrics'):
            if not user_session.performance_metrics:
                user_session.performance_metrics = {}
            user_session.performance_metrics.update(data['performanceMetrics'])
            user_session.save(update_fields=['performance_metrics'])

        return JsonResponse({
            'status': 'success',
            'processed_activities': len(activities),
            'session_active': True
        })

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error logging activity: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

@login_required
@require_POST
def end_session(request):
    """
    End user session properly
    All times handled in Asia/Kolkata timezone
    """
    try:
        data = json.loads(request.body) if request.body else {}

        tab_id = data.get('tabId') or request.headers.get('X-Tab-ID')
        parent_session_id = data.get('parentSessionId') or request.headers.get('X-Parent-Session-ID')

        current_time_ist = get_current_time_ist()
        current_time_utc = to_utc(current_time_ist)

        # End specific tab session
        if tab_id:
            user_session = UserSession.objects.filter(
                user=request.user,
                tab_id=tab_id,
                is_active=True
            ).first()

            if user_session:
                user_session.end_session(logout_time=current_time_utc)
                logger.info(f"Ended tab session {tab_id} for user {request.user.username}")

        # End all sessions for this parent session
        if parent_session_id:
            sessions = UserSession.objects.filter(
                user=request.user,
                parent_session_id=parent_session_id,
                is_active=True
            )

            for session in sessions:
                session.end_session(logout_time=current_time_utc)

            logger.info(f"Ended parent session {parent_session_id} for user {request.user.username}")

        # If no specific session specified, end all active sessions
        if not tab_id and not parent_session_id:
            sessions = UserSession.objects.filter(
                user=request.user,
                is_active=True
            )

            for session in sessions:
                session.end_session(logout_time=current_time_utc)

            logger.info(f"Ended all sessions for user {request.user.username}")

        return JsonResponse({'status': 'success', 'message': 'Session ended successfully'})

    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)
    except Exception as e:
        logger.error(f"Error ending session: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

@login_required
@require_GET
def session_status(request):
    """
    Get current session status and analytics
    All times returned in Asia/Kolkata timezone
    """
    try:
        tab_id = request.GET.get('tab_id') or request.headers.get('X-Tab-ID')

        # Get user's active sessions
        sessions = UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).order_by('-login_time')

        if tab_id:
            # Get specific tab session
            current_session = sessions.filter(tab_id=tab_id).first()
        else:
            # Get primary session
            current_session = sessions.filter(is_primary_tab=True).first() or sessions.first()

        if not current_session:
            return JsonResponse({'status': 'no_active_session'})

        # Calculate session analytics
        total_tabs = sessions.count()
        current_time_ist = get_current_time_ist()
        login_time_ist = to_ist(current_session.login_time)
        session_duration = (current_time_ist - login_time_ist).total_seconds() / 60

        # Get multi-tab analytics
        analytics = UserSession.get_multi_tab_analytics(user=request.user, days=1)

        return JsonResponse({
            'status': 'active',
            'current_session': current_session.get_session_summary(),
            'total_active_tabs': total_tabs,
            'session_duration_minutes': session_duration,
            'analytics': analytics,
            'server_time': current_time_ist.isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting session status: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

@login_required
@require_GET
def session_analytics(request):
    """
    Get comprehensive session analytics
    All times handled in Asia/Kolkata timezone
    """
    try:
        days = int(request.GET.get('days', 7))
        days = min(days, 90)  # Limit to 90 days

        current_time_ist = get_current_time_ist()
        start_date_ist = current_time_ist - timedelta(days=days)
        start_date_utc = to_utc(start_date_ist)

        # Get user sessions
        sessions = UserSession.objects.filter(
            user=request.user,
            login_time__gte=start_date_utc
        )

        # Basic statistics
        stats = {
            'total_sessions': sessions.count(),
            'avg_session_duration': sessions.aggregate(
                avg_duration=Avg('session_duration')
            )['avg_duration'] or 0,
            'total_working_hours': sessions.aggregate(
                total_hours=Sum('working_hours')
            )['total_hours'] or timedelta(0),
            'total_idle_time': sessions.aggregate(
                total_idle=Sum('idle_time')
            )['total_idle'] or timedelta(0),
            'avg_productivity_score': sessions.filter(
                productivity_score__isnull=False
            ).aggregate(
                avg_score=Avg('productivity_score')
            )['avg_score'] or 0
        }

        # Multi-tab analytics
        multi_tab_stats = UserSession.get_multi_tab_analytics(user=request.user, days=days)

        # Device type breakdown
        device_stats = sessions.values('device_type').annotate(
            count=Count('id'),
            avg_duration=Avg('session_duration')
        ).order_by('-count')

        # Location breakdown
        location_stats = sessions.values('location').annotate(
            count=Count('id'),
            total_hours=Sum('working_hours')
        ).order_by('-count')

        # Daily activity pattern
        daily_activity = sessions.extra(
            select={'day': 'date(login_time)'}
        ).values('day').annotate(
            session_count=Count('id'),
            total_duration=Sum('session_duration'),
            avg_productivity=Avg('productivity_score')
        ).order_by('day')

        return JsonResponse({
            'period_days': days,
            'basic_stats': stats,
            'multi_tab_stats': multi_tab_stats,
            'device_breakdown': list(device_stats),
            'location_breakdown': list(location_stats),
            'daily_activity': list(daily_activity),
            'generated_at': current_time_ist.isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting session analytics: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)

@login_required
@csrf_exempt
def update_last_activity(request):
    """
    View to handle activity updates from the client.
    Updates the user's last activity timestamp and tracks idle time.
    All times are handled and stored in Asia/Kolkata (IST) timezone.
    """
    if request.method == 'POST':
        try:
            with transaction.atomic():
                # Parse request data
                try:
                    data = json.loads(request.body)
                except ValueError:
                    data = {}

                # Get client IP
                x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
                ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

                # Get current time in IST
                current_time_ist = get_current_time_ist()
                current_time_utc = to_utc(current_time_ist)

                # Get or create user session using model logic
                user_session = UserSession.objects.filter(
                    user=request.user,
                    is_active=True
                ).select_for_update().first()

                if not user_session:
                    # Use model method to create session
                    user_session = UserSession.get_or_create_session(
                        user=request.user,
                        session_key=request.session.session_key,
                        ip_address=ip_address,
                        user_agent=request.META.get('HTTP_USER_AGENT', None)
                    )
                    return JsonResponse({
                        'status': 'success',
                        'message': 'New session created',
                        'session_id': user_session.id,
                        'server_time': current_time_ist.isoformat()
                    })

                # Ensure last_activity is in IST for comparison
                last_activity_ist = to_ist(user_session.last_activity)

                # Check for session timeout (5 minutes)
                if (current_time_ist - last_activity_ist) > timedelta(minutes=5):
                    user_session.end_session(current_time_utc, is_idle=True)
                    new_session = UserSession.get_or_create_session(
                        user=request.user,
                        session_key=request.session.session_key,
                        ip_address=ip_address,
                        user_agent=request.META.get('HTTP_USER_AGENT', None)
                    )
                    return JsonResponse({
                        'status': 'success',
                        'sessionExpired': True,
                        'message': 'Previous session timed out, new session created',
                        'session_id': new_session.id,
                        'server_time': current_time_ist.isoformat()
                    })

                # Update IP and location if changed
                if user_session.ip_address != ip_address:
                    user_session.ip_address = ip_address
                    user_session.location = user_session.determine_location()
                    user_session.save(update_fields=['ip_address', 'location'])

                # Handle client-reported idle state
                is_idle = data.get('isIdle', False)
                is_focused = data.get('isFocused', True)

                # Update activity with idle state
                user_session.update_activity(current_time_utc, is_idle=is_idle)

                user_session.refresh_from_db()

                # Always return times in IST
                last_activity_ist = to_ist(user_session.last_activity)
                working_hours = user_session.working_hours
                if working_hours is not None:
                    working_hours = str(working_hours)
                else:
                    working_hours = None

                return JsonResponse({
                    'status': 'success',
                    'last_activity': last_activity_ist.isoformat() if last_activity_ist else None,
                    'idle_time': str(user_session.idle_time),
                    'working_hours': working_hours,
                    'location': user_session.location,
                    'server_time': current_time_ist.isoformat()
                })

        except Exception as e:
            logger.error(f"Error updating last activity: {str(e)}")
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=400)

    return JsonResponse({
        'status': 'error',
        'message': 'Invalid request method'
    }, status=405)

@login_required
def get_session_status(request):
    """Get the current session status. All times are returned in Asia/Kolkata (IST) timezone."""
    try:
        user_session = UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).first()

        if not user_session:
            return JsonResponse({
                'status': 'error',
                'message': 'No active session found'
            }, status=404)

        current_time_ist = get_current_time_ist()
        login_time_ist = to_ist(user_session.login_time)
        last_activity_ist = to_ist(user_session.last_activity)

        return JsonResponse({
            'status': 'success',
            'session_id': user_session.id,
            'login_time': login_time_ist.isoformat() if login_time_ist else None,
            'last_activity': last_activity_ist.isoformat() if last_activity_ist else None,
            'idle_time': str(user_session.idle_time),
            'location': user_session.location,
            'session_duration': user_session.get_session_duration_display(),
            'server_time': current_time_ist.isoformat()
        })

    except Exception as e:
        return JsonResponse({
            'status': 'error',
            'message': str(e)
        }, status=400)

def _get_or_create_session(user, tab_id, parent_session_id, request, data):
    """
    Get existing session or create new one with enhanced tracking
    All times handled in Asia/Kolkata timezone
    """
    with transaction.atomic():
        current_time_ist = get_current_time_ist()
        current_time_utc = to_utc(current_time_ist)

        # Look for existing session with this tab_id
        user_session = UserSession.objects.filter(
            user=user,
            tab_id=tab_id,
            is_active=True
        ).select_for_update().first()

        if user_session:
            # Update existing session
            user_session.last_activity = current_time_utc
            user_session.save(update_fields=['last_activity'])
            return user_session

        # Generate parent session ID if not provided
        if not parent_session_id:
            parent_session_id = f"{user.id}_{current_time_ist.strftime('%Y%m%d_%H%M%S')}"

        # Check if this is the first tab in the session
        existing_tabs_count = UserSession.objects.filter(
            user=user,
            parent_session_id=parent_session_id,
            is_active=True
        ).count()

        is_primary_tab = existing_tabs_count == 0

        # Extract client info
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip_address = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')

        # Detect device type
        user_agent = request.META.get('HTTP_USER_AGENT', '').lower()
        if any(mobile in user_agent for mobile in ['mobile', 'android', 'iphone']):
            device_type = 'mobile'
        elif 'ipad' in user_agent or 'tablet' in user_agent:
            device_type = 'tablet'
        else:
            device_type = 'desktop'

        # Create session
        user_session = UserSession.objects.create(
            user=user,
            session_key=request.session.session_key or UserSession.generate_session_key(),
            ip_address=ip_address,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            login_time=current_time_utc,
            last_activity=current_time_utc,
            tab_id=tab_id,
            tab_opened_time=current_time_utc,
            tab_last_focus=current_time_utc,
            is_primary_tab=is_primary_tab,
            parent_session_id=parent_session_id,
            session_fingerprint=data.get('deviceFingerprint'),
            device_type=device_type,
            screen_resolution=data.get('sessionFingerprint', {}).get('screen'),
            timezone_offset=data.get('sessionFingerprint', {}).get('timezoneOffset'),
            language=data.get('sessionFingerprint', {}).get('language'),
            tab_url=data.get('url', request.get_full_path()),
            is_active=True
        )

        # Set location
        user_session.location = user_session.determine_location()
        user_session.save(update_fields=['location'])

        logger.info(f"Created new session for user {user.username}, tab_id: {tab_id}, primary: {is_primary_tab}")

        return user_session

def _process_activities(user_session, activities):
    """
    Process activity buffer from client
    All times handled in Asia/Kolkata timezone
    """
    if not activities:
        return

    current_time_ist = get_current_time_ist()
    current_time_utc = to_utc(current_time_ist)

    # Update last activity
    user_session.last_activity = current_time_utc

    # Process each activity
    for activity in activities:
        activity_type = activity.get('type')
        activity_timestamp = activity.get('timestamp')

        # Convert timestamp to IST if provided
        if activity_timestamp:
            try:
                activity_time_ist = datetime.fromtimestamp(activity_timestamp / 1000, tz=IST)
            except (ValueError, TypeError):
                activity_time_ist = current_time_ist
        else:
            activity_time_ist = current_time_ist

        if activity_type == 'click':
            if not user_session.click_events:
                user_session.click_events = []
            user_session.click_events.append({
                'timestamp': activity_time_ist.isoformat(),
                'target': activity.get('target'),
                'coordinates': activity.get('coordinates')
            })

        elif activity_type == 'scroll':
            if not user_session.scroll_events:
                user_session.scroll_events = []
            user_session.scroll_events.append({
                'timestamp': activity_time_ist.isoformat(),
                'scroll_position': activity.get('scrollPosition')
            })

        elif activity_type in ['keydown', 'keyup', 'keypress']:
            if not user_session.keyboard_events:
                user_session.keyboard_events = []
            user_session.keyboard_events.append({
                'timestamp': activity_time_ist.isoformat(),
                'key': activity.get('key')
            })

        elif activity_type == 'mousemove':
            user_session.mouse_movements += 1

        elif activity_type == 'page_change':
            user_session.tab_url = activity.get('url', user_session.tab_url)
            if not user_session.page_views:
                user_session.page_views = []
            user_session.page_views.append({
                'url': activity.get('url'),
                'timestamp': activity_time_ist.isoformat(),
                'referrer': activity.get('referrer', '')
            })

        elif activity_type in ['tab_focus', 'tab_blur']:
            if not user_session.tab_visibility_log:
                user_session.tab_visibility_log = []
            user_session.tab_visibility_log.append({
                'action': activity_type,
                'timestamp': activity_time_ist.isoformat(),
                'url': activity.get('url')
            })

            if activity_type == 'tab_focus':
                user_session.tab_switches += 1
                user_session.tab_last_focus = to_utc(activity_time_ist)

        elif activity_type == 'error':
            if not user_session.error_events:
                user_session.error_events = []
            user_session.error_events.append({
                'timestamp': activity_time_ist.isoformat(),
                'type': activity.get('error_type'),
                'message': activity.get('message'),
                'filename': activity.get('filename'),
                'lineno': activity.get('lineno')
            })

    # Trim arrays to prevent excessive growth
    for field in ['click_events', 'scroll_events', 'keyboard_events', 'page_views', 'tab_visibility_log', 'error_events']:
        events = getattr(user_session, field) or []
        if len(events) > 1000:  # Keep last 1000 events
            setattr(user_session, field, events[-1000:])

    # Update productivity and engagement scores
    user_session.calculate_productivity_score()
    user_session.calculate_engagement_score()

    user_session.save()


@login_required
@require_POST
def cleanup_sessions(request):
    """
    Clean up old expired sessions
    """
    try:
        hours = int(request.POST.get('hours', 24))
        hours = min(hours, 168)  # Limit to 1 week

        cleaned_count = UserSession.cleanup_expired_sessions(hours=hours)

        return JsonResponse({
            'status': 'success',
            'cleaned_sessions': cleaned_count,
            'hours': hours
        })

    except Exception as e:
        logger.error(f"Error cleaning up sessions: {str(e)}")
        return JsonResponse({'error': 'Internal server error'}, status=500)
