from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth.models import Group, User
from django.contrib import messages
from django.http import JsonResponse, HttpResponse, HttpResponseForbidden
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.db.models import (
    Q, Count, Avg, Sum, Max, Min, Prefetch,
    Case, When, Value, IntegerField, F, ExpressionWrapper,
    DateTimeField, DurationField
)
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_GET, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.db import transaction
from datetime import datetime, timedelta
import json
import csv
from collections import defaultdict, OrderedDict
from operator import itemgetter

# Import models from the main trueAlign app
from trueAlign.models import (
    UserSession, OfficeLocation, UserDetails,
    ShiftAssignment, ShiftMaster
)


# ============================================================================
# UTILITY FUNCTIONS & DECORATORS
# ============================================================================

def is_admin_user(user):
    """
    Enhanced admin check with caching for better performance.
    Returns True if user is superuser or belongs to 'Admin' group.
    """
    if not user.is_authenticated:
        return False

    # Cache the result for 5 minutes to avoid repeated database queries
    cache_key = f"is_admin_{user.id}"
    cached_result = cache.get(cache_key)
    if cached_result is not None:
        return cached_result

    result = False

    # Check if user is superuser
    if user.is_superuser:
        result = True
    elif hasattr(user, 'is_admin') and user.is_admin:
        result = True
    else:
        # Check if user belongs to Admin group
        try:
            result = user.groups.filter(name='Admin').exists()
        except Exception:
            result = False

    # Cache the result
    cache.set(cache_key, result, 300)  # 5 minutes
    return result


def admin_required(view_func):
    """Custom decorator to require admin privileges."""
    def wrapper(request, *args, **kwargs):
        if not is_admin_user(request.user):
            messages.error(request, 'You do not have permission to access this page.')
            return redirect('dashboard:main')
        return view_func(request, *args, **kwargs)
    return login_required(wrapper)


def get_admin_office_location(user):
    """
    Get the office location for the current admin user with caching.
    Returns None if no office location is found.
    """
    cache_key = f"admin_office_{user.id}"
    cached_office = cache.get(cache_key)
    if cached_office is not None:
        return cached_office

    try:
        user_details = user.profile
        office = user_details.office_location if hasattr(user_details, 'office_location') else None
        cache.set(cache_key, office, 300)  # Cache for 5 minutes
        return office
    except AttributeError:
        cache.set(cache_key, None, 300)
        return None


def get_user_shift_info(user, date=None):
    """
    Enhanced shift information retrieval with better error handling.
    """
    if date is None:
        date = timezone.now().date()

    cache_key = f"shift_info_{user.id}_{date}"
    cached_info = cache.get(cache_key)
    if cached_info is not None:
        return cached_info

    shift_info = {
        'current_shift': None,
        'current_shift_name': 'No shift assigned',
        'shift_type': 'unknown',
        'shift_history': [],
        'has_shift_data': False,
        'is_day_shift': True,
        'shift_start_time': None,
        'shift_end_time': None
    }

    try:
        # Get current shift with better error handling
        current_assignment = ShiftAssignment.objects.select_related('shift').filter(
            user=user,
            effective_from__lte=date,
            effective_to__gte=date,
            is_current=True
        ).first()

        if current_assignment and current_assignment.shift:
            shift = current_assignment.shift
            shift_info.update({
                'current_shift': shift,
                'current_shift_name': shift.name,
                'shift_type': getattr(shift, 'shift_type', 'unknown'),
                'has_shift_data': True,
                'is_day_shift': getattr(shift, 'is_day_shift', True),
                'shift_start_time': getattr(shift, 'start_time', None),
                'shift_end_time': getattr(shift, 'end_time', None)
            })

        # Get recent shift history
        shift_history = ShiftAssignment.objects.select_related('shift').filter(
            user=user
        ).order_by('-effective_from')[:5]

        shift_info['shift_history'] = [
            {
                'shift_name': assignment.shift.name if assignment.shift else 'Unknown',
                'effective_from': assignment.effective_from,
                'effective_to': assignment.effective_to,
                'is_current': assignment.effective_from <= date <= assignment.effective_to,
                'shift_type': getattr(assignment.shift, 'shift_type', 'unknown') if assignment.shift else 'unknown'
            }
            for assignment in shift_history
        ]

        if shift_history.exists():
            shift_info['has_shift_data'] = True

    except Exception as e:
        print(f"Error getting shift info for user {user.username}: {str(e)}")

    # Cache for 1 hour
    cache.set(cache_key, shift_info, 3600)
    return shift_info


def get_filtered_sessions_queryset(office_id=None, admin_office=None):
    """
    Optimized session filtering with proper joins and select_related.
    """
    try:
        # Base queryset with optimizations - use correct relationship path
        queryset = UserSession.objects.select_related('user')

        # Try to add profile relationship if it exists
        try:
            queryset = queryset.select_related('user__profile__office_location')
        except Exception:
            # Fall back to basic queryset if relationship doesn't exist
            pass

        # Apply office filtering
        if office_id and office_id != 'all':
            try:
                office = OfficeLocation.objects.get(id=office_id)
                office_users = User.objects.filter(
                    profile__office_location=office
                ).values_list('id', flat=True)
                if office_users.exists():
                    queryset = queryset.filter(user_id__in=office_users)
            except (OfficeLocation.DoesNotExist, Exception):
                # If office doesn't exist or query fails, return empty queryset
                return UserSession.objects.none()
        elif admin_office:
            try:
                office_users = User.objects.filter(
                    profile__office_location=admin_office
                ).values_list('id', flat=True)
                if office_users.exists():
                    queryset = queryset.filter(user_id__in=office_users)
                else:
                    # If no users in admin office, return empty queryset
                    return UserSession.objects.none()
            except Exception:
                # If query fails, return all sessions (no office restriction)
                pass

        return queryset
    except Exception:
        # If anything goes wrong, return empty queryset
        return UserSession.objects.none()


def calculate_session_metrics(sessions_queryset):
    """
    Calculate comprehensive session metrics efficiently.
    """
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_week = now - timedelta(days=7)

    # Get basic counts with single query
    metrics = sessions_queryset.aggregate(
        total_sessions=Count('id'),
        active_sessions=Count('id', filter=Q(is_active=True)),
        idle_sessions=Count('id', filter=Q(is_active=True, is_idle=True)),
        recent_24h=Count('id', filter=Q(created_at__gte=last_24h)),
        recent_week=Count('id', filter=Q(created_at__gte=last_week)),
        avg_duration=Avg(
            ExpressionWrapper(
                F('ended_at') - F('created_at'),
                output_field=DurationField()
            ),
            filter=Q(ended_at__isnull=False, is_active=False)
        )
    )

    # Convert average duration to minutes
    if metrics['avg_duration']:
        metrics['avg_duration_minutes'] = round(
            metrics['avg_duration'].total_seconds() / 60, 2
        )
    else:
        metrics['avg_duration_minutes'] = None

    # Calculate working vs idle time
    active_sessions = sessions_queryset.filter(is_active=True)
    total_working_time = active_sessions.aggregate(
        total_working=Sum('working_time')
    )['total_working']

    total_idle_time = active_sessions.aggregate(
        total_idle=Sum('total_idle_time')
    )['total_idle']

    metrics.update({
        'total_working_time': total_working_time or timedelta(0),
        'total_idle_time': total_idle_time or timedelta(0),
        'productivity_ratio': 0
    })

    # Calculate productivity ratio
    if total_working_time and total_idle_time:
        total_time = total_working_time + total_idle_time
        if total_time.total_seconds() > 0:
            metrics['productivity_ratio'] = round(
                (total_working_time.total_seconds() / total_time.total_seconds()) * 100, 2
            )

    return metrics


def get_top_users_with_shifts(sessions_queryset, limit=10):
    """
    Get top users by session count with shift information.
    """
    # Get top users efficiently
    top_users_data = (
        sessions_queryset
        .values('user__id', 'user__username', 'user__first_name', 'user__last_name')
        .annotate(
            session_count=Count('id'),
            active_sessions=Count('id', filter=Q(is_active=True)),
            last_activity=Max('last_activity'),
            total_time=Sum(
                ExpressionWrapper(
                    F('ended_at') - F('created_at'),
                    output_field=DurationField()
                ),
                filter=Q(ended_at__isnull=False)
            )
        )
        .order_by('-session_count')[:limit]
    )

    # Enhance with shift information
    enhanced_users = []
    for user_data in top_users_data:
        try:
            user = User.objects.get(id=user_data['user__id'])
            shift_info = get_user_shift_info(user)

            user_data.update({
                'current_shift': shift_info['current_shift_name'],
                'shift_type': shift_info['shift_type'],
                'has_shift_data': shift_info['has_shift_data'],
                'is_day_shift': shift_info['is_day_shift'],
                'total_time_hours': 0
            })

            # Calculate total time in hours
            if user_data['total_time']:
                user_data['total_time_hours'] = round(
                    user_data['total_time'].total_seconds() / 3600, 2
                )

            enhanced_users.append(user_data)
        except User.DoesNotExist:
            continue

    return enhanced_users


def get_device_statistics(sessions_queryset):
    """
    Get device type distribution and statistics.
    """
    device_stats = (
        sessions_queryset
        .filter(device_type__isnull=False)
        .exclude(device_type='')
        .values('device_type')
        .annotate(
            session_count=Count('id'),
            active_count=Count('id', filter=Q(is_active=True)),
            unique_users=Count('user', distinct=True)
        )
        .order_by('-session_count')
    )

    # Normalize device types
    normalized_stats = {}
    for stat in device_stats:
        device_type = stat['device_type'].lower()
        if 'mac' in device_type or 'darwin' in device_type:
            device_type = 'Mac'
        elif 'windows' in device_type or 'win' in device_type:
            device_type = 'Windows'
        elif 'linux' in device_type:
            device_type = 'Linux'
        elif 'android' in device_type:
            device_type = 'Android'
        elif 'iphone' in device_type or 'ios' in device_type:
            device_type = 'iOS'
        else:
            device_type = 'Unknown'

        if device_type in normalized_stats:
            normalized_stats[device_type]['session_count'] += stat['session_count']
            normalized_stats[device_type]['active_count'] += stat['active_count']
            normalized_stats[device_type]['unique_users'] += stat['unique_users']
        else:
            normalized_stats[device_type] = stat
            normalized_stats[device_type]['device_type'] = device_type

    return list(normalized_stats.values())


def get_location_statistics(sessions_queryset):
    """
    Get location-based session statistics.
    """
    return (
        sessions_queryset
        .filter(location_city__isnull=False)
        .exclude(location_city='')
        .values('location_city', 'location_country', 'location_region')
        .annotate(
            session_count=Count('id'),
            active_count=Count('id', filter=Q(is_active=True)),
            unique_users=Count('user', distinct=True)
        )
        .order_by('-session_count')[:10]
    )


# ============================================================================
# MAIN DASHBOARD VIEWS
# ============================================================================

@admin_required
def session_dashboard(request):
    """
    Enhanced real-time session dashboard with dynamic filtering.
    """
    context = {
        'page_title': 'Session Dashboard',
        'active_tab': 'dashboard'
    }

    try:
        # Get filtering parameters
        office_id = request.GET.get('office', None)
        refresh = request.GET.get('refresh', 'false') == 'true'

        # Get admin's office location
        admin_office = get_admin_office_location(request.user)

        # Get all available offices for the dropdown
        all_offices = OfficeLocation.objects.filter(is_active=True).order_by('name')

        # Determine which office to filter by
        selected_office = None
        if office_id and office_id != 'all':
            try:
                selected_office = OfficeLocation.objects.get(id=office_id)
            except OfficeLocation.DoesNotExist:
                messages.warning(request, 'Selected office not found. Showing default view.')
                office_id = None

        # Use admin office as default if no office specified
        if not office_id and admin_office:
            selected_office = admin_office
            office_id = str(admin_office.id)

        # Get filtered sessions
        sessions_queryset = get_filtered_sessions_queryset(office_id, admin_office)

        # Calculate metrics
        metrics = calculate_session_metrics(sessions_queryset)

        # Get top users with shift information
        top_users = get_top_users_with_shifts(sessions_queryset, limit=10)

        # Get device statistics
        device_stats = get_device_statistics(sessions_queryset)

        # Get location statistics
        location_stats = get_location_statistics(sessions_queryset)

        # Get office information
        if selected_office:
            office_info = {
                'id': selected_office.id,
                'name': selected_office.name,
                'code': selected_office.code,
                'location': selected_office.full_address,
                'total_employees': User.objects.filter(
                    profile__office_location=selected_office
                ).count(),
                'working_hours': selected_office.working_hours_display,
                'timezone': selected_office.timezone,
                'is_active': selected_office.is_active
            }
        else:
            office_info = {
                'id': 'all',
                'name': 'All Offices',
                'code': 'ALL',
                'location': 'System-wide view',
                'total_employees': User.objects.filter(profile__isnull=False).count(),
                'working_hours': 'Varies by location',
                'timezone': 'Multiple',
                'is_active': True
            }

        # Get recent activity (last 10 sessions)
        recent_activity = (
            sessions_queryset
            .select_related('user')
            .order_by('-last_activity')[:10]
        )

        # System health status
        system_health = {
            'status': 'operational',
            'active_tracking': metrics['active_sessions'] > 0,
            'last_update': timezone.now(),
            'total_tracked_users': sessions_queryset.values('user').distinct().count()
        }

        context.update({
            'metrics': metrics,
            'top_users': top_users,
            'device_stats': device_stats,
            'location_stats': location_stats,
            'office_info': office_info,
            'recent_activity': recent_activity,
            'system_health': system_health,
            'admin_office': admin_office,
            'selected_office': selected_office,
            'all_offices': all_offices,
            'selected_office_id': office_id or 'all',
            'refresh_enabled': refresh
        })

    except Exception as e:
        messages.error(request, f'Error loading dashboard data: {str(e)}')
        context.update({
            'metrics': {
                'total_sessions': 0,
                'active_sessions': 0,
                'idle_sessions': 0,
                'recent_24h': 0,
                'avg_duration_minutes': None,
                'productivity_ratio': 0
            },
            'top_users': [],
            'device_stats': [],
            'location_stats': [],
            'office_info': {
                'name': 'Error',
                'location': 'Unable to load',
                'total_employees': 0
            },
            'recent_activity': [],
            'system_health': {'status': 'error'},
            'admin_office': None,
            'all_offices': OfficeLocation.objects.filter(is_active=True).order_by('name'),
            'selected_office_id': 'all'
        })

    return render(request, 'sessions/dashboard.html', context)


@admin_required
@require_GET
def dashboard_ajax_update(request):
    """
    AJAX endpoint for real-time dashboard updates.
    """
    try:
        office_id = request.GET.get('office', None)
        admin_office = get_admin_office_location(request.user)

        # Get filtered sessions
        sessions_queryset = get_filtered_sessions_queryset(office_id, admin_office)

        # Calculate metrics
        metrics = calculate_session_metrics(sessions_queryset)

        # Get top users
        top_users = get_top_users_with_shifts(sessions_queryset, limit=5)

        # Get device stats
        device_stats = get_device_statistics(sessions_queryset)

        # System health
        system_health = {
            'status': 'operational',
            'active_tracking': metrics['active_sessions'] > 0,
            'last_update': timezone.now().isoformat(),
            'total_tracked_users': sessions_queryset.values('user').distinct().count()
        }

        return JsonResponse({
            'success': True,
            'metrics': metrics,
            'top_users': top_users,
            'device_stats': device_stats,
            'system_health': system_health,
            'timestamp': timezone.now().isoformat()
        })

    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@admin_required
def dashboard_filter(request):
    """
    Handle dashboard filtering and return updated data.
    """
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return dashboard_ajax_update(request)
    else:
        # Regular HTTP request - redirect to dashboard with parameters
        office_id = request.GET.get('office', 'all')
        return redirect(f"{request.path.replace('/filter/', '')}?office={office_id}")


# ============================================================================
# SESSION MANAGEMENT VIEWS
# ============================================================================

@login_required
def session_list(request):
    """
    Enhanced session list with user-date grouping and advanced filtering.
    """
    from collections import defaultdict
    from django.db.models import Count, Q

    # Get filtering parameters
    office_id = request.GET.get('office', None)
    status_filter = request.GET.get('status', 'all')  # all, active, idle, ended
    search_query = request.GET.get('search', '').strip()
    date_filter = request.GET.get('date', '')  # specific date filter
    user_filter = request.GET.get('user', '')  # specific user filter
    sort_by = request.GET.get('sort', '-date')
    page = request.GET.get('page', 1)

    # Get admin office - handle case where user has no office
    admin_office = get_admin_office_location(request.user)

    # Allow superusers and staff to see all sessions regardless of office
    if request.user.is_superuser or request.user.is_staff:
        admin_office_for_filter = None
    else:
        admin_office_for_filter = admin_office

    # Start with filtered sessions
    try:
        sessions_queryset = get_filtered_sessions_queryset(office_id, admin_office_for_filter)
    except Exception as e:
        messages.error(request, f'Error loading sessions: {str(e)}')
        sessions_queryset = UserSession.objects.none()

    # Apply search filtering
    if search_query:
        sessions_queryset = sessions_queryset.filter(
            Q(user__username__icontains=search_query) |
            Q(user__first_name__icontains=search_query) |
            Q(user__last_name__icontains=search_query) |
            Q(user__email__icontains=search_query)
        )

    # Apply date filtering
    if date_filter:
        try:
            from datetime import datetime
            filter_date = datetime.strptime(date_filter, '%Y-%m-%d').date()
            sessions_queryset = sessions_queryset.filter(created_at__date=filter_date)
        except ValueError:
            pass

    # Apply user filtering
    if user_filter:
        sessions_queryset = sessions_queryset.filter(user_id=user_filter)

    # Group sessions by user and date
    grouped_sessions = defaultdict(lambda: {
        'user': None,
        'date': None,
        'sessions': [],
        'total_count': 0,
        'active_count': 0,
        'idle_count': 0,
        'ended_count': 0,
        'total_working_time': 0,
        'total_idle_time': 0
    })

    for session in sessions_queryset.select_related('user').order_by('-created_at'):
        session_date = session.created_at.date()
        key = f"{session.user.id}_{session_date}"

        group = grouped_sessions[key]
        group['user'] = session.user
        group['date'] = session_date
        group['sessions'].append(session)
        group['total_count'] += 1

        # Count by status
        if session.is_active:
            if session.is_idle:
                group['idle_count'] += 1
            else:
                group['active_count'] += 1
        else:
            group['ended_count'] += 1

        # Calculate working and idle time
        if session.working_time:
            group['total_working_time'] += session.working_time.total_seconds() / 60  # in minutes
        if session.total_idle_time:
            group['total_idle_time'] += session.total_idle_time.total_seconds() / 60  # in minutes

    # Convert to list and apply status filtering
    session_groups = []
    for group in grouped_sessions.values():
        # Apply status filtering
        if status_filter == 'active' and group['active_count'] == 0:
            continue
        elif status_filter == 'idle' and group['idle_count'] == 0:
            continue
        elif status_filter == 'ended' and group['ended_count'] == 0:
            continue

        session_groups.append(group)

    # Apply sorting
    if sort_by == '-date':
        session_groups.sort(key=lambda x: x['date'], reverse=True)
    elif sort_by == 'date':
        session_groups.sort(key=lambda x: x['date'])
    elif sort_by == 'user':
        session_groups.sort(key=lambda x: x['user'].username if x['user'] else '')
    elif sort_by == '-user':
        session_groups.sort(key=lambda x: x['user'].username if x['user'] else '', reverse=True)
    elif sort_by == '-total_count':
        session_groups.sort(key=lambda x: x['total_count'], reverse=True)
    elif sort_by == 'total_count':
        session_groups.sort(key=lambda x: x['total_count'])

    # Paginate results
    paginator = Paginator(session_groups, 25)
    try:
        session_groups_page = paginator.page(page)
    except PageNotAnInteger:
        session_groups_page = paginator.page(1)
    except EmptyPage:
        session_groups_page = paginator.page(paginator.num_pages)

    # Get summary statistics
    total_sessions = sessions_queryset.count()
    summary_stats = {
        'total_sessions': total_sessions,
        'total_groups': len(session_groups),
        'active_sessions': sessions_queryset.filter(is_active=True, is_idle=False).count(),
        'idle_sessions': sessions_queryset.filter(is_active=True, is_idle=True).count(),
        'ended_sessions': sessions_queryset.filter(is_active=False).count(),
    }

    # Get all users for filter dropdown
    all_users = sessions_queryset.values('user__id', 'user__username', 'user__first_name', 'user__last_name').distinct().order_by('user__username')

    context = {
        'page_title': 'Session List (Grouped)',
        'active_tab': 'sessions',
        'session_groups': session_groups_page,
        'summary_stats': summary_stats,
        'all_offices': OfficeLocation.objects.filter(is_active=True).order_by('name'),
        'all_users': all_users,
        'admin_office': admin_office,
        'filters': {
            'office': office_id or 'all',
            'status': status_filter,
            'search': search_query,
            'date': date_filter,
            'user': user_filter,
            'sort': sort_by
        },
        'status_choices': [
            ('all', 'All Sessions'),
            ('active', 'Active'),
            ('idle', 'Idle'),
            ('ended', 'Ended')
        ],
        'sort_choices': [
            ('-date', 'Date (Newest)'),
            ('date', 'Date (Oldest)'),
            ('user', 'Username (A-Z)'),
            ('-user', 'Username (Z-A)'),
            ('-total_count', 'Session Count (High to Low)'),
            ('total_count', 'Session Count (Low to High)')
        ]
    }

    return render(request, 'sessions/session_list.html', context)


@admin_required
def session_detail(request, session_id):
    """
    Individual session detail view.
    """
    try:
        # Show individual session detail
        session = get_object_or_404(
            UserSession.objects.select_related(
                'user', 'user__profile', 'user__profile__office_location'
            ),
            id=session_id
        )

        # Check if admin can view this session
        admin_office = get_admin_office_location(request.user)
        if admin_office:
            try:
                user_office = session.user.profile.office_location if hasattr(session.user, 'profile') and hasattr(session.user.profile, 'office_location') else None
                if user_office != admin_office:
                    messages.error(request, 'You do not have permission to view this session.')
                    return redirect('sessions:session_list')
            except AttributeError:
                pass  # User has no office assigned

        # Get shift information
        shift_info = get_user_shift_info(session.user)

        # Calculate session metrics
        session_duration = None
        if session.ended_at and session.created_at:
            duration_delta = session.ended_at - session.created_at
            session_duration = int(duration_delta.total_seconds() / 60)
        elif session.is_active and session.created_at:
            duration_delta = timezone.now() - session.created_at
            session_duration = int(duration_delta.total_seconds() / 60)

        # Calculate time metrics in minutes
        working_time_minutes = None
        idle_time_minutes = None

        if session.working_time:
            working_time_minutes = int(session.working_time.total_seconds() / 60)

        if session.total_idle_time:
            idle_time_minutes = int(session.total_idle_time.total_seconds() / 60)
        elif session.idle_time:
            idle_time_minutes = int(session.idle_time.total_seconds() / 60)

        # Get related sessions (same user, recent)
        related_sessions = UserSession.objects.filter(
            user=session.user
        ).exclude(id=session.id).order_by('-created_at')[:5]

        # Activity timeline (simplified)
        activity_timeline = []
        if session.page_views:
            for view in session.page_views[-10:]:  # Last 10 page views
                activity_timeline.append({
                    'type': 'page_view',
                    'timestamp': view.get('timestamp'),
                    'data': view
                })

        # Session health score (simple calculation)
        health_score = 100
        if session.is_idle:
            health_score -= 20
        if session.total_idle_time and session.total_idle_time > timedelta(hours=1):
            health_score -= 30
        if not session.is_active and not session.ended_at:
            health_score -= 40

        context = {
            'page_title': f'Session Details - {session.user.username}',
            'active_tab': 'sessions',
            'session': session,
            'shift_info': shift_info,
            'session_duration': session_duration,
            'working_time_minutes': working_time_minutes,
            'idle_time_minutes': idle_time_minutes,
            'related_sessions': related_sessions,
            'activity_timeline': activity_timeline,
            'health_score': max(0, health_score),
            'raw_data_visible': request.GET.get('show_raw', 'false') == 'true'
        }

        return render(request, 'sessions/session_detail.html', context)

    except Exception as e:
        messages.error(request, f'Error loading session details: {str(e)}')
        return redirect('sessions:session_list')


@admin_required
def session_daily_detail(request, user_id, date):
    """
    Daily session detail view for a specific user and date.
    """
    try:
        from django.contrib.auth.models import User
        from datetime import datetime

        # Get user and parse date
        try:
            user = User.objects.get(id=user_id)
            target_date = datetime.strptime(date, '%Y-%m-%d').date()
        except (User.DoesNotExist, ValueError) as e:
            messages.error(request, f'Invalid user or date specified: {str(e)}')
            return redirect('sessions:session_list')

        # Permission check - allow users to view their own sessions or admin access
        can_view = False

        # Users can always view their own sessions
        if request.user.id == user.id:
            can_view = True
        else:
            # Check admin permissions for viewing other users
            admin_office = get_admin_office_location(request.user)
            if admin_office:
                try:
                    user_office = user.profile.office_location if hasattr(user, 'profile') and hasattr(user.profile, 'office_location') else None
                    if user_office == admin_office:
                        can_view = True
                except AttributeError:
                    # If user has no office assigned, allow admin to view
                    can_view = True
            # If no admin office, check if user is superuser or staff
            elif request.user.is_superuser or request.user.is_staff:
                can_view = True

        if not can_view:
            messages.error(request, 'You do not have permission to view this user\'s sessions.')
            return redirect('sessions:session_list')

        # Get all sessions for this user on this date
        daily_sessions = UserSession.objects.filter(
            user=user,
            created_at__date=target_date
        ).order_by('created_at')

        if not daily_sessions.exists():
            messages.info(request, f'No sessions found for {user.username} on {target_date.strftime("%B %d, %Y")}. Try a different date.')
            # Don't redirect, show empty state instead
            return render(request, 'sessions/session_daily_detail.html', {
                'page_title': f'Daily Session Summary - {user.username} - {target_date}',
                'active_tab': 'sessions',
                'is_daily_view': True,
                'user': user,
                'target_date': target_date,
                'daily_sessions': [],
                'login_logout_events': [],
                'shift_info': get_user_shift_info(user),
                'summary': {
                    'total_sessions': 0,
                    'active_sessions': 0,
                    'idle_sessions': 0,
                    'ended_sessions': 0,
                    'total_working_minutes': 0,
                    'total_idle_minutes': 0,
                    'total_session_minutes': 0,
                    'efficiency_percentage': 0
                }
            })

        return render_daily_session_detail(request, user, target_date, daily_sessions)

    except Exception as e:
        messages.error(request, f'Error loading daily session details: {str(e)}')
        return redirect('sessions:session_list')


def render_daily_session_detail(request, user, target_date, daily_sessions):
    """
    Render daily session summary for a user.
    """
    from datetime import timedelta

    # Calculate daily totals
    total_sessions = daily_sessions.count()
    active_sessions = daily_sessions.filter(is_active=True, is_idle=False).count()
    idle_sessions = daily_sessions.filter(is_active=True, is_idle=True).count()
    ended_sessions = daily_sessions.filter(is_active=False).count()

    # Calculate time totals
    total_working_time = timedelta()
    total_idle_time = timedelta()
    total_session_time = timedelta()

    session_details = []
    login_logout_events = []

    for session in daily_sessions:
        # Session duration
        session_duration = None
        if session.ended_at and session.created_at:
            duration = session.ended_at - session.created_at
            total_session_time += duration
            session_duration = int(duration.total_seconds() / 60)
        elif session.is_active and session.created_at:
            duration = timezone.now() - session.created_at
            total_session_time += duration
            session_duration = int(duration.total_seconds() / 60)

        # Working time
        working_time_minutes = 0
        if session.working_time:
            total_working_time += session.working_time
            working_time_minutes = int(session.working_time.total_seconds() / 60)

        # Idle time
        idle_time_minutes = 0
        if session.total_idle_time:
            total_idle_time += session.total_idle_time
            idle_time_minutes = int(session.total_idle_time.total_seconds() / 60)
        elif session.idle_time:
            total_idle_time += session.idle_time
            idle_time_minutes = int(session.idle_time.total_seconds() / 60)

        session_details.append({
            'session': session,
            'duration_minutes': session_duration,
            'working_time_minutes': working_time_minutes,
            'idle_time_minutes': idle_time_minutes
        })

        # Login/Logout events
        login_logout_events.append({
            'type': 'login',
            'time': session.created_at,
            'session_id': session.id
        })

        if session.ended_at:
            login_logout_events.append({
                'type': 'logout',
                'time': session.ended_at,
                'session_id': session.id
            })

    # Sort events by time
    login_logout_events.sort(key=lambda x: x['time'])

    # Calculate totals in minutes
    total_working_minutes = int(total_working_time.total_seconds() / 60)
    total_idle_minutes = int(total_idle_time.total_seconds() / 60)
    total_session_minutes = int(total_session_time.total_seconds() / 60)

    # Get shift information
    shift_info = get_user_shift_info(user)

    context = {
        'page_title': f'Daily Session Summary - {user.username} - {target_date}',
        'active_tab': 'sessions',
        'is_daily_view': True,
        'user': user,
        'target_date': target_date,
        'daily_sessions': session_details,
        'login_logout_events': login_logout_events,
        'shift_info': shift_info,
        'summary': {
            'total_sessions': total_sessions,
            'active_sessions': active_sessions,
            'idle_sessions': idle_sessions,
            'ended_sessions': ended_sessions,
            'total_working_minutes': total_working_minutes,
            'total_idle_minutes': total_idle_minutes,
            'total_session_minutes': total_session_minutes,
            'efficiency_percentage': round((total_working_minutes / total_session_minutes * 100) if total_session_minutes > 0 else 0, 1)
        }
    }

    return render(request, 'sessions/session_daily_detail.html', context)


@admin_required
@require_POST
def end_session(request, session_id):
    """
    Manually end a session with proper logging.
    """
    try:
        session = get_object_or_404(UserSession, id=session_id)

        # Check permissions
        admin_office = get_admin_office_location(request.user)
        if admin_office:
            try:
                user_office = session.user.profile.office_location
                if user_office != admin_office:
                    return JsonResponse({
                        'success': False,
                        'error': 'Permission denied'
                    }, status=403)
            except AttributeError:
                pass

        if session.is_active:
            with transaction.atomic():
                session.is_active = False
                session.ended_at = timezone.now()
                session.logout_time = timezone.now()

                # Calculate final session duration
                if session.created_at:
                    duration = session.ended_at - session.created_at
                    session.session_duration = duration.total_seconds() / 60

                session.save()

            # Clear relevant caches
            cache.delete(f"admin_office_{request.user.id}")

            messages.success(request, f'Session for {session.user.username} has been ended.')

            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': True,
                    'message': 'Session ended successfully'
                })
        else:
            messages.info(request, 'Session is already inactive.')

            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': False,
                    'error': 'Session is already inactive'
                })

    except Exception as e:
        messages.error(request, f'Error ending session: {str(e)}')

        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'success': False,
                'error': str(e)
            }, status=500)

    return redirect('sessions:session_list')


# ============================================================================
# ANALYTICS VIEWS
# ============================================================================

@admin_required
def session_analytics(request):
    """
    Enhanced analytics dashboard with comprehensive insights.
    """
    # Get filtering parameters
    office_id = request.GET.get('office', None)
    date_range = request.GET.get('range', '7')  # days

    try:
        days = int(date_range)
    except (ValueError, TypeError):
        days = 7

    admin_office = get_admin_office_location(request.user)

    # Date range for analytics
    end_date = timezone.now()
    start_date = end_date - timedelta(days=days)

    # Get filtered sessions
    sessions_queryset = get_filtered_sessions_queryset(office_id, admin_office)

    # Filter by date range
    sessions_queryset = sessions_queryset.filter(created_at__gte=start_date)

    # Calculate daily session counts
    daily_stats = []
    current_date = start_date.date()
    end_date_only = end_date.date()

    while current_date <= end_date_only:
        day_sessions = sessions_queryset.filter(created_at__date=current_date)
        daily_stats.append({
            'date': current_date.strftime('%Y-%m-%d'),
            'total_sessions': day_sessions.count(),
            'active_sessions': day_sessions.filter(is_active=True).count(),
            'unique_users': day_sessions.values('user').distinct().count()
        })
        current_date += timedelta(days=1)

    # Get hourly distribution (for current day or last 24h)
    last_24h = end_date - timedelta(hours=24)
    recent_sessions = sessions_queryset.filter(created_at__gte=last_24h)

    hourly_stats = []
    for hour in range(24):
        hour_start = last_24h.replace(minute=0, second=0, microsecond=0) + timedelta(hours=hour)
        hour_end = hour_start + timedelta(hours=1)
        hour_sessions = recent_sessions.filter(
            created_at__gte=hour_start,
            created_at__lt=hour_end
        )
        hourly_stats.append({
            'hour': hour,
            'sessions': hour_sessions.count(),
            'active_sessions': hour_sessions.filter(is_active=True).count()
        })

    # Get shift-based analytics
    shift_analytics = []
    try:
        for shift in ShiftMaster.objects.all():
            shift_users = ShiftAssignment.objects.filter(
                shift=shift,
                effective_from__lte=end_date.date(),
                effective_to__gte=start_date.date()
            ).values_list('user_id', flat=True).distinct()

            shift_sessions = sessions_queryset.filter(user_id__in=shift_users)

            shift_analytics.append({
                'shift_name': shift.name,
                'shift_type': getattr(shift, 'shift_type', 'unknown'),
                'total_users': len(shift_users),
                'total_sessions': shift_sessions.count(),
                'active_sessions': shift_sessions.filter(is_active=True).count(),
                'avg_duration': shift_sessions.filter(
                    ended_at__isnull=False
                ).aggregate(
                    avg_duration=Avg(
                        ExpressionWrapper(
                            F('ended_at') - F('created_at'),
                            output_field=DurationField()
                        )
                    )
                )['avg_duration']
            })
    except Exception:
        shift_analytics = []

    # Device and location trends
    device_trends = get_device_statistics(sessions_queryset)
    location_trends = get_location_statistics(sessions_queryset)

    # Performance metrics
    performance_metrics = {
        'avg_session_duration': sessions_queryset.filter(
            ended_at__isnull=False
        ).aggregate(
            avg_duration=Avg(
                ExpressionWrapper(
                    F('ended_at') - F('created_at'),
                    output_field=DurationField()
                )
            )
        )['avg_duration'],
        'total_working_time': sessions_queryset.aggregate(
            total_working=Sum('working_time')
        )['total_working'],
        'total_idle_time': sessions_queryset.aggregate(
            total_idle=Sum('total_idle_time')
        )['total_idle'],
        'completion_rate': 0
    }

    # Calculate completion rate
    total_sessions = sessions_queryset.count()
    completed_sessions = sessions_queryset.filter(ended_at__isnull=False).count()
    if total_sessions > 0:
        performance_metrics['completion_rate'] = round(
            (completed_sessions / total_sessions) * 100, 2
        )

    context = {
        'page_title': 'Session Analytics',
        'active_tab': 'analytics',
        'daily_stats': daily_stats,
        'hourly_stats': hourly_stats,
        'shift_analytics': shift_analytics,
        'device_trends': device_trends,
        'location_trends': location_trends,
        'performance_metrics': performance_metrics,
        'date_range': days,
        'start_date': start_date,
        'end_date': end_date,
        'all_offices': OfficeLocation.objects.filter(is_active=True).order_by('name'),
        'selected_office_id': office_id or 'all',
        'admin_office': admin_office
    }

    return render(request, 'sessions/analytics.html', context)


@admin_required
def session_export(request):
    """
    Enhanced CSV export functionality with comprehensive session data.
    """
    # Get filtering parameters
    office_id = request.GET.get('office', None)
    date_from = request.GET.get('date_from')
    date_to = request.GET.get('date_to')
    format_type = request.GET.get('format', 'csv')  # csv or json

    admin_office = get_admin_office_location(request.user)

    # Get filtered sessions
    sessions_queryset = get_filtered_sessions_queryset(office_id, admin_office)

    # Apply date filtering
    if date_from:
        try:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            sessions_queryset = sessions_queryset.filter(created_at__date__gte=date_from_obj)
        except ValueError:
            messages.error(request, 'Invalid start date format.')
            return redirect('sessions:analytics')

    if date_to:
        try:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            sessions_queryset = sessions_queryset.filter(created_at__date__lte=date_to_obj)
        except ValueError:
            messages.error(request, 'Invalid end date format.')
            return redirect('sessions:analytics')

    # Limit export size for performance
    sessions_queryset = sessions_queryset.order_by('-created_at')[:5000]

    if format_type == 'json':
        return _export_json(request, sessions_queryset, admin_office)
    else:
        return _export_csv(request, sessions_queryset, admin_office)


def _export_csv(request, sessions_queryset, admin_office):
    """Export sessions data as CSV."""
    response = HttpResponse(content_type='text/csv')

    # Generate filename
    office_suffix = f"_{admin_office.code}" if admin_office else "_all_offices"
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    filename = f"sessions_export{office_suffix}_{timestamp}.csv"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    writer = csv.writer(response)

    # Write header
    header = [
        'Session ID', 'Username', 'Full Name', 'Email',
        'Office Location', 'Created At', 'Last Activity', 'Ended At',
        'Is Active', 'Is Idle', 'Duration (minutes)',
        'Device Type', 'Browser', 'OS', 'IP Address',
        'Location City', 'Location Country', 'Current Shift',
        'Working Time (minutes)', 'Idle Time (minutes)'
    ]
    writer.writerow(header)

    # Write data rows
    for session in sessions_queryset:
        # Calculate duration
        duration_minutes = None
        if session.ended_at and session.created_at:
            duration = session.ended_at - session.created_at
            duration_minutes = round(duration.total_seconds() / 60, 2)
        elif session.is_active and session.created_at:
            duration = timezone.now() - session.created_at
            duration_minutes = round(duration.total_seconds() / 60, 2)

        # Get user office
        office_name = 'N/A'
        try:
            if hasattr(session.user, 'profile') and session.user.profile.office_location:
                office_name = session.user.profile.office_location.name
        except AttributeError:
            pass

        # Get shift info
        shift_info = get_user_shift_info(session.user)

        # Convert timedelta to minutes
        working_minutes = None
        if session.working_time:
            working_minutes = round(session.working_time.total_seconds() / 60, 2)

        idle_minutes = None
        if session.total_idle_time:
            idle_minutes = round(session.total_idle_time.total_seconds() / 60, 2)

        row = [
            str(session.id),
            session.user.username,
            f"{session.user.first_name} {session.user.last_name}".strip() or session.user.username,
            session.user.email,
            office_name,
            session.created_at.strftime('%Y-%m-%d %H:%M:%S') if session.created_at else '',
            session.last_activity.strftime('%Y-%m-%d %H:%M:%S') if session.last_activity else '',
            session.ended_at.strftime('%Y-%m-%d %H:%M:%S') if session.ended_at else '',
            'Yes' if session.is_active else 'No',
            'Yes' if session.is_idle else 'No',
            duration_minutes or '',
            session.device_type or '',
            session.browser or '',
            session.os or '',
            session.ip_address or '',
            session.location_city or '',
            session.location_country or '',
            shift_info['current_shift_name'],
            working_minutes or '',
            idle_minutes or ''
        ]
        writer.writerow(row)

    return response


def _export_json(request, sessions_queryset, admin_office):
    """Export sessions data as JSON."""
    export_data = []

    for session in sessions_queryset:
        # Get shift info
        shift_info = get_user_shift_info(session.user)

        # Get user office
        office_info = {'name': None, 'code': None}
        try:
            if hasattr(session.user, 'profile') and session.user.profile.office_location:
                office = session.user.profile.office_location
                office_info = {'name': office.name, 'code': office.code}
        except AttributeError:
            pass

        session_data = {
            'session_id': str(session.id),
            'user': {
                'username': session.user.username,
                'full_name': f"{session.user.first_name} {session.user.last_name}".strip(),
                'email': session.user.email
            },
            'office': office_info,
            'timestamps': {
                'created_at': session.created_at.isoformat() if session.created_at else None,
                'last_activity': session.last_activity.isoformat() if session.last_activity else None,
                'ended_at': session.ended_at.isoformat() if session.ended_at else None
            },
            'status': {
                'is_active': session.is_active,
                'is_idle': session.is_idle
            },
            'device': {
                'type': session.device_type,
                'browser': session.browser,
                'os': session.os,
                'screen_resolution': session.screen_resolution
            },
            'location': {
                'ip_address': session.ip_address,
                'city': session.location_city,
                'country': session.location_country,
                'latitude': session.location_latitude,
                'longitude': session.location_longitude
            },
            'shift': {
                'current_shift': shift_info['current_shift_name'],
                'shift_type': shift_info['shift_type'],
                'has_shift_data': shift_info['has_shift_data']
            },
            'metrics': {
                'working_time_seconds': session.working_time.total_seconds() if session.working_time else 0,
                'idle_time_seconds': session.total_idle_time.total_seconds() if session.total_idle_time else 0,
                'page_views': len(session.page_views) if session.page_views else 0,
                'clicks': len(session.clicks) if session.clicks else 0,
                'mouse_movements': session.mouse_movements or 0
            }
        }
        export_data.append(session_data)

    # Prepare response
    response_data = {
        'metadata': {
            'export_timestamp': timezone.now().isoformat(),
            'exported_by': request.user.username,
            'total_sessions': len(export_data),
            'office_filter': admin_office.name if admin_office else 'All Offices'
        },
        'sessions': export_data
    }

    response = JsonResponse(response_data, json_dumps_params={'indent': 2})

    # Set filename for download
    office_suffix = f"_{admin_office.code}" if admin_office else "_all_offices"
    timestamp = timezone.now().strftime('%Y%m%d_%H%M%S')
    filename = f"sessions_export{office_suffix}_{timestamp}.json"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'

    return response


# ============================================================================
# OFFICE LOCATION VIEWS
# ============================================================================

@admin_required
def office_locations(request):
    """
    Enhanced office locations view with session statistics.
    """
    admin_office = get_admin_office_location(request.user)

    # Get offices based on admin permissions
    if admin_office and not request.user.is_superuser:
        offices = OfficeLocation.objects.filter(id=admin_office.id, is_active=True)
    else:
        offices = OfficeLocation.objects.filter(is_active=True).order_by('name')

    # Enhance offices with statistics
    enhanced_offices = []
    for office in offices:
        # Get office users
        office_users = User.objects.filter(
            profile__office_location=office
        ).values_list('id', flat=True)

        # Get session statistics
        office_sessions = UserSession.objects.filter(user_id__in=office_users)
        last_24h = timezone.now() - timedelta(hours=24)

        office_stats = {
            'total_employees': len(office_users),
            'total_sessions': office_sessions.count(),
            'active_sessions': office_sessions.filter(is_active=True).count(),
            'recent_sessions': office_sessions.filter(created_at__gte=last_24h).count(),
            'avg_daily_sessions': 0
        }

        # Calculate average daily sessions (last 7 days)
        last_week = timezone.now() - timedelta(days=7)
        week_sessions = office_sessions.filter(created_at__gte=last_week).count()
        office_stats['avg_daily_sessions'] = round(week_sessions / 7, 1)

        enhanced_offices.append({
            'office': office,
            'stats': office_stats
        })

    context = {
        'page_title': 'Office Locations',
        'active_tab': 'locations',
        'enhanced_offices': enhanced_offices,
        'admin_office': admin_office,
        'is_restricted': admin_office and not request.user.is_superuser
    }

    return render(request, 'sessions/office_locations.html', context)


@admin_required
def location_detail(request, location_id):
    """
    Enhanced location detail view with comprehensive analytics.
    """
    admin_office = get_admin_office_location(request.user)

    # Get the office location
    office = get_object_or_404(OfficeLocation, id=location_id, is_active=True)

    # Check permissions
    if admin_office and admin_office != office and not request.user.is_superuser:
        messages.error(request, 'You can only view your own office location.')
        return redirect('sessions:office_locations')

    # Get employees with enhanced information
    employees = User.objects.filter(
        profile__office_location=office
    ).select_related('profile').order_by('username')

    enhanced_employees = []
    for employee in employees:
        # Get shift information
        shift_info = get_user_shift_info(employee)

        # Get recent session activity
        user_sessions = UserSession.objects.filter(user=employee)
        recent_sessions = user_sessions.filter(
            created_at__gte=timezone.now() - timedelta(days=7)
        ).count()

        active_session = user_sessions.filter(is_active=True).first()

        enhanced_employees.append({
            'employee': employee,
            'shift_info': shift_info,
            'recent_sessions': recent_sessions,
            'has_active_session': bool(active_session),
            'last_activity': active_session.last_activity if active_session else None
        })

    # Office statistics
    office_users = employees.values_list('user_id', flat=True)
    office_sessions = UserSession.objects.filter(user_id__in=office_users)

    now = timezone.now()
    today = now.date()
    week_ago = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    office_stats = {
        'total_employees': employees.count(),
        'active_employees': employees.filter(employment_status='active').count(),
        'total_sessions': office_sessions.count(),
        'active_sessions': office_sessions.filter(is_active=True).count(),
        'today_sessions': office_sessions.filter(created_at__date=today).count(),
        'week_sessions': office_sessions.filter(created_at__gte=week_ago).count(),
        'month_sessions': office_sessions.filter(created_at__gte=month_ago).count(),
        'avg_session_duration': None
    }

    # Calculate average session duration
    completed_sessions = office_sessions.filter(ended_at__isnull=False)
    if completed_sessions.exists():
        avg_duration = completed_sessions.aggregate(
            avg_duration=Avg(
                ExpressionWrapper(
                    F('ended_at') - F('created_at'),
                    output_field=DurationField()
                )
            )
        )['avg_duration']

        if avg_duration:
            office_stats['avg_session_duration'] = round(
                avg_duration.total_seconds() / 60, 2
            )

    # Daily session trend (last 7 days)
    daily_trends = []
    for i in range(7):
        date = (now - timedelta(days=i)).date()
        day_sessions = office_sessions.filter(created_at__date=date).count()
        daily_trends.append({
            'date': date.strftime('%Y-%m-%d'),
            'sessions': day_sessions
        })
    daily_trends.reverse()

    context = {
        'page_title': f'{office.name} - Location Details',
        'active_tab': 'locations',
        'office': office,
        'enhanced_employees': enhanced_employees,
        'office_stats': office_stats,
        'daily_trends': daily_trends,
        'admin_office': admin_office
    }

    return render(request, 'sessions/location_detail.html', context)
