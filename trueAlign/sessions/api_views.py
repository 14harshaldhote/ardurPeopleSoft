"""
Enhanced API views for sessions analytics with optimized querying and caching.
"""

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_GET
from django.core.cache import cache
from django.db.models import (
    Q, Count, Avg, Sum, Max, Min, F, Value,
    Case, When, IntegerField, DurationField, ExpressionWrapper
)
from django.db.models.functions import ExtractHour, TruncDate, TruncHour
from django.utils import timezone
from django.contrib.auth.models import User
from datetime import datetime, timedelta
from collections import defaultdict
import json

from trueAlign.models import UserSession, OfficeLocation, SessionActivity
from .views import is_admin_user, get_admin_office_location


# ============================================================================
# DASHBOARD STATS API
# ============================================================================

@login_required
@require_GET
def api_dashboard_stats(request):
    """
    Get comprehensive dashboard statistics with caching.
    
    Query Parameters:
    - office_id: Filter by office
    - date_from: Start date (YYYY-MM-DD)
    - date_to: End date (YYYY-MM-DD)
    - user_id: Filter by specific user
    - status: active/idle/ended
    """
    try:
        # Parse filters
        office_id = request.GET.get('office_id')
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')
        user_id = request.GET.get('user_id')
        status = request.GET.get('status')
        
        # Build cache key
        cache_key = f"dashboard_stats:{office_id}:{date_from}:{date_to}:{user_id}:{status}"
        cached_data = cache.get(cache_key)
        
        if cached_data:
            return JsonResponse(cached_data)
        
        # Build base queryset with optimizations
        sessions = UserSession.objects.select_related(
            'user', 'user__profile', 'current_office_location'
        ).all()
        
        # Apply filters
        if office_id:
            sessions = sessions.filter(current_office_location_id=office_id)
        elif not is_admin_user(request.user):
            # Non-admin users see only their office
            admin_office = get_admin_office_location(request.user)
            if admin_office:
                sessions = sessions.filter(current_office_location=admin_office)
        
        # Date range filter
        if date_from:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
            sessions = sessions.filter(created_at__date__gte=date_from_obj)
        
        if date_to:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
            sessions = sessions.filter(created_at__date__lte=date_to_obj)
        
        # User filter
        if user_id:
            sessions = sessions.filter(user_id=user_id)
        
        # Status filter
        if status:
            if status == 'active':
                sessions = sessions.filter(is_active=True, is_idle=False)
            elif status == 'idle':
                sessions = sessions.filter(is_active=True, is_idle=True)
            elif status == 'ended':
                sessions = sessions.filter(is_active=False)
        
        # Calculate stats
        total_sessions = sessions.count()
        active_sessions = sessions.filter(is_active=True, is_idle=False).count()
        idle_sessions = sessions.filter(is_active=True, is_idle=True).count()
        ended_sessions = sessions.filter(is_active=False).count()
        
        # Unique users
        total_users = sessions.values('user').distinct().count()
        
        # Average session duration (in minutes)
        avg_duration = sessions.filter(
            ended_at__isnull=False
        ).aggregate(
            avg=Avg(
                ExpressionWrapper(
                    F('ended_at') - F('login_time'),
                    output_field=DurationField()
                )
            )
        )['avg']
        
        avg_duration_minutes = 0
        if avg_duration:
            avg_duration_minutes = int(avg_duration.total_seconds() / 60)
        
        # Total session time today
        today_sessions = sessions.filter(created_at__date=timezone.now().date())
        total_time_today = 0
        for session in today_sessions:
            if session.ended_at:
                duration = (session.ended_at - session.login_time).total_seconds() / 3600
            else:
                duration = (timezone.now() - session.login_time).total_seconds() / 3600
            total_time_today += duration
        
        # Peak hour
        hourly_counts = sessions.annotate(
            hour=ExtractHour('login_time')
        ).values('hour').annotate(
            count=Count('id')
        ).order_by('-count').first()
        
        peak_hour = hourly_counts['hour'] if hourly_counts else 0
        
        # Remote workers (no office location)
        remote_count = sessions.filter(current_office_location__isnull=True).count()
        
        # Office occupancy (for specific office)
        office_occupancy = 0
        if office_id:
            office = OfficeLocation.objects.filter(id=office_id).first()
            if office and hasattr(office, 'capacity') and office.capacity:
                active_in_office = sessions.filter(
                    current_office_location_id=office_id,
                    is_active=True
                ).count()
                office_occupancy = int((active_in_office / office.capacity) * 100)
        
        # Build response
        stats = {
            'total_sessions': total_sessions,
            'active_sessions': active_sessions,
            'idle_sessions': idle_sessions,
            'ended_sessions': ended_sessions,
            'total_users': total_users,
            'avg_duration_minutes': avg_duration_minutes,
            'total_time_today_hours': round(total_time_today, 1),
            'peak_hour': peak_hour,
            'remote_workers': remote_count,
            'office_occupancy_percent': office_occupancy,
            'timestamp': timezone.now().isoformat(),
        }
        
        # Cache for 2 minutes
        cache.set(cache_key, stats, 120)
        
        return JsonResponse(stats)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================================================
# CHART DATA APIs
# ============================================================================

@login_required
@require_GET
def api_hourly_activity(request):
    """
    Get hourly activity data for line chart (last 24 hours).
    Returns: {hours: [], counts: [], labels: []}
    """
    try:
        office_id = request.GET.get('office_id')
        date_str = request.GET.get('date', timezone.now().date().isoformat())
        
        cache_key = f"hourly_activity:{office_id}:{date_str}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return JsonResponse(cached_data)
        
        # Get sessions for the specified date
        target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        sessions = UserSession.objects.filter(
            created_at__date=target_date
        ).select_related('current_office_location')
        
        if office_id:
            sessions = sessions.filter(current_office_location_id=office_id)
        
        # Group by hour
        hourly_data = sessions.annotate(
            hour=ExtractHour('login_time')
        ).values('hour').annotate(
            count=Count('id'),
            active_count=Count(Case(
                When(is_active=True, is_idle=False, then=1),
                output_field=IntegerField()
            )),
            idle_count=Count(Case(
                When(is_active=True, is_idle=True, then=1),
                output_field=IntegerField()
            ))
        ).order_by('hour')
        
        # Build arrays for chart
        hours = list(range(24))
        counts = [0] * 24
        active_counts = [0] * 24
        idle_counts = [0] * 24
        labels = [f"{h:02d}:00" for h in hours]
        
        for item in hourly_data:
            hour = item['hour']
            counts[hour] = item['count']
            active_counts[hour] = item['active_count']
            idle_counts[hour] = item['idle_count']
        
        data = {
            'hours': hours,
            'total': counts,
            'active': active_counts,
            'idle': idle_counts,
            'labels': labels,
        }
        
        cache.set(cache_key, data, 300)  # 5 minutes
        return JsonResponse(data)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_GET
def api_office_distribution(request):
    """
    Get office distribution data for pie chart.
    Returns: {labels: [], data: [], colors: [], offices: [{id, name, count}]}
    """
    try:
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')
        
        cache_key = f"office_dist:{date_from}:{date_to}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return JsonResponse(cached_data)
        
        sessions = UserSession.objects.select_related('current_office_location').all()
        
        if date_from:
            sessions = sessions.filter(created_at__date__gte=date_from)
        if date_to:
            sessions = sessions.filter(created_at__date__lte=date_to)
        
        # Group by office with ID
        office_data = sessions.values(
            'current_office_location__id',
            'current_office_location__name'
        ).annotate(
            count=Count('id')
        ).order_by('-count')
        
        labels = []
        data = []
        offices = []  # Store office details with IDs
        colors = [
            '#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6',
            '#ec4899', '#06b6d4', '#84cc16', '#f97316', '#6366f1'
        ]
        
        for idx, item in enumerate(office_data):
            office_id = item['current_office_location__id']
            office_name = item['current_office_location__name'] or 'Remote'
            count = item['count']
            
            labels.append(office_name)
            data.append(count)
            offices.append({
                'id': office_id,
                'name': office_name,
                'count': count
            })
        
        result = {
            'labels': labels,
            'data': data,
            'colors': colors[:len(labels)],
            'offices': offices,  # Include office IDs for drill-down
        }
        
        cache.set(cache_key, result, 300)
        return JsonResponse(result)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_GET
def api_device_statistics(request):
    """
    Get device type statistics for bar chart.
    Returns: {labels: [], data: []}
    """
    try:
        office_id = request.GET.get('office_id')
        
        cache_key = f"device_stats:{office_id}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return JsonResponse(cached_data)
        
        sessions = UserSession.objects.all()
        
        if office_id:
            sessions = sessions.filter(current_office_location_id=office_id)
        
        # Group by device type
        device_data = sessions.values('device_type').annotate(
            count=Count('id')
        ).order_by('-count')
        
        labels = []
        data = []
        
        for item in device_data:
            device_type = item['device_type'] or 'Unknown'
            labels.append(device_type.title())
            data.append(item['count'])
        
        result = {
            'labels': labels,
            'data': data,
        }
        
        cache.set(cache_key, result, 300)
        return JsonResponse(result)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_GET
def api_activity_timeline(request):
    """
    Get activity timeline data for timeline chart (office-wise).
    Returns: {datasets: [{office: str, data: [{x: timestamp, y: count}]}]}
    """
    try:
        date = request.GET.get('date', timezone.now().date().isoformat())
        
        cache_key = f"activity_timeline:{date}"
        cached_data = cache.get(cache_key)
        if cached_data:
            return JsonResponse(cached_data)
        
        target_date = datetime.strptime(date, '%Y-%m-%d').date()
        
        # Get all session activities for the date, grouped by hour and office
        activities = SessionActivity.objects.filter(
            created_at__date=target_date
        ).select_related('session__current_office_location')
        
        # Group by office and hour
        timeline_data = {}
        
        for activity in activities:
            office_name = 'Remote'
            if activity.session.current_office_location:
                office_name = activity.session.current_office_location.name
            
            hour = activity.created_at.hour
            
            if office_name not in timeline_data:
                timeline_data[office_name] = [0] * 24
            
            timeline_data[office_name][hour] += 1
        
        # Build datasets for Chart.js
        datasets = []
        colors = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6']
        
        for idx, (office, counts) in enumerate(timeline_data.items()):
            datasets.append({
                'label': office,
                'data': counts,
                'borderColor': colors[idx % len(colors)],
                'backgroundColor': colors[idx % len(colors)] + '20',  # 20% opacity
                'fill': True,
            })
        
        result = {
            'labels': [f"{h:02d}:00" for h in range(24)],
            'datasets': datasets,
        }
        
        cache.set(cache_key, result, 300)
        return JsonResponse(result)
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================================================
# DRILL-DOWN APIs
# ============================================================================

@login_required
@require_GET
def api_drill_active_sessions(request):
    """
    Get detailed list of active sessions for modal.
    Returns paginated session data.
    """
    try:
        office_id = request.GET.get('office_id')
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 50))
        
        sessions = UserSession.objects.filter(
            is_active=True,
            is_idle=False
        ).select_related(
            'user', 'user__profile', 'current_office_location'
        ).order_by('-login_time')
        
        if office_id:
            sessions = sessions.filter(current_office_location_id=office_id)
        
        # Paginate
        start = (page - 1) * page_size
        end = start + page_size
        total = sessions.count()
        sessions_page = sessions[start:end]
        
        # Build response
        session_list = []
        for session in sessions_page:
            duration = (timezone.now() - session.login_time).total_seconds() / 60
            
            session_list.append({
                'id': str(session.id),
                'user': {
                    'id': session.user.id,
                    'username': session.user.username,
                    'first_name': session.user.first_name,
                    'last_name': session.user.last_name,
                    'full_name': session.user.get_full_name() or session.user.username,
                },
                'office': session.current_office_location.name if session.current_office_location else 'Remote',
                'login_time': session.login_time.isoformat(),
                'duration_minutes': int(duration),
                'device_type': session.device_type or 'Unknown',
                'ip_address': session.ip_address,
                'status': 'Active',
            })
        
        return JsonResponse({
            'sessions': session_list,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size,
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_GET
def api_drill_idle_sessions(request):
    """
    Get detailed list of idle sessions for modal.
    """
    try:
        office_id = request.GET.get('office_id')
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 50))
        
        sessions = UserSession.objects.filter(
            is_active=True,
            is_idle=True
        ).select_related(
            'user', 'user__profile', 'current_office_location'
        ).order_by('-last_activity')
        
        if office_id:
            sessions = sessions.filter(current_office_location_id=office_id)
        
        # Paginate
        start = (page - 1) * page_size
        end = start + page_size
        total = sessions.count()
        sessions_page = sessions[start:end]
        
        # Build response
        session_list = []
        for session in sessions_page:
            idle_duration = 0
            if session.last_activity:
                idle_duration = (timezone.now() - session.last_activity).total_seconds() / 60
            
            session_list.append({
                'id': str(session.id),
                'user': {
                    'id': session.user.id,
                    'username': session.user.username,
                    'first_name': session.user.first_name,
                    'last_name': session.user.last_name,
                    'full_name': session.user.get_full_name() or session.user.username,
                },
                'office': session.current_office_location.name if session.current_office_location else 'Remote',
                'login_time': session.login_time.isoformat(),
                'last_activity': session.last_activity.isoformat() if session.last_activity else None,
                'idle_duration_minutes': int(idle_duration),
                'device_type': session.device_type or 'Unknown',
                'status': 'Idle',
            })
        
        return JsonResponse({
            'sessions': session_list,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size,
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_GET
def api_drill_office(request, office_id):
    """
    Get all sessions for a specific office.
    """
    try:
        page = int(request.GET.get('page', 1))
        page_size = int(request.GET.get('page_size', 50))
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')
        
        sessions = UserSession.objects.filter(
            current_office_location_id=office_id
        ).select_related(
            'user', 'user__profile'
        ).order_by('-login_time')
        
        if date_from:
            sessions = sessions.filter(created_at__date__gte=date_from)
        if date_to:
            sessions = sessions.filter(created_at__date__lte=date_to)
        
        # Paginate
        start = (page - 1) * page_size
        end = start + page_size
        total = sessions.count()
        sessions_page = sessions[start:end]
        
        # Build response
        session_list = []
        for session in sessions_page:
            if session.ended_at:
                duration = (session.ended_at - session.login_time).total_seconds() / 60
            else:
                duration = (timezone.now() - session.login_time).total_seconds() / 60
            
            session_list.append({
                'id': str(session.id),
                'user': {
                    'id': session.user.id,
                    'username': session.user.username,
                    'full_name': session.user.get_full_name() or session.user.username,
                },
                'login_time': session.login_time.isoformat(),
                'ended_at': session.ended_at.isoformat() if session.ended_at else None,
                'duration_minutes': int(duration),
                'is_active': session.is_active,
                'is_idle': session.is_idle,
                'device_type': session.device_type or 'Unknown',
            })
        
        return JsonResponse({
            'sessions': session_list,
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size,
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================================================
# LIVE ACTIVITY FEED API
# ============================================================================

@login_required
@require_GET
def api_live_activity_feed(request):
    """
    Get recent session activities for live feed.
    Returns last 50 activities since last_update timestamp.
    """
    try:
        last_update = request.GET.get('last_update')
        office_id = request.GET.get('office_id')
        
        # Get recent activities
        activities = SessionActivity.objects.select_related(
            'session__user',
            'session__current_office_location'
        ).order_by('-created_at')[:50]
        
        if last_update:
            last_update_dt = datetime.fromisoformat(last_update.replace('Z', '+00:00'))
            activities = activities.filter(created_at__gt=last_update_dt)
        
        if office_id:
            activities = activities.filter(session__current_office_location_id=office_id)
        
        # Build feed items
        feed_items = []
        for activity in activities:
            user_name = activity.session.user.get_full_name() or activity.session.user.username
            office = 'Remote'
            if activity.session.current_office_location:
                office = activity.session.current_office_location.name
            
            # Format activity message
            if activity.activity_type == 'heartbeat':
                message = f"{user_name} is active at {office}"
            elif activity.activity_type == 'page_view':
                message = f"{user_name} viewed a page at {office}"
            elif activity.activity_type == 'idle_state':
                message = f"{user_name} went idle at {office}"
            else:
                message = f"{user_name} - {activity.activity_type} at {office}"
            
            # Time ago
            time_diff = timezone.now() - activity.created_at
            if time_diff.seconds < 60:
                time_ago = f"{time_diff.seconds}s ago"
            elif time_diff.seconds < 3600:
                time_ago = f"{time_diff.seconds // 60}m ago"
            else:
                time_ago = f"{time_diff.seconds // 3600}h ago"
            
            feed_items.append({
                'id': activity.id,
                'message': message,
                'time_ago': time_ago,
                'timestamp': activity.created_at.isoformat(),
                'activity_type': activity.activity_type,
                'user_id': activity.session.user.id,
                'session_id': str(activity.session.id),
            })
        
        return JsonResponse({
            'activities': feed_items,
            'count': len(feed_items),
            'timestamp': timezone.now().isoformat(),
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)


# ============================================================================
# USER SEARCH API
# ============================================================================

@login_required
@require_GET
def api_user_search(request):
    """
    Search users by username, first_name, or last_name.
    Returns: [{id, username, first_name, last_name, full_name}]
    """
    try:
        query = request.GET.get('q', '').strip()
        
        if not query or len(query) < 2:
            return JsonResponse({'users': []})
        
        # Search in username, first_name, and last_name
        users = User.objects.filter(
            Q(username__icontains=query) |
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query)
        ).values(
            'id', 'username', 'first_name', 'last_name'
        )[:20]  # Limit to 20 results
        
        user_list = []
        for user in users:
            full_name = f"{user['first_name']} {user['last_name']}".strip()
            if not full_name:
                full_name = user['username']
            
            user_list.append({
                'id': user['id'],
                'username': user['username'],
                'first_name': user['first_name'],
                'last_name': user['last_name'],
                'full_name': full_name,
            })
        
        return JsonResponse({'users': user_list})
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
