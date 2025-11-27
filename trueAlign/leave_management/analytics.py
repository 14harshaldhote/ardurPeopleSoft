from django.db.models import Count, Q, Sum, Avg, F, ExpressionWrapper, DurationField, FloatField
from django.db.models.functions import TruncMonth, TruncDay, ExtractWeekDay, Cast
from django.utils import timezone
from trueAlign.models import LeaveRequest, UserLeaveBalance, LeaveType, LeavePolicy, CompOffRequest
from django.contrib.auth import get_user_model
import json
from datetime import timedelta

User = get_user_model()

def get_leave_analytics(filters=None):
    """
    Main entry point to get all analytics data based on filters.
    """
    if filters is None:
        filters = {}

    # Base QuerySet
    qs = LeaveRequest.objects.filter(is_deleted=False)

    # Apply Filters
    if filters.get('start_date'):
        qs = qs.filter(start_date__gte=filters['start_date'])
    if filters.get('end_date'):
        qs = qs.filter(end_date__lte=filters['end_date'])
    if filters.get('user_id'):
        qs = qs.filter(user_id=filters['user_id'])
    if filters.get('leave_type_id'):
        qs = qs.filter(leave_type_id=filters['leave_type_id'])
    if filters.get('department_id'): # Assuming group/department link via user or policy
        # This depends on how User is linked to Department/Group. 
        # Using LeavePolicy.group as a proxy if available, or User.groups
        qs = qs.filter(user__groups__id=filters['department_id'])
    if filters.get('status'):
        qs = qs.filter(status=filters['status'])

    # Aggregations
    kpis = get_kpi_metrics(qs)
    charts = {
        'type_distribution': get_leaves_by_type(qs),
        'trend': get_leaves_over_time(qs),
        'department_distribution': get_leaves_by_department(qs),
        'heatmap': get_calendar_heatmap_data(qs),
    }
    grid_data = get_aggrid_data(qs)

    return {
        'kpis': kpis,
        'charts': charts,
        'grid_data': grid_data
    }

def get_kpi_metrics(qs):
    """
    Calculate high-level KPIs.
    """
    total = qs.count()
    if total == 0:
        return {
            'total_requests': 0,
            'approval_rate': 0,
            'rejection_rate': 0,
            'avg_duration': 0,
            'pending_count': 0
        }

    stats = qs.aggregate(
        approved=Count('id', filter=Q(status='Approved')),
        rejected=Count('id', filter=Q(status='Rejected')),
        pending=Count('id', filter=Q(status='Pending')),
        avg_days=Avg('leave_days')
    )

    return {
        'total_requests': total,
        'approval_rate': round((stats['approved'] / total) * 100, 1),
        'rejection_rate': round((stats['rejected'] / total) * 100, 1),
        'avg_duration': round(stats['avg_days'] or 0, 1),
        'pending_count': stats['pending']
    }

def get_leaves_by_type(qs):
    """
    Data for Pie Chart: Leave Type Distribution.
    """
    data = qs.values('leave_type__name').annotate(value=Count('id')).order_by('-value')
    return [{'name': item['leave_type__name'], 'value': item['value']} for item in data]

def get_leaves_over_time(qs):
    """
    Data for Line Chart: Leaves over time (Monthly/Daily).
    """
    # Group by month for trend
    data = qs.annotate(month=TruncMonth('start_date')).values('month').annotate(count=Count('id')).order_by('month')
    
    return {
        'dates': [item['month'].strftime('%Y-%m-%d') for item in data if item['month']],
        'counts': [item['count'] for item in data if item['month']]
    }

def get_leaves_by_department(qs):
    """
    Data for Bar Chart: Leaves by Department/Group.
    """
    # Assuming User has a 'groups' relation or similar. 
    # If User model has 'department' field, use that.
    # Fallback to 'user__groups__name'
    data = qs.values('user__groups__name').annotate(count=Count('id')).order_by('-count')
    # Filter out None groups if any
    return [{'name': item['user__groups__name'] or 'Unassigned', 'value': item['count']} for item in data]

def get_calendar_heatmap_data(qs):
    """
    Data for ECharts Calendar Heatmap.
    Returns list of [date, count]
    """
    # This is tricky because a leave request spans multiple days.
    # For a true heatmap, we need to explode the date ranges.
    # Doing this in Python for simplicity as Django ORM doesn't support generating series easily without specific DB functions.
    
    heatmap_data = {}
    approved_leaves = qs.filter(status='Approved')
    
    for leave in approved_leaves:
        current_date = leave.start_date
        while current_date <= leave.end_date:
            date_str = current_date.strftime('%Y-%m-%d')
            heatmap_data[date_str] = heatmap_data.get(date_str, 0) + 1
            current_date += timedelta(days=1)
            
    return [[date, count] for date, count in heatmap_data.items()]

def get_aggrid_data(qs):
    """
    Flat JSON data for AG Grid.
    """
    data = qs.select_related('user', 'leave_type', 'approver').values(
        'id',
        'user__username',
        'user__email',
        'leave_type__name',
        'start_date',
        'end_date',
        'leave_days',
        'status',
        'reason',
        'approver__username',
        'created_at'
    ).order_by('-created_at')
    
    # Format for frontend
    formatted_data = []
    for item in data:
        formatted_data.append({
            'id': item['id'],
            'employee': item['user__username'],
            'email': item['user__email'],
            'type': item['leave_type__name'],
            'start_date': item['start_date'].strftime('%Y-%m-%d'),
            'end_date': item['end_date'].strftime('%Y-%m-%d'),
            'days': float(item['leave_days']),
            'status': item['status'],
            'reason': item['reason'],
            'approver': item['approver__username'] or 'N/A',
            'applied_on': item['created_at'].strftime('%Y-%m-%d %H:%M')
        })
    return formatted_data

# --- Legacy Support (Keep existing functions if used elsewhere, or refactor them to use new logic) ---

def get_leave_type_distribution(user_queryset=None):
    qs = LeaveRequest.objects.filter(status='Approved', is_deleted=False)
    if user_queryset:
        qs = qs.filter(user__in=user_queryset)
    return list(qs.values('leave_type__name').annotate(count=Count('id')).order_by('-count'))

def get_daily_leave_status(date=None):
    if date is None:
        date = timezone.localdate()
    return LeaveRequest.objects.filter(
        status='Approved',
        start_date__lte=date,
        end_date__gte=date,
        is_deleted=False
    ).select_related('user', 'leave_type')

def get_team_attendance_stats(manager):
    team_leaves = LeaveRequest.objects.filter(approver=manager, status='Approved', is_deleted=False)
    return list(team_leaves.values('user__username').annotate(total_leaves=Count('id')).order_by('-total_leaves'))

def get_pending_request_stats():
    return LeaveRequest.objects.filter(status='Pending', is_deleted=False).values('leave_type__name').annotate(count=Count('id'))
