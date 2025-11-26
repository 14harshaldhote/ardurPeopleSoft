from django.db.models import Count, Q
from django.utils import timezone
from trueAlign.models import LeaveRequest, UserLeaveBalance, LeaveType
from django.contrib.auth import get_user_model

User = get_user_model()

def get_leave_type_distribution(user_queryset=None):
    """
    Get distribution of leave types for a set of users (or all if None).
    Returns data suitable for a Pie Chart.
    """
    qs = LeaveRequest.objects.filter(status='Approved', is_deleted=False)
    if user_queryset:
        qs = qs.filter(user__in=user_queryset)
        
    distribution = qs.values('leave_type__name').annotate(count=Count('id')).order_by('-count')
    return list(distribution)

def get_daily_leave_status(date=None):
    """
    Get status of who is on leave for a specific date.
    """
    if date is None:
        date = timezone.localdate()
        
    on_leave = LeaveRequest.objects.filter(
        status='Approved',
        start_date__lte=date,
        end_date__gte=date,
        is_deleted=False
    ).select_related('user', 'leave_type')
    
    return on_leave

def get_team_attendance_stats(manager):
    """
    Get attendance stats for a manager's team for the current month.
    """
    # This would ideally query the Attendance model, but we can approximate with LeaveRequest
    # for "Planned Leaves".
    # For now, let's return leave counts for the team.
    
    # Assuming we can get team members via a helper or group
    # For this example, we'll use the 'approver' relationship as a proxy for team
    team_leaves = LeaveRequest.objects.filter(approver=manager, status='Approved', is_deleted=False)
    
    # Group by user
    stats = team_leaves.values('user__username').annotate(total_leaves=Count('id')).order_by('-total_leaves')
    return list(stats)

def get_pending_request_stats():
    """
    Get count of pending requests by type (for HR Dashboard).
    """
    return LeaveRequest.objects.filter(status='Pending', is_deleted=False).values('leave_type__name').annotate(count=Count('id'))
