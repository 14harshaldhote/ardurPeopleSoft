from django.db.models import Q
from django.utils import timezone
from decimal import Decimal
from trueAlign.models import LeavePolicy, LeaveAllocation, UserLeaveBalance, LeaveRequest, CompOffRequest, LeaveType

def initialize_user_balances(user, year):
    """
    Initialize or ensure user has leave balances for the given year based on their policy.
    Creates UserLeaveBalance entries if they don't exist.
    """
    policy = get_active_policy(user)
    if not policy:
        return
    
    # Get all allocations for this policy
    allocations = LeaveAllocation.objects.filter(
        policy=policy,
        is_deleted=False
    ).select_related('leave_type')
    
    for allocation in allocations:
        # Check if balance already exists for this user, year, and leave type
        balance, created = UserLeaveBalance.objects.get_or_create(
            user=user,
            leave_type=allocation.leave_type,
            year=year,
            defaults={
                'allocated': allocation.annual_days,
                'used': Decimal('0.00'),
                'additional': Decimal('0.00'),
                'carried_forward': Decimal('0.00'),
                'is_deleted': False
            }
        )
        
        # If balance already existed but has different allocated amount, update it
        if not created and balance.allocated != allocation.annual_days:
            balance.allocated = allocation.annual_days
            balance.save()

def get_user_leave_balance(user, year):
    """Get leave balance for a user for a specific year"""
    # First, ensure balances are initialized
    initialize_user_balances(user, year)
    
    # Now fetch and return balances
    balances = UserLeaveBalance.objects.filter(user=user, year=year, is_deleted=False).select_related('leave_type')
    return balances

def get_pending_approvals(user):
    """Get pending leave requests for a manager/approver"""
    return LeaveRequest.objects.filter(approver=user, status='Pending', is_deleted=False).select_related('user', 'leave_type')

def get_active_policy(user):
    """Get active leave policy for a user"""
    if not user:
        return None
    user_groups = user.groups.all()
    if not user_groups:
        return None
    return LeavePolicy.objects.filter(
        group__in=user_groups,
        is_active=True,
        is_deleted=False
    ).first()

def get_team_leaves(manager):
    """Get leave history for a manager's team"""
    # Assuming manager is the approver for their team
    return LeaveRequest.objects.filter(approver=manager, is_deleted=False).select_related('user', 'leave_type').order_by('-created_at')

def get_potential_approvers(user):
    """Get list of potential approvers for a user"""
    from django.contrib.auth import get_user_model
    User = get_user_model()
    # Return all users in Manager group, excluding self
    return User.objects.filter(groups__name='Manager').exclude(id=user.id)
