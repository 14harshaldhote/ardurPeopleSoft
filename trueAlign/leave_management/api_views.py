"""
API Views for Leave Management Policy Tracking and Allocation
"""
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.contrib.auth.models import User, Group
from django.utils import timezone
from django.db.models import Count, Sum, Q
from datetime import datetime, timedelta
import json
import logging

from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance,
    LeaveRequest
)
from .utils import is_hr, is_admin, require_hr_or_admin
from .services.leave_service import LeaveService, LeaveServiceError

logger = logging.getLogger(__name__)


@login_required
@require_http_methods(["GET"])
def api_policy_allocation_status(request):
    """
    API endpoint to get policy allocation status and tracking information
    """
    if not (is_hr(request.user) or is_admin(request.user)):
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        current_year = timezone.now().year
        
        # Get all active policies
        policies = LeavePolicy.objects.filter(is_active=True).prefetch_related(
            'allocations__leave_type', 'group'
        )
        
        policy_data = []
        for policy in policies:
            # Get users in this policy's group
            users_in_group = User.objects.filter(
                groups=policy.group, 
                is_active=True
            ).count()
            
            # Get users with allocated balances for this year
            allocated_users = UserLeaveBalance.objects.filter(
                user__groups=policy.group,
                year=current_year
            ).values('user').distinct().count()
            
            # Get policy allocations
            allocations = []
            for allocation in policy.allocations.all():
                allocations.append({
                    'leave_type': allocation.leave_type.name,
                    'annual_days': float(allocation.annual_days),
                    'max_consecutive_days': allocation.max_consecutive_days,
                    'advance_notice_days': allocation.advance_notice_days,
                    'carry_forward_limit': float(allocation.carryforward_limit)
                })
            
            # Check if policy is expiring (if it has an end date)
            expiring_soon = False
            if hasattr(policy, 'end_date') and policy.end_date:
                days_until_expiry = (policy.end_date - timezone.now().date()).days
                expiring_soon = days_until_expiry <= 30
            
            policy_data.append({
                'id': policy.id,
                'name': policy.name,
                'group': policy.group.name,
                'description': policy.description,
                'users_in_group': users_in_group,
                'allocated_users': allocated_users,
                'allocation_percentage': round((allocated_users / users_in_group * 100) if users_in_group > 0 else 0, 2),
                'allocations': allocations,
                'expiring_soon': expiring_soon,
                'is_active': policy.is_active
            })
        
        # Get overall statistics
        total_users = User.objects.filter(is_active=True).count()
        users_with_allocations = UserLeaveBalance.objects.filter(
            year=current_year
        ).values('user').distinct().count()
        
        stats = {
            'total_active_policies': len(policy_data),
            'total_users': total_users,
            'users_with_allocations': users_with_allocations,
            'allocation_coverage': round((users_with_allocations / total_users * 100) if total_users > 0 else 0, 2),
            'current_year': current_year
        }
        
        return JsonResponse({
            'success': True,
            'data': {
                'policies': policy_data,
                'statistics': stats
            },
            'error': None
        })
        
    except Exception as e:
        logger.error(f"Error getting policy allocation status: {str(e)}")
        return JsonResponse({
            'success': False,
            'data': None,
            'error': 'Failed to fetch policy allocation status'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def api_policy_expiration_alerts(request):
    """
    API endpoint to get policies that are expiring soon
    """
    if not (is_hr(request.user) or is_admin(request.user)):
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        # Get policies expiring in the next 30 days
        thirty_days_from_now = timezone.now().date() + timedelta(days=30)
        
        expiring_policies = []
        policies = LeavePolicy.objects.filter(is_active=True)
        
        for policy in policies:
            # Check if policy has an end date (you may need to add this field to the model)
            if hasattr(policy, 'end_date') and policy.end_date:
                if policy.end_date <= thirty_days_from_now:
                    days_remaining = (policy.end_date - timezone.now().date()).days
                    expiring_policies.append({
                        'id': policy.id,
                        'name': policy.name,
                        'group': policy.group.name,
                        'end_date': policy.end_date.isoformat(),
                        'days_remaining': days_remaining,
                        'urgency': 'critical' if days_remaining <= 7 else 'warning' if days_remaining <= 14 else 'info'
                    })
        
        return JsonResponse({
            'success': True,
            'data': {
                'expiring_policies': expiring_policies,
                'count': len(expiring_policies)
            },
            'error': None
        })
        
    except Exception as e:
        logger.error(f"Error getting policy expiration alerts: {str(e)}")
        return JsonResponse({
            'success': False,
            'data': None,
            'error': 'Failed to fetch policy expiration alerts'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def api_bulk_allocate_leaves(request):
    """
    API endpoint to perform bulk leave allocation
    """
    if not (is_hr(request.user) or is_admin(request.user)):
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        data = json.loads(request.body)
        group_name = data.get('group_name')
        year = data.get('year', timezone.now().year)
        
        if not group_name:
            return JsonResponse({
                'success': False,
                'error': 'Group name is required'
            }, status=400)
        
        # Get users in the specified group
        try:
            group = Group.objects.get(name=group_name)
            users = User.objects.filter(groups=group, is_active=True)
        except Group.DoesNotExist:
            return JsonResponse({
                'success': False,
                'error': f'Group "{group_name}" not found'
            }, status=404)
        
        if not users.exists():
            return JsonResponse({
                'success': False,
                'error': f'No active users found in group "{group_name}"'
            }, status=404)
        
        # Perform bulk allocation
        result = LeaveService.bulk_allocate_leaves(list(users), year)
        
        return JsonResponse({
            'success': True,
            'data': result,
            'error': None
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        logger.error(f"Error in bulk leave allocation: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to perform bulk allocation'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def api_leave_usage_analytics(request):
    """
    API endpoint to get leave usage analytics
    """
    if not (is_hr(request.user) or is_admin(request.user)):
        return JsonResponse({'error': 'Permission denied'}, status=403)

    try:
        current_year = timezone.now().year
        year = int(request.GET.get('year', current_year))
        
        # Get leave usage by type
        leave_usage_by_type = LeaveRequest.objects.filter(
            start_date__year=year,
            status='Approved'
        ).values('leave_type__name').annotate(
            total_requests=Count('id'),
            total_days=Sum('leave_days')
        ).order_by('-total_days')
        
        # Get leave usage by month
        monthly_usage = []
        for month in range(1, 13):
            month_data = LeaveRequest.objects.filter(
                start_date__year=year,
                start_date__month=month,
                status='Approved'
            ).aggregate(
                total_requests=Count('id'),
                total_days=Sum('leave_days')
            )
            monthly_usage.append({
                'month': month,
                'month_name': datetime(year, month, 1).strftime('%B'),
                'total_requests': month_data['total_requests'] or 0,
                'total_days': float(month_data['total_days'] or 0)
            })
        
        # Get top leave requesters
        top_requesters = LeaveRequest.objects.filter(
            start_date__year=year,
            status='Approved'
        ).values('user__username', 'user__first_name', 'user__last_name').annotate(
            total_requests=Count('id'),
            total_days=Sum('leave_days')
        ).order_by('-total_days')[:10]
        
        # Get pending requests summary
        pending_summary = LeaveRequest.objects.filter(
            status='Pending'
        ).aggregate(
            total_pending=Count('id'),
            pending_days=Sum('leave_days')
        )
        
        return JsonResponse({
            'success': True,
            'data': {
                'year': year,
                'leave_usage_by_type': list(leave_usage_by_type),
                'monthly_usage': monthly_usage,
                'top_requesters': list(top_requesters),
                'pending_summary': {
                    'total_pending': pending_summary['total_pending'] or 0,
                    'pending_days': float(pending_summary['pending_days'] or 0)
                }
            },
            'error': None
        })
        
    except Exception as e:
        logger.error(f"Error getting leave usage analytics: {str(e)}")
        return JsonResponse({
            'success': False,
            'data': None,
            'error': 'Failed to fetch leave usage analytics'
        }, status=500)
