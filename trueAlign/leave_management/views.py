"""
Simplified Leave Management Views - Core Functionality
"""
from .decorators import employee_required, manager_required, hr_required, multiple_roles_required

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, Http404
from django.core.paginator import Paginator
from django.db.models import Q, Count, Sum
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST
from django.contrib.auth.models import User, Group
from datetime import datetime, timedelta
import json
import logging

# Import models from trueAlign
from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance,
    LeaveRequest, CompOffRequest
)

# Import our utilities and services
from .utils import (
    can_approve_leave, can_view_leave_request, can_edit_leave_request,
    can_cancel_leave_request, is_employee, is_manager, is_hr, is_admin,
    get_user_roles, Roles, require_role, require_any_role, require_hr_or_admin
)
from .services.leave_service import LeaveService, LeaveServiceError
from .forms import LeaveApplicationForm, CompOffRequestForm, LeaveFilterForm

logger = logging.getLogger(__name__)

# ================================
# DASHBOARD VIEWS
# ================================

@login_required
def dashboard(request):
    """Main dashboard - routes to appropriate role-based dashboard"""
    user_roles = get_user_roles(request.user)

    if Roles.ADMIN in user_roles:
        return admin_dashboard(request)
    elif Roles.HR in user_roles:
        return hr_dashboard(request)
    elif Roles.MANAGER in user_roles:
        return manager_dashboard(request)
    else:
        return employee_dashboard(request)

@login_required
@employee_required
def employee_dashboard(request):
    """Employee dashboard showing personal leave information"""
    try:
        # Get leave summary
        summary = LeaveService.get_leave_summary(request.user)

        # Get recent requests
        recent_requests = LeaveRequest.objects.filter(
            user=request.user
        ).select_related('leave_type', 'approver', 'user').order_by('-created_at')[:5]

        # Get pending count
        pending_count = LeaveRequest.objects.filter(
            user=request.user,
            status='Pending'
        ).count()

        context = {
            'summary': summary,
            'recent_requests': recent_requests,
            'pending_count': pending_count,
            'current_year': timezone.now().year,
        }

        return render(request, 'leave_management/employee_dashboard.html', context)

    except Exception as e:
        logger.error(f"Error in employee dashboard for {request.user.username}: {str(e)}")
        messages.error(request, "Error loading dashboard")
        return render(request, 'leave_management/employee_dashboard.html', {})

@login_required
@require_role(Roles.MANAGER)
@manager_required
def manager_dashboard(request):
    """Manager dashboard showing team leave information"""
    try:
        # Get team members (employees)
        team_members = User.objects.filter(
            groups__name=Roles.EMPLOYEE,
            is_active=True
        ).select_related('profile').prefetch_related('groups')

        # Get pending approvals for team
        pending_approvals = LeaveRequest.objects.filter(
            user__in=team_members,
            status='Pending'
        ).select_related('user', 'leave_type', 'approver').order_by('created_at')[:10]

        # Get stats
        stats = {
            'total_team_members': team_members.count(),
            'pending_approvals': pending_approvals.count(),
            'on_leave_today': LeaveRequest.objects.filter(
                user__in=team_members,
                status='Approved',
                start_date__lte=timezone.now().date(),
                end_date__gte=timezone.now().date()
            ).select_related('user').count()
        }

        context = {
            'pending_approvals': pending_approvals,
            'stats': stats,
            'team_members': team_members,
        }

        return render(request, 'leave_management/manager_dashboard.html', context)

    except Exception as e:
        logger.error(f"Error in manager dashboard: {str(e)}")
        messages.error(request, "Error loading dashboard")
        return render(request, 'leave_management/manager_dashboard.html', {})

@login_required
@require_role(Roles.HR)
@hr_required
def hr_dashboard(request):
    """HR dashboard showing organization-wide leave information"""
    try:
        current_year = timezone.now().year

        stats = {
            'total_employees': User.objects.filter(is_active=True).count(),
            'pending_requests': LeaveRequest.objects.filter(status='Pending').count(),
            'approved_this_month': LeaveRequest.objects.filter(
                status='Approved',
                created_at__year=timezone.now().year,
                created_at__month=timezone.now().month
            ).count(),
            'total_leave_days_this_year': LeaveRequest.objects.filter(
                status='Approved',
                start_date__year=current_year
            ).aggregate(total=Sum('leave_days'))['total'] or 0
        }

        # Get recent requests
        recent_requests = LeaveRequest.objects.filter(
            status='Pending'
        ).select_related('user', 'leave_type', 'approver').order_by('created_at')[:10]

        context = {
            'stats': stats,
            'recent_requests': recent_requests,
            'current_year': current_year,
        }

        return render(request, 'leave_management/hr_dashboard.html', context)

    except Exception as e:
        logger.error(f"Error in HR dashboard: {str(e)}")
        messages.error(request, "Error loading dashboard")
        return render(request, 'leave_management/hr_dashboard.html', {})

@login_required
@require_role(Roles.ADMIN)
def admin_dashboard(request):
    """Admin dashboard with full system overview"""
    try:
        current_year = timezone.now().year

        stats = {
            'total_users': User.objects.filter(is_active=True).count(),
            'total_leave_types': LeaveType.objects.filter(is_active=True).count(),
            'total_policies': LeavePolicy.objects.filter(is_active=True).count(),
            'pending_requests': LeaveRequest.objects.filter(status='Pending').count(),
        }

        context = {
            'stats': stats,
            'current_year': current_year,
        }

        return render(request, 'leave_management/admin_dashboard.html', context)

    except Exception as e:
        logger.error(f"Error in admin dashboard: {str(e)}")
        messages.error(request, "Error loading dashboard")
        return render(request, 'leave_management/admin_dashboard.html', {})

# ================================
# LEAVE REQUEST VIEWS
# ================================

@login_required
def apply_leave(request):
    """Apply for leave"""
    if request.method == 'POST':
        form = LeaveApplicationForm(request.POST, request.FILES, user=request.user)
        if form.is_valid():
            try:
                leave_data = form.cleaned_data.copy()
                leave_request, result = LeaveService.apply_leave(request.user, leave_data)

                if result['is_valid']:
                    messages.success(request, f"Leave application submitted successfully. Request ID: {leave_request.id}")
                    return redirect('leave_management:my_leaves')
                else:
                    for error in result.get('errors', []):
                        messages.error(request, error)

            except LeaveServiceError as e:
                messages.error(request, str(e))
            except Exception as e:
                logger.error(f"Error applying leave for {request.user.username}: {str(e)}")
                messages.error(request, "An error occurred while processing your request")
    else:
        form = LeaveApplicationForm(user=request.user)

    # Get user's leave balances
    try:
        balance_data = LeaveService.get_user_leave_balance(request.user)
        balances = balance_data.get('balances', []) if balance_data.get('success') else []
    except:
        balances = []

    context = {
        'form': form,
        'balances': balances,
    }

    return render(request, 'leave_management/apply_leave.html', context)

@login_required
def my_leaves(request):
    """View user's own leave requests"""
    # Base queryset
    leaves = LeaveRequest.objects.filter(
        user=request.user
    ).select_related('leave_type', 'approver').order_by('-created_at')

    # Simple filtering by status
    status_filter = request.GET.get('status')
    if status_filter:
        leaves = leaves.filter(status=status_filter)

    # Pagination
    paginator = Paginator(leaves, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'status_filter': status_filter,
        'status_choices': LeaveRequest.STATUS_CHOICES,
    }

    return render(request, 'leave_management/my_leaves.html', context)

@login_required
def leave_detail(request, leave_id):
    """View detailed information about a leave request"""
    leave_request = get_object_or_404(LeaveRequest, id=leave_id)

    # Check if user can view this leave request
    if not can_view_leave_request(request.user, leave_request):
        raise Http404("Leave request not found")

    context = {
        'leave_request': leave_request,
        'can_edit': can_edit_leave_request(request.user, leave_request),
        'can_cancel': can_cancel_leave_request(request.user, leave_request),
        'can_approve': can_approve_leave(request.user, leave_request.user),
    }

    return render(request, 'leave_management/leave_detail.html', context)

@login_required
@require_POST
def approve_leave(request, leave_id):
    """Approve a leave request"""
    leave_request = get_object_or_404(LeaveRequest, id=leave_id)

    if not can_approve_leave(request.user, leave_request.user):
        messages.error(request, "You are not authorized to approve this leave request")
        return redirect('leave_management:leave_detail', leave_id=leave_id)

    try:
        result = LeaveService.approve_leave(leave_request, request.user)

        if result.get('success'):
            messages.success(request, "Leave request approved successfully")
        else:
            messages.error(request, result.get('message', 'Approval failed'))

    except LeaveServiceError as e:
        messages.error(request, str(e))
    except Exception as e:
        logger.error(f"Error approving leave {leave_id}: {str(e)}")
        messages.error(request, "An error occurred while approving the request")

    return redirect('leave_management:leave_detail', leave_id=leave_id)

@login_required
@require_POST
def reject_leave(request, leave_id):
    """Reject a leave request"""
    leave_request = get_object_or_404(LeaveRequest, id=leave_id)

    if not can_approve_leave(request.user, leave_request.user):
        messages.error(request, "You are not authorized to reject this leave request")
        return redirect('leave_management:leave_detail', leave_id=leave_id)

    rejection_reason = request.POST.get('rejection_reason', '')
    if not rejection_reason:
        messages.error(request, "Rejection reason is required")
        return redirect('leave_management:leave_detail', leave_id=leave_id)

    try:
        result = LeaveService.reject_leave(leave_request, request.user, rejection_reason)

        if result.get('success'):
            messages.success(request, "Leave request rejected")
        else:
            messages.error(request, result.get('message', 'Rejection failed'))

    except LeaveServiceError as e:
        messages.error(request, str(e))
    except Exception as e:
        logger.error(f"Error rejecting leave {leave_id}: {str(e)}")
        messages.error(request, "An error occurred while rejecting the request")

    return redirect('leave_management:leave_detail', leave_id=leave_id)

@login_required
@require_POST
def cancel_leave(request, leave_id):
    """Cancel a leave request"""
    leave_request = get_object_or_404(LeaveRequest, id=leave_id)

    if not can_cancel_leave_request(request.user, leave_request):
        messages.error(request, "You cannot cancel this leave request")
        return redirect('leave_management:leave_detail', leave_id=leave_id)

    try:
        reason = request.POST.get('cancellation_reason', '')
        result = LeaveService.cancel_leave(leave_request, request.user, reason)

        if result.get('success'):
            messages.success(request, "Leave request cancelled successfully")
        else:
            messages.error(request, result.get('message', 'Cancellation failed'))

    except LeaveServiceError as e:
        messages.error(request, str(e))
    except Exception as e:
        logger.error(f"Error cancelling leave {leave_id}: {str(e)}")
        messages.error(request, "An error occurred while cancelling the request")

    return redirect('leave_management:leave_detail', leave_id=leave_id)

# ================================
# TEAM MANAGEMENT (MANAGERS)
# ================================

@login_required
@require_any_role(Roles.MANAGER, Roles.HR, Roles.ADMIN)
def team_leaves(request):
    """View team leave requests"""
    if is_manager(request.user) and not (is_hr(request.user) or is_admin(request.user)):
        team_members = User.objects.filter(groups__name=Roles.EMPLOYEE, is_active=True)
    else:
        team_members = User.objects.filter(is_active=True)

    # Base queryset
    leaves = LeaveRequest.objects.filter(
        user__in=team_members
    ).select_related('user', 'leave_type', 'approver').order_by('-created_at')

    # Simple filtering
    status_filter = request.GET.get('status')
    if status_filter:
        leaves = leaves.filter(status=status_filter)

    user_filter = request.GET.get('user')
    if user_filter:
        try:
            user_id = int(user_filter)
            leaves = leaves.filter(user_id=user_id)
        except (ValueError, TypeError):
            messages.warning(request, "Invalid user filter parameter")

    # Pagination
    paginator = Paginator(leaves, 15)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'team_members': team_members,
        'status_filter': status_filter,
        'user_filter': user_filter,
        'status_choices': LeaveRequest.STATUS_CHOICES,
    }

    return render(request, 'leave_management/team_leaves.html', context)

# ================================
# BALANCE VIEWS
# ================================

@login_required
def leave_balance(request):
    """View leave balance"""
    user_to_view = request.user

    # HR/Admin can view other users' balances
    if is_hr(request.user) or is_admin(request.user):
        user_id = request.GET.get('user_id')
        if user_id:
            try:
                user_id_int = int(user_id)
                user_to_view = User.objects.get(id=user_id_int, is_active=True)
            except (ValueError, TypeError):
                messages.error(request, "Invalid user ID parameter")
            except User.DoesNotExist:
                messages.error(request, "User not found")

    try:
        year = int(request.GET.get('year', timezone.now().year))
    except (ValueError, TypeError):
        year = timezone.now().year
        messages.warning(request, "Invalid year parameter, using current year")

    try:
        balance_data = LeaveService.get_user_leave_balance(user_to_view, year)
        balances = balance_data.get('balances', []) if balance_data.get('success') else []
    except Exception as e:
        logger.error(f"Error getting leave balance: {str(e)}")
        balances = []
        messages.error(request, "Error loading leave balances")

    context = {
        'balances': balances,
        'user_to_view': user_to_view,
        'year': year,
        'can_view_all': is_hr(request.user) or is_admin(request.user),
    }

    return render(request, 'leave_management/leave_balance.html', context)

# ================================
# COMP-OFF VIEWS
# ================================

@login_required
def apply_comp_off(request):
    """Apply for compensation off"""
    if request.method == 'POST':
        form = CompOffRequestForm(request.POST, user=request.user)
        if form.is_valid():
            try:
                comp_off_data = form.cleaned_data
                comp_off_request, result = LeaveService.apply_comp_off(request.user, comp_off_data)

                if result.get('success'):
                    messages.success(request, f"Comp-off request submitted successfully. Request ID: {comp_off_request.id}")
                    return redirect('leave_management:my_comp_off')
                else:
                    messages.error(request, result.get('message', 'Comp-off application failed'))

            except Exception as e:
                logger.error(f"Error applying comp-off: {str(e)}")
                messages.error(request, "An error occurred while processing your request")
    else:
        form = CompOffRequestForm(user=request.user)

    context = {
        'form': form,
    }

    return render(request, 'leave_management/apply_comp_off.html', context)

@login_required
def my_comp_off(request):
    """View user's comp-off requests"""
    comp_off_requests = CompOffRequest.objects.filter(
        user=request.user
    ).select_related('approver').order_by('-created_at')

    paginator = Paginator(comp_off_requests, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
    }

    return render(request, 'leave_management/my_comp_off.html', context)

# ================================
# API ENDPOINTS
# ================================

@login_required
def api_leave_balance(request, user_id=None):
    """API endpoint to get leave balance data"""
    if user_id and not (is_hr(request.user) or is_admin(request.user)):
        return JsonResponse({'error': 'Permission denied'}, status=403)

    target_user = request.user
    if user_id:
        try:
            user_id_int = int(user_id)
            target_user = User.objects.get(id=user_id_int, is_active=True)
        except (ValueError, TypeError):
            return JsonResponse({'error': 'Invalid user ID parameter'}, status=400)
        except User.DoesNotExist:
            return JsonResponse({'error': 'User not found'}, status=404)

    try:
        year = int(request.GET.get('year', timezone.now().year))
    except (ValueError, TypeError):
        year = timezone.now().year

    try:
        balance_data = LeaveService.get_user_leave_balance(target_user, year)
        return JsonResponse({
            'success': True,
            'data': balance_data,
            'error': None
        })
    except LeaveServiceError as e:
        logger.error(f"Leave service error in API: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'data': None,
            'error': str(e)
        }, status=400)
    except Exception as e:
        logger.error(f"Unexpected error in leave balance API: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'data': None,
            'error': 'An unexpected error occurred while fetching leave balance'
        }, status=500)

@login_required
def api_leave_types(request):
    """API endpoint to get leave types"""
    try:
        leave_types = LeaveType.objects.filter(is_active=True).values(
            'id', 'name', 'is_paid', 'requires_approval', 'requires_documentation',
            'count_weekends', 'can_be_half_day'
        )

        return JsonResponse({
            'success': True,
            'data': {
                'leave_types': list(leave_types)
            },
            'error': None
        })
    except Exception as e:
        logger.error(f"Error fetching leave types: {str(e)}", exc_info=True)
        return JsonResponse({
            'success': False,
            'data': None,
            'error': 'Failed to fetch leave types'
        }, status=500)
