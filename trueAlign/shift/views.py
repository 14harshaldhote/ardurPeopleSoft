"""
Unified Shift Management Views
Provides both Django template views and API endpoints
"""

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.utils import timezone
from django.db.models import Q, Count
from django.contrib.auth.models import User, Group
from django.core.paginator import Paginator
from django.views.decorators.http import require_http_methods
from datetime import datetime, timedelta, date
import json
import logging

# Import from main models since we moved them there
from trueAlign.models import ShiftMaster, ShiftAssignment, ShiftConflict, ShiftValidationRule

logger = logging.getLogger(__name__)

def user_has_permission(user, required_groups):
    """Check if user belongs to any of the required groups"""
    if not user.is_authenticated:
        return False
    return user.groups.filter(name__in=required_groups).exists() or user.is_superuser


# =============================================================================
# DJANGO TEMPLATE VIEWS
# =============================================================================

@login_required
def dashboard(request):
    """Shift management dashboard"""
    # Check permissions
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to access shift management.')
        return redirect('dashboard')
    
    # Get dashboard statistics
    today = timezone.now().date()
    
    stats = {
        'total_shifts': ShiftMaster.objects.count(),
        'active_shifts': ShiftMaster.objects.filter(is_active=True).count(),
        'total_assignments': ShiftAssignment.objects.count(),
        'active_assignments': ShiftAssignment.objects.filter(
            effective_from__lte=today,
            status__in=['ACTIVE', 'APPROVED']
        ).filter(
            Q(effective_to__gte=today) | Q(effective_to__isnull=True)
        ).count(),
        'pending_approvals': ShiftAssignment.objects.filter(status='PENDING').count(),
        'unresolved_conflicts': ShiftConflict.objects.filter(is_resolved=False).count(),
    }
    
    # Recent assignments
    recent_assignments = ShiftAssignment.objects.select_related(
        'user', 'shift', 'created_by'
    ).order_by('-created_at')[:10]
    
    # Recent conflicts
    recent_conflicts = ShiftConflict.objects.select_related(
        'assignment__user', 'assignment__shift'
    ).order_by('-created_at')[:5]
    
    context = {
        'stats': stats,
        'recent_assignments': recent_assignments,
        'recent_conflicts': recent_conflicts,
        'is_admin': user_has_permission(request.user, ['Admin']),
        'is_hr': user_has_permission(request.user, ['HR']),
        'is_manager': user_has_permission(request.user, ['Manager']),
    }
    
    return render(request, 'shift/dashboard.html', context)

@login_required
def shift_list(request):
    """List all shifts"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to view shifts.')
        return redirect('shift:dashboard')
    
    shifts = ShiftMaster.objects.all()
    
    # Apply filters
    search = request.GET.get('search')
    if search:
        shifts = shifts.filter(
            Q(name__icontains=search) | Q(description__icontains=search)
        )
    
    is_active = request.GET.get('is_active')
    if is_active:
        shifts = shifts.filter(is_active=is_active.lower() == 'true')
    
    # Pagination
    paginator = Paginator(shifts, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'search': search,
        'is_active': is_active,
        'can_create': user_has_permission(request.user, ['Admin', 'HR', 'Manager']),
    }
    
    return render(request, 'shift/shift_list.html', context)

@login_required
def shift_create(request):
    """Create new shift"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to create shifts.')
        return redirect('shift:shift_list')
    
    if request.method == 'POST':
        try:
            shift = ShiftMaster.objects.create(
                name=request.POST['name'],
                start_time=request.POST['start_time'],
                end_time=request.POST['end_time'],
                work_days=request.POST.get('work_days', 'Weekdays'),
                custom_work_days=request.POST.get('custom_work_days', ''),
                description=request.POST.get('description', ''),
                color_code=request.POST.get('color_code', '#3B82F6'),
                requires_approval=request.POST.get('requires_approval') == 'on',
                created_by=request.user
            )
            
            messages.success(request, f'Shift "{shift.name}" created successfully.')
            return redirect('shift:shift_detail', pk=shift.pk)
            
        except Exception as e:
            messages.error(request, f'Error creating shift: {str(e)}')
    
    context = {
        'work_days_choices': ShiftMaster.WORK_DAYS_CHOICES,
    }
    
    return render(request, 'shift/shift_form.html', context)

@login_required
def assignment_list(request):
    """List all assignments"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to view assignments.')
        return redirect('shift:dashboard')
    
    assignments = ShiftAssignment.objects.select_related(
        'user', 'shift', 'created_by'
    ).order_by('-created_at')
    
    # Apply filters
    user_id = request.GET.get('user_id')
    if user_id:
        assignments = assignments.filter(user_id=user_id)
    
    shift_id = request.GET.get('shift_id')
    if shift_id:
        assignments = assignments.filter(shift_id=shift_id)
    
    status = request.GET.get('status')
    if status:
        assignments = assignments.filter(status=status)
    
    # Pagination
    paginator = Paginator(assignments, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    # Get filter options
    users = User.objects.filter(shift_assignments__isnull=False).distinct()
    shifts = ShiftMaster.objects.filter(assignments__isnull=False).distinct()
    
    context = {
        'page_obj': page_obj,
        'users': users,
        'shifts': shifts,
        'user_id': user_id,
        'shift_id': shift_id,
        'status': status,
        'assignment_status_choices': ShiftAssignment.ASSIGNMENT_STATUS,
        'can_create': user_has_permission(request.user, ['Admin', 'HR', 'Manager']),
    }
    
    return render(request, 'shift/assignment_list.html', context)


# =============================================================================
# API ENDPOINTS FOR FAST DATA PARSING
# =============================================================================

@login_required
@require_http_methods(["GET"])
def api_shifts_list(request):
    """API endpoint for shifts list"""
    shifts = ShiftMaster.objects.filter(is_active=True).values(
        'id', 'name', 'start_time', 'end_time', 'color_code', 'requires_approval'
    )
    return JsonResponse({'shifts': list(shifts)})

@login_required
@require_http_methods(["GET"])
def api_assignments_list(request):
    """API endpoint for assignments list"""
    assignments = ShiftAssignment.objects.select_related('user', 'shift').filter(
        status__in=['ACTIVE', 'APPROVED']
    ).values(
        'id', 'user__username', 'user__first_name', 'user__last_name',
        'shift__name', 'shift__color_code', 'effective_from', 'effective_to', 'status'
    )
    return JsonResponse({'assignments': list(assignments)})

@login_required
@require_http_methods(["GET"])
def api_dashboard_stats(request):
    """API endpoint for dashboard statistics"""
    today = timezone.now().date()
    
    stats = {
        'total_shifts': ShiftMaster.objects.count(),
        'active_shifts': ShiftMaster.objects.filter(is_active=True).count(),
        'total_assignments': ShiftAssignment.objects.count(),
        'active_assignments': ShiftAssignment.objects.filter(
            effective_from__lte=today,
            status__in=['ACTIVE', 'APPROVED']
        ).filter(
            Q(effective_to__gte=today) | Q(effective_to__isnull=True)
        ).count(),
        'pending_approvals': ShiftAssignment.objects.filter(status='PENDING').count(),
        'unresolved_conflicts': ShiftConflict.objects.filter(is_resolved=False).count(),
    }
    
    return JsonResponse(stats)


@login_required
def bulk_assignment_create(request):
    """Create bulk assignments"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to create bulk assignments.')
        return redirect('shift:assignment_list')
    
    if request.method == 'POST':
        try:
            # Process bulk assignment data
            users = request.POST.getlist('users')
            shift_id = request.POST.get('shift')
            effective_from = request.POST.get('effective_from')
            effective_to = request.POST.get('effective_to')
            notes = request.POST.get('notes', '')
            
            shift = get_object_or_404(ShiftMaster, pk=shift_id)
            created_count = 0
            
            for user_id in users:
                user = get_object_or_404(User, pk=user_id)
                assignment = ShiftAssignment.objects.create(
                    user=user,
                    shift=shift,
                    effective_from=effective_from,
                    effective_to=effective_to or None,
                    notes=notes,
                    status='PENDING' if shift.requires_approval else 'ACTIVE',
                    requires_approval=shift.requires_approval,
                    created_by=request.user
                )
                created_count += 1
            
            messages.success(request, f'Successfully created {created_count} assignments.')
            return redirect('shift:assignment_list')
            
        except Exception as e:
            messages.error(request, f'Error creating bulk assignments: {str(e)}')
    
    # Get available users and shifts
    users = User.objects.filter(is_active=True).order_by('first_name', 'last_name')
    shifts = ShiftMaster.objects.filter(is_active=True).order_by('name')
    
    context = {
        'users': users,
        'shifts': shifts,
    }
    
    return render(request, 'shift/bulk_assignment_form.html', context)

@login_required
def shift_detail(request, pk):
    """Shift detail view"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to view shift details.')
        return redirect('shift:dashboard')
    
    shift = get_object_or_404(ShiftMaster, pk=pk)
    
    # Get assignments for this shift
    assignments = shift.assignments.select_related('user').order_by('-created_at')
    
    # Apply filters
    status_filter = request.GET.get('status')
    if status_filter:
        assignments = assignments.filter(status=status_filter)
    
    # Pagination
    paginator = Paginator(assignments, 20)
    page_number = request.GET.get('page')
    assignments_page = paginator.get_page(page_number)
    
    context = {
        'shift': shift,
        'assignments_page': assignments_page,
        'status_filter': status_filter,
        'assignment_status_choices': ShiftAssignment.ASSIGNMENT_STATUS,
        'can_edit': user_has_permission(request.user, ['Admin', 'HR']),
        'can_assign': user_has_permission(request.user, ['Admin', 'HR', 'Manager']),
    }
    
    return render(request, 'shift/shift_detail.html', context)

@login_required
def assignment_create(request):
    """Create new assignment"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to create assignments.')
        return redirect('shift:assignment_list')
    
    if request.method == 'POST':
        try:
            # Get the shift to check if approval is required
            shift = get_object_or_404(ShiftMaster, pk=request.POST['shift'])
            
            assignment = ShiftAssignment.objects.create(
                user_id=request.POST['user'],
                shift=shift,
                effective_from=request.POST['effective_from'],
                effective_to=request.POST.get('effective_to') or None,
                notes=request.POST.get('notes', ''),
                status='PENDING' if shift.requires_approval else 'ACTIVE',
                requires_approval=shift.requires_approval,
                created_by=request.user
            )
            
            if shift.requires_approval:
                messages.info(request, f'Assignment created and sent for approval.')
            else:
                messages.success(request, f'Assignment created successfully.')
            
            return redirect('shift:assignment_detail', pk=assignment.pk)
            
        except Exception as e:
            messages.error(request, f'Error creating assignment: {str(e)}')
    
    # Get available users and shifts
    users = User.objects.filter(is_active=True).order_by('first_name', 'last_name')
    shifts = ShiftMaster.objects.filter(is_active=True).order_by('name')
    
    context = {
        'users': users,
        'shifts': shifts,
    }
    
    return render(request, 'shift/assignment_form.html', context)

@login_required
def assignment_detail(request, pk):
    """Assignment detail view"""
    assignment = get_object_or_404(ShiftAssignment, pk=pk)
    
    # Check permissions
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        # Allow users to view their own assignments
        if assignment.user != request.user:
            messages.error(request, 'You do not have permission to view this assignment.')
            return redirect('shift:dashboard')
    
    # Get conflicts for this assignment
    conflicts = assignment.conflicts.all().order_by('-created_at')
    
    context = {
        'assignment': assignment,
        'conflicts': conflicts,
        'can_edit': user_has_permission(request.user, ['Admin', 'HR', 'Manager']),
        'can_approve': user_has_permission(request.user, ['Admin', 'HR', 'Manager']),
    }
    
    return render(request, 'shift/assignment_detail.html', context)

@login_required
def assignment_approve(request, pk):
    """Approve assignment"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to approve assignments.')
        return redirect('shift:assignment_list')
    
    assignment = get_object_or_404(ShiftAssignment, pk=pk)
    
    if assignment.status != 'PENDING':
        messages.error(request, 'Only pending assignments can be approved.')
        return redirect('shift:assignment_detail', pk=pk)
    
    assignment.status = 'APPROVED'
    assignment.approved_by = request.user
    assignment.approved_at = timezone.now()
    assignment.save()
    
    messages.success(request, f'Assignment for {assignment.user.get_full_name()} approved successfully.')
    return redirect('shift:assignment_detail', pk=pk)

@login_required
def assignment_reject(request, pk):
    """Reject assignment"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to reject assignments.')
        return redirect('shift:assignment_list')
    
    assignment = get_object_or_404(ShiftAssignment, pk=pk)
    
    if assignment.status != 'PENDING':
        messages.error(request, 'Only pending assignments can be rejected.')
        return redirect('shift:assignment_detail', pk=pk)
    
    if request.method == 'POST':
        reason = request.POST.get('reason', '')
        assignment.status = 'REJECTED'
        if reason:
            assignment.notes = f"{assignment.notes}\nRejection reason: {reason}".strip()
        assignment.save()
        
        messages.success(request, f'Assignment for {assignment.user.get_full_name()} rejected.')
        return redirect('shift:assignment_detail', pk=pk)
    
    context = {'assignment': assignment}
    return render(request, 'shift/assignment_reject.html', context)

@login_required
def conflict_list(request):
    """List all conflicts"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to view conflicts.')
        return redirect('shift:dashboard')
    
    conflicts = ShiftConflict.objects.select_related(
        'assignment__user', 'assignment__shift'
    ).order_by('-created_at')
    
    # Apply filters
    is_resolved = request.GET.get('is_resolved')
    if is_resolved:
        conflicts = conflicts.filter(is_resolved=is_resolved.lower() == 'true')
    
    severity = request.GET.get('severity')
    if severity:
        conflicts = conflicts.filter(severity=severity)
    
    # Pagination
    paginator = Paginator(conflicts, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'is_resolved': is_resolved,
        'severity': severity,
        'severity_choices': ShiftConflict.CONFLICT_SEVERITY,
    }
    
    return render(request, 'shift/conflict_list.html', context)

@login_required
def calendar_view(request):
    """Calendar view of assignments"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to view calendar.')
        return redirect('shift:dashboard')
    
    # Get date from request or use today
    date_str = request.GET.get('date')
    if date_str:
        try:
            target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            target_date = timezone.now().date()
    else:
        target_date = timezone.now().date()
    
    # Get assignments for the target date
    assignments = ShiftAssignment.objects.filter(
        effective_from__lte=target_date,
        status__in=['ACTIVE', 'APPROVED']
    ).filter(
        Q(effective_to__gte=target_date) | Q(effective_to__isnull=True)
    ).select_related('user', 'shift').order_by('shift__start_time')
    
    # Group by shift
    shift_assignments = {}
    for assignment in assignments:
        shift_name = assignment.shift.name
        if shift_name not in shift_assignments:
            shift_assignments[shift_name] = {
                'shift': assignment.shift,
                'assignments': []
            }
        shift_assignments[shift_name]['assignments'].append(assignment)
    
    context = {
        'target_date': target_date,
        'shift_assignments': shift_assignments,
        'total_assignments': assignments.count(),
    }
    
    return render(request, 'shift/calendar.html', context)
