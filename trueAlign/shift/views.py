"""
Unified Shift Management Views
Provides both Django template views and API endpoints with comprehensive business logic
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
from django.db import transaction
from datetime import datetime, timedelta, date
import json
import logging

# Import from main models since we moved them there
from trueAlign.models import ShiftMaster, ShiftAssignment, ShiftConflict, ShiftValidationRule

# Import business logic services and validators
from .services import (
    ShiftService, ShiftAssignmentService, ConflictDetectionService, ReportingService
)
from .validators import ShiftAssignmentValidator, BulkAssignmentValidator

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
    """Enhanced shift management dashboard with comprehensive statistics"""
    # Check if user has management permissions
    has_management_access = user_has_permission(request.user, ['Admin', 'HR', 'Manager'])
    
    # If employee, show limited dashboard
    if not has_management_access:
        # Get user's current assignments
        user_assignments = ShiftAssignment.objects.filter(
            user=request.user,
            is_current=True
        ).select_related('shift')
        
        context = {
            'user_assignments': user_assignments,
            'is_employee_view': True,
        }
        return render(request, 'shift/dashboard.html', context)
    
    # Get comprehensive dashboard statistics using ReportingService
    try:
        stats = ReportingService.get_dashboard_statistics()
        
        # Transform the structure to match template expectations
        dashboard_stats = {
            'total_shifts': stats['shifts']['total'],
            'active_shifts': stats['shifts']['active'],
            'total_assignments': stats['assignments']['total'],
            'active_assignments': stats['assignments']['active_today'],
            'pending_approvals': stats['assignments']['pending_approval'],
            'unresolved_conflicts': stats['conflicts']['unresolved'],
            'users': {
                'total_users': User.objects.filter(is_active=True).count(),
                'with_active_shifts': stats['users']['with_active_shifts']
            },
            'assignments': {
                'expiring_soon': stats['assignments']['expiring_soon']
            }
        }
        stats = dashboard_stats
        
        # Get recent activity with enhanced data
        recent_assignments = ShiftAssignment.objects.select_related(
            'user', 'shift', 'created_by', 'approved_by'
        ).order_by('-created_at')[:10]
        
        recent_conflicts = ShiftConflict.objects.select_related(
            'assignment__user', 'assignment__shift', 'resolved_by'
        ).filter(is_resolved=False).order_by('-created_at')[:5]
        
        # Get shift breakdown by name (since shift_type field doesn't exist)
        shift_type_stats = ShiftMaster.objects.filter(is_active=True).values('name').annotate(
            count=Count('id')
        ).order_by('-count')[:10]  # Limit to top 10 shifts
        
        # Get assignment status breakdown
        assignment_status_stats = ShiftAssignment.objects.values('status').annotate(
            count=Count('id')
        ).order_by('-count')
        
        context = {
            'stats': stats,
            'recent_assignments': recent_assignments,
            'recent_conflicts': recent_conflicts,
            'shift_type_stats': shift_type_stats,
            'assignment_status_stats': assignment_status_stats,
            'is_admin': user_has_permission(request.user, ['Admin']),
            'is_hr': user_has_permission(request.user, ['HR']),
            'is_manager': user_has_permission(request.user, ['Manager']),
            'can_create': user_has_permission(request.user, ['Admin', 'HR', 'Manager']),
            'can_approve': user_has_permission(request.user, ['Admin', 'HR']),
        }
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        messages.error(request, 'Error loading dashboard data.')
        context = {
            'stats': {},
            'recent_assignments': [],
            'recent_conflicts': [],
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
    
    shifts = ShiftMaster.objects.all().order_by('name')
    
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
            # Parse duration fields
            break_duration_str = request.POST.get('break_duration', '30')
            grace_period_str = request.POST.get('grace_period', '15')
            
            shift = ShiftMaster.objects.create(
                name=request.POST['name'],
                start_time=request.POST['start_time'],
                end_time=request.POST['end_time'],
                work_days=request.POST.get('work_days', 'Weekdays'),
                custom_work_days=request.POST.get('custom_work_days', ''),
                description=request.POST.get('description', ''),
                color_code=request.POST.get('color_code', '#3B82F6'),
                requires_approval=request.POST.get('requires_approval') == 'on',
                is_active=request.POST.get('is_active') == 'on',
                break_duration=timedelta(minutes=int(break_duration_str)),
                grace_period=timedelta(minutes=int(grace_period_str)),
                created_by=request.user
            )
            
            messages.success(request, f'Shift "{shift.name}" created successfully.')
            return redirect('shift:shift_detail', pk=shift.pk)
            
        except Exception as e:
            messages.error(request, f'Error creating shift: {str(e)}')
    
    context = {
        'work_days_choices': ShiftMaster.WORK_DAYS_CHOICES,
        'break_duration_minutes': 30,
        'grace_period_minutes': 15,
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
        'total_users': User.objects.filter(is_active=True).count(),
        'expiring_soon': ShiftAssignment.objects.filter(
            effective_to__range=[today, today + timedelta(days=7)],
            status__in=['ACTIVE', 'APPROVED']
        ).count(),
    }
    
    return JsonResponse(stats)


@login_required
def bulk_assignment_create(request):
    """Create bulk assignments with comprehensive validation"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to create assignments.')
        return redirect('shift:assignment_list')
    
    if request.method == 'POST':
        try:
            users = request.POST.getlist('users')
            shift_id = request.POST.get('shift')
            effective_from = request.POST.get('effective_from')
            effective_to = request.POST.get('effective_to')
            notes = request.POST.get('notes', '')
            
            # Validate required fields
            if not users:
                raise ValueError("No users selected")
            if not shift_id:
                raise ValueError("No shift selected")
            if not effective_from:
                raise ValueError("Effective from date is required")
            
            # Parse dates
            effective_from_date = datetime.strptime(effective_from, '%Y-%m-%d').date()
            effective_to_date = None
            if effective_to:
                effective_to_date = datetime.strptime(effective_to, '%Y-%m-%d').date()
            
            # Prepare bulk assignment data
            assignments_data = []
            for user_id in users:
                if user_id:  # Ensure user_id is not None or empty
                    assignments_data.append({
                        'user_id': int(user_id),
                        'shift_id': int(shift_id),
                        'effective_from': effective_from_date,
                        'effective_to': effective_to_date,
                        'notes': notes,
                    })
            
            # Use ShiftAssignmentService for bulk creation with validation
            result = ShiftAssignmentService.bulk_create_assignments(
                assignments_data, 
                created_by=request.user
            )
            
            assignments = result['assignments']
            warnings = result.get('warnings', [])
            conflicts = result.get('conflicts', [])
            
            # Handle warnings
            if warnings:
                for warning in warnings:
                    messages.warning(request, f'Warning: {warning}')
            
            # Handle conflicts
            if conflicts:
                messages.warning(request, f'Created {len(assignments)} assignments with {len(conflicts)} conflict(s) detected.')
                for conflict in conflicts:
                    messages.warning(request, f'Conflict: {conflict.description}')
            
            messages.success(request, f'Successfully created {len(assignments)} assignments.')
            return redirect('shift:assignment_list')
            
        except Exception as e:
            logger.error(f"Bulk assignment creation error: {str(e)}")
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
    """Create new assignment with comprehensive validation and conflict detection"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to create assignments.')
        return redirect('shift:assignment_list')
    
    if request.method == 'POST':
        try:
            # Prepare assignment data
            assignment_data = {
                'user_id': request.POST['user'],
                'shift_id': request.POST['shift'],
                'effective_from': request.POST['effective_from'],
                'effective_to': request.POST.get('effective_to') or None,
                'notes': request.POST.get('notes', ''),
            }
            
            # Use ShiftAssignmentService for comprehensive creation
            result = ShiftAssignmentService.create_assignment(
                assignment_data, 
                created_by=request.user
            )
            
            assignment = result['assignment']
            warnings = result.get('warnings', [])
            conflicts = result.get('conflicts', [])
            
            # Handle warnings
            if warnings:
                for warning in warnings:
                    messages.warning(request, f'Warning: {warning}')
            
            # Handle conflicts
            if conflicts:
                messages.warning(request, f'Created assignment with {len(conflicts)} conflict(s) detected.')
                for conflict in conflicts:
                    messages.warning(request, f'Conflict: {conflict.description}')
            
            # Success message based on approval requirement
            if assignment.requires_approval:
                messages.info(request, 'Assignment created and sent for approval.')
            else:
                messages.success(request, 'Assignment created successfully.')
            
            return redirect('shift:assignment_detail', pk=assignment.pk)
            
        except Exception as e:
            logger.error(f"Assignment creation error: {str(e)}")
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
    """Enhanced conflict list with comprehensive filtering and statistics"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to view conflicts.')
        return redirect('shift:dashboard')
    
    # Get conflicts with enhanced filtering
    conflicts = ShiftConflict.objects.select_related(
        'assignment__user', 'assignment__shift', 'conflicting_assignment__user',
        'conflicting_assignment__shift', 'resolved_by'
    ).order_by('-created_at')
    
    # Apply filters
    is_resolved = request.GET.get('is_resolved')
    if is_resolved:
        conflicts = conflicts.filter(is_resolved=is_resolved.lower() == 'true')
    
    severity = request.GET.get('severity')
    if severity:
        conflicts = conflicts.filter(severity=severity)
    
    conflict_type = request.GET.get('conflict_type')
    if conflict_type:
        conflicts = conflicts.filter(conflict_type=conflict_type)
    
    user_id = request.GET.get('user_id')
    if user_id:
        conflicts = conflicts.filter(assignment__user_id=user_id)
    
    # Get conflict statistics using ConflictDetectionService
    try:
        conflict_summary = ConflictDetectionService.get_conflict_summary()
    except Exception as e:
        logger.error(f"Error getting conflict summary: {str(e)}")
        conflict_summary = {}
    
    # Pagination
    paginator = Paginator(conflicts, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    
    context = {
        'page_obj': page_obj,
        'is_resolved': is_resolved,
        'severity': severity,
        'conflict_type': conflict_type,
        'user_id': user_id,
        'severity_choices': ShiftConflict.CONFLICT_SEVERITY,
        'conflict_type_choices': ShiftConflict.CONFLICT_TYPES,
        'conflict_summary': conflict_summary,
        'can_resolve': user_has_permission(request.user, ['Admin', 'HR']),
        'users': User.objects.filter(is_active=True).order_by('first_name', 'last_name'),
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


# =============================================================================
# ENHANCED API ENDPOINTS AND BUSINESS LOGIC VIEWS
# =============================================================================

@login_required
@require_http_methods(["POST"])
def resolve_conflict(request, conflict_id):
    """Resolve a specific conflict"""
    if not user_has_permission(request.user, ['Admin', 'HR']):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        conflict = get_object_or_404(ShiftConflict, id=conflict_id)
        
        if conflict.is_resolved:
            return JsonResponse({'error': 'Conflict is already resolved'}, status=400)
        
        resolution_notes = request.POST.get('resolution_notes', '')
        
        # Use ConflictDetectionService to resolve conflict
        resolved_conflict = ConflictDetectionService.resolve_conflict(
            conflict_id, request.user, resolution_notes
        )
        
        return JsonResponse({
            'message': 'Conflict resolved successfully',
            'conflict': {
                'id': resolved_conflict.id,
                'is_resolved': resolved_conflict.is_resolved,
                'resolved_by': resolved_conflict.resolved_by.get_full_name(),
                'resolved_at': resolved_conflict.resolved_at.isoformat() if resolved_conflict.resolved_at else None,
                'resolution_notes': resolved_conflict.resolution_notes
            }
        })
        
    except Exception as e:
        logger.error(f"Error resolving conflict {conflict_id}: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def assignment_history(request, user_id):
    """Get assignment history for a specific user"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        user = get_object_or_404(User, id=user_id)
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        
        # Convert string dates to date objects
        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        # Use ShiftAssignmentService to get timeline
        timeline = ShiftAssignmentService.get_user_shift_timeline(
            user_id, start_date, end_date
        )
        
        # Format response
        timeline_data = []
        for item in timeline:
            assignment = item['assignment']
            timeline_data.append({
                'id': assignment.id,
                'shift_name': assignment.shift.name,
                'shift_type': assignment.shift.get_shift_type_display(),
                'start_date': item['start_date'].isoformat(),
                'end_date': item['end_date'].isoformat(),
                'duration_days': item['duration_days'],
                'status': assignment.get_status_display(),
                'is_current': item['is_current'],
                'created_at': assignment.created_at.isoformat(),
                'notes': assignment.notes
            })
        
        return JsonResponse({
            'user': {
                'id': user.id,
                'name': user.get_full_name(),
                'email': user.email
            },
            'timeline': timeline_data,
            'total_assignments': len(timeline_data)
        })
        
    except Exception as e:
        logger.error(f"Error getting assignment history for user {user_id}: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def current_assignments_api(request):
    """Get current active assignments (API endpoint)"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        today = timezone.now().date()
        target_date = request.GET.get('date')
        
        if target_date:
            target_date = datetime.strptime(target_date, '%Y-%m-%d').date()
        else:
            target_date = today
        
        # Get active assignments for the date
        assignments = ShiftAssignment.objects.filter(
            effective_from__lte=target_date,
            status__in=['ACTIVE', 'APPROVED']
        ).filter(
            Q(effective_to__gte=target_date) | Q(effective_to__isnull=True)
        ).select_related('user', 'shift').order_by('shift__start_time')
        
        # Apply filters
        user_id = request.GET.get('user_id')
        if user_id:
            assignments = assignments.filter(user_id=user_id)
        
        shift_id = request.GET.get('shift_id')
        if shift_id:
            assignments = assignments.filter(shift_id=shift_id)
        
        # Format response
        assignments_data = []
        for assignment in assignments:
            assignments_data.append({
                'id': assignment.id,
                'user': {
                    'id': assignment.user.id,
                    'name': assignment.user.get_full_name(),
                    'email': assignment.user.email
                },
                'shift': {
                    'id': assignment.shift.id,
                    'name': assignment.shift.name,
                    'start_time': assignment.shift.start_time.strftime('%H:%M'),
                    'end_time': assignment.shift.end_time.strftime('%H:%M'),
                    'shift_type': assignment.shift.get_shift_type_display()
                },
                'effective_from': assignment.effective_from.isoformat(),
                'effective_to': assignment.effective_to.isoformat() if assignment.effective_to else None,
                'status': assignment.get_status_display(),
                'is_current': assignment.is_current,
                'notes': assignment.notes
            })
        
        return JsonResponse({
            'date': target_date.isoformat(),
            'assignments': assignments_data,
            'total_count': len(assignments_data)
        })
        
    except Exception as e:
        logger.error(f"Error getting current assignments: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def shift_utilization_report(request, shift_id):
    """Get shift utilization report"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        shift = get_object_or_404(ShiftMaster, id=shift_id)
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        
        # Convert string dates to date objects
        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        # Use ShiftService to get utilization
        utilization = ShiftService.get_shift_utilization(
            shift_id, start_date, end_date
        )
        
        # Format response
        return JsonResponse({
            'shift': {
                'id': shift.id,
                'name': shift.name,
                'shift_type': shift.get_shift_type_display()
            },
            'period': {
                'start_date': utilization['period']['start_date'].isoformat(),
                'end_date': utilization['period']['end_date'].isoformat()
            },
            'statistics': {
                'total_assignments': utilization['total_assignments'],
                'unique_users': utilization['unique_users'],
                'utilization_rate': utilization['utilization_rate'],
                'total_days': utilization['total_days'],
                'assigned_days': utilization['assigned_days']
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting shift utilization for shift {shift_id}: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def assignment_report(request):
    """Generate comprehensive assignment report"""
    if not user_has_permission(request.user, ['Admin', 'HR']):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        # Get parameters
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        user_ids = request.GET.getlist('user_ids')
        shift_ids = request.GET.getlist('shift_ids')
        include_conflicts = request.GET.get('include_conflicts', 'false').lower() == 'true'
        
        # Convert string dates to date objects
        if not start_date or not end_date:
            return JsonResponse({'error': 'start_date and end_date are required'}, status=400)
        
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        
        # Convert string IDs to integers
        user_ids = [int(uid) for uid in user_ids if uid]
        shift_ids = [int(sid) for sid in shift_ids if sid]
        
        # Use ReportingService to generate report
        report = ReportingService.generate_assignment_report(
            start_date, end_date, user_ids or None, shift_ids or None
        )
        
        # Format assignments data
        assignments_data = []
        for assignment in report['assignments']:
            assignment_data = {
                'id': assignment.id,
                'user': {
                    'id': assignment.user.id,
                    'name': assignment.user.get_full_name(),
                    'email': assignment.user.email
                },
                'shift': {
                    'id': assignment.shift.id,
                    'name': assignment.shift.name,
                    'shift_type': assignment.shift.get_shift_type_display()
                },
                'effective_from': assignment.effective_from.isoformat(),
                'effective_to': assignment.effective_to.isoformat() if assignment.effective_to else None,
                'status': assignment.get_status_display(),
                'duration_days': assignment.duration_days,
                'created_at': assignment.created_at.isoformat(),
                'notes': assignment.notes
            }
            assignments_data.append(assignment_data)
        
        response_data = {
            'period': {
                'start_date': report['period']['start_date'].isoformat(),
                'end_date': report['period']['end_date'].isoformat()
            },
            'statistics': report['statistics'],
            'assignments': assignments_data
        }
        
        # Include conflicts if requested
        if include_conflicts:
            conflicts = ShiftConflict.objects.filter(
                assignment__in=report['assignments']
            ).select_related('assignment', 'conflicting_assignment')
            
            conflicts_data = []
            for conflict in conflicts:
                conflicts_data.append({
                    'id': conflict.id,
                    'conflict_type': conflict.get_conflict_type_display(),
                    'severity': conflict.get_severity_display(),
                    'description': conflict.description,
                    'is_resolved': conflict.is_resolved,
                    'created_at': conflict.created_at.isoformat()
                })
            
            response_data['conflicts'] = conflicts_data
        
        return JsonResponse(response_data)
        
    except Exception as e:
        logger.error(f"Error generating assignment report: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def conflict_statistics(request):
    """Get comprehensive conflict statistics"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        # Use ConflictDetectionService to get statistics
        stats = ConflictDetectionService.get_conflict_summary()
        
        # Add recent conflicts
        recent_conflicts = ShiftConflict.objects.select_related(
            'assignment__user', 'assignment__shift'
        ).order_by('-created_at')[:10]
        
        recent_conflicts_data = []
        for conflict in recent_conflicts:
            recent_conflicts_data.append({
                'id': conflict.id,
                'conflict_type': conflict.get_conflict_type_display(),
                'severity': conflict.get_severity_display(),
                'description': conflict.description,
                'is_resolved': conflict.is_resolved,
                'user_name': conflict.assignment.user.get_full_name(),
                'shift_name': conflict.assignment.shift.name,
                'created_at': conflict.created_at.isoformat()
            })
        
        stats['recent_conflicts'] = recent_conflicts_data
        
        return JsonResponse(stats)
        
    except Exception as e:
        logger.error(f"Error getting conflict statistics: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def duplicate_shift(request, shift_id):
    """Duplicate an existing shift"""
    if not user_has_permission(request.user, ['Admin', 'HR']):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        import json
        data = json.loads(request.body)
        new_name = data.get('new_name')
        
        if not new_name:
            return JsonResponse({'error': 'New shift name is required'}, status=400)
        
        # Use ShiftService to duplicate shift
        new_shift = ShiftService.duplicate_shift(
            shift_id, new_name, request.user
        )
        
        return JsonResponse({
            'message': 'Shift duplicated successfully',
            'shift': {
                'id': new_shift.id,
                'name': new_shift.name,
                'start_time': new_shift.start_time.strftime('%H:%M'),
                'end_time': new_shift.end_time.strftime('%H:%M'),
                'shift_type': new_shift.get_shift_type_display()
            }
        })
        
    except Exception as e:
        logger.error(f"Error duplicating shift {shift_id}: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def reassign_assignment(request, assignment_id):
    """Reassign an assignment to a different shift"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        return JsonResponse({'error': 'Permission denied'}, status=403)
    
    try:
        import json
        data = json.loads(request.body)
        new_shift_id = data.get('new_shift_id')
        effective_from = data.get('effective_from')
        reason = data.get('reason', '')
        
        if not new_shift_id or not effective_from:
            return JsonResponse({'error': 'New shift ID and effective date are required'}, status=400)
        
        # Convert string date to date object
        from datetime import datetime
        effective_from = datetime.strptime(effective_from, '%Y-%m-%d').date()
        
        # Use ShiftAssignmentService to reassign
        result = ShiftAssignmentService.reassign_shift(
            assignment_id, new_shift_id, effective_from, reason
        )
        
        new_assignment = result['assignment']
        
        return JsonResponse({
            'message': 'Assignment reassigned successfully',
            'assignment': {
                'id': new_assignment.id,
                'user_name': new_assignment.user.get_full_name(),
                'shift_name': new_assignment.shift.name,
                'effective_from': new_assignment.effective_from.isoformat(),
                'status': new_assignment.get_status_display()
            }
        })
        
    except Exception as e:
        logger.error(f"Error reassigning assignment {assignment_id}: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def team_assignments_view(request):
    """View team assignments for a specific date"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to view team assignments.')
        return redirect('shift:dashboard')
    
    try:
        # Get target date from request or use today
        target_date_str = request.GET.get('date')
        if target_date_str:
            target_date = datetime.strptime(target_date_str, '%Y-%m-%d').date()
        else:
            target_date = timezone.now().date()
        
        # Get team assignments for the target date directly
        assignments = ShiftAssignment.objects.select_related('user', 'shift').filter(
            effective_from__lte=target_date,
            status__in=['ACTIVE', 'APPROVED']
        ).filter(
            Q(effective_to__gte=target_date) | Q(effective_to__isnull=True)
        ).order_by('shift__name', 'user__first_name')
        
        # Group assignments by shift
        shift_assignments = []
        current_shift = None
        current_assignments = []
        
        for assignment in assignments:
            if current_shift != assignment.shift:
                if current_shift is not None:
                    shift_assignments.append({
                        'shift': current_shift,
                        'assignments': current_assignments
                    })
                current_shift = assignment.shift
                current_assignments = [assignment]
            else:
                current_assignments.append(assignment)
        
        # Add the last group
        if current_shift is not None:
            shift_assignments.append({
                'shift': current_shift,
                'assignments': current_assignments
            })
        
        # Calculate summary statistics
        total_assignments = sum(len(group['assignments']) for group in shift_assignments)
        active_shifts_count = len(shift_assignments)
        unique_users = set()
        for group in shift_assignments:
            for assignment in group['assignments']:
                unique_users.add(assignment.user.id)
        unique_users_count = len(unique_users)
        
        # Calculate coverage percentage (assuming we want to show utilization)
        total_shifts = ShiftMaster.objects.filter(is_active=True).count()
        coverage_percentage = (active_shifts_count / total_shifts * 100) if total_shifts > 0 else 0
        
        context = {
            'target_date': target_date,
            'shift_assignments': shift_assignments,
            'total_assignments': total_assignments,
            'active_shifts_count': active_shifts_count,
            'unique_users_count': unique_users_count,
            'coverage_percentage': coverage_percentage,
        }
        
        return render(request, 'shift/team_assignments.html', context)
        
    except Exception as e:
        logger.error(f"Error loading team assignments: {str(e)}")
        messages.error(request, 'Error loading team assignments.')
        return redirect('shift:dashboard')

@login_required
def utilization_reports_view(request):
    """View utilization reports with filtering"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to view utilization reports.')
        return redirect('shift:dashboard')
    
    try:
        # Get filter parameters
        start_date_str = request.GET.get('start_date')
        end_date_str = request.GET.get('end_date')
        shift_name = request.GET.get('shift_name')  # Changed from shift_type to shift_name
        
        # Set default date range (last 30 days)
        if start_date_str:
            start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        else:
            start_date = timezone.now().date() - timedelta(days=30)
            
        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
        else:
            end_date = timezone.now().date()
        
        report = None
        
        # Generate report if dates are provided
        if start_date and end_date:
            # Create a simple utilization report since ReportingService method may not exist
            shifts_query = ShiftMaster.objects.filter(is_active=True)
            if shift_name:
                shifts_query = shifts_query.filter(name__icontains=shift_name)
            
            shift_details = []
            total_shifts = 0
            utilized_shifts = 0
            
            for shift in shifts_query:
                assignment_count = ShiftAssignment.objects.filter(
                    shift=shift,
                    effective_from__lte=end_date,
                    status__in=['ACTIVE', 'APPROVED']
                ).filter(
                    Q(effective_to__gte=start_date) | Q(effective_to__isnull=True)
                ).count()
                
                utilization_percentage = min(100.0, (assignment_count * 10))  # Simple calculation
                
                shift_details.append({
                    'shift': shift,
                    'assignment_count': assignment_count,
                    'utilization_percentage': utilization_percentage
                })
                
                total_shifts += 1
                if assignment_count > 0:
                    utilized_shifts += 1
            
            utilization_rate = (utilized_shifts / total_shifts * 100) if total_shifts > 0 else 0
            active_users = ShiftAssignment.objects.filter(
                effective_from__lte=end_date,
                status__in=['ACTIVE', 'APPROVED']
            ).filter(
                Q(effective_to__gte=start_date) | Q(effective_to__isnull=True)
            ).values('user').distinct().count()
            
            report = {
                'summary': {
                    'total_shifts': total_shifts,
                    'utilized_shifts': utilized_shifts,
                    'utilization_rate': utilization_rate,
                    'active_users': active_users
                },
                'shift_details': shift_details
            }
        
        # Check if export is requested
        if request.GET.get('export') == 'true' and report:
            # Return CSV export
            import csv
            from django.http import HttpResponse
            
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = f'attachment; filename="utilization_report_{start_date}_{end_date}.csv"'
            
            writer = csv.writer(response)
            writer.writerow(['Shift Name', 'Type', 'Start Time', 'End Time', 'Assignments', 'Utilization %'])
            
            for shift_data in report.get('shift_details', []):
                writer.writerow([
                    shift_data['shift'].name,
                    shift_data['shift'].name,  # Using name instead of get_shift_type_display
                    shift_data['shift'].start_time.strftime('%H:%M'),
                    shift_data['shift'].end_time.strftime('%H:%M'),
                    shift_data['assignment_count'],
                    f"{shift_data['utilization_percentage']:.1f}"
                ])
            
            return response
        
        context = {
            'start_date': start_date,
            'end_date': end_date,
            'shift_name': shift_name,
            'report': report,
        }
        
        return render(request, 'shift/utilization_reports.html', context)
        
    except Exception as e:
        logger.error(f"Error loading utilization reports: {str(e)}")
        messages.error(request, 'Error loading utilization reports.')
        return redirect('shift:dashboard')

@login_required
def shift_edit(request, pk):
    """Edit shift view"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to edit shifts.')
        return redirect('shift:shift_list')
    
    shift = get_object_or_404(ShiftMaster, pk=pk)
    
    if request.method == 'POST':
        try:
            # Update shift data
            shift.name = request.POST['name']
            shift.start_time = request.POST['start_time']
            shift.end_time = request.POST['end_time']
            shift.work_days = request.POST['work_days']
            shift.description = request.POST.get('description', '')
            shift.color_code = request.POST.get('color_code', '#3B82F6')
            shift.requires_approval = 'requires_approval' in request.POST
            shift.is_active = 'is_active' in request.POST
            
            # Parse duration fields
            break_duration_str = request.POST.get('break_duration', '30')
            grace_period_str = request.POST.get('grace_period', '15')
            
            shift.break_duration = timedelta(minutes=int(break_duration_str))
            shift.grace_period = timedelta(minutes=int(grace_period_str))
            
            shift.save()
            
            messages.success(request, f'Shift "{shift.name}" updated successfully.')
            return redirect('shift:shift_detail', pk=shift.pk)
            
        except Exception as e:
            logger.error(f"Error updating shift {pk}: {str(e)}")
            messages.error(request, f'Error updating shift: {str(e)}')
    
    # Convert durations to minutes for form display
    break_duration_minutes = int(shift.break_duration.total_seconds() / 60) if shift.break_duration else 30
    grace_period_minutes = int(shift.grace_period.total_seconds() / 60) if shift.grace_period else 15
    
    context = {
        'shift': shift,
        'work_days_choices': ShiftMaster.WORK_DAYS_CHOICES,
        'break_duration_minutes': break_duration_minutes,
        'grace_period_minutes': grace_period_minutes,
    }
    
    return render(request, 'shift/shift_form.html', context)

@login_required
def shift_delete(request, pk):
    """Delete shift view"""
    if not user_has_permission(request.user, ['Admin', 'Manager']):
        messages.error(request, 'You do not have permission to delete shifts.')
        return redirect('shift:shift_list')
    
    shift = get_object_or_404(ShiftMaster, pk=pk)
    
    if request.method == 'POST':
        try:
            # Check if shift has active assignments
            active_assignments = shift.assignments.filter(status__in=['ACTIVE', 'APPROVED']).count()
            
            if active_assignments > 0:
                messages.error(request, f'Cannot delete shift "{shift.name}" - it has {active_assignments} active assignment(s). Please reassign or end these assignments first.')
                return redirect('shift:shift_detail', pk=shift.pk)
            
            shift_name = shift.name
            shift.delete()
            
            messages.success(request, f'Shift "{shift_name}" deleted successfully.')
            return redirect('shift:shift_list')
            
        except Exception as e:
            logger.error(f"Error deleting shift {pk}: {str(e)}")
            messages.error(request, f'Error deleting shift: {str(e)}')
            return redirect('shift:shift_detail', pk=shift.pk)
    
    return redirect('shift:shift_list')

@login_required
def assignment_end(request, pk):
    """End assignment view"""
    if not user_has_permission(request.user, ['Admin', 'HR', 'Manager']):
        messages.error(request, 'You do not have permission to end assignments.')
        return redirect('shift:assignment_list')
    
    assignment = get_object_or_404(ShiftAssignment, pk=pk)
    
    if request.method == 'POST':
        try:
            end_date_str = request.POST.get('end_date')
            reason = request.POST.get('reason', '')
            
            if end_date_str:
                end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            else:
                end_date = timezone.now().date()
            
            # End the assignment
            assignment.effective_to = end_date
            assignment.is_current = False
            assignment.notes = f"{assignment.notes}\n\nEnded on {end_date}. Reason: {reason}".strip()
            assignment.full_clean()  # This will trigger validation
            assignment.save()
            
            messages.success(request, f'Assignment for {assignment.user.get_full_name()} ended successfully.')
            return redirect('shift:assignment_detail', pk=assignment.pk)
            
        except Exception as e:
            logger.error(f"Error ending assignment {pk}: {str(e)}")
            messages.error(request, f'Error ending assignment: {str(e)}')
    
    return redirect('shift:assignment_detail', pk=assignment.pk)
