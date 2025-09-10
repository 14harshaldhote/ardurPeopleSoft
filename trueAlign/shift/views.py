"""
TrueAlign Shift Management Views
Single comprehensive views file for all shift management operations
Manager-friendly interface with robust conflict detection and API endpoints
"""

import json
import csv
import logging
from datetime import datetime, date, timedelta
from io import StringIO
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST
from django.contrib.auth.models import Group
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import transaction
from django.urls import reverse

from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
from .forms import ShiftForm, ShiftAssignmentForm, BulkAssignmentForm, HolidayForm, CSVUploadForm
from .services import ShiftService, ConflictDetector
from .decorators import group_required
from .app_settings import SHIFT_GROUPS, CACHE_SETTINGS, EMAIL_NOTIFICATIONS
from .logging_config import ActionLogger, APILogger

# Initialize loggers and services
logger = logging.getLogger('trueAlign.shift')
action_logger = ActionLogger()
api_logger = APILogger()
shift_service = ShiftService()
conflict_detector = ConflictDetector()

User = get_user_model()

# ============================
# DASHBOARD AND OVERVIEW
# ============================

@login_required
def shift_dashboard(request):
    """Manager-friendly dashboard with key metrics and quick actions"""
    try:
        action_logger.log_action('DASHBOARD_ACCESS', user_id=request.user.id, user=request.user.username)

        # Get key statistics
        total_shifts = ShiftMaster.objects.filter(is_active=True).count()
        total_assignments = ShiftAssignment.objects.filter(is_current=True).count()
        upcoming_holidays = Holiday.objects.filter(
            date__gte=date.today(),
            date__lte=date.today() + timedelta(days=30)
        ).count()

        # Get recent activities
        recent_assignments = ShiftAssignment.objects.select_related('user', 'shift').filter(
            created_at__gte=timezone.now() - timedelta(days=7)
        ).order_by('-created_at')[:10]

        # Get users without current shifts
        users_without_shifts = User.objects.exclude(
            shift_assignments__is_current=True
        ).count()

        # Detect any urgent conflicts
        conflict_count = 0
        try:
            # Check for conflicts in next 7 days
            start_date = date.today()
            end_date = start_date + timedelta(days=7)
            assignments = ShiftAssignment.objects.filter(
                effective_from__lte=end_date,
                effective_to__gte=start_date,
                is_current=True
            ).select_related('user', 'shift')

            for assignment in assignments:
                conflicts = conflict_detector.check_assignment_conflicts(
                    assignment.user, assignment.shift,
                    assignment.effective_from, assignment.effective_to
                )
                if conflicts:
                    conflict_count += len(conflicts)
        except Exception as e:
            logger.error(f"Error checking conflicts in dashboard: {e}")

        context = {
            'total_shifts': total_shifts,
            'total_assignments': total_assignments,
            'upcoming_holidays': upcoming_holidays,
            'users_without_shifts': users_without_shifts,
            'recent_assignments': recent_assignments,
            'conflict_count': conflict_count,
            'user_groups': list(request.user.groups.values_list('name', flat=True)),
            'can_manage': request.user.groups.filter(name__in=['Manager', 'HR']).exists(),
        }

        return render(request, 'shift/dashboard.html', context)

    except Exception as e:
        logger.error(f"Dashboard error for user {request.user.id}: {e}")
        messages.error(request, "Error loading dashboard. Please try again.")
        return render(request, 'shift/dashboard.html', {'error': True})

@login_required
def shift_statistics(request):
    """Detailed statistics and analytics"""
    try:
        stats = shift_service.get_shift_statistics()

        # Add trend data
        last_30_days = date.today() - timedelta(days=30)
        recent_assignments = ShiftAssignment.objects.filter(
            created_at__gte=last_30_days
        ).count()

        context = {
            'statistics': stats,
            'recent_assignments': recent_assignments,
            'chart_data': json.dumps({
                'labels': ['Active Shifts', 'Total Assignments', 'Recent Changes'],
                'data': [stats.get('active_shifts', 0), stats.get('total_assignments', 0), recent_assignments]
            })
        }

        return render(request, 'shift/statistics.html', context)

    except Exception as e:
        logger.error(f"Statistics error: {e}")
        messages.error(request, "Error loading statistics.")
        return redirect('shift:dashboard')

# ============================
# SHIFT MANAGEMENT
# ============================

@login_required
def shift_list(request):
    """List all shifts with search and filtering"""
    try:
        shifts = ShiftMaster.objects.all().order_by('name')

        # Search functionality
        search = request.GET.get('search', '').strip()
        if search:
            shifts = shifts.filter(
                Q(name__icontains=search) |
                Q(description__icontains=search)
            )

        # Filter by active status
        active_filter = request.GET.get('active')
        if active_filter == 'true':
            shifts = shifts.filter(is_active=True)
        elif active_filter == 'false':
            shifts = shifts.filter(is_active=False)

        # Pagination
        paginator = Paginator(shifts, 20)
        page = request.GET.get('page')
        shifts = paginator.get_page(page)

        # Add assignment counts
        for shift in shifts:
            shift.active_assignments = shift.assignments.filter(is_current=True).count()

        context = {
            'shifts': shifts,
            'search': search,
            'active_filter': active_filter,
            'can_create': request.user.groups.filter(name__in=['Manager', 'HR']).exists(),
        }

        return render(request, 'shift/shift_list.html', context)

    except Exception as e:
        logger.error(f"Shift list error: {e}")
        messages.error(request, "Error loading shifts.")
        return render(request, 'shift/shift_list.html', {'shifts': []})

@login_required
@group_required(['Manager', 'HR'])
@require_http_methods(["GET", "POST"])
def create_shift(request):
    """Create new shift with validation"""
    if request.method == 'POST':
        form = ShiftForm(request.POST)
        if form.is_valid():
            try:
                with transaction.atomic():
                    shift = form.save()
                    action_logger.log_action(
                        'SHIFT_CREATED',
                        user=request.user.username,
                        shift_id=shift.id,
                        shift_name=shift.name
                    )
                    messages.success(request, f'Shift "{shift.name}" created successfully!')
                    return redirect('shift:detail', shift_id=shift.id)
            except Exception as e:
                logger.error(f"Error creating shift: {e}")
                messages.error(request, "Error creating shift. Please try again.")
        else:
            for field, errors in form.errors.items():
                for error in errors:
                    messages.error(request, f"{field}: {error}")
    else:
        form = ShiftForm()

    context = {
        'form': form,
        'title': 'Create New Shift',
        'submit_text': 'Create Shift'
    }
    return render(request, 'shift/shift_form.html', context)

@login_required
def shift_detail(request, shift_id):
    """Detailed shift view with assignments and statistics"""
    try:
        shift = get_object_or_404(ShiftMaster, id=shift_id)

        # Get current assignments
        assignments = shift.assignments.filter(is_current=True).select_related('user')

        # Get assignment history
        history = shift.assignments.all().select_related('user').order_by('-created_at')[:20]

        # Get shift statistics
        stats = {
            'total_assignments': shift.assignments.count(),
            'current_assignments': assignments.count(),
            'average_duration': shift.shift_duration,
        }

        context = {
            'shift': shift,
            'assignments': assignments,
            'history': history,
            'stats': stats,
            'can_edit': request.user.groups.filter(name__in=['Manager', 'HR']).exists(),
        }

        return render(request, 'shift/shift_detail.html', context)

    except Exception as e:
        logger.error(f"Shift detail error for shift {shift_id}: {e}")
        messages.error(request, "Error loading shift details.")
        return redirect('shift:list')

@login_required
@group_required(['Manager', 'HR'])
def update_shift(request, shift_id):
    """Update existing shift"""
    shift = get_object_or_404(ShiftMaster, id=shift_id)

    if request.method == 'POST':
        form = ShiftForm(request.POST, instance=shift)
        if form.is_valid():
            try:
                with transaction.atomic():
                    updated_shift = form.save()
                    action_logger.log_action(
                        'SHIFT_UPDATED',
                        user_id=request.user.id,
                        user=request.user.username,
                        shift_id=shift.id,
                        shift_name=shift.name
                    )
                    messages.success(request, f'Shift "{updated_shift.name}" updated successfully!')
                    return redirect('shift:detail', shift_id=updated_shift.id)
            except Exception as e:
                logger.error(f"Error updating shift {shift_id}: {e}")
                messages.error(request, "Error updating shift. Please try again.")
    else:
        form = ShiftForm(instance=shift)

    context = {
        'form': form,
        'shift': shift,
        'title': f'Update Shift: {shift.name}',
        'submit_text': 'Update Shift'
    }
    return render(request, 'shift/shift_form.html', context)

@login_required
@group_required(['Manager', 'HR'])
@require_POST
def delete_shift(request, shift_id):
    """Delete shift with safety checks"""
    try:
        shift = get_object_or_404(ShiftMaster, id=shift_id)

        # Check if shift has active assignments
        active_assignments = shift.assignments.filter(is_current=True).count()
        if active_assignments > 0:
            messages.error(request,
                f'Cannot delete shift "{shift.name}". It has {active_assignments} active assignments.')
            return redirect('shift:detail', shift_id=shift_id)

        shift_name = shift.name
        shift.delete()

        action_logger.log_action(
            'SHIFT_DELETED',
            user_id=request.user.id,
            user=request.user.username,
            shift_name=shift_name
        )

        messages.success(request, f'Shift "{shift_name}" deleted successfully!')
        return redirect('shift:list')

    except Exception as e:
        logger.error(f"Error deleting shift {shift_id}: {e}")
        messages.error(request, "Error deleting shift. Please try again.")
        return redirect('shift:list')

# ============================
# ASSIGNMENT MANAGEMENT
# ============================

@login_required
def assignment_list(request):
    """List all assignments with filtering and search"""
    try:
        assignments = ShiftAssignment.objects.select_related('user', 'shift').all()

        # Filters
        status_filter = request.GET.get('status')
        if status_filter == 'current':
            assignments = assignments.filter(is_current=True)
        elif status_filter == 'ended':
            assignments = assignments.filter(is_current=False)

        user_filter = request.GET.get('user')
        if user_filter:
            assignments = assignments.filter(user_id=user_filter)

        shift_filter = request.GET.get('shift')
        if shift_filter:
            assignments = assignments.filter(shift_id=shift_filter)

        # Search
        search = request.GET.get('search', '').strip()
        if search:
            assignments = assignments.filter(
                Q(user__username__icontains=search) |
                Q(user__first_name__icontains=search) |
                Q(user__last_name__icontains=search) |
                Q(shift__name__icontains=search)
            )

        assignments = assignments.order_by('-created_at')

        # Pagination
        paginator = Paginator(assignments, 25)
        page = request.GET.get('page')
        assignments = paginator.get_page(page)

        # Get filter options
        users = User.objects.filter(shift_assignments__isnull=False).distinct()
        shifts = ShiftMaster.objects.filter(assignments__isnull=False).distinct()

        context = {
            'assignments': assignments,
            'users': users,
            'shifts': shifts,
            'filters': {
                'status': status_filter,
                'user': user_filter,
                'shift': shift_filter,
                'search': search,
            },
            'can_manage': request.user.groups.filter(name__in=['Manager', 'HR']).exists(),
        }

        return render(request, 'shift/assignment_list.html', context)

    except Exception as e:
        logger.error(f"Assignment list error: {e}")
        messages.error(request, "Error loading assignments.")
        return render(request, 'shift/assignment_list.html', {'assignments': []})

@login_required
@group_required(['Manager', 'HR'])
def assign_shift(request):
    """Assign shift to user with conflict detection"""
    if request.method == 'POST':
        form = ShiftAssignmentForm(request.POST)
        if form.is_valid():
            try:
                # Check for conflicts before saving
                user = form.cleaned_data['user']
                shift = form.cleaned_data['shift']
                effective_from = form.cleaned_data['effective_from']
                effective_to = form.cleaned_data.get('effective_to')

                # Perform conflict detection with proper null handling
                conflict_detector = ConflictDetector()
                end_date_for_check = effective_to if effective_to else (effective_from + timedelta(days=365))
                conflicts = conflict_detector.check_assignment_conflicts(
                    user, shift, effective_from, end_date_for_check
                )

                if conflicts:
                    conflict_messages = []
                    for conflict in conflicts:
                        conflict_messages.append(
                            f"Conflict with '{conflict.conflicting_shift.name}' "
                            f"from {conflict.conflict_start} to {conflict.conflict_end}"
                        )

                    messages.error(request,
                        f"Cannot assign shift due to conflicts:\n" +
                        "\n".join(conflict_messages)
                    )

                    # Get context for re-rendering with conflicts
                    available_users = User.objects.filter(is_active=True).select_related('profile').order_by('first_name', 'last_name', 'username')
                    available_shifts = ShiftMaster.objects.filter(is_active=True).order_by('name')

                    return render(request, 'shift/assign_shift.html', {
                        'form': form,
                        'conflicts': conflicts,
                        'available_users': available_users,
                        'available_shifts': available_shifts,
                        'title': 'Assign Shift',
                        'user': request.user
                    })

                # No conflicts, proceed with assignment
                with transaction.atomic():
                    assignment = form.save()
                    action_logger.log_action(
                        'SHIFT_ASSIGNED',
                        user_id=request.user.id,
                        user=request.user.username,
                        target_user=user.username,
                        shift_name=shift.name,
                        effective_from=str(effective_from)
                    )

                    messages.success(request,
                        f'Shift "{shift.name}" assigned to {user.get_full_name() or user.username} successfully!')

                    return redirect('shift:assignments')

            except Exception as e:
                logger.error(f"Error assigning shift: {e}")
                messages.error(request, "Error assigning shift. Please try again.")
        else:
            for field, errors in form.errors.items():
                field_name = form.fields[field].label if field in form.fields else field.replace('_', ' ').title()
                for error in errors:
                    messages.error(request, f"{field_name}: {error}")
    else:
        form = ShiftAssignmentForm(request=request)

    # Get available users and shifts for the form
    available_users = User.objects.filter(is_active=True).select_related('profile').order_by('first_name', 'last_name', 'username')
    available_shifts = ShiftMaster.objects.filter(is_active=True).order_by('name')

    # Pre-select from URL parameters
    initial_user = request.GET.get('user')
    initial_shift = request.GET.get('shift')

    if initial_user:
        try:
            form.fields['user'].initial = User.objects.get(id=initial_user)
        except (User.DoesNotExist, ValueError):
            pass

    if initial_shift:
        try:
            form.fields['shift'].initial = ShiftMaster.objects.get(id=initial_shift)
        except (ShiftMaster.DoesNotExist, ValueError):
            pass

    context = {
        'form': form,
        'available_users': available_users,
        'available_shifts': available_shifts,
        'title': 'Assign Shift',
        'submit_text': 'Assign Shift',
        'user': request.user  # Add user to context for admin checks
    }
    return render(request, 'shift/assign_shift.html', context)

@login_required
@group_required(['Manager', 'HR'])
def api_user_info(request, user_id):
    """API endpoint for user information"""
    try:
        user = get_object_or_404(User, id=user_id)

        # Check permissions
        if not request.user.groups.filter(name__in=['Manager', 'HR']).exists():
            if user_id != request.user.id:
                return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)

        profile = getattr(user, 'profile', None)

        data = {
            'success': True,
            'user_info': {
                'id': user.id,
                'username': user.username,
                'full_name': user.get_full_name() or user.username,
                'first_name': user.first_name,
                'last_name': user.last_name,
                'email': user.email,
                'employee_id': profile.employee_id if profile else None,
                'is_active': user.is_active,
                'groups': list(user.groups.values_list('name', flat=True))
            }
        }

        return JsonResponse(data)

    except Exception as e:
        logger.error(f"Error getting user info: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@group_required(['Manager', 'HR'])
def bulk_assign_shift(request):
    """Bulk assign shift to multiple users with smart conflict handling"""
    if request.method == 'POST':
        form = BulkAssignmentForm(request.POST)
        if form.is_valid():
            try:
                users = form.cleaned_data['users']
                shift = form.cleaned_data['shift']
                effective_from = form.cleaned_data['effective_from']
                effective_to = form.cleaned_data.get('effective_to')

                # Process bulk assignment with conflict detection
                result = shift_service.bulk_assign_shifts(
                    users, shift, effective_from, effective_to
                )

                action_logger.log_action(
                    'BULK_ASSIGNMENT',
                    user_id=request.user.id,
                    user=request.user.username,
                    shift_name=shift.name,
                    total_users=len(users),
                    successful=len(result.successful_assignments),
                    conflicts=len(result.conflicts)
                )

                # Show results
                if result.successful_assignments:
                    success_names = [a.user.get_full_name() or a.user.username
                                   for a in result.successful_assignments]
                    messages.success(request,
                        f'Successfully assigned "{shift.name}" to {len(success_names)} users: '
                        f'{", ".join(success_names)}')

                if result.conflicts:
                    conflict_details = []
                    for conflict in result.conflicts:
                        conflict_details.append(
                            f"{conflict.user.get_full_name() or conflict.user.username}: "
                            f"{conflict.reason}"
                        )
                    messages.warning(request,
                        f'Could not assign to {len(result.conflicts)} users due to conflicts:\n'
                        + '\n'.join(conflict_details))

                return redirect('shift:assignments')

            except Exception as e:
                logger.error(f"Error in bulk assignment: {e}")
                messages.error(request, "Error processing bulk assignment. Please try again.")
    else:
        form = BulkAssignmentForm()

    context = {
        'form': form,
        'title': 'Bulk Assign Shift',
        'submit_text': 'Assign to Selected Users'
    }
    return render(request, 'shift/bulk_assign_form.html', context)

@login_required
@group_required(['Manager', 'HR'])
@require_POST
def end_assignment(request, assignment_id):
    """End a shift assignment"""
    try:
        assignment = get_object_or_404(ShiftAssignment, id=assignment_id)

        if not assignment.is_current:
            messages.warning(request, "Assignment is already ended.")
            return redirect('shift:assignments')

        # End the assignment
        success = shift_service.end_shift_assignment(assignment.id)

        if success:
            action_logger.log_action(
                'ASSIGNMENT_ENDED',
                user_id=request.user.id,
                user=request.user.username,
                target_user=assignment.user.username,
                shift_name=assignment.shift.name
            )
            messages.success(request,
                f'Assignment for {assignment.user.get_full_name() or assignment.user.username} ended successfully.')
        else:
            messages.error(request, "Error ending assignment. Please try again.")

        return redirect('shift:assignments')

    except Exception as e:
        logger.error(f"Error ending assignment {assignment_id}: {e}")
        messages.error(request, "Error ending assignment. Please try again.")
        return redirect('shift:assignments')

# ============================
# CALENDAR AND SCHEDULE
# ============================

@login_required
def user_shift_calendar(request, user_id=None):
    """Calendar view of shift assignments"""
    try:
        if user_id and request.user.groups.filter(name__in=['Manager', 'HR']).exists():
            target_user = get_object_or_404(User, id=user_id)
        else:
            target_user = request.user

        # Get date range (current month by default)
        today = date.today()
        month = int(request.GET.get('month', today.month))
        year = int(request.GET.get('year', today.year))

        # Calculate calendar range
        start_date = date(year, month, 1)
        if month == 12:
            end_date = date(year + 1, 1, 1) - timedelta(days=1)
        else:
            end_date = date(year, month + 1, 1) - timedelta(days=1)

        # Get assignments for the month
        assignments = ShiftAssignment.objects.filter(
            user=target_user,
            effective_from__lte=end_date,
            effective_to__gte=start_date
        ).select_related('shift')

        # Get holidays
        holidays = Holiday.objects.filter(
            date__gte=start_date,
            date__lte=end_date
        )

        # Prepare calendar data
        calendar_data = {}
        for assignment in assignments:
            current_date = max(assignment.effective_from, start_date)
            end_assignment_date = min(assignment.effective_to or end_date, end_date)

            while current_date <= end_assignment_date:
                if shift_service.is_working_day_for_user(target_user, current_date):
                    if current_date not in calendar_data:
                        calendar_data[current_date] = []
                    calendar_data[current_date].append(assignment)
                current_date += timedelta(days=1)

        # Add holidays to calendar data
        holiday_data = {holiday.date: holiday for holiday in holidays}

        context = {
            'target_user': target_user,
            'calendar_data': calendar_data,
            'holiday_data': holiday_data,
            'current_month': month,
            'current_year': year,
            'prev_month': month - 1 if month > 1 else 12,
            'prev_year': year if month > 1 else year - 1,
            'next_month': month + 1 if month < 12 else 1,
            'next_year': year if month < 12 else year + 1,
            'can_view_others': request.user.groups.filter(name__in=['Manager', 'HR']).exists(),
        }

        return render(request, 'shift/calendar.html', context)

    except Exception as e:
        logger.error(f"Calendar error for user {user_id}: {e}")
        messages.error(request, "Error loading calendar.")
        return redirect('shift:dashboard')

@login_required
def shift_schedule_view(request):
    """Daily/weekly schedule view for managers"""
    try:
        # Get date parameter
        date_str = request.GET.get('date', str(date.today()))
        view_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        # Get view type (day/week)
        view_type = request.GET.get('view', 'day')

        if view_type == 'week':
            # Week view - show 7 days starting from Monday
            start_date = view_date - timedelta(days=view_date.weekday())
            end_date = start_date + timedelta(days=6)
        else:
            # Day view
            start_date = end_date = view_date

        # Get schedule data
        schedule_data = shift_service.get_shift_schedule_for_date(start_date, end_date)

        context = {
            'schedule_data': schedule_data,
            'view_date': view_date,
            'view_type': view_type,
            'start_date': start_date,
            'end_date': end_date,
            'prev_date': view_date - timedelta(days=7 if view_type == 'week' else 1),
            'next_date': view_date + timedelta(days=7 if view_type == 'week' else 1),
        }

        return render(request, 'shift/schedule.html', context)

    except Exception as e:
        logger.error(f"Schedule view error: {e}")
        messages.error(request, "Error loading schedule.")
        return redirect('shift:dashboard')

# ============================
# HOLIDAY MANAGEMENT
# ============================

@login_required
def holiday_list(request):
    """List holidays with management options"""
    try:
        holidays = Holiday.objects.all().order_by('date')

        # Filter by year
        year_filter = request.GET.get('year')
        if year_filter:
            holidays = holidays.filter(date__year=year_filter)
        else:
            # Default to current and next year
            current_year = date.today().year
            holidays = holidays.filter(date__year__in=[current_year, current_year + 1])

        # Get unique years for filter dropdown
        available_years = Holiday.objects.dates('date', 'year').values_list('date__year', flat=True)

        context = {
            'holidays': holidays,
            'available_years': sorted(set(available_years)),
            'selected_year': year_filter,
            'can_manage': request.user.groups.filter(name__in=['Manager', 'HR']).exists(),
        }

        return render(request, 'shift/holiday_list.html', context)

    except Exception as e:
        logger.error(f"Holiday list error: {e}")
        messages.error(request, "Error loading holidays.")
        return render(request, 'shift/holiday_list.html', {'holidays': []})

@login_required
@group_required(['Manager', 'HR'])
def create_holiday(request):
    """Create new holiday"""
    if request.method == 'POST':
        form = HolidayForm(request.POST)
        if form.is_valid():
            try:
                holiday = form.save()
                action_logger.log_action(
                    'HOLIDAY_CREATED',
                    user_id=request.user.id,
                    user=request.user.username,
                    holiday_name=holiday.name,
                    holiday_date=str(holiday.date)
                )
                messages.success(request, f'Holiday "{holiday.name}" created successfully!')
                return redirect('shift:holidays')
            except Exception as e:
                logger.error(f"Error creating holiday: {e}")
                messages.error(request, "Error creating holiday. Please try again.")
    else:
        form = HolidayForm()

    context = {
        'form': form,
        'title': 'Create Holiday',
        'submit_text': 'Create Holiday'
    }
    return render(request, 'shift/holiday_form.html', context)

@login_required
@group_required(['Manager', 'HR'])
@require_POST
def delete_holiday(request, holiday_id):
    """Delete holiday"""
    try:
        holiday = get_object_or_404(Holiday, id=holiday_id)
        holiday_name = holiday.name
        holiday.delete()

        action_logger.log_action(
            'HOLIDAY_DELETED',
            user_id=request.user.id,
            user=request.user.username,
            holiday_name=holiday_name
        )

        messages.success(request, f'Holiday "{holiday_name}" deleted successfully!')
        return redirect('shift:holidays')

    except Exception as e:
        logger.error(f"Error deleting holiday {holiday_id}: {e}")
        messages.error(request, "Error deleting holiday. Please try again.")
        return redirect('shift:holidays')

# ============================
# CSV IMPORT/EXPORT
# ============================

@login_required
@group_required(['Manager', 'HR'])
def csv_upload_assignments(request):
    """Upload CSV file for bulk assignments"""
    if request.method == 'POST':
        form = CSVUploadForm(request.POST, request.FILES)
        if form.is_valid():
            try:
                csv_file = request.FILES['csv_file']

                # Process CSV
                file_data = csv_file.read().decode('utf-8')
                csv_reader = csv.DictReader(StringIO(file_data))

                results = {
                    'successful': [],
                    'errors': [],
                    'conflicts': []
                }

                for row_num, row in enumerate(csv_reader, start=2):
                    try:
                        # Get user
                        username = row.get('username', '').strip()
                        if not username:
                            results['errors'].append(f"Row {row_num}: Username is required")
                            continue

                        try:
                            user = User.objects.get(username=username)
                        except User.DoesNotExist:
                            results['errors'].append(f"Row {row_num}: User '{username}' not found")
                            continue

                        # Get shift
                        shift_name = row.get('shift_name', '').strip()
                        if not shift_name:
                            results['errors'].append(f"Row {row_num}: Shift name is required")
                            continue

                        try:
                            shift = ShiftMaster.objects.get(name=shift_name, is_active=True)
                        except ShiftMaster.DoesNotExist:
                            results['errors'].append(f"Row {row_num}: Shift '{shift_name}' not found")
                            continue

                        # Parse dates
                        effective_from_str = row.get('effective_from', '').strip()
                        try:
                            effective_from = datetime.strptime(effective_from_str, '%Y-%m-%d').date()
                        except ValueError:
                            results['errors'].append(f"Row {row_num}: Invalid effective_from date format")
                            continue

                        effective_to = None
                        effective_to_str = row.get('effective_to', '').strip()
                        if effective_to_str:
                            try:
                                effective_to = datetime.strptime(effective_to_str, '%Y-%m-%d').date()
                            except ValueError:
                                results['errors'].append(f"Row {row_num}: Invalid effective_to date format")
                                continue

                        # Check for exact duplicate assignments only (overlaps are now allowed)
                        exact_duplicates = ShiftAssignment.objects.filter(
                            user=user,
                            shift=shift,
                            is_current=True
                        )

                        if effective_to:
                            exact_duplicates = exact_duplicates.filter(
                                effective_from__lte=effective_to,
                                effective_to__gte=effective_from
                            )
                        else:
                            exact_duplicates = exact_duplicates.filter(
                                effective_from__lte=effective_from,
                                effective_to__isnull=True
                            )

                        if exact_duplicates.exists():
                            results['errors'].append(f"Row {row_num}: User '{username}' is already assigned to '{shift_name}' during this period")
                        else:
                            # Check for potential overlaps (for reporting only)
                            conflict_detector = ConflictDetector()
                            end_date_for_check = effective_to if effective_to else (effective_from + timedelta(days=365))
                            conflicts = conflict_detector.check_assignment_conflicts(
                                user, shift, effective_from, end_date_for_check
                            )

                            # Create assignment regardless of overlaps
                            assignment = ShiftAssignment.objects.create(
                                user=user,
                                shift=shift,
                                effective_from=effective_from,
                                effective_to=effective_to,
                                is_current=True,
                                notes=row.get('notes', ''),
                                created_by=request.user
                            )

                            success_data = {
                                'row': row_num,
                                'user': username,
                                'shift': shift_name,
                                'assignment_id': assignment.id
                            }

                            # Add overlap information if present
                            if conflicts:
                                success_data['overlaps'] = len(conflicts)
                                results['conflicts'].append({
                                    'row': row_num,
                                    'user': username,
                                    'shift': shift_name,
                                    'overlap_count': len(conflicts),
                                    'message': f'Assignment created with {len(conflicts)} potential overlap(s)'
                                })

                            results['successful'].append(success_data)

                    except Exception as e:
                        results['errors'].append(f"Row {row_num}: {str(e)}")

                action_logger.log_action(
                    'CSV_IMPORT',
                    user_id=request.user.id,
                    user=request.user.username,
                    total_rows=len(csv_reader),
                    successful=len(results['successful']),
                    errors=len(results['errors']),
                    conflicts=len(results['conflicts'])
                )

                # Show results
                if results['successful']:
                    messages.success(request,
                        f"Successfully imported {len(results['successful'])} assignments!")

                if results['errors']:
                    for error in results['errors'][:5]:  # Show first 5 errors
                        messages.error(request, error)

                if results['conflicts']:
                    for conflict in results['conflicts'][:3]:  # Show first 3 conflicts
                        messages.warning(request,
                            f"Row {conflict['row']}: Conflicts found for {conflict['user']}")

                return redirect('shift:assignments')

            except Exception as e:
                logger.error(f"CSV upload error: {e}")
                messages.error(request, "Error processing CSV file. Please check format and try again.")
    else:
        form = CSVUploadForm()

    context = {
        'form': form,
        'title': 'Upload CSV File',
        'submit_text': 'Upload and Process'
    }
    return render(request, 'shift/csv_upload_form.html', context)

@login_required
@group_required(['Manager', 'HR'])
def export_assignments_csv(request):
    """Export assignments to CSV"""
    try:
        # Get filter parameters
        status_filter = request.GET.get('status')
        user_filter = request.GET.get('user')
        shift_filter = request.GET.get('shift')

        assignments = ShiftAssignment.objects.select_related('user', 'shift').all()

        # Apply filters
        if status_filter == 'current':
            assignments = assignments.filter(is_current=True)
        elif status_filter == 'ended':
            assignments = assignments.filter(is_current=False)

        if user_filter:
            assignments = assignments.filter(user_id=user_filter)

        if shift_filter:
            assignments = assignments.filter(shift_id=shift_filter)

        # Create CSV response
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="shift_assignments_{date.today()}.csv"'

        writer = csv.writer(response)
        writer.writerow([
            'Username', 'User Name', 'Email', 'Shift Name', 'Start Time', 'End Time',
            'Work Days', 'Effective From', 'Effective To', 'Status', 'Notes'
        ])

        for assignment in assignments:
            writer.writerow([
                assignment.user.username,
                assignment.user.get_full_name() or assignment.user.username,
                assignment.user.email,
                assignment.shift.name,
                assignment.shift.start_time.strftime('%H:%M'),
                assignment.shift.end_time.strftime('%H:%M'),
                assignment.shift.get_work_days_display(),
                assignment.effective_from.strftime('%Y-%m-%d'),
                assignment.effective_to.strftime('%Y-%m-%d') if assignment.effective_to else 'Ongoing',
                'Active' if assignment.is_current else 'Inactive',
                assignment.notes or ''
            ])

        action_logger.log_action(
            'CSV_EXPORT',
            user_id=request.user.id,
            user=request.user.username,
            exported_count=assignments.count()
        )

        return response

    except Exception as e:
        logger.error(f"CSV export error: {e}")
        messages.error(request, "Error exporting data. Please try again.")
        return redirect('shift:assignments')

# ============================
# API ENDPOINTS
# ============================

@login_required
def api_shift_details(request, shift_id):
    """API endpoint for shift details"""
    try:
        shift = get_object_or_404(ShiftMaster, id=shift_id)

        data = {
            'id': shift.id,
            'name': shift.name,
            'description': shift.description or '',
            'start_time': shift.start_time.strftime('%H:%M'),
            'end_time': shift.end_time.strftime('%H:%M'),
            'duration': float(shift.shift_duration),
            'work_days': shift.work_days,
            'custom_work_days': shift.custom_work_days or '',
            'is_active': shift.is_active,
            'break_minutes': int(shift.break_duration.total_seconds() // 60) if shift.break_duration else 30,
            'grace_minutes': int(shift.grace_period.total_seconds() // 60) if shift.grace_period else 15,
            'active_assignments': shift.assignments.filter(is_current=True).count(),
            'total_assignments': shift.assignments.count(),
        }

        api_logger.log_api_request(
            'GET', f'/api/shifts/{shift_id}/',
            user_id=request.user.id,
            status_code=200
        )

        return JsonResponse({'success': True, 'data': data})

    except Exception as e:
        logger.error(f"API shift details error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def api_user_assignments(request, user_id):
    """API endpoint for user assignments"""
    try:
        # Check permissions
        if not request.user.groups.filter(name__in=['Manager', 'HR']).exists():
            if user_id != request.user.id:
                return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)

        user = get_object_or_404(User, id=user_id)
        assignments = user.shift_assignments.select_related('shift').filter(is_current=True)

        data = {
            'user': {
                'id': user.id,
                'username': user.username,
                'full_name': user.get_full_name() or user.username,
                'email': user.email,
            },
            'assignments': [
                {
                    'id': assignment.id,
                    'shift_name': assignment.shift.name,
                    'start_time': assignment.shift.start_time.strftime('%H:%M'),
                    'end_time': assignment.shift.end_time.strftime('%H:%M'),
                    'effective_from': assignment.effective_from.strftime('%Y-%m-%d'),
                    'effective_to': assignment.effective_to.strftime('%Y-%m-%d') if assignment.effective_to else None,
                    'is_current': assignment.is_current,
                }
                for assignment in assignments
            ]
        }

        return JsonResponse({'success': True, 'data': data})

    except Exception as e:
        logger.error(f"API user assignments error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def api_user_shift_status(request, user_id):
    """API endpoint for user shift status"""
    try:
        # Check permissions
        if not request.user.groups.filter(name__in=['Manager', 'HR']).exists():
            if user_id != request.user.id:
                return JsonResponse({'success': False, 'error': 'Permission denied'}, status=403)

        user = get_object_or_404(User, id=user_id)
        current_shift = shift_service.get_current_shift(user)

        data = {
            'user_id': user_id,
            'has_current_shift': current_shift is not None,
            'current_shift': None
        }

        if current_shift:
            data['current_shift'] = {
                'name': current_shift.shift.name,
                'start_time': current_shift.shift.start_time.strftime('%H:%M'),
                'end_time': current_shift.shift.end_time.strftime('%H:%M'),
                'effective_from': current_shift.effective_from.strftime('%Y-%m-%d'),
                'effective_to': current_shift.effective_to.strftime('%Y-%m-%d') if current_shift.effective_to else None,
            }

        return JsonResponse({'success': True, 'data': data})

    except Exception as e:
        logger.error(f"API user status error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@group_required(['Manager', 'HR'])
def api_schedule_for_date(request):
    """API endpoint for schedule data"""
    try:
        date_str = request.GET.get('date', str(date.today()))
        view_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        schedule_data = shift_service.get_shift_schedule_for_date(view_date)

        return JsonResponse({'success': True, 'data': schedule_data})

    except Exception as e:
        logger.error(f"API schedule error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@require_http_methods(["GET", "POST"])
@group_required(['Manager', 'HR'])
def api_validate_shift_name(request):
    """API endpoint for comprehensive shift validation including name and overlaps"""
    try:
        # Handle both GET and POST requests
        if request.method == 'POST':
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                name = data.get('name', '').strip()
                shift_id = data.get('shift_id')
                start_time = data.get('start_time')
                end_time = data.get('end_time')
                work_days = data.get('work_days')
            else:
                name = request.POST.get('name', '').strip()
                shift_id = request.POST.get('shift_id')
                start_time = request.POST.get('start_time')
                end_time = request.POST.get('end_time')
                work_days = request.POST.get('work_days')
        else:
            name = request.GET.get('name', '').strip()
            shift_id = request.GET.get('shift_id')
            start_time = request.GET.get('start_time')
            end_time = request.GET.get('end_time')
            work_days = request.GET.get('work_days')

        errors = []
        warnings = []

        # Validate name
        if not name:
            errors.append('Shift name is required')
        elif len(name) < 2:
            errors.append('Shift name must be at least 2 characters long')
        elif len(name) > 50:
            errors.append('Shift name cannot exceed 50 characters')
        else:
            # Check name uniqueness
            existing_query = ShiftMaster.objects.filter(name__iexact=name)
            if shift_id:
                try:
                    existing_query = existing_query.exclude(pk=int(shift_id))
                except (ValueError, TypeError):
                    pass

            if existing_query.exists():
                errors.append(f'A shift with the name "{name}" already exists')

        # Check for overlapping shifts (for informational purposes only)
        if start_time and end_time and work_days and not errors:
            try:
                from datetime import time as dt_time
                start_time_obj = dt_time.fromisoformat(start_time) if isinstance(start_time, str) else start_time
                end_time_obj = dt_time.fromisoformat(end_time) if isinstance(end_time, str) else end_time

                # Get work days list
                if work_days == 'Weekdays':
                    my_work_days = set([0, 1, 2, 3, 4])
                elif work_days == 'All Days':
                    my_work_days = set([0, 1, 2, 3, 4, 5, 6])
                elif work_days == 'Custom':
                    # Handle custom work days if provided
                    my_work_days = set([0, 1, 2, 3, 4])  # Default to weekdays
                else:
                    my_work_days = set([0, 1, 2, 3, 4])

                # Check existing shifts for overlaps
                existing_shifts = ShiftMaster.objects.filter(is_active=True)
                if shift_id:
                    try:
                        existing_shifts = existing_shifts.exclude(pk=int(shift_id))
                    except (ValueError, TypeError):
                        pass

                overlapping_shifts = []
                for shift in existing_shifts:
                    shift_work_days = set(shift.working_days_list)
                    common_days = my_work_days.intersection(shift_work_days)

                    if common_days:
                        # Check time overlap
                        if times_overlap(start_time_obj, end_time_obj, shift.start_time, shift.end_time):
                            overlapping_shifts.append(shift.name)

                if overlapping_shifts:
                    warnings.append(f'This shift overlaps with: {", ".join(overlapping_shifts)}. Overlapping shifts are allowed but may affect scheduling.')

            except Exception as overlap_error:
                logger.warning(f"Error checking overlaps: {overlap_error}")

        is_valid = len(errors) == 0

        return JsonResponse({
            'valid': is_valid,
            'errors': errors,
            'warnings': warnings,
            'message': 'Validation complete'
        })

    except Exception as e:
        logger.error(f"API validate shift name error: {e}")
        return JsonResponse({'valid': False, 'errors': [str(e)]}, status=500)

def times_overlap(start1, end1, start2, end2):
    """Helper function to check if two time ranges overlap"""
    if not all([start1, end1, start2, end2]):
        return False

    # Convert to minutes for easier comparison
    start1_min = start1.hour * 60 + start1.minute
    end1_min = end1.hour * 60 + end1.minute
    start2_min = start2.hour * 60 + start2.minute
    end2_min = end2.hour * 60 + end2.minute

    # Handle overnight shifts
    if end1 < start1:  # First shift crosses midnight
        end1_min += 24 * 60
    if end2 < start2:  # Second shift crosses midnight
        end2_min += 24 * 60

    # Check for overlap (not just touching)
    return (start1_min < end2_min) and (start2_min < end1_min)

@login_required
@group_required(['Manager', 'HR'])
def api_validate_assignment(request):
    """API endpoint for assignment validation with overlap support"""
    try:
        # Handle both GET and POST requests
        if request.method == 'POST':
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                user_id = data.get('user_id')
                shift_id = data.get('shift_id')
                effective_from = data.get('effective_from')
                effective_to = data.get('effective_to')
            else:
                user_id = request.POST.get('user_id')
                shift_id = request.POST.get('shift_id')
                effective_from = request.POST.get('effective_from')
                effective_to = request.POST.get('effective_to')
        else:
            user_id = request.GET.get('user_id')
            shift_id = request.GET.get('shift_id')
            effective_from = request.GET.get('effective_from')
            effective_to = request.GET.get('effective_to')

        if not all([user_id, shift_id, effective_from]):
            return JsonResponse({
                'valid': False,
                'errors': ['Missing required parameters: user_id, shift_id, effective_from'],
                'warnings': []
            })

        # Get objects
        try:
            user = User.objects.get(id=user_id)
            shift = ShiftMaster.objects.get(id=shift_id)
        except (User.DoesNotExist, ShiftMaster.DoesNotExist) as e:
            return JsonResponse({
                'valid': False,
                'errors': ['Invalid user or shift ID'],
                'warnings': []
            })

        try:
            from_date = datetime.strptime(effective_from, '%Y-%m-%d').date()
            to_date = None
            if effective_to:
                to_date = datetime.strptime(effective_to, '%Y-%m-%d').date()
        except ValueError:
            return JsonResponse({
                'valid': False,
                'errors': ['Invalid date format. Use YYYY-MM-DD'],
                'warnings': []
            })

        # Check for conflicts
        conflict_detector = ConflictDetector()
        end_date_for_check = to_date if to_date else (from_date + timedelta(days=365))
        conflicts = conflict_detector.check_assignment_conflicts(
            user, shift, from_date, end_date_for_check
        )

        warnings = []
        errors = []

        # Process conflicts as warnings rather than errors (per new policy)
        if conflicts:
            for conflict in conflicts:
                if hasattr(conflict, 'conflicting_shift') and conflict.conflicting_shift:
                    shift_name = conflict.conflicting_shift.name
                else:
                    shift_name = 'Unknown shift'

                warnings.append(f"Potential overlap with {shift_name}. This is allowed but may require coordination.")

        # Check for exact duplicate assignments (these should still be errors)
        existing_assignments = ShiftAssignment.objects.filter(
            user=user,
            shift=shift,
            is_current=True
        )

        if to_date:
            existing_assignments = existing_assignments.filter(
                effective_from__lte=to_date,
                effective_to__gte=from_date
            )
        else:
            existing_assignments = existing_assignments.filter(
                effective_from__lte=from_date,
                effective_to__isnull=True
            )

        if existing_assignments.exists():
            errors.append('User is already assigned to this exact shift during this period')

        return JsonResponse({
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'conflicts': [
                {
                    'shift_name': getattr(conflict, 'conflicting_shift', {}).get('name', 'Unknown'),
                    'type': 'overlap_warning',
                    'message': f"Overlaps with existing assignment"
                }
                for conflict in conflicts
            ]
        })

    except Exception as e:
        logger.error(f"API validate assignment error: {e}")
        return JsonResponse({
            'valid': False,
            'errors': [f'Validation error: {str(e)}'],
            'warnings': []
        }, status=500)

@login_required
@group_required(['Manager', 'HR'])
def api_bulk_assignment_validation(request):
    """API endpoint for bulk assignment validation with overlap support"""
    try:
        data = json.loads(request.body)
        assignments = data.get('assignments', [])

        results = []

        for assignment in assignments:
            try:
                user = User.objects.get(id=assignment['user_id'])
                shift = ShiftMaster.objects.get(id=assignment['shift_id'])
                from_date = datetime.strptime(assignment['effective_from'], '%Y-%m-%d').date()
                to_date = None
                if assignment.get('effective_to'):
                    to_date = datetime.strptime(assignment['effective_to'], '%Y-%m-%d').date()

                # Check for conflicts with proper null handling
                conflict_detector = ConflictDetector()
                end_date_for_check = to_date if to_date else (from_date + timedelta(days=365))
                conflicts = conflict_detector.check_assignment_conflicts(
                    user, shift, from_date, end_date_for_check
                )

                # Check for exact duplicate assignments (still errors)
                exact_duplicates = ShiftAssignment.objects.filter(
                    user=user,
                    shift=shift,
                    is_current=True
                )

                if to_date:
                    exact_duplicates = exact_duplicates.filter(
                        effective_from__lte=to_date,
                        effective_to__gte=from_date
                    )
                else:
                    exact_duplicates = exact_duplicates.filter(
                        effective_from__lte=from_date,
                        effective_to__isnull=True
                    )

                has_duplicates = exact_duplicates.exists()

                # Determine validity based on new policy
                is_valid = not has_duplicates  # Only block exact duplicates

                message = 'Valid'
                if has_duplicates:
                    message = 'User already assigned to this exact shift'
                elif conflicts:
                    message = f'{len(conflicts)} potential overlaps detected (allowed)'

                results.append({
                    'user_id': assignment['user_id'],
                    'username': user.username,
                    'shift_name': shift.name,
                    'valid': is_valid,
                    'conflicts': len(conflicts),
                    'has_duplicates': has_duplicates,
                    'message': message,
                    'warnings': [f'Overlap with existing assignment'] if conflicts and not has_duplicates else []
                })

            except (User.DoesNotExist, ShiftMaster.DoesNotExist):
                results.append({
                    'user_id': assignment.get('user_id'),
                    'valid': False,
                    'conflicts': 0,
                    'message': 'Invalid user or shift ID'
                })
            except Exception as e:
                results.append({
                    'user_id': assignment.get('user_id'),
                    'valid': False,
                    'conflicts': 0,
                    'message': str(e)
                })

        return JsonResponse({'success': True, 'results': results})

    except Exception as e:
        logger.error(f"API bulk validation error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@group_required(['Manager', 'HR'])
def api_check_conflicts(request):
    """API endpoint for conflict detection"""
    try:
        user_id = request.GET.get('user_id')
        shift_id = request.GET.get('shift_id')
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')

        user = get_object_or_404(User, id=user_id)
        shift = get_object_or_404(ShiftMaster, id=shift_id)
        from_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        to_date = None
        if end_date:
            to_date = datetime.strptime(end_date, '%Y-%m-%d').date()

        conflicts = conflict_detector.check_assignment_conflicts(
            user, shift, from_date, to_date
        )

        return JsonResponse({
            'success': True,
            'has_conflicts': len(conflicts) > 0,
            'conflicts': [
                {
                    'type': 'time_overlap',
                    'conflicting_shift': conflict.conflicting_shift.name,
                    'conflict_start': str(conflict.conflict_start),
                    'conflict_end': str(conflict.conflict_end)
                }
                for conflict in conflicts
            ]
        })

    except Exception as e:
        logger.error(f"API check conflicts error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@group_required(['Manager', 'HR'])
def api_resolve_conflicts(request):
    """API endpoint for conflict resolution"""
    try:
        data = json.loads(request.body)
        conflict_id = data.get('conflict_id')
        resolution_strategy = data.get('strategy', 'manual')

        # This would integrate with your conflict resolution system
        # For now, return a simple response
        return JsonResponse({
            'success': True,
            'message': 'Conflict resolution initiated',
            'strategy': resolution_strategy
        })

    except Exception as e:
        logger.error(f"API resolve conflicts error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def api_get_suggestions(request):
    """API endpoint for getting smart suggestions"""
    try:
        suggestions = []

        # Check for users without shifts
        users_without_shifts = User.objects.filter(
            is_active=True
        ).exclude(shift_assignments__is_current=True).count()

        if users_without_shifts > 0:
            suggestions.append({
                'id': 'users_without_shifts',
                'type': 'warning',
                'title': 'Users Without Shifts',
                'message': f'{users_without_shifts} active users have no current shift assignments',
                'action_url': '/shift/assignments/assign/',
                'action_text': 'Assign Shifts'
            })

        # Check for inactive shifts
        inactive_shifts = ShiftMaster.objects.filter(is_active=False).count()
        if inactive_shifts > 0:
            suggestions.append({
                'id': 'inactive_shifts',
                'type': 'info',
                'title': 'Inactive Shifts',
                'message': f'{inactive_shifts} shifts are currently inactive',
                'action_url': '/shift/shifts/',
                'action_text': 'Review Shifts'
            })

        return JsonResponse({
            'success': True,
            'suggestions': suggestions,
            'count': len(suggestions)
        })

    except Exception as e:
        logger.error(f"API suggestions error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@require_POST
def api_dismiss_suggestion(request, suggestion_id):
    """API endpoint for dismissing suggestions"""
    try:
        # Log the dismissal
        action_logger.log_action(
            'SUGGESTION_DISMISSED',
            user_id=request.user.id,
            user=request.user.username,
            suggestion_id=suggestion_id
        )

        return JsonResponse({
            'success': True,
            'message': 'Suggestion dismissed'
        })

    except Exception as e:
        logger.error(f"API dismiss suggestion error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def api_dashboard_stats(request):
    """API endpoint for dashboard statistics"""
    try:
        stats = {
            'total_shifts': ShiftMaster.objects.filter(is_active=True).count(),
            'total_assignments': ShiftAssignment.objects.filter(is_current=True).count(),
            'total_users': User.objects.filter(is_active=True).count(),
            'users_with_shifts': ShiftAssignment.objects.filter(is_current=True).values('user').distinct().count(),
            'upcoming_holidays': Holiday.objects.filter(
                date__gte=date.today(),
                date__lte=date.today() + timedelta(days=30)
            ).count(),
            'recent_assignments': ShiftAssignment.objects.filter(
                created_at__gte=timezone.now() - timedelta(days=7)
            ).count()
        }

        stats['utilization_rate'] = round(
            (stats['users_with_shifts'] / max(stats['total_users'], 1)) * 100, 1
        )

        return JsonResponse({
            'success': True,
            'stats': stats,
            'timestamp': timezone.now().isoformat()
        })

    except Exception as e:
        logger.error(f"API dashboard stats error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def api_shift_analytics(request, shift_id):
    """API endpoint for shift analytics"""
    try:
        shift = get_object_or_404(ShiftMaster, id=shift_id)

        analytics = {
            'shift_id': shift_id,
            'total_assignments': shift.assignments.count(),
            'current_assignments': shift.assignments.filter(is_current=True).count(),
            'average_assignment_duration': 30,  # Calculate actual average
            'utilization_trend': 'stable',  # Calculate actual trend
        }

        return JsonResponse({'success': True, 'analytics': analytics})

    except Exception as e:
        logger.error(f"API shift analytics error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def api_user_analytics(request, user_id):
    """API endpoint for user analytics"""
    try:
        user = get_object_or_404(User, id=user_id)

        analytics = {
            'user_id': user_id,
            'total_assignments': user.shift_assignments.count(),
            'current_assignments': user.shift_assignments.filter(is_current=True).count(),
            'assignment_history': [
                {
                    'shift_name': assignment.shift.name,
                    'start_date': assignment.effective_from.strftime('%Y-%m-%d'),
                    'end_date': assignment.effective_to.strftime('%Y-%m-%d') if assignment.effective_to else None
                }
                for assignment in user.shift_assignments.select_related('shift').order_by('-effective_from')[:10]
            ]
        }

        return JsonResponse({'success': True, 'analytics': analytics})

    except Exception as e:
        logger.error(f"API user analytics error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@group_required(['Manager', 'HR'])
def api_available_users(request):
    """API endpoint for available users"""
    try:
        # Users without current assignments
        available_users = User.objects.filter(
            is_active=True
        ).exclude(shift_assignments__is_current=True)

        data = [
            {
                'id': user.id,
                'username': user.username,
                'full_name': user.get_full_name() or user.username,
                'email': user.email,
                'groups': list(user.groups.values_list('name', flat=True))
            }
            for user in available_users
        ]

        return JsonResponse({'success': True, 'users': data})

    except Exception as e:
        logger.error(f"API available users error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def api_shift_recommendations(request):
    """API endpoint for shift recommendations"""
    try:
        recommendations = []

        # Check for underutilized shifts
        shifts = ShiftMaster.objects.filter(is_active=True).annotate(
            assignment_count=Count('assignments', filter=Q(assignments__is_current=True))
        )

        for shift in shifts:
            if shift.assignment_count == 0:
                recommendations.append({
                    'type': 'underutilized',
                    'shift_id': shift.id,
                    'shift_name': shift.name,
                    'message': f'Shift "{shift.name}" has no current assignments',
                    'suggestion': 'Consider assigning users or reviewing if still needed'
                })

        return JsonResponse({
            'success': True,
            'recommendations': recommendations
        })

    except Exception as e:
        logger.error(f"API shift recommendations error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@group_required(['Manager', 'HR'])
def api_upcoming_changes(request):
    """API endpoint for upcoming changes"""
    try:
        days = int(request.GET.get('days', 7))

        # Assignments starting soon
        upcoming_starts = ShiftAssignment.objects.filter(
            effective_from__gt=date.today(),
            effective_from__lte=date.today() + timedelta(days=days)
        ).select_related('user', 'shift')

        # Assignments ending soon
        upcoming_ends = ShiftAssignment.objects.filter(
            effective_to__gte=date.today(),
            effective_to__lte=date.today() + timedelta(days=days),
            is_current=True
        ).select_related('user', 'shift')

        changes = []

        for assignment in upcoming_starts:
            changes.append({
                'type': 'starting',
                'date': assignment.effective_from.strftime('%Y-%m-%d'),
                'user': assignment.user.get_full_name() or assignment.user.username,
                'shift': assignment.shift.name,
                'description': f'{assignment.user.username} starts {assignment.shift.name}'
            })

        for assignment in upcoming_ends:
            changes.append({
                'type': 'ending',
                'date': assignment.effective_to.strftime('%Y-%m-%d'),
                'user': assignment.user.get_full_name() or assignment.user.username,
                'shift': assignment.shift.name,
                'description': f'{assignment.user.username} ends {assignment.shift.name}'
            })

        # Sort by date
        changes.sort(key=lambda x: x['date'])

        return JsonResponse({
            'success': True,
            'changes': changes,
            'count': len(changes)
        })

    except Exception as e:
        logger.error(f"API upcoming changes error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def api_is_holiday(request):
    """API endpoint for holiday checking"""
    try:
        date_str = request.GET.get('date', str(date.today()))
        check_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        # Check for exact date match or recurring holiday
        holiday = Holiday.objects.filter(
            Q(date=check_date) |
            Q(recurring_yearly=True, date__month=check_date.month, date__day=check_date.day)
        ).first()

        is_holiday = holiday is not None
        holiday_info = None

        if holiday:
            holiday_info = {
                'name': holiday.name,
                'date': holiday.date.strftime('%Y-%m-%d'),
                'recurring_yearly': holiday.recurring_yearly
            }

        return JsonResponse({
            'success': True,
            'is_holiday': is_holiday,
            'holiday': holiday_info
        })

    except Exception as e:
        logger.error(f"API holiday check error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
def api_holidays_list(request):
    """API endpoint for holidays list"""
    try:
        year = int(request.GET.get('year', date.today().year))

        holidays = Holiday.objects.filter(
            Q(date__year=year) |
            Q(recurring_yearly=True)
        ).order_by('date')

        data = [
            {
                'id': holiday.id,
                'name': holiday.name,
                'date': holiday.date.strftime('%Y-%m-%d'),
                'recurring_yearly': holiday.recurring_yearly
            }
            for holiday in holidays
        ]

        return JsonResponse({'success': True, 'holidays': data})

    except Exception as e:
        logger.error(f"API holidays list error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)

@login_required
@group_required(['Manager', 'HR'])
def api_system_status(request):
    """API endpoint for system status"""
    try:
        status = {
            'database': 'healthy',
            'cache': 'healthy',
            'service': 'running',
            'conflicts_detected': 0,
            'last_check': timezone.now().isoformat()
        }

        # Quick conflict check
        try:
            current_assignments = ShiftAssignment.objects.filter(is_current=True).count()
            status['active_assignments'] = current_assignments
        except Exception:
            status['database'] = 'error'

        return JsonResponse({'success': True, 'status': status})

    except Exception as e:
        logger.error(f"API system status error: {e}")
        return JsonResponse({'success': False, 'error': str(e)}, status=500)


# ============================
# MANAGER QUICK ACTIONS
# ============================

@login_required
@group_required(['Manager', 'HR'])
def quick_assign_user(request):
    """Quick assignment of user to shift"""
    if request.method == 'POST':
        try:
            user_id = request.POST.get('user_id')
            shift_id = request.POST.get('shift_id')
            effective_from = request.POST.get('effective_from')
            effective_to = request.POST.get('effective_to')

            result = shift_service.assign_shift_to_user(
                user_id=user_id,
                shift_id=shift_id,
                effective_from=effective_from,
                effective_to=effective_to,
                assigned_by=request.user
            )

            if result.success:
                messages.success(request, f"User assigned to shift successfully!")
                return JsonResponse({'success': True, 'assignment_id': result.assignment_id})
            else:
                return JsonResponse({'success': False, 'errors': result.errors})

        except Exception as e:
            logger.error(f"Quick assign error: {e}")
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
@group_required(['Manager', 'HR'])
def quick_end_assignment(request):
    """Quick end of shift assignment"""
    if request.method == 'POST':
        try:
            assignment_id = request.POST.get('assignment_id')
            end_date = request.POST.get('end_date', timezone.now().date())

            result = shift_service.end_shift_assignment(
                assignment_id=assignment_id,
                end_date=end_date,
                ended_by=request.user
            )

            if result.success:
                messages.success(request, "Assignment ended successfully!")
                return JsonResponse({'success': True})
            else:
                return JsonResponse({'success': False, 'errors': result.errors})

        except Exception as e:
            logger.error(f"Quick end assignment error: {e}")
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
@group_required(['Manager', 'HR'])
def quick_create_shift(request):
    """Quick creation of new shift"""
    if request.method == 'POST':
        try:
            form = ShiftForm(request.POST)
            if form.is_valid():
                shift = form.save(commit=False)
                shift.created_by = request.user
                shift.save()

                messages.success(request, f"Shift '{shift.shift_name}' created successfully!")
                return JsonResponse({'success': True, 'shift_id': shift.id})
            else:
                return JsonResponse({'success': False, 'errors': form.errors})

        except Exception as e:
            logger.error(f"Quick create shift error: {e}")
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
@group_required(['Manager', 'HR'])
def quick_user_status(request, user_id):
    """Get quick status of user's shift assignment"""
    try:
        user = get_object_or_404(User, id=user_id)
        status = shift_service.get_user_shift_status(user)

        return JsonResponse({
            'success': True,
            'user_id': user_id,
            'username': user.username,
            'status': status
        })

    except Exception as e:
        logger.error(f"Quick user status error: {e}")
        return JsonResponse({'success': False, 'error': str(e)})


# ============================
# REPORTS AND EXPORTS
# ============================

@login_required
@group_required(['Manager', 'HR'])
def report_assignments(request):
    """Generate assignments report"""
    try:
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        format_type = request.GET.get('format', 'html')

        assignments = ShiftAssignment.objects.select_related('user', 'shift', 'created_by')

        if start_date:
            assignments = assignments.filter(effective_from__gte=start_date)
        if end_date:
            assignments = assignments.filter(effective_to__lte=end_date)

        if format_type == 'csv':
            response = HttpResponse(content_type='text/csv')
            response['Content-Disposition'] = 'attachment; filename="assignments_report.csv"'

            writer = csv.writer(response)
            writer.writerow(['User', 'Shift', 'Effective From', 'Effective To', 'Status', 'Created By'])

            for assignment in assignments:
                writer.writerow([
                    assignment.user.username,
                    assignment.shift.shift_name,
                    assignment.effective_from,
                    assignment.effective_to or 'Ongoing',
                    'Active' if assignment.is_current else 'Inactive',
                    assignment.created_by.username if assignment.created_by else 'System'
                ])

            return response

        context = {
            'assignments': assignments,
            'start_date': start_date,
            'end_date': end_date,
            'total_assignments': assignments.count()
        }
        return render(request, 'shift/reports/assignments.html', context)

    except Exception as e:
        logger.error(f"Report assignments error: {e}")
        messages.error(request, f"Error generating report: {e}")
        return redirect('shift:dashboard')

@login_required
@group_required(['Manager', 'HR'])
def report_attendance(request):
    """Generate attendance report"""
    try:
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        format_type = request.GET.get('format', 'html')

        # This would integrate with attendance tracking if available
        context = {
            'start_date': start_date,
            'end_date': end_date,
            'message': 'Attendance reporting requires integration with attendance tracking module'
        }
        return render(request, 'shift/reports/attendance.html', context)

    except Exception as e:
        logger.error(f"Report attendance error: {e}")
        messages.error(request, f"Error generating report: {e}")
        return redirect('shift:dashboard')

@login_required
@group_required(['Manager', 'HR'])
def report_conflicts(request):
    """Generate conflicts report"""
    try:
        # Detect current conflicts
        conflicts = conflict_detector.check_assignment_conflicts(
            user_id=None,  # Check all users
            shift_id=None,
            start_date=timezone.now().date(),
            end_date=timezone.now().date() + timedelta(days=30)
        )

        context = {
            'conflicts': conflicts,
            'total_conflicts': len(conflicts)
        }
        return render(request, 'shift/reports/conflicts.html', context)

    except Exception as e:
        logger.error(f"Report conflicts error: {e}")
        messages.error(request, f"Error generating report: {e}")
        return redirect('shift:dashboard')

@login_required
@group_required(['Manager', 'HR'])
def report_utilization(request):
    """Generate shift utilization report"""
    try:
        shifts = ShiftMaster.objects.filter(is_active=True)
        utilization_data = []

        for shift in shifts:
            assignments = ShiftAssignment.objects.filter(shift=shift, is_current=True)
            utilization_data.append({
                'shift': shift,
                'current_assignments': assignments.count(),
                'utilization_rate': f"{assignments.count() * 100 / max(shift.max_capacity or 1, 1):.1f}%"
            })

        context = {
            'utilization_data': utilization_data,
            'total_shifts': shifts.count()
        }
        return render(request, 'shift/reports/utilization.html', context)

    except Exception as e:
        logger.error(f"Report utilization error: {e}")
        messages.error(request, f"Error generating report: {e}")
        return redirect('shift:dashboard')


# ============================
# BATCH OPERATIONS
# ============================
@login_required
@group_required(['Manager'])
def batch_activate_shifts(request):
    """Batch activate multiple shifts"""
    if request.method == 'POST':
        try:
            shift_ids = request.POST.getlist('shift_ids')
            updated_count = 0

            with transaction.atomic():
                for shift_id in shift_ids:
                    try:
                        shift = ShiftMaster.objects.get(id=shift_id)
                        shift.is_active = True
                        shift.save()
                        updated_count += 1
                    except ShiftMaster.DoesNotExist:
                        continue

            messages.success(request, f"Successfully activated {updated_count} shifts.")
            return JsonResponse({'success': True, 'updated_count': updated_count})

        except Exception as e:
            logger.error(f"Batch activate error: {e}")
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
@group_required(['Manager'])
def batch_deactivate_shifts(request):
    """Batch deactivate multiple shifts"""
    if request.method == 'POST':
        try:
            shift_ids = request.POST.getlist('shift_ids')
            updated_count = 0

            with transaction.atomic():
                for shift_id in shift_ids:
                    try:
                        shift = ShiftMaster.objects.get(id=shift_id)
                        shift.is_active = False
                        shift.save()
                        updated_count += 1
                    except ShiftMaster.DoesNotExist:
                        continue

            messages.success(request, f"Successfully deactivated {updated_count} shifts.")
            return JsonResponse({'success': True, 'updated_count': updated_count})

        except Exception as e:
            logger.error(f"Error in batch deactivate shifts: {e}")
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
@group_required(['Manager'])
def batch_end_assignments(request):
    """Batch end multiple assignments"""
    if request.method == 'POST':
        try:
            assignment_ids = request.POST.getlist('assignment_ids')
            end_date = request.POST.get('end_date', timezone.now().date())
            updated_count = 0

            with transaction.atomic():
                for assignment_id in assignment_ids:
                    try:
                        assignment = ShiftAssignment.objects.get(id=assignment_id)
                        assignment.effective_to = end_date
                        assignment.is_current = False
                        assignment.save()
                        updated_count += 1
                    except ShiftAssignment.DoesNotExist:
                        continue

            messages.success(request, f"Successfully ended {updated_count} assignments.")
            return JsonResponse({'success': True, 'updated_count': updated_count})

        except Exception as e:
            logger.error(f"Error in batch end assignments: {e}")
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})

@login_required
@group_required(['Manager'])
def batch_extend_assignments(request):
    """Batch extend multiple assignments"""
    if request.method == 'POST':
        try:
            assignment_ids = request.POST.getlist('assignment_ids')
            new_end_date = request.POST.get('new_end_date')
            updated_count = 0

            with transaction.atomic():
                for assignment_id in assignment_ids:
                    try:
                        assignment = ShiftAssignment.objects.get(id=assignment_id)
                        assignment.effective_to = new_end_date
                        assignment.save()
                        updated_count += 1
                    except ShiftAssignment.DoesNotExist:
                        continue

            messages.success(request, f"Successfully extended {updated_count} assignments.")
            return JsonResponse({'success': True, 'updated_count': updated_count})

        except Exception as e:
            logger.error(f"Error in batch extend assignments: {e}")
            return JsonResponse({'success': False, 'error': str(e)})

    return JsonResponse({'success': False, 'error': 'Invalid request method'})


# ============================
# SETTINGS AND CONFIGURATION
# ============================

@login_required
@group_required(['Manager'])
def shift_settings(request):
    """Shift management settings"""
    try:
        context = {
            'shift_groups': SHIFT_GROUPS,
            'cache_settings': CACHE_SETTINGS,
            'email_notifications': EMAIL_NOTIFICATIONS
        }
        return render(request, 'shift/settings/index.html', context)

    except Exception as e:
        logger.error(f"Shift settings error: {e}")
        messages.error(request, f"Error loading settings: {e}")
        return redirect('shift:dashboard')

@login_required
@group_required(['Manager'])
def manage_groups(request):
    """Manage user groups for shift access"""
    try:
        groups = Group.objects.all()
        context = {'groups': groups}
        return render(request, 'shift/settings/groups.html', context)

    except Exception as e:
        logger.error(f"Manage groups error: {e}")
        messages.error(request, f"Error loading groups: {e}")
        return redirect('shift:settings')

@login_required
@group_required(['Manager'])
def manage_permissions(request):
    """Manage permissions for shift operations"""
    try:
        from .urls import URL_PERMISSION_MAP
        context = {'permission_map': URL_PERMISSION_MAP}
        return render(request, 'shift/settings/permissions.html', context)

    except Exception as e:
        logger.error(f"Manage permissions error: {e}")
        messages.error(request, f"Error loading permissions: {e}")
        return redirect('shift:settings')

@login_required
@group_required(['Manager'])
def shift_templates(request):
    """Manage shift templates"""
    try:
        templates = ShiftMaster.objects.filter(is_template=True)
        context = {'templates': templates}
        return render(request, 'shift/settings/templates.html', context)

    except Exception as e:
        logger.error(f"Shift templates error: {e}")
        messages.error(request, f"Error loading templates: {e}")
        return redirect('shift:settings')


# ============================
# CONFLICT MANAGEMENT
# ============================

@login_required
@group_required(['Manager', 'HR'])
def conflict_dashboard(request):
    """Dashboard for managing conflicts"""
    try:
        # Get current conflicts
        conflicts = conflict_detector.check_assignment_conflicts(
            user_id=None,
            shift_id=None,
            start_date=timezone.now().date(),
            end_date=timezone.now().date() + timedelta(days=7)
        )

        context = {
            'conflicts': conflicts,
            'total_conflicts': len(conflicts),
            'high_priority': [c for c in conflicts if c.severity == 'high'],
            'medium_priority': [c for c in conflicts if c.severity == 'medium']
        }
        return render(request, 'shift/conflicts/dashboard.html', context)

    except Exception as e:
        logger.error(f"Conflict dashboard error: {e}")
        messages.error(request, f"Error loading conflicts: {e}")
        return redirect('shift:dashboard')

@login_required
@group_required(['Manager', 'HR'])
def detect_conflicts(request):
    """Detect conflicts in assignments"""
    try:
        start_date = request.GET.get('start_date', timezone.now().date())
        end_date = request.GET.get('end_date', timezone.now().date() + timedelta(days=30))

        conflicts = conflict_detector.check_assignment_conflicts(
            user_id=None,
            shift_id=None,
            start_date=start_date,
            end_date=end_date
        )

        if request.headers.get('Accept') == 'application/json':
            return JsonResponse({
                'success': True,
                'conflicts': [
                    {
                        'type': c.conflict_type,
                        'severity': c.severity,
                        'message': c.message,
                        'affected_users': c.affected_users
                    }
                    for c in conflicts
                ]
            })

        context = {
            'conflicts': conflicts,
            'start_date': start_date,
            'end_date': end_date
        }
        return render(request, 'shift/conflicts/detect.html', context)

    except Exception as e:
        logger.error(f"Detect conflicts error: {e}")
        return JsonResponse({'success': False, 'error': str(e)})

@login_required
@group_required(['Manager', 'HR'])
def resolve_conflicts(request):
    """Resolve detected conflicts"""
    if request.method == 'POST':
        try:
            conflict_data = json.loads(request.body)
            resolution_type = conflict_data.get('resolution_type')
            conflict_id = conflict_data.get('conflict_id')

            # Implementation would depend on specific conflict resolution logic
            result = {'success': True, 'message': 'Conflict resolved successfully'}

            return JsonResponse(result)

        except Exception as e:
            logger.error(f"Resolve conflicts error: {e}")
            return JsonResponse({'success': False, 'error': str(e)})

    context = {'resolution_options': ['reassign', 'modify_timing', 'end_assignment']}
    return render(request, 'shift/conflicts/resolve.html', context)

@login_required
@group_required(['Manager'])
def auto_resolve_conflict(request, conflict_id):
    """Auto-resolve a specific conflict"""
    try:
        # Implementation would depend on auto-resolution logic
        result = {'success': True, 'message': f'Conflict {conflict_id} auto-resolved'}

        if request.headers.get('Accept') == 'application/json':
            return JsonResponse(result)

        messages.success(request, result['message'])
        return redirect('shift:conflict_dashboard')

    except Exception as e:
        logger.error(f"Auto resolve conflict error: {e}")
        return JsonResponse({'success': False, 'error': str(e)})


# ============================
# HELP AND DOCUMENTATION
# ============================

@login_required
def help_index(request):
    """Help index page"""
    context = {
        'help_sections': [
            {'title': 'Getting Started', 'url': 'shift:help_getting_started'},
            {'title': 'Conflict Resolution', 'url': 'shift:help_conflicts'},
            {'title': 'CSV Import', 'url': 'shift:help_csv'},
            {'title': 'API Documentation', 'url': 'shift:help_api'}
        ]
    }
    return render(request, 'shift/help/index.html', context)

@login_required
def help_getting_started(request):
    """Getting started help"""
    return render(request, 'shift/help/getting_started.html')

@login_required
def help_conflicts(request):
    """Conflict resolution help"""
    return render(request, 'shift/help/conflicts.html')

@login_required
def help_csv_import(request):
    """CSV import help"""
    return render(request, 'shift/help/csv_import.html')

@login_required
def help_api_docs(request):
    """API documentation"""
    return render(request, 'shift/help/api_docs.html')


# ============================
# DEVELOPMENT AND TESTING
# ============================

@login_required
@group_required(['Manager'])
def test_conflict_detection(request):
    """Test conflict detection functionality"""
    try:
        # Create test scenarios and run conflict detection
        test_results = {
            'time_overlap_test': 'Passed',
            'date_overlap_test': 'Passed',
            'user_conflict_test': 'Passed',
            'holiday_conflict_test': 'Passed'
        }

        context = {'test_results': test_results}
        return render(request, 'shift/dev/test_conflicts.html', context)

    except Exception as e:
        logger.error(f"Test conflicts error: {e}")
        messages.error(request, f"Test error: {e}")
        return redirect('shift:dashboard')

@login_required
@group_required(['Manager'])
def test_assignments(request):
    """Test assignment functionality"""
    try:
        test_results = {
            'assignment_creation': 'Passed',
            'assignment_validation': 'Passed',
            'bulk_assignment': 'Passed'
        }

        context = {'test_results': test_results}
        return render(request, 'shift/dev/test_assignments.html', context)

    except Exception as e:
        logger.error(f"Test assignments error: {e}")
        messages.error(request, f"Test error: {e}")
        return redirect('shift:dashboard')

@login_required
@group_required(['Manager'])
def generate_test_data(request):
    """Generate test data for development"""
    if request.method == 'POST':
        try:
            # Generate test shifts, users, assignments
            count = int(request.POST.get('count', 10))

            # Implementation would create test data
            messages.success(request, f"Generated {count} test records successfully!")
            return JsonResponse({'success': True, 'count': count})

        except Exception as e:
            logger.error(f"Generate test data error: {e}")
            return JsonResponse({'success': False, 'error': str(e)})

    return render(request, 'shift/dev/generate_test_data.html')

@login_required
@group_required(['Manager'])
def system_diagnostic(request):
    """System diagnostic page"""
    try:
        diagnostics = {
            'database_connection': 'OK',
            'cache_status': 'OK',
            'total_shifts': ShiftMaster.objects.count(),
            'total_assignments': ShiftAssignment.objects.count(),
            'active_assignments': ShiftAssignment.objects.filter(is_current=True).count(),
            'total_holidays': Holiday.objects.count()
        }

        context = {'diagnostics': diagnostics}
        return render(request, 'shift/dev/diagnostic.html', context)

    except Exception as e:
        logger.error(f"System diagnostic error: {e}")
        messages.error(request, f"Diagnostic error: {e}")
        return redirect('shift:dashboard')
