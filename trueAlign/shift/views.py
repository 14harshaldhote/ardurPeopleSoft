import json
import logging
import time
import uuid
from datetime import datetime, date, timedelta
from typing import Dict, Any, List
from functools import wraps
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User, Group
from django.core.paginator import Paginator
from django.db import transaction
from django.http import JsonResponse, HttpResponse, Http404
from django.shortcuts import render, get_object_or_404, redirect
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import ListView, DetailView
from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
from trueAlign.shift.decorators import group_required, superuser_required
from trueAlign.shift.forms import (
    ShiftForm, ShiftAssignmentForm, BulkAssignmentForm, HolidayForm,
    CSVUploadForm, ShiftFilterForm, AssignmentFilterForm, ReportGenerationForm
)
from trueAlign.shift.services import ShiftService
from django.db import transaction


logger = logging.getLogger('trueAlign.shift')

# Initialize service
shift_service = ShiftService()


def get_client_ip(request):
    """Get client IP address from request."""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


def log_action(action_name):
    """Decorator for comprehensive action-based logging."""
    def decorator(func):
        @wraps(func)
        def wrapper(request, *args, **kwargs):
            # Generate unique request ID
            request_id = str(uuid.uuid4())[:8]

            # Get user and IP info
            user = getattr(request, 'user', None)
            username = user.username if user and user.is_authenticated else 'anonymous'
            user_id = user.id if user and user.is_authenticated else None
            ip_address = get_client_ip(request)

            # Create log context
            log_context = {
                'request_id': request_id,
                'action': action_name,
                'user': username,
                'user_id': user_id,
                'ip': ip_address,
                'method': request.method,
                'path': request.path,
                'view_args': str(args),
                'kwargs': {k: v for k, v in kwargs.items() if 'password' not in k.lower()}
            }

            # Log action start
            start_time = time.time()
            logger.info(f"[{request_id}] ACTION_START - {action_name}", extra=log_context)

            try:
                # Execute the function
                result = func(request, *args, **kwargs)

                # Log successful completion
                duration = round((time.time() - start_time) * 1000, 2)
                log_context.update({
                    'status': 'success',
                    'duration_ms': duration
                })
                logger.info(f"[{request_id}] ACTION_SUCCESS - {action_name} completed in {duration}ms", extra=log_context)
                return result

            except Exception as e:
                # Log error details
                duration = round((time.time() - start_time) * 1000, 2)
                log_context.update({
                    'status': 'error',
                    'duration_ms': duration,
                    'error_type': type(e).__name__,
                    'error_message': str(e)
                })
                logger.error(f"[{request_id}] ACTION_ERROR - {action_name} failed after {duration}ms: {str(e)}",
                           extra=log_context, exc_info=True)
                raise

        return wrapper
    return decorator


def log_db_operation(operation, model_name, object_id=None, details=None):
    """Log database operations with context."""
    logger.info(f"DB_OPERATION - {operation} on {model_name}", extra={
        'operation': operation,
        'model': model_name,
        'object_id': object_id,
        'details': details
    })


def log_user_action(user, action, target=None, details=None):
    """Log user-specific actions."""
    username = user.username if user and user.is_authenticated else 'anonymous'
    logger.info(f"USER_ACTION - {username}: {action}", extra={
        'user': username,
        'user_id': user.id if user and user.is_authenticated else None,
        'action': action,
        'target': target,
        'details': details
    })


# ============================
# HELPER FUNCTIONS
# ============================

def _get_user_permissions(user):
    """Helper function to get user permissions for templates."""
    if not user.is_authenticated:
        return {'can_manage': False, 'can_assign': False, 'can_view_all': False}

    return {
        'is_manager': user.groups.filter(name='Manager').exists(),
        'is_hr': user.groups.filter(name='HR').exists(),
        'is_employee': user.groups.filter(name='Employee').exists(),
        'is_superuser': user.is_superuser,
        'can_manage': user.groups.filter(name__in=['Manager', 'HR']).exists() or user.is_superuser,
        'can_assign': user.groups.filter(name__in=['Manager', 'HR']).exists() or user.is_superuser,
        'can_view_all': user.groups.filter(name__in=['Manager', 'HR']).exists() or user.is_superuser,
    }


def _handle_form_errors(request, form, action_name):
    """Helper to handle form validation errors consistently."""
    for field, errors in form.errors.items():
        for error in errors:
            messages.error(request, f"{field.title()}: {error}")
    log_user_action(request.user, f'{action_name}_validation_failed',
                   details={'errors': form.errors.as_json()})


def _validate_date_range(start_date, end_date, max_days=365):
    """Helper function to validate date ranges."""
    if start_date and end_date:
        if start_date > end_date:
            return False, "Start date must be before end date"
        if (end_date - start_date).days > max_days:
            return False, f"Date range cannot exceed {max_days} days"
    return True, "Valid date range"


# ============================
# DASHBOARD AND OVERVIEW VIEWS
# ============================

@login_required
@group_required(group_names=['Manager', 'Employee', 'HR'])
@log_action('SHIFT_DASHBOARD_VIEW')
def shift_dashboard(request):
    """Enhanced dashboard showing comprehensive shift overview, statistics, and suggestions."""
    try:
        permissions = _get_user_permissions(request.user)
        context = {
            'page_title': 'Shift Management Dashboard',
            'user': request.user,
            **permissions
        }

        # Get user's current shift and status
        current_shift = shift_service.get_current_shift(request.user)
        shift_status = shift_service.is_user_on_shift_now(request.user)

        context.update({
            'current_shift': current_shift,
            'shift_status': shift_status
        })

        # Get comprehensive statistics for managers and HR
        if permissions['can_view_all']:
            # Enhanced shift statistics
            stats = shift_service.get_shift_statistics()

            # Calculate additional metrics
            total_shifts = ShiftMaster.objects.filter(is_active=True).count()
            active_shifts = ShiftMaster.objects.filter(is_active=True).count()
            users_with_shifts = ShiftAssignment.objects.filter(
                is_current=True
            ).values('user').distinct().count()

            total_users = User.objects.filter(is_active=True).count()
            users_without_shifts = total_users - users_with_shifts

            shift_stats = {
                'total_shifts': total_shifts,
                'active_shifts': active_shifts,
                'users_with_shifts': users_with_shifts,
                'users_without_shifts': users_without_shifts,
                'utilization_rate': round((users_with_shifts / max(total_users, 1)) * 100, 1)
            }

            # Get upcoming changes and conflicts
            upcoming_changes = shift_service.get_upcoming_shift_changes(days=7)

            # Generate smart suggestions
            suggestions = generate_shift_suggestions(request.user)

            # Get recent activities
            recent_activities = get_recent_shift_activities(limit=10)

            context.update({
                'shift_stats': shift_stats,
                'statistics': stats,
                'upcoming_changes': upcoming_changes[:5],
                'suggestions': suggestions,
                'recent_activities': recent_activities
            })

        # Get holidays for current year
        current_year = timezone.now().year
        holidays = Holiday.objects.filter(
            date__year__in=[current_year, current_year + 1]
        ).order_by('date')[:10]

        # Get user's calendar and recent assignments
        now = timezone.now()
        user_calendar = shift_service.get_user_shift_calendar(request.user, now.month, now.year)
        recent_assignments = shift_service.get_shift_history(request.user.id)[:5]

        context.update({
            'user_calendar': user_calendar,
            'recent_assignments': recent_assignments,
            'holidays': holidays,
            'current_year': current_year
        })

        return render(request, 'shift/dashboard.html', context)

    except Exception as e:
        logger.error(f"Error in shift dashboard: {str(e)}")
        messages.error(request, "Error loading dashboard. Please try again.")
        return render(request, 'shift/dashboard.html', {'error': True})


def generate_shift_suggestions(user):
    """Generate intelligent shift management suggestions."""
    suggestions = []

    try:
        # Check for unassigned users
        unassigned_users = User.objects.filter(
            is_active=True
        ).exclude(
            shift_assignments__is_current=True
        ).count()

        if unassigned_users > 0:
            suggestions.append({
                'id': 'unassigned_users',
                'type': 'warning',
                'priority': 'high',
                'priority_color': 'yellow',
                'title': 'Users Without Shift Assignments',
                'description': f'{unassigned_users} active users are not assigned to any shift.',
                'affected_users': unassigned_users,
                'action_url': reverse('shift:assignments'),
                'action_text': 'Assign Shifts'
            })

        # Check for shifts without assignments
        unused_shifts = ShiftMaster.objects.filter(
            is_active=True
        ).exclude(
            assignments__is_current=True
        ).count()

        if unused_shifts > 0:
            suggestions.append({
                'id': 'unused_shifts',
                'type': 'optimization',
                'priority': 'medium',
                'priority_color': 'blue',
                'title': 'Unused Active Shifts',
                'description': f'{unused_shifts} active shifts have no current assignments.',
                'action_url': reverse('shift:list'),
                'action_text': 'Review Shifts'
            })

        # Check for expiring assignments
        expiring_soon = ShiftAssignment.objects.filter(
            is_current=True,
            effective_to__lte=timezone.now().date() + timedelta(days=7),
            effective_to__isnull=False
        ).count()

        if expiring_soon > 0:
            suggestions.append({
                'id': 'expiring_assignments',
                'type': 'warning',
                'priority': 'high',
                'priority_color': 'red',
                'title': 'Assignments Expiring Soon',
                'description': f'{expiring_soon} shift assignments will expire within 7 days.',
                'affected_users': expiring_soon,
                'action_url': reverse('shift:assignments'),
                'action_text': 'Extend Assignments'
            })

        # Check for shifts with insufficient break time
        insufficient_breaks = ShiftMaster.objects.filter(
            is_active=True,
            shift_duration__gte=8.0,
            break_duration__lt=timedelta(minutes=30)
        ).count()

        if insufficient_breaks > 0:
            suggestions.append({
                'id': 'insufficient_breaks',
                'type': 'compliance',
                'priority': 'medium',
                'priority_color': 'yellow',
                'title': 'Insufficient Break Times',
                'description': f'{insufficient_breaks} shifts of 8+ hours have less than 30 minutes break.',
                'action_url': reverse('shift:list'),
                'action_text': 'Review Break Times'
            })

        return {
            'suggestions': suggestions,
            'count': len(suggestions)
        }

    except Exception as e:
        logger.error(f"Error generating suggestions: {str(e)}")
        return {'suggestions': [], 'count': 0}


def get_recent_shift_activities(limit=10):
    """Get recent shift management activities."""
    activities = []

    try:
        # Get recent assignments
        recent_assignments = ShiftAssignment.objects.select_related(
            'user', 'shift'
        ).order_by('-created_at')[:limit]

        for assignment in recent_assignments:
            activities.append({
                'type': 'assignment',
                'type_color': 'blue',
                'description': f'{assignment.user.get_full_name() or assignment.user.username} assigned to {assignment.shift.name}',
                'timestamp': assignment.created_at
            })

        # Sort by timestamp
        activities.sort(key=lambda x: x['timestamp'], reverse=True)

        return activities[:limit]

    except Exception as e:
        logger.error(f"Error getting recent activities: {str(e)}")
        return []


@login_required
@group_required(group_names=['Manager', 'HR'])
@log_action('SHIFT_STATISTICS_VIEW')
def shift_statistics(request):
    """Detailed statistics page for managers and HR."""
    try:
        stats = shift_service.get_shift_statistics()
        upcoming_changes = shift_service.get_upcoming_shift_changes(days=30)

        today = timezone.now().date()
        end_date = today + timedelta(days=30)
        conflicts = shift_service.get_shift_conflicts(today, end_date)

        context = {
            'page_title': 'Shift Statistics',
            'statistics': stats,
            'upcoming_changes': upcoming_changes,
            'conflicts': conflicts,
            'date_range': {'start': today, 'end': end_date}
        }

        return render(request, 'shift/statistics.html', context)

    except Exception as e:
        logger.error(f"Error in shift statistics: {str(e)}")
        messages.error(request, "Error loading statistics.")
        return redirect('shift:dashboard')


# ============================
# SHIFT MANAGEMENT VIEWS
# ============================

@login_required
@group_required(group_names=['Manager', 'HR'])
@log_action('SHIFT_LIST_VIEW')
def shift_list(request):
    """List all shifts with filtering, pagination, and inline create/edit forms."""
    try:
        print("\n=== SHIFT LIST VIEW ===")
        print(f"User: {request.user.username} (ID: {request.user.id})")

        # Get permissions
        permissions = _get_user_permissions(request.user)
        print(f"Permissions: {permissions}")

        # Handle filters
        filter_form = ShiftFilterForm(request.GET)

        print("\n--- Filter Form Data ---")
        print(dict(request.GET))  # Raw query parameters

        if filter_form.is_valid():
            print("Filter form is valid.")
            print(f"Cleaned Filter Data: {filter_form.cleaned_data}")
        else:
            print("Filter form is NOT valid.")
            print(filter_form.errors)

        # Get pagination info
        page = int(request.GET.get('page', 1))
        per_page = int(request.GET.get('per_page', 10))
        print(f"Pagination: page={page}, per_page={per_page}")

        # Determine active filter from request
        active_only = True  # Default to showing active shifts
        if request.GET.get('is_active') == 'false':
            active_only = False
        elif request.GET.get('is_active') == '':
            active_only = None  # Show all

        print(f"Active Only Filter: {active_only}")

        # Call shift service with correct parameters
        print("Fetching shifts from shift_service...")
        shifts_data = shift_service.get_all_shifts(
            active_only=active_only,
            page=page,
            per_page=per_page
        )
        print(f"Service returned: {type(shifts_data)}")
        print(f"Shifts count: {len(shifts_data.get('shifts', [])) if isinstance(shifts_data, dict) else 0}")

        # Apply additional filters to the shifts (since service doesn't support filters parameter)
        shifts_list = shifts_data.get('shifts', []) if isinstance(shifts_data, dict) else []

        # Apply name filter
        if filter_form.is_valid() and filter_form.cleaned_data.get('name'):
            name_filter = filter_form.cleaned_data['name'].lower()
            shifts_list = [s for s in shifts_list if name_filter in s['name'].lower()]

        # Apply work_days filter
        if filter_form.is_valid() and filter_form.cleaned_data.get('work_days'):
            work_days_filter = filter_form.cleaned_data['work_days']
            shifts_list = [s for s in shifts_list if s['work_days'] == work_days_filter]

        # Convert shifts data to objects for template compatibility
        class ShiftObject:
            def __init__(self, data):
                self.id = data['id']
                self.name = data['name']
                self.description = data.get('description', '')
                self.start_time = datetime.strptime(data['start_time'], '%H:%M').time()
                self.end_time = datetime.strptime(data['end_time'], '%H:%M').time()
                self.shift_duration = data['duration']
                self.work_days = data['work_days']
                self.custom_work_days = data.get('custom_work_days', '')
                self.is_active = data['is_active']
                self.break_duration = timedelta(minutes=data.get('break_minutes', 30))
                self.grace_period = timedelta(minutes=data.get('grace_minutes', 15))

            def get_work_days_display(self):
                work_days_map = {
                    'Weekdays': 'Monday to Friday',
                    'All Days': 'Monday to Saturday',
                    'Custom': 'Custom Days'
                }
                return work_days_map.get(self.work_days, self.work_days)

        # Convert to shift objects
        shifts = [ShiftObject(shift_data) for shift_data in shifts_list]

        # Create a simple pagination-like object for template
        class SimplePaginator:
            def __init__(self, shifts, page, per_page, total_count):
                self.object_list = shifts
                self.number = page
                self.count = total_count
                self.num_pages = (total_count + per_page - 1) // per_page if total_count > 0 else 1
                self._per_page = per_page

            def __iter__(self):
                return iter(self.object_list)

            def has_other_pages(self):
                return self.num_pages > 1

            def has_previous(self):
                return self.number > 1

            def has_next(self):
                return self.number < self.num_pages

            def previous_page_number(self):
                return self.number - 1 if self.has_previous() else None

            def next_page_number(self):
                return self.number + 1 if self.has_next() else None

            @property
            def paginator(self):
                return self

            @property
            def page_range(self):
                return range(1, self.num_pages + 1)

            @property
            def start_index(self):
                return (self.number - 1) * self._per_page + 1 if self.count > 0 else 0

            @property
            def end_index(self):
                return min(self.number * self._per_page, self.count) if self.count > 0 else 0

        # Create paginator object
        pagination_info = shifts_data.get('pagination', {}) if isinstance(shifts_data, dict) else {}
        total_count = pagination_info.get('total_count', len(shifts))
        shifts_paginator = SimplePaginator(shifts, page, per_page, total_count)

        # Create form
        create_form = ShiftForm()

        context = {
            'page_title': 'Shifts',
            'shifts': shifts_paginator,
            'filter_form': filter_form,
            'create_form': create_form,
            **permissions,
        }

        print("Rendering shift_list.html with context.")
        print(f"Context keys: {list(context.keys())}")
        print(f"Shifts in context: {len(shifts)}")

        return render(request, 'shift/shift_list.html', context)

    except Exception as e:
        logger.error(f"Error in shift list: {str(e)}", exc_info=True)
        messages.error(request, f"Error loading shifts: {str(e)}")
        print(f"Exception occurred: {str(e)}")
        print(f"Exception type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")

        # Return empty context on error with proper iterable
        class EmptyPaginator:
            def __init__(self):
                self.object_list = []
                self.number = 1
                self.count = 0
                self.num_pages = 1

            def __iter__(self):
                return iter(self.object_list)

            def has_other_pages(self):
                return False

            def has_previous(self):
                return False

            def has_next(self):
                return False

            @property
            def paginator(self):
                return self

            @property
            def page_range(self):
                return range(1, 2)

            @property
            def start_index(self):
                return 0

            @property
            def end_index(self):
                return 0

        context = {
            'page_title': 'Shifts',
            'shifts': EmptyPaginator(),
            'filter_form': ShiftFilterForm(),
            'create_form': ShiftForm(),
            'error': True,
            **_get_user_permissions(request.user),
        }
        return render(request, 'shift/shift_list.html', context)







@login_required
@group_required(group_names=['Manager', 'Employee', 'HR'])
@log_action('SHIFT_DETAIL_VIEW')
def shift_detail(request, shift_id):
    """Show detailed information about a specific shift."""
    try:
        # Get shift details from service instead of direct model access
        shift_data = shift_service.get_shift_by_id(shift_id)

        if not shift_data:
            messages.error(request, "Shift not found.")
            return redirect('shift:list')

        permissions = _get_user_permissions(request.user)

        # Get assignments for this shift
        try:
            assignments = shift_service.get_shift_assignments(
                filters={'shift_id': shift_id}, page=1, per_page=50
            )
        except Exception as e:
            logger.warning(f"Could not load assignments: {str(e)}")
            assignments = {'assignments': [], 'pagination': {'total_count': 0}}

        # Get shift statistics
        try:
            shift_stats = {
                'total_assignments': ShiftAssignment.objects.filter(shift_id=shift_id).count(),
                'current_assignments': ShiftAssignment.objects.filter(shift_id=shift_id, is_current=True).count(),
                'upcoming_endings': ShiftAssignment.objects.filter(
                    shift_id=shift_id,
                    effective_to__gte=timezone.now().date(),
                    effective_to__lte=timezone.now().date() + timedelta(days=30)
                ).count()
            }
        except Exception as e:
            logger.warning(f"Could not load shift stats: {str(e)}")
            shift_stats = {
                'total_assignments': 0,
                'current_assignments': 0,
                'upcoming_endings': 0
            }

        # Convert service data to object for template
        class ShiftDetailObject:
            def __init__(self, data):
                self.id = data['id']
                self.name = data['name']
                self.description = data.get('description', '')
                self.start_time = datetime.strptime(data['start_time'], '%H:%M').time()
                self.end_time = datetime.strptime(data['end_time'], '%H:%M').time()
                self.shift_duration = data['duration']
                self.work_days = data['work_days']
                self.custom_work_days = data.get('custom_work_days', '')
                self.is_active = data['is_active']
                self.break_duration = timedelta(minutes=data.get('break_minutes', 30))
                self.grace_period = timedelta(minutes=data.get('grace_minutes', 15))
                self.crosses_midnight = data.get('crosses_midnight', False)
                self.created_at = data.get('created_at')
                self.updated_at = data.get('updated_at')

            def get_work_days_display(self):
                work_days_map = {
                    'Weekdays': 'Monday to Friday',
                    'All Days': 'Monday to Saturday',
                    'Custom': 'Custom Days'
                }
                return work_days_map.get(self.work_days, self.work_days)

        shift = ShiftDetailObject(shift_data)

        # Edit form for modal - create from model instance for form compatibility
        edit_form = None
        if permissions['can_manage']:
            try:
                shift_model = ShiftMaster.objects.get(id=shift_id)
                edit_form = ShiftForm(instance=shift_model)
            except ShiftMaster.DoesNotExist:
                logger.warning(f"ShiftMaster model not found for ID {shift_id}")

        context = {
            'page_title': f'Shift: {shift.name}',
            'shift': shift,
            'assignments': assignments,
            'shift_stats': shift_stats,
            'edit_form': edit_form,
            **permissions,
        }

        return render(request, 'shift/shift_detail.html', context)

    except Exception as e:
        logger.error(f"Error in shift detail: {str(e)}", exc_info=True)
        messages.error(request, f"Error loading shift details: {str(e)}")
        return redirect('shift:list')



@transaction.atomic
@login_required
@group_required(group_names=['Manager', 'HR'])
@require_POST
@log_action('SHIFT_CREATE')
def create_shift(request):
    """Create a new shift and redirect to shift list."""
    form = ShiftForm(request.POST)

    if form.is_valid():
        try:
            with transaction.atomic():
                shift = form.save()
                log_db_operation('CREATE', 'ShiftMaster', shift.id, {'name': shift.name})
                log_user_action(request.user, 'shift_created', target=f'shift_{shift.id}',
                              details={'shift_name': shift.name})
                messages.success(request, f"Shift '{shift.name}' created successfully!")

        except Exception as e:
            logger.error(f"Error creating shift: {str(e)}", exc_info=True)
            log_user_action(request.user, 'shift_create_failed', details={'error': str(e)})
            messages.error(request, f"Error creating shift: {str(e)}")
    else:
        _handle_form_errors(request, form, 'shift_create')

    return redirect('shift:list')


@login_required
@group_required(group_names=['Manager', 'HR'])
@require_POST
@log_action('SHIFT_UPDATE')
def update_shift(request, shift_id):
    """Update an existing shift and redirect to shift list."""
    shift = get_object_or_404(ShiftMaster, id=shift_id)

    # Store original values for comparison
    original_values = {
        'name': shift.name,
        'start_time': shift.start_time,
        'end_time': shift.end_time
    }

    form = ShiftForm(request.POST, instance=shift)

    if form.is_valid():
        try:
            with transaction.atomic():
                updated_shift = form.save()

                # Log what changed
                changes = {}
                for field, old_value in original_values.items():
                    new_value = getattr(updated_shift, field)
                    if old_value != new_value:
                        changes[field] = {'old': str(old_value), 'new': str(new_value)}

                log_db_operation('UPDATE', 'ShiftMaster', shift_id, changes)
                log_user_action(request.user, 'shift_updated', target=f'shift_{shift_id}',
                              details={'shift_name': updated_shift.name, 'changes': changes})
                messages.success(request, f"Shift '{updated_shift.name}' updated successfully!")

        except Exception as e:
            logger.error(f"Error updating shift {shift_id}: {str(e)}", exc_info=True)
            log_user_action(request.user, 'shift_update_failed', target=f'shift_{shift_id}',
                          details={'error': str(e)})
            messages.error(request, f"Error updating shift: {str(e)}")
    else:
        _handle_form_errors(request, form, 'shift_update')

    return redirect('shift:detail', shift_id=shift_id)


@login_required
@group_required(group_names=['Manager', 'HR'])
@require_POST
@log_action('SHIFT_DELETE')
def delete_shift(request, shift_id):
    """Delete a shift and redirect to shift list."""
    try:
        shift = get_object_or_404(ShiftMaster, id=shift_id)
        shift_name = shift.name
        force_delete = request.POST.get('force', 'false').lower() == 'true'

        log_user_action(request.user, 'shift_delete_attempt', target=f'shift_{shift_id}',
                      details={'shift_name': shift_name, 'force_delete': force_delete})

        success, message = shift_service.delete_shift(shift_id, force=force_delete)

        if success:
            log_db_operation('DELETE', 'ShiftMaster', shift_id,
                           {'name': shift_name, 'force': force_delete})
            log_user_action(request.user, 'shift_deleted', target=f'shift_{shift_id}',
                          details={'shift_name': shift_name, 'force_delete': force_delete})
            messages.success(request, message)
        else:
            log_user_action(request.user, 'shift_delete_failed', target=f'shift_{shift_id}',
                          details={'shift_name': shift_name, 'reason': message})
            messages.error(request, message)

    except Exception as e:
        logger.error(f"Error deleting shift {shift_id}: {str(e)}", exc_info=True)
        log_user_action(request.user, 'shift_delete_error', target=f'shift_{shift_id}',
                      details={'error': str(e)})
        messages.error(request, f"Error deleting shift: {str(e)}")

    return redirect('shift:list')


# ============================
# ASSIGNMENT MANAGEMENT VIEWS
# ============================

@login_required
@group_required(group_names=['Manager', 'HR'])
@log_action('ASSIGNMENT_LIST_VIEW')
def assignment_list(request):
    """List shift assignments with filtering and inline assignment forms."""
    try:
        permissions = _get_user_permissions(request.user)
        log_user_action(request.user, 'assignment_list_access')

        # Handle filters
        filter_form = AssignmentFilterForm(request.GET or None)
        filters = {}

        if filter_form.is_valid():
            if filter_form.cleaned_data.get('user'):
                filters['user_id'] = filter_form.cleaned_data['user'].id
            if filter_form.cleaned_data.get('shift'):
                filters['shift_id'] = filter_form.cleaned_data['shift'].id
            if filter_form.cleaned_data.get('status'):
                status = filter_form.cleaned_data['status']
                if status == 'current':
                    filters['is_current'] = True
                elif status == 'ended':
                    filters['is_current'] = False
                    filters['effective_to__lt'] = timezone.now().date()
            if filter_form.cleaned_data.get('date_from'):
                filters['effective_from__gte'] = filter_form.cleaned_data['date_from']
            if filter_form.cleaned_data.get('date_to'):
                filters['effective_to__lte'] = filter_form.cleaned_data['date_to']

        # Restrict employees to their own assignments
        if not permissions.get('can_view_all', False):
            filters['user_id'] = request.user.id
            log_user_action(request.user, 'assignment_list_restricted_to_own')

        # Get paginated assignments
        page = int(request.GET.get('page', 1))
        per_page = int(request.GET.get('per_page', 20))

        assignments_data = shift_service.get_shift_assignments(
            filters=filters, page=page, per_page=per_page
        )

        # Create forms for modals with error handling
        assign_form = None
        bulk_assign_form = None
        csv_form = None
        users_data = []

        if permissions.get('can_assign', False):
            try:
                assign_form = ShiftAssignmentForm()
            except Exception as e:
                logger.error(f"Error creating assign form: {str(e)}")

            try:
                bulk_assign_form = BulkAssignmentForm()

                # Prepare user data for bulk assignment with groups
                if bulk_assign_form and bulk_assign_form.fields['users'].queryset.exists():
                    for user in bulk_assign_form.fields['users'].queryset.select_related().prefetch_related('groups'):
                        try:
                            user_groups = [group.name for group in user.groups.all()]
                            full_name = f"{user.first_name or ''} {user.last_name or ''}".strip()
                            display_name = full_name if full_name else user.username

                            users_data.append({
                                'id': user.id,
                                'username': user.username,
                                'first_name': user.first_name or '',
                                'last_name': user.last_name or '',
                                'display_name': display_name,
                                'email': user.email or '',
                                'groups': user_groups,  # Array of group names
                                'groups_string': ', '.join(user_groups) if user_groups else ''
                            })
                        except Exception as e:
                            logger.error(f"Error processing user {user.id}: {str(e)}")
                            continue

                # Convert to JSON string for template
                users_data_json = json.dumps(users_data)

            except Exception as e:
                logger.error(f"Error creating bulk assign form: {str(e)}")
                users_data_json = "[]"
        else:
            users_data_json = "[]"

        try:
            csv_form = CSVUploadForm()
        except Exception as e:
            logger.error(f"Error creating CSV form: {str(e)}")

        context = {
            'page_title': 'Shift Assignments',
            'assignments_data': assignments_data,
            'filter_form': filter_form,
            'assign_form': assign_form,
            'bulk_assign_form': bulk_assign_form,
            'csv_form': csv_form,
            'users_data': users_data,
            'users_data_json': users_data_json,
        }

        # Add permissions to context
        context.update(permissions)

        return render(request, 'shift/assignment_list.html', context)

    except Exception as e:
        logger.error(f"Error in assignment list: {str(e)}", exc_info=True)
        log_user_action(request.user, 'assignment_list_error', details={'error': str(e)})
        messages.error(request, f"Error loading assignments: {str(e)}")

        # Return a minimal context to prevent template errors
        context = {
            'page_title': 'Shift Assignments',
            'assignments_data': {'assignments': [], 'total_count': 0, 'has_other_pages': False},
            'filter_form': AssignmentFilterForm(),
            'users_data': [],
            'users_data_json': "[]",
            'error': True,
            'can_assign': False,
            'can_view_all': False,
        }
        return render(request, 'shift/assignment_list.html', context)




@login_required
@group_required(group_names=['Manager', 'HR'])
@require_POST
@log_action('ASSIGN_SHIFT')
def assign_shift(request):
    """Assign shift to user and redirect to assignment list."""
    form = ShiftAssignmentForm(request.POST)

    if form.is_valid():
        try:
            user = form.cleaned_data['user']
            shift = form.cleaned_data['shift']
            effective_from = form.cleaned_data['effective_from']
            effective_to = form.cleaned_data.get('effective_to')

            assignment_details = {
                'target_user': user.username,
                'target_user_id': user.id,
                'shift_name': shift.name,
                'shift_id': shift.id,
                'effective_from': str(effective_from),
                'effective_to': str(effective_to) if effective_to else None
            }

            success, result = shift_service.assign_shift_to_user(
                user.id, shift.id, effective_from, effective_to
            )

            if success:
                log_db_operation('CREATE', 'ShiftAssignment',
                               result.id if hasattr(result, 'id') else None, assignment_details)
                log_user_action(request.user, 'shift_assigned', target=f'user_{user.id}',
                              details=assignment_details)
                messages.success(request, f"Shift '{shift.name}' assigned to {user.username} successfully!")
            else:
                log_user_action(request.user, 'shift_assignment_failed', details={**assignment_details, 'reason': result})
                messages.error(request, f"Assignment failed: {result}")

        except Exception as e:
            logger.error(f"Error assigning shift: {str(e)}", exc_info=True)
            log_user_action(request.user, 'shift_assignment_error', details={'error': str(e)})
            messages.error(request, f"Error assigning shift: {str(e)}")
    else:
        _handle_form_errors(request, form, 'shift_assignment')

    return redirect('shift:assignments')


@login_required
@group_required(group_names=['Manager', 'HR'])
@require_POST
@log_action('BULK_ASSIGN_SHIFT')
def bulk_assign_shift(request):
    """Bulk assign shift to multiple users and redirect to assignment list."""
    form = BulkAssignmentForm(request.POST)

    if form.is_valid():
        try:
            users = form.cleaned_data['users']
            shift = form.cleaned_data['shift']
            effective_from = form.cleaned_data['effective_from']
            effective_to = form.cleaned_data.get('effective_to')

            bulk_details = {
                'target_users': [{'id': user.id, 'username': user.username} for user in users],
                'user_count': len(users),
                'shift_name': shift.name,
                'shift_id': shift.id,
                'effective_from': str(effective_from),
                'effective_to': str(effective_to) if effective_to else None
            }

            user_ids = [user.id for user in users]
            success_count, error_count, errors = shift_service.assign_shifts_to_users(
                user_ids, shift.id, effective_from, effective_to
            )

            if success_count > 0:
                log_db_operation('BULK_CREATE', 'ShiftAssignment', None,
                               {**bulk_details, 'success_count': success_count})
                messages.success(request, f"Successfully assigned shift to {success_count} users!")

            if error_count > 0:
                error_msg = f"{error_count} assignments failed. Errors: {'; '.join(errors[:3])}"
                if len(errors) > 3:
                    error_msg += f" and {len(errors) - 3} more..."
                messages.error(request, error_msg)

            log_user_action(request.user, 'bulk_assignment_completed',
                          details={**bulk_details, 'success_count': success_count,
                                 'error_count': error_count, 'errors': errors[:5]})

        except Exception as e:
            logger.error(f"Error in bulk assignment: {str(e)}")
            messages.error(request, f"Error in bulk assignment: {str(e)}")
    else:
        _handle_form_errors(request, form, 'bulk_assignment')

    return redirect('shift:assignments')


@login_required
@group_required(group_names=['Manager', 'HR'])
@require_POST
@log_action('CSV_UPLOAD_ASSIGNMENTS')
def csv_upload_assignments(request):
    """Upload CSV file for bulk assignments and redirect to results."""
    form = CSVUploadForm(request.POST, request.FILES)

    if form.is_valid():
        try:
            csv_file = form.cleaned_data['csv_file']
            file_details = {
                'filename': csv_file.name,
                'size': csv_file.size,
                'content_type': csv_file.content_type
            }
            log_user_action(request.user, 'csv_file_processing', details=file_details)

            results = shift_service.assign_shifts_from_csv(csv_file)

            result_details = {
                'filename': csv_file.name,
                'success_count': results.get('success_count', 0),
                'error_count': results.get('error_count', 0),
                'total_processed': results.get('success_count', 0) + results.get('error_count', 0),
                'errors': results.get('errors', [])[:5]
            }

            if results['success']:
                log_user_action(request.user, 'csv_import_success', details=result_details)
                messages.success(request, f"CSV import completed successfully! {results['success_count']} assignments created.")
            else:
                log_user_action(request.user, 'csv_import_partial_success', details=result_details)
                messages.warning(request, f"CSV import completed with issues. {results['success_count']} successful, {results['error_count']} failed.")

            # Store results in session for detailed view
            request.session['csv_import_results'] = results
            return redirect('shift:csv_results')

        except Exception as e:
            logger.error(f"Error in CSV upload: {str(e)}", exc_info=True)
            log_user_action(request.user, 'csv_upload_error', details={'error': str(e)})
            messages.error(request, f"Error processing CSV: {str(e)}")
    else:
        _handle_form_errors(request, form, 'csv_upload')

    return redirect('shift:assignments')


@login_required
@group_required(group_names=['Manager', 'HR'])
@log_action('CSV_IMPORT_RESULTS_VIEW')
def csv_import_results(request):
    """Show results of CSV import."""
    results = request.session.get('csv_import_results')
    if not results:
        log_user_action(request.user, 'csv_results_not_found')
        messages.error(request, "No import results found.")
        return redirect('shift:assignments')

    results_summary = {
        'success_count': results.get('success_count', 0),
        'error_count': results.get('error_count', 0),
        'has_errors': bool(results.get('errors', []))
    }
    log_user_action(request.user, 'csv_results_viewed', details=results_summary)

    # Clear results from session
    request.session.pop('csv_import_results', None)

    context = {
        'page_title': 'CSV Import Results',
        'results': results,
    }

    return render(request, 'shift/csv_results.html', context)


@login_required
@group_required(group_names=['Manager', 'HR'])
@require_POST
@log_action('END_ASSIGNMENT')
def end_assignment(request, assignment_id):
    """End a shift assignment and redirect to assignment list."""
    try:
        assignment = get_object_or_404(ShiftAssignment, id=assignment_id)
        end_date_str = request.POST.get('end_date')
        end_date = None

        assignment_details = {
            'assignment_id': assignment_id,
            'user': assignment.user.username,
            'user_id': assignment.user.id,
            'shift_name': assignment.shift.name,
            'shift_id': assignment.shift.id,
            'original_end_date': str(assignment.effective_to) if assignment.effective_to else None
        }

        if end_date_str:
            end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()
            assignment_details['new_end_date'] = str(end_date)

        log_user_action(request.user, 'assignment_end_attempt',
                       target=f'assignment_{assignment_id}', details=assignment_details)

        success, message = shift_service.end_shift_assignment(assignment_id, end_date)

        if success:
            log_db_operation('UPDATE', 'ShiftAssignment', assignment_id,
                           {'end_date': str(end_date) if end_date else 'today'})
            log_user_action(request.user, 'assignment_ended',
                           target=f'assignment_{assignment_id}', details=assignment_details)
            messages.success(request, message)
        else:
            log_user_action(request.user, 'assignment_end_failed',
                           target=f'assignment_{assignment_id}',
                           details={**assignment_details, 'reason': message})
            messages.error(request, message)

    except Exception as e:
        logger.error(f"Error ending assignment {assignment_id}: {str(e)}", exc_info=True)
        log_user_action(request.user, 'assignment_end_error',
                       target=f'assignment_{assignment_id}', details={'error': str(e)})
        messages.error(request, f"Error ending assignment: {str(e)}")

    return redirect('shift:assignments')


# ============================
# CALENDAR AND SCHEDULE VIEWS
# ============================

@login_required
@group_required(group_names=['Manager', 'Employee', 'HR'])
@log_action('USER_SHIFT_CALENDAR_VIEW')
def user_shift_calendar(request, user_id=None):
    """Show shift calendar for a user."""
    try:
        permissions = _get_user_permissions(request.user)

        # Default to current user if no user_id provided
        if user_id is None:
            user = request.user
            log_user_action(request.user, 'calendar_view_own')
        else:
            # Only managers and HR can view other users' calendars
            if not permissions['can_view_all']:
                if user_id != request.user.id:
                    log_user_action(request.user, 'calendar_access_denied',
                                   target=f'user_{user_id}', details={'reason': 'insufficient_permissions'})
                    messages.error(request, "You can only view your own calendar.")
                    return redirect('shift:user_calendar')
            user = get_object_or_404(User, id=user_id)
            log_user_action(request.user, 'calendar_view_other',
                           target=f'user_{user_id}', details={'target_username': user.username})

        # Get month and year from query params
        try:
            month = int(request.GET.get('month', timezone.now().month))
            year = int(request.GET.get('year', timezone.now().year))
        except (ValueError, TypeError):
            month = timezone.now().month
            year = timezone.now().year

        # Validate month and year
        if not (1 <= month <= 12) or not (2020 <= year <= 2030):
            month = timezone.now().month
            year = timezone.now().year

        calendar_data = shift_service.get_user_shift_calendar(user, month, year)
        log_user_action(request.user, 'calendar_data_loaded',
                       details={'target_user': user.username, 'month': month, 'year': year})

        # Get navigation dates
        prev_month = month - 1 if month > 1 else 12
        prev_year = year if month > 1 else year - 1
        next_month = month + 1 if month < 12 else 1
        next_year = year if month < 12 else year + 1

        context = {
            'page_title': f'Calendar - {user.get_full_name() or user.username}',
            'calendar_data': calendar_data,
            'target_user': user,
            'current_month': month,
            'current_year': year,
            'prev_month': prev_month,
            'prev_year': prev_year,
            'next_month': next_month,
            'next_year': next_year,
            'is_own_calendar': user == request.user,
            **permissions,
        }

        return render(request, 'shift/user_calendar.html', context)

    except Exception as e:
        logger.error(f"Error in user calendar: {str(e)}")
        messages.error(request, "Error loading calendar.")
        return redirect('shift:dashboard')


@login_required
@group_required(group_names=['Manager', 'HR'])
@log_action('SHIFT_SCHEDULE_VIEW')
def shift_schedule_view(request):
    """Show who's on shift for a specific date (managers and HR only)."""
    try:
        # Get date from query params
        date_str = request.GET.get('date')
        if date_str:
            try:
                target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            except ValueError:
                target_date = timezone.now().date()
                log_user_action(request.user, 'schedule_view_invalid_date', details={'invalid_date': date_str})
                messages.warning(request, "Invalid date format. Showing today's schedule.")
        else:
            target_date = timezone.now().date()

        log_user_action(request.user, 'schedule_view_access', details={'target_date': str(target_date)})
        schedule_data = shift_service.get_shift_schedule_for_date(target_date)

        context = {
            'page_title': f'Schedule - {target_date.strftime("%B %d, %Y")}',
            'schedule_data': schedule_data,
            'target_date': target_date,
        }

        return render(request, 'shift/schedule_view.html', context)

    except Exception as e:
        logger.error(f"Error in schedule view: {str(e)}", exc_info=True)
        log_user_action(request.user, 'schedule_view_error', details={'error': str(e)})
        messages.error(request, "Error loading schedule.")
        return redirect('shift:dashboard')


# ============================
# HOLIDAY MANAGEMENT VIEWS
# ============================

@login_required
@group_required(group_names=['Manager', 'HR'])
@log_action('HOLIDAY_LIST_VIEW')
def holiday_list(request):
    """List all holidays with inline create form."""
    try:
        permissions = _get_user_permissions(request.user)
        year = request.GET.get('year')
        if year:
            try:
                year = int(year)
            except ValueError:
                log_user_action(request.user, 'holiday_list_invalid_year', details={'invalid_year': year})
                year = None

        log_user_action(request.user, 'holiday_list_access', details={'year': year})
        holidays = shift_service.get_holidays(year=year)

        # Create form for modal
        create_form = HolidayForm()

        # Calculate recurring holidays count
        recurring_count = sum(1 for holiday in holidays if holiday.get('recurring_yearly', False))

        context = {
            'page_title': 'Holidays',
            'holidays': holidays,
            'recurring_count': recurring_count,
            'current_year': year or timezone.now().year,
            'available_years': range(2020, 2031),
            'create_form': create_form,
            **permissions,
        }

        return render(request, 'shift/holiday_list.html', context)

    except Exception as e:
        logger.error(f"Error in holiday list: {str(e)}", exc_info=True)
        log_user_action(request.user, 'holiday_list_error', details={'error': str(e)})
        messages.error(request, "Error loading holidays.")
        return render(request, 'shift/holiday_list.html', {'error': True})


@login_required
@group_required(group_names=['Manager', 'HR'])
@require_POST
@log_action('CREATE_HOLIDAY')
def create_holiday(request):
    """Create a new holiday and redirect to holiday list."""
    form = HolidayForm(request.POST)

    if form.is_valid():
        try:
            holiday_data = {
                'name': form.cleaned_data['name'],
                'date': form.cleaned_data['date'],
                'recurring_yearly': form.cleaned_data['recurring_yearly']
            }

            success, result = shift_service.create_holiday(holiday_data)

            if success:
                log_db_operation('CREATE', 'Holiday', result.id if hasattr(result, 'id') else None, holiday_data)
                log_user_action(request.user, 'holiday_created', target=f'holiday_{result.id}', details=holiday_data)
                messages.success(request, f"Holiday '{result.name}' created successfully!")
            else:
                log_user_action(request.user, 'holiday_create_failed', details={**holiday_data, 'reason': result})
                messages.error(request, f"Error creating holiday: {result}")

        except Exception as e:
            logger.error(f"Error creating holiday: {str(e)}", exc_info=True)
            log_user_action(request.user, 'holiday_create_error', details={'error': str(e)})
            messages.error(request, f"Error creating holiday: {str(e)}")
    else:
        _handle_form_errors(request, form, 'holiday_create')

    return redirect('shift:holidays')


@login_required
@group_required(group_names=['Manager', 'HR'])
@require_POST
@log_action('DELETE_HOLIDAY')
def delete_holiday(request, holiday_id):
    """Delete a holiday and redirect to holiday list."""
    try:
        holiday = get_object_or_404(Holiday, id=holiday_id)
        holiday_name = holiday.name

        log_user_action(request.user, 'holiday_delete_attempt', target=f'holiday_{holiday_id}',
                       details={'holiday_name': holiday_name})

        holiday.delete()
        log_db_operation('DELETE', 'Holiday', holiday_id, {'name': holiday_name})
        log_user_action(request.user, 'holiday_deleted', target=f'holiday_{holiday_id}',
                       details={'holiday_name': holiday_name})
        messages.success(request, f"Holiday '{holiday_name}' deleted successfully!")

    except Exception as e:
        logger.error(f"Error deleting holiday {holiday_id}: {str(e)}", exc_info=True)
        log_user_action(request.user, 'holiday_delete_error', target=f'holiday_{holiday_id}',
                       details={'error': str(e)})
        messages.error(request, f"Error deleting holiday: {str(e)}")

    return redirect('shift:holidays')


# ============================
# API ENDPOINTS
# ============================

@login_required
@group_required(group_names=['Manager', 'Employee', 'HR'])
@log_action('API_SHIFT_DETAILS')
def api_shift_details(request, shift_id):
    """API endpoint to get shift details."""
    try:
        log_user_action(request.user, 'api_shift_details_request', target=f'shift_{shift_id}')
        shift = get_object_or_404(ShiftMaster, id=shift_id)

        # Get current assignments
        current_assignments = ShiftAssignment.objects.filter(
            shift=shift, is_current=True
        ).select_related('user').values(
            'user__id', 'user__username', 'user__first_name', 'user__last_name',
            'effective_from', 'effective_to'
        )

        data = {
            'id': shift.id,
            'name': shift.name,
            'start_time': shift.start_time.strftime('%H:%M'),
            'end_time': shift.end_time.strftime('%H:%M'),
            'duration': float(shift.shift_duration),
            'work_days': shift.work_days,
            'custom_work_days': shift.custom_work_days,
            'is_active': shift.is_active,
            'crosses_midnight': shift.crosses_midnight,
            'expected_hours': shift.expected_hours,
            'break_minutes': int(shift.break_duration.total_seconds() // 60),
            'grace_minutes': int(shift.grace_period.total_seconds() // 60),
            'current_assignments': list(current_assignments),
            'assignment_count': len(current_assignments)
        }

        log_user_action(request.user, 'api_shift_details_success', target=f'shift_{shift_id}',
                       details={'assignment_count': len(current_assignments)})

        return JsonResponse({'status': 'success', 'data': data})

    except Exception as e:
        logger.error(f"Error in API shift details for shift {shift_id}: {str(e)}", exc_info=True)
        log_user_action(request.user, 'api_shift_details_error', target=f'shift_{shift_id}',
                       details={'error': str(e)})
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@group_required(group_names=['Manager', 'Employee', 'HR'])
@log_action('API_USER_ASSIGNMENTS')
def api_user_assignments(request, user_id):
    """API endpoint to get user's shift assignments."""
    try:
        permissions = _get_user_permissions(request.user)
        log_user_action(request.user, 'api_user_assignments_request', target=f'user_{user_id}')

        # Check permissions
        if not permissions['can_view_all']:
            if user_id != request.user.id:
                log_user_action(request.user, 'api_user_assignments_permission_denied', target=f'user_{user_id}')
                return JsonResponse({'status': 'error', 'message': 'Permission denied'}, status=403)

        user = get_object_or_404(User, id=user_id)

        # Get assignments
        assignments = shift_service.get_shift_assignments(
            filters={'user_id': user_id}, page=1, per_page=50
        )

        data = {
            'user': {
                'id': user.id,
                'username': user.username,
                'full_name': user.get_full_name(),
                'email': user.email
            },
            'assignments': assignments['assignments']
        }

        log_user_action(request.user, 'api_user_assignments_success', target=f'user_{user_id}',
                       details={'assignment_count': len(assignments['assignments'])})

        return JsonResponse({'status': 'success', 'data': data})

    except Exception as e:
        logger.error(f"Error in API user assignments for user {user_id}: {str(e)}", exc_info=True)
        log_user_action(request.user, 'api_user_assignments_error', target=f'user_{user_id}',
                       details={'error': str(e)})
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@group_required(group_names=['Manager', 'HR'])
@log_action('API_UPCOMING_CHANGES')
def api_upcoming_changes(request):
    """API endpoint to get upcoming shift changes."""
    try:
        days = int(request.GET.get('days', 7))
        log_user_action(request.user, 'api_upcoming_changes_request', details={'days': days})

        changes = shift_service.get_upcoming_shift_changes(days=days)

        log_user_action(request.user, 'api_upcoming_changes_success',
                       details={'days': days, 'change_count': len(changes)})

        return JsonResponse({'status': 'success', 'data': changes})

    except Exception as e:
        logger.error(f"Error in API upcoming changes: {str(e)}", exc_info=True)
        log_user_action(request.user, 'api_upcoming_changes_error', details={'error': str(e)})
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@group_required(group_names=['Manager', 'Employee', 'HR'])
@log_action('API_USER_SHIFT_STATUS')
def api_user_shift_status(request, user_id=None):
    """API endpoint to check if user is currently on shift."""
    try:
        permissions = _get_user_permissions(request.user)

        # Default to current user
        if user_id is None:
            user = request.user
            log_user_action(request.user, 'api_shift_status_request_own')
        else:
            # Check permissions
            if not permissions['can_view_all']:
                if user_id != request.user.id:
                    log_user_action(request.user, 'api_shift_status_permission_denied', target=f'user_{user_id}')
                    return JsonResponse({'status': 'error', 'message': 'Permission denied'}, status=403)
            user = get_object_or_404(User, id=user_id)
            log_user_action(request.user, 'api_shift_status_request_other', target=f'user_{user_id}',
                           details={'target_username': user.username})

        shift_status = shift_service.is_user_on_shift_now(user)

        log_user_action(request.user, 'api_shift_status_success',
                       target=f'user_{user.id}' if user_id else None,
                       details={'target_user': user.username, 'on_shift': shift_status.get('on_shift', False)})

        return JsonResponse({'status': 'success', 'data': shift_status})

    except Exception as e:
        logger.error(f"Error in API user shift status for user {user_id or 'self'}: {str(e)}", exc_info=True)
        log_user_action(request.user, 'api_shift_status_error',
                       target=f'user_{user_id}' if user_id else None, details={'error': str(e)})
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@group_required(group_names=['Manager', 'HR'])
@log_action('API_SCHEDULE_FOR_DATE')
def api_schedule_for_date(request):
    """API endpoint to get schedule for a specific date."""
    try:
        date_str = request.GET.get('date')
        if not date_str:
            log_user_action(request.user, 'api_schedule_missing_date')
            return JsonResponse({'status': 'error', 'message': 'Date parameter is required'}, status=400)

        try:
            target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            log_user_action(request.user, 'api_schedule_invalid_date', details={'invalid_date': date_str})
            return JsonResponse({'status': 'error', 'message': 'Invalid date format. Use YYYY-MM-DD'}, status=400)

        log_user_action(request.user, 'api_schedule_request', details={'target_date': str(target_date)})
        schedule_data = shift_service.get_shift_schedule_for_date(target_date)

        log_user_action(request.user, 'api_schedule_success', details={'target_date': str(target_date)})

        return JsonResponse({'status': 'success', 'data': schedule_data})

    except Exception as e:
        logger.error(f"Error in API schedule for date {date_str}: {str(e)}", exc_info=True)
        log_user_action(request.user, 'api_schedule_error', details={'target_date': date_str, 'error': str(e)})
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@group_required(group_names=['Manager', 'Employee', 'HR'])
@log_action('API_IS_HOLIDAY')
def api_is_holiday(request):
    """API endpoint to check if a date is a holiday."""
    try:
        date_str = request.GET.get('date')
        if not date_str:
            target_date = timezone.now().date()
            log_user_action(request.user, 'api_holiday_check_today')
        else:
            try:
                target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                log_user_action(request.user, 'api_holiday_check_date', details={'target_date': str(target_date)})
            except ValueError:
                log_user_action(request.user, 'api_holiday_invalid_date', details={'invalid_date': date_str})
                return JsonResponse({'status': 'error', 'message': 'Invalid date format. Use YYYY-MM-DD'}, status=400)

        is_holiday = shift_service.is_holiday(target_date)
        holiday_info = None

        if is_holiday:
            from django.db import models
            holiday = Holiday.objects.filter(
                models.Q(date=target_date) |
                models.Q(recurring_yearly=True, date__month=target_date.month, date__day=target_date.day)
            ).first()
            if holiday:
                holiday_info = {
                    'name': holiday.name,
                    'date': holiday.date,
                    'recurring_yearly': holiday.recurring_yearly
                }

        data = {
            'date': target_date,
            'is_holiday': is_holiday,
            'holiday_info': holiday_info
        }

        log_user_action(request.user, 'api_holiday_check_success',
                       details={'target_date': str(target_date), 'is_holiday': is_holiday,
                               'holiday_name': holiday_info['name'] if holiday_info else None})

        return JsonResponse({'status': 'success', 'data': data})

    except Exception as e:
        logger.error(f"Error in API holiday check for {date_str or 'today'}: {str(e)}", exc_info=True)
        log_user_action(request.user, 'api_holiday_check_error',
                       details={'target_date': date_str or 'today', 'error': str(e)})
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


# ============================
# ENHANCED API ENDPOINTS FOR SUGGESTIONS SYSTEM
# ============================

@login_required
@require_http_methods(["GET"])
def api_suggestions(request):
    """API endpoint for getting shift management suggestions."""
    try:
        suggestions_data = generate_shift_suggestions(request.user)

        log_user_action(request.user, 'api_suggestions_retrieved',
                       details={'suggestion_count': suggestions_data['count']})

        return JsonResponse({
            'status': 'success',
            'suggestions': suggestions_data['suggestions'],
            'count': suggestions_data['count']
        })

    except Exception as e:
        logger.error(f"Error retrieving suggestions: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Failed to retrieve suggestions'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def api_dismiss_suggestion(request, suggestion_id):
    """API endpoint for dismissing a suggestion."""
    try:
        # For now, just log the dismissal
        # In a full implementation, you'd store dismissed suggestions in the database
        log_user_action(request.user, 'suggestion_dismissed',
                       details={'suggestion_id': suggestion_id})

        return JsonResponse({
            'status': 'success',
            'message': 'Suggestion dismissed successfully'
        })

    except Exception as e:
        logger.error(f"Error dismissing suggestion: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Failed to dismiss suggestion'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def api_validate_shift_name(request):
    """API endpoint for validating shift name uniqueness."""
    try:
        name = request.GET.get('name', '').strip()
        original_name = request.GET.get('original_name', '').strip()

        if not name:
            return JsonResponse({
                'status': 'error',
                'message': 'Shift name is required'
            })

        # Check for duplicates
        existing_query = ShiftMaster.objects.filter(name__iexact=name)
        if original_name and original_name.lower() != name.lower():
            # Editing existing shift, exclude original
            existing_query = existing_query.exclude(name__iexact=original_name)

        is_available = not existing_query.exists()

        return JsonResponse({
            'status': 'success',
            'is_available': is_available,
            'message': 'Name is available' if is_available else 'Name already exists'
        })

    except Exception as e:
        logger.error(f"Error validating shift name: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Validation error'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def api_validate_user_assignment(request):
    """API endpoint for validating user assignment conflicts."""
    try:
        user_id = request.GET.get('user_id')
        shift_id = request.GET.get('shift_id')
        effective_from = request.GET.get('effective_from')
        effective_to = request.GET.get('effective_to')

        if not all([user_id, shift_id, effective_from]):
            return JsonResponse({
                'status': 'error',
                'message': 'Missing required parameters'
            })

        # Parse dates
        from datetime import datetime
        effective_from_date = datetime.strptime(effective_from, '%Y-%m-%d').date()
        effective_to_date = None
        if effective_to:
            effective_to_date = datetime.strptime(effective_to, '%Y-%m-%d').date()

        # Validate assignment
        is_valid, message, details = shift_service.validate_shift_assignment(
            int(user_id), int(shift_id), effective_from_date, effective_to_date
        )

        return JsonResponse({
            'status': 'success',
            'is_valid': is_valid,
            'message': message,
            'details': details
        })

    except Exception as e:
        logger.error(f"Error validating user assignment: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Validation error'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def api_shift_recommendations(request, shift_id):
    """API endpoint for getting shift-specific recommendations."""
    try:
        shift = get_object_or_404(ShiftMaster, id=shift_id)

        recommendations = []

        # Check shift utilization
        assignment_count = ShiftAssignment.objects.filter(
            shift=shift, is_current=True
        ).count()

        if assignment_count == 0:
            recommendations.append({
                'type': 'warning',
                'title': 'Unused Shift',
                'message': 'This shift has no current assignments.'
            })

        # Check break duration
        if shift.shift_duration >= 8 and shift.break_duration.total_seconds() < 1800:  # 30 min
            recommendations.append({
                'type': 'suggestion',
                'title': 'Consider Longer Break',
                'message': 'For 8+ hour shifts, consider at least 30 minutes break time.'
            })

        # Check grace period
        if shift.grace_period.total_seconds() < 300:  # 5 min
            recommendations.append({
                'type': 'suggestion',
                'title': 'Grace Period',
                'message': 'Consider adding a grace period for better attendance flexibility.'
            })

        return JsonResponse({
            'status': 'success',
            'recommendations': recommendations
        })

    except Exception as e:
        logger.error(f"Error getting shift recommendations: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Failed to get recommendations'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def api_dashboard_stats(request):
    """API endpoint for refreshing dashboard statistics."""
    try:
        if not (request.user.is_superuser or request.user.groups.filter(name__in=['Manager', 'HR']).exists()):
            return JsonResponse({
                'status': 'error',
                'message': 'Insufficient permissions'
            }, status=403)

        # Get comprehensive statistics
        total_shifts = ShiftMaster.objects.filter(is_active=True).count()
        active_shifts = ShiftMaster.objects.filter(is_active=True).count()
        users_with_shifts = ShiftAssignment.objects.filter(
            is_current=True
        ).values('user').distinct().count()

        total_users = User.objects.filter(is_active=True).count()
        users_without_shifts = total_users - users_with_shifts

        upcoming_changes = shift_service.get_upcoming_shift_changes(days=7)
        suggestions_data = generate_shift_suggestions(request.user)

        stats = {
            'total_shifts': total_shifts,
            'active_shifts': active_shifts,
            'users_with_shifts': users_with_shifts,
            'users_without_shifts': users_without_shifts,
            'utilization_rate': round((users_with_shifts / max(total_users, 1)) * 100, 1),
            'upcoming_changes_count': len(upcoming_changes),
            'suggestions_count': suggestions_data['count']
        }

        return JsonResponse({
            'status': 'success',
            'stats': stats,
            'last_updated': timezone.now().isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting dashboard stats: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Failed to get statistics'
        }, status=500)


@login_required
@require_http_methods(["POST"])
def api_bulk_assignment_validation(request):
    """API endpoint for validating bulk shift assignments."""
    try:
        import json
        data = json.loads(request.body)

        assignments = data.get('assignments', [])
        results = []

        for assignment in assignments:
            user_id = assignment.get('user_id')
            shift_id = assignment.get('shift_id')
            effective_from = assignment.get('effective_from')
            effective_to = assignment.get('effective_to')

            if not all([user_id, shift_id, effective_from]):
                results.append({
                    'user_id': user_id,
                    'is_valid': False,
                    'message': 'Missing required fields'
                })
                continue

            # Parse dates
            from datetime import datetime
            effective_from_date = datetime.strptime(effective_from, '%Y-%m-%d').date()
            effective_to_date = None
            if effective_to:
                effective_to_date = datetime.strptime(effective_to, '%Y-%m-%d').date()

            # Validate assignment
            is_valid, message, details = shift_service.validate_shift_assignment(
                user_id, shift_id, effective_from_date, effective_to_date
            )

            results.append({
                'user_id': user_id,
                'is_valid': is_valid,
                'message': message,
                'details': details
            })

        return JsonResponse({
            'status': 'success',
            'results': results
        })

    except Exception as e:
        logger.error(f"Error in bulk assignment validation: {str(e)}")
        return JsonResponse({
            'status': 'error',
            'message': 'Bulk validation failed'
        }, status=500)


# ============================
# ERROR HANDLERS
# ============================


# ============================
# ERROR HANDLERS
# ============================

def handle_404(request, exception):
    """Custom 404 handler for shift app."""
    user = getattr(request, 'user', None)
    username = user.username if user and user.is_authenticated else 'anonymous'
    logger.warning(f"404 Error - Page not found for user {username}: {request.path}")
    log_user_action(user, '404_error', details={'path': request.path, 'method': request.method})

    context = {
        'error_title': 'Page Not Found',
        'error_message': 'The requested page could not be found.',
        'user_permissions': _get_user_permissions(request.user) if request.user.is_authenticated else {}
    }
    return render(request, 'shift/errors/404.html', context, status=404)


def handle_403(request, exception):
    """Custom 403 handler for shift app."""
    user = getattr(request, 'user', None)
    username = user.username if user and user.is_authenticated else 'anonymous'
    logger.warning(f"403 Error - Access denied for user {username}: {request.path}")
    log_user_action(user, '403_error', details={'path': request.path, 'method': request.method})

    context = {
        'error_title': 'Access Denied',
        'error_message': 'You do not have permission to access this page.',
        'user_permissions': _get_user_permissions(request.user) if request.user.is_authenticated else {}
    }
    return render(request, 'shift/errors/403.html', context, status=403)


def handle_500(request):
    """Custom 500 handler for shift app."""
    user = getattr(request, 'user', None)
    username = user.username if user and user.is_authenticated else 'anonymous'
    logger.error(f"500 Error - Internal server error for user {username}: {request.path}")
    log_user_action(user, '500_error', details={'path': request.path, 'method': request.method})

    context = {
        'error_title': 'Server Error',
        'error_message': 'An internal server error occurred. Please try again later.',
        'user_permissions': _get_user_permissions(request.user) if request.user.is_authenticated else {}
    }
    return render(request, 'shift/errors/500.html', context, status=500)


# ============================
# API ENDPOINTS FOR AJAX
# ============================

@login_required
@require_http_methods(["GET"])
def shift_api(request, shift_id):
    """API endpoint to get shift data as JSON."""
    try:
        shift = get_object_or_404(ShiftMaster, id=shift_id)

        data = {
            'success': True,
            'shift': {
                'id': shift.id,
                'name': shift.name,
                'description': shift.description or '',
                'start_time': shift.start_time.strftime('%H:%M'),
                'end_time': shift.end_time.strftime('%H:%M'),
                'duration': float(shift.shift_duration),
                'work_days': shift.work_days,
                'custom_work_days': shift.custom_work_days or '',
                'is_active': shift.is_active,
                'break_minutes': shift.break_duration.total_seconds() // 60 if shift.break_duration else 30,
                'grace_minutes': shift.grace_period.total_seconds() // 60 if shift.grace_period else 15,
                'priority': getattr(shift, 'priority', 2),
                'shift_color': getattr(shift, 'shift_color', 'blue'),
                'created_at': shift.created_at.isoformat(),
                'updated_at': shift.updated_at.isoformat(),
            }
        }

        return JsonResponse(data)

    except Exception as e:
        logger.error(f"Error in shift API: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@require_http_methods(["GET"])
def shift_assignments_api(request, shift_id):
    """API endpoint to get shift assignments as JSON."""
    try:
        shift = get_object_or_404(ShiftMaster, id=shift_id)

        assignments = ShiftAssignment.objects.filter(shift=shift).select_related('employee').order_by('-created_at')[:10]

        assignments_data = []
        for assignment in assignments:
            assignments_data.append({
                'id': assignment.id,
                'employee_name': f"{assignment.employee.first_name} {assignment.employee.last_name}",
                'employee_id': assignment.employee.employee_id,
                'effective_from': assignment.effective_from.isoformat(),
                'effective_to': assignment.effective_to.isoformat() if assignment.effective_to else None,
                'is_current': assignment.is_current,
                'priority': assignment.priority,
            })

        return JsonResponse({
            'success': True,
            'assignments': assignments_data
        })

    except Exception as e:
        logger.error(f"Error in shift assignments API: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@login_required
@require_http_methods(["GET"])
def shift_statistics_api(request, shift_id):
    """API endpoint to get shift statistics as JSON."""
    try:
        shift = get_object_or_404(ShiftMaster, id=shift_id)

        stats = {
            'total_assignments': ShiftAssignment.objects.filter(shift=shift).count(),
            'current_assignments': ShiftAssignment.objects.filter(shift=shift, is_current=True).count(),
            'total_employees': ShiftAssignment.objects.filter(shift=shift).values('employee').distinct().count(),
        }

        return JsonResponse({
            'success': True,
            'statistics': stats
        })

    except Exception as e:
        logger.error(f"Error in shift statistics API: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)
