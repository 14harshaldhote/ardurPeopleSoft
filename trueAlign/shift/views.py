# views.py for shift management
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import  require_GET
from django.utils import timezone
from django.contrib.auth.models import User
from datetime import datetime
import logging
from .decorators import group_required

from .services import ShiftService
from .forms import ShiftForm, ShiftAssignmentForm, HolidayForm

from ..models import Holiday, ShiftMaster

# Set up logging
logger = logging.getLogger(__name__)

# Initialize service
shift_service = ShiftService()

@login_required
def shift_dashboard(request):
    """Main dashboard for shift management"""
    try:
        # Get shift statistics
        shift_stats = shift_service.get_shift_statistics()

        # Get upcoming shift changes
        upcoming_changes = shift_service.get_upcoming_shift_changes(days=7)

        # Get holidays for current year
        current_year = timezone.now().year
        holidays = shift_service.get_holidays(year=current_year)

        context = {
            'shift_stats': shift_stats,
            'upcoming_changes': upcoming_changes,
            'holidays': holidays,
            'title': 'Shift Management Dashboard'
        }

        return render(request, 'components/shift/dashboard.html', context)
    except Exception as e:
        logger.error(f"Error in shift dashboard: {str(e)}")
        messages.error(request, "An error occurred while loading the shift dashboard.")
        return redirect('core:dashboard')


@login_required
def shift_list(request):
    """View all shifts"""
    try:
        print("[DEBUG] Accessing shift_list view")
        include_inactive = request.user.is_staff or request.user.is_superuser
        print(f"[DEBUG] include_inactive: {include_inactive}")

        shifts = shift_service.get_all_shifts(include_inactive=include_inactive)
        print(f"[DEBUG] Retrieved {len(shifts)} shifts")

        context = {
            'shifts': shifts,
            'title': 'All Shifts'
        }

        return render(request, 'components/shift/shift_list.html', context)
    except Exception as e:
        logger.error(f"Error in shift list: {str(e)}")
        print(f"[ERROR] Exception in shift_list: {str(e)}")
        messages.error(request, "An error occurred while loading shifts.")
        return redirect('shift:dashboard')


@login_required
def shift_detail(request, shift_id):
    """View shift details and users assigned to it"""
    try:
        print(f"[DEBUG] Accessing shift_detail view for shift_id: {shift_id}")

        shift = shift_service.get_shift_by_id(shift_id)
        print(f"[DEBUG] shift: {shift}")
        if not shift:
            print("[WARN] Shift not found")
            messages.error(request, "Shift not found.")
            return redirect('shift:list')

        current_date = timezone.now().date()
        print(f"[DEBUG] current_date: {current_date}")

        assignments = shift_service.get_shift_assignments(active_only=True, date=current_date)
        print(f"[DEBUG] Assignments count: {len(assignments)}")

        users_in_shift = [a for a in assignments if a.shift_id == shift_id]
        print(f"[DEBUG] Users in shift: {len(users_in_shift)}")

        context = {
            'shift': shift,
            'users_in_shift': users_in_shift,
            'title': f'Shift Details: {shift.name}'
        }

        return render(request, 'components/shift/shift_detail.html', context)
    except Exception as e:
        logger.error(f"Error in shift detail: {str(e)}")
        print(f"[ERROR] Exception in shift_detail: {str(e)}")
        messages.error(request, "An error occurred while loading shift details.")
        return redirect('shift:list')



@login_required
@group_required(group_names=['Manager']) 
def create_shift(request):
    """Create a new shift"""
    if request.method == 'POST':
        form = ShiftForm(request.POST)
        if form.is_valid():
            try:
                shift_data = form.cleaned_data
                shift = shift_service.create_shift(shift_data)
                messages.success(request, f"Shift '{shift.name}' created successfully.")
                return redirect('shift:shift_detail', shift_id=shift.id)
            except Exception as e:
                logger.error(f"Error creating shift: {str(e)}")
                messages.error(request, f"An error occurred while creating the shift: {str(e)}")
        else:
            # Form is invalid, it will be re-rendered with errors
            messages.error(request, "Please correct the errors below.")
    else:
        form = ShiftForm()

    return render(request, 'components/shift/shift_form.html', {
        'form': form,
        'title': 'Create New Shift',
        'is_update': False
    })


@login_required
@group_required(group_names=['Manager']) 
def update_shift(request, shift_id):
    """Update an existing shift"""
    shift = shift_service.get_shift_by_id(shift_id)
    if not shift:
        messages.error(request, "Shift not found.")
        return redirect('shift:list')

    if request.method == 'POST':
        form = ShiftForm(request.POST, instance=shift)
        if form.is_valid():
            try:
                shift_data = form.cleaned_data
                updated_shift = shift_service.update_shift(shift_id, shift_data)
                messages.success(request, f"Shift '{updated_shift.name}' updated successfully.")
                return redirect('shift:shift_detail', shift_id=updated_shift.id)
            except Exception as e:
                logger.error(f"Error updating shift {shift_id}: {str(e)}")
                messages.error(request, f"An error occurred while updating the shift: {str(e)}")
        else:
            messages.error(request, "Please correct the errors below.")
    else:
        form = ShiftForm(instance=shift)

    return render(request, 'components/shift/shift_form.html', {
        'form': form,
        'shift': shift,
        'title': f'Update Shift: {shift.name}',
        'is_update': True
    })


@login_required
def assignment_list(request):
    """View all shift assignments"""
    try:
        # Get filter parameters
        user_id = request.GET.get('user_id')
        active_only = request.GET.get('active_only', 'true').lower() == 'true'

        # Get assignments based on filters
        assignments = shift_service.get_shift_assignments(
            user_id=user_id,
            active_only=active_only
        )

        context = {
            'assignments': assignments,
            'active_only': active_only,
            'title': 'Shift Assignments'
        }

        return render(request, 'components/shift/assignment_list.html', context)
    except Exception as e:
        logger.error(f"Error in assignment list: {str(e)}")
        messages.error(request, "An error occurred while loading shift assignments.")
        return redirect('shift:dashboard')

@login_required
def assign_shift(request):
    """Assign a shift to a user"""
    if not request.user.is_staff and not request.user.is_superuser:
        messages.error(request, "You don't have permission to assign shifts.")
        return redirect('shift:assignments')

    if request.method == 'POST':
        form = ShiftAssignmentForm(request.POST)
        if form.is_valid():
            try:
                user_id = form.cleaned_data['user'].id
                shift_id = form.cleaned_data['shift'].id
                effective_from = form.cleaned_data['effective_from']
                effective_to = form.cleaned_data.get('effective_to')

                assignment = shift_service.assign_shift_to_user(
                    user_id=user_id,
                    shift_id=shift_id,
                    effective_from=effective_from,
                    effective_to=effective_to
                )

                if assignment:
                    messages.success(request, "Shift assigned successfully.")
                    return redirect('shift:assignments')
                else:
                    messages.error(request, "Failed to assign shift.")
            except Exception as e:
                logger.error(f"Error assigning shift: {str(e)}")
                messages.error(request, f"An error occurred: {str(e)}")
    else:
        form = ShiftAssignmentForm()

    return render(request, 'components/shift/assignment_form.html', {
        'form': form,
        'title': 'Assign Shift'
    })

@login_required
def end_assignment(request, assignment_id):
    """End a shift assignment"""
    if not request.user.is_staff and not request.user.is_superuser:
        messages.error(request, "You don't have permission to end shift assignments.")
        return redirect('shift:assignments')

    if request.method == 'POST':
        try:
            end_date = request.POST.get('end_date')
            if not end_date:
                end_date = timezone.now().date()
            else:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()

            assignment = shift_service.end_shift_assignment(
                assignment_id=assignment_id,
                end_date=end_date
            )

            if assignment:
                messages.success(request, "Shift assignment ended successfully.")
            else:
                messages.error(request, "Failed to end shift assignment.")

        except Exception as e:
            logger.error(f"Error ending shift assignment: {str(e)}")
            messages.error(request, f"An error occurred: {str(e)}")

    return redirect('shift:assignments')

@login_required
def user_shift_history(request, user_id):
        """View shift history for a specific user"""
        try:
            # Use filter().first() instead of get() to avoid DoesNotExist exception
            user = User.objects.filter(id=user_id).first()

            if not user:
                messages.error(request, "User not found.")
                return redirect('shift:assignments')

            shift_history = shift_service.get_shift_history(user_id=user_id)

            context = {
                'user': user,
                'shift_history': shift_history,
                'title': f'Shift History: {user.get_full_name() or user.username}'
            }

            return render(request, 'components/shift/user_shift_info.html', context)
        except Exception as e:
            logger.error(f"Error in user shift history: {str(e)}")
            messages.error(request, "An error occurred while loading shift history.")
            return redirect('shift:assignments')

@login_required
def unassigned_users(request):
    """View users without shift assignments"""
    try:
        date_str = request.GET.get('date')
        if date_str:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            date = timezone.now().date()

        users = shift_service.get_users_without_shifts(date=date)

        context = {
            'users': users,
            'date': date,
            'title': 'Users Without Shifts'
        }

        return render(request, 'components/shift/unassigned_users.html', context)
    except Exception as e:
        logger.error(f"Error in unassigned users: {str(e)}")
        messages.error(request, "An error occurred while loading unassigned users.")
        return redirect('shift:dashboard')

@login_required
def holiday_list(request):
    """View all holidays"""
    try:
        year = request.GET.get('year')
        if year:
            year = int(year)
        else:
            year = timezone.now().year

        holidays = shift_service.get_holidays(year=year)

        context = {
            'holidays': holidays,
            'current_year': year,
            'title': f'Holidays - {year}'
        }

        return render(request, 'components/shift/holiday_list.html', context)
    except Exception as e:
        logger.error(f"Error in holiday list: {str(e)}")
        messages.error(request, "An error occurred while loading holidays.")
        return redirect('shift:dashboard')

@login_required
def create_holiday(request):
    """Create a new holiday"""
    if not request.user.is_staff and not request.user.is_superuser:
        messages.error(request, "You don't have permission to create holidays.")
        return redirect('shift:holiday_list')

    if request.method == 'POST':
        form = HolidayForm(request.POST)
        if form.is_valid():
            try:
                holiday_data = form.cleaned_data
                holiday = shift_service.create_holiday(holiday_data)

                if holiday:
                    messages.success(request, f"Holiday '{holiday.name}' created successfully.")
                    return redirect('shift:holiday_list')
                else:
                    messages.error(request, "Failed to create holiday.")
            except Exception as e:
                logger.error(f"Error creating holiday: {str(e)}")
                messages.error(request, f"An error occurred: {str(e)}")
    else:
        form = HolidayForm()

    return render(request, 'components/shift/holiday_form.html', {
        'form': form,
        'title': 'Create New Holiday'
    })

@login_required
def shift_calendar(request):
    """View shift calendar"""
    try:
        # Get all shifts for the calendar
        shifts = shift_service.get_all_shifts()

        # Get all holidays
        current_year = timezone.now().year
        holidays = shift_service.get_holidays(year=current_year)

        context = {
            'shifts': shifts,
            'holidays': holidays,
            'title': 'Shift Calendar'
        }

        return render(request, 'components/shift/shift_calendar.html', context)
    except Exception as e:
        logger.error(f"Error in shift calendar: {str(e)}")
        messages.error(request, "An error occurred while loading the shift calendar.")
        return redirect('shift:dashboard')

@login_required
@require_GET
def api_get_shift_data(request):
    """API endpoint to get shift data for AJAX requests"""
    try:
        shift_id = request.GET.get('shift_id')
        if shift_id:
            shift = shift_service.get_shift_by_id(int(shift_id))
            if shift:
                data = {
                    'id': shift.id,
                    'name': shift.name,
                    'start_time': shift.start_time.strftime('%H:%M'),
                    'end_time': shift.end_time.strftime('%H:%M'),
                    'shift_duration': float(shift.shift_duration),
                    'break_duration': shift.break_duration.total_seconds() / 60,  # in minutes
                    'grace_period': shift.grace_period.total_seconds() / 60,  # in minutes
                    'work_days': shift.work_days,
                    'custom_work_days': shift.custom_work_days,
                    'is_active': shift.is_active,
                    'crosses_midnight': shift.crosses_midnight
                }
                return JsonResponse({'status': 'success', 'data': data})

        return JsonResponse({'status': 'error', 'message': 'Shift not found'}, status=404)
    except Exception as e:
        logger.error(f"Error in API get shift data: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
@require_GET
def api_get_user_shift(request):
    """API endpoint to get a user's current shift"""
    try:
        user_id = request.GET.get('user_id')
        date_str = request.GET.get('date')

        if date_str:
            date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            date = timezone.now().date()

        if user_id:
            # Get current assignment for user
            assignments = shift_service.get_shift_assignments(
                user_id=int(user_id),
                active_only=True,
                date=date
            )

            if assignments:
                assignment = assignments[0]  # Get the most recent active assignment
                data = {
                    'user_id': assignment.user.id,
                    'user_name': assignment.user.get_full_name() or assignment.user.username,
                    'shift_id': assignment.shift.id,
                    'shift_name': assignment.shift.name,
                    'start_time': assignment.shift.start_time.strftime('%H:%M'),
                    'end_time': assignment.shift.end_time.strftime('%H:%M'),
                    'effective_from': assignment.effective_from.strftime('%Y-%m-%d'),
                    'effective_to': assignment.effective_to.strftime('%Y-%m-%d') if assignment.effective_to else None
                }
                return JsonResponse({'status': 'success', 'data': data})
            else:
                return JsonResponse({'status': 'not_found', 'message': 'No active shift assignment found for this user'}, status=404)

        return JsonResponse({'status': 'error', 'message': 'User ID is required'}, status=400)
    except Exception as e:
        logger.error(f"Error in API get user shift: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
def update_holiday(request, holiday_id):
    """Update an existing holiday"""
    if not request.user.is_staff and not request.user.is_superuser:
        messages.error(request, "You don't have permission to update holidays.")
        return redirect('shift:holiday_list')

    try:
        holiday = get_object_or_404(Holiday, id=holiday_id)

        if request.method == 'POST':
            form = HolidayForm(request.POST, instance=holiday)
            if form.is_valid():
                updated_holiday = form.save()
                messages.success(request, f"Holiday '{updated_holiday.name}' updated successfully.")
                return redirect('shift:holiday_list')
        else:
            form = HolidayForm(instance=holiday)

        return render(request, 'components/shift/holiday_form.html', {
            'form': form,
            'holiday': holiday,
            'title': f'Update Holiday: {holiday.name}',
            'is_update': True
        })
    except Exception as e:
        logger.error(f"Error updating holiday: {str(e)}")
        messages.error(request, "An error occurred while updating the holiday.")
        return redirect('shift:holiday_list')

@login_required
def delete_holiday(request, holiday_id):
    """Delete a holiday"""
    if not request.user.is_staff and not request.user.is_superuser:
        messages.error(request, "You don't have permission to delete holidays.")
        return redirect('shift:holiday_list')

    try:
        holiday = get_object_or_404(Holiday, id=holiday_id)

        if request.method == 'POST':
            holiday_name = holiday.name
            holiday.delete()
            messages.success(request, f"Holiday '{holiday_name}' deleted successfully.")
        else:
            messages.error(request, "Invalid request method.")

        return redirect('shift:holiday_list')
    except Exception as e:
        logger.error(f"Error deleting holiday: {str(e)}")
        messages.error(request, "An error occurred while deleting the holiday.")
        return redirect('shift:holiday_list')

@login_required
@require_GET
def api_shift_details(request, shift_id):
    """API endpoint to get detailed shift information"""
    try:
        shift = shift_service.get_shift_by_id(shift_id)
        if not shift:
            return JsonResponse({'status': 'error', 'message': 'Shift not found'}, status=404)

        # Get current users assigned to this shift
        current_date = timezone.now().date()
        assignments = shift_service.get_shift_assignments(active_only=True, date=current_date)
        users_in_shift = [
            {
                'id': a.user.id,
                'name': a.user.get_full_name() or a.user.username,
                'assignment_id': a.id,
                'effective_from': a.effective_from.strftime('%Y-%m-%d'),
                'effective_to': a.effective_to.strftime('%Y-%m-%d') if a.effective_to else None
            }
            for a in assignments if a.shift_id == shift_id
        ]

        data = {
            'id': shift.id,
            'name': shift.name,
            'start_time': shift.start_time.strftime('%H:%M'),
            'end_time': shift.end_time.strftime('%H:%M'),
            'description': shift.description,
            'is_active': shift.is_active,
            'users': users_in_shift,
            'user_count': len(users_in_shift)
        }

        return JsonResponse({'status': 'success', 'data': data})
    except Exception as e:
        logger.error(f"Error in API shift details: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
@require_GET
def api_user_assignments(request, user_id):
    """API endpoint to get a user's shift assignments"""
    try:
        user = get_object_or_404(User, id=user_id)

        # Get all assignments for this user
        assignments = shift_service.get_shift_history(user_id=user_id)

        data = {
            'user': {
                'id': user.id,
                'name': user.get_full_name() or user.username,
                'username': user.username,
                'email': user.email
            },
            'assignments': [
                {
                    'id': a.id,
                    'shift_id': a.shift.id,
                    'shift_name': a.shift.name,
                    'effective_from': a.effective_from.strftime('%Y-%m-%d'),
                    'effective_to': a.effective_to.strftime('%Y-%m-%d') if a.effective_to else None,
                    'is_current': a.is_current
                }
                for a in assignments
            ]
        }

        return JsonResponse({'status': 'success', 'data': data})
    except Exception as e:
        logger.error(f"Error in API user assignments: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
@require_GET
def api_upcoming_changes(request):
    """API endpoint to get upcoming shift changes"""
    try:
        days = request.GET.get('days', 7)
        try:
            days = int(days)
        except ValueError:
            days = 7

        changes = shift_service.get_upcoming_shift_changes(days=days)

        data = [
            {
                'id': c.id,
                'user_id': c.user.id,
                'user_name': c.user.get_full_name() or c.user.username,
                'shift_id': c.shift.id,
                'shift_name': c.shift.name,
                'effective_from': c.effective_from.strftime('%Y-%m-%d'),
                'effective_to': c.effective_to.strftime('%Y-%m-%d') if c.effective_to else None
            }
            for c in changes
        ]

        return JsonResponse({'status': 'success', 'data': data})
    except Exception as e:
        logger.error(f"Error in API upcoming changes: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
@require_GET
def api_holidays_by_year(request, year):
    """API endpoint to get holidays for a specific year"""
    try:
        holidays = shift_service.get_holidays(year=year)

        data = [
            {
                'id': h.id,
                'name': h.name,
                'date': h.date.strftime('%Y-%m-%d'),
                'description': h.description,
                'recurring_yearly': h.recurring_yearly
            }
            for h in holidays
        ]

        return JsonResponse({'status': 'success', 'data': data})
    except Exception as e:
        logger.error(f"Error in API holidays by year: {str(e)}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@login_required
def end_shift_assignment(request, assignment_id):
    """End a shift assignment"""
    if not request.user.is_staff and not request.user.is_superuser:
        messages.error(request, "You don't have permission to end shift assignments.")
        return redirect('shift:assignments')

    if request.method == 'POST':
        try:
            end_date = request.POST.get('end_date')
            if not end_date:
                end_date = timezone.now().date()
            else:
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()

            assignment = shift_service.end_shift_assignment(
                assignment_id=assignment_id,
                end_date=end_date
            )

            if assignment:
                messages.success(request, "Shift assignment ended successfully.")
            else:
                messages.error(request, "Failed to end shift assignment.")

        except Exception as e:
            logger.error(f"Error ending shift assignment: {str(e)}")
            messages.error(request, f"An error occurred: {str(e)}")

    return redirect('shift:assignments')

@login_required
@group_required(group_names=['Manager']) 
def delete_shift(request, shift_id):
    """Delete a shift"""


    try:
        shift = get_object_or_404(ShiftMaster, id=shift_id)

        # Check if the shift has any active assignments
        current_date = timezone.now().date()
        assignments = shift_service.get_shift_assignments(active_only=True, date=current_date)
        active_assignments = [a for a in assignments if a.shift_id == shift_id]

        if active_assignments and request.method != 'POST':
            # If there are active assignments and it's not a confirmed POST request,
            # show a confirmation page
            return render(request, 'components/shift/confirm_delete.html', {
                'shift': shift,
                'active_assignments': active_assignments,
                'title': f'Confirm Delete: {shift.name}'
            })

        if request.method == 'POST':
            shift_name = shift.name
            shift.delete()
            messages.success(request, f"Shift '{shift_name}' deleted successfully.")
            return redirect('shift:list')

        # If no active assignments, show the confirmation page
        return render(request, 'components/shift/confirm_delete.html', {
            'shift': shift,
            'active_assignments': [],
            'title': f'Confirm Delete: {shift.name}'
        })
    except Exception as e:
        logger.error(f"Error deleting shift: {str(e)}")
        messages.error(request, "An error occurred while deleting the shift.")
        return redirect('shift:list')


@login_required
def shift_statistics(request):
    """View shift statistics"""
    try:
        # Get shift statistics
        stats = shift_service.get_shift_statistics()

        # Get additional stats like shift changes over time
        # Pass the number of days to look back instead of date objects
        recent_changes = shift_service.get_recent_shift_changes(days=30)

        context = {
            'stats': stats,
            'recent_changes': recent_changes,
            'title': 'Shift Statistics'
        }

        return render(request, 'components/shift/statistics.html', context)
    except Exception as e:
        logger.error(f"Error in shift statistics: {str(e)}")
        messages.error(request, "An error occurred while loading shift statistics.")
        return redirect('shift:dashboard')
