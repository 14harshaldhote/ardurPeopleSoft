# views.py for shift management
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.http import require_POST, require_GET
from django.utils import timezone
from django.db.models import Q
from django.contrib.auth.models import User
from datetime import datetime, timedelta
import json
import logging

from .services import ShiftService
from .forms import ShiftForm, ShiftAssignmentForm, HolidayForm

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
        # Get all shifts including inactive ones for admins
        include_inactive = request.user.is_staff or request.user.is_superuser
        shifts = shift_service.get_all_shifts(include_inactive=include_inactive)
        
        context = {
            'shifts': shifts,
            'title': 'All Shifts'
        }
        
        return render(request, 'components/shift/shift_list.html', context)
    except Exception as e:
        logger.error(f"Error in shift list: {str(e)}")
        messages.error(request, "An error occurred while loading shifts.")
        return redirect('shift:dashboard')

@login_required
def shift_detail(request, shift_id):
    """View shift details and users assigned to it"""
    try:
        # Get shift by ID
        shift = shift_service.get_shift_by_id(shift_id)
        if not shift:
            messages.error(request, "Shift not found.")
            return redirect('shift:shift_list')
        
        # Get current date for filtering
        current_date = timezone.now().date()
        
        # Get users currently assigned to this shift
        assignments = shift_service.get_shift_assignments(active_only=True, date=current_date)
        users_in_shift = [a for a in assignments if a.shift_id == shift_id]
        
        context = {
            'shift': shift,
            'users_in_shift': users_in_shift,
            'title': f'Shift Details: {shift.name}'
        }
        
        return render(request, 'components/shift/shift_detail.html', context)
    except Exception as e:
        logger.error(f"Error in shift detail: {str(e)}")
        messages.error(request, "An error occurred while loading shift details.")
        return redirect('shift:shift_list')

@login_required
def create_shift(request):
    """Create a new shift"""
    if not request.user.is_staff and not request.user.is_superuser:
        messages.error(request, "You don't have permission to create shifts.")
        return redirect('shift:shift_list')
    
    if request.method == 'POST':
        form = ShiftForm(request.POST)
        if form.is_valid():
            try:
                shift_data = form.cleaned_data
                shift = shift_service.create_shift(shift_data)
                
                if shift:
                    messages.success(request, f"Shift '{shift.name}' created successfully.")
                    return redirect('shift:shift_detail', shift_id=shift.id)
                else:
                    messages.error(request, "Failed to create shift.")
            except Exception as e:
                logger.error(f"Error creating shift: {str(e)}")
                messages.error(request, f"An error occurred: {str(e)}")
    else:
        form = ShiftForm()
    
    return render(request, 'components/shift/shift_form.html', {
        'form': form,
        'title': 'Create New Shift',
        'is_update': False
    })

@login_required
def update_shift(request, shift_id):
    """Update an existing shift"""
    if not request.user.is_staff and not request.user.is_superuser:
        messages.error(request, "You don't have permission to update shifts.")
        return redirect('shift:shift_list')
    
    shift = shift_service.get_shift_by_id(shift_id)
    if not shift:
        messages.error(request, "Shift not found.")
        return redirect('shift:shift_list')
    
    if request.method == 'POST':
        form = ShiftForm(request.POST, instance=shift)
        if form.is_valid():
            try:
                shift_data = form.cleaned_data
                updated_shift = shift_service.update_shift(shift_id, shift_data)
                
                if updated_shift:
                    messages.success(request, f"Shift '{updated_shift.name}' updated successfully.")
                    return redirect('shift:shift_detail', shift_id=updated_shift.id)
                else:
                    messages.error(request, "Failed to update shift.")
            except Exception as e:
                logger.error(f"Error updating shift: {str(e)}")
                messages.error(request, f"An error occurred: {str(e)}")
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
        return redirect('shift:assignment_list')
    
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
                    return redirect('shift:assignment_list')
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
        return redirect('shift:assignment_list')
    
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
    
    return redirect('shift:assignment_list')

@login_required
def user_shift_history(request, user_id):
    """View shift history for a specific user"""
    try:
        user = User.objects.get(id=user_id)
        shift_history = shift_service.get_shift_history(user_id=user_id)
        
        context = {
            'user': user,
            'shift_history': shift_history,
            'title': f'Shift History: {user.get_full_name() or user.username}'
        }
        
        return render(request, 'components/shift/user_shift_info.html', context)
    except User.DoesNotExist:
        messages.error(request, "User not found.")
        return redirect('shift:assignment_list')
    except Exception as e:
        logger.error(f"Error in user shift history: {str(e)}")
        messages.error(request, "An error occurred while loading shift history.")
        return redirect('shift:assignment_list')

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