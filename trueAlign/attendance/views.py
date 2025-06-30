# attendance/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.core.paginator import Paginator
from django.db.models import Q, Count, Sum, Avg
from django.utils import timezone
from django.contrib.auth.models import User
from django.urls import reverse
from datetime import datetime, date, timedelta
import calendar
import json
import logging

from ..models import Attendance, UserSession, ShiftAssignment, LeaveRequest, Holiday
from ..services.attendance_service import AttendanceService
from ..services.date_service import DateService
from ..services.user_service import UserService
from .forms import AttendanceForm, RegularizationForm, AttendanceFilterForm

logger = logging.getLogger(__name__)

# Helper functions for role checking
def is_hr_check(user):
    """Check if user is HR"""
    return user.groups.filter(name='HR').exists() or user.is_superuser

def is_manager_check(user):
    """Check if user is Manager"""
    return user.groups.filter(name__in=['Manager', 'HR']).exists() or user.is_superuser

def is_employee_check(user):
    """Check if user is Employee (basic access)"""
    return user.is_authenticated

# Initialize services
attendance_service = AttendanceService()
date_service = DateService()
user_service = UserService()


@login_required
def attendance_dashboard(request):
    """
    Main attendance dashboard for employees
    Shows personal attendance data with filtering options
    """
    try:
        user = request.user

        # Get date range from request
        time_period = request.GET.get('time_period', 'this_month')
        custom_start = request.GET.get('start_date')
        custom_end = request.GET.get('end_date')

        # Convert string dates to date objects if provided
        if custom_start:
            custom_start = datetime.strptime(custom_start, '%Y-%m-%d').date()
        if custom_end:
            custom_end = datetime.strptime(custom_end, '%Y-%m-%d').date()

        # Get date range
        date_range = date_service.get_date_range(time_period, custom_start, custom_end)

        # Get attendance overview
        attendance_overview = attendance_service.get_attendance_overview(
            user_id=user.id,
            start_date=date_range['start_date'],
            end_date=date_range['end_date']
        )

        # Get attendance history with pagination
        page = request.GET.get('page', 1)
        attendance_history = attendance_service.get_user_attendance_history(
            user_id=user.id,
            start_date=date_range['start_date'],
            end_date=date_range['end_date'],
            page=page,
            per_page=10
        )

        # Get today's attendance
        today = date_service.get_current_date()
        today_attendance = Attendance.objects.filter(
            user=user,
            date=today
        ).first()

        # Check active session
        active_session = UserSession.objects.filter(
            user=user,
            is_active=True
        ).first()

        # Get current shift
        current_shift = None
        try:
            current_shift = ShiftAssignment.get_user_current_shift(user, today)
        except Exception as e:
            logger.error(f"Error getting current shift for user {user.id}: {str(e)}")

        context = {
            'attendance_overview': attendance_overview,
            'attendance_history': attendance_history,
            'today_attendance': today_attendance,
            'active_session': active_session,
            'current_shift': current_shift,
            'time_period': time_period,
            'date_range': date_range,
            'user': user,
        }

        return render(request, 'attendance/dashboard.html', context)

    except Exception as e:
        logger.error(f"Error in attendance_dashboard: {str(e)}")
        messages.error(request, "An error occurred while loading the dashboard.")
        return render(request, 'attendance/dashboard.html', {})


@login_required
def attendance_calendar(request):
    """
    Calendar view showing monthly attendance for the user
    """
    try:
        user = request.user

        # Get month and year from request
        month = int(request.GET.get('month', date_service.get_current_date().month))
        year = int(request.GET.get('year', date_service.get_current_date().year))

        # Create calendar
        cal = calendar.monthcalendar(year, month)

        # Get attendance data for the month
        start_date = date(year, month, 1)
        if month == 12:
            end_date = date(year + 1, 1, 1) - timedelta(days=1)
        else:
            end_date = date(year, month + 1, 1) - timedelta(days=1)

        attendance_data = {}
        attendances = Attendance.objects.filter(
            user=user,
            date__range=[start_date, end_date]
        )

        for attendance in attendances:
            attendance_data[attendance.date.day] = {
                'status': attendance.status,
                'clock_in': attendance.clock_in_time,
                'clock_out': attendance.clock_out_time,
                'total_hours': attendance.total_hours,
                'late_minutes': attendance.late_minutes,
            }

        # Get current shift
        current_shift = None
        try:
            current_shift = ShiftAssignment.get_user_current_shift(user, date_service.get_current_date())
        except Exception as e:
            logger.error(f"Error getting current shift: {str(e)}")

        # Navigation dates
        prev_month = month - 1 if month > 1 else 12
        prev_year = year if month > 1 else year - 1
        next_month = month + 1 if month < 12 else 1
        next_year = year if month < 12 else year + 1

        context = {
            'calendar': cal,
            'attendance_data': attendance_data,
            'month': month,
            'year': year,
            'month_name': calendar.month_name[month],
            'current_shift': current_shift,
            'prev_month': prev_month,
            'prev_year': prev_year,
            'next_month': next_month,
            'next_year': next_year,
            'user': user,
        }

        return render(request, 'attendance/calendar.html', context)

    except Exception as e:
        logger.error(f"Error in attendance_calendar: {str(e)}")
        messages.error(request, "An error occurred while loading the calendar.")
        return render(request, 'attendance/calendar.html', {})


@login_required
@user_passes_test(is_manager_check)
def manager_attendance_overview(request):
    """
    Manager's attendance overview showing team data
    """
    try:
        # Get date range
        time_period = request.GET.get('time_period', 'today')
        location = request.GET.get('location', '')

        date_range = date_service.get_date_range(time_period)

        # Get attendance overview
        attendance_overview = attendance_service.get_attendance_overview(
            start_date=date_range['start_date'],
            end_date=date_range['end_date']
        )

        # Get location-wise attendance
        location_attendance = attendance_service.get_location_wise_attendance(
            start_date=date_range['start_date'],
            end_date=date_range['end_date'],
            location=location
        )

        # Get users by status
        present_users = attendance_service.get_users_by_status(
            'Present',
            start_date=date_range['start_date'],
            end_date=date_range['end_date']
        )

        absent_users = attendance_service.get_users_by_status(
            'Absent',
            start_date=date_range['start_date'],
            end_date=date_range['end_date']
        )

        late_users = attendance_service.get_users_by_status(
            'Present & Late',
            start_date=date_range['start_date'],
            end_date=date_range['end_date']
        )

        # Get top absent and late users
        top_absent_users = attendance_service.get_top_absent_users(
            start_date=date_range['start_date'],
            end_date=date_range['end_date']
        )

        top_late_users = attendance_service.get_top_late_users(
            start_date=date_range['start_date'],
            end_date=date_range['end_date']
        )

        # Get yet to clock in users (for today only)
        yet_to_clock_in = []
        if date_range['end_date'] >= date_service.get_current_date():
            yet_to_clock_in = attendance_service.get_yet_to_clock_in_users()

        # Get all locations for filter
        all_locations = user_service.get_all_locations()

        context = {
            'attendance_overview': attendance_overview,
            'location_attendance': location_attendance,
            'present_users': present_users,
            'absent_users': absent_users,
            'late_users': late_users,
            'top_absent_users': top_absent_users,
            'top_late_users': top_late_users,
            'yet_to_clock_in': yet_to_clock_in,
            'all_locations': all_locations,
            'time_period': time_period,
            'selected_location': location,
            'date_range': date_range,
        }

        return render(request, 'attendance/manager_overview.html', context)

    except Exception as e:
        logger.error(f"Error in manager_attendance_overview: {str(e)}")
        messages.error(request, "An error occurred while loading the overview.")
        return render(request, 'attendance/manager_overview.html', {})


@login_required
@user_passes_test(is_hr_check)
def hr_attendance_dashboard(request):
    """
    HR attendance dashboard with comprehensive data
    """
    try:
        # Get filters
        time_period = request.GET.get('time_period', 'today')
        location = request.GET.get('location', '')
        department = request.GET.get('department', '')

        date_range = date_service.get_date_range(time_period)

        # Get comprehensive attendance data
        attendance_overview = attendance_service.get_attendance_overview(
            start_date=date_range['start_date'],
            end_date=date_range['end_date']
        )

        # Get location-wise data
        location_attendance = attendance_service.get_location_wise_attendance(
            start_date=date_range['start_date'],
            end_date=date_range['end_date'],
            location=location
        )

        # Get detailed user data
        all_users_attendance = Attendance.objects.filter(
            date__range=[date_range['start_date'], date_range['end_date']]
        ).select_related('user', 'shift').order_by('-date', 'user__first_name')

        # Apply filters
        if location:
            all_users_attendance = all_users_attendance.filter(location=location)

        # Pagination
        paginator = Paginator(all_users_attendance, 20)
        page = request.GET.get('page', 1)
        attendance_records = paginator.get_page(page)

        # Get statistics
        total_employees = user_service.get_total_employee_count()
        location_stats = user_service.get_location_wise_employee_count()

        # Get pending regularization requests
        pending_regularizations = Attendance.objects.filter(
            regularization_status='Pending'
        ).count()

        context = {
            'attendance_overview': attendance_overview,
            'location_attendance': location_attendance,
            'attendance_records': attendance_records,
            'total_employees': total_employees,
            'location_stats': location_stats,
            'pending_regularizations': pending_regularizations,
            'time_period': time_period,
            'selected_location': location,
            'date_range': date_range,
            'all_locations': user_service.get_all_locations(),
        }

        return render(request, 'attendance/hr_dashboard.html', context)

    except Exception as e:
        logger.error(f"Error in hr_attendance_dashboard: {str(e)}")
        messages.error(request, "An error occurred while loading the HR dashboard.")
        return render(request, 'attendance/hr_dashboard.html', {})


@login_required
@user_passes_test(is_hr_check)
def hr_regularization_requests(request):
    """
    HR view for managing attendance regularization requests
    """
    try:
        # Get filters
        status_filter = request.GET.get('status', '')
        date_from = request.GET.get('date_from', '')
        date_to = request.GET.get('date_to', '')
        employee_search = request.GET.get('employee_search', '')

        # Base queryset
        regularizations = Attendance.objects.filter(
            regularization_status__isnull=False
        ).select_related('user', 'shift', 'modified_by').order_by(
            'regularization_status', '-last_regularization_date'
        )

        # Apply filters
        if status_filter:
            regularizations = regularizations.filter(regularization_status=status_filter)

        if date_from:
            date_from_obj = datetime.strptime(date_from, '%Y-%m-%d').date()
            regularizations = regularizations.filter(date__gte=date_from_obj)

        if date_to:
            date_to_obj = datetime.strptime(date_to, '%Y-%m-%d').date()
            regularizations = regularizations.filter(date__lte=date_to_obj)

        if employee_search:
            regularizations = regularizations.filter(
                Q(user__first_name__icontains=employee_search) |
                Q(user__last_name__icontains=employee_search) |
                Q(user__username__icontains=employee_search)
            )

        # Pagination
        paginator = Paginator(regularizations, 15)
        page = request.GET.get('page', 1)
        regularization_requests = paginator.get_page(page)

        # Get statistics
        stats = {
            'total': regularizations.count(),
            'pending': regularizations.filter(regularization_status='Pending').count(),
            'approved': regularizations.filter(regularization_status='Approved').count(),
            'rejected': regularizations.filter(regularization_status='Rejected').count(),
        }

        context = {
            'regularization_requests': regularization_requests,
            'stats': stats,
            'status_filter': status_filter,
            'date_from': date_from,
            'date_to': date_to,
            'employee_search': employee_search,
            'status_choices': Attendance._meta.get_field('regularization_status').choices,
        }

        return render(request, 'attendance/hr_regularization_requests.html', context)

    except Exception as e:
        logger.error(f"Error in hr_regularization_requests: {str(e)}")
        messages.error(request, "An error occurred while loading regularization requests.")
        return render(request, 'attendance/hr_regularization_requests.html', {})


@login_required
@user_passes_test(is_hr_check)
@require_http_methods(["POST"])
def process_regularization(request, attendance_id):
    """
    Process regularization request (approve/reject)
    """
    try:
        attendance = get_object_or_404(Attendance, id=attendance_id)
        action = request.POST.get('action')
        comments = request.POST.get('comments', '')

        if action == 'approve':
            attendance.regularization_status = 'Approved'
            attendance.modified_by = request.user

            # Apply the requested changes
            if attendance.requested_status:
                attendance.original_status = attendance.status
                attendance.status = attendance.requested_status

            messages.success(request, f"Regularization approved for {attendance.user.get_full_name()}")

        elif action == 'reject':
            attendance.regularization_status = 'Rejected'
            attendance.modified_by = request.user
            messages.warning(request, f"Regularization rejected for {attendance.user.get_full_name()}")

        if comments:
            attendance.remarks = comments

        attendance.save()

        return JsonResponse({'status': 'success', 'message': 'Regularization processed successfully'})

    except Exception as e:
        logger.error(f"Error processing regularization: {str(e)}")
        return JsonResponse({'status': 'error', 'message': 'An error occurred while processing the request'})


@login_required
@user_passes_test(is_hr_check)
def hr_add_attendance(request):
    """
    HR view to manually add attendance records
    """
    if request.method == 'POST':
        try:
            user_id = request.POST.get('user_id')
            attendance_date = request.POST.get('date')
            status = request.POST.get('status')
            clock_in_time = request.POST.get('clock_in_time')
            clock_out_time = request.POST.get('clock_out_time')
            location = request.POST.get('location', 'Office')
            remarks = request.POST.get('remarks', '')

            user = get_object_or_404(User, id=user_id)
            attendance_date = datetime.strptime(attendance_date, '%Y-%m-%d').date()

            # Check if attendance already exists
            existing_attendance = Attendance.objects.filter(
                user=user,
                date=attendance_date
            ).first()

            if existing_attendance:
                messages.error(request, f"Attendance already exists for {user.get_full_name()} on {attendance_date}")
                return redirect('attendance:hr_add_attendance')

            # Create attendance record
            attendance_data = {
                'user': user,
                'date': attendance_date,
                'status': status,
                'location': location,
                'remarks': remarks,
                'modified_by': request.user,
                'regularization_reason': f"Manually added by HR: {request.user.get_full_name()}"
            }

            # Parse times if provided
            if clock_in_time:
                clock_in_datetime = datetime.strptime(f"{attendance_date} {clock_in_time}", '%Y-%m-%d %H:%M')
                attendance_data['clock_in_time'] = timezone.make_aware(clock_in_datetime)

            if clock_out_time:
                clock_out_datetime = datetime.strptime(f"{attendance_date} {clock_out_time}", '%Y-%m-%d %H:%M')
                attendance_data['clock_out_time'] = timezone.make_aware(clock_out_datetime)

            # Get user's shift for the date
            try:
                current_shift = ShiftAssignment.get_user_current_shift(user, attendance_date)
                if current_shift:
                    attendance_data['shift'] = current_shift
                    attendance_data['expected_hours'] = current_shift.shift_duration
            except Exception as e:
                logger.error(f"Error getting shift for user {user.id}: {str(e)}")

            attendance = Attendance(**attendance_data)
            attendance.save()

            messages.success(request, f"Attendance added successfully for {user.get_full_name()}")
            return redirect('attendance:hr_add_attendance')

        except Exception as e:
            logger.error(f"Error adding attendance: {str(e)}")
            messages.error(request, "An error occurred while adding attendance.")

    # Get all active users for the form
    users = user_service.get_active_users()

    context = {
        'users': users,
        'status_choices': Attendance.STATUS_CHOICES,
        'location_choices': Attendance.LOCATION_CHOICES,
    }

    return render(request, 'attendance/hr_add_attendance.html', context)


@login_required
def attendance_report(request):
    """
    Generate attendance reports with various filters
    """
    try:
        # Get filters
        time_period = request.GET.get('time_period', 'this_month')
        user_id = request.GET.get('user_id', '')
        location = request.GET.get('location', '')
        status = request.GET.get('status', '')
        export_format = request.GET.get('format', 'html')

        # Check permissions
        if not (is_hr_check(request.user) or is_manager_check(request.user)):
            if user_id and int(user_id) != request.user.id:
                messages.error(request, "You can only view your own attendance report.")
                return redirect('attendance:dashboard')

        date_range = date_service.get_date_range(time_period)

        # Build query
        attendance_query = Attendance.objects.select_related('user', 'shift')

        if user_id:
            attendance_query = attendance_query.filter(user_id=user_id)

        if location:
            attendance_query = attendance_query.filter(location=location)

        if status:
            attendance_query = attendance_query.filter(status=status)

        attendance_query = attendance_query.filter(
            date__range=[date_range['start_date'], date_range['end_date']]
        ).order_by('-date', 'user__first_name')

        # Get summary statistics
        summary = attendance_query.aggregate(
            total_records=Count('id'),
            total_hours=Sum('total_hours'),
            total_overtime=Sum('overtime_hours'),
            present_count=Count('id', filter=Q(status__in=['Present', 'Present & Late'])),
            absent_count=Count('id', filter=Q(status='Absent')),
            leave_count=Count('id', filter=Q(status='On Leave')),
        )

        # Pagination for HTML view
        if export_format == 'html':
            paginator = Paginator(attendance_query, 25)
            page = request.GET.get('page', 1)
            attendance_records = paginator.get_page(page)
        else:
            attendance_records = attendance_query

        # Get filter options
        all_users = user_service.get_active_users() if (is_hr_check(request.user) or is_manager_check(request.user)) else []
        all_locations = user_service.get_all_locations()

        context = {
            'attendance_records': attendance_records,
            'summary': summary,
            'date_range': date_range,
            'time_period': time_period,
            'selected_user_id': user_id,
            'selected_location': location,
            'selected_status': status,
            'all_users': all_users,
            'all_locations': all_locations,
            'status_choices': Attendance.STATUS_CHOICES,
        }

        if export_format == 'csv':
            return export_attendance_csv(attendance_records, date_range)

        return render(request, 'attendance/report.html', context)

    except Exception as e:
        logger.error(f"Error generating attendance report: {str(e)}")
        messages.error(request, "An error occurred while generating the report.")
        return render(request, 'attendance/report.html', {})


def export_attendance_csv(attendance_records, date_range):
    """
    Export attendance data to CSV
    """
    import csv
    from django.http import HttpResponse

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="attendance_report_{date_range["start_date"]}_to_{date_range["end_date"]}.csv"'

    writer = csv.writer(response)
    writer.writerow([
        'Employee Name', 'Date', 'Status', 'Clock In', 'Clock Out',
        'Total Hours', 'Overtime Hours', 'Late Minutes', 'Location',
        'Shift', 'Remarks'
    ])

    for attendance in attendance_records:
        writer.writerow([
            attendance.user.get_full_name(),
            attendance.date,
            attendance.status,
            attendance.clock_in_time.strftime('%H:%M') if attendance.clock_in_time else '',
            attendance.clock_out_time.strftime('%H:%M') if attendance.clock_out_time else '',
            attendance.total_hours or 0,
            attendance.overtime_hours or 0,
            attendance.late_minutes or 0,
            attendance.location,
            attendance.shift.name if attendance.shift else '',
            attendance.remarks or ''
        ])

    return response


@login_required
def request_regularization(request):
    """
    Employee request for attendance regularization
    """
    if request.method == 'POST':
        try:
            attendance_id = request.POST.get('attendance_id')
            requested_status = request.POST.get('requested_status')
            reason = request.POST.get('reason')

            attendance = get_object_or_404(Attendance, id=attendance_id, user=request.user)

            # Check if already has pending request
            if attendance.regularization_status == 'Pending':
                messages.warning(request, "You already have a pending regularization request for this date.")
                return redirect('attendance:dashboard')

            # Update attendance
            attendance.requested_status = requested_status
            attendance.regularization_reason = reason
            attendance.regularization_status = 'Pending'
            attendance.regularization_attempts += 1
            attendance.last_regularization_date = timezone.now()
            attendance.save()

            messages.success(request, "Regularization request submitted successfully.")
            return redirect('attendance:dashboard')

        except Exception as e:
            logger.error(f"Error submitting regularization request: {str(e)}")
            messages.error(request, "An error occurred while submitting your request.")

    return redirect('attendance:dashboard')


@login_required
def get_attendance_data(request):
    """
    API endpoint to get attendance data for AJAX requests
    """
    try:
        user_id = request.GET.get('user_id')
        date_str = request.GET.get('date')

        if not user_id or not date_str:
            return JsonResponse({'error': 'Missing required parameters'}, status=400)

        # Check permissions
        if not (is_hr_check(request.user) or is_manager_check(request.user)):
            if int(user_id) != request.user.id:
                return JsonResponse({'error': 'Permission denied'}, status=403)

        attendance_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        attendance = Attendance.objects.filter(
            user_id=user_id,
            date=attendance_date
        ).first()

        if attendance:
            data = {
                'id': attendance.id,
                'status': attendance.status,
                'clock_in_time': attendance.clock_in_time.strftime('%H:%M') if attendance.clock_in_time else '',
                'clock_out_time': attendance.clock_out_time.strftime('%H:%M') if attendance.clock_out_time else '',
                'total_hours': float(attendance.total_hours) if attendance.total_hours else 0,
                'late_minutes': attendance.late_minutes,
                'location': attendance.location,
                'remarks': attendance.remarks or '',
                'regularization_status': attendance.regularization_status,
            }
        else:
            data = {'message': 'No attendance record found'}

        return JsonResponse(data)

    except Exception as e:
        logger.error(f"Error getting attendance data: {str(e)}")
        return JsonResponse({'error': 'An error occurred'}, status=500)


@login_required
@user_passes_test(is_hr_check)
def attendance_analytics(request):
    """
    Advanced attendance analytics for HR
    """
    try:
        # Get date range
        time_period = request.GET.get('time_period', 'this_month')
        date_range = date_service.get_date_range(time_period)

        # Get attendance trends
        attendance_trends = attendance_service.get_attendance_trends(
            start_date=date_range['start_date'],
            end_date=date_range['end_date']
        )

        # Get monthly summaries for multiple users
        monthly_summaries = []
        active_users = user_service.get_active_users()[:10]  # Limit for performance

        for user in active_users:
            summary = attendance_service.get_monthly_attendance_summary(
                user_id=user.id,
                month=date_range['start_date'].month,
                year=date_range['start_date'].year
            )
            if summary:
                monthly_summaries.append(summary)

        # Get location-wise statistics
        location_stats = attendance_service.get_location_wise_attendance(
            start_date=date_range['start_date'],
            end_date=date_range['end_date']
        )

        context = {
            'attendance_trends': attendance_trends,
            'monthly_summaries': monthly_summaries,
            'location_stats': location_stats,
            'date_range': date_range,
            'time_period': time_period,
        }

        return render(request, 'attendance/analytics.html', context)

    except Exception as e:
        logger.error(f"Error in attendance_analytics: {str(e)}")
        messages.error(request, "An error occurred while loading analytics.")
        return render(request, 'attendance/analytics.html', {})
