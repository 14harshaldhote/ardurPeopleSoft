# attendance/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.core.paginator import Paginator
from django.db import transaction
from django.core.exceptions import ValidationError
from datetime import datetime, date, timedelta
import calendar
import csv
import json
import pytz
import logging
from trueAlign.attendance.decorators import group_required

from trueAlign.models import Attendance, UserSession, Holiday, ShiftAssignment
from .forms import (
    AttendanceForm, RegularizationForm, AttendanceFilterForm,
    HRRegularizationProcessForm, BulkAttendanceForm, AttendanceSearchForm,
    QuickAttendanceForm
)
from .services import (
    AttendanceAutoMarkingService,
    AttendanceIntegrationService,
    AttendanceRegularizationService,
    AttendanceReportService,
    AttendanceAnalyticsService,
    AttendanceNotificationService,
    AttendanceBulkOperationService,
    get_attendance_services
)

logger = logging.getLogger(__name__)
User = get_user_model()
IST = pytz.timezone('Asia/Kolkata')

# Permission checker functions
def is_hr_check(user):
    """Check if user is HR"""
    return user.groups.filter(name='HR').exists() or user.is_superuser

def is_manager_check(user):
    """Check if user is manager"""
    return user.groups.filter(name__in=['Manager', 'HR']).exists() or user.is_superuser

def is_employee_check(user):
    """Check if user is employee (has access to employee features)"""
    return user.is_authenticated and user.is_active


# Employee Views
@login_required
def attendance_dashboard(request):
    """
    Employee attendance dashboard with quick actions and overview
    """
    try:
        services = get_attendance_services()
        today = timezone.now().astimezone(IST).date()

        # Get or create today's attendance
        attendance_today, created = Attendance.objects.get_or_create_today_attendance(
            request.user, today
        )

        if created:
            logger.info(f"Created attendance record for {request.user.username} on dashboard access")

        # Get recent attendance (last 7 days)
        start_date = today - timedelta(days=6)
        recent_attendance = Attendance.objects.get_user_attendance_for_period(
            request.user, start_date, today
        )

        # Calculate quick stats
        this_month_start = today.replace(day=1)
        monthly_attendance = Attendance.objects.get_user_attendance_for_period(
            request.user, this_month_start, today
        )

        present_days = monthly_attendance.filter(
            status__in=['Present', 'Present & Late', 'Work From Home']
        ).count()
        total_days = monthly_attendance.count()
        attendance_percentage = (present_days / total_days * 100) if total_days > 0 else 0

        # Quick attendance form
        quick_form = QuickAttendanceForm()

        # Handle quick attendance submission
        if request.method == 'POST' and 'quick_attendance' in request.POST:
            quick_form = QuickAttendanceForm(request.POST)
            if quick_form.is_valid():
                try:
                    attendance_today.status = quick_form.cleaned_data['status']
                    attendance_today.location = quick_form.cleaned_data['location']
                    attendance_today.remarks = quick_form.cleaned_data.get('remarks', '')
                    attendance_today.modified_by = request.user
                    attendance_today.save()

                    messages.success(request, 'Attendance marked successfully!')
                    return redirect('attendance:dashboard')

                except Exception as e:
                    logger.error(f"Error marking quick attendance: {e}")
                    messages.error(request, 'Error marking attendance. Please try again.')

        # Get current shift
        current_shift = ShiftAssignment.get_user_current_shift(request.user, today)

        # Check for pending regularizations
        pending_regularizations = Attendance.objects.filter(
            user=request.user,
            regularization_status='Pending'
        ).count()

        context = {
            'attendance_today': attendance_today,
            'recent_attendance': recent_attendance,
            'quick_form': quick_form,
            'current_shift': current_shift,
            'attendance_percentage': round(attendance_percentage, 1),
            'present_days': present_days,
            'total_days': total_days,
            'pending_regularizations': pending_regularizations,
            'today': today,
        }

        return render(request, 'attendance/dashboard.html', context)

    except Exception as e:
        logger.error(f"Error in attendance dashboard: {e}")
        messages.error(request, 'Error loading dashboard. Please try again.')
        return render(request, 'attendance/dashboard.html', {})


@login_required
def attendance_calendar(request, year=None, month=None):
    """
    Employee attendance calendar view
    """
    try:
        # Get current date or use provided year/month
        now = timezone.now().astimezone(IST)
        year = year or now.year
        month = month or now.month

        # Create calendar
        cal = calendar.monthcalendar(year, month)

        # Get attendance data for the month
        start_date = date(year, month, 1)
        if month == 12:
            end_date = date(year + 1, 1, 1) - timedelta(days=1)
        else:
            end_date = date(year, month + 1, 1) - timedelta(days=1)

        attendances = Attendance.objects.filter(
            user=request.user,
            date__range=[start_date, end_date]
        ).select_related('shift')

        # Organize attendance data by day
        attendance_data = {}
        for attendance in attendances:
            attendance_data[attendance.date.day] = {
                'id': attendance.id,
                'status': attendance.status,
                'status_color': attendance.get_status_color(),
                'clock_in': attendance.clock_in_time.strftime('%H:%M') if attendance.clock_in_time else None,
                'clock_out': attendance.clock_out_time.strftime('%H:%M') if attendance.clock_out_time else None,
                'total_hours': attendance.get_formatted_duration(),
                'late_minutes': attendance.late_minutes,
                'location': attendance.get_location_display(),
                'can_regularize': attendance.can_request_regularization(),
                'regularization_status': attendance.regularization_status,
                'shift_name': attendance.shift.name if attendance.shift else None
            }

        # Navigation links
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
            'prev_month': prev_month,
            'prev_year': prev_year,
            'next_month': next_month,
            'next_year': next_year,
            'today': now.date(),
        }

        return render(request, 'attendance/calendar.html', context)

    except Exception as e:
        logger.error(f"Error in attendance calendar: {e}")
        messages.error(request, 'Error loading calendar. Please try again.')
        return render(request, 'attendance/calendar.html', {})


@login_required
@group_required(group_names=['Manager', 'Employee', 'HR'])
def request_regularization(request, attendance_id=None):
    """
    Employee regularization request view
    """
    try:
        services = get_attendance_services()
        regularization_service = services['regularization']

        if attendance_id:
            attendance = get_object_or_404(
                Attendance,
                id=attendance_id,
                user=request.user
            )

            # Check if regularization can be requested
            if not attendance.can_request_regularization():
                messages.error(request, 'Regularization cannot be requested for this attendance record.')
                return redirect('attendance:calendar')

            if request.method == 'POST':
                form = RegularizationForm(request.POST)
                form.fields['attendance_id'].initial = attendance.id

                if form.is_valid():
                    result = regularization_service.submit_regularization_request(
                        attendance=attendance,
                        requested_status=form.cleaned_data['requested_status'],
                        reason=form.cleaned_data['reason'],
                        requested_by=request.user
                    )

                    if result['success']:
                        messages.success(request, result['message'])
                        return redirect('attendance:calendar')
                    else:
                        messages.error(request, result.get('error', 'Error submitting request'))
            else:
                form = RegularizationForm(initial={
                    'attendance_id': attendance.id,
                    'requested_status': attendance.status
                })

            context = {
                'form': form,
                'attendance': attendance,
                'title': f'Request Regularization for {attendance.date}'
            }

            return render(request, 'attendance/request_regularization.html', context)

        else:
            # Show list of attendance records that can be regularized
            regularizable_attendance = Attendance.objects.filter(
                user=request.user,
                date__gte=timezone.now().date() - timedelta(days=7)
            ).exclude(
                regularization_status='Approved'
            ).order_by('-date')

            # Filter records that can be regularized
            available_records = [
                att for att in regularizable_attendance
                if att.can_request_regularization()
            ]

            context = {
                'available_records': available_records,
                'title': 'Request Regularization'
            }

            return render(request, 'attendance/regularization_list.html', context)

    except Exception as e:
        logger.error(f"Error in request regularization: {e}")
        messages.error(request, 'Error processing regularization request.')
        return redirect('attendance:dashboard')


# Manager Views
@login_required
@group_required(group_names=['Manager'])
def manager_attendance_overview(request):
    """
    Manager attendance overview for team members
    """
    try:
        services = get_attendance_services()
        today = timezone.now().astimezone(IST).date()

        # Get team members (assuming there's a manager relationship)
        if request.user.is_superuser:
            team_members = User.objects.filter(is_active=True)
        else:
            team_members = User.objects.filter(
                profile__manager=request.user,
                is_active=True
            )

        # Get today's attendance for team
        team_attendance = Attendance.objects.filter(
            user__in=team_members,
            date=today
        ).select_related('user', 'shift')

        # Get attendance summary
        summary = Attendance.objects.get_attendance_summary(today)

        # Filter summary for team members only
        team_summary = {
            'total_team_members': team_members.count(),
            'present_count': team_attendance.filter(
                status__in=['Present', 'Present & Late', 'Work From Home']
            ).count(),
            'absent_count': team_attendance.filter(status='Absent').count(),
            'late_count': team_attendance.filter(
                status__in=['Present & Late', 'Late']
            ).count(),
            'on_leave_count': team_attendance.filter(status='On Leave').count(),
            'not_marked_count': team_attendance.filter(
                status__in=['Not Marked', 'Yet to Clock In']
            ).count(),
        }

        # Calculate team attendance percentage
        working_members = team_summary['total_team_members'] - team_summary['on_leave_count']
        if working_members > 0:
            team_summary['attendance_percentage'] = round(
                (team_summary['present_count'] / working_members) * 100, 1
            )
        else:
            team_summary['attendance_percentage'] = 0

        # Get pending regularizations for team
        pending_regularizations = Attendance.objects.filter(
            user__in=team_members,
            regularization_status='Pending'
        ).select_related('user').order_by('-last_regularization_date')

        # Filter form for detailed view
        filter_form = AttendanceFilterForm()

        context = {
            'team_attendance': team_attendance,
            'team_summary': team_summary,
            'pending_regularizations': pending_regularizations,
            'filter_form': filter_form,
            'today': today,
        }

        return render(request, 'attendance/overview.html', context)

    except Exception as e:
        logger.error(f"Error in manager overview: {e}")
        messages.error(request, 'Error loading manager overview.')
        return render(request, 'attendance/overview.html', {})


# HR Views
@login_required
@group_required(group_names=['HR'])
def hr_attendance_dashboard(request):
    """
    HR attendance dashboard with company-wide overview
    """
    try:
        services = get_attendance_services()
        today = timezone.now().astimezone(IST).date()

        # Get overall attendance summary
        summary = Attendance.objects.get_attendance_summary(today)

        # Get department-wise analytics
        dept_analytics = services['analytics'].get_department_analytics(today)

        # Get recent attendance trends (last 7 days)
        start_date = today - timedelta(days=6)
        trends = services['analytics'].get_attendance_trends(start_date, today)

        # Get late arrivals today
        late_attendances = Attendance.objects.get_late_attendances(today, threshold_minutes=5)

        # Get pending regularizations
        pending_regularizations = services['regularization'].get_pending_regularizations()

        # Quick stats for cards
        active_users = User.objects.filter(is_active=True).count()

        context = {
            'summary': summary,
            'dept_analytics': dept_analytics.get('analytics', []) if dept_analytics['success'] else [],
            'trends': trends.get('trends', []) if trends['success'] else [],
            'late_attendances': late_attendances[:10],  # Top 10 late arrivals
            'pending_regularizations_count': len(pending_regularizations),
            'active_users': active_users,
            'today': today,
        }

        return render(request, 'attendance/hr_dashboard.html', context)

    except Exception as e:
        logger.error(f"Error in HR dashboard: {e}")
        messages.error(request, 'Error loading HR dashboard.')
        return render(request, 'attendance/hr_dashboard.html', {})


@login_required
@group_required(group_names=['HR'])
def hr_regularization_requests(request):
    """
    HR view to manage regularization requests
    """
    try:
        services = get_attendance_services()
        regularization_service = services['regularization']

        # Get filtering parameters
        status_filter = request.GET.get('status', 'Pending')
        date_from = request.GET.get('date_from')
        date_to = request.GET.get('date_to')
        employee_search = request.GET.get('employee_search', '')

        # Get regularization requests
        queryset = Attendance.objects.get_regularization_requests(status=status_filter)

        # Apply additional filters
        if date_from:
            try:
                date_from = datetime.strptime(date_from, '%Y-%m-%d').date()
                queryset = queryset.filter(date__gte=date_from)
            except ValueError:
                pass

        if date_to:
            try:
                date_to = datetime.strptime(date_to, '%Y-%m-%d').date()
                queryset = queryset.filter(date__lte=date_to)
            except ValueError:
                pass

        if employee_search:
            queryset = queryset.filter(
                user__username__icontains=employee_search
            ) | queryset.filter(
                user__first_name__icontains=employee_search
            ) | queryset.filter(
                user__last_name__icontains=employee_search
            )

        # Pagination
        paginator = Paginator(queryset, 20)
        page_number = request.GET.get('page')
        page_obj = paginator.get_page(page_number)

        # Statistics
        stats = {
            'total': Attendance.objects.get_regularization_requests().count(),
            'pending': Attendance.objects.get_regularization_requests(status='Pending').count(),
            'approved': Attendance.objects.get_regularization_requests(status='Approved').count(),
            'rejected': Attendance.objects.get_regularization_requests(status='Rejected').count(),
        }

        context = {
            'page_obj': page_obj,
            'stats': stats,
            'status_filter': status_filter,
            'date_from': request.GET.get('date_from', ''),
            'date_to': request.GET.get('date_to', ''),
            'employee_search': employee_search,
        }

        return render(request, 'attendance/regularization_requests.html', context)

    except Exception as e:
        logger.error(f"Error in HR regularization requests: {e}")
        messages.error(request, 'Error loading regularization requests.')
        return render(request, 'attendance/regularization_requests.html', {})


@login_required
@user_passes_test(is_hr_check)
def process_regularization(request, attendance_id):
    """
    HR view to process individual regularization request
    """
    try:
        services = get_attendance_services()
        regularization_service = services['regularization']

        attendance = get_object_or_404(
            Attendance,
            id=attendance_id,
            regularization_status='Pending'
        )

        if request.method == 'POST':
            form = HRRegularizationProcessForm(request.POST)
            if form.is_valid():
                action = form.cleaned_data['action']
                comments = form.cleaned_data.get('comments', '')

                result = regularization_service.process_regularization_request(
                    attendance=attendance,
                    action=action,
                    processed_by=request.user,
                    comments=comments
                )

                if result['success']:
                    messages.success(request, result['message'])
                    return redirect('attendance:hr_regularization_requests')
                else:
                    messages.error(request, result.get('error', 'Error processing request'))
        else:
            form = HRRegularizationProcessForm()

        context = {
            'attendance': attendance,
            'form': form,
        }

        return render(request, 'attendance/process_regularization.html', context)

    except Exception as e:
        logger.error(f"Error processing regularization: {e}")
        messages.error(request, 'Error processing regularization request.')
        return redirect('attendance:hr_regularization_requests')


@login_required
@user_passes_test(is_hr_check)
def hr_add_attendance(request):
    """
    HR view to manually add/edit attendance records
    """
    try:
        if request.method == 'POST':
            form = AttendanceForm(request.POST, user=request.user)
            if form.is_valid():
                try:
                    with transaction.atomic():
                        attendance = form.save(commit=False)
                        attendance.modified_by = request.user
                        attendance.regularization_reason = f"Manually added by {request.user.get_full_name()}"
                        attendance.save()

                        messages.success(request, 'Attendance record created successfully!')
                        return redirect('attendance:hr_add_attendance')

                except Exception as e:
                    logger.error(f"Error saving attendance: {e}")
                    messages.error(request, 'Error saving attendance record.')
        else:
            form = AttendanceForm(user=request.user)

        # Show recent additions
        recent_additions = Attendance.objects.filter(
            modified_by=request.user,
            last_modified__gte=timezone.now() - timedelta(hours=24)
        ).select_related('user').order_by('-last_modified')[:10]

        context = {
            'form': form,
            'recent_additions': recent_additions,
        }

        return render(request, 'attendance/add_attendance.html', context)

    except Exception as e:
        logger.error(f"Error in HR add attendance: {e}")
        messages.error(request, 'Error loading attendance form.')
        return render(request, 'attendance/add_attendance.html', {})


@login_required
@group_required(group_names=['HR'])
def bulk_attendance_operations(request):
    """
    HR view for bulk attendance operations
    """
    try:
        services = get_attendance_services()
        bulk_service = services['bulk_operations']

        if request.method == 'POST':
            form = BulkAttendanceForm(request.POST)
            if form.is_valid():
                users = form.cleaned_data['users']
                date = form.cleaned_data['date']
                action = form.cleaned_data['action']
                reason = form.cleaned_data['reason']

                # Map action to status
                action_status_map = {
                    'mark_present': 'Present',
                    'mark_absent': 'Absent',
                    'mark_holiday': 'Holiday',
                    'mark_weekend': 'Weekend',
                }

                status = action_status_map.get(action)
                if status:
                    result = bulk_service.bulk_mark_attendance(
                        users=users,
                        date=date,
                        status=status,
                        reason=reason,
                        marked_by=request.user
                    )

                    if result['success']:
                        messages.success(
                            request,
                            f"Bulk operation completed: {result['created']} created, {result['updated']} updated"
                        )
                    else:
                        messages.error(request, f"Error in bulk operation: {result.get('error')}")
                else:
                    messages.error(request, 'Invalid bulk action selected.')

                return redirect('attendance:bulk_attendance_operations')
        else:
            form = BulkAttendanceForm()

        context = {
            'form': form,
        }

        return render(request, 'attendance/bulk_operations.html', context)

    except Exception as e:
        logger.error(f"Error in bulk operations: {e}")
        messages.error(request, 'Error in bulk operations.')
        return render(request, 'attendance/bulk_operations.html', {})


# Report Views
@login_required
@group_required(group_names=['Manager','HR'])
def attendance_report(request):
    """
    Generate attendance reports with various filters
    """
    try:
        services = get_attendance_services()
        report_service = services['reports']

        # Handle filter form
        filter_form = AttendanceFilterForm(request.GET or None, user=request.user)

        # Default date range (current month)
        today = timezone.now().astimezone(IST).date()
        start_date = today.replace(day=1)
        end_date = today

        if filter_form.is_valid():
            time_period = filter_form.cleaned_data.get('time_period')

            if time_period == 'custom':
                start_date = filter_form.cleaned_data.get('start_date') or start_date
                end_date = filter_form.cleaned_data.get('end_date') or end_date
            else:
                # Handle predefined time periods
                if time_period == 'today':
                    start_date = end_date = today
                elif time_period == 'yesterday':
                    start_date = end_date = today - timedelta(days=1)
                elif time_period == 'this_week':
                    start_date = today - timedelta(days=today.weekday())
                elif time_period == 'last_week':
                    start_date = today - timedelta(days=today.weekday() + 7)
                    end_date = start_date + timedelta(days=6)
                elif time_period == 'last_month':
                    if today.month == 1:
                        start_date = date(today.year - 1, 12, 1)
                        end_date = date(today.year - 1, 12, 31)
                    else:
                        start_date = date(today.year, today.month - 1, 1)
                        end_date = (date(today.year, today.month, 1) - timedelta(days=1))

        # Get user filter
        user_filter = None
        if filter_form.is_valid():
            user_filter = filter_form.cleaned_data.get('user')

        # Generate report based on user type and permissions
        if user_filter:
            # User-specific report
            report = report_service.generate_user_summary(
                user_filter, start_date, end_date
            )
        elif is_hr_check(request.user):
            # Company-wide report for HR
            report = report_service.generate_monthly_report(
                end_date.year, end_date.month
            )
        else:
            # User's own report
            report = report_service.generate_user_summary(
                request.user, start_date, end_date
            )

        context = {
            'filter_form': filter_form,
            'report': report,
            'start_date': start_date,
            'end_date': end_date,
            'can_export': True,
        }

        return render(request, 'attendance/report.html', context)

    except Exception as e:
        logger.error(f"Error generating attendance report: {e}")
        messages.error(request, 'Error generating report.')
        return render(request, 'attendance/report.html', {})


@login_required
def export_attendance_csv(request):
    """
    Export attendance data to CSV
    """
    try:
        # Get filter parameters
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        user_id = request.GET.get('user_id')

        # Parse dates
        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        else:
            start_date = timezone.now().date().replace(day=1)

        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        else:
            end_date = timezone.now().date()

        # Build queryset
        queryset = Attendance.objects.filter(
            date__range=[start_date, end_date]
        ).select_related('user', 'shift')

        if user_id:
            queryset = queryset.filter(user_id=user_id)
        elif not is_hr_check(request.user):
            # Non-HR users can only export their own data
            queryset = queryset.filter(user=request.user)

        # Create HTTP response with CSV content type
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="attendance_report_{start_date}_to_{end_date}.csv"'

        # Create CSV writer
        writer = csv.writer(response)

        # Write headers
        writer.writerow([
            'Employee', 'Date', 'Status', 'Clock In', 'Clock Out',
            'Total Hours', 'Late Minutes', 'Overtime Hours', 'Location',
            'Shift', 'Remarks'
        ])

        # Write data rows
        for attendance in queryset:
            writer.writerow([
                attendance.user.get_full_name(),
                attendance.date.strftime('%Y-%m-%d'),
                attendance.status,
                attendance.clock_in_time.strftime('%H:%M') if attendance.clock_in_time else '',
                attendance.clock_out_time.strftime('%H:%M') if attendance.clock_out_time else '',
                str(attendance.total_hours or 0),
                attendance.late_minutes,
                str(attendance.overtime_hours or 0),
                attendance.get_location_display(),
                attendance.shift.name if attendance.shift else '',
                attendance.remarks or ''
            ])

        return response

    except Exception as e:
        logger.error(f"Error exporting CSV: {e}")
        messages.error(request, 'Error exporting data.')
        return redirect('attendance:report')


# Analytics Views
@login_required
@group_required(group_names=['Manager', 'HR'])
def attendance_analytics(request):
    """
    HR analytics dashboard with detailed insights
    """
    try:
        services = get_attendance_services()
        analytics_service = services['analytics']

        # Get date range (default to current month)
        today = timezone.now().astimezone(IST).date()
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')

        if start_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
        else:
            start_date = today.replace(day=1)

        if end_date:
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        else:
            end_date = today

        # Get analytics data
        trends = analytics_service.get_attendance_trends(start_date, end_date)
        dept_analytics = analytics_service.get_department_analytics()
        late_analysis = analytics_service.get_late_arrival_analysis(start_date, end_date)

        context = {
            'trends': trends.get('trends', []) if trends['success'] else [],
            'dept_analytics': dept_analytics.get('analytics', []) if dept_analytics['success'] else [],
            'late_analysis': late_analysis.get('analysis', []) if late_analysis['success'] else [],
            'start_date': start_date,
            'end_date': end_date,
        }

        return render(request, 'attendance/analytics.html', context)

    except Exception as e:
        logger.error(f"Error in attendance analytics: {e}")
        messages.error(request, 'Error loading analytics.')
        return render(request, 'attendance/analytics.html', {})


# API Views
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
                'status_color': attendance.get_status_color(),
                'clock_in_time': attendance.clock_in_time.strftime('%H:%M') if attendance.clock_in_time else '',
                'clock_out_time': attendance.clock_out_time.strftime('%H:%M') if attendance.clock_out_time else '',
                'total_hours': str(attendance.total_hours) if attendance.total_hours else '0',
                'formatted_duration': attendance.get_formatted_duration(),
                'late_minutes': attendance.late_minutes,
                'overtime_hours': str(attendance.overtime_hours),
                'location': attendance.get_location_display(),
                'remarks': attendance.remarks or '',
                'regularization_status': attendance.regularization_status,
                'can_regularize': attendance.can_request_regularization(),
                'shift_name': attendance.shift.name if attendance.shift else None,
            }
        else:
            data = {'message': 'No attendance record found'}

        return JsonResponse(data)

    except Exception as e:
        logger.error(f"Error getting attendance data: {e}")
        return JsonResponse({'error': 'An error occurred'}, status=500)


@login_required
def get_monthly_attendance_data(request):
    """
    API endpoint to get monthly attendance data for calendar
    """
    try:
        user_id = request.GET.get('user_id', request.user.id)
        year = int(request.GET.get('year', timezone.now().year))
        month = int(request.GET.get('month', timezone.now().month))

        # Check permissions
        if not (is_hr_check(request.user) or is_manager_check(request.user)):
            if int(user_id) != request.user.id:
                return JsonResponse({'error': 'Permission denied'}, status=403)

        # Get date range for the month
        start_date = date(year, month, 1)
        if month == 12:
            end_date = date(year + 1, 1, 1) - timedelta(days=1)
        else:
            end_date = date(year, month + 1, 1) - timedelta(days=1)

        attendances = Attendance.objects.filter(
            user_id=user_id,
            date__range=[start_date, end_date]
        ).select_related('shift')

        attendance_data = {}
        for attendance in attendances:
            attendance_data[attendance.date.day] = {
                'id': attendance.id,
                'status': attendance.status,
                'status_color': attendance.get_status_color(),
                'clock_in': attendance.clock_in_time.strftime('%H:%M') if attendance.clock_in_time else None,
                'clock_out': attendance.clock_out_time.strftime('%H:%M') if attendance.clock_out_time else None,
                'total_hours': attendance.get_formatted_duration(),
                'late_minutes': attendance.late_minutes,
                'location': attendance.get_location_display(),
                'can_regularize': attendance.can_request_regularization(),
                'regularization_status': attendance.regularization_status,
            }

        return JsonResponse({
            'success': True,
            'attendance_data': attendance_data,
            'month': month,
            'year': year
        })

    except Exception as e:
        logger.error(f"Error getting monthly attendance data: {e}")
        return JsonResponse({'error': 'An error occurred'}, status=500)


@login_required
@group_required(group_names=['HR'])
def run_auto_marking(request):
    """
    API endpoint to manually trigger auto attendance marking
    """
    try:
        services = get_attendance_services()
        auto_marking_service = services['auto_marking']

        date_str = request.GET.get('date')
        if date_str:
            target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            target_date = timezone.now().astimezone(IST).date()

        result = auto_marking_service.run_auto_marking(target_date)

        return JsonResponse(result)

    except Exception as e:
        logger.error(f"Error running auto marking: {e}")
        return JsonResponse({'success': False, 'error': str(e)})


@login_required
def attendance_summary_api(request):
    """
    API endpoint to get attendance summary data
    """
    try:
        date_str = request.GET.get('date')
        if date_str:
            target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            target_date = timezone.now().astimezone(IST).date()

        # Check permissions
        if is_hr_check(request.user):
            # HR can see all data
            summary = Attendance.objects.get_attendance_summary(target_date)
        elif is_manager_check(request.user):
            # Manager can see team data
            team_members = User.objects.filter(
                profile__manager=request.user,
                is_active=True
            )
            team_attendance = Attendance.objects.filter(
                user__in=team_members,
                date=target_date
            )
            summary = {
                'total_employees': team_members.count(),
                'present_count': team_attendance.filter(
                    status__in=['Present', 'Present & Late', 'Work From Home']
                ).count(),
                'absent_count': team_attendance.filter(status='Absent').count(),
                'late_count': team_attendance.filter(
                    status__in=['Present & Late', 'Late']
                ).count(),
                'on_leave_count': team_attendance.filter(status='On Leave').count(),
            }
        else:
            # Employee can see only their own data
            user_attendance = Attendance.objects.filter(
                user=request.user,
                date=target_date
            ).first()

            summary = {
                'status': user_attendance.status if user_attendance else 'Not Marked',
                'clock_in_time': user_attendance.clock_in_time if user_attendance else None,
                'clock_out_time': user_attendance.clock_out_time if user_attendance else None,
                'total_hours': str(user_attendance.total_hours) if user_attendance and user_attendance.total_hours else '0',
            }

        return JsonResponse({
            'success': True,
            'summary': summary,
            'date': target_date.isoformat()
        })

    except Exception as e:
        logger.error(f"Error getting attendance summary: {e}")
        return JsonResponse({'success': False, 'error': str(e)})


# Utility Views
@login_required
def search_attendance(request):
    """
    Search attendance records with various filters
    """
    try:
        form = AttendanceSearchForm(request.GET or None)
        results = []

        if form.is_valid():
            queryset = Attendance.objects.select_related('user', 'shift')

            # Apply filters
            employee_search = form.cleaned_data.get('employee_search')
            if employee_search:
                queryset = queryset.filter(
                    user__username__icontains=employee_search
                ) | queryset.filter(
                    user__first_name__icontains=employee_search
                ) | queryset.filter(
                    user__last_name__icontains=employee_search
                )

            date_from = form.cleaned_data.get('date_from')
            if date_from:
                queryset = queryset.filter(date__gte=date_from)

            date_to = form.cleaned_data.get('date_to')
            if date_to:
                queryset = queryset.filter(date__lte=date_to)

            status = form.cleaned_data.get('status')
            if status:
                queryset = queryset.filter(status=status)

            regularization_status = form.cleaned_data.get('regularization_status')
            if regularization_status:
                queryset = queryset.filter(regularization_status=regularization_status)

            # Apply permissions
            if not (is_hr_check(request.user) or is_manager_check(request.user)):
                queryset = queryset.filter(user=request.user)

            # Pagination
            paginator = Paginator(queryset.order_by('-date'), 25)
            page_number = request.GET.get('page')
            results = paginator.get_page(page_number)

        context = {
            'form': form,
            'results': results,
        }

        return render(request, 'attendance/search.html', context)

    except Exception as e:
        logger.error(f"Error in search attendance: {e}")
        messages.error(request, 'Error performing search.')
        return render(request, 'attendance/search.html', {})


@login_required
@group_required(group_names=['HR'])
def attendance_cleanup(request):
    """
    HR utility to cleanup old attendance records
    """
    try:
        if request.method == 'POST':
            days_to_keep = int(request.POST.get('days_to_keep', 365))

            if days_to_keep < 30:
                messages.error(request, 'Cannot delete records newer than 30 days.')
                return redirect('attendance:cleanup')

            deleted_count = Attendance.objects.cleanup_old_records(days_to_keep)

            messages.success(
                request,
                f'Successfully cleaned up {deleted_count} old attendance records.'
            )

            return redirect('attendance:hr_dashboard')

        context = {
            'total_records': Attendance.objects.count(),
        }

        return render(request, 'attendance/cleanup.html', context)

    except Exception as e:
        logger.error(f"Error in attendance cleanup: {e}")
        messages.error(request, 'Error in cleanup operation.')
        return render(request, 'attendance/cleanup.html', {})
