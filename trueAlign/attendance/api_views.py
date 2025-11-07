# attendance/api_views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib.auth import get_user_model
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.utils import timezone
from django.core.paginator import Paginator
from django.db import transaction
from django.core.exceptions import ValidationError
from django.views import View
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from datetime import datetime, date, timedelta
import calendar
import csv
import json
import pytz
import logging
import openpyxl
from openpyxl.styles import Font, Alignment, PatternFill
from io import BytesIO
from functools import wraps

from trueAlign.models import Attendance, UserSession, Holiday, ShiftAssignment, User
from .decorators import role_required, group_required
from .services import (
    AttendanceAutoMarkingService,
    AttendanceIntegrationService,
    AttendanceRegularizationService,
    AttendanceReportService,
    AttendanceAnalyticsService,
    AttendanceBulkOperationService,
    get_attendance_services
)

logger = logging.getLogger(__name__)
User = get_user_model()
IST = pytz.timezone('Asia/Kolkata')


def get_user_role(user):
    """Get user role based on group membership"""
    if user.groups.filter(name='HR').exists():
        return 'HR'
    elif user.groups.filter(name='Manager').exists():
        return 'Manager'
    elif user.groups.filter(name='Admin').exists():
        return 'Admin'
    else:
        return 'Employee'


def has_view_all_permission(user):
    """Check if user can view all attendance data"""
    return user.groups.filter(name__in=['HR', 'Admin']).exists() or user.is_superuser


def has_export_permission(user):
    """Check if user has export permissions"""
    return user.groups.filter(name__in=['HR', 'Manager', 'Admin']).exists() or user.is_superuser


def has_regularize_permission(user):
    """Check if user can approve/reject regularizations"""
    return user.groups.filter(name__in=['HR', 'Admin']).exists() or user.is_superuser


class RoleBasedAttendanceAPI:
    """Base class for role-based API access"""

    @staticmethod
    def get_user_accessible_data(user, queryset):
        """Filter queryset based on user role"""
        role = get_user_role(user)

        if role in ['HR', 'Admin'] or user.is_superuser:
            return queryset
        elif role == 'Manager':
            # Managers can see their team members
            team_members = User.objects.filter(
                profile__manager=user
            ).values_list('id', flat=True)
            return queryset.filter(user_id__in=list(team_members) + [user.id])
        else:
            # Employees can only see their own data
            return queryset.filter(user=user)


@method_decorator(login_required, name='dispatch')
class DashboardDataAPI(View, RoleBasedAttendanceAPI):
    """API endpoint for dashboard data based on user role"""

    def get(self, request):
        try:
            user_role = get_user_role(request.user)
            today = timezone.now().astimezone(IST).date()

            # Get date range from request
            start_date = request.GET.get('start_date')
            end_date = request.GET.get('end_date')

            if start_date and end_date:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            else:
                # Default to current month
                start_date = today.replace(day=1)
                end_date = today

            # Base queryset
            queryset = Attendance.objects.select_related('user', 'shift').filter(
                date__range=[start_date, end_date]
            )

            # Apply role-based filtering
            queryset = self.get_user_accessible_data(request.user, queryset)

            # Prepare response data based on role
            if user_role in ['HR', 'Admin']:
                data = self._get_hr_dashboard_data(queryset, start_date, end_date)
            elif user_role == 'Manager':
                data = self._get_manager_dashboard_data(queryset, start_date, end_date, request.user)
            else:
                data = self._get_employee_dashboard_data(queryset, start_date, end_date, request.user)

            return JsonResponse({
                'status': 'success',
                'role': user_role,
                'data': data
            })

        except Exception as e:
            logger.error(f"Dashboard API error for user {request.user.username}: {e}")
            return JsonResponse({
                'status': 'error',
                'message': 'Failed to fetch dashboard data'
            }, status=500)

    def _get_hr_dashboard_data(self, queryset, start_date, end_date):
        """Get comprehensive dashboard data for HR"""
        total_records = queryset.count()
        present_count = queryset.filter(status__icontains='Present').count()
        absent_count = queryset.filter(status='Absent').count()
        late_count = queryset.filter(status='Present & Late').count()
        on_leave_count = queryset.filter(status='On Leave').count()

        # Department-wise breakdown
        dept_data = {}
        for attendance in queryset.select_related('user__profile'):
            dept = getattr(attendance.user.profile, 'department', 'Unknown') if hasattr(attendance.user, 'profile') else 'Unknown'
            if dept not in dept_data:
                dept_data[dept] = {'total': 0, 'present': 0, 'absent': 0}
            dept_data[dept]['total'] += 1
            if 'Present' in attendance.status:
                dept_data[dept]['present'] += 1
            elif attendance.status == 'Absent':
                dept_data[dept]['absent'] += 1

        return {
            'summary': {
                'total_records': total_records,
                'present_count': present_count,
                'absent_count': absent_count,
                'late_count': late_count,
                'on_leave_count': on_leave_count,
                'attendance_rate': round((present_count / total_records * 100), 2) if total_records > 0 else 0
            },
            'department_breakdown': dept_data,
            'recent_activities': list(queryset.order_by('-created_at')[:10].values(
                'user__username', 'date', 'status', 'clock_in_time', 'clock_out_time'
            )),
            'pending_regularizations': Attendance.objects.filter(
                regularization_requested=True,
                regularization_status='Pending'
            ).count()
        }

    def _get_manager_dashboard_data(self, queryset, start_date, end_date, manager):
        """Get team-specific dashboard data for managers"""
        # Get team members
        team_members = User.objects.filter(profile__manager=manager)
        team_queryset = queryset.filter(user__in=team_members)

        total_records = team_queryset.count()
        present_count = team_queryset.filter(status__icontains='Present').count()
        absent_count = team_queryset.filter(status='Absent').count()
        late_count = team_queryset.filter(status='Present & Late').count()

        # Team member breakdown
        team_data = []
        for member in team_members:
            member_attendance = team_queryset.filter(user=member)
            team_data.append({
                'username': member.username,
                'full_name': f"{member.first_name} {member.last_name}".strip(),
                'total_days': member_attendance.count(),
                'present_days': member_attendance.filter(status__icontains='Present').count(),
                'absent_days': member_attendance.filter(status='Absent').count(),
                'late_days': member_attendance.filter(status='Present & Late').count()
            })

        return {
            'summary': {
                'team_size': team_members.count(),
                'total_records': total_records,
                'present_count': present_count,
                'absent_count': absent_count,
                'late_count': late_count,
                'team_attendance_rate': round((present_count / total_records * 100), 2) if total_records > 0 else 0
            },
            'team_breakdown': team_data,
            'recent_activities': list(team_queryset.order_by('-created_at')[:5].values(
                'user__username', 'date', 'status', 'clock_in_time', 'clock_out_time'
            ))
        }

    def _get_employee_dashboard_data(self, queryset, start_date, end_date, employee):
        """Get personal dashboard data for employees"""
        personal_queryset = queryset.filter(user=employee)

        total_days = personal_queryset.count()
        present_days = personal_queryset.filter(status__icontains='Present').count()
        absent_days = personal_queryset.filter(status='Absent').count()
        late_days = personal_queryset.filter(status='Present & Late').count()
        leave_days = personal_queryset.filter(status='On Leave').count()

        # Today's status
        today_attendance = personal_queryset.filter(date=timezone.now().astimezone(IST).date()).first()

        # Weekly pattern
        weekly_data = []
        for i in range(7):
            day_date = start_date + timedelta(days=i)
            if day_date <= end_date:
                day_attendance = personal_queryset.filter(date=day_date).first()
                weekly_data.append({
                    'date': day_date.strftime('%Y-%m-%d'),
                    'day': day_date.strftime('%A'),
                    'status': day_attendance.status if day_attendance else 'No Record',
                    'clock_in': day_attendance.clock_in_time.strftime('%H:%M') if day_attendance and day_attendance.clock_in_time else None,
                    'clock_out': day_attendance.clock_out_time.strftime('%H:%M') if day_attendance and day_attendance.clock_out_time else None,
                    'total_hours': str(day_attendance.total_hours) if day_attendance and day_attendance.total_hours else None
                })

        return {
            'summary': {
                'total_days': total_days,
                'present_days': present_days,
                'absent_days': absent_days,
                'late_days': late_days,
                'leave_days': leave_days,
                'attendance_rate': round((present_days / total_days * 100), 2) if total_days > 0 else 0
            },
            'today_status': {
                'date': timezone.now().astimezone(IST).date().strftime('%Y-%m-%d'),
                'status': today_attendance.status if today_attendance else 'Not Marked',
                'clock_in': today_attendance.clock_in_time.strftime('%H:%M') if today_attendance and today_attendance.clock_in_time else None,
                'clock_out': today_attendance.clock_out_time.strftime('%H:%M') if today_attendance and today_attendance.clock_out_time else None,
                'total_hours': str(today_attendance.total_hours) if today_attendance and today_attendance.total_hours else None
            },
            'weekly_pattern': weekly_data,
            'pending_regularizations': personal_queryset.filter(
                regularization_requested=True,
                regularization_status='Pending'
            ).count()
        }


@login_required
def dashboard_charts_api(request):
    """API endpoint for dashboard charts data"""
    try:
        user_role = get_user_role(request.user)

        # Get date range
        days = int(request.GET.get('days', 30))
        end_date = timezone.now().astimezone(IST).date()
        start_date = end_date - timedelta(days=days)

        # Base queryset
        queryset = Attendance.objects.filter(date__range=[start_date, end_date])

        # Apply role-based filtering
        api = RoleBasedAttendanceAPI()
        queryset = api.get_user_accessible_data(request.user, queryset)

        # Prepare chart data
        daily_data = []
        for i in range(days):
            day_date = start_date + timedelta(days=i)
            day_queryset = queryset.filter(date=day_date)

            daily_data.append({
                'date': day_date.strftime('%Y-%m-%d'),
                'present': day_queryset.filter(status__icontains='Present').count(),
                'absent': day_queryset.filter(status='Absent').count(),
                'late': day_queryset.filter(status='Present & Late').count(),
                'on_leave': day_queryset.filter(status='On Leave').count()
            })

        # Status distribution
        status_distribution = {
            'Present': queryset.filter(status='Present').count(),
            'Present & Late': queryset.filter(status='Present & Late').count(),
            'Absent': queryset.filter(status='Absent').count(),
            'On Leave': queryset.filter(status='On Leave').count(),
            'Holiday': queryset.filter(status='Holiday').count(),
            'Weekend': queryset.filter(status='Weekend').count()
        }

        return JsonResponse({
            'status': 'success',
            'data': {
                'daily_trend': daily_data,
                'status_distribution': status_distribution
            }
        })

    except Exception as e:
        logger.error(f"Charts API error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def dashboard_summary_api(request):
    """API endpoint for dashboard summary"""
    try:
        today = timezone.now().astimezone(IST).date()
        user_role = get_user_role(request.user)

        # Base queryset for today
        today_queryset = Attendance.objects.filter(date=today)

        # Apply role-based filtering
        api = RoleBasedAttendanceAPI()
        today_queryset = api.get_user_accessible_data(request.user, today_queryset)

        summary = {
            'total_employees': today_queryset.values('user').distinct().count(),
            'present_today': today_queryset.filter(status__icontains='Present').count(),
            'absent_today': today_queryset.filter(status='Absent').count(),
            'late_today': today_queryset.filter(status='Present & Late').count(),
            'on_leave_today': today_queryset.filter(status='On Leave').count(),
            'yet_to_clock_in': today_queryset.filter(status='Yet to Clock In').count()
        }

        # Add role-specific data
        if user_role in ['HR', 'Admin']:
            summary['pending_regularizations'] = Attendance.objects.filter(
                regularization_requested=True,
                regularization_status='Pending'
            ).count()

        return JsonResponse({
            'status': 'success',
            'data': summary
        })

    except Exception as e:
        logger.error(f"Summary API error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def employee_personal_data(request):
    """API endpoint for employee personal attendance data"""
    try:
        # Get date range
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')

        if start_date and end_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        else:
            today = timezone.now().astimezone(IST).date()
            start_date = today.replace(day=1)
            end_date = today

        # Get personal attendance data
        queryset = Attendance.objects.filter(
            user=request.user,
            date__range=[start_date, end_date]
        ).order_by('-date')

        data = []
        for attendance in queryset:
            data.append({
                'id': attendance.id,
                'date': attendance.date.strftime('%Y-%m-%d'),
                'day': attendance.date.strftime('%A'),
                'status': attendance.status,
                'clock_in': attendance.clock_in_time.strftime('%H:%M:%S') if attendance.clock_in_time else None,
                'clock_out': attendance.clock_out_time.strftime('%H:%M:%S') if attendance.clock_out_time else None,
                'total_hours': str(attendance.total_hours) if attendance.total_hours else None,
                'overtime_hours': str(attendance.overtime_hours) if attendance.overtime_hours else None,
                'late_minutes': attendance.late_minutes,
                'regularization_requested': attendance.regularization_requested,
                'regularization_status': attendance.regularization_status,
                'regularization_reason': attendance.regularization_reason
            })

        return JsonResponse({
            'status': 'success',
            'data': data,
            'date_range': {
                'start_date': start_date.strftime('%Y-%m-%d'),
                'end_date': end_date.strftime('%Y-%m-%d')
            }
        })

    except Exception as e:
        logger.error(f"Employee personal data API error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def employee_monthly_summary(request):
    """API endpoint for employee monthly summary"""
    try:
        # Get month and year from request
        month = int(request.GET.get('month', timezone.now().month))
        year = int(request.GET.get('year', timezone.now().year))

        # Get monthly data
        start_date = date(year, month, 1)
        end_date = date(year, month, calendar.monthrange(year, month)[1])

        queryset = Attendance.objects.filter(
            user=request.user,
            date__range=[start_date, end_date]
        )

        # Calculate summary
        total_days = queryset.count()
        present_days = queryset.filter(status__icontains='Present').count()
        absent_days = queryset.filter(status='Absent').count()
        late_days = queryset.filter(status='Present & Late').count()
        leave_days = queryset.filter(status='On Leave').count()
        holiday_days = queryset.filter(status='Holiday').count()
        weekend_days = queryset.filter(status='Weekend').count()

        # Calculate total working hours
        total_hours = sum([
            float(att.total_hours) for att in queryset
            if att.total_hours and att.status not in ['Absent', 'On Leave', 'Holiday', 'Weekend']
        ])

        # Calculate overtime hours
        overtime_hours = sum([
            float(att.overtime_hours) for att in queryset
            if att.overtime_hours
        ])

        return JsonResponse({
            'status': 'success',
            'data': {
                'month': month,
                'year': year,
                'summary': {
                    'total_days': total_days,
                    'present_days': present_days,
                    'absent_days': absent_days,
                    'late_days': late_days,
                    'leave_days': leave_days,
                    'holiday_days': holiday_days,
                    'weekend_days': weekend_days,
                    'total_working_hours': round(total_hours, 2),
                    'overtime_hours': round(overtime_hours, 2),
                    'attendance_percentage': round((present_days / total_days * 100), 2) if total_days > 0 else 0
                }
            }
        })

    except Exception as e:
        logger.error(f"Employee monthly summary API error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def employee_attendance_history(request):
    """API endpoint for employee attendance history"""
    try:
        # Pagination
        page = int(request.GET.get('page', 1))
        per_page = int(request.GET.get('per_page', 20))

        queryset = Attendance.objects.filter(user=request.user).order_by('-date')
        paginator = Paginator(queryset, per_page)
        page_obj = paginator.get_page(page)

        data = []
        for attendance in page_obj:
            data.append({
                'id': attendance.id,
                'date': attendance.date.strftime('%Y-%m-%d'),
                'status': attendance.status,
                'clock_in': attendance.clock_in_time.strftime('%H:%M') if attendance.clock_in_time else None,
                'clock_out': attendance.clock_out_time.strftime('%H:%M') if attendance.clock_out_time else None,
                'total_hours': str(attendance.total_hours) if attendance.total_hours else None,
                'regularization_requested': attendance.regularization_requested
            })

        return JsonResponse({
            'status': 'success',
            'data': data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_pages': paginator.num_pages,
                'total_records': paginator.count,
                'has_next': page_obj.has_next(),
                'has_previous': page_obj.has_previous()
            }
        })

    except Exception as e:
        logger.error(f"Employee attendance history API error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@role_required(['Manager', 'HR', 'Admin'])
def manager_team_overview(request):
    """API endpoint for manager team overview"""
    try:
        # Get team members
        if get_user_role(request.user) in ['HR', 'Admin']:
            # HR can see all users, optionally filtered by department
            department = request.GET.get('department')
            if department:
                team_members = User.objects.filter(profile__department=department)
            else:
                team_members = User.objects.all()
        else:
            # Managers see their team
            team_members = User.objects.filter(profile__manager=request.user)

        # Get date range
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')

        if start_date and end_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        else:
            today = timezone.now().astimezone(IST).date()
            start_date = today.replace(day=1)
            end_date = today

        team_data = []
        for member in team_members:
            member_attendance = Attendance.objects.filter(
                user=member,
                date__range=[start_date, end_date]
            )

            present_days = member_attendance.filter(status__icontains='Present').count()
            total_days = member_attendance.count()

            team_data.append({
                'user_id': member.id,
                'username': member.username,
                'full_name': f"{member.first_name} {member.last_name}".strip(),
                'email': member.email,
                'department': getattr(member.profile, 'department', 'Unknown') if hasattr(member, 'profile') else 'Unknown',
                'total_days': total_days,
                'present_days': present_days,
                'absent_days': member_attendance.filter(status='Absent').count(),
                'late_days': member_attendance.filter(status='Present & Late').count(),
                'leave_days': member_attendance.filter(status='On Leave').count(),
                'attendance_rate': round((present_days / total_days * 100), 2) if total_days > 0 else 0,
                'last_activity': member_attendance.order_by('-date').first().date.strftime('%Y-%m-%d') if member_attendance.exists() else None
            })

        return JsonResponse({
            'status': 'success',
            'data': {
                'team_members': team_data,
                'date_range': {
                    'start_date': start_date.strftime('%Y-%m-%d'),
                    'end_date': end_date.strftime('%Y-%m-%d')
                }
            }
        })

    except Exception as e:
        logger.error(f"Manager team overview API error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@role_required(['Manager', 'HR', 'Admin'])
def manager_team_summary(request):
    """API endpoint for manager team summary"""
    try:
        user_role = get_user_role(request.user)
        today = timezone.now().astimezone(IST).date()

        # Get team members based on role
        if user_role in ['HR', 'Admin']:
            team_members = User.objects.all()
        else:
            team_members = User.objects.filter(profile__manager=request.user)

        # Today's summary
        today_attendance = Attendance.objects.filter(
            user__in=team_members,
            date=today
        )

        summary = {
            'team_size': team_members.count(),
            'present_today': today_attendance.filter(status__icontains='Present').count(),
            'absent_today': today_attendance.filter(status='Absent').count(),
            'late_today': today_attendance.filter(status='Present & Late').count(),
            'on_leave_today': today_attendance.filter(status='On Leave').count(),
            'yet_to_clock_in': today_attendance.filter(status='Yet to Clock In').count(),
            'attendance_rate': 0
        }

        if summary['team_size'] > 0:
            summary['attendance_rate'] = round(
                ((summary['present_today'] + summary['late_today']) / summary['team_size'] * 100), 2
            )

        return JsonResponse({
            'status': 'success',
            'data': summary
        })

    except Exception as e:
        logger.error(f"Manager team summary API error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@role_required(['HR', 'Admin'])
def hr_all_users_data(request):
    """API endpoint for HR to get all users attendance data"""
    try:
        # Get date range
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')

        if start_date and end_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        else:
            today = timezone.now().astimezone(IST).date()
            start_date = today.replace(day=1)
            end_date = today

        # Pagination
        page = int(request.GET.get('page', 1))
        per_page = int(request.GET.get('per_page', 50))

        # Filters
        department = request.GET.get('department')
        status = request.GET.get('status')

        queryset = Attendance.objects.filter(
            date__range=[start_date, end_date]
        ).select_related('user', 'user__profile', 'shift')

        if department:
            queryset = queryset.filter(user__profile__department=department)

        if status:
            queryset = queryset.filter(status=status)

        queryset = queryset.order_by('-date', 'user__username')

        paginator = Paginator(queryset, per_page)
        page_obj = paginator.get_page(page)

        data = []
        for attendance in page_obj:
            data.append({
                'id': attendance.id,
                'user_id': attendance.user.id,
                'username': attendance.user.username,
                'full_name': f"{attendance.user.first_name} {attendance.user.last_name}".strip(),
                'department': getattr(attendance.user.profile, 'department', 'Unknown') if hasattr(attendance.user, 'profile') else 'Unknown',
                'date': attendance.date.strftime('%Y-%m-%d'),
                'status': attendance.status,
                'clock_in': attendance.clock_in_time.strftime('%H:%M:%S') if attendance.clock_in_time else None,
                'clock_out': attendance.clock_out_time.strftime('%H:%M:%S') if attendance.clock_out_time else None,
                'total_hours': str(attendance.total_hours) if attendance.total_hours else None,
                'late_minutes': attendance.late_minutes,
                'regularization_requested': attendance.regularization_requested,
                'regularization_status': attendance.regularization_status
            })

        return JsonResponse({
            'status': 'success',
            'data': data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total_pages': paginator.num_pages,
                'total_records': paginator.count,
                'has_next': page_obj.has_next(),
                'has_previous': page_obj.has_previous()
            },
            'filters': {
                'date_range': {
                    'start_date': start_date.strftime('%Y-%m-%d'),
                    'end_date': end_date.strftime('%Y-%m-%d')
                },
                'department': department,
                'status': status
            }
        })

    except Exception as e:
        logger.error(f"HR all users data API error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@role_required(['HR', 'Admin'])
def hr_analytics_data(request):
    """API endpoint for HR analytics data"""
    try:
        # Get date range
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')

        if start_date and end_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        else:
            today = timezone.now().astimezone(IST).date()
            start_date = today.replace(day=1)
            end_date = today

        queryset = Attendance.objects.filter(date__range=[start_date, end_date])

        # Overall statistics
        total_records = queryset.count()
        present_count = queryset.filter(status__icontains='Present').count()
        absent_count = queryset.filter(status='Absent').count()
        late_count = queryset.filter(status='Present & Late').count()
        leave_count = queryset.filter(status='On Leave').count()

        # Department-wise analytics
        dept_analytics = {}
        for attendance in queryset.select_related('user__profile'):
            dept = getattr(attendance.user.profile, 'department', 'Unknown') if hasattr(attendance.user, 'profile') else 'Unknown'
            if dept not in dept_analytics:
                dept_analytics[dept] = {
                    'total': 0, 'present': 0, 'absent': 0, 'late': 0, 'leave': 0
                }
            dept_analytics[dept]['total'] += 1
            if 'Present' in attendance.status:
                if 'Late' in attendance.status:
                    dept_analytics[dept]['late'] += 1
                dept_analytics[dept]['present'] += 1
            elif attendance.status == 'Absent':
                dept_analytics[dept]['absent'] += 1
            elif attendance.status == 'On Leave':
                dept_analytics[dept]['leave'] += 1

        # Daily trend
        daily_trend = []
        current_date = start_date
        while current_date <= end_date:
            day_data = queryset.filter(date=current_date)
            daily_trend.append({
                'date': current_date.strftime('%Y-%m-%d'),
                'present': day_data.filter(status__icontains='Present').count(),
                'absent': day_data.filter(status='Absent').count(),
                'late': day_data.filter(status='Present & Late').count(),
                'leave': day_data.filter(status='On Leave').count()
            })
            current_date += timedelta(days=1)

        return JsonResponse({
            'status': 'success',
            'data': {
                'overall_stats': {
                    'total_records': total_records,
                    'present_count': present_count,
                    'absent_count': absent_count,
                    'late_count': late_count,
                    'leave_count': leave_count,
                    'attendance_rate': round((present_count / total_records * 100), 2) if total_records > 0 else 0,
                    'punctuality_rate': round(((present_count - late_count) / present_count * 100), 2) if present_count > 0 else 0
                },
                'department_analytics': dept_analytics,
                'daily_trend': daily_trend
            }
        })

    except Exception as e:
        logger.error(f"HR analytics API error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@role_required(['HR', 'Admin'])
def hr_department_summary(request):
    """API endpoint for HR department summary"""
    try:
        today = timezone.now().astimezone(IST).date()

        # Get all departments
        departments = User.objects.filter(
            profile__department__isnull=False
        ).values_list('profile__department', flat=True).distinct()

        dept_summary = []
        for dept in departments:
            dept_users = User.objects.filter(profile__department=dept)
            today_attendance = Attendance.objects.filter(
                user__in=dept_users,
                date=today
            )

            dept_summary.append({
                'department': dept,
                'total_employees': dept_users.count(),
                'present_today': today_attendance.filter(status__icontains='Present').count(),
                'absent_today': today_attendance.filter(status='Absent').count(),
                'late_today': today_attendance.filter(status='Present & Late').count(),
                'on_leave_today': today_attendance.filter(status='On Leave').count(),
                'attendance_rate': round(
                    (today_attendance.filter(status__icontains='Present').count() / dept_users.count() * 100), 2
                ) if dept_users.count() > 0 else 0
            })

        return JsonResponse({
            'status': 'success',
            'data': {
                'department_summary': dept_summary,
                'date': today.strftime('%Y-%m-%d')
            }
        })

    except Exception as e:
        logger.error(f"HR department summary API error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def export_excel(request):
    """Export attendance data to Excel"""
    try:
        if not has_export_permission(request.user):
            return JsonResponse({'error': 'Permission denied'}, status=403)

        # Get parameters
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')
        user_ids = request.GET.getlist('user_ids')

        if start_date and end_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        else:
            today = timezone.now().astimezone(IST).date()
            start_date = today.replace(day=1)
            end_date = today

        # Base queryset
        queryset = Attendance.objects.filter(date__range=[start_date, end_date])

        # Apply role-based filtering
        api = RoleBasedAttendanceAPI()
        queryset = api.get_user_accessible_data(request.user, queryset)

        if user_ids:
            queryset = queryset.filter(user_id__in=user_ids)

        # Create Excel workbook
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Attendance Report"

        # Headers
        headers = [
            'Date', 'Employee ID', 'Employee Name', 'Department',
            'Status', 'Clock In', 'Clock Out', 'Total Hours',
            'Overtime Hours', 'Late Minutes', 'Regularization Status'
        ]

        for col, header in enumerate(headers, 1):
            cell = ws.cell(row=1, column=col, value=header)
            cell.font = Font(bold=True)
            cell.fill = PatternFill(start_color='CCCCCC', end_color='CCCCCC', fill_type='solid')

        # Data rows
        for row, attendance in enumerate(queryset.select_related('user', 'user__profile'), 2):
            ws.cell(row=row, column=1, value=attendance.date.strftime('%Y-%m-%d'))
            ws.cell(row=row, column=2, value=attendance.user.username)
            ws.cell(row=row, column=3, value=f"{attendance.user.first_name} {attendance.user.last_name}".strip())
            ws.cell(row=row, column=4, value=getattr(attendance.user.profile, 'department', 'Unknown') if hasattr(attendance.user, 'profile') else 'Unknown')
            ws.cell(row=row, column=5, value=attendance.status)
            ws.cell(row=row, column=6, value=attendance.clock_in_time.strftime('%H:%M:%S') if attendance.clock_in_time else '')
            ws.cell(row=row, column=7, value=attendance.clock_out_time.strftime('%H:%M:%S') if attendance.clock_out_time else '')
            ws.cell(row=row, column=8, value=str(attendance.total_hours) if attendance.total_hours else '')
            ws.cell(row=row, column=9, value=str(attendance.overtime_hours) if attendance.overtime_hours else '')
            ws.cell(row=row, column=10, value=attendance.late_minutes)
            ws.cell(row=row, column=11, value=attendance.regularization_status)

        # Auto-adjust column widths
        for column in ws.columns:
            max_length = 0
            column = list(column)
            for cell in column:
                try:
                    if len(str(cell.value)) > max_length:
                        max_length = len(str(cell.value))
                except:
                    pass
            adjusted_width = min(max_length + 2, 50)
            ws.column_dimensions[column[0].column_letter].width = adjusted_width

        # Save to BytesIO
        buffer = BytesIO()
        wb.save(buffer)
        buffer.seek(0)

        # Create response
        response = HttpResponse(
            buffer.read(),
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        filename = f'attendance_report_{start_date.strftime("%Y%m%d")}_{end_date.strftime("%Y%m%d")}.xlsx'
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response

    except Exception as e:
        logger.error(f"Excel export error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def export_csv(request):
    """Export attendance data to CSV"""
    try:
        if not has_export_permission(request.user):
            return JsonResponse({'error': 'Permission denied'}, status=403)

        # Get parameters (same as Excel export)
        start_date = request.GET.get('start_date')
        end_date = request.GET.get('end_date')

        if start_date and end_date:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        else:
            today = timezone.now().astimezone(IST).date()
            start_date = today.replace(day=1)
            end_date = today

        # Base queryset
        queryset = Attendance.objects.filter(date__range=[start_date, end_date])

        # Apply role-based filtering
        api = RoleBasedAttendanceAPI()
        queryset = api.get_user_accessible_data(request.user, queryset)

        # Create CSV response
        response = HttpResponse(content_type='text/csv')
        filename = f'attendance_report_{start_date.strftime("%Y%m%d")}_{end_date.strftime("%Y%m%d")}.csv'
        response['Content-Disposition'] = f'attachment; filename="{filename}"'

        writer = csv.writer(response)

        # Headers
        writer.writerow([
            'Date', 'Employee ID', 'Employee Name', 'Department',
            'Status', 'Clock In', 'Clock Out', 'Total Hours',
            'Overtime Hours', 'Late Minutes', 'Regularization Status'
        ])

        # Data rows
        for attendance in queryset.select_related('user', 'user__profile'):
            writer.writerow([
                attendance.date.strftime('%Y-%m-%d'),
                attendance.user.username,
                f"{attendance.user.first_name} {attendance.user.last_name}".strip(),
                getattr(attendance.user.profile, 'department', 'Unknown') if hasattr(attendance.user, 'profile') else 'Unknown',
                attendance.status,
                attendance.clock_in_time.strftime('%H:%M:%S') if attendance.clock_in_time else '',
                attendance.clock_out_time.strftime('%H:%M:%S') if attendance.clock_out_time else '',
                str(attendance.total_hours) if attendance.total_hours else '',
                str(attendance.overtime_hours) if attendance.overtime_hours else '',
                attendance.late_minutes,
                attendance.regularization_status
            ])

        return response

    except Exception as e:
        logger.error(f"CSV export error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def export_pdf(request):
    """Export attendance data to PDF"""
    try:
        if not has_export_permission(request.user):
            return JsonResponse({'error': 'Permission denied'}, status=403)

        return JsonResponse({
            'status': 'info',
            'message': 'PDF export feature will be implemented soon. Please use Excel or CSV export for now.'
        })

    except Exception as e:
        logger.error(f"PDF export error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@csrf_exempt
def regularization_request(request):
    """API endpoint to submit regularization request"""
    try:
        if request.method != 'POST':
            return JsonResponse({'error': 'Only POST method allowed'}, status=405)

        data = json.loads(request.body)
        attendance_id = data.get('attendance_id')
        requested_status = data.get('requested_status')
        reason = data.get('reason')

        if not all([attendance_id, requested_status, reason]):
            return JsonResponse({
                'status': 'error',
                'message': 'Missing required fields: attendance_id, requested_status, reason'
            }, status=400)

        # Get attendance record
        attendance = get_object_or_404(Attendance, id=attendance_id, user=request.user)

        # Update regularization fields
        attendance.regularization_requested = True
        attendance.regularization_status = 'Pending'
        attendance.regularization_reason = reason
        attendance.requested_status = requested_status
        attendance.regularization_requested_at = timezone.now()
        attendance.save()

        # Send notification to HR
        try:
            notification_service = AttendanceNotificationService()
            notification_service.notify_regularization_request(attendance, request.user)
        except Exception as e:
            logger.warning(f"Failed to send regularization notification: {e}")

        return JsonResponse({
            'status': 'success',
            'message': 'Regularization request submitted successfully',
            'data': {
                'attendance_id': attendance.id,
                'status': 'Pending',
                'submitted_at': attendance.regularization_requested_at.isoformat()
            }
        })

    except Exception as e:
        logger.error(f"Regularization request error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def regularization_status(request, attendance_id):
    """API endpoint to get regularization status"""
    try:
        attendance = get_object_or_404(Attendance, id=attendance_id)

        # Check permissions
        user_role = get_user_role(request.user)
        if user_role == 'Employee' and attendance.user != request.user:
            return JsonResponse({'error': 'Permission denied'}, status=403)

        return JsonResponse({
            'status': 'success',
            'data': {
                'attendance_id': attendance.id,
                'regularization_requested': attendance.regularization_requested,
                'regularization_status': attendance.regularization_status,
                'regularization_reason': attendance.regularization_reason,
                'requested_status': attendance.requested_status,
                'regularization_requested_at': attendance.regularization_requested_at.isoformat() if attendance.regularization_requested_at else None,
                'regularization_processed_at': attendance.regularization_processed_at.isoformat() if attendance.regularization_processed_at else None,
                'regularization_processed_by': attendance.regularization_processed_by.username if attendance.regularization_processed_by else None
            }
        })

    except Exception as e:
        logger.error(f"Regularization status error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@role_required(['HR', 'Admin'])
@csrf_exempt
def approve_regularization(request):
    """API endpoint to approve regularization"""
    try:
        if request.method != 'POST':
            return JsonResponse({'error': 'Only POST method allowed'}, status=405)

        data = json.loads(request.body)
        attendance_id = data.get('attendance_id')
        comments = data.get('comments', '')

        attendance = get_object_or_404(Attendance, id=attendance_id)

        # Update attendance record
        attendance.status = attendance.requested_status
        attendance.regularization_status = 'Approved'
        attendance.regularization_comments = comments
        attendance.regularization_processed_by = request.user
        attendance.regularization_processed_at = timezone.now()
        attendance.save()

        # Send notification
        try:
            notification_service = AttendanceNotificationService()
            notification_service.notify_regularization_status(attendance, 'Approved')
        except Exception as e:
            logger.warning(f"Failed to send approval notification: {e}")

        return JsonResponse({
            'status': 'success',
            'message': 'Regularization approved successfully',
            'data': {
                'attendance_id': attendance.id,
                'new_status': attendance.status,
                'processed_by': request.user.username,
                'processed_at': attendance.regularization_processed_at.isoformat()
            }
        })

    except Exception as e:
        logger.error(f"Approve regularization error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@role_required(['HR', 'Admin'])
@csrf_exempt
def reject_regularization(request):
    """API endpoint to reject regularization"""
    try:
        if request.method != 'POST':
            return JsonResponse({'error': 'Only POST method allowed'}, status=405)

        data = json.loads(request.body)
        attendance_id = data.get('attendance_id')
        comments = data.get('comments', '')

        attendance = get_object_or_404(Attendance, id=attendance_id)

        # Update regularization status
        attendance.regularization_status = 'Rejected'
        attendance.regularization_comments = comments
        attendance.regularization_processed_by = request.user
        attendance.regularization_processed_at = timezone.now()
        attendance.save()

        # Send notification
        try:
            notification_service = AttendanceNotificationService()
            notification_service.notify_regularization_status(attendance, 'Rejected')
        except Exception as e:
            logger.warning(f"Failed to send rejection notification: {e}")

        return JsonResponse({
            'status': 'success',
            'message': 'Regularization rejected',
            'data': {
                'attendance_id': attendance.id,
                'status': 'Rejected',
                'processed_by': request.user.username,
                'processed_at': attendance.regularization_processed_at.isoformat()
            }
        })

    except Exception as e:
        logger.error(f"Reject regularization error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def monthly_analytics(request):
    """API endpoint for monthly analytics"""
    try:
        month = int(request.GET.get('month', timezone.now().month))
        year = int(request.GET.get('year', timezone.now().year))

        start_date = date(year, month, 1)
        end_date = date(year, month, calendar.monthrange(year, month)[1])

        # Base queryset
        queryset = Attendance.objects.filter(date__range=[start_date, end_date])

        # Apply role-based filtering
        api = RoleBasedAttendanceAPI()
        queryset = api.get_user_accessible_data(request.user, queryset)

        # Calculate analytics
        total_working_days = queryset.exclude(status__in=['Holiday', 'Weekend']).values('date').distinct().count()
        total_records = queryset.count()
        present_days = queryset.filter(status__icontains='Present').count()
        absent_days = queryset.filter(status='Absent').count()
        leave_days = queryset.filter(status='On Leave').count()

        # Weekly breakdown
        weekly_data = []
        current_date = start_date
        week_number = 1

        while current_date <= end_date:
            week_end = min(current_date + timedelta(days=6), end_date)
            week_queryset = queryset.filter(date__range=[current_date, week_end])

            weekly_data.append({
                'week': week_number,
                'start_date': current_date.strftime('%Y-%m-%d'),
                'end_date': week_end.strftime('%Y-%m-%d'),
                'present': week_queryset.filter(status__icontains='Present').count(),
                'absent': week_queryset.filter(status='Absent').count(),
                'leave': week_queryset.filter(status='On Leave').count()
            })

            current_date = week_end + timedelta(days=1)
            week_number += 1

        return JsonResponse({
            'status': 'success',
            'data': {
                'month': month,
                'year': year,
                'summary': {
                    'total_working_days': total_working_days,
                    'total_records': total_records,
                    'present_days': present_days,
                    'absent_days': absent_days,
                    'leave_days': leave_days,
                    'attendance_rate': round((present_days / total_records * 100), 2) if total_records > 0 else 0
                },
                'weekly_breakdown': weekly_data
            }
        })

    except Exception as e:
        logger.error(f"Monthly analytics error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def weekly_analytics(request):
    """API endpoint for weekly analytics"""
    try:
        today = timezone.now().astimezone(IST).date()

        # Get week start (Monday)
        days_since_monday = today.weekday()
        week_start = today - timedelta(days=days_since_monday)
        week_end = week_start + timedelta(days=6)

        # Override with custom dates if provided
        start_date = request.GET.get('start_date')
        if start_date:
            week_start = datetime.strptime(start_date, '%Y-%m-%d').date()
            week_end = week_start + timedelta(days=6)

        # Base queryset
        queryset = Attendance.objects.filter(date__range=[week_start, week_end])

        # Apply role-based filtering
        api = RoleBasedAttendanceAPI()
        queryset = api.get_user_accessible_data(request.user, queryset)

        # Daily breakdown
        daily_data = []
        for i in range(7):
            day_date = week_start + timedelta(days=i)
            day_queryset = queryset.filter(date=day_date)

            daily_data.append({
                'date': day_date.strftime('%Y-%m-%d'),
                'day': day_date.strftime('%A'),
                'present': day_queryset.filter(status__icontains='Present').count(),
                'absent': day_queryset.filter(status='Absent').count(),
                'late': day_queryset.filter(status='Present & Late').count(),
                'leave': day_queryset.filter(status='On Leave').count()
            })

        return JsonResponse({
            'status': 'success',
            'data': {
                'week_start': week_start.strftime('%Y-%m-%d'),
                'week_end': week_end.strftime('%Y-%m-%d'),
                'daily_breakdown': daily_data
            }
        })

    except Exception as e:
        logger.error(f"Weekly analytics error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def yearly_analytics(request):
    """API endpoint for yearly analytics"""
    try:
        year = int(request.GET.get('year', timezone.now().year))

        start_date = date(year, 1, 1)
        end_date = date(year, 12, 31)

        # Base queryset
        queryset = Attendance.objects.filter(date__range=[start_date, end_date])

        # Apply role-based filtering
        api = RoleBasedAttendanceAPI()
        queryset = api.get_user_accessible_data(request.user, queryset)

        # Monthly breakdown
        monthly_data = []
        for month in range(1, 13):
            month_start = date(year, month, 1)
            month_end = date(year, month, calendar.monthrange(year, month)[1])
            month_queryset = queryset.filter(date__range=[month_start, month_end])

            monthly_data.append({
                'month': month,
                'month_name': calendar.month_name[month],
                'present': month_queryset.filter(status__icontains='Present').count(),
                'absent': month_queryset.filter(status='Absent').count(),
                'leave': month_queryset.filter(status='On Leave').count(),
                'total': month_queryset.count()
            })

        # Overall yearly stats
        total_records = queryset.count()
        present_count = queryset.filter(status__icontains='Present').count()
        absent_count = queryset.filter(status='Absent').count()
        leave_count = queryset.filter(status='On Leave').count()

        return JsonResponse({
            'status': 'success',
            'data': {
                'year': year,
                'summary': {
                    'total_records': total_records,
                    'present_count': present_count,
                    'absent_count': absent_count,
                    'leave_count': leave_count,
                    'attendance_rate': round((present_count / total_records * 100), 2) if total_records > 0 else 0
                },
                'monthly_breakdown': monthly_data
            }
        })

    except Exception as e:
        logger.error(f"Yearly analytics error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def live_attendance_count(request):
    """API endpoint for live attendance count"""
    try:
        today = timezone.now().astimezone(IST).date()
        user_role = get_user_role(request.user)

        # Base queryset for today
        queryset = Attendance.objects.filter(date=today)

        # Apply role-based filtering
        api = RoleBasedAttendanceAPI()
        queryset = api.get_user_accessible_data(request.user, queryset)

        counts = {
            'total_employees': queryset.values('user').distinct().count(),
            'present': queryset.filter(status__icontains='Present').count(),
            'absent': queryset.filter(status='Absent').count(),
            'late': queryset.filter(status='Present & Late').count(),
            'on_leave': queryset.filter(status='On Leave').count(),
            'yet_to_clock_in': queryset.filter(status='Yet to Clock In').count(),
            'last_updated': timezone.now().isoformat()
        }

        return JsonResponse({
            'status': 'success',
            'data': counts
        })

    except Exception as e:
        logger.error(f"Live attendance count error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def live_current_status(request):
    """API endpoint for user's current status"""
    try:
        today = timezone.now().astimezone(IST).date()

        # Get user's today attendance
        attendance = Attendance.objects.filter(
            user=request.user,
            date=today
        ).first()

        if attendance:
            data = {
                'user': request.user.username,
                'date': today.strftime('%Y-%m-%d'),
                'status': attendance.status,
                'clock_in_time': attendance.clock_in_time.strftime('%H:%M:%S') if attendance.clock_in_time else None,
                'clock_out_time': attendance.clock_out_time.strftime('%H:%M:%S') if attendance.clock_out_time else None,
                'total_hours': str(attendance.total_hours) if attendance.total_hours else None,
                'late_minutes': attendance.late_minutes,
                'last_updated': timezone.now().isoformat()
            }
        else:
            data = {
                'user': request.user.username,
                'date': today.strftime('%Y-%m-%d'),
                'status': 'No Record',
                'clock_in_time': None,
                'clock_out_time': None,
                'total_hours': None,
                'late_minutes': 0,
                'last_updated': timezone.now().isoformat()
            }

        return JsonResponse({
            'status': 'success',
            'data': data
        })

    except Exception as e:
        logger.error(f"Live current status error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


# Utility endpoints (migrated from existing views.py)
@login_required
def get_attendance_data(request):
    """API endpoint to get attendance data"""
    try:
        user_id = request.GET.get('user_id')
        date_str = request.GET.get('date')

        if not user_id or not date_str:
            return JsonResponse({'error': 'Missing user_id or date parameter'}, status=400)

        target_date = datetime.strptime(date_str, '%Y-%m-%d').date()

        # Check permissions - users can only see their own data unless they're HR/Admin
        user_role = get_user_role(request.user)
        if user_role == 'Employee' and str(request.user.id) != user_id:
            return JsonResponse({'error': 'Permission denied'}, status=403)

        target_user = get_object_or_404(User, id=user_id)
        attendance = Attendance.objects.filter(
            user=target_user,
            date=target_date
        ).first()

        if attendance:
            data = {
                'id': attendance.id,
                'user_id': attendance.user.id,
                'username': attendance.user.username,
                'date': attendance.date.strftime('%Y-%m-%d'),
                'status': attendance.status,
                'clock_in_time': attendance.clock_in_time.strftime('%H:%M:%S') if attendance.clock_in_time else None,
                'clock_out_time': attendance.clock_out_time.strftime('%H:%M:%S') if attendance.clock_out_time else None,
                'total_hours': str(attendance.total_hours) if attendance.total_hours else None,
                'overtime_hours': str(attendance.overtime_hours) if attendance.overtime_hours else None,
                'late_minutes': attendance.late_minutes,
                'regularization_requested': attendance.regularization_requested,
                'regularization_status': attendance.regularization_status
            }
        else:
            data = {
                'user_id': int(user_id),
                'username': target_user.username,
                'date': target_date.strftime('%Y-%m-%d'),
                'status': 'No Record',
                'message': 'No attendance record found for this date'
            }

        return JsonResponse({
            'status': 'success',
            'data': data
        })

    except Exception as e:
        logger.error(f"Get attendance data error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def get_monthly_attendance_data(request):
    """API endpoint to get monthly attendance data"""
    try:
        user_id = request.GET.get('user_id')
        month = int(request.GET.get('month', timezone.now().month))
        year = int(request.GET.get('year', timezone.now().year))

        # Check permissions
        user_role = get_user_role(request.user)
        if user_role == 'Employee' and (not user_id or str(request.user.id) != user_id):
            user_id = request.user.id
        elif user_id:
            user_id = int(user_id)
        else:
            user_id = request.user.id

        target_user = get_object_or_404(User, id=user_id)

        # Get monthly date range
        start_date = date(year, month, 1)
        end_date = date(year, month, calendar.monthrange(year, month)[1])

        # Get attendance records
        queryset = Attendance.objects.filter(
            user=target_user,
            date__range=[start_date, end_date]
        ).order_by('date')

        # Prepare data
        attendance_data = []
        for attendance in queryset:
            attendance_data.append({
                'id': attendance.id,
                'date': attendance.date.strftime('%Y-%m-%d'),
                'day': attendance.date.strftime('%A'),
                'status': attendance.status,
                'clock_in': attendance.clock_in_time.strftime('%H:%M') if attendance.clock_in_time else None,
                'clock_out': attendance.clock_out_time.strftime('%H:%M') if attendance.clock_out_time else None,
                'total_hours': str(attendance.total_hours) if attendance.total_hours else None,
                'late_minutes': attendance.late_minutes,
                'regularization_requested': attendance.regularization_requested
            })

        # Calculate summary
        total_records = len(attendance_data)
        present_count = len([a for a in attendance_data if 'Present' in a['status']])
        absent_count = len([a for a in attendance_data if a['status'] == 'Absent'])
        late_count = len([a for a in attendance_data if a['status'] == 'Present & Late'])

        return JsonResponse({
            'status': 'success',
            'data': {
                'user_id': user_id,
                'username': target_user.username,
                'month': month,
                'year': year,
                'attendance_records': attendance_data,
                'summary': {
                    'total_records': total_records,
                    'present_count': present_count,
                    'absent_count': absent_count,
                    'late_count': late_count,
                    'attendance_rate': round((present_count / total_records * 100), 2) if total_records > 0 else 0
                }
            }
        })

    except Exception as e:
        logger.error(f"Get monthly attendance data error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@role_required(['HR', 'Admin'])
def run_auto_marking(request):
    """API endpoint to run auto-marking process"""
    try:
        target_date = request.GET.get('date')
        if target_date:
            target_date = datetime.strptime(target_date, '%Y-%m-%d').date()
        else:
            target_date = timezone.now().astimezone(IST).date()

        # Run auto-marking service
        try:
            auto_marking_service = AttendanceAutoMarkingService()
            result = auto_marking_service.run_daily_auto_marking(target_date)

            return JsonResponse({
                'status': 'success',
                'message': 'Auto-marking process completed',
                'data': {
                    'date': target_date.strftime('%Y-%m-%d'),
                    'processed': result.get('processed', 0),
                    'updated': result.get('updated', 0),
                    'errors': result.get('errors', 0)
                }
            })
        except Exception as service_error:
            logger.error(f"Auto-marking service error: {service_error}")
            return JsonResponse({
                'status': 'error',
                'message': f'Auto-marking failed: {str(service_error)}'
            }, status=500)

    except Exception as e:
        logger.error(f"Run auto marking API error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def attendance_summary_api(request):
    """API endpoint to get attendance summary data"""
    try:
        date_str = request.GET.get('date')
        if date_str:
            target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        else:
            target_date = timezone.now().astimezone(IST).date()

        # Base queryset
        queryset = Attendance.objects.filter(date=target_date)

        # Apply role-based filtering
        api = RoleBasedAttendanceAPI()
        queryset = api.get_user_accessible_data(request.user, queryset)

        # Calculate summary statistics
        total_employees = queryset.values('user').distinct().count()
        present_count = queryset.filter(status__icontains='Present').count()
        absent_count = queryset.filter(status='Absent').count()
        late_count = queryset.filter(status='Present & Late').count()
        on_leave_count = queryset.filter(status='On Leave').count()
        yet_to_clock_in = queryset.filter(status='Yet to Clock In').count()

        # Department-wise breakdown (if user has permission)
        department_breakdown = {}
        if has_view_all_permission(request.user):
            for attendance in queryset.select_related('user__profile'):
                dept = getattr(attendance.user.profile, 'department', 'Unknown') if hasattr(attendance.user, 'profile') else 'Unknown'
                if dept not in department_breakdown:
                    department_breakdown[dept] = {
                        'total': 0, 'present': 0, 'absent': 0, 'late': 0
                    }
                department_breakdown[dept]['total'] += 1
                if 'Present' in attendance.status:
                    department_breakdown[dept]['present'] += 1
                    if 'Late' in attendance.status:
                        department_breakdown[dept]['late'] += 1
                elif attendance.status == 'Absent':
                    department_breakdown[dept]['absent'] += 1

        return JsonResponse({
            'status': 'success',
            'data': {
                'date': target_date.strftime('%Y-%m-%d'),
                'summary': {
                    'total_employees': total_employees,
                    'present_count': present_count,
                    'absent_count': absent_count,
                    'late_count': late_count,
                    'on_leave_count': on_leave_count,
                    'yet_to_clock_in': yet_to_clock_in,
                    'attendance_rate': round((present_count / total_employees * 100), 2) if total_employees > 0 else 0,
                    'punctuality_rate': round(((present_count - late_count) / present_count * 100), 2) if present_count > 0 else 0
                },
                'department_breakdown': department_breakdown if has_view_all_permission(request.user) else {}
            }
        })

    except Exception as e:
        logger.error(f"Attendance summary API error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
def attendance_health_check(request):
    """API endpoint for system health check"""
    try:
        # Check database connectivity
        try:
            attendance_count = Attendance.objects.count()
            db_status = 'healthy'
        except Exception as db_error:
            attendance_count = 0
            db_status = f'error: {str(db_error)}'

        # Check today's data
        today = timezone.now().astimezone(IST).date()
        today_count = Attendance.objects.filter(date=today).count()

        # Check pending regularizations
        pending_regularizations = Attendance.objects.filter(
            regularization_requested=True,
            regularization_status='Pending'
        ).count()

        # System info
        current_time = timezone.now().astimezone(IST)

        health_data = {
            'system_status': 'healthy' if db_status == 'healthy' else 'degraded',
            'database': {
                'status': db_status,
                'total_attendance_records': attendance_count,
                'today_records': today_count
            },
            'attendance_system': {
                'pending_regularizations': pending_regularizations,
                'auto_marking_enabled': True,  # Could be from settings
                'notifications_enabled': True   # Could be from settings
            },
            'timestamp': current_time.isoformat(),
            'server_time': current_time.strftime('%Y-%m-%d %H:%M:%S %Z')
        }

        return JsonResponse({
            'status': 'success',
            'data': health_data
        })

    except Exception as e:
        logger.error(f"Health check error: {e}")
        return JsonResponse({
            'status': 'error',
            'message': str(e),
            'timestamp': timezone.now().isoformat()
        }, status=500)


@login_required
def verify_session_status(request):
    """API endpoint to verify user session status"""
    try:
        user_session = UserSession.objects.filter(user=request.user).first()

        if user_session:
            session_data = {
                'session_active': user_session.is_active,
                'last_activity': user_session.last_activity.isoformat() if user_session.last_activity else None,
                'session_start': user_session.start_time.isoformat() if user_session.start_time else None,
                'idle_time': str(user_session.idle_time) if user_session.idle_time else None,
                'status': user_session.status if hasattr(user_session, 'status') else 'Unknown'
            }
        else:
            session_data = {
                'session_active': False,
                'message': 'No active session found'
            }

        # Check today's attendance
        today = timezone.now().astimezone(IST).date()
        today_attendance = Attendance.objects.filter(
            user=request.user,
            date=today
        ).first()

        attendance_data = {
            'has_attendance_today': bool(today_attendance),
            'status': today_attendance.status if today_attendance else 'No Record',
            'clock_in_time': today_attendance.clock_in_time.strftime('%H:%M:%S') if today_attendance and today_attendance.clock_in_time else None,
            'clock_out_time': today_attendance.clock_out_time.strftime('%H:%M:%S') if today_attendance and today_attendance.clock_out_time else None
        }

        return JsonResponse({
            'status': 'success',
            'data': {
                'user': request.user.username,
                'session': session_data,
                'attendance': attendance_data,
                'timestamp': timezone.now().isoformat()
            }
        })

    except Exception as e:
        logger.error(f"Verify session status error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@csrf_exempt
def update_activity(request):
    """API endpoint to update user activity"""
    try:
        if request.method != 'POST':
            return JsonResponse({'error': 'Only POST method allowed'}, status=405)

        # Update user session - handle multiple sessions by getting the most recent active one
        try:
            user_session = UserSession.objects.filter(
                user=request.user,
                is_active=True
            ).latest('last_activity')
            created = False

        except UserSession.DoesNotExist:
            user_session = UserSession.objects.create(
                user=request.user,
                start_time=timezone.now(),
                last_activity=timezone.now(),
                is_active=True,
                session_key=request.session.session_key or ''
            )
            created = True

        if not created:
            user_session.last_activity = timezone.now()
            user_session.is_active = True
            user_session.save()

        # Update today's attendance if exists
        today = timezone.now().astimezone(IST).date()
        attendance = Attendance.objects.filter(
            user=request.user,
            date=today
        ).first()

        attendance_updated = False
        if attendance and attendance.status == 'Yet to Clock In':
            # Auto-clock in if first activity of the day
            current_time = timezone.now().astimezone(IST)
            attendance.clock_in_time = current_time
            attendance.status = 'Present'
            attendance.save()
            attendance_updated = True

        return JsonResponse({
            'status': 'success',
            'data': {
                'activity_updated': True,
                'session_active': user_session.is_active,
                'last_activity': user_session.last_activity.isoformat(),
                'attendance_updated': attendance_updated,
                'timestamp': timezone.now().isoformat()
            }
        })

    except Exception as e:
        logger.error(f"Update activity error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@csrf_exempt
def optimized_heartbeat(request):
    """
    Optimized heartbeat endpoint for session tracker
    Handles heartbeat pings from JavaScript session tracker
    """
    try:
        if request.method != 'POST':
            return JsonResponse({'error': 'Only POST method allowed'}, status=405)

        # Parse JSON body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        # Get tab_id and parent_session_id from request
        tab_id = data.get('tab_id')
        parent_session_id = data.get('parent_session_id')

        # Try to find specific session by tab_id first, then by parent_session_id
        user_session = None
        if tab_id:
            user_session = UserSession.objects.filter(
                user=request.user,
                tab_id=tab_id,
                is_active=True
            ).first()
        
        if not user_session and parent_session_id:
            user_session = UserSession.objects.filter(
                user=request.user,
                parent_session_id=parent_session_id,
                is_active=True
            ).first()
        
        # If still not found, get the most recent active session
        if not user_session:
            user_session = UserSession.objects.filter(
                user=request.user,
                is_active=True
            ).order_by('-last_activity').first()
        
        # Update or create session
        if user_session:
            user_session.last_activity = timezone.now()
            user_session.save(update_fields=['last_activity'])
            created = False
        else:
            # Create new session
            user_session = UserSession.objects.create(
                user=request.user,
                session_key=request.session.session_key or '',
                tab_id=tab_id,
                parent_session_id=parent_session_id,
                is_active=True
            )
            created = True

        return JsonResponse({
            'status': 'success',
            'session_id': str(user_session.id),
            'created': created,
            'timestamp': timezone.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Optimized heartbeat error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@csrf_exempt
def optimized_batch_activity(request):
    """
    Optimized batch activity endpoint for session tracker
    Handles batched activity data from JavaScript
    """
    try:
        if request.method != 'POST':
            return JsonResponse({'error': 'Only POST method allowed'}, status=405)

        # Parse JSON body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        # Update session with activity data
        user_session = UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).first()

        if user_session:
            user_session.last_activity = timezone.now()
            user_session.save()

        return JsonResponse({
            'status': 'success',
            'activities_received': len(data.get('activities', [])),
            'timestamp': timezone.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Optimized batch activity error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@login_required
@csrf_exempt
def optimized_end_session(request):
    """
    Optimized end session endpoint for session tracker
    Handles session termination from JavaScript
    """
    try:
        if request.method != 'POST':
            return JsonResponse({'error': 'Only POST method allowed'}, status=405)

        # Parse JSON body
        try:
            data = json.loads(request.body)
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON'}, status=400)

        reason = data.get('reason', 'manual')

        # End all active sessions for user
        UserSession.objects.filter(
            user=request.user,
            is_active=True
        ).update(
            is_active=False,
            logout_time=timezone.now()
        )

        return JsonResponse({
            'status': 'success',
            'reason': reason,
            'timestamp': timezone.now().isoformat(),
        })

    except Exception as e:
        logger.error(f"Optimized end session error: {e}")
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)
