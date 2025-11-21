# attendance/views.py
import logging
from datetime import datetime, date, timedelta
from decimal import Decimal
from typing import Optional, List, Dict, Any

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.core.paginator import Paginator
from django.core.cache import cache
from django.db.models import Q, Count, Avg, Sum
from django.utils import timezone
from django.views.decorators.http import require_http_methods, require_POST
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError, ObjectDoesNotExist
import json
import csv
from django.template.loader import render_to_string
import pytz

from trueAlign.models import Attendance, UserSession, Holiday, ShiftAssignment
from .services import (
    AttendanceAutoMarkingService,
    AttendanceIntegrationService,
    AttendanceRegularizationService,
    AttendanceAnalyticsService,
    AttendanceBulkOperationService,
    AttendanceReportService,
    get_attendance_services,
)
from .forms import AttendanceForm, AttendanceSearchForm
from .decorators import (
    role_required,
    hr_required,
    manager_required,
    employee_required,
    attendance_permission_required,
)
from .config import PRESENT_STATUSES, get_setting


logger = logging.getLogger(__name__)

User = get_user_model()
IST = pytz.timezone("Asia/Kolkata")


# Helper Functions
def is_hr_check(user):
    """Check if user has HR role"""
    return user.groups.filter(name__in=["HR", "Admin"]).exists() or user.is_superuser


def is_manager_check(user):
    """Check if user has manager role or higher"""
    return (
        user.groups.filter(name__in=["Manager", "HR", "Admin"]).exists()
        or user.is_superuser
    )


def is_employee_check(user):
    """Check if user is authenticated employee"""
    return user.is_authenticated


# Main Dashboard Views
@login_required
@employee_required()
def attendance_dashboard(request):
    """
    Employee attendance dashboard with OPTIMIZED loading
    
    PERFORMANCE: Removed auto-marking call (runs via cron 6x/day)
    CACHING: Dashboard data cached for 5 minutes per user
    """
    try:
        # Ensure attendance integration (lightweight)
        _ensure_attendance_integration(request.user)

        # REMOVED: auto_service.run_auto_marking()
        # Reason: Auto-marking runs every 2-3 hours via cron (Phase 1 optimization)
        # Impact: 3x faster dashboard load (300ms → 100ms)
        
        # Check cache first
        cache_key = f'dashboard_context_{request.user.id}'
        context = cache.get(cache_key)
        
        if not context:
            # Build context (only if not cached)
            context = _build_dashboard_context(request)
            # Cache for 5 minutes
            cache.set(cache_key, context, 300)
        
        return render(request, "attendance/dashboard.html", context)

    except Exception as e:
        logger.error(f"Error in attendance dashboard: {e}")
        messages.error(request, "Error loading dashboard. Please try again.")
        return render(request, "attendance/dashboard.html", {})


def _ensure_attendance_integration(user):
    """Ensure attendance is properly integrated with current session"""
    try:
        integration_service = AttendanceIntegrationService()

        # Get current active session
        current_session = UserSession.objects.filter(user=user, is_active=True).first()

        if current_session:
            integration_service.process_session_login(user, current_session)

    except Exception as e:
        logger.error(f"Error ensuring attendance integration: {e}")


def _build_dashboard_context(request):
    """Build context for dashboard"""
    today = timezone.now().astimezone(IST).date()

    attendance_today = _get_or_create_today_attendance(request.user, today)
    recent_attendance = _get_recent_attendance(request.user, today)
    monthly_stats = _calculate_monthly_stats(request.user, today)

    # Get current session info for display
    current_session = UserSession.objects.filter(
        user=request.user, is_active=True
    ).first()

    return {
        "attendance_today": attendance_today,
        "recent_attendance": recent_attendance,
        "monthly_stats": monthly_stats,
        "current_shift": _get_user_current_shift(request.user, today),
        "attendance_percentage": monthly_stats["percentage"],
        "present_days": monthly_stats["present_days"],
        "total_days": monthly_stats["total_days"],
        "pending_regularizations": _get_pending_regularizations_count(request.user),
        "current_session": current_session,
        "today": today,
        "auto_attendance_enabled": True,
    }


def _get_or_create_today_attendance(user, today):
    """Get or create today's attendance and ensure it's automatically calculated"""
    try:
        attendance_today, created = Attendance.objects.get_or_create(
            user=user,
            date=today,
            defaults={
                "status": "Not Marked",
                "regularization_reason": "Auto-created attendance record",
            },
        )

        if created:
            logger.info(
                f"Created attendance record for {user.username} on dashboard access"
            )

        # Always update from sessions to ensure current data
        _update_attendance_from_sessions(attendance_today)

        # Calculate status automatically
        _calculate_attendance_status(attendance_today)

        return attendance_today
    except Exception as e:
        logger.error(f"Error getting/creating today's attendance: {e}")
        return None


def _get_recent_attendance(user, today):
    """Get recent attendance records for user"""
    try:
        return (
            Attendance.objects.filter(user=user, date__lt=today)
            .select_related("shift")
            .order_by("-date")[:7]
        )
    except Exception as e:
        logger.error(f"Error getting recent attendance: {e}")
        return []


def _calculate_monthly_stats(user, today):
    """Calculate monthly attendance statistics"""
    try:
        start_of_month = today.replace(day=1)

        monthly_attendance = Attendance.objects.filter(
            user=user, date__range=[start_of_month, today]
        )

        total_days = monthly_attendance.count()
        present_days = monthly_attendance.filter(status__in=PRESENT_STATUSES).count()
        absent_days = monthly_attendance.filter(status="Absent").count()
        late_days = monthly_attendance.filter(status__contains="Late").count()
        leave_days = monthly_attendance.filter(status="On Leave").count()

        working_days = total_days - leave_days
        percentage = round(
            (present_days / working_days * 100) if working_days > 0 else 0, 1
        )

        return {
            "total_days": total_days,
            "present_days": present_days,
            "absent_days": absent_days,
            "late_days": late_days,
            "leave_days": leave_days,
            "working_days": working_days,
            "percentage": percentage,
        }
    except Exception as e:
        logger.error(f"Error calculating monthly stats: {e}")
        return {
            "total_days": 0,
            "present_days": 0,
            "absent_days": 0,
            "late_days": 0,
            "leave_days": 0,
            "working_days": 0,
            "percentage": 0,
        }


def _get_pending_regularizations_count(user):
    """Get count of pending regularizations for user"""
    try:
        return Attendance.objects.filter(
            user=user, regularization_status="Pending"
        ).count()
    except Exception as e:
        logger.error(f"Error getting pending regularizations count: {e}")
        return 0


def _handle_automatic_attendance_update(user, attendance_today):
    """Update attendance automatically based on current session data"""
    try:
        # Get current session data
        current_session = UserSession.objects.filter(user=user, is_active=True).first()

        if current_session:
            # Update attendance with session data
            from .services import AttendanceAutoMarkingService

            auto_service = AttendanceAutoMarkingService()
            auto_service._update_attendance_with_sessions(
                attendance_today, [current_session]
            )

            logger.info(f"Updated automatic attendance for {user.username}")

    except Exception as e:
        logger.error(f"Error updating automatic attendance: {e}")


def _update_attendance_from_sessions(attendance):
    """Update attendance record automatically from session data"""
    try:
        # 🔥 FIX: Use timezone-aware date range instead of login_time__date
        from datetime import datetime
        import pytz
        
        IST = pytz.timezone('Asia/Kolkata')
        target_date = attendance.date
        
        # Create IST date range for the target date
        start_of_day = IST.localize(datetime.combine(target_date, datetime.min.time()))
        end_of_day = IST.localize(datetime.combine(target_date, datetime.max.time()))
        
        # Get all sessions for this user on this date (timezone-aware)
        user_sessions = UserSession.objects.filter(
            user=attendance.user,
            login_time__gte=start_of_day,
            login_time__lte=end_of_day
        ).order_by("login_time")

        if user_sessions.exists():
            from .services import AttendanceAutoMarkingService

            auto_service = AttendanceAutoMarkingService()
            auto_service._update_attendance_with_sessions(
                attendance, list(user_sessions)
            )
            logger.info(f"Updated attendance from {user_sessions.count()} sessions for {attendance.user.username}")
            return True

        logger.debug(f"No sessions found for {attendance.user.username} on {target_date}")
        return False
    except Exception as e:
        logger.error(f"Error updating attendance from sessions: {e}")
        return False


@login_required
@employee_required()
def attendance_calendar(request, year=None, month=None):
    """Display attendance calendar view"""
    try:
        today = timezone.now().astimezone(IST).date()

        if year is None:
            year = today.year
        if month is None:
            month = today.month

        # Calculate navigation dates
        current_date = date(year, month, 1)
        prev_month = current_date - timedelta(days=1)
        next_month = (current_date + timedelta(days=32)).replace(day=1)

        # Get attendance records for the month
        attendance_records = (
            Attendance.objects.filter(
                user=request.user, date__year=year, date__month=month
            )
            .select_related("shift")
            .order_by("date")
        )

        # Create calendar data - convert times to IST
        calendar_data = {}
        for record in attendance_records:
            # Convert times to IST explicitly
            clock_in_ist = record.clock_in_time.astimezone(IST) if record.clock_in_time else None
            clock_out_ist = record.clock_out_time.astimezone(IST) if record.clock_out_time else None
            
            calendar_data[record.date.day] = {
                "status": record.status,
                "clock_in": clock_in_ist.strftime("%H:%M") if clock_in_ist else None,
                "clock_out": clock_out_ist.strftime("%H:%M") if clock_out_ist else None,
                "total_hours": float(record.total_hours or 0),
                "late_minutes": max(0, record.late_minutes or 0),
                "can_regularize": record.regularization_status not in ["Approved", "Rejected"],
                "id": record.id,
            }

        # Generate calendar grid using Python's calendar module
        import calendar as cal
        month_calendar = cal.monthcalendar(year, month)
        
        calendar_weeks = []
        for week in month_calendar:
            week_data = []
            for day in week:
                if day == 0:  # Empty day (padding)
                    week_data.append({'date': None})
                else:
                    day_date = date(year, month, day)
                    is_weekend = day_date.weekday() >= 5  # Saturday=5, Sunday=6
                    
                    week_data.append({
                        'date': day_date,
                        'day': day,
                        'is_today': day_date == today,
                        'is_weekend': is_weekend,
                        'attendance': calendar_data.get(day),
                    })
            calendar_weeks.append(week_data)
        
        # Calculate monthly statistics
        present_count = sum(1 for d in calendar_data.values() if d['status'] in ['Present', 'Present & Late'])
        absent_count = sum(1 for d in calendar_data.values() if d['status'] == 'Absent')
        late_count = sum(1 for d in calendar_data.values() if 'Late' in d['status'])
        total_days = len(calendar_data)
        attendance_rate = round((present_count / total_days * 100) if total_days > 0 else 0, 1)

        context = {
            "year": year,
            "month": month,
            "current_date": current_date,
            "prev_year": prev_month.year,
            "prev_month": prev_month.month,
            "next_year": next_month.year,
            "next_month": next_month.month,
            "calendar_data": calendar_data,
            "calendar_weeks": calendar_weeks,
            "today": today,
            "weekdays": ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'],
            "monthly_stats": {
                "present_days": present_count,
                "absent_days": absent_count,
                "late_days": late_count,
                "total_days": total_days,
                "attendance_rate": attendance_rate,
            },
        }

        return render(request, "attendance/calendar.html", context)

    except Exception as e:
        logger.error(f"Error in attendance calendar: {e}")
        messages.error(request, "Error loading calendar.")
        return render(request, "attendance/calendar.html", {})


@login_required
@employee_required()
def request_regularization(request, attendance_id=None):
    """Handle attendance regularization requests"""
    try:
        attendance = None
        if attendance_id:
            attendance = get_object_or_404(
                Attendance, id=attendance_id, user=request.user
            )

        if request.method == "POST":
            if not attendance_id:
                # Get attendance from form data
                date_str = request.POST.get("date")
                if date_str:
                    target_date = datetime.strptime(date_str, "%Y-%m-%d").date()
                    try:
                        attendance = Attendance.objects.get(
                            user=request.user, date=target_date
                        )
                    except Attendance.DoesNotExist:
                        # Create attendance record if it doesn't exist
                        attendance = Attendance.objects.create(
                            user=request.user,
                            date=target_date,
                            status="Not Marked"
                        )

            if attendance:
                # Get form fields
                regularization_type = request.POST.get("regularization_type")
                reason = request.POST.get("reason")
                requested_check_in = request.POST.get("requested_check_in")
                requested_check_out = request.POST.get("requested_check_out")
                comments = request.POST.get("comments", "")
                
                # Build requested_status based on regularization_type
                requested_status = f"{regularization_type}|{requested_check_in or ''}|{requested_check_out or ''}|{comments}"

                if regularization_type and reason:
                    regularization_service = AttendanceRegularizationService()
                    result = regularization_service.submit_regularization_request(
                        attendance=attendance,
                        requested_status=requested_status,
                        reason=reason,
                        requested_by=request.user,
                    )

                    if result.success:
                        messages.success(
                            request, "Regularization request submitted successfully."
                        )
                        return redirect("attendance:calendar")
                    else:
                        messages.error(request, result.message)
                else:
                    messages.error(request, "Please fill in all required fields.")

        # Get user's attendance records that can be regularized
        regularizable_records = (
            Attendance.objects.filter(
                user=request.user, regularization_status__in=["", "Not Requested"]
            )
            .exclude(status__in=["Holiday", "Weekend"])
            .order_by("-date")[:30]
        )  # Last 30 days

        context = {
            "attendance": attendance,
            "regularizable_records": regularizable_records,
        }

        return render(request, "attendance/request_regularization.html", context)

    except Exception as e:
        logger.error(f"Error in request regularization: {e}")
        messages.error(request, "Error processing regularization request.")
        return redirect("attendance:dashboard")


@login_required
@manager_required()
def manager_attendance_overview(request):
    """Manager's team attendance overview"""
    try:
        # Get team members (this would depend on your user hierarchy model)
        team_members = User.objects.filter(
            is_active=True
            # Add your team member filtering logic here
            # e.g., profile__manager=request.user
        )

        today = timezone.now().astimezone(IST).date()

        # Get today's attendance for team
        today_attendance = (
            Attendance.objects.filter(user__in=team_members, date=today)
            .select_related("user")
            .order_by("user__first_name")
        )

        # Calculate team statistics
        total_team = team_members.count()
        present_today = today_attendance.filter(status__in=PRESENT_STATUSES).count()
        absent_today = today_attendance.filter(status="Absent").count()
        late_today = today_attendance.filter(status__contains="Late").count()
        on_leave_today = today_attendance.filter(status="On Leave").count()

        # Create a map of user_id -> attendance record for O(1) lookup
        attendance_map = {att.user_id: att for att in today_attendance}

        # Prepare team data list
        team_data = []
        for member in team_members:
            team_data.append({
                'user': member,
                'attendance': attendance_map.get(member.id)
            })

        context = {
            "team_data": team_data,
            "team_stats": {
                "total_team": total_team,
                "present_today": present_today,
                "absent_today": absent_today,
                "late_today": late_today,
                "on_leave_today": on_leave_today,
                "attendance_rate": round(
                    (present_today / total_team * 100) if total_team > 0 else 0, 1
                ),
            },
            "today": today,
        }

        return render(request, "attendance/manager_overview.html", context)

    except Exception as e:
        logger.error(f"Error in manager attendance overview: {e}")
        messages.error(request, "Error loading team overview.")
        return render(request, "attendance/manager_overview.html", {})


@login_required
@hr_required()
def hr_attendance_dashboard(request):
    """HR attendance dashboard with comprehensive analytics"""
    try:
        today = timezone.now().astimezone(IST).date()

        # Get overall statistics - only count employees (not HR/Admin who don't track attendance)
        all_users = User.objects.filter(is_active=True, groups__name='Employee')
        
        # Get or create attendance records for today using integration service
        integration_service = AttendanceIntegrationService()
        integration_service.create_daily_attendance_records(today)
        
        today_attendance = Attendance.objects.filter(date=today).select_related('user')

        # Calculate statistics
        total_employees = all_users.count()
        present_today = today_attendance.filter(status__in=PRESENT_STATUSES).count()
        absent_today = today_attendance.filter(status="Absent").count()
        late_today = today_attendance.filter(status__contains="Late").count()
        on_leave_today = today_attendance.filter(status="On Leave").count()

        # Get pending regularizations
        pending_regularizations = (
            Attendance.objects.filter(regularization_status="Pending")
            .select_related("user")
            .order_by("-last_regularization_date")[:10]
        )

        # Calculate percentages for today's stats
        present_percentage = (present_today / total_employees * 100) if total_employees > 0 else 0
        absent_percentage = (absent_today / total_employees * 100) if total_employees > 0 else 0

        # Get detailed status breakdown
        status_breakdown = {
            'present_on_time': today_attendance.filter(status='Present').exclude(status__contains='Late').count(),
            'present_late': today_attendance.filter(status='Present & Late').count(),
            'work_from_home': today_attendance.filter(status='Work From Home').count(),
            'on_leave': on_leave_today,
            'absent': absent_today,
            'not_marked': today_attendance.filter(status='Not Marked').count(),
            'half_day': today_attendance.filter(is_half_day=True).count(),
        }

        # Get weekly trends (last 7 days)
        week_ago = today - timedelta(days=7)
        weekly_data = []
        for i in range(7):
            date = today - timedelta(days=6-i)
            day_attendance = Attendance.objects.filter(date=date)
            weekly_data.append({
                'date': date.strftime('%Y-%m-%d'),
                'day': date.strftime('%a'),
                'present': day_attendance.filter(status__in=PRESENT_STATUSES).count(),
                'absent': day_attendance.filter(status='Absent').count(),
                'late': day_attendance.filter(status__contains='Late').count(),
            })
        
        # Format weekly stats for chart
        import json
        weekly_stats_json = {
            'present': json.dumps([day['present'] for day in weekly_data]),
            'absent': json.dumps([day['absent'] for day in weekly_data]),
            'late': json.dumps([day['late'] for day in weekly_data]),
            'labels': json.dumps([day['day'] for day in weekly_data]),
        }

        # Get recent activity/changes
        recent_activity = Attendance.objects.filter(
            last_modified__gte=today - timedelta(days=1)
        ).select_related('user', 'modified_by').order_by('-last_modified')[:10]

        context = {
            # Top-level stats
            "total_employees": total_employees,
            "present_today": present_today,
            "absent_today": absent_today,
            "late_today": late_today,
            "on_leave_today": on_leave_today,
            "pending_requests": pending_regularizations.count(),
            "today": today,
            
            # Detailed status breakdown
            "status_breakdown": status_breakdown,
            
            # Today's stats with percentages
            "today_stats": {
                "present": present_today,
                "absent": absent_today,
                "late": late_today,
                "on_leave": on_leave_today,
                "present_percentage": round(present_percentage, 1),
                "absent_percentage": round(absent_percentage, 1),
                "attendance_rate": round(present_percentage, 1),
            },
            
            # Weekly trends (JSON for chart)
            "weekly_stats": weekly_stats_json,
            "weekly_data": weekly_data,
            
            # Regularizations
            "recent_regularizations": pending_regularizations,
            "pending_regularizations_count": pending_regularizations.count(),
            
            # Recent activity
            "recent_activity": recent_activity,
        }

        return render(request, "attendance/hr_dashboard.html", context)

    except Exception as e:
        logger.error(f"Error in HR attendance dashboard: {e}")
        messages.error(request, "Error loading HR dashboard.")
        return render(request, "attendance/hr_dashboard.html", {})


@login_required
@hr_required()
def hr_regularization_requests(request):
    """HR view for processing regularization requests"""
    try:
        # Get all regularization requests with different statuses
        all_pending = Attendance.objects.filter(regularization_status='Pending').select_related('user')
        all_approved = Attendance.objects.filter(regularization_status='Approved').select_related('user')
        all_rejected = Attendance.objects.filter(regularization_status='Rejected').select_related('user')
        
        # Get filter from request
        filter_status = request.GET.get('status', 'all')
        
        # Filter based on status
        if filter_status == 'pending':
            filtered_requests = all_pending
        elif filter_status == 'approved':
            filtered_requests = all_approved
        elif filter_status == 'rejected':
            filtered_requests = all_rejected
        else:
            # Get all regularization requests
            filtered_requests = Attendance.objects.filter(
                regularization_status__in=['Pending', 'Approved', 'Rejected']
            ).select_related('user').order_by('-last_regularization_date')

        # Pagination
        paginator = Paginator(filtered_requests, 25)
        page_number = request.GET.get("page")
        page_obj = paginator.get_page(page_number)

        # Calculate summary statistics
        summary_stats = {
            'pending': all_pending.count(),
            'approved': all_approved.count(),
            'rejected': all_rejected.count(),
            'total': all_pending.count() + all_approved.count() + all_rejected.count(),
        }

        context = {
            "page_obj": page_obj,
            "total_requests": filtered_requests.count(),
            "summary_stats": summary_stats,
            "filter_status": filter_status,
        }

        return render(request, "attendance/hr_regularization_requests.html", context)

    except Exception as e:
        logger.error(f"Error in HR regularization requests: {e}")
        messages.error(request, "Error loading regularization requests.")
        return render(request, "attendance/hr_regularization_requests.html", {})


@login_required
@hr_required()
@require_POST
def process_regularization(request, attendance_id):
    """Process regularization request (approve/reject)"""
    try:
        attendance = get_object_or_404(Attendance, id=attendance_id)
        action = request.POST.get("action")
        remarks = request.POST.get("remarks", "")

        if action not in ["approve", "reject"]:
            messages.error(request, "Invalid action.")
            return redirect("attendance:hr_regularization_requests")

        regularization_service = AttendanceRegularizationService()
        result = regularization_service.process_regularization_request(
            attendance=attendance,
            action=action,
            processed_by=request.user,
            remarks=remarks,
        )

        if result.success:
            messages.success(request, result.message)
        else:
            messages.error(request, result.message)

        return redirect("attendance:hr_regularization_requests")

    except Exception as e:
        logger.error(f"Error processing regularization: {e}")
        messages.error(request, "Error processing regularization request.")
        return redirect("attendance:hr_regularization_requests")


@login_required
@hr_required()
def hr_add_attendance(request):
    """HR add attendance record manually"""
    try:
        if request.method == "POST":
            form = AttendanceForm(request.POST, user=request.user)
            if form.is_valid():
                attendance = form.save()
                messages.success(
                    request,
                    f"Attendance record added for {attendance.user.get_full_name()}",
                )
                return redirect("attendance:hr_dashboard")
        else:
            form = AttendanceForm(user=request.user)

        context = {
            "form": form,
        }

        return render(request, "attendance/hr_add_attendance.html", context)

    except Exception as e:
        logger.error(f"Error in HR add attendance: {e}")
        messages.error(request, "Error adding attendance record.")
        return render(
            request, "attendance/hr_add_attendance.html", {"form": AttendanceForm()}
        )


@login_required
@hr_required()
def bulk_attendance_operations(request):
    """HR bulk attendance operations"""
    try:
        if request.method == "POST":
            operation = request.POST.get("operation")
            target_date_str = request.POST.get("target_date")
            user_ids = request.POST.getlist("user_ids")

            if not all([operation, target_date_str, user_ids]):
                messages.error(request, "Please fill in all required fields.")
                return redirect("attendance:bulk_attendance_operations")

            target_date = datetime.strptime(target_date_str, "%Y-%m-%d").date()
            users = User.objects.filter(id__in=user_ids)

            bulk_service = AttendanceBulkOperationService()

            if operation == "mark_present":
                result = bulk_service.bulk_mark_attendance(
                    users=list(users),
                    target_date=target_date,
                    status="Present",
                    remarks="Bulk marked by HR",
                )
            elif operation == "mark_absent":
                result = bulk_service.bulk_mark_attendance(
                    users=list(users),
                    target_date=target_date,
                    status="Absent",
                    remarks="Bulk marked by HR",
                )
            else:
                messages.error(request, "Invalid operation.")
                return redirect("attendance:bulk_attendance_operations")

            if result.success:
                messages.success(request, result.message)
            else:
                messages.error(request, result.message)

        # Get all active users for selection
        all_users = User.objects.filter(is_active=True).order_by(
            "first_name", "last_name"
        )

        context = {
            "all_users": all_users,
        }

        return render(request, "attendance/bulk_operations.html", context)

    except Exception as e:
        logger.error(f"Error in bulk attendance operations: {e}")
        messages.error(request, "Error processing bulk operation.")
        return render(request, "attendance/bulk_operations.html", {})


@login_required
@attendance_permission_required("export")
def attendance_report(request):
    """Generate attendance reports with filtering"""
    try:
        form = AttendanceSearchForm(request.GET or None)

        # Base queryset
        queryset = Attendance.objects.all().select_related("user", "shift")

        # Apply filters
        if form.is_valid():
            if form.cleaned_data.get("user"):
                queryset = queryset.filter(user=form.cleaned_data["user"])

            if form.cleaned_data.get("department"):
                queryset = queryset.filter(
                    user__profile__department=form.cleaned_data["department"]
                )

            if form.cleaned_data.get("start_date"):
                queryset = queryset.filter(date__gte=form.cleaned_data["start_date"])

            if form.cleaned_data.get("end_date"):
                queryset = queryset.filter(date__lte=form.cleaned_data["end_date"])

            if form.cleaned_data.get("status"):
                queryset = queryset.filter(status=form.cleaned_data["status"])

        # Apply default date range if no filters
        if not any(form.cleaned_data.values()) if form.is_valid() else True:
            today = timezone.now().astimezone(IST).date()
            month_start = today.replace(day=1)
            queryset = queryset.filter(date__range=[month_start, today])

        # Pagination
        paginator = Paginator(queryset.order_by("-date"), 50)
        page_number = request.GET.get("page")
        page_obj = paginator.get_page(page_number)

        # Calculate summary
        summary_stats = {
            "total_records": queryset.count(),
            "present_count": queryset.filter(status__in=PRESENT_STATUSES).count(),
            "absent_count": queryset.filter(status="Absent").count(),
            "late_count": queryset.filter(status__contains="Late").count(),
            "leave_count": queryset.filter(status="On Leave").count(),
        }

        context = {
            "form": form,
            "page_obj": page_obj,
            "summary_stats": summary_stats,
        }

        return render(request, "attendance/report.html", context)

    except Exception as e:
        logger.error(f"Error in attendance report: {e}")
        messages.error(request, "Error generating report.")
        return render(request, "attendance/report.html", {})


@login_required
@attendance_permission_required("export")
def export_attendance_csv(request):
    """Export attendance data to CSV"""
    try:
        # Get the same queryset as the report
        form = AttendanceSearchForm(request.GET or None)
        queryset = Attendance.objects.all().select_related("user", "shift")

        if form.is_valid():
            # Apply the same filters as in attendance_report
            if form.cleaned_data.get("user"):
                queryset = queryset.filter(user=form.cleaned_data["user"])
            if form.cleaned_data.get("department"):
                queryset = queryset.filter(
                    user__profile__department=form.cleaned_data["department"]
                )
            if form.cleaned_data.get("start_date"):
                queryset = queryset.filter(date__gte=form.cleaned_data["start_date"])
            if form.cleaned_data.get("end_date"):
                queryset = queryset.filter(date__lte=form.cleaned_data["end_date"])
            if form.cleaned_data.get("status"):
                queryset = queryset.filter(status=form.cleaned_data["status"])

        # Create CSV response
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = (
            f'attachment; filename="attendance_export_{timezone.now().strftime("%Y%m%d")}.csv"'
        )

        writer = csv.writer(response)

        # Write headers
        writer.writerow(
            [
                "Employee",
                "Date",
                "Status",
                "Clock In",
                "Clock Out",
                "Total Hours",
                "Late Minutes",
                "Location",
                "Remarks",
            ]
        )

        # Write data
        for attendance in queryset.order_by("-date", "user__first_name"):
            writer.writerow(
                [
                    attendance.user.get_full_name(),
                    attendance.date.strftime("%Y-%m-%d"),
                    attendance.status,
                    attendance.clock_in_time.strftime("%H:%M")
                    if attendance.clock_in_time
                    else "",
                    attendance.clock_out_time.strftime("%H:%M")
                    if attendance.clock_out_time
                    else "",
                    float(attendance.total_hours or 0),
                    attendance.late_minutes or 0,
                    attendance.location or "",
                    attendance.remarks or "",
                ]
            )

        return response

    except Exception as e:
        logger.error(f"Error exporting CSV: {e}")
        messages.error(request, "Error exporting data.")
        return redirect("attendance:report")


@login_required
@hr_required()
def attendance_analytics(request):
    """Advanced attendance analytics page"""
    try:
        analytics_service = AttendanceAnalyticsService()
        today = timezone.now().astimezone(IST).date()

        # Get data for different time periods
        last_30_days = today - timedelta(days=30)
        trends_result = analytics_service.get_attendance_trends(last_30_days, today)
        department_result = analytics_service.get_department_analytics(today)
        late_analysis_result = analytics_service.get_late_arrival_analysis(
            last_30_days, today
        )

        context = {
            "trends_data": trends_result.data if trends_result.success else [],
            "department_data": department_result.data
            if department_result.success
            else [],
            "late_patterns": late_analysis_result.data
            if late_analysis_result.success
            else [],
            "today": today,
        }

        return render(request, "attendance/analytics.html", context)

    except Exception as e:
        logger.error(f"Error in attendance analytics: {e}")
        messages.error(request, "Error loading analytics.")
        return render(request, "attendance/analytics.html", {})


# API Endpoints
@login_required
@require_http_methods(["GET"])
def get_attendance_data(request):
    """API endpoint for attendance data"""
    try:
        user_id = request.GET.get("user_id")
        start_date_str = request.GET.get("start_date")
        end_date_str = request.GET.get("end_date")

        # Parse dates with better error handling
        try:
            if start_date_str and end_date_str:
                start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
                end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
            else:
                today = timezone.now().astimezone(IST).date()
                start_date = today - timedelta(days=30)
                end_date = today
        except ValueError as e:
            logger.error(f"Date parsing error in get_attendance_data: {e}")
            return JsonResponse({"success": False, "error": "Invalid date format. Use YYYY-MM-DD"}, status=400)

        # Build queryset
        queryset = Attendance.objects.filter(date__range=[start_date, end_date])

        if user_id:
            queryset = queryset.filter(user_id=user_id)
        elif not is_hr_check(request.user):
            # Non-HR users can only see their own data
            queryset = queryset.filter(user=request.user)

        # Prepare data
        data = []
        for attendance in queryset.select_related("user"):
            data.append(
                {
                    "id": attendance.id,
                    "user": attendance.user.get_full_name(),
                    "date": attendance.date.isoformat(),
                    "status": attendance.status,
                    "clock_in": attendance.clock_in_time.isoformat()
                    if attendance.clock_in_time
                    else None,
                    "clock_out": attendance.clock_out_time.isoformat()
                    if attendance.clock_out_time
                    else None,
                    "total_hours": float(attendance.total_hours or 0),
                    "late_minutes": max(0, attendance.late_minutes or 0),  # Ensure non-negative
                    "location": attendance.location or "",
                }
            )

        return JsonResponse({"success": True, "data": data})

    except Exception as e:
        logger.error(f"Error in get_attendance_data: {e}")
        return JsonResponse({"success": False, "error": str(e)})


@login_required
@require_http_methods(["GET"])
def get_monthly_attendance_data(request):
    """API endpoint for monthly attendance calendar data"""
    try:
        user_id = request.GET.get("user_id", request.user.id)
        year = int(request.GET.get("year", timezone.now().year))
        month = int(request.GET.get("month", timezone.now().month))

        # Check permissions
        if not is_hr_check(request.user) and int(user_id) != request.user.id:
            return JsonResponse({"error": "Permission denied"}, status=403)

        # Get attendance records for the month
        attendance_records = Attendance.objects.filter(
            user_id=user_id, date__year=year, date__month=month
        ).select_related("shift")

        # Organize data by day
        monthly_data = {}
        for record in attendance_records:
            monthly_data[record.date.day] = {
                "status": record.status,
                "clock_in": record.clock_in_time.strftime("%H:%M")
                if record.clock_in_time
                else None,
                "clock_out": record.clock_out_time.strftime("%H:%M")
                if record.clock_out_time
                else None,
                "total_hours": float(record.total_hours or 0),
                "late_minutes": max(0, record.late_minutes or 0),  # Ensure non-negative
                "can_regularize": record.regularization_status
                not in ["Approved", "Rejected"],
            }

        return JsonResponse(
            {"success": True, "data": monthly_data, "year": year, "month": month}
        )

    except Exception as e:
        logger.error(f"Error getting monthly attendance data: {e}")
        return JsonResponse({"success": False, "error": str(e)})


@login_required
@hr_required(api_response=True)
def run_auto_marking(request):
    """API endpoint to run auto attendance marking"""
    try:
        date_str = request.GET.get("date")
        if date_str:
            target_date = datetime.strptime(date_str, "%Y-%m-%d").date()
        else:
            target_date = timezone.now().astimezone(IST).date()

        auto_marking_service = AttendanceAutoMarkingService()
        result = auto_marking_service.run_auto_marking(target_date)

        return JsonResponse(result.to_dict())

    except Exception as e:
        logger.error(f"Error running auto marking: {e}")
        return JsonResponse({"success": False, "error": str(e)})


@login_required
def attendance_summary_api(request):
    """API endpoint for attendance summary data"""
    try:
        date_str = request.GET.get("date")
        target_date = (
            datetime.strptime(date_str, "%Y-%m-%d").date()
            if date_str
            else timezone.now().astimezone(IST).date()
        )

        if is_hr_check(request.user):
            # HR gets company-wide summary
            all_attendance = Attendance.objects.filter(date=target_date)
            summary = {
                "total_employees": User.objects.filter(is_active=True).count(),
                "present_count": all_attendance.filter(
                    status__in=PRESENT_STATUSES
                ).count(),
                "absent_count": all_attendance.filter(status="Absent").count(),
                "late_count": all_attendance.filter(status__contains="Late").count(),
                "on_leave_count": all_attendance.filter(status="On Leave").count(),
            }
        else:
            # Employee gets their own summary
            try:
                attendance = Attendance.objects.get(user=request.user, date=target_date)
                summary = {
                    "status": attendance.status,
                    "clock_in": attendance.clock_in_time.isoformat()
                    if attendance.clock_in_time
                    else None,
                    "clock_out": attendance.clock_out_time.isoformat()
                    if attendance.clock_out_time
                    else None,
                    "total_hours": float(attendance.total_hours or 0),
                    "late_minutes": max(0, attendance.late_minutes or 0),  # Ensure non-negative
                }
            except Attendance.DoesNotExist:
                summary = {"status": "Not Marked"}

        return JsonResponse(
            {"success": True, "data": summary, "date": target_date.isoformat()}
        )

    except Exception as e:
        logger.error(f"Error getting attendance summary: {e}")
        return JsonResponse({"success": False, "error": str(e)})


@login_required
@employee_required()
def search_attendance(request):
    """Search attendance records"""
    try:
        form = AttendanceSearchForm(request.GET or None)
        results = []

        if form.is_valid():
            queryset = Attendance.objects.select_related("user", "shift")

            # Apply filters
            if form.cleaned_data.get("user"):
                queryset = queryset.filter(user=form.cleaned_data["user"])

            if form.cleaned_data.get("start_date"):
                queryset = queryset.filter(date__gte=form.cleaned_data["start_date"])

            if form.cleaned_data.get("end_date"):
                queryset = queryset.filter(date__lte=form.cleaned_data["end_date"])

            if form.cleaned_data.get("status"):
                queryset = queryset.filter(status=form.cleaned_data["status"])

            # Apply permissions
            if not is_hr_check(request.user):
                queryset = queryset.filter(user=request.user)

            # Pagination
            paginator = Paginator(queryset.order_by("-date"), 25)
            page_number = request.GET.get("page")
            results = paginator.get_page(page_number)

        context = {
            "form": form,
            "results": results,
        }

        return render(request, "attendance/search.html", context)

    except Exception as e:
        logger.error(f"Error in search attendance: {e}")
        messages.error(request, "Error performing search.")
        return render(request, "attendance/search.html", {})


@login_required
@hr_required()
def attendance_cleanup(request):
    """Cleanup old attendance records"""
    try:
        if request.method == "POST":
            days_to_keep = int(request.POST.get("days_to_keep", 365))

            if days_to_keep < 30:
                messages.error(request, "Cannot delete records newer than 30 days.")
                return redirect("attendance:cleanup")

            cutoff_date = timezone.now().date() - timedelta(days=days_to_keep)
            deleted_count = Attendance.objects.filter(date__lt=cutoff_date).count()
            Attendance.objects.filter(date__lt=cutoff_date).delete()

            messages.success(
                request, f"Successfully cleaned up {deleted_count} old records."
            )
            return redirect("attendance:hr_dashboard")

        context = {
            "total_records": Attendance.objects.count(),
        }

        return render(request, "attendance/cleanup.html", context)

    except Exception as e:
        logger.error(f"Error in attendance cleanup: {e}")
        messages.error(request, "Error in cleanup operation.")
        return render(request, "attendance/cleanup.html", {})


@login_required
def verify_session_status(request):
    """API to verify session status and fix attendance discrepancies"""
    try:
        today = timezone.now().astimezone(IST).date()

        # Get active sessions
        active_sessions = UserSession.objects.filter(
            user=request.user, is_active=True, login_time__date=today
        )

        # Get attendance record
        try:
            attendance = Attendance.objects.get(user=request.user, date=today)
        except Attendance.DoesNotExist:
            attendance = None

        session_active = active_sessions.exists()
        should_clear_logout = False

        # Fix discrepancy if user has active session but attendance shows logout
        if session_active and attendance and attendance.clock_out_time:
            attendance.clock_out_time = None
            attendance.save()
            should_clear_logout = True
            logger.info(f"Fixed false logout for {request.user.username}")

        return JsonResponse(
            {
                "success": True,
                "session_active": session_active,
                "should_clear_logout": should_clear_logout,
                "active_sessions_count": active_sessions.count(),
            }
        )

    except Exception as e:
        logger.error(f"Error verifying session status: {e}")
        return JsonResponse({"success": False, "error": str(e)})


@login_required
@csrf_exempt
def update_activity(request):
    """API to update user activity"""
    try:
        if request.method == "POST":
            # Update active sessions with current activity
            UserSession.objects.filter(user=request.user, is_active=True).update(
                last_activity=timezone.now(), is_idle=False
            )

            return JsonResponse({"success": True})

        return JsonResponse({"success": False, "error": "Invalid method"})

    except Exception as e:
        logger.error(f"Error updating activity: {e}")
        return JsonResponse({"success": False, "error": str(e)})


# Helper Functions
def _get_user_current_shift(user, target_date):
    """Get user's current shift assignment"""
    try:
        return (
            ShiftAssignment.objects.filter(
                user=user, effective_from__lte=target_date, effective_to__gte=target_date
            )
            .select_related("shift")
            .first()
        )
    except Exception as e:
        logger.error(f"Error getting current shift for {user.username}: {e}")
        return None


def _calculate_attendance_status(attendance):
    """Calculate and update attendance status based on business rules"""
    try:
        # Skip if already processed statuses
        if attendance.status in ["On Leave", "Holiday", "Weekend"]:
            return

        # If no clock-in, mark as absent (unless it's today and still early)
        if not attendance.clock_in_time:
            today = timezone.now().astimezone(IST).date()
            if attendance.date < today:
                attendance.status = "Absent"
                attendance.save()
        else:
            # Calculate if late based on shift
            if attendance.shift and attendance.clock_in_time:
                shift_start_time = attendance.shift.start_time
                clock_in_time = attendance.clock_in_time.astimezone(IST).time()

                if clock_in_time > shift_start_time:
                    # Calculate late minutes
                    shift_start_datetime = (
                        timezone.now()
                        .replace(
                            hour=shift_start_time.hour,
                            minute=shift_start_time.minute,
                            second=0,
                            microsecond=0,
                        )
                        .astimezone(IST)
                    )

                    clock_in_datetime = attendance.clock_in_time.astimezone(IST)
                    late_delta = clock_in_datetime - shift_start_datetime
                    late_minutes_calc = int(late_delta.total_seconds() / 60)
                    
                    # Ensure late_minutes is never negative (if clocked in early)
                    attendance.late_minutes = max(0, late_minutes_calc)
                    attendance.status = "Present & Late"
                else:
                    attendance.status = "Present"
                    attendance.late_minutes = 0
            else:
                # No shift defined, just mark as present
                attendance.status = "Present"

            # Calculate total hours if both times available
            if attendance.clock_in_time and attendance.clock_out_time:
                duration = attendance.clock_out_time - attendance.clock_in_time
                total_hours = duration.total_seconds() / 3600
                
                # Cap total hours at 24.0 to prevent validation errors
                if total_hours > 24.0:
                    logger.warning(f"Total hours {total_hours} capped at 24.0 for attendance {attendance.id}")
                    total_hours = 24.0
                    
                attendance.total_hours = Decimal(str(round(total_hours, 2)))

            attendance.save()

    except Exception as e:
        logger.error(f"Error calculating attendance status: {e}")


def get_attendance_context_for_user(user):
    """Get attendance context for user - used by other views"""
    try:
        today = timezone.now().astimezone(IST).date()
        attendance_today = _get_or_create_today_attendance(user, today)
        monthly_stats = _calculate_monthly_stats(user, today)
        pending_regularizations = _get_pending_regularizations_count(user)

        return {
            "today_attendance": attendance_today,
            "monthly_stats": monthly_stats,
            "pending_regularizations": pending_regularizations,
        }
    except Exception as e:
        logger.error(f"Error getting attendance context for user {user.username}: {e}")
        return {
            "today_attendance": None,
            "monthly_stats": {
                "total_days": 0,
                "present_days": 0,
                "absent_days": 0,
                "late_days": 0,
                "leave_days": 0,
                "percentage": 0,
            },
            "pending_regularizations": 0,
        }
