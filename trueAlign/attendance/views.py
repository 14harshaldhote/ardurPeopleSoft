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
    """Employee attendance dashboard with automatic attendance tracking"""
    try:
        # Force attendance integration and auto-marking
        _ensure_attendance_integration(request.user)

        # Run auto-marking for today to ensure attendance is current
        from .services import AttendanceAutoMarkingService

        auto_service = AttendanceAutoMarkingService()
        auto_service.run_auto_marking()

        context = _build_dashboard_context(request)

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
        # Get all sessions for this user on this date
        user_sessions = UserSession.objects.filter(
            user=attendance.user, login_time__date=attendance.date
        ).order_by("login_time")

        if user_sessions.exists():
            from .services import AttendanceAutoMarkingService

            auto_service = AttendanceAutoMarkingService()
            auto_service._update_attendance_with_sessions(
                attendance, list(user_sessions)
            )
            return True

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

        # Create calendar data
        calendar_data = {}
        for record in attendance_records:
            calendar_data[record.date.day] = {
                "status": record.status,
                "clock_in": record.clock_in_time.strftime("%H:%M")
                if record.clock_in_time
                else None,
                "clock_out": record.clock_out_time.strftime("%H:%M")
                if record.clock_out_time
                else None,
                "total_hours": float(record.total_hours or 0),
                "late_minutes": record.late_minutes or 0,
                "can_regularize": record.regularization_status
                not in ["Approved", "Rejected"],
            }

        context = {
            "year": year,
            "month": month,
            "current_date": current_date,
            "prev_year": prev_month.year,
            "prev_month": prev_month.month,
            "next_year": next_month.year,
            "next_month": next_month.month,
            "calendar_data": calendar_data,
            "today": today,
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
                    attendance = get_object_or_404(
                        Attendance, user=request.user, date=target_date
                    )

            if attendance:
                requested_status = request.POST.get("requested_status")
                reason = request.POST.get("reason")

                if requested_status and reason:
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

        context = {
            "team_members": team_members,
            "today_attendance": today_attendance,
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

        # Get overall statistics
        all_users = User.objects.filter(is_active=True)
        today_attendance = Attendance.objects.filter(date=today)

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
            .order_by("-regularization_requested_at")[:10]
        )

        # Get analytics services
        analytics_service = AttendanceAnalyticsService()

        # Get recent trends
        week_ago = today - timedelta(days=7)
        trends_result = analytics_service.get_attendance_trends(week_ago, today)

        # Get department analytics
        department_result = analytics_service.get_department_analytics(today)

        context = {
            "overview": {
                "total_employees": total_employees,
                "present_today": present_today,
                "absent_today": absent_today,
                "late_today": late_today,
                "on_leave_today": on_leave_today,
                "attendance_rate": round(
                    (present_today / total_employees * 100)
                    if total_employees > 0
                    else 0,
                    1,
                ),
                "pending_regularizations": pending_regularizations.count(),
            },
            "recent_regularizations": pending_regularizations,
            "trends_data": trends_result.data if trends_result.success else [],
            "department_data": department_result.data
            if department_result.success
            else [],
            "today": today,
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
        regularization_service = AttendanceRegularizationService()
        result = regularization_service.get_pending_regularizations()

        if result.success:
            pending_requests = result.data
        else:
            pending_requests = []
            messages.error(request, "Error loading regularization requests.")

        # Pagination
        paginator = Paginator(pending_requests, 25)
        page_number = request.GET.get("page")
        page_obj = paginator.get_page(page_number)

        context = {
            "page_obj": page_obj,
            "total_requests": len(pending_requests),
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

        # Parse dates
        if start_date_str and end_date_str:
            start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
            end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
        else:
            today = timezone.now().astimezone(IST).date()
            start_date = today - timedelta(days=30)
            end_date = today

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
                    "late_minutes": attendance.late_minutes or 0,
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
                "late_minutes": record.late_minutes or 0,
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
                    "late_minutes": attendance.late_minutes or 0,
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
                user=user, start_date__lte=target_date, end_date__gte=target_date
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
                    attendance.late_minutes = int(late_delta.total_seconds() / 60)
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
                attendance.total_hours = Decimal(str(duration.total_seconds() / 3600))

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
