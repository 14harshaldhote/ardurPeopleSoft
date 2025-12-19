# attendance/services/__init__.py
"""
Attendance Services Package

Modular service layer for attendance management.
Each service handles a specific domain of attendance functionality.
"""

import logging
from datetime import date
from typing import List, Dict, Optional, Any, TYPE_CHECKING
from decimal import Decimal

from django.utils import timezone
from django.core.cache import cache
from django.contrib.auth import get_user_model
from django.db import models
from django.db.models import Q

import pytz

from trueAlign.models import Attendance, UserSession, Holiday, LeaveRequest, ShiftAssignment

User = get_user_model()
IST = pytz.timezone("Asia/Kolkata")

if TYPE_CHECKING:
    from django.contrib.auth.models import User as UserType
else:
    UserType = User

logger = logging.getLogger("trueAlign.attendance.services")


class ServiceResult:
    """Standard result class for service operations"""

    def __init__(
        self,
        success: bool = True,
        message: str = "",
        data: Any = None,
        errors: Optional[List[str]] = None,
    ):
        self.success = success
        self.message = message
        self.data = data
        self.errors = errors or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "message": self.message,
            "data": self.data,
            "errors": self.errors,
        }


class BaseAttendanceService:
    """Base service class with common functionality"""

    def __init__(self):
        self.ist = IST
        self.today = timezone.now().astimezone(self.ist).date()
        self.current_time = timezone.now().astimezone(self.ist)

    def _log_operation(
        self, operation: str, user: Optional[str] = None, details: Optional[str] = None
    ):
        """Log service operations"""
        log_msg = f"[{operation}]"
        if user:
            log_msg += f" User: {user}"
        if details:
            log_msg += f" - {details}"
        logger.info(log_msg)

    def _handle_exception(
        self, operation: str, error: Exception, user: Optional[str] = None
    ) -> ServiceResult:
        """Handle exceptions consistently"""
        error_msg = f"Error in {operation}: {str(error)}"
        if user:
            error_msg = f"Error in {operation} for {user}: {str(error)}"

        logger.error(error_msg, exc_info=True)
        return ServiceResult(success=False, message="An error occurred", errors=[error_msg])

    def _get_cache_key(self, *args) -> str:
        """Generate cache key from arguments"""
        return "_".join(str(arg) for arg in args)

    def _invalidate_user_cache(self, user_id: int, target_date: Optional[date] = None):
        """Invalidate user-specific caches"""
        if not target_date:
            target_date = self.today

        cache_keys = [
            f"attendance_today_{user_id}_{target_date}",
            f"user_attendance_{user_id}_{target_date}",
            f"user_monthly_summary_{user_id}_{target_date.year}_{target_date.month}",
        ]
        cache.delete_many(cache_keys)

    def _get_attendance_defaults(self, user: "UserType", target_date: date) -> Dict[str, Any]:
        """Get default attendance values based on business rules"""

        # Check for existing sessions first
        existing_sessions = UserSession.objects.filter(user=user, login_time__date=target_date)

        if existing_sessions.exists():
            # User has sessions, create with present status and session data
            first_session = existing_sessions.order_by("login_time").first()
            defaults: Dict[str, Any] = {
                "status": "Present",
                "clock_in_time": first_session.login_time,
                "first_session": first_session,
                "regularization_reason": "Auto-created from existing session",
            }
            logger.info(
                f"Creating attendance with session data for {user.username} on {target_date}"
            )
            return defaults

        # No sessions, continue with standard defaults
        defaults: Dict[str, Any] = {
            "status": "Not Marked",
            "regularization_reason": "Auto-created attendance record",
        }

        # Check for leave
        if self._is_user_on_leave(user, target_date):
            leave_request = (
                LeaveRequest.objects.filter(
                    user=user,
                    status="Approved",
                    start_date__lte=target_date,
                    end_date__gte=target_date,
                )
                .select_related("leave_type")
                .first()
            )

            leave_update: Dict[str, Any] = {
                "status": "On Leave",
                "leave_type": leave_request.leave_type.name if leave_request else "Leave",
                "regularization_reason": (
                    f"On {leave_request.leave_type.name} leave" if leave_request else "On Leave"
                ),
            }
            defaults.update(leave_update)
            logger.info(f"User {user.username} is on leave on {target_date}")
            return defaults

        # Check for holiday
        if self._is_holiday(target_date):
            defaults["status"] = "Holiday"
            defaults["regularization_reason"] = "Public Holiday"
            logger.info(f"Date {target_date} is a holiday")
            return defaults

        # Check for weekend using shift assignment
        shift_assignment = self._get_user_shift_assignment(user, target_date)
        if shift_assignment and self._is_weekend(target_date, shift_assignment):
            defaults["status"] = "Weekend"
            defaults["regularization_reason"] = "Weekend"
            logger.info(f"Date {target_date} is weekend for user {user.username}")

        return defaults

    def _is_user_on_leave(self, user: "UserType", target_date: date) -> bool:
        """Check if user is on approved leave"""
        return LeaveRequest.objects.filter(
            user=user, status="Approved", start_date__lte=target_date, end_date__gte=target_date
        ).exists()

    def _is_holiday(self, target_date: date) -> bool:
        """Check if date is a holiday"""
        return Holiday.objects.filter(date=target_date).exists()

    def _get_user_shift_assignment(self, user: "UserType", target_date: date):
        """Get user's shift assignment for date"""
        return (
            ShiftAssignment.objects.filter(user=user, start_date__lte=target_date)
            .filter(models.Q(end_date__isnull=True) | models.Q(end_date__gte=target_date))
            .select_related("shift")
            .first()
        )

    def _is_weekend(self, target_date: date, shift_assignment) -> bool:
        """Check if date is weekend based on shift"""
        if not shift_assignment or not shift_assignment.shift:
            # Default: Saturday and Sunday
            return target_date.weekday() in [5, 6]

        shift = shift_assignment.shift
        weekday = target_date.weekday()

        # Map weekday to shift working days
        working_days_map = {
            0: shift.is_working_monday,
            1: shift.is_working_tuesday,
            2: shift.is_working_wednesday,
            3: shift.is_working_thursday,
            4: shift.is_working_friday,
            5: shift.is_working_saturday,
            6: shift.is_working_sunday,
        }

        return not working_days_map.get(weekday, True)


# Import all service classes for easy access
from .analytics import AttendanceAnalyticsService
from .reports import AttendanceReportService
from .bulk_ops import AttendanceBulkOperationService
from .regularization import AttendanceRegularizationService
from .auto_marking import AttendanceAutoMarkingService
from .integration import AttendanceIntegrationService

__all__ = [
    "ServiceResult",
    "BaseAttendanceService",
    "AttendanceAnalyticsService",
    "AttendanceReportService",
    "AttendanceBulkOperationService",
    "AttendanceRegularizationService",
    "AttendanceAutoMarkingService",
    "AttendanceIntegrationService",
    "get_attendance_services",
]


# Utility Functions
def get_attendance_services():
    """Get all attendance services in a dictionary"""
    return {
        "auto_marking": AttendanceAutoMarkingService(),
        "integration": AttendanceIntegrationService(),
        "regularization": AttendanceRegularizationService(),
        "reports": AttendanceReportService(),
        "analytics": AttendanceAnalyticsService(),
        "bulk_operations": AttendanceBulkOperationService(),
    }
