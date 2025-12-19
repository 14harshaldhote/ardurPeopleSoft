# attendance/services/reports.py
"""
Reports Service

Handles attendance report generation and summaries.
"""

from datetime import date
from decimal import Decimal
from typing import List, Optional

from django.db.models import Q, Count

from trueAlign.models import Attendance
from ..config import PRESENT_STATUSES
from . import BaseAttendanceService, ServiceResult, User


class AttendanceReportService(BaseAttendanceService):
    """Service for attendance reports generation"""

    def generate_user_summary(self, user: User, start_date: date, end_date: date) -> ServiceResult:
        """Generate attendance summary for user"""
        try:
            attendance_records = Attendance.objects.filter(
                user=user, date__range=[start_date, end_date]
            ).order_by("date")

            summary = {
                "user": user.get_full_name(),
                "period": f"{start_date} to {end_date}",
                "total_days": attendance_records.count(),
                "present_days": attendance_records.filter(status__in=PRESENT_STATUSES).count(),
                "absent_days": attendance_records.filter(status="Absent").count(),
                "late_days": attendance_records.filter(status__contains="Late").count(),
                "leave_days": attendance_records.filter(status="On Leave").count(),
                "total_hours": sum([r.total_hours or Decimal("0") for r in attendance_records]),
                "records": [],
            }

            for record in attendance_records:
                summary["records"].append(
                    {
                        "date": record.date,
                        "status": record.status,
                        "clock_in": (
                            record.clock_in_time.strftime("%H:%M") if record.clock_in_time else None
                        ),
                        "clock_out": (
                            record.clock_out_time.strftime("%H:%M")
                            if record.clock_out_time
                            else None
                        ),
                        "total_hours": float(record.total_hours or 0),
                        "late_minutes": record.late_minutes or 0,
                    }
                )

            return ServiceResult(success=True, data=summary)

        except Exception as e:
            return self._handle_exception("GENERATE_USER_SUMMARY", e, user.username)

    def generate_monthly_report(
        self, year: int, month: int, users: Optional[List[User]] = None
    ) -> ServiceResult:
        """Generate monthly attendance report"""
        try:
            queryset = Attendance.objects.filter(date__year=year, date__month=month)

            if users:
                queryset = queryset.filter(user__in=users)

            report_data = {
                "period": f"{year}-{month:02d}",
                "summary": {
                    "total_records": queryset.count(),
                    "present_count": queryset.filter(status__in=PRESENT_STATUSES).count(),
                    "absent_count": queryset.filter(status="Absent").count(),
                    "late_count": queryset.filter(status__contains="Late").count(),
                    "leave_count": queryset.filter(status="On Leave").count(),
                },
                "daily_stats": [],
            }

            # Daily statistics
            daily_stats = (
                queryset.values("date")
                .annotate(
                    total=Count("id"),
                    present=Count("id", filter=Q(status__in=PRESENT_STATUSES)),
                    absent=Count("id", filter=Q(status="Absent")),
                    late=Count("id", filter=Q(status__contains="Late")),
                )
                .order_by("date")
            )

            report_data["daily_stats"] = list(daily_stats)

            return ServiceResult(success=True, data=report_data)

        except Exception as e:
            return self._handle_exception("GENERATE_MONTHLY_REPORT", e)
