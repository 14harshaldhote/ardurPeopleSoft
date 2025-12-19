# attendance/services/analytics.py
"""
Attendance Analytics Service

Handles all analytics and statistical calculations for attendance data.
"""

from datetime import date
from typing import List
from calendar import monthrange

from django.db.models import Avg, Sum, Q, Count
from django.contrib.auth import get_user_model

from trueAlign.models import Attendance
from ..config import PRESENT_STATUSES
from . import BaseAttendanceService, ServiceResult

User = get_user_model()


class AttendanceAnalyticsService(BaseAttendanceService):
    """Service for attendance analytics and reporting"""

    def get_attendance_trends(
        self, start_date: date, end_date: date, users: List = None
    ) -> ServiceResult:
        """Get attendance trends for date range"""
        try:
            queryset = Attendance.objects.filter(date__range=[start_date, end_date])

            if users:
                queryset = queryset.filter(user__in=users)

            # Calculate trends
            trends = (
                queryset.values("date")
                .annotate(
                    total=Count("id"),
                    present=Count("id", filter=Q(status__in=PRESENT_STATUSES)),
                    absent=Count("id", filter=Q(status="Absent")),
                    late=Count("id", filter=Q(status__contains="Late")),
                )
                .order_by("date")
            )

            return ServiceResult(success=True, data=list(trends))

        except Exception as e:
            return self._handle_exception("GET_ATTENDANCE_TRENDS", e)

    def get_status_analytics(self, target_date: date = None) -> ServiceResult:
        """Get overall status-wise attendance analytics"""
        try:
            if not target_date:
                target_date = self.today

            queryset = Attendance.objects.filter(date=target_date)

            analytics = {
                "date": str(target_date),
                "total_records": queryset.count(),
                "present_on_time": queryset.filter(status="Present")
                .exclude(status__contains="Late")
                .count(),
                "present_late": queryset.filter(status="Present & Late").count(),
                "work_from_home": queryset.filter(status="Work From Home").count(),
                "on_leave": queryset.filter(status="On Leave").count(),
                "absent": queryset.filter(status="Absent").count(),
                "not_marked": queryset.filter(status="Not Marked").count(),
                "half_day": queryset.filter(is_half_day=True).count(),
            }

            return ServiceResult(success=True, data=analytics)

        except Exception as e:
            return self._handle_exception("GET_STATUS_ANALYTICS", e)

    def get_late_arrival_analysis(self, start_date: date, end_date: date) -> ServiceResult:
        """Analyze late arrival patterns"""
        try:
            late_patterns = (
                Attendance.objects.filter(
                    date__range=[start_date, end_date], status__contains="Late"
                )
                .values("user__username", "user__first_name", "user__last_name")
                .annotate(late_count=Count("id"), avg_late_minutes=Avg("late_minutes"))
                .order_by("-late_count")
            )

            return ServiceResult(success=True, data=list(late_patterns))

        except Exception as e:
            return self._handle_exception("GET_LATE_ARRIVAL_ANALYSIS", e)

    def get_department_analytics(self, target_date: date) -> ServiceResult:
        """Get department-wise attendance analytics"""
        try:
            # Get all users with their departments
            departments = {}

            users_with_dept = User.objects.filter(is_active=True).select_related("profile")

            for user in users_with_dept:
                dept_name = (
                    getattr(user.profile, "department", "Unspecified")
                    if hasattr(user, "profile")
                    else "Unspecified"
                )
                if dept_name not in departments:
                    departments[dept_name] = []
                departments[dept_name].append(user.id)

            # Get attendance stats for each department
            dept_analytics = []
            for dept_name, user_ids in departments.items():
                dept_attendance = Attendance.objects.filter(user_id__in=user_ids, date=target_date)

                total_employees = len(user_ids)
                total_records = dept_attendance.count()
                present_count = dept_attendance.filter(status__in=PRESENT_STATUSES).count()
                absent_count = dept_attendance.filter(status="Absent").count()
                late_count = dept_attendance.filter(status__contains="Late").count()

                attendance_rate = round(
                    (present_count / total_records * 100) if total_records > 0 else 0, 1
                )

                dept_analytics.append(
                    {
                        "department": dept_name,
                        "total_employees": total_employees,
                        "present": present_count,
                        "absent": absent_count,
                        "late": late_count,
                        "attendance_rate": attendance_rate,
                    }
                )

            dept_analytics.sort(key=lambda x: x["attendance_rate"], reverse=True)

            return ServiceResult(success=True, data=dept_analytics)

        except Exception as e:
            return self._handle_exception("GET_DEPARTMENT_ANALYTICS", e)

    def get_top_performers(
        self, start_date: date, end_date: date, limit: int = 10
    ) -> ServiceResult:
        """Get top performing employees by attendance"""
        try:
            performers = []
            active_users = User.objects.filter(is_active=True)

            for user in active_users:
                user_attendance = Attendance.objects.filter(
                    user=user, date__range=[start_date, end_date]
                )

                total_days = user_attendance.count()
                if total_days == 0:
                    continue

                present_days = user_attendance.filter(status__in=PRESENT_STATUSES).count()
                on_time_days = (
                    user_attendance.filter(status="Present")
                    .exclude(status__contains="Late")
                    .count()
                )

                attendance_rate = round((present_days / total_days * 100), 1)
                punctuality_rate = round((on_time_days / total_days * 100), 1)
                overall_score = round((attendance_rate * 0.6 + punctuality_rate * 0.4), 1)

                performers.append(
                    {
                        "user_id": user.id,
                        "name": user.get_full_name() or user.username,
                        "username": user.username,
                        "attendance_rate": attendance_rate,
                        "punctuality_rate": punctuality_rate,
                        "overall_score": overall_score,
                        "total_days": total_days,
                        "present_days": present_days,
                    }
                )

            performers.sort(key=lambda x: x["overall_score"], reverse=True)
            return ServiceResult(success=True, data=performers[:limit])

        except Exception as e:
            return self._handle_exception("GET_TOP_PERFORMERS", e)

    def get_attendance_concerns(
        self, start_date: date, end_date: date, limit: int = 10
    ) -> ServiceResult:
        """Get employees with attendance concerns"""
        try:
            concerns = []
            active_users = User.objects.filter(is_active=True)

            for user in active_users:
                user_attendance = Attendance.objects.filter(
                    user=user, date__range=[start_date, end_date]
                )

                total_days = user_attendance.count()
                if total_days < 5:
                    continue

                absent_days = user_attendance.filter(status="Absent").count()
                late_days = user_attendance.filter(status__contains="Late").count()

                absent_rate = round((absent_days / total_days * 100), 1)
                late_rate = round((late_days / total_days * 100), 1)

                if absent_rate > 20 or late_rate > 30:
                    concern_type = []
                    if absent_rate > 20:
                        concern_type.append(f"High Absences ({absent_rate}%)")
                    if late_rate > 30:
                        concern_type.append(f"Frequent Late ({late_rate}%)")

                    concerns.append(
                        {
                            "user_id": user.id,
                            "name": user.get_full_name() or user.username,
                            "username": user.username,
                            "absent_days": absent_days,
                            "late_days": late_days,
                            "total_days": total_days,
                            "absent_rate": absent_rate,
                            "late_rate": late_rate,
                            "concern_type": ", ".join(concern_type),
                        }
                    )

            concerns.sort(key=lambda x: x["absent_rate"] + x["late_rate"], reverse=True)
            return ServiceResult(success=True, data=concerns[:limit])

        except Exception as e:
            return self._handle_exception("GET_ATTENDANCE_CONCERNS", e)

    def get_monthly_summary(self, year: int, month: int) -> ServiceResult:
        """Get comprehensive monthly attendance summary"""
        try:
            first_day = date(year, month, 1)
            last_day = date(year, month, monthrange(year, month)[1])

            attendance_records = Attendance.objects.filter(date__range=[first_day, last_day])

            summary = {
                "year": year,
                "month": month,
                "total_records": attendance_records.count(),
                "present_count": attendance_records.filter(status__in=PRESENT_STATUSES).count(),
                "absent_count": attendance_records.filter(status="Absent").count(),
                "late_count": attendance_records.filter(status__contains="Late").count(),
                "leave_count": attendance_records.filter(status="On Leave").count(),
                "wfh_count": attendance_records.filter(status="Work From Home").count(),
                "half_day_count": attendance_records.filter(is_half_day=True).count(),
                "avg_hours": attendance_records.aggregate(Avg("total_hours"))["total_hours__avg"]
                or 0,
                "total_overtime": attendance_records.aggregate(Sum("overtime_hours"))[
                    "overtime_hours__sum"
                ]
                or 0,
            }

            if summary["total_records"] > 0:
                summary["attendance_rate"] = round(
                    (summary["present_count"] / summary["total_records"] * 100), 1
                )
                summary["late_rate"] = round(
                    (summary["late_count"] / summary["total_records"] * 100), 1
                )
            else:
                summary["attendance_rate"] = 0
                summary["late_rate"] = 0

            return ServiceResult(success=True, data=summary)

        except Exception as e:
            return self._handle_exception("GET_MONTHLY_SUMMARY", e)

    def get_key_metrics(self, start_date: date, end_date: date) -> ServiceResult:
        """Get key attendance metrics for dashboard"""
        try:
            attendance_records = Attendance.objects.filter(date__range=[start_date, end_date])

            total_records = attendance_records.count()
            present_count = attendance_records.filter(status__in=PRESENT_STATUSES).count()
            on_time_count = (
                attendance_records.filter(status="Present").exclude(status__contains="Late").count()
            )

            metrics = {
                "overall_attendance": round(
                    (present_count / total_records * 100) if total_records > 0 else 0, 1
                ),
                "on_time_arrival": round(
                    (on_time_count / total_records * 100) if total_records > 0 else 0, 1
                ),
                "average_hours": round(
                    attendance_records.aggregate(Avg("total_hours"))["total_hours__avg"] or 0, 1
                ),
                "total_overtime": round(
                    attendance_records.aggregate(Sum("overtime_hours"))["overtime_hours__sum"] or 0,
                    1,
                ),
                "total_records": total_records,
                "present_count": present_count,
                "absent_count": attendance_records.filter(status="Absent").count(),
                "late_count": attendance_records.filter(status__contains="Late").count(),
            }

            return ServiceResult(success=True, data=metrics)

        except Exception as e:
            return self._handle_exception("GET_KEY_METRICS", e)
