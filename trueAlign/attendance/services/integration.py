# attendance/services/integration.py
"""
Integration Service

Handles integration of attendance with sessions and other systems.
"""

from datetime import date
from decimal import Decimal
from typing import Optional

from django.db import transaction
from django.utils import timezone
from django.conf import settings

from trueAlign.models import Attendance, UserSession
from . import BaseAttendanceService, ServiceResult, User, IST, logger


class AttendanceIntegrationService(BaseAttendanceService):
    """Service for integrating attendance with sessions and other systems"""

    def process_session_login(self, user: User, session: UserSession) -> ServiceResult:
        """Process session login and update attendance"""
        try:
            login_time = getattr(session, "login_time", timezone.now())
            login_date = login_time.astimezone(IST).date()

            # Get or create attendance record
            attendance, created = Attendance.objects.get_or_create(
                user=user, date=login_date, defaults=self._get_attendance_defaults(user, login_date)
            )

            # Update with session data
            if (
                not attendance.first_session
                or session.login_time < attendance.first_session.login_time
            ):
                attendance.first_session = session
                attendance.clock_in_time = session.login_time

            if not attendance.clock_in_time:
                attendance.clock_in_time = session.login_time

            # Mark as Present when user logs in
            if attendance.status in [
                "Not Marked",
                None,
                "",
                "Weekend",
                "Holiday",
                "Yet to Clock In",
            ]:
                old_status = attendance.status
                attendance.status = "Present"

                if old_status in ["Weekend", "Holiday"]:
                    attendance.is_weekend = False
                    attendance.is_holiday = False
                    logger.info(f"Marked {user.username} as PRESENT on {old_status}")
                else:
                    logger.info(f"Marked {user.username} as PRESENT on login")

            # Determine location from IP
            location = self._determine_location_from_ip(session.ip_address)
            if location and hasattr(attendance, "location"):
                attendance.location = location

            attendance.save()
            self._invalidate_user_cache(user.pk, login_date)

            return ServiceResult(
                success=True,
                message="Session login processed",
                data={"attendance_id": attendance.pk},
            )

        except Exception as e:
            return self._handle_exception("PROCESS_SESSION_LOGIN", e, user.username)

    def process_session_logout(self, user: User, session: UserSession) -> ServiceResult:
        """Process session logout and update attendance"""
        try:
            logout_time_ist = (
                session.logout_time.astimezone(self.ist) if session.logout_time else None
            )
            logout_date = logout_time_ist.date() if logout_time_ist else self.today

            try:
                attendance = Attendance.objects.get(user=user, date=logout_date)

                if logout_time_ist:
                    clock_out_ist = (
                        attendance.clock_out_time.astimezone(self.ist)
                        if attendance.clock_out_time
                        else None
                    )

                    if (
                        not attendance.last_session
                        or not clock_out_ist
                        or logout_time_ist > clock_out_ist
                    ):
                        attendance.last_session = session
                        attendance.clock_out_time = logout_time_ist
                        logger.info(f"Updated clock_out for {user.username}")

                    # Calculate total hours
                    if attendance.clock_in_time and attendance.clock_out_time:
                        clock_in_ist = attendance.clock_in_time.astimezone(self.ist)
                        time_diff = attendance.clock_out_time.astimezone(self.ist) - clock_in_ist
                        total_seconds = time_diff.total_seconds()

                        if total_seconds > 0:
                            attendance.total_hours = Decimal(str(round(total_seconds / 3600, 2)))
                            logger.info(f"Calculated total_hours: {attendance.total_hours}h")

                attendance.save()
                self._invalidate_user_cache(user.pk, logout_date)

                return ServiceResult(success=True, message="Session logout processed")

            except Attendance.DoesNotExist:
                logger.warning(f"No attendance record found for {user.username} on {logout_date}")
                return ServiceResult(success=False, message="No attendance record found")

        except Exception as e:
            return self._handle_exception("PROCESS_SESSION_LOGOUT", e, user.username)

    def _determine_location_from_ip(self, ip_address: str) -> str:
        """Determine work location from IP address"""
        try:
            office_ranges = getattr(settings, "OFFICE_IP_RANGES", ["192.168.1.0/24", "10.0.0.0/16"])

            import ipaddress

            ip = ipaddress.ip_address(ip_address)

            for ip_range in office_ranges:
                if ip in ipaddress.ip_network(ip_range):
                    return "Office"

            return "Remote"

        except Exception as e:
            logger.warning(f"Could not determine location from IP {ip_address}: {e}")
            return "Unknown"

    def create_daily_attendance_records(self, target_date: Optional[date] = None) -> ServiceResult:
        """Create daily attendance records for all active users"""
        if not target_date:
            target_date = self.today

        try:
            active_users = User.objects.filter(is_active=True)
            created_count = 0

            for user in active_users:
                try:
                    attendance, created = Attendance.objects.get_or_create(
                        user=user,
                        date=target_date,
                        defaults=self._get_attendance_defaults(user, target_date),
                    )

                    if created:
                        created_count += 1

                except Exception as e:
                    logger.error(f"Error creating attendance for {user.username}: {e}")

            self._log_operation(
                "DAILY_RECORDS_CREATED", details=f"Date: {target_date}, Created: {created_count}"
            )

            return ServiceResult(
                success=True,
                message=f"Created {created_count} daily attendance records",
                data={"created_count": created_count, "date": str(target_date)},
            )

        except Exception as e:
            return self._handle_exception("CREATE_DAILY_RECORDS", e)
