# attendance/services/auto_marking.py
"""
Auto-Marking Service

Handles automated attendance marking based on session data and business rules.
"""

from datetime import date, timedelta
from decimal import Decimal
from typing import List, Optional
from collections import defaultdict

from django.db import transaction
from django.utils import timezone

import logging

from trueAlign.models import Attendance, UserSession
from ..config import PRESENT_STATUSES
from . import BaseAttendanceService, ServiceResult

logger = logging.getLogger("trueAlign.attendance.services")


class AttendanceAutoMarkingService(BaseAttendanceService):
    """Service for automatic attendance marking and updates"""

    def run_auto_marking(self, target_date: Optional[date] = None) -> ServiceResult:
        """Run automatic attendance marking for a specific date"""
        if not target_date:
            target_date = self.today

        try:
            self._log_operation("AUTO_MARKING_START", details=f"Date: {target_date}")

            # Main pipeline
            updated_count, processed_count, skipped_count = self._batch_process_records(target_date)

            # Process pending statuses
            pending_count = self._process_pending_statuses(target_date)

            # Update with session data
            session_update_count = self._update_with_sessions(target_date)

            # Real-time update for active sessions
            if target_date == self.today:
                self._update_real_time_attendance()

            self._log_operation(
                "AUTO_MARKING_COMPLETE",
                details=f"Updated: {updated_count}, Processed: {processed_count}, "
                f"Skipped: {skipped_count}, Pending: {pending_count}, Sessions: {session_update_count}",
            )

            return ServiceResult(
                success=True,
                message="Auto-marking completed successfully",
                data={
                    "date": str(target_date),
                    "updated": updated_count,
                    "processed": processed_count,
                    "skipped": skipped_count,
                    "pending": pending_count,
                    "sessions": session_update_count,
                },
            )

        except Exception as e:
            return self._handle_exception("AUTO_MARKING", e)

    def _batch_process_records(self, target_date: date):
        """Batch process attendance records for efficiency"""
        records = Attendance.objects.filter(date=target_date).select_related("user", "shift")

        updated_count = 0
        processed_count = 0
        skipped_count = 0

        for attendance in records:
            try:
                if (
                    hasattr(attendance, "acquire_processing_lock")
                    and attendance.acquire_processing_lock()
                ):
                    try:
                        if self._calculate_attendance_status(attendance):
                            updated_count += 1
                        processed_count += 1
                    finally:
                        attendance.release_processing_lock()
            except Exception as e:
                logger.error(f"Error processing record {attendance.id}: {e}")
                skipped_count += 1

        return updated_count, processed_count, skipped_count

    def _update_with_sessions(self, target_date: date) -> int:
        """Update attendance records with session data"""
        sessions_for_date = (
            UserSession.objects.filter(login_time__date=target_date)
            .select_related("user")
            .order_by("user_id", "login_time")
        )

        if not sessions_for_date.exists():
            return 0

        updated_count = 0
        user_sessions = defaultdict(list)

        for session in sessions_for_date:
            user_sessions[session.user.id].append(session)

        for user_id, sessions in user_sessions.items():
            try:
                attendance = Attendance.objects.get(user_id=user_id, date=target_date)
                if self._update_attendance_with_sessions(attendance, sessions):
                    updated_count += 1
            except Attendance.DoesNotExist:
                pass
            except Exception as e:
                logger.error(f"Error updating attendance for user {user_id}: {e}")

        return updated_count

    def _update_attendance_with_sessions(
        self, attendance: Attendance, sessions: List[UserSession]
    ) -> bool:
        """Update attendance record with session data"""
        if not sessions or attendance.status in ["On Leave", "Holiday", "Weekend"]:
            return False

        try:
            sessions = sorted(sessions, key=lambda s: s.login_time)
            first_session = sessions[0]

            updated = False

            # Update clock-in time
            if not attendance.clock_in_time or first_session.login_time < attendance.clock_in_time:
                attendance.clock_in_time = first_session.login_time
                attendance.first_session = first_session
                updated = True

            # Update clock-out time
            latest_logout = max((s.logout_time for s in sessions if s.logout_time), default=None)
            if latest_logout and (
                not attendance.clock_out_time or latest_logout > attendance.clock_out_time
            ):
                attendance.clock_out_time = latest_logout
                updated = True

            # Update status
            if attendance.status in ["Not Marked", "Yet to Clock In"]:
                attendance.status = "Present"
                updated = True

            if updated:
                attendance.save()
                self._invalidate_user_cache(attendance.user.pk, attendance.date)

            return updated

        except Exception as e:
            logger.error(f"Error updating attendance {attendance.id}: {e}")
            return False

    def _process_pending_statuses(self, target_date: date) -> int:
        """Process pending attendance statuses"""
        try:
            pending_records = Attendance.objects.filter(date=target_date, status="Yet to Clock In")

            processed_count = 0
            for record in pending_records:
                if self._should_mark_absent(record):
                    record.status = "Absent"
                    record.save()
                    processed_count += 1

            return processed_count
        except Exception as e:
            logger.error(f"Error processing pending statuses: {e}")
            return 0

    def _update_real_time_attendance(self):
        """Update attendance for currently active sessions"""
        try:
            active_sessions = UserSession.objects.filter(
                is_active=True, login_time__date=self.today
            ).select_related("user")

            for session in active_sessions:
                try:
                    attendance, created = Attendance.objects.get_or_create(
                        user=session.user,
                        date=self.today,
                        defaults={
                            "status": "Present",
                            "regularization_reason": "Auto-created from active session",
                        },
                    )

                    if (
                        not attendance.clock_in_time
                        or session.login_time < attendance.clock_in_time
                    ):
                        attendance.clock_in_time = session.login_time
                        attendance.status = "Present"
                        attendance.save()

                except Exception as e:
                    logger.error(f"Error updating real-time attendance: {e}")

        except Exception as e:
            logger.error(f"Error in real-time attendance update: {e}")

    def _calculate_attendance_status(self, attendance: Attendance) -> bool:
        """Calculate attendance status based on business rules"""
        try:
            if attendance.status in ["On Leave", "Holiday", "Weekend"]:
                return False

            original_status = attendance.status

            if not attendance.clock_in_time:
                attendance.status = (
                    "Absent" if self._should_mark_absent(attendance) else "Yet to Clock In"
                )
            else:
                attendance.status = self._determine_presence_status(attendance)

            if attendance.status != original_status:
                attendance.save()
                return True

            return False

        except Exception as e:
            logger.error(f"Error calculating status: {e}")
            return False

    def _should_mark_absent(self, attendance: Attendance) -> bool:
        """Determine if attendance should be marked as absent"""
        if attendance.date >= self.today:
            return False
        if attendance.status in ["On Leave", "Holiday", "Weekend"]:
            return False
        return attendance.date < self.today and not attendance.clock_in_time

    def _determine_presence_status(self, attendance: Attendance) -> str:
        """Determine presence status based on clock-in time"""
        if not attendance.clock_in_time:
            return "Absent"

        if attendance.shift:
            clock_in_time = attendance.clock_in_time.astimezone(self.ist).time()
            shift_start = attendance.shift.start_time
            grace_period = getattr(attendance.shift, "grace_period", timedelta(minutes=10))
            grace_minutes = int(grace_period.total_seconds() / 60)

            shift_start_minutes = shift_start.hour * 60 + shift_start.minute
            clock_in_minutes = clock_in_time.hour * 60 + clock_in_time.minute

            if clock_in_minutes > (shift_start_minutes + grace_minutes):
                attendance.late_minutes = clock_in_minutes - shift_start_minutes
                return "Present & Late"

        return "Present"
