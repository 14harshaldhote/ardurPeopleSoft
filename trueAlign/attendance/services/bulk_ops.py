# attendance/services/bulk_ops.py
"""
Bulk Operations Service

Handles bulk attendance operations for multiple users.
"""

from datetime import date
from typing import List, Optional

from django.db import transaction

from trueAlign.models import Attendance
from . import BaseAttendanceService, ServiceResult, UserType


class AttendanceBulkOperationService(BaseAttendanceService):
    """Service for bulk attendance operations"""

    def bulk_mark_attendance(
        self, users: List[UserType], target_date: date, status: str, remarks: Optional[str] = None
    ) -> ServiceResult:
        """Bulk mark attendance for multiple users"""
        try:
            with transaction.atomic():
                updated_count = 0
                errors = []

                for user in users:
                    try:
                        attendance, created = Attendance.objects.get_or_create(
                            user=user,
                            date=target_date,
                            defaults={"status": status, "remarks": remarks},
                        )

                        if not created:
                            attendance.status = status
                            attendance.remarks = remarks
                            attendance.save()

                        updated_count += 1

                    except Exception as e:
                        errors.append(f"Error updating {user.username}: {str(e)}")

                return ServiceResult(
                    success=len(errors) == 0,
                    message=f"Bulk operation completed. Updated: {updated_count}",
                    data={"updated_count": updated_count},
                    errors=errors,
                )

        except Exception as e:
            return self._handle_exception("BULK_MARK_ATTENDANCE", e)
