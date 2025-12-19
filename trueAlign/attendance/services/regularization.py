# attendance/services/regularization.py
"""
Regularization Service

Handles attendance regularization requests, approval/rejection workflow.
"""

from datetime import date
from typing import Optional

from django.db import transaction
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings

import logging

from trueAlign.models import Attendance
from . import BaseAttendanceService, ServiceResult, User

logger = logging.getLogger("trueAlign.attendance.services")


class AttendanceRegularizationService(BaseAttendanceService):
    """Service for handling attendance regularization requests"""

    def submit_regularization_request(
        self, attendance: Attendance, requested_status: str, reason: str, requested_by: User
    ) -> ServiceResult:
        """Submit regularization request"""
        try:
            with transaction.atomic():
                attendance.regularization_status = "Pending"
                attendance.regularization_reason = reason
                attendance.regularization_requested_status = requested_status
                attendance.regularization_requested_by = requested_by
                attendance.regularization_requested_at = timezone.now()
                attendance.save()

                # Send notification to HR
                self._notify_hr_regularization_request(attendance, requested_by)

                return ServiceResult(
                    success=True,
                    message="Regularization request submitted successfully",
                    data={"attendance_id": attendance.pk},
                )

        except Exception as e:
            return self._handle_exception("SUBMIT_REGULARIZATION", e, requested_by.username)

    def process_regularization_request(
        self, attendance: Attendance, action: str, processed_by: User, remarks: Optional[str] = None
    ) -> ServiceResult:
        """Process regularization request (approve/reject)"""
        try:
            with transaction.atomic():
                if action == "approve":
                    attendance.regularization_status = "Approved"
                    if attendance.regularization_requested_status:
                        attendance.status = attendance.regularization_requested_status
                elif action == "reject":
                    attendance.regularization_status = "Rejected"

                attendance.regularization_processed_by = processed_by
                attendance.regularization_processed_at = timezone.now()
                attendance.regularization_remarks = remarks
                attendance.save()

                # Notify employee
                self._notify_employee_regularization_status(attendance, action, processed_by)

                return ServiceResult(
                    success=True,
                    message=f"Regularization request {action}d successfully",
                    data={"attendance_id": attendance.pk, "action": action},
                )

        except Exception as e:
            return self._handle_exception("PROCESS_REGULARIZATION", e, processed_by.username)

    def get_pending_regularizations(self, user: Optional[User] = None) -> ServiceResult:
        """Get pending regularization requests"""
        try:
            queryset = Attendance.objects.filter(regularization_status="Pending")

            if user and not user.groups.filter(name__in=["HR", "Admin"]).exists():
                queryset = queryset.filter(user=user)

            pending_requests = queryset.select_related(
                "user", "regularization_requested_by"
            ).order_by("-regularization_requested_at")

            data = []
            for attendance in pending_requests:
                data.append(
                    {
                        "id": attendance.pk,
                        "user": attendance.user.get_full_name(),
                        "date": attendance.date,
                        "current_status": attendance.status,
                        "requested_status": attendance.regularization_requested_status,
                        "reason": attendance.regularization_reason,
                        "requested_by": (
                            attendance.regularization_requested_by.get_full_name()
                            if attendance.regularization_requested_by
                            else ""
                        ),
                        "requested_at": attendance.regularization_requested_at,
                    }
                )

            return ServiceResult(success=True, data=data)

        except Exception as e:
            return self._handle_exception("GET_PENDING_REGULARIZATIONS", e)

    def _notify_hr_regularization_request(self, attendance: Attendance, requested_by: User):
        """Notify HR about regularization request"""
        try:
            hr_users = User.objects.filter(groups__name="HR", is_active=True)
            notification_sent = False

            for hr_user in hr_users:
                subject = f"Attendance Regularization Request - {attendance.user.get_full_name()}"
                message = f"""
                A new attendance regularization request has been submitted.

                Employee: {attendance.user.get_full_name()}
                Date: {attendance.date}
                Current Status: {attendance.status}
                Reason: {attendance.regularization_reason}
                Requested by: {requested_by.get_full_name()}
                """

                send_mail(
                    subject=subject,
                    message=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[hr_user.email],
                    fail_silently=True,
                )
                notification_sent = True

            if notification_sent:
                attendance.is_hr_notified = True
                attendance.save(update_fields=["is_hr_notified"])

        except Exception as e:
            logger.error(f"Error sending HR notification: {e}")

    def _notify_employee_regularization_status(
        self, attendance: Attendance, action: str, processed_by: User
    ):
        """Notify employee about regularization status"""
        try:
            subject = f"Attendance Regularization {action.title()} - {attendance.date}"
            message = f"""
            Your attendance regularization request has been {action}d.

            Date: {attendance.date}
            Status: {attendance.status}
            Remarks: {attendance.regularization_remarks or 'None'}
            Processed by: {processed_by.get_full_name() if processed_by else 'HR'}
            """

            send_mail(
                subject=subject,
                message=message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[attendance.user.email],
                fail_silently=True,
            )

            attendance.is_employee_notified = True
            attendance.save(update_fields=["is_employee_notified"])

        except Exception as e:
            logger.error(f"Error sending employee notification: {e}")
