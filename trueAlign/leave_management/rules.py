from .services.notification_service import create_notification
import logging

logger = logging.getLogger(__name__)

def handle_leave_requested(leave_request, actor, **kwargs):
    # Notify approver
    if leave_request.approver and leave_request.approver != actor:
        create_notification(
            recipient=leave_request.approver,
            title=f"New Leave Request: {actor.get_full_name()}",
            message=f"{actor.get_full_name()} has requested leave from {leave_request.start_date} to {leave_request.end_date}.",
            leave_request=leave_request
        )

def handle_leave_approved(leave_request, actor, **kwargs):
    # Notify employee
    if leave_request.user != actor:
        create_notification(
            recipient=leave_request.user,
            title="Leave Approved",
            message=f"Your leave request for {leave_request.start_date} to {leave_request.end_date} has been approved.",
            leave_request=leave_request
        )

def handle_leave_rejected(leave_request, actor, **kwargs):
    # Notify employee
    if leave_request.user != actor:
        reason = kwargs.get('reason', 'No reason provided')
        create_notification(
            recipient=leave_request.user,
            title="Leave Rejected",
            message=f"Your leave request has been rejected. Reason: {reason}",
            leave_request=leave_request
        )

def handle_dates_suggested(leave_request, actor, **kwargs):
    # Notify employee
    if leave_request.user != actor:
        suggested_dates = kwargs.get('suggested_dates', {})
        start = suggested_dates.get('start_date')
        end = suggested_dates.get('end_date')
        create_notification(
            recipient=leave_request.user,
            title="New Dates Suggested",
            message=f"Manager has suggested new dates: {start} to {end}. Please review.",
            leave_request=leave_request
        )

LEAVE_NOTIFICATION_RULES = {
    'leave_requested': handle_leave_requested,
    'leave_approved': handle_leave_approved,
    'leave_rejected': handle_leave_rejected,
    'dates_suggested': handle_dates_suggested,
}
