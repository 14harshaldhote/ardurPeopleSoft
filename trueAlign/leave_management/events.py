from .rules import LEAVE_NOTIFICATION_RULES
import logging

logger = logging.getLogger(__name__)

# Event Types
LEAVE_REQUESTED = 'leave_requested'
LEAVE_APPROVED = 'leave_approved'
LEAVE_REJECTED = 'leave_rejected'
LEAVE_CANCELLED = 'leave_cancelled'
DATES_SUGGESTED = 'dates_suggested'

def dispatch_leave_event(event_type, leave_request, actor, **kwargs):
    """
    Dispatch a leave management event to the rule engine.
    """
    logger.info(f"Dispatching leave event: {event_type} for request {leave_request.id} by {actor.username}")
    
    if event_type not in LEAVE_NOTIFICATION_RULES:
        logger.warning(f"No rules defined for leave event type: {event_type}")
        return

    try:
        handler = LEAVE_NOTIFICATION_RULES[event_type]
        handler(leave_request, actor, **kwargs)
        logger.info(f"Successfully handled leave event: {event_type}")
    except Exception as e:
        logger.error(f"Error handling leave event {event_type}: {str(e)}", exc_info=True)
