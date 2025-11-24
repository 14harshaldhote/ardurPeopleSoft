import logging
from .rules import NOTIFICATION_RULES

logger = logging.getLogger(__name__)

def dispatch_event(event_type, ticket, actor, **kwargs):
    """
    Dispatch a support event to the rule engine.
    
    Args:
        event_type (str): The type of event (e.g., 'ticket_created', 'ticket_assigned')
        ticket (Support): The ticket instance involved
        actor (User): The user who triggered the event
        **kwargs: Additional context (e.g., comment_content, old_assignee)
    """
    logger.info(f"Dispatching event: {event_type} for ticket {ticket.ticket_id} by {actor.username}")
    
    if event_type not in NOTIFICATION_RULES:
        logger.warning(f"No rules defined for event type: {event_type}")
        return

    try:
        handler = NOTIFICATION_RULES[event_type]
        handler(ticket, actor, **kwargs)
        logger.info(f"Successfully handled event: {event_type}")
    except Exception as e:
        logger.error(f"Error handling event {event_type}: {str(e)}", exc_info=True)
