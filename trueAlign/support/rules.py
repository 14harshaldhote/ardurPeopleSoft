import logging
from django.contrib.auth.models import User
from trueAlign.models import Notification, Support

logger = logging.getLogger(__name__)

def create_notification(recipient, title, message, ticket, link=None):
    """Helper to create a notification record"""
    if not recipient:
        return
        
    # Don't notify the user about their own actions (optional, but usually good UX)
    # But for now, we'll keep it simple and maybe filter at the call site if needed.
    # Actually, let's filter it here: if the recipient is the one who triggered it, maybe skip?
    # The prompt says: "If agent comments -> notify ticket owner". If agent IS owner, they shouldn't get notified.
    # We will handle "don't notify actor" logic in the rules themselves.

    try:
        Notification.objects.create(
            recipient=recipient,
            title=title,
            message=message,
            module='support',
            reference_id=ticket.ticket_id,
            url=link or f"/support/ticket/{ticket.id}/"
        )
        logger.info(f"Notification created for {recipient.username}: {title}")
    except Exception as e:
        logger.error(f"Failed to create notification: {str(e)}")

# --- Recipient Helpers ---

def get_ticket_owner(ticket):
    return ticket.user

def get_assignee(ticket):
    return ticket.assigned_to_user

def get_support_leads():
    # Logic to find support leads. For now, let's assume Superusers or a specific group.
    # Or maybe just return None if not defined.
    # Prompt says: "Notify support team lead for high priority".
    # We'll try to find users in a 'Support Lead' group, or fallback to Admin.
    from django.contrib.auth.models import Group
    try:
        group = Group.objects.get(name='Support Lead')
        return group.user_set.all()
    except Group.DoesNotExist:
        return User.objects.filter(is_superuser=True)

def get_escalation_manager():
    # Similar logic for escalation manager
    from django.contrib.auth.models import Group
    try:
        group = Group.objects.get(name='Escalation Manager')
        return group.user_set.all()
    except Group.DoesNotExist:
        return User.objects.filter(is_superuser=True)

# --- Event Handlers ---

def handle_ticket_created(ticket, actor, **kwargs):
    # Notify assigned agent (if auto-assigned)
    assignee = get_assignee(ticket)
    if assignee and assignee != actor:
        create_notification(
            recipient=assignee,
            title=f"New Ticket Assigned: {ticket.ticket_id}",
            message=f"A new ticket '{ticket.subject}' has been assigned to you.",
            ticket=ticket
        )

    # Notify support leads for high priority
    if ticket.priority in [Support.Priority.HIGH, Support.Priority.CRITICAL]:
        leads = get_support_leads()
        for lead in leads:
            if lead != actor:
                create_notification(
                    recipient=lead,
                    title=f"High Priority Ticket: {ticket.ticket_id}",
                    message=f"A high priority ticket '{ticket.subject}' has been created.",
                    ticket=ticket
                )

def handle_ticket_assigned(ticket, actor, **kwargs):
    assignee = get_assignee(ticket)
    if assignee and assignee != actor:
        create_notification(
            recipient=assignee,
            title=f"Ticket Assigned: {ticket.ticket_id}",
            message=f"Ticket '{ticket.subject}' has been assigned to you.",
            ticket=ticket
        )

def handle_ticket_reassigned(ticket, actor, **kwargs):
    new_assignee = get_assignee(ticket)
    old_assignee = kwargs.get('old_assignee')

    # Notify new assignee
    if new_assignee and new_assignee != actor:
        create_notification(
            recipient=new_assignee,
            title=f"Ticket Reassigned: {ticket.ticket_id}",
            message=f"Ticket '{ticket.subject}' has been reassigned to you.",
            ticket=ticket
        )

    # Notify old assignee
    if old_assignee and old_assignee != actor and old_assignee != new_assignee:
        create_notification(
            recipient=old_assignee,
            title=f"Ticket Unassigned: {ticket.ticket_id}",
            message=f"Ticket '{ticket.subject}' has been reassigned to {new_assignee.get_full_name() if new_assignee else 'Unassigned'}.",
            ticket=ticket
        )

def handle_ticket_status_changed(ticket, actor, **kwargs):
    owner = get_ticket_owner(ticket)
    assignee = get_assignee(ticket)
    old_status = kwargs.get('old_status')
    new_status = ticket.status

    # Notify owner
    if owner != actor:
        create_notification(
            recipient=owner,
            title=f"Ticket Updated: {ticket.ticket_id}",
            message=f"Your ticket '{ticket.subject}' is now {new_status}.",
            ticket=ticket
        )

    # Notify assignee
    if assignee and assignee != actor:
        create_notification(
            recipient=assignee,
            title=f"Ticket Status Changed: {ticket.ticket_id}",
            message=f"Ticket '{ticket.subject}' status changed to {new_status}.",
            ticket=ticket
        )

def handle_ticket_escalated(ticket, actor, **kwargs):
    owner = get_ticket_owner(ticket)
    assignee = get_assignee(ticket)
    managers = get_escalation_manager()

    # Notify managers
    for manager in managers:
        if manager != actor:
            create_notification(
                recipient=manager,
                title=f"Ticket Escalated: {ticket.ticket_id}",
                message=f"Ticket '{ticket.subject}' has been escalated. Reason: {kwargs.get('reason', 'No reason provided')}",
                ticket=ticket
            )

    # Notify owner
    if owner != actor:
        create_notification(
            recipient=owner,
            title=f"Ticket Escalated: {ticket.ticket_id}",
            message=f"Your ticket '{ticket.subject}' has been escalated for further review.",
            ticket=ticket
        )
    
    # Notify assignee
    if assignee and assignee != actor:
        create_notification(
            recipient=assignee,
            title=f"Ticket Escalated: {ticket.ticket_id}",
            message=f"Ticket '{ticket.subject}' assigned to you has been escalated.",
            ticket=ticket
        )

def handle_ticket_comment_added(ticket, actor, **kwargs):
    owner = get_ticket_owner(ticket)
    assignee = get_assignee(ticket)
    is_internal = kwargs.get('is_internal', False)

    # If internal comment, only notify assignee (if not actor)
    if is_internal:
        if assignee and assignee != actor:
            create_notification(
                recipient=assignee,
                title=f"Internal Note: {ticket.ticket_id}",
                message=f"{actor.get_full_name()} added an internal note to ticket '{ticket.subject}'.",
                ticket=ticket
            )
        return

    # Public comment logic
    
    # If agent (or anyone else) comments -> notify ticket owner
    if owner != actor:
        create_notification(
            recipient=owner,
            title=f"New Comment: {ticket.ticket_id}",
            message=f"{actor.get_full_name()} commented on your ticket '{ticket.subject}'.",
            ticket=ticket
        )

    # If ticket owner comments -> notify agent
    if assignee and assignee != actor:
        create_notification(
            recipient=assignee,
            title=f"New Comment: {ticket.ticket_id}",
            message=f"{actor.get_full_name()} commented on ticket '{ticket.subject}'.",
            ticket=ticket
        )

# --- Rule Mapping ---

NOTIFICATION_RULES = {
    'ticket_created': handle_ticket_created,
    'ticket_assigned': handle_ticket_assigned,
    'ticket_reassigned': handle_ticket_reassigned,
    'ticket_status_changed': handle_ticket_status_changed,
    'ticket_escalated': handle_ticket_escalated,
    'ticket_comment_added': handle_ticket_comment_added,
}
