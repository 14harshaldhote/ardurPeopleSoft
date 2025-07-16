"""
Support Signals Module
Signal handlers for email notifications and activity logging
"""

import logging
from django.db.models.signals import post_save, pre_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from django.utils import timezone
from django.utils.html import strip_tags
from django.urls import reverse
from trueAlign.models import (
    Support, TicketComment, TicketActivity,
    TicketAttachment, CommentAttachment
)

logger = logging.getLogger('support')


# ================================
# NOTIFICATION FUNCTIONS
# ================================

def get_notification_recipients(ticket, action_type, exclude_user=None):
    """Get list of users who should receive notifications for this ticket action"""
    recipients = set()

    # Always notify ticket creator (unless they performed the action)
    if ticket.user and ticket.user != exclude_user and ticket.user.email:
        recipients.add(ticket.user.email)

    # Notify assigned user
    if ticket.assigned_to_user and ticket.assigned_to_user != exclude_user and ticket.assigned_to_user.email:
        recipients.add(ticket.assigned_to_user.email)

    # Notify CC users
    for cc_user in ticket.cc_users.all():
        if cc_user != exclude_user and cc_user.email:
            recipients.add(cc_user.email)

    # For certain actions, notify admins and managers
    if action_type in ['CREATED', 'ESCALATED', 'SLA_BREACH']:
        admin_emails = User.objects.filter(
            is_superuser=True,
            email__isnull=False,
            is_active=True
        ).values_list('email', flat=True)
        recipients.update(admin_emails)

        # Notify HR group for HR tickets
        if ticket.assigned_group == Support.AssignedGroup.HR:
            hr_emails = User.objects.filter(
                groups__name='HR',
                email__isnull=False,
                is_active=True
            ).values_list('email', flat=True)
            recipients.update(hr_emails)

    # Remove empty emails and convert to list
    return [email for email in recipients if email and email.strip()]


def send_ticket_notification(ticket, action_type, user=None, comment=None, additional_context=None):
    """Send email notification for ticket events"""

    # Check if email notifications are enabled
    if not getattr(settings, 'SUPPORT_EMAIL_NOTIFICATIONS', True):
        return

    try:
        # Get recipients
        recipients = get_notification_recipients(ticket, action_type, exclude_user=user)

        if not recipients:
            logger.info(f"No recipients found for ticket {ticket.ticket_id} notification")
            return

        # Prepare context
        context = {
            'ticket': ticket,
            'action_type': action_type,
            'user': user,
            'comment': comment,
            'site_name': getattr(settings, 'SITE_NAME', 'Support System'),
            'site_url': getattr(settings, 'SITE_URL', 'http://localhost:8000'),
            'ticket_url': f"{getattr(settings, 'SITE_URL', 'http://localhost:8000')}/support/tickets/{ticket.pk}/",
        }

        if additional_context:
            context.update(additional_context)

        # Generate subject
        subject_templates = {
            'CREATED': f'New Support Ticket: {ticket.ticket_id}',
            'UPDATED': f'Ticket Updated: {ticket.ticket_id}',
            'ASSIGNED': f'Ticket Assigned: {ticket.ticket_id}',
            'COMMENTED': f'New Comment: {ticket.ticket_id}',
            'STATUS_CHANGED': f'Status Changed: {ticket.ticket_id}',
            'RESOLVED': f'Ticket Resolved: {ticket.ticket_id}',
            'CLOSED': f'Ticket Closed: {ticket.ticket_id}',
            'REOPENED': f'Ticket Reopened: {ticket.ticket_id}',
            'ESCALATED': f'Ticket Escalated: {ticket.ticket_id}',
            'SLA_BREACH': f'SLA BREACH: {ticket.ticket_id}',
            'DUE_SOON': f'Ticket Due Soon: {ticket.ticket_id}',
        }

        subject = subject_templates.get(action_type, f'Ticket Update: {ticket.ticket_id}')
        subject = f'[{getattr(settings, "SITE_NAME", "Support")}] {subject}'

        # Generate email content
        try:
            html_content = render_to_string('components/support/emails/ticket_notification.html', context)
            text_content = render_to_string('components/support/emails/ticket_notification.txt', context)
        except:
            # Fallback to simple text if templates don't exist
            text_content = generate_fallback_email_content(ticket, action_type, user, comment)
            html_content = text_content.replace('\n', '<br>')

        # Send email
        msg = EmailMultiAlternatives(
            subject=subject,
            body=text_content,
            from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
            to=recipients[:1],  # Primary recipient
            bcc=recipients[1:] if len(recipients) > 1 else []  # BCC others for privacy
        )
        msg.attach_alternative(html_content, "text/html")
        msg.send()

        logger.info(f"Notification sent for ticket {ticket.ticket_id} to {len(recipients)} recipients")

    except Exception as e:
        logger.error(f"Failed to send notification for ticket {ticket.ticket_id}: {str(e)}")


def generate_fallback_email_content(ticket, action_type, user, comment):
    """Generate fallback email content when templates are not available"""
    content = f"""
Ticket Update: {ticket.ticket_id}

Subject: {ticket.subject}
Status: {ticket.get_status_display()}
Priority: {ticket.get_priority_display()}
Created by: {ticket.user.get_full_name() or ticket.user.username}
Assigned to: {ticket.assigned_to_user.get_full_name() if ticket.assigned_to_user else 'Unassigned'}

Action: {action_type.replace('_', ' ').title()}
"""

    if user:
        content += f"Performed by: {user.get_full_name() or user.username}\n"

    if comment:
        content += f"\nComment:\n{comment.content}\n"

    content += f"\nView ticket: {getattr(settings, 'SITE_URL', 'http://localhost:8000')}/support/tickets/{ticket.pk}/"

    return content


# ================================
# SIGNAL HANDLERS
# ================================

@receiver(post_save, sender=Support)
def handle_ticket_created_or_updated(sender, instance, created, **kwargs):
    """Handle ticket creation and updates"""

    if created:
        # New ticket created
        logger.info(f"New ticket created: {instance.ticket_id}")

        # Create initial activity log
        TicketActivity.objects.create(
            ticket=instance,
            action=TicketActivity.Action.CREATED,
            user=getattr(instance, '_created_by', None),
            details="Ticket created"
        )

        # Send notification
        send_ticket_notification(
            ticket=instance,
            action_type='CREATED',
            user=getattr(instance, '_created_by', None)
        )

        # Check for immediate SLA concerns
        check_sla_status(instance)

    else:
        # Ticket updated
        logger.info(f"Ticket updated: {instance.ticket_id}")

        # Check if status changed
        if hasattr(instance, '_status_changed') and instance._status_changed:
            old_status, new_status = instance._status_changed

            # Log status change activity
            TicketActivity.objects.create(
                ticket=instance,
                action=TicketActivity.Action.UPDATED,
                user=getattr(instance, '_updated_by', None),
                details=f"Status changed from {old_status} to {new_status}"
            )

            # Send status change notification
            send_ticket_notification(
                ticket=instance,
                action_type='STATUS_CHANGED',
                user=getattr(instance, '_updated_by', None),
                additional_context={
                    'old_status': old_status,
                    'new_status': new_status
                }
            )

            # Special handling for resolution and closure
            if new_status == Support.Status.RESOLVED:
                send_ticket_notification(
                    ticket=instance,
                    action_type='RESOLVED',
                    user=getattr(instance, '_updated_by', None)
                )
            elif new_status == Support.Status.CLOSED:
                send_ticket_notification(
                    ticket=instance,
                    action_type='CLOSED',
                    user=getattr(instance, '_updated_by', None)
                )
            elif old_status in [Support.Status.RESOLVED, Support.Status.CLOSED] and new_status == Support.Status.OPEN:
                send_ticket_notification(
                    ticket=instance,
                    action_type='REOPENED',
                    user=getattr(instance, '_updated_by', None)
                )


@receiver(post_save, sender=TicketComment)
def handle_comment_created(sender, instance, created, **kwargs):
    """Handle new comments"""

    if created:
        logger.info(f"New comment added to ticket {instance.ticket.ticket_id}")

        # Create activity log (if not already created by the service)
        if not TicketActivity.objects.filter(
            ticket=instance.ticket,
            action=TicketActivity.Action.COMMENTED,
            user=instance.user,
            timestamp__gte=timezone.now() - timezone.timedelta(seconds=30)
        ).exists():
            TicketActivity.objects.create(
                ticket=instance.ticket,
                action=TicketActivity.Action.COMMENTED,
                user=instance.user,
                details=f"{'Internal' if instance.is_internal else 'Public'} comment added"
            )

        # Send notification (only for public comments or to users who can see internal)
        if not instance.is_internal:
            send_ticket_notification(
                ticket=instance.ticket,
                action_type='COMMENTED',
                user=instance.user,
                comment=instance
            )


@receiver(post_save, sender=TicketAttachment)
def handle_attachment_uploaded(sender, instance, created, **kwargs):
    """Handle file attachment uploads"""

    if created:
        logger.info(f"New attachment uploaded to ticket {instance.ticket.ticket_id}: {instance.original_filename}")

        # Create activity log
        TicketActivity.objects.create(
            ticket=instance.ticket,
            action=TicketActivity.Action.UPDATED,
            user=instance.uploaded_by,
            details=f"File attached: {instance.original_filename}"
        )


@receiver(post_save, sender=CommentAttachment)
def handle_comment_attachment_uploaded(sender, instance, created, **kwargs):
    """Handle comment attachment uploads"""

    if created:
        logger.info(f"New comment attachment uploaded: {instance.original_filename}")

        # Activity log is usually created by the comment creation process
        # This is just for additional logging if needed


def check_sla_status(ticket):
    """Check and handle SLA status for a ticket"""

    if not ticket.sla_target_date:
        return

    now = timezone.now()

    # Check if SLA is breached
    if now > ticket.sla_target_date and not ticket.resolved_at:
        if not ticket.sla_breach:
            ticket.sla_breach = True
            ticket.save()

            logger.warning(f"SLA breached for ticket {ticket.ticket_id}")

            # Send SLA breach notification
            send_ticket_notification(
                ticket=ticket,
                action_type='SLA_BREACH'
            )

            # Create activity log
            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.UPDATED,
                details="SLA target date exceeded"
            )

    # Check if ticket is due soon (within 2 hours)
    elif ticket.sla_target_date - now <= timezone.timedelta(hours=2) and not ticket.resolved_at:
        # Check if we haven't sent this notification recently
        recent_due_soon_activity = TicketActivity.objects.filter(
            ticket=ticket,
            details__contains="Due soon notification",
            timestamp__gte=now - timezone.timedelta(hours=1)
        ).exists()

        if not recent_due_soon_activity:
            logger.info(f"Ticket {ticket.ticket_id} is due soon")

            send_ticket_notification(
                ticket=ticket,
                action_type='DUE_SOON'
            )

            # Create activity log
            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.UPDATED,
                details="Due soon notification sent"
            )


# ================================
# PERIODIC TASK SIGNALS (for SLA monitoring)
# ================================

def monitor_sla_status():
    """
    Function to be called periodically (e.g., by Celery) to monitor SLA status
    This should be called every 15-30 minutes
    """

    open_tickets = Support.objects.filter(
        status__in=[
            Support.Status.NEW,
            Support.Status.OPEN,
            Support.Status.IN_PROGRESS,
            Support.Status.PENDING_USER,
            Support.Status.PENDING_THIRD_PARTY,
            Support.Status.ON_HOLD
        ],
        is_deleted=False,
        sla_target_date__isnull=False
    )

    for ticket in open_tickets:
        check_sla_status(ticket)

    logger.info(f"SLA monitoring completed for {open_tickets.count()} open tickets")


# ================================
# ESCALATION SIGNALS
# ================================

@receiver(post_save, sender=Support)
def handle_ticket_escalation(sender, instance, created, **kwargs):
    """Handle ticket escalation events"""

    if not created and hasattr(instance, '_escalation_level_changed'):
        old_level, new_level = instance._escalation_level_changed

        if new_level > old_level:
            logger.warning(f"Ticket {instance.ticket_id} escalated to level {new_level}")

            # Create activity log
            TicketActivity.objects.create(
                ticket=instance,
                action=TicketActivity.Action.ESCALATED,
                user=getattr(instance, '_escalated_by', None),
                details=f"Ticket escalated from level {old_level} to level {new_level}"
            )

            # Send escalation notification
            send_ticket_notification(
                ticket=instance,
                action_type='ESCALATED',
                user=getattr(instance, '_escalated_by', None),
                additional_context={
                    'old_level': old_level,
                    'new_level': new_level
                }
            )


# ================================
# ASSIGNMENT SIGNALS
# ================================

@receiver(post_save, sender=Support)
def handle_ticket_assignment(sender, instance, created, **kwargs):
    """Handle ticket assignment changes"""

    if not created and hasattr(instance, '_assignment_changed'):
        old_user, new_user, old_group, new_group = instance._assignment_changed

        details = []
        if old_user != new_user:
            old_name = old_user.get_full_name() if old_user else 'Unassigned'
            new_name = new_user.get_full_name() if new_user else 'Unassigned'
            details.append(f"Assigned user: {old_name} → {new_name}")

        if old_group != new_group:
            details.append(f"Assigned group: {old_group or 'None'} → {new_group or 'None'}")

        if details:
            logger.info(f"Assignment changed for ticket {instance.ticket_id}: {'; '.join(details)}")

            # Create activity log
            TicketActivity.objects.create(
                ticket=instance,
                action=TicketActivity.Action.ASSIGNED,
                user=getattr(instance, '_assigned_by', None),
                details='; '.join(details)
            )

            # Send assignment notification
            send_ticket_notification(
                ticket=instance,
                action_type='ASSIGNED',
                user=getattr(instance, '_assigned_by', None),
                additional_context={
                    'assignment_details': details
                }
            )


# ================================
# CLEANUP SIGNALS
# ================================

@receiver(post_delete, sender=TicketAttachment)
def handle_attachment_deleted(sender, instance, **kwargs):
    """Handle attachment deletion"""

    logger.info(f"Attachment deleted from ticket {instance.ticket.ticket_id}: {instance.original_filename}")

    # Create activity log
    TicketActivity.objects.create(
        ticket=instance.ticket,
        action=TicketActivity.Action.UPDATED,
        details=f"Attachment deleted: {instance.original_filename}"
    )


@receiver(post_delete, sender=CommentAttachment)
def handle_comment_attachment_deleted(sender, instance, **kwargs):
    """Handle comment attachment deletion"""

    logger.info(f"Comment attachment deleted: {instance.original_filename}")

    # Create activity log if ticket still exists
    if hasattr(instance, 'ticket_activity') and instance.ticket_activity.ticket:
        TicketActivity.objects.create(
            ticket=instance.ticket_activity.ticket,
            action=TicketActivity.Action.UPDATED,
            details=f"Comment attachment deleted: {instance.original_filename}"
        )


# ================================
# UTILITY FUNCTIONS
# ================================

def disable_notifications():
    """Utility function to temporarily disable notifications"""
    settings.SUPPORT_EMAIL_NOTIFICATIONS = False


def enable_notifications():
    """Utility function to re-enable notifications"""
    settings.SUPPORT_EMAIL_NOTIFICATIONS = True


def send_bulk_notification(tickets, message, subject="Bulk Notification"):
    """Send a custom notification to all users involved with multiple tickets"""

    recipients = set()

    for ticket in tickets:
        ticket_recipients = get_notification_recipients(ticket, 'BULK_NOTIFICATION')
        recipients.update(ticket_recipients)

    if recipients:
        try:
            send_mail(
                subject=f'[{getattr(settings, "SITE_NAME", "Support")}] {subject}',
                message=message,
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
                recipient_list=list(recipients),
                fail_silently=False
            )
            logger.info(f"Bulk notification sent to {len(recipients)} recipients")
        except Exception as e:
            logger.error(f"Failed to send bulk notification: {str(e)}")
