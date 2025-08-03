"""
Notification Signals
Django signals to trigger notifications for various events
"""

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.conf import settings

# Import models from other apps
from trueAlign.models import Support, TicketComment, LeaveRequest, Attendance
from .models import Notification
from .tasks import send_notification_task, send_browser_notification_task


@receiver(post_save, sender=Support)
def support_ticket_notification(sender, instance, created, **kwargs):
    """
    Send notifications when support tickets are created or updated
    """
    if not settings.NOTIFICATION_CONFIG.get('REAL_TIME_EVENTS', {}).get('support_ticket_created', False):
        return
    
    if created:
        # New ticket created - notify admins/HR
        notify_users = get_notification_recipients_for_support(instance)
        
        for user in notify_users:
            notification = Notification.objects.create(
                recipient=user,
                type='BROWSER',
                title=f'New Support Ticket: {instance.ticket_id}',
                message=f'A new {instance.priority} priority ticket has been created by {instance.user.get_full_name() or instance.user.username}: {instance.subject}',
                event_type='support_ticket_created',
                event_reference_id=str(instance.id)
            )
            
            # Send browser notification
            send_browser_notification_task.delay(notification.id)
            
            # Send email if enabled
            if settings.NOTIFICATION_CONFIG.get('ENABLE_EMAIL_NOTIFICATIONS', False):
                email_notification = Notification.objects.create(
                    recipient=user,
                    type='EMAIL',
                    title=f'New Support Ticket: {instance.ticket_id}',
                    message=f'''Hello {user.get_full_name() or user.username},

A new support ticket has been created:

Ticket ID: {instance.ticket_id}
Priority: {instance.priority}
Issue Type: {instance.get_issue_type_display()}
Created by: {instance.user.get_full_name() or instance.user.username}
Subject: {instance.subject}

Description:
{instance.description}

Please log in to the system to review and respond to this ticket.

Best regards,
ArdurTrueAlign System''',
                    event_type='support_ticket_created',
                    event_reference_id=str(instance.id)
                )
                send_notification_task.delay(email_notification.id)
    
    else:
        # Ticket updated - notify ticket creator and assigned users
        if hasattr(instance, '_status_changed') and instance._status_changed:
            old_status, new_status = instance._status_changed
            
            notify_users = [instance.user]  # Always notify the ticket creator
            if instance.assigned_to_user and instance.assigned_to_user != instance.user:
                notify_users.append(instance.assigned_to_user)
            
            # Add CC users
            notify_users.extend(instance.cc_users.all())
            
            for user in set(notify_users):  # Remove duplicates
                notification = Notification.objects.create(
                    recipient=user,
                    type='BROWSER',
                    title=f'Ticket Updated: {instance.ticket_id}',
                    message=f'Ticket status changed from "{old_status}" to "{new_status}"',
                    event_type='support_ticket_updated',
                    event_reference_id=str(instance.id)
                )
                send_browser_notification_task.delay(notification.id)


@receiver(post_save, sender=TicketComment)
def ticket_comment_notification(sender, instance, created, **kwargs):
    """
    Send notifications when comments are added to tickets
    """
    if not created:
        return
    
    ticket = instance.ticket
    
    # Notify ticket creator and assigned user (but not the commenter)
    notify_users = [ticket.user]
    if ticket.assigned_to_user and ticket.assigned_to_user != instance.user:
        notify_users.append(ticket.assigned_to_user)
    
    # Add CC users (excluding the commenter)
    cc_users = ticket.cc_users.exclude(id=instance.user.id)
    notify_users.extend(cc_users)
    
    # Remove the commenter and duplicates
    notify_users = [user for user in set(notify_users) if user != instance.user]
    
    for user in notify_users:
        notification = Notification.objects.create(
            recipient=user,
            type='BROWSER',
            title=f'New Comment on Ticket: {ticket.ticket_id}',
            message=f'{instance.user.get_full_name() or instance.user.username} added a comment to ticket {ticket.ticket_id}',
            event_type='support_ticket_comment',
            event_reference_id=str(ticket.id)
        )
        send_browser_notification_task.delay(notification.id)


@receiver(post_save, sender=LeaveRequest)
def leave_request_notification(sender, instance, created, **kwargs):
    """
    Send notifications for leave request events
    """
    if created:
        # New leave request - notify managers and HR
        if settings.NOTIFICATION_CONFIG.get('REAL_TIME_EVENTS', {}).get('leave_request_created', False):
            notify_users = get_notification_recipients_for_leave(instance)
            
            for user in notify_users:
                notification = Notification.objects.create(
                    recipient=user,
                    type='BROWSER',
                    title=f'New Leave Request from {instance.user.get_full_name() or instance.user.username}',
                    message=f'Leave request for {instance.leave_days} day(s) from {instance.start_date} to {instance.end_date}',
                    event_type='leave_request_created',
                    event_reference_id=str(instance.id)
                )
                send_browser_notification_task.delay(notification.id)
    
    else:
        # Leave request status changed
        if hasattr(instance, '_status_changed'):
            old_status, new_status = instance._status_changed
            
            if new_status in ['Approved', 'Rejected']:
                event_type = f'leave_request_{new_status.lower()}'
                
                if settings.NOTIFICATION_CONFIG.get('REAL_TIME_EVENTS', {}).get(event_type, False):
                    notification = Notification.objects.create(
                        recipient=instance.user,
                        type='BROWSER',
                        title=f'Leave Request {new_status}',
                        message=f'Your leave request from {instance.start_date} to {instance.end_date} has been {new_status.lower()}',
                        event_type=event_type,
                        event_reference_id=str(instance.id)
                    )
                    send_browser_notification_task.delay(notification.id)
                    
                    # Send email notification for important status changes
                    if settings.NOTIFICATION_CONFIG.get('ENABLE_EMAIL_NOTIFICATIONS', False):
                        email_notification = Notification.objects.create(
                            recipient=instance.user,
                            type='EMAIL',
                            title=f'Leave Request {new_status}',
                            message=f'''Hello {instance.user.get_full_name() or instance.user.username},

Your leave request has been {new_status.lower()}.

Leave Details:
- From: {instance.start_date}
- To: {instance.end_date}
- Days: {instance.leave_days}
- Type: {instance.get_leave_type_display()}
- Status: {new_status}

{"Reason: " + instance.reason if instance.reason else ""}

Best regards,
ArdurTrueAlign System''',
                            event_type=event_type,
                            event_reference_id=str(instance.id)
                        )
                        send_notification_task.delay(email_notification.id)


@receiver(post_save, sender=Attendance)
def attendance_alert_notification(sender, instance, created, **kwargs):
    """
    Send notifications for attendance alerts (late, absent, etc.)
    """
    if not settings.NOTIFICATION_CONFIG.get('REAL_TIME_EVENTS', {}).get('attendance_alert', False):
        return
    
    # Only send alerts for certain statuses
    alert_statuses = ['Late', 'Absent', 'Present & Late']
    
    if instance.status in alert_statuses:
        # Notify HR and managers
        hr_users = User.objects.filter(groups__name='HR')
        manager_users = User.objects.filter(groups__name='Manager')
        
        notify_users = list(hr_users) + list(manager_users)
        
        for user in set(notify_users):  # Remove duplicates
            notification = Notification.objects.create(
                recipient=user,
                type='BROWSER',
                title=f'Attendance Alert: {instance.user.get_full_name() or instance.user.username}',
                message=f'{instance.user.get_full_name() or instance.user.username} is marked as "{instance.status}" for {instance.date}',
                event_type='attendance_alert',
                event_reference_id=str(instance.id)
            )
            send_browser_notification_task.delay(notification.id)


def get_notification_recipients_for_support(ticket):
    """
    Get list of users who should be notified for support ticket events
    """
    recipients = []
    
    # Add HR users for HR-related tickets
    if ticket.assigned_group == 'HR':
        hr_users = User.objects.filter(groups__name='HR', is_active=True)
        recipients.extend(hr_users)
    
    # Add Admin users for other tickets
    if ticket.assigned_group == 'Admin':
        admin_users = User.objects.filter(groups__name='Admin', is_active=True)
        recipients.extend(admin_users)
    
    # Add specifically assigned user if exists
    if ticket.assigned_to_user:
        recipients.append(ticket.assigned_to_user)
    
    return list(set(recipients))  # Remove duplicates


def get_notification_recipients_for_leave(leave_request):
    """
    Get list of users who should be notified for leave request events
    """
    recipients = []
    
    # Add HR users
    hr_users = User.objects.filter(groups__name='HR', is_active=True)
    recipients.extend(hr_users)
    
    # Add Manager users
    manager_users = User.objects.filter(groups__name='Manager', is_active=True)
    recipients.extend(manager_users)
    
    return list(set(recipients))  # Remove duplicates
