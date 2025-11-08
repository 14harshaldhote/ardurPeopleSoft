"""
Notification Signals
Django signals to trigger notifications for various events
"""

from django.db.models.signals import post_save
from django.dispatch import receiver
from django.core.cache import cache
from django.contrib.auth import get_user_model

from trueAlign.models import Notification, Support, Attendance, TicketComment, LeaveRequest

User = get_user_model()

def create_notification(recipient, title, message, module, reference_id=None, url=None):
    """Helper function to create notifications and update cache"""
    notification = Notification.objects.create(
        recipient=recipient,
        title=title,
        message=message,
        module=module,
        reference_id=reference_id,
        url=url
    )

    # Update cache for real-time notifications
    cache_key = f"user_notifications_{recipient.id}"
    cached_notifications = cache.get(cache_key, [])
    notification_data = {
        'id': notification.id,
        'title': title,
        'message': message,
        'timestamp': notification.timestamp.isoformat(),
        'url': url,
        'module': module
    }
    cached_notifications.insert(0, notification_data)
    cache.set(cache_key, cached_notifications[:20], 3600)  # Cache for 1 hour

    return notification

# Support Module Signals
@receiver(post_save, sender=Support)
def ticket_notification(sender, instance, created, **kwargs):
    if created:
        create_notification(
            recipient=instance.assigned_to,
            title='🎫 New Ticket Assigned',
            message=f'Ticket #{instance.id} has been assigned to you',
            module='support',
            reference_id=str(instance.id),
            url=f'/support/ticket/{instance.id}/'
        )
    elif hasattr(instance, '_escalated') and instance._escalated:
        create_notification(
            recipient=instance.escalation_handler,
            title='⚠️ Ticket Escalated',
            message=f'Ticket #{instance.id} requires immediate attention',
            module='support',
            reference_id=str(instance.id),
            url=f'/support/ticket/{instance.id}/'
        )

@receiver(post_save, sender=TicketComment)
def ticket_comment_notification(sender, instance, created, **kwargs):
    if created:
        # Notify ticket creator and assigned user
        recipients = {instance.ticket.created_by, instance.ticket.assigned_to}
        recipients.discard(instance.user)  # Remove comment author

        for recipient in recipients:
            create_notification(
                recipient=recipient,
                title='💬 New Ticket Comment',
                message=f'New comment on ticket #{instance.ticket.id}',
                module='support',
                reference_id=str(instance.ticket.id),
                url=f'/support/ticket/{instance.ticket.id}/#comment-{instance.id}'
            )

# Attendance Module Signals
@receiver(post_save, sender=Attendance)
def attendance_notification(sender, instance, created, **kwargs):
    # Skip if in test mode or if required methods don't exist
    if not hasattr(instance, 'get_approvers') or not hasattr(instance, 'employee'):
        return
    
    if created:
        try:
            for manager in instance.get_approvers():
                create_notification(
                    recipient=manager,
                    title='⏰ New Regularization Request',
                    message=f'Regularization request from {instance.employee.get_full_name()}',
                    module='attendance',
                    reference_id=str(instance.id),
                    url=f'/attendance/regularization/{instance.id}/'
                )
        except AttributeError:
            pass  # Silently skip if methods don't exist
    elif hasattr(instance, 'status_changed') and instance.status_changed:
        if instance.status in ['approved', 'rejected']:
            create_notification(
                recipient=instance.employee,
                title=f'{"✅" if instance.status == "approved" else "❌"} Regularization {instance.status.title()}',
                message=f'Your attendance regularization request has been {instance.status}',
                module='attendance',
                reference_id=str(instance.id),
                url=f'/attendance/regularization/{instance.id}/'
            )

# Leave Management Signals
@receiver(post_save, sender=LeaveRequest)
def leave_notification(sender, instance, created, **kwargs):
    if created:
        for manager in instance.get_approvers():
            create_notification(
                recipient=manager,
                title='📅 New Leave Request',
                message=f'Leave request from {instance.employee.get_full_name()}',
                module='leave',
                reference_id=str(instance.id),
                url=f'/leave/request/{instance.id}/'
            )
    elif hasattr(instance, 'status_changed') and instance.status_changed:
        if instance.status in ['approved', 'rejected']:
            create_notification(
                recipient=instance.employee,
                title=f'{"✅" if instance.status == "approved" else "❌"} Leave {instance.status.title()}',
                message=f'Your leave request has been {instance.status}',
                module='leave',
                reference_id=str(instance.id),
                url=f'/leave/request/{instance.id}/'
            )

# Shift Management Signals
# @receiver(post_save, sender=ShiftChangeRequest)
# def shift_notification(sender, instance, created, **kwargs):
#     if created:
#         if instance.request_type == 'change':
#             create_notification(
#                 recipient=instance.manager,
#                 title='🔄 Shift Change Request',
#                 message=f'New shift change request from {instance.employee.get_full_name()}',
#                 module='shift',
#                 reference_id=str(instance.id),
#                 url=f'/shift/request/{instance.id}/'
#             )
#         elif instance.request_type == 'swap':
#             create_notification(
#                 recipient=instance.target_employee,
#                 title='🔄 Shift Swap Proposed',
#                 message=f'Shift swap requested by {instance.employee.get_full_name()}',
#                 module='shift',
#                 reference_id=str(instance.id),
#                 url=f'/shift/request/{instance.id}/'
#             )
#     elif hasattr(instance, 'status_changed') and instance.status_changed and instance.status == 'approved':
#         recipients = [instance.employee]
#         if instance.request_type == 'swap':
#             recipients.append(instance.target_employee)
#
#         for recipient in recipients:
#             create_notification(
#                 recipient=recipient,
#                 title='✅ Shift Change Approved',
#                 message='Your shift change request has been approved',
#                 module='shift',
#                 reference_id=str(instance.id),
#                 url=f'/shift/request/{instance.id}/'
#             )
