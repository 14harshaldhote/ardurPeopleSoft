"""
Notification Signals
Django signals to trigger notifications for various events
"""

from django.db.models.signals import post_save, post_delete
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.conf import settings

# Import models from other apps
from trueAlign.models import LeaveRequest, Attendance
from .models import Notification
from .tasks import send_notification_task, send_browser_notification_task


# Support and TicketComment models don't exist - signals commented out
# @receiver(post_save, sender=Support)
# def support_ticket_notification(sender, instance, created, **kwargs):
#     """Support ticket notifications - disabled until Support model is implemented"""
#     pass

# @receiver(post_save, sender=TicketComment)
# def ticket_comment_notification(sender, instance, created, **kwargs):
#     """Ticket comment notifications - disabled until TicketComment model is implemented"""
#     pass


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

                # Check if async processing is enabled
                use_async = settings.NOTIFICATION_CONFIG.get('USE_ASYNC_PROCESSING', False)

                if use_async:
                    try:
                        send_browser_notification_task.delay(notification.id)
                    except Exception as e:
                        # Fallback to synchronous processing if Celery is unavailable
                        _process_notification_sync(notification)
                else:
                    # Use synchronous processing directly
                    _process_notification_sync(notification)

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

                    # Check if async processing is enabled
                    use_async = settings.NOTIFICATION_CONFIG.get('USE_ASYNC_PROCESSING', False)

                    if use_async:
                        try:
                            send_browser_notification_task.delay(notification.id)
                        except Exception as e:
                            # Fallback to synchronous processing if Celery is unavailable
                            _process_notification_sync(notification)
                    else:
                        # Use synchronous processing directly
                        _process_notification_sync(notification)

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
- Type: {instance.leave_type.name}
- Status: {new_status}

{"Reason: " + instance.reason if instance.reason else ""}

Best regards,
ArdurTrueAlign System''',
                            event_type=event_type,
                            event_reference_id=str(instance.id)
                        )

                        # Check if async processing is enabled for email
                        use_async = settings.NOTIFICATION_CONFIG.get('USE_ASYNC_PROCESSING', False)

                        if use_async:
                            try:
                                send_notification_task.delay(email_notification.id)
                            except Exception as e:
                                # Fallback to synchronous processing if Celery is unavailable
                                _process_email_notification_sync(email_notification)
                        else:
                            # Use synchronous processing directly
                            _process_email_notification_sync(email_notification)


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

            # Check if async processing is enabled
            use_async = settings.NOTIFICATION_CONFIG.get('USE_ASYNC_PROCESSING', False)

            if use_async:
                try:
                    send_browser_notification_task.delay(notification.id)
                except Exception as e:
                    # Fallback to synchronous processing if Celery is unavailable
                    _process_notification_sync(notification)
            else:
                # Use synchronous processing directly
                _process_notification_sync(notification)


# def get_notification_recipients_for_support(ticket):
#     """Support ticket recipients - disabled until Support model is implemented"""
#     return []


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


def _process_notification_sync(notification):
    """
    Process browser notification synchronously when Celery is unavailable
    """
    try:
        from django.core.cache import cache

        # Store notification in cache for real-time retrieval
        cache_key = f"notifications_{notification.recipient.id}"
        cached_notifications = cache.get(cache_key, [])

        notification_data = {
            'id': notification.id,
            'title': notification.title,
            'message': notification.message,
            'timestamp': notification.timestamp.isoformat(),
            'event_type': notification.event_type,
            'event_reference_id': notification.event_reference_id,
            'read': notification.read
        }

        cached_notifications.insert(0, notification_data)  # Add to beginning
        cached_notifications = cached_notifications[:50]  # Keep only last 50

        # Cache for 1 hour
        cache.set(cache_key, cached_notifications, 3600)

        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Processed notification {notification.id} synchronously for user {notification.recipient.username}")

    except Exception as e:
        # If cache also fails, at least the notification is in the database
        import logging
        logger = logging.getLogger(__name__)
        logger.warning(f"Failed to cache notification {notification.id}: {e}. Notification saved in database.")


def _process_email_notification_sync(notification):
    """
    Process email notification synchronously when Celery is unavailable
    """
    try:
        from django.core.mail import send_mail

        send_mail(
            notification.title,
            notification.message,
            settings.DEFAULT_FROM_EMAIL,
            [notification.recipient.email],
            fail_silently=False,
        )

        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Sent email notification {notification.id} synchronously to {notification.recipient.email}")

    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Failed to send email notification {notification.id}: {e}")
