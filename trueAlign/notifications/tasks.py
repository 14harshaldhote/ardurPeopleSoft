from celery import shared_task
from django.core.mail import send_mail
from django.conf import settings
from django.core.cache import cache
from django.utils import timezone
from datetime import timedelta
import json
import logging

from .models import Notification

logger = logging.getLogger(__name__)


@shared_task
def send_notification_task(notification_id):
    """
    Sends notifications via email, browser, or system, based on type.
    """
    try:
        notification = Notification.objects.get(id=notification_id)
        logger.info(f"Processing notification {notification_id} for user {notification.recipient.username}")

        # Send email notifications
        if notification.type == 'EMAIL':
            send_mail(
                notification.title,
                notification.message,
                settings.DEFAULT_FROM_EMAIL,
                [notification.recipient.email],
                fail_silently=False,
            )
            logger.info(f"Email notification sent to {notification.recipient.email}")
        
        # Handle other types if necessary (e.g. Browser, SMS)
        # For SMS, integrate with SMS providers like Twilio, etc.
        elif notification.type == 'SMS':
            # TODO: Implement SMS notification using Twilio or other providers
            logger.info(f"SMS notification would be sent to {notification.recipient.username}")

    except Notification.DoesNotExist:
        logger.error(f"Notification ID {notification_id} does not exist.")
    except Exception as e:
        logger.error(f"Error sending notification {notification_id}: {str(e)}")


@shared_task
def send_browser_notification_task(notification_id):
    """
    Process browser notifications by storing them in cache for real-time polling
    """
    try:
        notification = Notification.objects.get(id=notification_id)
        
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
        
        # Keep only last 50 notifications in cache
        cached_notifications = cached_notifications[:50]
        
        # Cache for 1 hour
        cache.set(cache_key, cached_notifications, 3600)
        
        logger.info(f"Browser notification cached for user {notification.recipient.username}")
        
    except Notification.DoesNotExist:
        logger.error(f"Notification ID {notification_id} does not exist.")
    except Exception as e:
        logger.error(f"Error caching browser notification {notification_id}: {str(e)}")


@shared_task
def cleanup_old_notifications():
    """
    Clean up old notifications based on retention policy
    """
    try:
        retention_days = settings.NOTIFICATION_CONFIG.get('NOTIFICATION_RETENTION_DAYS', 30)
        cutoff_date = timezone.now() - timedelta(days=retention_days)
        
        deleted_count = Notification.objects.filter(timestamp__lt=cutoff_date).delete()[0]
        logger.info(f"Cleaned up {deleted_count} old notifications")
        
    except Exception as e:
        logger.error(f"Error cleaning up notifications: {str(e)}")


@shared_task
def send_bulk_notification(user_ids, notification_type, title, message, event_type=None):
    """
    Send bulk notifications to multiple users
    """
    try:
        from django.contrib.auth.models import User
        
        users = User.objects.filter(id__in=user_ids, is_active=True)
        notifications_created = 0
        
        for user in users:
            notification = Notification.objects.create(
                recipient=user,
                type=notification_type,
                title=title,
                message=message,
                event_type=event_type
            )
            
            if notification_type == 'BROWSER':
                send_browser_notification_task.delay(notification.id)
            elif notification_type == 'EMAIL':
                send_notification_task.delay(notification.id)
            
            notifications_created += 1
        
        logger.info(f"Created {notifications_created} bulk notifications")
        
    except Exception as e:
        logger.error(f"Error sending bulk notification: {str(e)}")


@shared_task
def send_system_announcement(title, message, user_groups=None, all_users=False):
    """
    Send system-wide announcements
    """
    try:
        from django.contrib.auth.models import User, Group
        
        if all_users:
            users = User.objects.filter(is_active=True)
        elif user_groups:
            users = User.objects.filter(groups__name__in=user_groups, is_active=True).distinct()
        else:
            users = User.objects.none()
        
        for user in users:
            notification = Notification.objects.create(
                recipient=user,
                type='BROWSER',
                title=title,
                message=message,
                event_type='system_announcement'
            )
            send_browser_notification_task.delay(notification.id)
            
            # Also send email for important announcements
            email_notification = Notification.objects.create(
                recipient=user,
                type='EMAIL',
                title=title,
                message=message,
                event_type='system_announcement'
            )
            send_notification_task.delay(email_notification.id)
        
        logger.info(f"Sent system announcement to {users.count()} users")
        
    except Exception as e:
        logger.error(f"Error sending system announcement: {str(e)}")

