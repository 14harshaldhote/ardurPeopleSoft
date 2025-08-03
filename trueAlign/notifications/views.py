"""
Notification Views
API endpoints for real-time notifications
"""

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from django.utils.decorators import method_decorator
from django.views.generic import View
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import json
import logging

from .models import Notification
from .tasks import send_browser_notification_task, send_bulk_notification

logger = logging.getLogger(__name__)


@login_required
@require_http_methods(["GET"])
def get_notifications(request):
    """
    Get notifications for the current user (for polling)
    """
    try:
        user = request.user
        
        # Get from cache first (for real-time notifications)
        cache_key = f"notifications_{user.id}"
        cached_notifications = cache.get(cache_key, [])
        
        # Also get recent notifications from database
        recent_notifications = Notification.objects.filter(
            recipient=user,
            timestamp__gte=timezone.now() - timedelta(hours=24)
        ).order_by('-timestamp')
        
        # Convert database notifications to dict format
        db_notifications = []
        for notification in recent_notifications:
            db_notifications.append({
                'id': notification.id,
                'title': notification.title,
                'message': notification.message,
                'timestamp': notification.timestamp.isoformat(),
                'event_type': notification.event_type,
                'event_reference_id': notification.event_reference_id,
                'read': notification.read,
                'type': notification.type
            })
        
        # Merge cached and database notifications, remove duplicates
        all_notifications = cached_notifications.copy()
        cached_ids = {notif['id'] for notif in cached_notifications}
        
        for db_notif in db_notifications:
            if db_notif['id'] not in cached_ids:
                all_notifications.append(db_notif)
        
        # Sort by timestamp (newest first)
        all_notifications.sort(key=lambda x: x['timestamp'], reverse=True)
        
        # Limit to max notifications per user
        max_notifications = settings.NOTIFICATION_CONFIG.get('MAX_NOTIFICATIONS_PER_USER', 100)
        all_notifications = all_notifications[:max_notifications]
        
        # Count unread notifications
        unread_count = sum(1 for notif in all_notifications if not notif['read'])
        
        return JsonResponse({
            'success': True,
            'notifications': all_notifications,
            'unread_count': unread_count,
            'timestamp': timezone.now().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error getting notifications for user {request.user.username}: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to get notifications'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_exempt
def mark_notification_read(request, notification_id):
    """
    Mark a notification as read
    """
    try:
        notification = Notification.objects.get(
            id=notification_id,
            recipient=request.user
        )
        notification.read = True
        notification.save()
        
        # Update cache as well
        cache_key = f"notifications_{request.user.id}"
        cached_notifications = cache.get(cache_key, [])
        
        for notif in cached_notifications:
            if notif['id'] == notification.id:
                notif['read'] = True
                break
        
        cache.set(cache_key, cached_notifications, 3600)
        
        return JsonResponse({
            'success': True,
            'message': 'Notification marked as read'
        })
        
    except Notification.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Notification not found'
        }, status=404)
    except Exception as e:
        logger.error(f"Error marking notification as read: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to mark notification as read'
        }, status=500)


@login_required
@require_http_methods(["POST"])
@csrf_exempt
def mark_all_notifications_read(request):
    """
    Mark all notifications as read for the current user
    """
    try:
        user = request.user
        
        # Update database
        updated_count = Notification.objects.filter(
            recipient=user,
            read=False
        ).update(read=True)
        
        # Update cache
        cache_key = f"notifications_{user.id}"
        cached_notifications = cache.get(cache_key, [])
        
        for notif in cached_notifications:
            notif['read'] = True
        
        cache.set(cache_key, cached_notifications, 3600)
        
        return JsonResponse({
            'success': True,
            'message': f'{updated_count} notifications marked as read'
        })
        
    except Exception as e:
        logger.error(f"Error marking all notifications as read: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to mark notifications as read'
        }, status=500)


@login_required
@require_http_methods(["DELETE"])
@csrf_exempt
def delete_notification(request, notification_id):
    """
    Delete a notification
    """
    try:
        notification = Notification.objects.get(
            id=notification_id,
            recipient=request.user
        )
        notification.delete()
        
        # Remove from cache as well
        cache_key = f"notifications_{request.user.id}"
        cached_notifications = cache.get(cache_key, [])
        cached_notifications = [notif for notif in cached_notifications if notif['id'] != notification_id]
        cache.set(cache_key, cached_notifications, 3600)
        
        return JsonResponse({
            'success': True,
            'message': 'Notification deleted'
        })
        
    except Notification.DoesNotExist:
        return JsonResponse({
            'success': False,
            'error': 'Notification not found'
        }, status=404)
    except Exception as e:
        logger.error(f"Error deleting notification: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to delete notification'
        }, status=500)


@login_required
@require_http_methods(["GET"])
def notification_settings(request):
    """
    Get notification settings for the current user
    """
    return JsonResponse({
        'success': True,
        'settings': {
            'browser_notifications_enabled': settings.NOTIFICATION_CONFIG.get('ENABLE_BROWSER_NOTIFICATIONS', True),
            'email_notifications_enabled': settings.NOTIFICATION_CONFIG.get('ENABLE_EMAIL_NOTIFICATIONS', True),
            'polling_interval': settings.NOTIFICATION_CONFIG.get('POLLING_INTERVAL_SECONDS', 30),
            'max_notifications': settings.NOTIFICATION_CONFIG.get('MAX_NOTIFICATIONS_PER_USER', 100)
        }
    })


# Admin-only views
from django.contrib.admin.views.decorators import staff_member_required


@staff_member_required
@require_http_methods(["POST"])
@csrf_exempt
def send_announcement(request):
    """
    Send system-wide announcement (admin only)
    """
    try:
        data = json.loads(request.body)
        title = data.get('title')
        message = data.get('message')
        user_groups = data.get('user_groups', [])
        all_users = data.get('all_users', False)
        
        if not title or not message:
            return JsonResponse({
                'success': False,
                'error': 'Title and message are required'
            }, status=400)
        
        # Send announcement via Celery task
        from .tasks import send_system_announcement
        send_system_announcement.delay(title, message, user_groups, all_users)
        
        return JsonResponse({
            'success': True,
            'message': 'Announcement sent successfully'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({
            'success': False,
            'error': 'Invalid JSON data'
        }, status=400)
    except Exception as e:
        logger.error(f"Error sending announcement: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to send announcement'
        }, status=500)


@staff_member_required
@require_http_methods(["GET"])
def notification_stats(request):
    """
    Get notification statistics (admin only)
    """
    try:
        from django.db.models import Count
        from django.contrib.auth.models import User
        
        # Get statistics
        total_notifications = Notification.objects.count()
        unread_notifications = Notification.objects.filter(read=False).count()
        notifications_by_type = Notification.objects.values('type').annotate(count=Count('type'))
        notifications_by_event = Notification.objects.values('event_type').annotate(count=Count('event_type'))
        
        # Recent activity (last 24 hours)
        recent_notifications = Notification.objects.filter(
            timestamp__gte=timezone.now() - timedelta(hours=24)
        ).count()
        
        return JsonResponse({
            'success': True,
            'stats': {
                'total_notifications': total_notifications,
                'unread_notifications': unread_notifications,
                'recent_notifications_24h': recent_notifications,
                'notifications_by_type': list(notifications_by_type),
                'notifications_by_event': list(notifications_by_event)
            }
        })
        
    except Exception as e:
        logger.error(f"Error getting notification stats: {str(e)}")
        return JsonResponse({
            'success': False,
            'error': 'Failed to get notification statistics'
        }, status=500)
