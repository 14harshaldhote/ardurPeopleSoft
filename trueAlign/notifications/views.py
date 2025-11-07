"""
Notification Views
API endpoints for real-time notifications
"""

from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_http_methods
from django.core.cache import cache
from django.shortcuts import get_object_or_404
from trueAlign.models import Notification

@login_required
@require_http_methods(["GET"])
def get_notifications(request):
    """Get unread notifications for current user"""
    # Try to get from cache first
    cache_key = f"user_notifications_{request.user.id}"
    cached_notifications = cache.get(cache_key)

    if cached_notifications is None:
        # If not in cache, get from database
        notifications = (
            Notification.objects
            .filter(recipient=request.user)
            .order_by('-timestamp')[:20]
        )

        cached_notifications = [{
            'id': n.id,
            'title': n.title,
            'message': n.message,
            'module': n.module,
            'timestamp': n.timestamp.isoformat(),
            'read': n.read,
            'url': n.url
        } for n in notifications]

        # Cache for 1 hour
        cache.set(cache_key, cached_notifications, 3600)

    unread_count = len([n for n in cached_notifications if not n['read']])

    return JsonResponse({
        'notifications': cached_notifications,
        'unread_count': unread_count
    })

@login_required
@require_http_methods(["POST"])
def mark_notification_read(request, notification_id):
    """Mark a notification as read"""
    notification = get_object_or_404(
        Notification,
        id=notification_id,
        recipient=request.user
    )
    notification.mark_as_read()

    # Update cache
    cache_key = f"user_notifications_{request.user.id}"
    cached_notifications = cache.get(cache_key, [])

    for n in cached_notifications:
        if n['id'] == notification_id:
            n['read'] = True
            break

    cache.set(cache_key, cached_notifications, 3600)

    return JsonResponse({'status': 'success'})

@login_required
@require_http_methods(["POST"])
def mark_all_read(request):
    """Mark all notifications as read"""
    Notification.objects.filter(
        recipient=request.user,
        read=False
    ).update(read=True)

    # Clear cache
    cache_key = f"user_notifications_{request.user.id}"
    cache.delete(cache_key)

    return JsonResponse({'status': 'success'})

@login_required
@require_http_methods(["DELETE"])
def delete_notification(request, notification_id):
    """Delete a notification"""
    notification = get_object_or_404(
        Notification,
        id=notification_id,
        recipient=request.user
    )
    notification.delete()

    # Update cache
    cache_key = f"user_notifications_{request.user.id}"
    cached_notifications = cache.get(cache_key, [])

    if cached_notifications:
        cached_notifications = [
            n for n in cached_notifications
            if n['id'] != notification_id
        ]
        cache.set(cache_key, cached_notifications, 3600)

    return JsonResponse({'status': 'success'})
