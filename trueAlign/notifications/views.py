from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_exempt
from trueAlign.models import Notification

@login_required
@require_http_methods(["GET"])
def get_unread_notifications(request):
    """Get unread notifications for the current user"""
    notifications = Notification.objects.filter(
        recipient=request.user,
        read=False
    ).order_by('-timestamp')[:20]  # Limit to last 20 unread

    data = {
        'unread_count': Notification.objects.filter(recipient=request.user, read=False).count(),
        'notifications': [
            {
                'id': n.id,
                'title': n.title,
                'message': n.message,
                'module': n.module,
                'timestamp': n.timestamp.isoformat(),
                'read': n.read,
                'url': n.url
            } for n in notifications
        ]
    }
    return JsonResponse(data)

@login_required
@require_http_methods(["POST"])
def mark_notification_read(request, notification_id):
    """Mark a specific notification as read"""
    notification = get_object_or_404(Notification, id=notification_id, recipient=request.user)
    notification.read = True
    notification.save()
    return JsonResponse({'status': 'success'})

@login_required
@require_http_methods(["POST"])
def mark_all_read(request):
    """Mark all notifications as read for the current user"""
    Notification.objects.filter(recipient=request.user, read=False).update(read=True)
    return JsonResponse({'status': 'success'})
