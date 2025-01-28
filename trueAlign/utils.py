# utils.py


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip


# utils.py
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from django.utils import timezone

def send_notification(user_id, message, notification_type, chat_id=None, sender=None):
    # Send notification via WebSocket (no database storage)
    channel_layer = get_channel_layer()
    async_to_sync(channel_layer.group_send)(
        f'notifications_{user_id}',
        {
            'type': 'notification',
            'message': message,
            'notification_type': notification_type,
            'chat_id': chat_id,
            'sender': sender,
            'timestamp': timezone.now().isoformat()
        }
    )
