from celery import shared_task
from django.contrib.auth import get_user_model
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import MessageRead, Message
from .services import get_unread_counts

@shared_task
def send_unread_message_notifications(user_id):
    """
    Background task to process unread messages and send notifications
    Args:
        user_id: ID of user to check notifications for
    """
    User = get_user_model()
    try:
        user = User.objects.get(id=user_id)
        
        # Get total unread count using same query as NotificationConsumer
        unread_count = MessageRead.objects.filter(
            user=user,
            read_at__isnull=True
        ).count()

        if unread_count > 0:
            # Get unread counts per chat using service function
            unread_counts = get_unread_counts(user)
            
            # Get most recent unread message for notification preview
            latest_message = Message.objects.filter(
                messageread__user=user,
                messageread__read_at__isnull=True
            ).select_related('sender').order_by('-sent_at').first()

            # Prepare notification message with preview
            if latest_message:
                sender = latest_message.sender.get_full_name() or latest_message.sender.username
                preview = latest_message.content[:50] + "..." if len(latest_message.content) > 50 else latest_message.content
                chat_name = latest_message.group.name if latest_message.group else "direct message"
                message = f"You have {unread_count} unread messages. Latest from {sender} in {chat_name}: {preview}"
            else:
                message = f"You have {unread_count} unread messages"
            
            # Send notification via WebSocket using same format as NotificationConsumer
            channel_layer = get_channel_layer()
            async_to_sync(channel_layer.group_send)(
                f'notifications_{user.id}',
                {
                    'type': 'notify',
                    'message': message,
                    'unread_count': unread_count
                }
            )

    except User.DoesNotExist:
        return
