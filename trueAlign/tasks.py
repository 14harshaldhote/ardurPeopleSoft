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
    print(f"[DEBUG] send_unread_message_notifications: Starting task for user_id {user_id}")
    
    User = get_user_model()
    try:
        print(f"[DEBUG] send_unread_message_notifications: Getting user with ID {user_id}")
        user = User.objects.get(id=user_id)
        print(f"[DEBUG] send_unread_message_notifications: Found user {user}")
        
        # Get total unread count using same query as NotificationConsumer
        print("[DEBUG] send_unread_message_notifications: Querying unread messages")
        unread_count = MessageRead.objects.filter(
            user=user,
            read_at__isnull=True
        ).count()
        print(f"[DEBUG] send_unread_message_notifications: Found {unread_count} unread messages")

        if unread_count > 0:
            print("[DEBUG] send_unread_message_notifications: Processing unread messages")
            
            # Get unread counts per chat using service function
            print("[DEBUG] send_unread_message_notifications: Getting unread counts per chat")
            unread_counts = get_unread_counts(user)
            print(f"[DEBUG] send_unread_message_notifications: Unread counts by chat: {unread_counts}")
            
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
            print(f"[DEBUG] send_unread_message_notifications: Prepared message: {message}")
            
            # Send notification via WebSocket using same format as NotificationConsumer
            print("[DEBUG] send_unread_message_notifications: Getting channel layer")
            channel_layer = get_channel_layer()
            print(f"[DEBUG] send_unread_message_notifications: Sending notification to notifications_{user.id}")
            async_to_sync(channel_layer.group_send)(
                f'notifications_{user.id}',
                {
                    'type': 'notify',
                    'message': message,
                    'unread_count': unread_count
                }
            )
            print("[DEBUG] send_unread_message_notifications: Notification sent successfully")

    except User.DoesNotExist:
        print(f"[DEBUG] send_unread_message_notifications: User {user_id} not found")
        return
