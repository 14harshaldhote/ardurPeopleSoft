# utils.py
from django.utils import timezone
from django.core.exceptions import ValidationError
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from .models import ChatGroup, GroupMember, DirectMessage, Message, MessageRead

def get_client_ip(request):
    """Get client IP address from request"""
    print("[DEBUG] get_client_ip: Getting client IP")
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
        print(f"[DEBUG] get_client_ip: Found forwarded IP: {ip}")
    else:
        ip = request.META.get('REMOTE_ADDR')
        print(f"[DEBUG] get_client_ip: Using REMOTE_ADDR: {ip}")
    return ip

def validate_user_in_chat(user, chat_id):
    """
    Validate that a user has access to a chat
    Args:
        user: User to validate
        chat_id: ID of chat to check
    Raises:
        ValidationError if user does not have access
    """
    print(f"[DEBUG] validate_user_in_chat: Validating access for user {user} in chat {chat_id}")
    try:
        # Check group chat access
        print("[DEBUG] validate_user_in_chat: Checking group chat access")
        chat_group = ChatGroup.objects.get(id=chat_id)
        print(f"[DEBUG] validate_user_in_chat: Found group chat: {chat_group}")
        if not GroupMember.objects.filter(group=chat_group, user=user, is_active=True).exists():
            print("[DEBUG] validate_user_in_chat: User not in group, raising error")
            raise ValidationError("User is not an active member of this group")
        print("[DEBUG] validate_user_in_chat: User has group access")
    except ChatGroup.DoesNotExist:
        # Check direct message access
        print("[DEBUG] validate_user_in_chat: Group not found, checking direct message")
        direct_message = DirectMessage.objects.get(id=chat_id, is_active=True)
        print(f"[DEBUG] validate_user_in_chat: Found direct message: {direct_message}")
        if not direct_message.participants.filter(id=user.id).exists():
            print("[DEBUG] validate_user_in_chat: User not in DM, raising error")
            raise ValidationError("User is not a participant in this conversation")
        print("[DEBUG] validate_user_in_chat: User has DM access")

def get_last_seen(user):
    """
    Get user's last seen timestamp from their most recent group activity
    Args:
        user: User to check
    Returns:
        Last seen datetime or None
    """
    print(f"[DEBUG] get_last_seen: Getting last seen for user {user}")
    last_group_activity = GroupMember.objects.filter(
        user=user,
        is_active=True
    ).order_by('-last_seen').first()
    
    if last_group_activity:
        print(f"[DEBUG] get_last_seen: Found last activity at {last_group_activity.last_seen}")
        return last_group_activity.last_seen
    print("[DEBUG] get_last_seen: No activity found")
    return None

def soft_delete_message(message_id, user):
    """
    Soft delete a message if user has permission
    Args:
        message_id: ID of message to delete
        user: User requesting deletion
    Raises:
        ValidationError if user cannot delete message
    """
    print(f"[DEBUG] soft_delete_message: Attempting to delete message {message_id} by user {user}")
    try:
        message = Message.objects.get(id=message_id, is_deleted=False)
        print(f"[DEBUG] soft_delete_message: Found message: {message}")
        
        # Validate user can delete message
        if message.sender != user:
            print("[DEBUG] soft_delete_message: User is not sender, checking group admin status")
            if message.group:
                if not GroupMember.objects.filter(
                    group=message.group,
                    user=user,
                    role='admin',
                    is_active=True
                ).exists():
                    print("[DEBUG] soft_delete_message: User not admin, raising error")
                    raise ValidationError("Only message sender or group admin can delete messages")
            else:
                print("[DEBUG] soft_delete_message: Not group message, raising error")
                raise ValidationError("Only message sender can delete direct messages")
                
        print("[DEBUG] soft_delete_message: Performing soft delete")
        message.soft_delete()
        print("[DEBUG] soft_delete_message: Message deleted successfully")
        
    except Message.DoesNotExist:
        print("[DEBUG] soft_delete_message: Message not found")
        raise ValidationError("Message not found")

def send_notification(user_id, message, notification_type, chat_id=None, sender=None, hours_ago=24):
    """
    Send notification via WebSocket
    Args:
        user_id: ID of user to notify
        message: Notification message
        notification_type: Type of notification
        chat_id: Optional chat ID
        sender: Optional sender info
        hours_ago: Number of hours to look back for unread messages (default 24)
    """
    print(f"[DEBUG] send_notification: Sending notification to user {user_id}")
    print(f"[DEBUG] send_notification: Message: {message}")
    print(f"[DEBUG] send_notification: Type: {notification_type}")
    
    channel_layer = get_channel_layer()
    print("[DEBUG] send_notification: Got channel layer")
    
    # Get unread counts using service function
    unread_count = MessageRead.objects.filter(
        user_id=user_id,
        read_at__isnull=True,
        message__is_deleted=False
    ).count()
    print(f"[DEBUG] send_notification: Unread count: {unread_count}")
    
    notification_data = {
        'type': 'notify',
        'message': message,
        'notification_type': notification_type,
        'chat_id': chat_id,
        'sender': sender,
        'timestamp': timezone.now().isoformat(),
        'unread_count': unread_count
    }
    print(f"[DEBUG] send_notification: Sending data: {notification_data}")
    
    async_to_sync(channel_layer.group_send)(
        f'notifications_{user_id}',
        notification_data
    )
    print("[DEBUG] send_notification: Notification sent successfully")
