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
    try:
        # Check group chat access
        chat_group = ChatGroup.objects.get(id=chat_id)
        if not GroupMember.objects.filter(group=chat_group, user=user, is_active=True).exists():
            raise ValidationError("User is not an active member of this group")
    except ChatGroup.DoesNotExist:
        # Check direct message access
        direct_message = DirectMessage.objects.get(id=chat_id, is_active=True)
        if not direct_message.participants.filter(id=user.id).exists():
            raise ValidationError("User is not a participant in this conversation")

def get_last_seen(user):
    """
    Get user's last seen timestamp from their most recent group activity
    Args:
        user: User to check
    Returns:
        Last seen datetime or None
    """
    last_group_activity = GroupMember.objects.filter(
        user=user,
        is_active=True
    ).order_by('-last_seen').first()
    
    if last_group_activity:
        return last_group_activity.last_seen
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
    try:
        message = Message.objects.get(id=message_id, is_deleted=False)
        
        # Validate user can delete message
        if message.sender != user:
            if message.group:
                if not GroupMember.objects.filter(
                    group=message.group,
                    user=user,
                    role='admin',
                    is_active=True
                ).exists():
                    raise ValidationError("Only message sender or group admin can delete messages")
            else:
                raise ValidationError("Only message sender can delete direct messages")
                
        message.soft_delete()
        
    except Message.DoesNotExist:
        raise ValidationError("Message not found")

# def send_notification(user_id, message, notification_type, chat_id=None, sender=None, hours_ago=24):
#     """
#     Send notification via WebSocket
#     Args:
#         user_id: ID of user to notify
#         message: Notification message
#         notification_type: Type of notification
#         chat_id: Optional chat ID
#         sender: Optional sender info
#         hours_ago: Number of hours to look back for unread messages (default 24)
#     """
#     channel_layer = get_channel_layer()
    
#     # Get unread counts using service function
#     unread_count = MessageRead.objects.filter(
#         user_id=user_id,
#         read_at__isnull=True,
#         message__is_deleted=False
#     ).count()

    
#     notification_data = {
#         'type': 'notify',
#         'message': message,
#         'notification_type': notification_type,
#         'chat_id': chat_id,
#         'sender': sender,
#         'timestamp': timezone.now().isoformat(),
#         'unread_count': unread_count
#     }
    
#     async_to_sync(channel_layer.group_send)(
#         f'notifications_{user_id}',
#         notification_data
#     )
def send_notification(user_id, message, notification_type, chat_id, sender_name=None):
    """
    Send a notification to a user
    
    Args:
        user_id (int): The ID of the user to notify
        message (str): The notification message
        notification_type (str): Type of notification (read_status, direct_message, group_add, etc.)
        chat_id (int): The ID of the relevant chat
        sender_name (str, optional): The name of the sender if applicable
        
    Returns:
        bool: True if notification was sent successfully, False otherwise
    """
    try:
        # Only send notifications to users other than the current user
        from django.contrib.auth.models import User
        user = User.objects.get(id=user_id)
        
        # Check if the user has notification preferences enabled for this type
        # You might have a UserPreference model to check this
        
        # Implement your notification logic here
        # This could be WebSocket, database record, email, etc.
        
        # Example WebSocket notification (using Django Channels)
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            f"user_{user_id}",
            {
                "type": "notification.message",
                "message": message,
                "notification_type": notification_type,
                "chat_id": chat_id,
                "sender_name": sender_name
            }
        )
        
        return True
    except Exception as e:
        # Log the error but don't crash
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error sending notification to user {user_id}: {str(e)}")
        return False


def send_ticket_notification(ticket, action, performed_by=None, extra_message=None):
    """
    Send a notification related to a support ticket action.

    Args:
        ticket (Support): The ticket instance.
        action (str): The action performed (e.g., 'created', 'updated', 'assigned', 'commented', etc.).
        performed_by (User, optional): The user who performed the action.
        extra_message (str, optional): Any extra message to include.
    Returns:
        bool: True if notification sent, False otherwise.
    """
    try:
        # Determine recipients based on action and ticket assignment
        recipients = set()
        if hasattr(ticket, "assigned_to_user") and ticket.assigned_to_user:
            recipients.add(ticket.assigned_to_user)
        if hasattr(ticket, "user") and ticket.user:
            recipients.add(ticket.user)
        # Optionally notify group members (e.g., HR/Admin group)
        if hasattr(ticket, "assigned_group") and ticket.assigned_group:
            from django.contrib.auth.models import Group
            group_qs = Group.objects.filter(name=ticket.assigned_group)
            if group_qs.exists():
                group = group_qs.first()
                for user in group.user_set.all():
                    recipients.add(user)
        # Remove the performer from recipients (don't notify self)
        if performed_by in recipients:
            recipients.remove(performed_by)
        # Compose the notification message
        action_map = {
            "created": "A new support ticket has been created.",
            "updated": "A support ticket has been updated.",
            "assigned": "A support ticket has been assigned.",
            "commented": "A new comment was added to your ticket.",
            "closed": "A support ticket has been closed.",
            "reopened": "A support ticket has been reopened.",
            "resolved": "A support ticket has been resolved.",
            "escalated": "A support ticket has been escalated.",
        }
        action_text = action_map.get(action, f"Ticket action: {action}")
        performer_name = performed_by.username if performed_by else "System"
        message = f"{action_text}\nTicket: {ticket.title}\nBy: {performer_name}"
        if extra_message:
            message += f"\n{extra_message}"
        # Send notification to each recipient
        for user in recipients:
            send_notification(
                user_id=user.id,
                message=message,
                notification_type="ticket_" + action,
                chat_id=getattr(ticket, "id", None) or getattr(ticket, "pk", None),
                sender_name=performer_name
            )
        return True
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error sending ticket notification: {str(e)}")
        return False
