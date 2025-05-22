from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db.models import Q, Count
from .models import ChatGroup, GroupMember, DirectMessage, Message, MessageRead

def get_chat_history(chat_id, user, chat_type='group', limit=50):
    """
    Fetch chat history efficiently with pagination
    Args:
        chat_id: ID of the chat (group or direct message)
        user: Requesting user
        chat_type: Type of chat ('group' or 'direct')
        limit: Number of messages to return (default 50)
    Returns:
        QuerySet of messages
    """
    try:
        if chat_type == 'group':
            chat_group = ChatGroup.objects.get(id=chat_id)
            
            if not GroupMember.objects.filter(group=chat_group, user=user, is_active=True).exists():
                raise ValidationError("User is not an active member of this group")
                
            messages = Message.objects.filter(group=chat_group, is_deleted=False)
            
        else:
            direct_message = DirectMessage.objects.get(id=chat_id, is_active=True)
            
            if not direct_message.participants.filter(id=user.id).exists():
                raise ValidationError("User is not a participant in this conversation")
                
            messages = Message.objects.filter(direct_message=direct_message, is_deleted=False)
        
        result = messages.select_related('sender').order_by('-sent_at')[:limit]
        return result
        
    except (ChatGroup.DoesNotExist, DirectMessage.DoesNotExist) as e:
        raise ValidationError(f"Chat not found: {str(e)}")
    
def mark_messages_as_read(chat_id, user, chat_type):
    """Mark all messages in a chat as read for a user"""
    try:
        current_time = timezone.now()
        
        # Get all unread messages in this chat for this user
        if chat_type == 'group':
            # For group messages
            read_receipts = MessageRead.objects.filter(
                message__group_id=chat_id,
                message__is_deleted=False,
                user=user,
                read_at__isnull=True
            )
        else:
            # For direct messages
            read_receipts = MessageRead.objects.filter(
                message__direct_message_id=chat_id,
                message__is_deleted=False,
                user=user,
                read_at__isnull=True
            )
        
        # Update read_at timestamp for all unread messages at once
        updated_count = read_receipts.update(read_at=current_time)
        
        return updated_count
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error marking messages as read: {str(e)}")
        return 0

# def mark_messages_as_read(chat_id, user, chat_type='group'):
#     """
#     Mark all unread messages in a chat as read
#     Args:
#         chat_id: ID of the chat
#         user: User marking messages as read
#         chat_type: Type of chat ('group' or 'direct')
#     """
#     try:
#         if chat_type == 'group':
#             chat_group = ChatGroup.objects.get(id=chat_id, is_active=True)
#             if not GroupMember.objects.filter(group=chat_group, user=user, is_active=True).exists():
#                 raise ValidationError("User is not an active member of this group")
#             messages = Message.objects.filter(group=chat_group, is_deleted=False)
#         else:
#             direct_message = DirectMessage.objects.get(id=chat_id, is_active=True)
#             if not direct_message.participants.filter(id=user.id).exists():
#                 raise ValidationError("User is not a participant in this conversation")
#             messages = Message.objects.filter(direct_message=direct_message, is_deleted=False)

#         now = timezone.now()
#         MessageRead.objects.filter(
#             message__in=messages,
#             user=user,
#             read_at__isnull=True
#         ).update(read_at=now)
        
#         unread_messages = messages.exclude(read_receipts__user=user)
        
#         read_receipts = [
#             MessageRead(message=msg, user=user, read_at=now)
#             for msg in unread_messages
#         ]
#         MessageRead.objects.bulk_create(read_receipts, ignore_conflicts=True)

#     except (ChatGroup.DoesNotExist, DirectMessage.DoesNotExist) as e:
#         raise ValidationError(f"Chat not found: {str(e)}")

def get_unread_counts(user):
    """
    Get unread message counts for all user's chats
    Args:
        user: User to get counts for
    Returns:
        Dict with chat_id: unread_count mapping
    """
    # Get unread counts for groups
    group_counts = ChatGroup.objects.filter(
        memberships__user=user,
        memberships__is_active=True,
        is_active=True
    ).annotate(
        unread=Count(
            'messages',
            filter=Q(messages__is_deleted=False) & 
                  Q(messages__read_receipts__user=user, 
                    messages__read_receipts__read_at__isnull=True)
        )
    ).values('id', 'unread')

    # Get unread counts for direct messages
    dm_counts = DirectMessage.objects.filter(
        participants=user,
        is_active=True
    ).annotate(
        unread=Count(
            'messages',
            filter=Q(messages__is_deleted=False) &
                  Q(messages__read_receipts__user=user,
                    messages__read_receipts__read_at__isnull=True)
        )
    ).values('id', 'unread')

    # Combine into single dictionary
    unread_counts = {
        chat['id']: chat['unread'] 
        for chat in list(group_counts) + list(dm_counts)
    }
    
    return unread_counts

def create_group(name, created_by, description=""):
    """
    Create a new chat group
    Args:
        name: Group name
        created_by: User creating the group
        description: Optional group description
    Returns:
        Created ChatGroup instance
    """
    # Validate creator permissions
    if not created_by.groups.filter(name__in=['Admin', 'Manager']).exists():
        raise ValidationError("Only managers and administrators can create chat groups")
        
    group = ChatGroup.objects.create(
        name=name,
        description=description,
        created_by=created_by,
        is_active=True
    )

    # Add creator as admin member
    GroupMember.objects.create(
        group=group,
        user=created_by,
        role='admin',
        is_active=True
    )

    return group


