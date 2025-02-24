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
    print(f"[DEBUG] get_chat_history: Starting fetch for {chat_type} chat {chat_id} and user {user}")
    try:
        if chat_type == 'group':
            print(f"[DEBUG] get_chat_history: Fetching group chat with ID {chat_id}")
            chat_group = ChatGroup.objects.get(id=chat_id)
            print(f"[DEBUG] get_chat_history: Found group chat: {chat_group}")
            
            if not GroupMember.objects.filter(group=chat_group, user=user, is_active=True).exists():
                print(f"[DEBUG] get_chat_history: User {user} is not an active member of group {chat_group}")
                raise ValidationError("User is not an active member of this group")
                
            print(f"[DEBUG] get_chat_history: Fetching messages for group chat {chat_group}")
            messages = Message.objects.filter(group=chat_group, is_deleted=False)
            
        else:
            print(f"[DEBUG] get_chat_history: Fetching direct message chat with ID {chat_id}")
            direct_message = DirectMessage.objects.get(id=chat_id, is_active=True)
            print(f"[DEBUG] get_chat_history: Found direct message chat: {direct_message}")
            
            if not direct_message.participants.filter(id=user.id).exists():
                print(f"[DEBUG] get_chat_history: User {user} is not a participant in DM {direct_message}")
                raise ValidationError("User is not a participant in this conversation")
                
            print(f"[DEBUG] get_chat_history: Fetching messages for DM {direct_message}")
            messages = Message.objects.filter(direct_message=direct_message, is_deleted=False)
        
        result = messages.select_related('sender').order_by('-sent_at')[:limit]
        print(f"[DEBUG] get_chat_history: Returning {result.count()} messages")
        return result
        
    except (ChatGroup.DoesNotExist, DirectMessage.DoesNotExist) as e:
        print(f"[DEBUG] get_chat_history: Error fetching chat: {str(e)}")
        raise ValidationError(f"Chat not found: {str(e)}")

def mark_messages_as_read(chat_id, user, chat_type='group'):
    """
    Mark all unread messages in a chat as read
    Args:
        chat_id: ID of the chat
        user: User marking messages as read
        chat_type: Type of chat ('group' or 'direct')
    """
    print(f"[DEBUG] mark_messages_as_read: Starting for {chat_type} chat {chat_id} and user {user}")
    try:
        if chat_type == 'group':
            print(f"[DEBUG] mark_messages_as_read: Fetching group chat {chat_id}")
            chat_group = ChatGroup.objects.get(id=chat_id, is_active=True)
            if not GroupMember.objects.filter(group=chat_group, user=user, is_active=True).exists():
                raise ValidationError("User is not an active member of this group")
            print(f"[DEBUG] mark_messages_as_read: Found group chat, fetching messages")
            messages = Message.objects.filter(group=chat_group, is_deleted=False)
        else:
            print(f"[DEBUG] mark_messages_as_read: Fetching direct message {chat_id}")
            direct_message = DirectMessage.objects.get(id=chat_id, is_active=True)
            if not direct_message.participants.filter(id=user.id).exists():
                raise ValidationError("User is not a participant in this conversation")
            print(f"[DEBUG] mark_messages_as_read: Found direct message, fetching messages")
            messages = Message.objects.filter(direct_message=direct_message, is_deleted=False)

        # Update existing read receipts and create new ones
        print(f"[DEBUG] mark_messages_as_read: Finding unread messages")
        now = timezone.now()
        MessageRead.objects.filter(
            message__in=messages,
            user=user,
            read_at__isnull=True
        ).update(read_at=now)
        
        # Create read receipts for messages without them
        unread_messages = messages.exclude(read_receipts__user=user)
        print(f"[DEBUG] mark_messages_as_read: Found {unread_messages.count()} unread messages")
        
        read_receipts = [
            MessageRead(message=msg, user=user, read_at=now)
            for msg in unread_messages
        ]
        print(f"[DEBUG] mark_messages_as_read: Creating {len(read_receipts)} read receipts")
        MessageRead.objects.bulk_create(read_receipts, ignore_conflicts=True)
        print("[DEBUG] mark_messages_as_read: Completed creating read receipts")

    except (ChatGroup.DoesNotExist, DirectMessage.DoesNotExist) as e:
        print(f"[DEBUG] mark_messages_as_read: Error finding chat: {str(e)}")
        raise ValidationError(f"Chat not found: {str(e)}")

def get_unread_counts(user):
    """
    Get unread message counts for all user's chats
    Args:
        user: User to get counts for
    Returns:
        Dict with chat_id: unread_count mapping
    """
    print(f"[DEBUG] get_unread_counts: Starting count for user {user}")
    
    # Get unread counts for groups
    print("[DEBUG] get_unread_counts: Fetching group chat counts")
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
    print(f"[DEBUG] get_unread_counts: Found {len(group_counts)} group chats")

    # Get unread counts for direct messages
    print("[DEBUG] get_unread_counts: Fetching direct message counts")
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
    print(f"[DEBUG] get_unread_counts: Found {len(dm_counts)} direct messages")

    # Combine into single dictionary
    unread_counts = {
        chat['id']: chat['unread'] 
        for chat in list(group_counts) + list(dm_counts)
    }
    print(f"[DEBUG] get_unread_counts: Returning counts for {len(unread_counts)} total chats")
    
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
    print(f"[DEBUG] create_group: Creating new group '{name}' by user {created_by}")
    
    # Validate creator permissions
    if not created_by.groups.filter(name__in=['Admin', 'Manager']).exists():
        raise ValidationError("Only managers and administrators can create chat groups")
        
    group = ChatGroup.objects.create(
        name=name,
        description=description,
        created_by=created_by,
        is_active=True
    )
    print(f"[DEBUG] create_group: Created group with ID {group.id}")

    # Add creator as admin member
    print(f"[DEBUG] create_group: Adding creator as admin member")
    GroupMember.objects.create(
        group=group,
        user=created_by,
        role='admin',
        is_active=True
    )
    print(f"[DEBUG] create_group: Successfully created group and added admin")

    return group
