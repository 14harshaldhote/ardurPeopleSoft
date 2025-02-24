import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from .models import Message, ChatGroup, GroupMember, DirectMessage, MessageRead

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        print("[DEBUG] ChatConsumer: Starting connect")
        # Get chat_id and chat_type from URL pattern
        self.chat_id = self.scope['url_route']['kwargs']['chat_id']
        self.chat_type = self.scope['url_route']['kwargs'].get('chat_type', 'group')
        self.room_group_name = f'chat_{self.chat_id}'
        self.user = self.scope['user']
        print(f"[DEBUG] ChatConsumer: Connecting user {self.user} to {self.chat_type} chat {self.chat_id}")

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        print(f"[DEBUG] ChatConsumer: Added to group {self.room_group_name}")

        await self.accept()
        print("[DEBUG] ChatConsumer: Connection accepted")

    async def disconnect(self, close_code):
        print(f"[DEBUG] ChatConsumer: Disconnecting with code {close_code}")
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
        print(f"[DEBUG] ChatConsumer: Left group {self.room_group_name}")

    async def receive(self, text_data):
        print(f"[DEBUG] ChatConsumer: Received message: {text_data}")
        data = json.loads(text_data)
        message_type = data['type']
        content = data['message']
        
        if message_type == 'chat_message':
            print(f"[DEBUG] ChatConsumer: Processing chat message: {content}")
            # Save message to database
            message = await self.save_message(content)
            print(f"[DEBUG] ChatConsumer: Saved message with ID {message.id}")
            
            # Send message to room group
            await self.channel_layer.group_send(
                self.room_group_name,
                {
                    'type': 'chat_message',
                    'message': content,
                    'sender': self.user.username,
                    'timestamp': str(message.sent_at),
                    'message_type': message.message_type,
                    'file_url': message.file_attachment.url if message.file_attachment else None,
                    'edited': bool(message.edited_at),
                    'is_deleted': message.is_deleted
                }
            )
            print(f"[DEBUG] ChatConsumer: Sent message to group {self.room_group_name}")

    async def chat_message(self, event):
        print(f"[DEBUG] ChatConsumer: Broadcasting message: {event}")
        # Send message to WebSocket
        await self.send(text_data=json.dumps({
            'type': 'chat_message',
            'message': event['message'],
            'sender': event['sender'],
            'timestamp': event['timestamp'],
            'message_type': event['message_type'],
            'file_url': event['file_url'],
            'edited': event['edited'],
            'is_deleted': event['is_deleted']
        }))
        print("[DEBUG] ChatConsumer: Message broadcast complete")

    @database_sync_to_async
    def save_message(self, content):
        print(f"[DEBUG] ChatConsumer: Saving message: {content}")
        # Determine if this is a group or direct message based on chat_type
        if self.chat_type == 'group':
            print(f"[DEBUG] ChatConsumer: Saving group message for chat {self.chat_id}")
            group = ChatGroup.objects.get(id=self.chat_id)
            message = Message.objects.create(
                group=group,
                sender=self.user,
                content=content,
                message_type='text'
            )
            # Create read receipts for all group members
            for member in GroupMember.objects.filter(group=group, is_active=True):
                MessageRead.objects.create(message=message, user=member.user)
                
        else:
            print(f"[DEBUG] ChatConsumer: Saving direct message for chat {self.chat_id}")
            direct_message = DirectMessage.objects.get(id=self.chat_id)
            message = Message.objects.create(
                direct_message=direct_message,
                sender=self.user,
                content=content,
                message_type='text'
            )
            # Create read receipts for both participants
            for participant in direct_message.participants.all():
                MessageRead.objects.create(message=message, user=participant)
                
        print(f"[DEBUG] ChatConsumer: Message saved successfully with ID {message.id}")
        return message

class TypingIndicatorConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        print("[DEBUG] TypingIndicatorConsumer: Starting connect")
        self.chat_id = self.scope['url_route']['kwargs']['chat_id']
        self.chat_type = self.scope['url_route']['kwargs'].get('chat_type', 'group')
        self.room_group_name = f'typing_{self.chat_id}'
        self.user = self.scope['user']
        print(f"[DEBUG] TypingIndicatorConsumer: User {self.user} connecting to {self.chat_type} chat {self.chat_id}")

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        print(f"[DEBUG] TypingIndicatorConsumer: Added to group {self.room_group_name}")
        await self.accept()
        print("[DEBUG] TypingIndicatorConsumer: Connection accepted")

    async def disconnect(self, close_code):
        print(f"[DEBUG] TypingIndicatorConsumer: Disconnecting with code {close_code}")
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )
        print(f"[DEBUG] TypingIndicatorConsumer: Left group {self.room_group_name}")

    async def receive(self, text_data):
        print(f"[DEBUG] TypingIndicatorConsumer: Received data: {text_data}")
        data = json.loads(text_data)
        typing_status = data['typing']
        
        if typing_status:
            print(f"[DEBUG] TypingIndicatorConsumer: Updating typing status for {self.user}")
            await self.update_typing_status()
        else:
            print(f"[DEBUG] TypingIndicatorConsumer: Clearing typing status for {self.user}")
            await self.clear_typing_status()

        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'typing_status',
                'user': self.user.username,
                'typing': typing_status
            }
        )
        print(f"[DEBUG] TypingIndicatorConsumer: Sent typing status to group {self.room_group_name}")

    async def typing_status(self, event):
        print(f"[DEBUG] TypingIndicatorConsumer: Broadcasting typing status: {event}")
        await self.send(text_data=json.dumps({
            'user': event['user'],
            'typing': event['typing']
        }))
        print("[DEBUG] TypingIndicatorConsumer: Typing status broadcast complete")

    @database_sync_to_async
    def update_typing_status(self):
        print(f"[DEBUG] TypingIndicatorConsumer: Updating typing status in database for user {self.user}")
        if self.chat_type == 'group':
            member = GroupMember.objects.get(
                group_id=self.chat_id,
                user=self.user,
                is_active=True
            )
            member.mark_typing()
        print("[DEBUG] TypingIndicatorConsumer: Typing status updated")

    @database_sync_to_async
    def clear_typing_status(self):
        print(f"[DEBUG] TypingIndicatorConsumer: Clearing typing status in database for user {self.user}")
        if self.chat_type == 'group':
            member = GroupMember.objects.get(
                group_id=self.chat_id,
                user=self.user,
                is_active=True
            )
            member.clear_typing()
        print("[DEBUG] TypingIndicatorConsumer: Typing status cleared")

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        print("[DEBUG] NotificationConsumer: Starting connect")
        self.user = self.scope['user']
        await self.channel_layer.group_add(
            f'notifications_{self.user.id}',
            self.channel_name
        )
        print(f"[DEBUG] NotificationConsumer: Added user {self.user} to notifications group")
        await self.accept()
        print("[DEBUG] NotificationConsumer: Connection accepted")

    async def disconnect(self, close_code):
        print(f"[DEBUG] NotificationConsumer: Disconnecting with code {close_code}")
        await self.channel_layer.group_discard(
            f'notifications_{self.user.id}',
            self.channel_name
        )
        print(f"[DEBUG] NotificationConsumer: Removed user {self.user} from notifications group")

    async def notify(self, event):
        print(f"[DEBUG] NotificationConsumer: Sending notification: {event}")
        await self.send(text_data=json.dumps({
            'type': 'notification',
            'message': event['message'],
            'unread_count': event['unread_count']
        }))
        print("[DEBUG] NotificationConsumer: Notification sent")

    @database_sync_to_async
    def get_unread_count(self):
        print(f"[DEBUG] NotificationConsumer: Getting unread count for user {self.user}")
        # Get unread messages from both group and direct messages
        unread_count = MessageRead.objects.filter(
            user=self.user,
            read_at__isnull=True
        ).count()
        print(f"[DEBUG] NotificationConsumer: Unread count is {unread_count}")
        return unread_count
