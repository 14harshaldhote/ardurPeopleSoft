import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from .models import Message, ChatGroup, GroupMember, DirectMessage, MessageRead

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Get chat_id and chat_type from URL pattern
        self.chat_id = self.scope['url_route']['kwargs']['chat_id']
        self.chat_type = self.scope['url_route']['kwargs'].get('chat_type', 'group')
        self.room_group_name = f'chat_{self.chat_id}'
        self.user = self.scope['user']

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        message_type = data['type']
        content = data['message']
        
        if message_type == 'chat_message':
            # Save message to database
            message = await self.save_message(content)
            
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

    async def chat_message(self, event):
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

    @database_sync_to_async
    def save_message(self, content):
        # Determine if this is a group or direct message based on chat_type
        if self.chat_type == 'group':
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
                
        return message

class TypingIndicatorConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.chat_id = self.scope['url_route']['kwargs']['chat_id']
        self.chat_type = self.scope['url_route']['kwargs'].get('chat_type', 'group')
        self.room_group_name = f'typing_{self.chat_id}'
        self.user = self.scope['user']

        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        typing_status = data['typing']
        
        if typing_status:
            await self.update_typing_status()
        else:
            await self.clear_typing_status()

        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'typing_status',
                'user': self.user.username,
                'typing': typing_status
            }
        )

    async def typing_status(self, event):
        await self.send(text_data=json.dumps({
            'user': event['user'],
            'typing': event['typing']
        }))

    @database_sync_to_async
    def update_typing_status(self):
        if self.chat_type == 'group':
            member = GroupMember.objects.get(
                group_id=self.chat_id,
                user=self.user,
                is_active=True
            )
            member.mark_typing()

    @database_sync_to_async
    def clear_typing_status(self):
        if self.chat_type == 'group':
            member = GroupMember.objects.get(
                group_id=self.chat_id,
                user=self.user,
                is_active=True
            )
            member.clear_typing()

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.user = self.scope['user']
        await self.channel_layer.group_add(
            f'notifications_{self.user.id}',
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            f'notifications_{self.user.id}',
            self.channel_name
        )

    async def notify(self, event):
        await self.send(text_data=json.dumps({
            'type': 'notification',
            'message': event['message'],
            'unread_count': event['unread_count']
        }))

    @database_sync_to_async
    def get_unread_count(self):
        # Get unread messages from both group and direct messages
        unread_count = MessageRead.objects.filter(
            user=self.user,
            read_at__isnull=True
        ).count()
        return unread_count
