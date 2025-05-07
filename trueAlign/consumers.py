import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.utils import timezone
from django.core.exceptions import ObjectDoesNotExist
from .models import Message, ChatGroup, GroupMember, DirectMessage, MessageRead

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            # Get chat_id and chat_type from URL pattern
            self.chat_id = self.scope['url_route']['kwargs']['chat_id']
            self.chat_type = self.scope['url_route']['kwargs'].get('chat_type', 'group')
            self.room_group_name = f'chat_{self.chat_id}'
            self.user = self.scope['user']

            # Validate chat exists and user has access
            if not await self.validate_chat_access():
                await self.close()
                return

            # Join room group
            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )

            await self.accept()

        except Exception as e:
            print(f"WebSocket connect error: {str(e)}")
            await self.close()

    async def disconnect(self, close_code):
        try:
            # Leave room group
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
        except Exception as e:
            print(f"WebSocket disconnect error: {str(e)}")

    async def receive(self, text_data):
        try:
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
        except Exception as e:
            print(f"WebSocket receive error: {str(e)}")
            await self.send(text_data=json.dumps({
                'error': 'Failed to process message'
            }))

    async def chat_message(self, event):
        try:
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
        except Exception as e:
            print(f"WebSocket chat_message error: {str(e)}")

    @database_sync_to_async
    def validate_chat_access(self):
        try:
            if self.chat_type == 'group':
                return GroupMember.objects.filter(
                    group_id=self.chat_id,
                    user=self.user,
                    is_active=True
                ).exists()
            else:
                return DirectMessage.objects.filter(
                    id=self.chat_id,
                    participants=self.user
                ).exists()
        except Exception:
            return False

    @database_sync_to_async
    def save_message(self, content):
        try:
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
        except Exception as e:
            print(f"Error saving message: {str(e)}")
            raise

class TypingIndicatorConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            self.chat_id = self.scope['url_route']['kwargs']['chat_id']
            self.chat_type = self.scope['url_route']['kwargs'].get('chat_type', 'group')
            self.room_group_name = f'typing_{self.chat_id}'
            self.user = self.scope['user']

            await self.channel_layer.group_add(
                self.room_group_name,
                self.channel_name
            )
            await self.accept()
        except Exception as e:
            print(f"Typing indicator connect error: {str(e)}")
            await self.close()

    async def disconnect(self, close_code):
        try:
            await self.channel_layer.group_discard(
                self.room_group_name,
                self.channel_name
            )
        except Exception as e:
            print(f"Typing indicator disconnect error: {str(e)}")

    async def receive(self, text_data):
        try:
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
        except Exception as e:
            print(f"Typing indicator receive error: {str(e)}")

    async def typing_status(self, event):
        try:
            await self.send(text_data=json.dumps({
                'user': event['user'],
                'typing': event['typing']
            }))
        except Exception as e:
            print(f"Typing status error: {str(e)}")

    @database_sync_to_async
    def update_typing_status(self):
        try:
            if self.chat_type == 'group':
                member = GroupMember.objects.get(
                    group_id=self.chat_id,
                    user=self.user,
                    is_active=True
                )
                member.mark_typing()
        except Exception as e:
            print(f"Update typing status error: {str(e)}")

    @database_sync_to_async
    def clear_typing_status(self):
        try:
            if self.chat_type == 'group':
                member = GroupMember.objects.get(
                    group_id=self.chat_id,
                    user=self.user,
                    is_active=True
                )
                member.clear_typing()
        except Exception as e:
            print(f"Clear typing status error: {str(e)}")

class NotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        try:
            self.user = self.scope['user']
            await self.channel_layer.group_add(
                f'notifications_{self.user.id}',
                self.channel_name
            )
            await self.accept()
        except Exception as e:
            print(f"Notification connect error: {str(e)}")
            await self.close()

    async def disconnect(self, close_code):
        try:
            await self.channel_layer.group_discard(
                f'notifications_{self.user.id}',
                self.channel_name
            )
        except Exception as e:
            print(f"Notification disconnect error: {str(e)}")

    async def notify(self, event):
        try:
            await self.send(text_data=json.dumps({
                'type': 'notification',
                'message': event['message'],
                'unread_count': event['unread_count']
            }))
        except Exception as e:
            print(f"Notification send error: {str(e)}")

    @database_sync_to_async
    def get_unread_count(self):
        try:
            # Get unread messages from both group and direct messages
            unread_count = MessageRead.objects.filter(
                user=self.user,
                read_at__isnull=True
            ).count()
            return unread_count
        except Exception as e:
            print(f"Get unread count error: {str(e)}")
            return 0
