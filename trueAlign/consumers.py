# trueAlign/consumers.py
import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import Chat, Message
from django.contrib.auth.models import User

class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.chat_id = self.scope['url_route']['kwargs']['chat_id']
        self.room_group_name = f'chat_{self.chat_id}'
        print(f'User {self.scope["user"].id} connected to chat {self.chat_id}')

        # Join room group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        print(f'User {self.scope["user"].id} disconnected from chat {self.chat_id}')
        # Leave room group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        print(f'Received WebSocket message: {text_data}')
        text_data_json = json.loads(text_data)
        message = text_data_json['message']
        user_id = self.scope["user"].id

        # Save message to database
        print(f'Saving message to database: User {user_id}, Message: {message}')
        await self.save_message(user_id, message)

        # Send message to room group
        print(f'Sending message to room group: {self.room_group_name}')
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': message,
                'user_id': user_id,
                'username': self.scope["user"].username
            }
        )

    async def chat_message(self, event):
        print(f'Sending chat message to WebSocket: {event}')
        await self.send(text_data=json.dumps({
            'message': event['message'],
            'user_id': event['user_id'],
            'username': event['username']
        }))

    @database_sync_to_async
    def save_message(self, user_id, message):
        print(f'Attempting to save message: {message}')
        try:
            user = User.objects.get(id=user_id)
            chat = Chat.objects.get(id=self.chat_id)
            Message.objects.create(
                chat=chat,
                sender=user,
                content=message
            )
            print(f'Message saved successfully: {message}')
        except Exception as e:
            print(f'Error saving message: {e}')

