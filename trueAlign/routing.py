from django.urls import re_path
from .consumers import ChatConsumer, TypingIndicatorConsumer

websocket_urlpatterns = [
    re_path(r'ws/chat/(?P<chat_id>\d+)/$', ChatConsumer.as_asgi()),
    re_path(r'ws/typing/(?P<chat_id>\d+)/$', TypingIndicatorConsumer.as_asgi()),
]
