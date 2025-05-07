# ardurTrueAlign/asgi.py

import os
from django.core.asgi import get_asgi_application
from channels.routing import ProtocolTypeRouter, URLRouter
from channels.auth import AuthMiddlewareStack
from trueAlign.routing import websocket_urlpatterns  # Import your app's routing

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')

application = ProtocolTypeRouter({
    "http": get_asgi_application(),
    "websocket": AuthMiddlewareStack(
        URLRouter(
            websocket_urlpatterns  # Use the URL patterns for websockets
        )
    ),
})
