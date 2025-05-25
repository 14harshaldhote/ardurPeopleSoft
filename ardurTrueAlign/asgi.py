# ardurTrueAlign/asgi.py

import os
from django.core.asgi import get_asgi_application

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')

# Simple ASGI application without WebSocket support
application = get_asgi_application()
