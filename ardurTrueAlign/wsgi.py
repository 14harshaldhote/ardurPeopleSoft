"""
WSGI config for ardurTrueAlign project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.1/howto/deployment/wsgi/
"""

# ardurTrueAlign/wsgi.py
import os
from django.core.wsgi import get_wsgi_application

# Set the Django settings module path
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')

# Create the WSGI application
application = get_wsgi_application()