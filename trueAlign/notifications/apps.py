"""
Notification App Configuration
Django app configuration for the real-time notification system
"""

from django.apps import AppConfig


class NotificationsConfig(AppConfig):
    """
    Configuration class for the Notifications application.

    This app provides a comprehensive real-time notification system with:
    - Database-driven notification storage
    - Celery-based asynchronous processing
    - Long-polling for pseudo real-time updates
    - Email notifications
    - Browser notifications
    - Flexible event system
    """

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'trueAlign.notifications'
    verbose_name = 'Real-Time Notification System'

    def ready(self):
        """
        Called when the app is ready.
        Import signal handlers here to ensure they are registered.
        """
        try:
            # Import signals to register them
            from . import signals
        except ImportError:
            # Signals module doesn't exist yet, that's okay
            pass
