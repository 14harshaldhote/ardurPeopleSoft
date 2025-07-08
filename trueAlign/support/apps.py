"""
Support App Configuration
Django app configuration for the support ticket system
"""

from django.apps import AppConfig


class SupportConfig(AppConfig):
    """
    Configuration class for the Support application.

    This app provides a comprehensive support ticket system with:
    - Ticket creation, management, and tracking
    - SLA monitoring and breach detection
    - Comment system with file attachments
    - User role-based permissions
    - Bulk operations on tickets
    - Email notifications
    - Dashboard and reporting
    - Advanced search and filtering
    """

    default_auto_field = 'django.db.models.BigAutoField'
    name = 'trueAlign.support'
    verbose_name = 'Support Ticket System'

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
