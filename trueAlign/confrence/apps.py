"""
Conference Room Module App Configuration
"""

from django.apps import AppConfig


class ConferenceConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'trueAlign.confrence'
    verbose_name = 'Conference Room Management'
    
    def ready(self):
        """Import signals when app is ready."""
        import trueAlign.confrence.signals  # noqa
