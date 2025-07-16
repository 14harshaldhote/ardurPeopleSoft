"""
Django app configuration for trueAlign.core
Handles signal registration and app initialization
"""

from django.apps import AppConfig
from django.db.models.signals import post_migrate
import logging

logger = logging.getLogger(__name__)


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'trueAlign.core'
    verbose_name = 'True Align Core'

    def ready(self):
        """
        Initialize the app and register signals
        """
        try:
            # Import and register signals
            from . import signals

            # The signals are automatically registered when the module is imported
            # due to the @receiver decorators

            logger.info("Core app signals registered successfully")

        except Exception as e:
            logger.error(f"Error registering core app signals: {str(e)}")

        # Register post_migrate signal for setup tasks
        post_migrate.connect(self.setup_periodic_tasks, sender=self)

    def setup_periodic_tasks(self, sender, **kwargs):
        """
        Set up periodic maintenance tasks after migration
        """
        try:
            from .signals import setup_django_native_scheduler
            setup_django_native_scheduler()
            logger.info("Periodic maintenance tasks set up successfully")
        except Exception as e:
            logger.error(f"Error setting up periodic tasks: {str(e)}")
