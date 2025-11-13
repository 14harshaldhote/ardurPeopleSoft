"""
Django App Configuration for Shift Management
"""

from django.apps import AppConfig


class ShiftConfig(AppConfig):
    """Configuration for shift management app"""
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'trueAlign.shift'
    verbose_name = 'Shift Management'
    
    def ready(self):
        """Initialize app when Django starts"""
        # Import signals if any
        # import shift.signals
        pass
