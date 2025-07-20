from django.apps import AppConfig


class SessionsConfig(AppConfig):
    """
    Sessions app configuration for TrueAlign.

    This app provides administrative views for UserSession and OfficeLocation data.
    Access is restricted to superusers and users in the "Admin" group.
    """
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'trueAlign.sessions'
    label = 'ta_sessions'
    verbose_name = 'Session Management'

    def ready(self):
        """
        Initialize the app when Django starts.
        """
        pass
