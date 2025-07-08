from django.apps import AppConfig


class AttendanceConfig(AppConfig):
    name = 'trueAlign.attendance'
    verbose_name = 'Attendance Management'
    default_auto_field = 'django.db.models.BigAutoField'

    def ready(self):
        """
        Import signals when the app is ready
        """
        try:
            import trueAlign.attendance.signals  # noqa
        except ImportError:
            pass
