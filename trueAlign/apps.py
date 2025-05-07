from django.apps import AppConfig


class TruealignConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'

    name = 'trueAlign'
    def ready(self):
        import trueAlign.signals  
        # Replace 'aps' with your app name


    