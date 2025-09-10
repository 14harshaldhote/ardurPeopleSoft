from django.apps import AppConfig


class NotesConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'trueAlign.notes'
    verbose_name = 'Global Updates'

    def ready(self):
        """
        Initialize the app when Django starts.
        This method is called once Django has loaded all models.
        """
        pass
