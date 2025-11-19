from django.apps import AppConfig


class FinanceConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'trueAlign.finance'
    verbose_name = 'Finance & Payroll Management'

    def ready(self):
        # Import signals if any
        pass
