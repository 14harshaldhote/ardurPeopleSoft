#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys


def main():
    """Run administrative tasks."""
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
    try:
        from django.core.management import execute_from_command_line
        # Patch for django-cron compatibility with Django 5.1
        from django.db.models import options
        if 'index_together' not in options.DEFAULT_NAMES:
            options.DEFAULT_NAMES = options.DEFAULT_NAMES + ('index_together',)
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()
