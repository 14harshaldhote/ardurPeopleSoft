"""
Celery Configuration for ArdurTrueAlign
"""

import os
from celery import Celery
from django.conf import settings

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')

app = Celery('ardurTrueAlign')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
# - namespace='CELERY' means all celery-related configuration keys
#   should have a `CELERY_` prefix.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django apps.
app.autodiscover_tasks()

# Optional configuration, see the application user guide.
app.conf.update(
    task_serializer='json',
    accept_content=['json'],
    result_serializer='json',
    timezone=settings.TIME_ZONE,
    enable_utc=True,
    task_track_started=True,
    task_time_limit=30 * 60,  # 30 minutes
    task_soft_time_limit=25 * 60,  # 25 minutes
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    # Beat schedule for periodic tasks
    beat_schedule={
        'cleanup-old-notifications': {
            'task': 'trueAlign.notifications.tasks.cleanup_old_notifications',
            'schedule': 24 * 60 * 60,  # Run daily
        },
    },
)


@app.task(bind=True)
def debug_task(self):
    print(f'Request: {self.request!r}')
