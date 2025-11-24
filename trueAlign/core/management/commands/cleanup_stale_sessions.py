from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from trueAlign.models import UserSession
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Cleans up stale user sessions that were not properly closed'

    def add_arguments(self, parser):
        parser.add_argument(
            '--hours',
            type=int,
            default=24,
            help='Number of hours of inactivity before a session is considered stale'
        )

    def handle(self, *args, **options):
        hours = options['hours']
        threshold = timezone.now() - timedelta(hours=hours)
        
        self.stdout.write(f"Cleaning up sessions inactive since {threshold}")
        
        stale_sessions = UserSession.objects.filter(
            is_active=True,
            last_activity__lt=threshold
        )
        
        count = stale_sessions.count()
        
        if count > 0:
            updated = stale_sessions.update(
                is_active=False,
                session_end_time=timezone.now(),
                ended_at=timezone.now(),
                end_reason='stale_cleanup_job'
            )
            msg = f"Successfully cleaned up {updated} stale sessions"
            self.stdout.write(self.style.SUCCESS(msg))
            logger.info(msg)
        else:
            self.stdout.write(self.style.SUCCESS("No stale sessions found"))
