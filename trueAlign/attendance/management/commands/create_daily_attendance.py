from django.core.management.base import BaseCommand
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import datetime, timedelta
import pytz
import logging
from ...services import AttendanceIntegrationService
logger = logging.getLogger('cron')

User = get_user_model()


class Command(BaseCommand):
    help = 'Create daily attendance records for all active users'

    def add_arguments(self, parser):
        parser.add_argument(
            '--date',
            type=str,
            help='Date to create records for (YYYY-MM-DD). Defaults to today.',
        )

    def handle(self, *args, **options):
        IST = pytz.timezone('Asia/Kolkata')

        if options['date']:
            try:
                target_date = datetime.strptime(options['date'], '%Y-%m-%d').date()
            except ValueError:
                self.stdout.write(
                    self.style.ERROR('Invalid date format. Use YYYY-MM-DD.')
                )
                return
        else:
            target_date = timezone.now().astimezone(IST).date()

        self.stdout.write(f'Creating daily attendance records for {target_date}...')

        service = AttendanceIntegrationService()
        created_count = service.create_daily_attendance_records(target_date)

        self.stdout.write(
            self.style.SUCCESS(
                f'Successfully created {created_count} attendance records for {target_date}'
            )
        )
