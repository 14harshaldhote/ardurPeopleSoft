# attendance/management/commands/auto_mark_attendance.py
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import datetime, date, timedelta
import pytz
import logging

from ...services import AttendanceAutoMarkingService, get_attendance_services

logger = logging.getLogger(__name__)
User = get_user_model()


class Command(BaseCommand):
    help = 'Automatically mark attendance for all users based on sessions, shifts, and leave data'

    def add_arguments(self, parser):
        parser.add_argument(
            '--date',
            type=str,
            help='Date to process in YYYY-MM-DD format. Defaults to today.',
        )

        parser.add_argument(
            '--days-back',
            type=int,
            default=0,
            help='Number of days back from today to process. Default is 0 (today only).',
        )

        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Run in dry-run mode without making any changes.',
        )

        parser.add_argument(
            '--force',
            action='store_true',
            help='Force processing even if records already exist.',
        )

        parser.add_argument(
            '--users',
            type=str,
            nargs='+',
            help='Specific usernames to process. If not provided, all active users will be processed.',
        )

    def handle(self, *args, **options):
        try:
            # Initialize timezone
            IST = pytz.timezone('Asia/Kolkata')

            # Determine date(s) to process
            if options['date']:
                try:
                    target_date = datetime.strptime(options['date'], '%Y-%m-%d').date()
                except ValueError:
                    raise CommandError('Invalid date format. Use YYYY-MM-DD.')
            else:
                target_date = timezone.now().astimezone(IST).date()

            # Calculate date range if days_back is specified
            dates_to_process = []
            if options['days_back'] > 0:
                for i in range(options['days_back'] + 1):
                    process_date = target_date - timedelta(days=i)
                    dates_to_process.append(process_date)
            else:
                dates_to_process = [target_date]

            # Initialize services
            auto_marking_service = AttendanceAutoMarkingService()

            # Filter users if specified
            target_users = None
            if options['users']:
                target_users = User.objects.filter(
                    username__in=options['users'],
                    is_active=True
                )
                if not target_users.exists():
                    raise CommandError('No active users found with the specified usernames.')

                self.stdout.write(
                    self.style.SUCCESS(
                        f'Processing {target_users.count()} specific users: {", ".join(options["users"])}'
                    )
                )

            total_results = {
                'dates_processed': 0,
                'total_created': 0,
                'total_updated': 0,
                'total_processed': 0,
                'total_calculated': 0,
                'errors': []
            }

            # Process each date
            for process_date in sorted(dates_to_process):
                self.stdout.write(f'\nProcessing attendance for {process_date}...')

                if options['dry_run']:
                    self.stdout.write(
                        self.style.WARNING('DRY RUN MODE - No changes will be made')
                    )
                    continue

                try:
                    # Run auto marking for the date
                    result = auto_marking_service.run_auto_marking(process_date)

                    if result['success']:
                        total_results['dates_processed'] += 1
                        total_results['total_created'] += result.get('created', 0)
                        total_results['total_updated'] += result.get('updated', 0)
                        total_results['total_processed'] += result.get('processed', 0)
                        total_results['total_calculated'] += result.get('calculated', 0)

                        self.stdout.write(
                            self.style.SUCCESS(
                                f'✓ {process_date}: Created: {result.get("created", 0)}, '
                                f'Updated: {result.get("updated", 0)}, '
                                f'Processed: {result.get("processed", 0)}, '
                                f'Calculated: {result.get("calculated", 0)}'
                            )
                        )
                    else:
                        error_msg = f'Failed to process {process_date}: {result.get("error", "Unknown error")}'
                        total_results['errors'].append(error_msg)
                        self.stdout.write(self.style.ERROR(f'✗ {error_msg}'))

                except Exception as e:
                    error_msg = f'Exception processing {process_date}: {str(e)}'
                    total_results['errors'].append(error_msg)
                    self.stdout.write(self.style.ERROR(f'✗ {error_msg}'))
                    logger.error(error_msg, exc_info=True)

            # Print summary
            self.print_summary(total_results, options['dry_run'])

            # Exit with error code if there were errors
            if total_results['errors']:
                raise CommandError(f'Command completed with {len(total_results["errors"])} errors.')

            self.stdout.write(
                self.style.SUCCESS('Auto attendance marking completed successfully!')
            )

        except KeyboardInterrupt:
            self.stdout.write(self.style.ERROR('\nOperation cancelled by user.'))
            raise CommandError('Operation cancelled.')

        except Exception as e:
            logger.error(f'Unexpected error in auto_mark_attendance command: {e}', exc_info=True)
            raise CommandError(f'Unexpected error: {str(e)}')

    def print_summary(self, results, dry_run=False):
        """Print a summary of the processing results"""
        self.stdout.write('\n' + '='*60)
        self.stdout.write(self.style.SUCCESS('SUMMARY'))
        self.stdout.write('='*60)

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No actual changes were made'))
        else:
            self.stdout.write(f'Dates processed: {results["dates_processed"]}')
            self.stdout.write(f'Total attendance records created: {results["total_created"]}')
            self.stdout.write(f'Total attendance records updated: {results["total_updated"]}')
            self.stdout.write(f'Total "Yet to Clock In" processed: {results["total_processed"]}')
            self.stdout.write(f'Total statuses recalculated: {results["total_calculated"]}')

        if results['errors']:
            self.stdout.write(f'\nErrors encountered: {len(results["errors"])}')
            for error in results['errors']:
                self.stdout.write(self.style.ERROR(f'  - {error}'))
        else:
            self.stdout.write(self.style.SUCCESS('\nNo errors encountered.'))

        self.stdout.write('='*60)

    def validate_date_range(self, start_date, end_date):
        """Validate that the date range is reasonable"""
        if start_date > end_date:
            raise CommandError('Start date cannot be after end date.')

        # Don't allow processing more than 30 days at once
        if (end_date - start_date).days > 30:
            raise CommandError('Cannot process more than 30 days at once.')

        # Don't allow processing future dates
        today = timezone.now().date()
        if end_date > today:
            raise CommandError('Cannot process future dates.')

    def get_attendance_stats(self, date):
        """Get attendance statistics for a given date"""
        try:
            from ...models import Attendance

            stats = Attendance.objects.get_attendance_summary(date)
            return stats
        except Exception as e:
            logger.error(f'Error getting attendance stats for {date}: {e}')
            return {}
