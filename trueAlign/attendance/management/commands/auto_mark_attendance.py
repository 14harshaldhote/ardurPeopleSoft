# attendance/management/commands/auto_mark_attendance.py
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.contrib.auth import get_user_model
from datetime import datetime, date, timedelta
import pytz
import logging

from trueAlign.attendance.services import AttendanceAutoMarkingService, get_attendance_services

logger = logging.getLogger('cron')
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

    # In ardurPeopleSoft/trueAlign/attendance/management/commands/auto_mark_attendance.py
    # Replace the handle method

    def handle(self, *args, **options):
        """Main command handler with reduced complexity"""
        try:
            config = self._parse_options(options)
            results = self._process_attendance_marking(config)
            self._handle_completion(results, options.get('dry_run', False))

        except KeyboardInterrupt:
            self._handle_cancellation()
        except Exception as e:
            self._handle_error(e)

    def _parse_options(self, options):
        """Parse and validate command options"""
        IST = pytz.timezone('Asia/Kolkata')

        target_date = self._parse_target_date(options.get('date'), IST)
        dates_to_process = self._calculate_date_range(target_date, options.get('days_back', 0))
        target_users = self._get_target_users(options.get('users'))

        return {
            'dates_to_process': dates_to_process,
            'target_users': target_users,
            'dry_run': options.get('dry_run', False),
            'force': options.get('force', False)
        }

    def _parse_target_date(self, date_str, IST):
        """Parse target date from string or use today"""
        if date_str:
            try:
                return datetime.strptime(date_str, '%Y-%m-%d').date()
            except ValueError:
                raise CommandError('Invalid date format. Use YYYY-MM-DD.')
        return timezone.now().astimezone(IST).date()

    def _calculate_date_range(self, target_date, days_back):
        """Calculate range of dates to process"""
        if days_back > 0:
            return [target_date - timedelta(days=i) for i in range(days_back + 1)]
        return [target_date]

    def _get_target_users(self, usernames):
        """Get target users if specified"""
        if usernames:
            users = User.objects.filter(username__in=usernames, is_active=True)
            if not users.exists():
                raise CommandError('No active users found with the specified usernames.')
            return users
        return None

    def _process_attendance_marking(self, config):
        """Process attendance marking for all dates"""
        auto_marking_service = AttendanceAutoMarkingService()
        results = self._initialize_results()

        for process_date in sorted(config['dates_to_process']):
            if config['dry_run']:
                self._handle_dry_run(process_date)
                continue

            result = self._process_single_date(auto_marking_service, process_date)
            self._update_results(results, result, process_date)

        return results

    def _initialize_results(self):
        """Initialize results tracking"""
        return {
            'dates_processed': 0,
            'total_created': 0,
            'total_updated': 0,
            'total_processed': 0,
            'total_calculated': 0,
            'errors': []
        }

    def _process_single_date(self, service, process_date):
        """Process attendance for a single date"""
        try:
            self.stdout.write(f'\nProcessing attendance for {process_date}...')
            return service.run_auto_marking(process_date)
        except Exception as e:
            error_msg = f'Exception processing {process_date}: {str(e)}'
            logger.error(error_msg, exc_info=True)
            return {'success': False, 'error': error_msg}

    def _update_results(self, results, result, process_date):
        """Update results with single date processing outcome"""
        if result['success']:
            results['dates_processed'] += 1
            results['total_created'] += result.get('created', 0)
            results['total_updated'] += result.get('updated', 0)
            results['total_processed'] += result.get('processed', 0)
            results['total_calculated'] += result.get('calculated', 0)

            self.stdout.write(self.style.SUCCESS(
                f'✓ {process_date}: Created: {result.get("created", 0)}, '
                f'Updated: {result.get("updated", 0)}, '
                f'Processed: {result.get("processed", 0)}, '
                f'Calculated: {result.get("calculated", 0)}'
            ))
        else:
            error_msg = f'Failed to process {process_date}: {result.get("error", "Unknown error")}'
            results['errors'].append(error_msg)
            self.stdout.write(self.style.ERROR(f'✗ {error_msg}'))

    def _handle_completion(self, results, dry_run):
        """Handle successful completion"""
        self.print_summary(results, dry_run)

        if results['errors']:
            raise CommandError(f'Command completed with {len(results["errors"])} errors.')

        self.stdout.write(self.style.SUCCESS('Auto attendance marking completed successfully!'))

    def _handle_cancellation(self):
        """Handle user cancellation"""
        self.stdout.write(self.style.ERROR('\nOperation cancelled by user.'))
        raise CommandError('Operation cancelled.')

    def _handle_error(self, error):
        """Handle unexpected errors"""
        logger.error(f'Unexpected error in auto_mark_attendance command: {error}', exc_info=True)
        raise CommandError(f'Unexpected error: {str(error)}')

    def _handle_dry_run(self, process_date):
        """Handle dry run mode"""
        self.stdout.write(f'\nProcessing attendance for {process_date}...')
        self.stdout.write(self.style.WARNING('DRY RUN MODE - No changes will be made'))

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

            stats = Attendance.objects.get_attendance_summary(date)
            return stats
        except Exception as e:
            logger.error(f'Error getting attendance stats for {date}: {e}')
            return {}
