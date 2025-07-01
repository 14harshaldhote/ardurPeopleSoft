# attendance/management/commands/process_yet_to_clock_in.py
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import transaction
from datetime import datetime, date, timedelta
import pytz
import logging

from trueAlign.models import Attendance, ShiftAssignment
from ...services import AttendanceAutoMarkingService

logger = logging.getLogger(__name__)
User = get_user_model()


class Command(BaseCommand):
    help = 'Process "Yet to Clock In" attendance records and mark them as "Absent" if shift has ended'

    def add_arguments(self, parser):
        parser.add_argument(
            '--date',
            type=str,
            help='Date to process in YYYY-MM-DD format. Defaults to today.',
        )

        parser.add_argument(
            '--all-dates',
            action='store_true',
            help='Process all dates with "Yet to Clock In" status.',
        )

        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Run in dry-run mode without making any changes.',
        )

        parser.add_argument(
            '--force',
            action='store_true',
            help='Force processing even for future dates.',
        )

        parser.add_argument(
            '--users',
            type=str,
            nargs='+',
            help='Specific usernames to process. If not provided, all users will be processed.',
        )

        parser.add_argument(
            '--grace-minutes',
            type=int,
            default=0,
            help='Additional grace period in minutes beyond shift end time.',
        )

    def handle(self, *args, **options):
        try:
            # Initialize timezone
            IST = pytz.timezone('Asia/Kolkata')
            current_time_ist = timezone.now().astimezone(IST)
            current_date = current_time_ist.date()
            current_time = current_time_ist.time()

            # Determine date(s) to process
            if options['all_dates']:
                # Process all dates with "Yet to Clock In" status
                target_dates = Attendance.objects.filter(
                    status='Yet to Clock In'
                ).values_list('date', flat=True).distinct().order_by('date')

                if not target_dates:
                    self.stdout.write(
                        self.style.SUCCESS('No "Yet to Clock In" records found.')
                    )
                    return

                target_dates = list(target_dates)
                self.stdout.write(
                    f'Found "Yet to Clock In" records for {len(target_dates)} dates: '
                    f'{", ".join(str(d) for d in target_dates)}'
                )

            elif options['date']:
                try:
                    target_date = datetime.strptime(options['date'], '%Y-%m-%d').date()
                    target_dates = [target_date]
                except ValueError:
                    raise CommandError('Invalid date format. Use YYYY-MM-DD.')
            else:
                target_dates = [current_date]

            # Validate dates
            if not options['force']:
                future_dates = [d for d in target_dates if d > current_date]
                if future_dates:
                    raise CommandError(
                        f'Cannot process future dates: {", ".join(str(d) for d in future_dates)}. '
                        f'Use --force to override.'
                    )

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
                    f'Processing specific users: {", ".join(options["users"])}'
                )

            # Initialize results tracking
            total_results = {
                'dates_processed': 0,
                'total_found': 0,
                'total_updated': 0,
                'total_skipped': 0,
                'errors': []
            }

            # Process each date
            for process_date in target_dates:
                self.stdout.write(f'\nProcessing "Yet to Clock In" records for {process_date}...')

                try:
                    result = self.process_date(
                        process_date,
                        current_time,
                        current_date,
                        target_users,
                        options
                    )

                    total_results['dates_processed'] += 1
                    total_results['total_found'] += result['found']
                    total_results['total_updated'] += result['updated']
                    total_results['total_skipped'] += result['skipped']

                    self.stdout.write(
                        self.style.SUCCESS(
                            f'✓ {process_date}: Found: {result["found"]}, '
                            f'Updated: {result["updated"]}, Skipped: {result["skipped"]}'
                        )
                    )

                except Exception as e:
                    error_msg = f'Error processing {process_date}: {str(e)}'
                    total_results['errors'].append(error_msg)
                    self.stdout.write(self.style.ERROR(f'✗ {error_msg}'))
                    logger.error(error_msg, exc_info=True)

            # Print summary
            self.print_summary(total_results, options['dry_run'])

            # Exit with error code if there were errors
            if total_results['errors']:
                raise CommandError(f'Command completed with {len(total_results["errors"])} errors.')

            self.stdout.write(
                self.style.SUCCESS('Processing "Yet to Clock In" records completed successfully!')
            )

        except KeyboardInterrupt:
            self.stdout.write(self.style.ERROR('\nOperation cancelled by user.'))
            raise CommandError('Operation cancelled.')

        except Exception as e:
            logger.error(f'Unexpected error in process_yet_to_clock_in command: {e}', exc_info=True)
            raise CommandError(f'Unexpected error: {str(e)}')

    def process_date(self, process_date, current_time, current_date, target_users, options):
        """Process 'Yet to Clock In' records for a specific date"""

        # Get 'Yet to Clock In' records for the date
        queryset = Attendance.objects.filter(
            date=process_date,
            status='Yet to Clock In'
        ).select_related('user', 'shift')

        if target_users:
            queryset = queryset.filter(user__in=target_users)

        yet_to_clock_in_records = list(queryset)

        result = {
            'found': len(yet_to_clock_in_records),
            'updated': 0,
            'skipped': 0
        }

        if not yet_to_clock_in_records:
            return result

        # Process each record
        with transaction.atomic():
            for attendance in yet_to_clock_in_records:
                try:
                    should_update = self.should_mark_absent(
                        attendance,
                        current_time,
                        current_date,
                        process_date,
                        options['grace_minutes']
                    )

                    if should_update:
                        if not options['dry_run']:
                            self.update_to_absent(attendance)

                        result['updated'] += 1

                        self.stdout.write(
                            f'  {"[DRY RUN] " if options["dry_run"] else ""}'
                            f'Updated {attendance.user.username} to Absent '
                            f'(shift ended at {attendance.shift.end_time if attendance.shift else "N/A"})'
                        )
                    else:
                        result['skipped'] += 1

                        reason = self.get_skip_reason(attendance, current_date, process_date)
                        self.stdout.write(
                            f'  Skipped {attendance.user.username}: {reason}'
                        )

                except Exception as e:
                    error_msg = f'Error processing {attendance.user.username} for {process_date}: {str(e)}'
                    logger.error(error_msg, exc_info=True)
                    # Continue processing other records
                    result['skipped'] += 1

        return result

    def should_mark_absent(self, attendance, current_time, current_date, process_date, grace_minutes):
        """Determine if attendance should be marked as absent"""

        # If no shift assigned, cannot determine if shift ended
        if not attendance.shift:
            return process_date < current_date  # Only mark past dates without shift

        # For past dates, always mark as absent
        if process_date < current_date:
            return True

        # For today, check if shift has ended
        if process_date == current_date:
            return self.is_shift_ended_with_grace(
                current_time,
                attendance.shift.start_time,
                attendance.shift.end_time,
                grace_minutes
            )

        # For future dates, don't mark as absent
        return False

    def is_shift_ended_with_grace(self, current_time, shift_start, shift_end, grace_minutes):
        """Check if shift has ended considering grace period"""

        current_minutes = current_time.hour * 60 + current_time.minute
        start_minutes = shift_start.hour * 60 + shift_start.minute
        end_minutes = shift_end.hour * 60 + shift_end.minute

        # Add grace period to shift end
        end_minutes += grace_minutes

        # Handle night shifts (crosses midnight)
        if end_minutes < start_minutes or end_minutes >= 24 * 60:
            end_minutes += 24 * 60
            if current_minutes < start_minutes:
                current_minutes += 24 * 60

        return current_minutes > end_minutes

    def update_to_absent(self, attendance):
        """Update attendance record to Absent status"""

        attendance.status = 'Absent'
        attendance.regularization_reason = (
            f"Auto-updated: Absent (shift ended, no activity) - "
            f"Processed at {timezone.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )
        attendance.save(update_fields=['status', 'regularization_reason', 'last_modified'])

    def get_skip_reason(self, attendance, current_date, process_date):
        """Get reason why attendance was skipped"""

        if not attendance.shift:
            if process_date >= current_date:
                return "No shift assigned, current/future date"
            else:
                return "No shift assigned (should have been processed)"

        if process_date > current_date:
            return "Future date"

        if process_date == current_date:
            return f"Shift not ended yet (ends at {attendance.shift.end_time})"

        return "Unknown reason"

    def print_summary(self, results, dry_run=False):
        """Print a summary of the processing results"""

        self.stdout.write('\n' + '='*60)
        self.stdout.write(self.style.SUCCESS('SUMMARY'))
        self.stdout.write('='*60)

        if dry_run:
            self.stdout.write(self.style.WARNING('DRY RUN MODE - No actual changes were made'))

        self.stdout.write(f'Dates processed: {results["dates_processed"]}')
        self.stdout.write(f'Total "Yet to Clock In" records found: {results["total_found"]}')
        self.stdout.write(f'Total records updated to "Absent": {results["total_updated"]}')
        self.stdout.write(f'Total records skipped: {results["total_skipped"]}')

        if results['errors']:
            self.stdout.write(f'\nErrors encountered: {len(results["errors"])}')
            for error in results['errors']:
                self.stdout.write(self.style.ERROR(f'  - {error}'))
        else:
            self.stdout.write(self.style.SUCCESS('\nNo errors encountered.'))

        # Calculate efficiency
        if results['total_found'] > 0:
            efficiency = (results['total_updated'] / results['total_found']) * 100
            self.stdout.write(f'Processing efficiency: {efficiency:.1f}%')

        self.stdout.write('='*60)

    def validate_grace_minutes(self, grace_minutes):
        """Validate grace period"""
        if grace_minutes < 0:
            raise CommandError('Grace period cannot be negative.')

        if grace_minutes > 240:  # 4 hours
            raise CommandError('Grace period cannot exceed 240 minutes (4 hours).')
