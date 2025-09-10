# attendance/management/commands/run_attendance_auto_marking.py
import logging
from datetime import datetime, date, timedelta
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.conf import settings
import pytz
import time

from trueAlign.attendance.services import AttendanceAutoMarkingService
from trueAlign.attendance.notifications import notification_service
from trueAlign.models import UserSession

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = 'Run attendance auto-marking process for a specific date or today'

    def add_arguments(self, parser):
        parser.add_argument(
            '--date',
            type=str,
            help='Date in YYYY-MM-DD format (default: today)',
        )
        parser.add_argument(
            '--days-back',
            type=int,
            help='Number of days back from today to process (processes multiple days)',
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Run in dry-run mode without making actual changes',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force processing even if already processed',
        )
        parser.add_argument(
            '--send-notifications',
            action='store_true',
            help='Send notifications after processing',
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output',
        )
        parser.add_argument(
            '--real-time',
            action='store_true',
            help='Enable real-time continuous attendance updates',
        )
        parser.add_argument(
            '--interval',
            type=int,
            default=300,
            help='Update interval in seconds for real-time mode (default: 300)',
        )

    def handle(self, *args, **options):
        """Enhanced command handler with real-time support"""
        self.setup_logging(options['verbose'])

        try:
            # Check for real-time mode
            if options['real_time']:
                return self.run_real_time_mode(options)

            # Determine dates to process
            dates_to_process = self.get_dates_to_process(options)

            if not dates_to_process:
                raise CommandError("No dates to process")

            self.stdout.write(
                self.style.SUCCESS(f"Processing attendance auto-marking for {len(dates_to_process)} date(s)")
            )

            # Initialize service
            auto_marking_service = AttendanceAutoMarkingService()
            total_results = {
                'created': 0,
                'updated': 0,
                'processed': 0,
                'absent': 0,
                'errors': 0
            }

            # Process each date
            for target_date in dates_to_process:
                try:
                    self.stdout.write(f"\nProcessing date: {target_date}")

                    if options['dry_run']:
                        self.stdout.write(self.style.WARNING("DRY RUN MODE - No changes will be made"))
                        result = self.simulate_auto_marking(target_date)
                    else:
                        result = auto_marking_service.run_auto_marking(target_date)

                        # Process real-time updates for today
                        if target_date == timezone.now().date():
                            self.process_real_time_updates(auto_marking_service)

                    # Accumulate results
                    for key in total_results:
                        if key in result:
                            total_results[key] += result[key]

                    # Display results for this date
                    self.display_date_results(target_date, result)

                    # Send notifications if requested
                    if options['send_notifications'] and not options['dry_run']:
                        self.send_processing_notifications(target_date, result)

                except Exception as e:
                    total_results['errors'] += 1
                    self.stdout.write(
                        self.style.ERROR(f"Error processing {target_date}: {str(e)}")
                    )
                    logger.error(f"Auto-marking error for {target_date}: {e}")

            # Display final summary
            self.display_final_summary(total_results, len(dates_to_process))

            # Success message
            if total_results['errors'] == 0:
                self.stdout.write(
                    self.style.SUCCESS(f"✅ Successfully completed attendance auto-marking for all dates")
                )
            else:
                self.stdout.write(
                    self.style.WARNING(f"⚠️ Completed with {total_results['errors']} errors")
                )

        except Exception as e:
            logger.error(f"Command execution error: {e}")
            raise CommandError(f"Failed to run attendance auto-marking: {str(e)}")

    def run_real_time_mode(self, options):
        """Run in real-time continuous update mode"""
        interval = options['interval']

        self.stdout.write(
            self.style.SUCCESS(f"🔄 Starting real-time attendance monitoring (update every {interval}s)")
        )

        auto_marking_service = AttendanceAutoMarkingService()

        try:
            while True:
                self.stdout.write(f"\n⏰ Running real-time update at {timezone.now().strftime('%H:%M:%S')}")

                # Process today's attendance
                today = timezone.now().date()
                result = auto_marking_service.run_auto_marking(today)

                # Process active sessions
                active_sessions_count = self.process_active_sessions(auto_marking_service)

                self.stdout.write(f"  📊 Updated {result.get('updated', 0)} records, {active_sessions_count} active sessions")

                # Wait for next interval
                time.sleep(interval)

        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("\n⏹️ Real-time monitoring stopped by user"))
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"\n❌ Real-time monitoring error: {str(e)}"))
            logger.error(f"Real-time monitoring error: {e}")

    def process_active_sessions(self, auto_marking_service):
        """Process currently active sessions for real-time updates"""
        try:
            today = timezone.now().date()
            active_sessions = UserSession.objects.filter(
                is_active=True,
                login_time__date=today
            ).select_related('user')

            updated_count = 0
            for session in active_sessions:
                try:
                    from trueAlign.models import Attendance

                    # Get or create today's attendance
                    attendance, created = Attendance.objects.get_or_create(
                        user=session.user,
                        date=today,
                        defaults={
                            'status': 'Present',
                            'regularization_reason': 'Auto-created from active session'
                        }
                    )

                    # Update with session data
                    if auto_marking_service._update_attendance_with_sessions(attendance, [session]):
                        updated_count += 1

                except Exception as e:
                    logger.error(f"Error processing active session for {session.user.username}: {e}")

            return updated_count

        except Exception as e:
            logger.error(f"Error processing active sessions: {e}")
            return 0

    def process_real_time_updates(self, auto_marking_service):
        """Process real-time updates for current day"""
        try:
            # Update attendance based on current active sessions
            active_count = self.process_active_sessions(auto_marking_service)

            if active_count > 0:
                self.stdout.write(f"  🔄 Real-time: Updated {active_count} active session records")

        except Exception as e:
            logger.error(f"Real-time update error: {e}")

    def get_dates_to_process(self, options):
        """Determine which dates to process based on options"""
        IST = pytz.timezone('Asia/Kolkata')
        today = timezone.now().astimezone(IST).date()
        dates = []

        if options['date']:
            # Process specific date
            try:
                target_date = datetime.strptime(options['date'], '%Y-%m-%d').date()
                dates.append(target_date)
            except ValueError:
                raise CommandError(f"Invalid date format: {options['date']}. Use YYYY-MM-DD")

        elif options['days_back']:
            # Process multiple days back
            days_back = options['days_back']
            if days_back < 1:
                raise CommandError("days-back must be a positive integer")

            for i in range(days_back):
                target_date = today - timedelta(days=i)
                dates.append(target_date)

        else:
            # Default to today
            dates.append(today)

        return sorted(dates)

    def simulate_auto_marking(self, target_date):
        """Simulate auto-marking process for dry-run mode"""
        from trueAlign.models import Attendance
        from django.contrib.auth import get_user_model

        User = get_user_model()

        # Count existing records
        existing_count = Attendance.objects.filter(date=target_date).count()
        total_users = User.objects.filter(is_active=True).count()

        # Simulate results
        return {
            'created': max(0, total_users - existing_count),
            'updated': existing_count // 3,  # Estimate
            'processed': existing_count // 4,  # Estimate
            'absent': existing_count // 10,  # Estimate
            'total': total_users
        }

    def display_date_results(self, target_date, result):
        """Display results for a single date"""
        self.stdout.write(f"  📊 Results for {target_date}:")
        self.stdout.write(f"    • Created: {result.get('created', 0)} new records")
        self.stdout.write(f"    • Updated: {result.get('updated', 0)} existing records")
        self.stdout.write(f"    • Processed: {result.get('processed', 0)} status changes")
        self.stdout.write(f"    • Marked Absent: {result.get('absent', 0)} users")
        self.stdout.write(f"    • Total Affected: {result.get('total', 0)} records")

    def display_final_summary(self, total_results, date_count):
        """Display final summary of all processing"""
        self.stdout.write(f"\n{'='*50}")
        self.stdout.write(self.style.SUCCESS("📋 FINAL SUMMARY"))
        self.stdout.write(f"{'='*50}")
        self.stdout.write(f"Dates Processed: {date_count}")
        self.stdout.write(f"Total Created: {total_results['created']}")
        self.stdout.write(f"Total Updated: {total_results['updated']}")
        self.stdout.write(f"Total Processed: {total_results['processed']}")
        self.stdout.write(f"Total Marked Absent: {total_results['absent']}")
        self.stdout.write(f"Total Errors: {total_results['errors']}")

        total_affected = (
            total_results['created'] +
            total_results['updated'] +
            total_results['processed'] +
            total_results['absent']
        )
        self.stdout.write(f"Total Records Affected: {total_affected}")
        self.stdout.write(f"{'='*50}")

    def send_processing_notifications(self, target_date, result):
        """Send notifications about processing results"""
        try:
            # Send summary to HR users
            summary_data = {
                'date': target_date,
                'created': result.get('created', 0),
                'updated': result.get('updated', 0),
                'processed': result.get('processed', 0),
                'absent': result.get('absent', 0),
                'total': result.get('total', 0)
            }

            notification_service.notify_bulk_operation(
                'Automatic Attendance Processing',
                result.get('total', 0),
                None  # System operation
            )

            self.stdout.write("  📧 Notifications sent")

        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f"  ⚠️ Failed to send notifications: {str(e)}")
            )

    def setup_logging(self, verbose=False):
        """Setup logging configuration"""
        if verbose:
            logging.getLogger('trueAlign.attendance').setLevel(logging.DEBUG)
        else:
            logging.getLogger('trueAlign.attendance').setLevel(logging.INFO)

    def validate_options(self, options):
        """Validate command options"""
        if options['date'] and options['days_back']:
            raise CommandError("Cannot specify both --date and --days-back options")

        return True


# Example usage in comments:
# python manage.py run_attendance_auto_marking
# python manage.py run_attendance_auto_marking --date 2024-01-15
# python manage.py run_attendance_auto_marking --days-back 7
# python manage.py run_attendance_auto_marking --dry-run --verbose
# python manage.py run_attendance_auto_marking --force --send-notifications
# python manage.py run_attendance_auto_marking --real-time --interval 180
# python manage.py run_attendance_auto_marking --real-time --verbose
