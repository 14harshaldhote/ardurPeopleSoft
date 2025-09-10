# attendance/management/commands/manage_attendance_cron.py
"""
Management command for attendance cron job operations

This command provides a unified interface for managing all attendance-related
cron jobs including running them manually, checking status, viewing logs,
and performing maintenance operations.

Usage Examples:
    python manage.py manage_attendance_cron status
    python manage.py manage_attendance_cron run daily_creation
    python manage.py manage_attendance_cron run all
    python manage.py manage_attendance_cron logs --job auto_marking --days 7
    python manage.py manage_attendance_cron health_check
    python manage.py manage_attendance_cron emergency_fix --date 2024-01-15
"""

import json
import logging
from datetime import datetime, timedelta
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from django.core.management import call_command
from django.conf import settings
from django.db import connection
import pytz

# Import cron job classes
from trueAlign.attendance.cron import (
    DailyAttendanceCreationCronJob,
    AttendanceAutoMarkingCronJob,
    AttendanceNotificationCronJob,
    AttendanceCleanupCronJob,
    get_cron_job_status,
    run_emergency_attendance_fix
)

logger = logging.getLogger('cron')


class Command(BaseCommand):
    help = 'Manage attendance cron jobs - run, monitor, and maintain'

    def add_arguments(self, parser):
        """Add command arguments"""
        subparsers = parser.add_subparsers(dest='action', help='Available actions')

        # Status command
        status_parser = subparsers.add_parser('status', help='Show cron job status')
        status_parser.add_argument(
            '--json',
            action='store_true',
            help='Output in JSON format'
        )

        # Run command
        run_parser = subparsers.add_parser('run', help='Run specific cron job')
        run_parser.add_argument(
            'job',
            choices=['daily_creation', 'auto_marking', 'notifications', 'cleanup', 'all'],
            help='Job to run'
        )
        run_parser.add_argument(
            '--force',
            action='store_true',
            help='Force run even if recently executed'
        )

        # Logs command
        logs_parser = subparsers.add_parser('logs', help='View cron job logs')
        logs_parser.add_argument(
            '--job',
            choices=['daily_creation', 'auto_marking', 'notifications', 'cleanup'],
            help='Filter by specific job'
        )
        logs_parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Number of days to show (default: 7)'
        )
        logs_parser.add_argument(
            '--failures-only',
            action='store_true',
            help='Show only failed jobs'
        )

        # Health check command
        health_parser = subparsers.add_parser('health_check', help='Check cron job health')
        health_parser.add_argument(
            '--fix',
            action='store_true',
            help='Attempt to fix issues automatically'
        )

        # Emergency fix command
        emergency_parser = subparsers.add_parser('emergency_fix', help='Run emergency attendance fix')
        emergency_parser.add_argument(
            '--date',
            type=str,
            help='Date to fix (YYYY-MM-DD), defaults to today'
        )
        emergency_parser.add_argument(
            '--days-back',
            type=int,
            help='Number of days back to fix'
        )

        # Schedule command
        schedule_parser = subparsers.add_parser('schedule', help='Show cron job schedules')

        # Test command
        test_parser = subparsers.add_parser('test', help='Test cron job functionality')
        test_parser.add_argument(
            'job',
            choices=['daily_creation', 'auto_marking', 'notifications', 'cleanup'],
            help='Job to test'
        )

    def handle(self, *args, **options):
        """Main command handler"""
        action = options.get('action')

        if not action:
            self.print_help('manage.py', 'manage_attendance_cron')
            return

        try:
            if action == 'status':
                self.handle_status(options)
            elif action == 'run':
                self.handle_run(options)
            elif action == 'logs':
                self.handle_logs(options)
            elif action == 'health_check':
                self.handle_health_check(options)
            elif action == 'emergency_fix':
                self.handle_emergency_fix(options)
            elif action == 'schedule':
                self.handle_schedule(options)
            elif action == 'test':
                self.handle_test(options)
            else:
                raise CommandError(f"Unknown action: {action}")

        except Exception as e:
            logger.error(f"Command failed: {e}")
            raise CommandError(f"Failed to execute {action}: {str(e)}")

    def handle_status(self, options):
        """Handle status command"""
        self.stdout.write(self.style.SUCCESS("📊 Attendance Cron Job Status"))
        self.stdout.write("=" * 50)

        try:
            status = get_cron_job_status()

            if options.get('json'):
                self.stdout.write(json.dumps(status, indent=2, default=str))
                return

            if 'error' in status:
                self.stdout.write(self.style.ERROR(f"Error getting status: {status['error']}"))
                return

            # Overall statistics
            self.stdout.write(f"Total Runs (last 7 days): {status.get('total_runs', 0)}")
            self.stdout.write(f"Successful Runs: {status.get('successful_runs', 0)}")
            self.stdout.write(f"Failed Runs: {status.get('failed_runs', 0)}")

            if status.get('total_runs', 0) > 0:
                success_rate = (status.get('successful_runs', 0) / status.get('total_runs', 1)) * 100
                self.stdout.write(f"Success Rate: {success_rate:.1f}%")

            # Recent job runs
            self.stdout.write("\n📋 Recent Job Runs:")
            recent_logs = status.get('recent_logs', [])

            if not recent_logs:
                self.stdout.write("  No recent logs found")
            else:
                for log in recent_logs[:10]:  # Show last 10
                    status_icon = "✅" if log.get('is_success') else "❌"
                    job_code = log.get('code', 'unknown')
                    start_time = log.get('start_time', 'unknown')

                    self.stdout.write(f"  {status_icon} {job_code} - {start_time}")

                    if not log.get('is_success') and log.get('message'):
                        self.stdout.write(f"    Error: {log['message']}")

            # Job-specific status
            self._show_job_specific_status()

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to get status: {e}"))

    def handle_run(self, options):
        """Handle run command"""
        job = options.get('job')
        force = options.get('force', False)

        self.stdout.write(self.style.SUCCESS(f"🚀 Running attendance cron job: {job}"))

        job_mapping = {
            'daily_creation': DailyAttendanceCreationCronJob,
            'auto_marking': AttendanceAutoMarkingCronJob,
            'notifications': AttendanceNotificationCronJob,
            'cleanup': AttendanceCleanupCronJob,
        }

        if job == 'all':
            # Run all jobs in sequence
            for job_name, job_class in job_mapping.items():
                self.stdout.write(f"\n▶️ Running {job_name}...")
                try:
                    job_instance = job_class()
                    job_instance.do()
                    self.stdout.write(self.style.SUCCESS(f"✅ {job_name} completed"))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f"❌ {job_name} failed: {e}"))
        else:
            if job not in job_mapping:
                raise CommandError(f"Unknown job: {job}")

            try:
                job_class = job_mapping[job]
                job_instance = job_class()

                # Check if job was recently run (unless forced)
                if not force:
                    if self._was_recently_run(job):
                        self.stdout.write(
                            self.style.WARNING(f"⚠️ Job {job} was recently run. Use --force to override.")
                        )
                        return

                # Run the job
                start_time = timezone.now()
                job_instance.do()
                end_time = timezone.now()

                duration = (end_time - start_time).total_seconds()
                self.stdout.write(
                    self.style.SUCCESS(f"✅ Job {job} completed successfully in {duration:.2f} seconds")
                )

                # Show results if available
                if hasattr(job_instance, 'results') and job_instance.results:
                    self.stdout.write("\n📈 Results:")
                    for key, value in job_instance.results.items():
                        self.stdout.write(f"  {key}: {value}")

            except Exception as e:
                self.stdout.write(self.style.ERROR(f"❌ Job {job} failed: {e}"))
                raise

    def handle_logs(self, options):
        """Handle logs command"""
        job_filter = options.get('job')
        days = options.get('days', 7)
        failures_only = options.get('failures_only', False)

        self.stdout.write(self.style.SUCCESS(f"📜 Cron Job Logs (last {days} days)"))
        self.stdout.write("=" * 50)

        try:
            from django_cron.models import CronJobLog

            # Build query
            cutoff_date = timezone.now() - timedelta(days=days)
            logs = CronJobLog.objects.filter(start_time__gte=cutoff_date)

            if job_filter:
                job_code_mapping = {
                    'daily_creation': 'attendance.daily_creation',
                    'auto_marking': 'attendance.auto_marking',
                    'notifications': 'attendance.notifications',
                    'cleanup': 'attendance.cleanup',
                }
                logs = logs.filter(code=job_code_mapping.get(job_filter))

            if failures_only:
                logs = logs.filter(is_success=False)

            logs = logs.order_by('-start_time')[:50]

            if not logs.exists():
                self.stdout.write("No logs found matching criteria")
                return

            for log in logs:
                status_icon = "✅" if log.is_success else "❌"
                duration = ""
                if log.end_time and log.start_time:
                    duration = f" ({(log.end_time - log.start_time).total_seconds():.1f}s)"

                self.stdout.write(
                    f"{status_icon} {log.code} - {log.start_time.strftime('%Y-%m-%d %H:%M:%S')}{duration}"
                )

                if log.message:
                    message = log.message[:200] + "..." if len(log.message) > 200 else log.message
                    self.stdout.write(f"   Message: {message}")

                if not log.is_success and log.error:
                    error = log.error[:200] + "..." if len(log.error) > 200 else log.error
                    self.stdout.write(self.style.ERROR(f"   Error: {error}"))

                self.stdout.write("")  # Empty line

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Failed to retrieve logs: {e}"))

    def handle_health_check(self, options):
        """Handle health check command"""
        fix_issues = options.get('fix', False)

        self.stdout.write(self.style.SUCCESS("🏥 Attendance Cron Job Health Check"))
        self.stdout.write("=" * 50)

        health_issues = []

        # Check if django-cron is properly configured
        if 'django_cron' not in settings.INSTALLED_APPS:
            health_issues.append("django_cron not in INSTALLED_APPS")

        # Check if cron classes are configured
        if not hasattr(settings, 'CRON_CLASSES') or not settings.CRON_CLASSES:
            health_issues.append("CRON_CLASSES not configured in settings")

        # Check recent job execution
        try:
            from django_cron.models import CronJobLog

            recent_cutoff = timezone.now() - timedelta(hours=24)
            recent_jobs = CronJobLog.objects.filter(start_time__gte=recent_cutoff)

            if not recent_jobs.exists():
                health_issues.append("No cron jobs executed in the last 24 hours")

            # Check for high failure rates
            total_recent = recent_jobs.count()
            failed_recent = recent_jobs.filter(is_success=False).count()

            if total_recent > 0:
                failure_rate = (failed_recent / total_recent) * 100
                if failure_rate > 20:  # More than 20% failure rate
                    health_issues.append(f"High failure rate: {failure_rate:.1f}% ({failed_recent}/{total_recent})")

        except Exception as e:
            health_issues.append(f"Cannot check job execution history: {e}")

        # Check database connectivity
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
            self.stdout.write("✅ Database connectivity: OK")
        except Exception as e:
            health_issues.append(f"Database connectivity issue: {e}")

        # Check attendance data integrity
        try:
            from trueAlign.models import Attendance
            today = timezone.now().date()
            yesterday = today - timedelta(days=1)

            today_count = Attendance.objects.filter(date=today).count()
            yesterday_count = Attendance.objects.filter(date=yesterday).count()

            self.stdout.write(f"✅ Attendance records - Today: {today_count}, Yesterday: {yesterday_count}")

            if today_count == 0:
                health_issues.append("No attendance records for today")

        except Exception as e:
            health_issues.append(f"Cannot check attendance data: {e}")

        # Report results
        if not health_issues:
            self.stdout.write(self.style.SUCCESS("🎉 All health checks passed!"))
        else:
            self.stdout.write(self.style.ERROR(f"⚠️ Found {len(health_issues)} health issues:"))
            for issue in health_issues:
                self.stdout.write(f"  ❌ {issue}")

            if fix_issues:
                self.stdout.write("\n🔧 Attempting to fix issues...")
                self._attempt_fixes(health_issues)

    def handle_emergency_fix(self, options):
        """Handle emergency fix command"""
        date_str = options.get('date')
        days_back = options.get('days_back')

        self.stdout.write(self.style.WARNING("🚨 Running Emergency Attendance Fix"))
        self.stdout.write("=" * 50)

        try:
            IST = pytz.timezone('Asia/Kolkata')

            if days_back:
                # Fix multiple days
                today = timezone.now().astimezone(IST).date()
                dates_to_fix = [today - timedelta(days=i) for i in range(days_back + 1)]
            elif date_str:
                # Fix specific date
                target_date = datetime.strptime(date_str, '%Y-%m-%d').date()
                dates_to_fix = [target_date]
            else:
                # Fix today
                dates_to_fix = [timezone.now().astimezone(IST).date()]

            total_results = {'fixed_dates': 0, 'errors': 0}

            for target_date in dates_to_fix:
                self.stdout.write(f"🔧 Fixing attendance for {target_date}...")

                try:
                    result = run_emergency_attendance_fix(target_date)

                    if result.get('success', False):
                        total_results['fixed_dates'] += 1
                        self.stdout.write(
                            self.style.SUCCESS(f"✅ Fixed {target_date}: {result}")
                        )
                    else:
                        total_results['errors'] += 1
                        self.stdout.write(
                            self.style.ERROR(f"❌ Failed to fix {target_date}: {result.get('error', 'Unknown error')}")
                        )

                except Exception as e:
                    total_results['errors'] += 1
                    self.stdout.write(
                        self.style.ERROR(f"❌ Exception fixing {target_date}: {e}")
                    )

            # Summary
            self.stdout.write(f"\n📊 Emergency Fix Summary:")
            self.stdout.write(f"  Fixed dates: {total_results['fixed_dates']}")
            self.stdout.write(f"  Errors: {total_results['errors']}")

            if total_results['errors'] == 0:
                self.stdout.write(self.style.SUCCESS("🎉 Emergency fix completed successfully!"))
            else:
                self.stdout.write(self.style.WARNING("⚠️ Emergency fix completed with some errors"))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Emergency fix failed: {e}"))
            raise

    def handle_schedule(self, options):
        """Handle schedule command"""
        self.stdout.write(self.style.SUCCESS("📅 Attendance Cron Job Schedules"))
        self.stdout.write("=" * 50)

        schedules = {
            'Daily Attendance Creation': {
                'class': 'DailyAttendanceCreationCronJob',
                'schedule': 'Daily at 6:00 AM IST',
                'description': 'Creates daily attendance records for all active users'
            },
            'Attendance Auto-Marking': {
                'class': 'AttendanceAutoMarkingCronJob',
                'schedule': 'Every 30 minutes (9 AM - 7 PM IST)',
                'description': 'Auto-marks attendance based on sessions and shifts'
            },
            'Attendance Notifications': {
                'class': 'AttendanceNotificationCronJob',
                'schedule': '9:15 AM, 11:00 AM, 3:00 PM, 6:00 PM IST',
                'description': 'Sends various attendance notifications and reminders'
            },
            'Attendance Cleanup': {
                'class': 'AttendanceCleanupCronJob',
                'schedule': 'Weekly on Sunday at 2:00 AM IST',
                'description': 'Performs cleanup and maintenance tasks'
            }
        }

        for job_name, details in schedules.items():
            self.stdout.write(f"\n📋 {job_name}")
            self.stdout.write(f"   Class: {details['class']}")
            self.stdout.write(f"   Schedule: {details['schedule']}")
            self.stdout.write(f"   Description: {details['description']}")

        self.stdout.write(f"\n💡 To set up system cron:")
        self.stdout.write(f"   0 * * * * cd {settings.BASE_DIR} && python manage.py runcrons")

    def handle_test(self, options):
        """Handle test command"""
        job = options.get('job')

        self.stdout.write(self.style.SUCCESS(f"🧪 Testing cron job: {job}"))

        # This would run a dry-run or test version of the job
        # Implementation depends on the specific testing requirements
        self.stdout.write("Test functionality not yet implemented")

    def _show_job_specific_status(self):
        """Show status for specific job types"""
        try:
            from django_cron.models import CronJobLog

            job_codes = [
                'attendance.daily_creation',
                'attendance.auto_marking',
                'attendance.notifications',
                'attendance.cleanup'
            ]

            self.stdout.write("\n🔧 Job-Specific Status:")

            for code in job_codes:
                latest_log = CronJobLog.objects.filter(code=code).order_by('-start_time').first()

                if latest_log:
                    status_icon = "✅" if latest_log.is_success else "❌"
                    time_str = latest_log.start_time.strftime('%Y-%m-%d %H:%M:%S')
                    self.stdout.write(f"  {status_icon} {code}: Last run {time_str}")
                else:
                    self.stdout.write(f"  ⚪ {code}: Never run")

        except Exception as e:
            self.stdout.write(f"  ⚠️ Could not get job-specific status: {e}")

    def _was_recently_run(self, job_name):
        """Check if job was recently run"""
        try:
            from django_cron.models import CronJobLog

            job_code_mapping = {
                'daily_creation': 'attendance.daily_creation',
                'auto_marking': 'attendance.auto_marking',
                'notifications': 'attendance.notifications',
                'cleanup': 'attendance.cleanup',
            }

            code = job_code_mapping.get(job_name)
            if not code:
                return False

            # Check if run in the last hour
            recent_cutoff = timezone.now() - timedelta(hours=1)
            recent_run = CronJobLog.objects.filter(
                code=code,
                start_time__gte=recent_cutoff
            ).exists()

            return recent_run

        except Exception:
            return False

    def _attempt_fixes(self, health_issues):
        """Attempt to automatically fix health issues"""
        fixed_count = 0

        for issue in health_issues:
            try:
                if "No attendance records for today" in issue:
                    # Run daily creation job
                    self.stdout.write("  🔧 Creating today's attendance records...")
                    job = DailyAttendanceCreationCronJob()
                    job.do()
                    fixed_count += 1
                    self.stdout.write("  ✅ Created attendance records")

                elif "No cron jobs executed" in issue:
                    # Run auto-marking job
                    self.stdout.write("  🔧 Running attendance auto-marking...")
                    job = AttendanceAutoMarkingCronJob()
                    job.do()
                    fixed_count += 1
                    self.stdout.write("  ✅ Executed auto-marking job")

                else:
                    self.stdout.write(f"  ⚠️ Cannot auto-fix: {issue}")

            except Exception as e:
                self.stdout.write(f"  ❌ Failed to fix '{issue}': {e}")

        if fixed_count > 0:
            self.stdout.write(f"\n🎉 Successfully fixed {fixed_count} issues!")
        else:
            self.stdout.write("\n⚠️ No issues could be automatically fixed")
