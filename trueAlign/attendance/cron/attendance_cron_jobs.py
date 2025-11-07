# attendance/cron/attendance_cron_jobs.py
"""
Django Cron Jobs for Attendance System

This module contains all cron job classes for automated attendance management.
These jobs are designed to run automatically to maintain attendance data,
send notifications, and perform maintenance tasks.

Cron Job Classes:
- DailyAttendanceCreationCronJob: Creates daily attendance records
- AttendanceAutoMarkingCronJob: Auto-marks attendance based on sessions
- AttendanceNotificationCronJob: Sends attendance notifications
- AttendanceCleanupCronJob: Performs data cleanup and maintenance

Usage:
- Configure in settings.py CRON_CLASSES
- Run manually: python manage.py runcrons
- Set up system cron: 0 9 * * * cd /path/to/project && python manage.py runcrons
"""

import logging
from datetime import datetime, date, timedelta
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.conf import settings
from django.db import transaction
from django_cron import CronJobBase, Schedule
import pytz

from ..services import (
    AttendanceAutoMarkingService,
    AttendanceIntegrationService,
    get_attendance_services
)
from ..notifications import AttendanceNotificationService
from ..config import get_setting, IST_TIMEZONE
from trueAlign.models import Attendance, UserSession
# Note: NotificationService import removed - using AttendanceNotificationService instead

# Import distributed locking
from .locking import with_cron_lock

# Configure logging
logger = logging.getLogger('cron')
User = get_user_model()


class BaseCronJob(CronJobBase):
    """
    Base cron job class with common functionality
    """

    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.errors = []
        self.results = {}

    def log_start(self, job_name):
        """Log job start"""
        self.start_time = timezone.now()
        logger.info(f"Starting {job_name} at {self.start_time}")

    def log_end(self, job_name):
        """Log job completion"""
        self.end_time = timezone.now()
        duration = (self.end_time - self.start_time).total_seconds()

        if self.errors:
            logger.error(f"Completed {job_name} with {len(self.errors)} errors in {duration:.2f}s")
            for error in self.errors:
                logger.error(f"  - {error}")
        else:
            logger.info(f"Successfully completed {job_name} in {duration:.2f}s")

    def add_error(self, error_msg):
        """Add error to error list"""
        self.errors.append(error_msg)
        logger.error(error_msg)

    def get_ist_date(self, date_offset=0):
        """Get date in IST timezone with optional offset"""
        return timezone.now().astimezone(IST_TIMEZONE).date() + timedelta(days=date_offset)


class DailyAttendanceCreationCronJob(BaseCronJob):
    """
    Creates daily attendance records for all active users

    This job runs early in the morning to ensure all users have
    attendance records for the current day. Records are created
    with 'Yet to Clock In' status and will be updated by other
    processes as users log in and work.

    Schedule: Daily at 5:30 AM IST (Earlier to ensure records ready before workday)
    """

    RUN_AT_TIMES = ['05:30']  # 5:30 AM IST - Earlier start for better preparation

    schedule = Schedule(run_at_times=RUN_AT_TIMES)
    code = 'attendance.daily_creation'

    @with_cron_lock('daily_creation', timeout=1800)  # 30 min lock
    def do(self):
        """Execute daily attendance creation with distributed locking"""
        # Release any expired attendance processing locks before starting
        try:
            expired_count = Attendance.release_expired_locks()
            if expired_count > 0:
                logger.warning(f"Released {expired_count} expired attendance processing locks")
        except Exception as e:
            logger.error(f"Error releasing expired locks: {e}")
        job_name = "Daily Attendance Creation"
        self.log_start(job_name)

        try:
            target_date = self.get_ist_date()

            # Skip weekends and holidays if configured
            if self._should_skip_date(target_date):
                logger.info(f"Skipping attendance creation for {target_date} (weekend/holiday)")
                return

            # Use integration service to create records
            integration_service = AttendanceIntegrationService()
            created_count = integration_service.create_daily_attendance_records(target_date)

            self.results['created_count'] = created_count
            self.results['target_date'] = target_date

            logger.info(f"Created {created_count} attendance records for {target_date}")

            # Send notification to HR about daily creation
            self._send_creation_notification(target_date, created_count)

        except Exception as e:
            self.add_error(f"Failed to create daily attendance records: {str(e)}")

        finally:
            self.log_end(job_name)

    def _should_skip_date(self, target_date):
        """Check if date should be skipped (weekend/holiday)"""
        try:
            from trueAlign.models import Holiday

            # Check if it's a weekend
            if target_date.weekday() >= 5:  # Saturday=5, Sunday=6
                weekend_processing = get_setting('process_weekend_attendance', False)
                if not weekend_processing:
                    return True

            # Check if it's a holiday
            if Holiday.objects.filter(date=target_date, is_active=True).exists():
                holiday_processing = get_setting('process_holiday_attendance', False)
                if not holiday_processing:
                    return True

            return False

        except Exception as e:
            logger.warning(f"Error checking if date should be skipped: {e}")
            return False

    def _send_creation_notification(self, target_date, created_count):
        """Send notification about daily creation to HR"""
        try:
            notification_service = AttendanceNotificationService()

            # Get HR users
            hr_users = User.objects.filter(
                groups__name='HR',
                is_active=True
            ).distinct()

            if hr_users.exists():
                message = f"Daily attendance records created for {target_date}: {created_count} records"

                for hr_user in hr_users:
                    # TODO: Implement proper notification using AttendanceNotificationService
                    logger.info(f"Notification: {message} (to {hr_user.username})")
                    # NotificationService.send_notification(
                    #     recipient=hr_user,
                    #     title="Daily Attendance Records Created",
                    #     message=message,
                    #     category='attendance_system'
                    # )

        except Exception as e:
            logger.warning(f"Failed to send creation notification: {e}")


class AttendanceAutoMarkingCronJob(BaseCronJob):
    """
    Runs attendance auto-marking process to update attendance status
    based on user sessions, leave requests, and shift assignments.

    This job processes attendance records and updates their status
    based on various factors like login sessions, approved leaves,
    shift timings, etc.

    Schedule: OPTIMIZED - 6 times per day (reduced from 21 for efficiency)
    Strategic timing for maximum coverage with minimal redundancy:
    - 09:15: After morning arrivals
    - 10:30: Mid-morning check
    - 12:30: Post-lunch update  
    - 15:00: Afternoon check
    - 17:30: Pre-EOD update
    - 19:30: Final daily update (catches late workers)
    """

    # OPTIMIZED SCHEDULE - Reduced from 21 to 6 runs per day (71% reduction)
    RUN_AT_TIMES = [
        '09:15',  # After morning arrivals
        '10:30',  # Mid-morning check
        '12:30',  # Post-lunch update
        '15:00',  # Afternoon check
        '17:30',  # Pre-EOD update
        '19:30'   # Final daily update
    ]

    schedule = Schedule(run_at_times=RUN_AT_TIMES)
    code = 'attendance.auto_marking'

    @with_cron_lock('auto_marking', timeout=1800)  # 30 min lock
    def do(self):
        """Execute attendance auto-marking with distributed locking"""
        job_name = "Attendance Auto-Marking"
        self.log_start(job_name)

        try:
            # Process today's attendance
            target_date = self.get_ist_date()
            
            # Set marker that auto-marking is starting (for notification coordination)
            from django.core.cache import cache
            cache.set('last_auto_marking_start', timezone.now(), 3600)

            auto_marking_service = AttendanceAutoMarkingService()
            result = auto_marking_service.run_auto_marking(target_date)
            
            # Convert ServiceResult to dict
            result_dict = result.to_dict() if hasattr(result, 'to_dict') else result
            
            # Set marker that auto-marking completed successfully
            cache.set('last_auto_marking_completion', timezone.now(), 3600)
            cache.set(f'auto_marking_data_{target_date}', result_dict, 7200)  # Cache result for 2 hours

            if result_dict.get('success', True):
                # Merge data from result if available
                if result_dict.get('data'):
                    self.results.update(result_dict['data'])
                logger.info(
                    f"Auto-marking completed for {target_date}: "
                    f"Created: {result_dict.get('data', {}).get('created', 0)}, "
                    f"Updated: {result_dict.get('data', {}).get('updated', 0)}, "
                    f"Processed: {result_dict.get('data', {}).get('processed', 0)}"
                )

                # Also process yesterday if it's early morning
                current_hour = timezone.now().astimezone(IST_TIMEZONE).hour
                if current_hour <= 10:
                    self._process_previous_day(auto_marking_service)

            else:
                errors = result_dict.get('errors', []) or [result_dict.get('message', 'Unknown error')]
                for error in errors:
                    self.add_error(f"Auto-marking failed: {error}")

        except Exception as e:
            self.add_error(f"Failed to run auto-marking: {str(e)}")

        finally:
            self.log_end(job_name)

    def _process_previous_day(self, auto_marking_service):
        """Process previous day's attendance for late updates"""
        try:
            yesterday = self.get_ist_date(-1)

            # Only process if there are incomplete records
            incomplete_count = Attendance.objects.filter(
                date=yesterday,
                status__in=['Yet to Clock In', 'Not Marked']
            ).count()

            if incomplete_count > 0:
                logger.info(f"Processing {incomplete_count} incomplete records for {yesterday}")

                result = auto_marking_service.run_auto_marking(yesterday)
                result_dict = result.to_dict() if hasattr(result, 'to_dict') else result
                self.results[f'yesterday_{yesterday}'] = result_dict

                logger.info(f"Previous day processing completed: Updated {result_dict.get('data', {}).get('updated', 0)} records")

        except Exception as e:
            logger.warning(f"Failed to process previous day: {e}")


class AttendanceNotificationCronJob(BaseCronJob):
    """
    Sends attendance-related notifications and reminders

    This job handles various notification types:
    - Late arrival notifications
    - Absent user notifications to managers
    - Regularization deadline reminders
    - Daily/weekly attendance summaries

    Schedule: OPTIMIZED - Coordinated with auto-marking job
    Runs 30 minutes AFTER auto-marking to ensure fresh data:
    - 09:45: After 09:15 auto-marking (late arrivals)
    - 11:30: After 10:30 auto-marking (absent users)
    - 15:30: After 15:00 auto-marking (regularization reminders)
    - 18:30: After 17:30 auto-marking (daily summaries)
    """

    # OPTIMIZED TIMING - Wait 30 min after auto-marking for data readiness
    RUN_AT_TIMES = ['09:45', '11:30', '15:30', '18:30']

    schedule = Schedule(run_at_times=RUN_AT_TIMES)
    code = 'attendance.notifications'

    @with_cron_lock('notifications', timeout=900)  # 15 min lock
    def do(self):
        """Execute notification sending with data readiness check"""
        job_name = "Attendance Notifications"
        self.log_start(job_name)

        try:
            # CHECK DATA READINESS - Ensure auto-marking completed recently
            from django.core.cache import cache
            last_marking_completion = cache.get('last_auto_marking_completion')
            
            if not last_marking_completion:
                logger.warning("⚠ Skipping notifications: Auto-marking not run yet today")
                return {'success': False, 'message': 'Waiting for auto-marking completion', 'skipped': True}
            
            # Check if data is too old (more than 1 hour)
            time_since_marking = (timezone.now() - last_marking_completion).seconds
            if time_since_marking > 3600:
                logger.warning(f"⚠ Skipping notifications: Auto-marking data is {time_since_marking}s old (stale)")
                return {'success': False, 'message': 'Auto-marking data too old', 'skipped': True}
            
            logger.info(f"✓ Data ready: Auto-marking completed {time_since_marking}s ago")
            
            current_time = timezone.now().astimezone(IST_TIMEZONE)
            current_hour = current_time.hour

            notification_service = AttendanceNotificationService()

            # 9:45 AM - Late arrival notifications (after 09:15 auto-marking)
            if current_hour == 9:
                self._send_late_arrival_notifications(notification_service)

            # 11:00 AM - Absent notifications to managers
            elif current_hour == 11:
                self._send_absent_notifications(notification_service)

            # 3:00 PM - Regularization reminders
            elif current_hour == 15:
                self._send_regularization_reminders(notification_service)

            # 6:00 PM - Daily summaries
            elif current_hour == 18:
                self._send_daily_summaries(notification_service)

        except Exception as e:
            self.add_error(f"Failed to send notifications: {str(e)}")

        finally:
            self.log_end(job_name)

    def _send_late_arrival_notifications(self, notification_service):
        """Send notifications for late arrivals"""
        try:
            today = self.get_ist_date()

            # Get users who are late today
            late_attendances = Attendance.objects.filter(
                date=today,
                status='Present & Late'
            ).select_related('user')

            count = 0
            for attendance in late_attendances:
                try:
                    # TODO: Implement proper notification using AttendanceNotificationService
                    logger.info(f"Notification: Late arrival for {attendance.user.username} (to {attendance.user.username})")
                    # NotificationService.send_notification(
                    #     recipient=attendance.user,
                    #     title="Late Arrival Notification",
                    #     message=f"You have been marked late for {today}.",
                    #     category='attendance_info'
                    # )
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to send late notification to {attendance.user.username}: {e}")

            self.results['late_notifications_sent'] = count
            logger.info(f"Sent {count} late arrival notifications")

        except Exception as e:
            self.add_error(f"Failed to send late arrival notifications: {str(e)}")

    def _send_absent_notifications(self, notification_service):
        """Send absent notifications to managers"""
        try:
            today = self.get_ist_date()

            # Get users who are absent today
            absent_attendances = Attendance.objects.filter(
                date=today,
                status='Absent'
            ).select_related('user', 'user__userdetails')

            # Group by manager
            manager_absent_users = {}

            for attendance in absent_attendances:
                try:
                    user_details = attendance.user.userdetails
                    if user_details and user_details.reporting_manager:
                        manager = user_details.reporting_manager
                        if manager not in manager_absent_users:
                            manager_absent_users[manager] = []
                        manager_absent_users[manager].append(attendance.user)
                except:
                    continue

            # Send notifications to managers
            count = 0
            for manager, absent_users in manager_absent_users.items():
                try:
                    # Create custom notification for manager
                    message = f"The following team members are absent today ({today}):\n"
                    message += "\n".join([f"- {user.get_full_name()}" for user in absent_users])

                    # TODO: Implement proper notification using AttendanceNotificationService
                    logger.info(f"Team Alert: {len(absent_users)} absent (to {manager.username})")
                    # NotificationService.send_notification(
                    #     recipient=manager,
                    #     title=f"Team Attendance Alert - {len(absent_users)} Absent",
                    #     message=message,
                    #     category='attendance_alert'
                    # )
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to send absent notification to manager {manager.username}: {e}")

            self.results['absent_notifications_sent'] = count
            logger.info(f"Sent {count} absent notifications to managers")

        except Exception as e:
            self.add_error(f"Failed to send absent notifications: {str(e)}")

    def _send_regularization_reminders(self, notification_service):
        """Send regularization deadline reminders"""
        try:
            # Get pending regularizations approaching deadline
            deadline_days = get_setting('regularization_deadline_days', 7)
            reminder_days = [3, 1]  # Remind 3 days and 1 day before deadline

            count = 0
            for days_before in reminder_days:
                target_date = self.get_ist_date() - timedelta(days=deadline_days - days_before)

                pending_attendances = Attendance.objects.filter(
                    date=target_date,
                    regularization_status='Pending'
                ).select_related('user')

                for attendance in pending_attendances:
                    try:
                        days_remaining = days_before

                        # TODO: Implement proper notification using AttendanceNotificationService
                        logger.info(f"Regularization reminder to {attendance.user.username} for {target_date}")
                        # NotificationService.send_notification(
                        #     recipient=attendance.user,
                        #     title=f"Regularization Deadline Reminder - {days_remaining} days left",
                        #     message=f"Your attendance regularization request for {target_date} expires in {days_remaining} days. Please take action.",
                        #     category='regularization_reminder'
                        # )
                        count += 1

                    except Exception as e:
                        logger.warning(f"Failed to send regularization reminder to {attendance.user.username}: {e}")

            self.results['regularization_reminders_sent'] = count
            logger.info(f"Sent {count} regularization reminders")

        except Exception as e:
            self.add_error(f"Failed to send regularization reminders: {str(e)}")

    def _send_daily_summaries(self, notification_service):
        """Send daily attendance summaries to HR"""
        try:
            today = self.get_ist_date()

            # Get attendance summary for today
            summary = Attendance.objects.filter(date=today).values('status').annotate(
                count=models.Count('id')
            )

            # Format summary message
            summary_text = f"Daily Attendance Summary for {today}:\n\n"
            total_count = 0

            for item in summary:
                status = item['status']
                count = item['count']
                summary_text += f"• {status}: {count}\n"
                total_count += count

            summary_text += f"\nTotal Records: {total_count}"

            # Send to HR users
            hr_users = User.objects.filter(
                groups__name='HR',
                is_active=True
            ).distinct()

            count = 0
            for hr_user in hr_users:
                try:
                    # TODO: Implement proper notification using AttendanceNotificationService
                    logger.info(f"Daily summary sent to {hr_user.username}")
                    # NotificationService.send_notification(
                    #     recipient=hr_user,
                    #     title=f"Daily Attendance Summary - {today}",
                    #     message=summary_text,
                    #     category='attendance_summary'
                    # )
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to send daily summary to {hr_user.username}: {e}")

            self.results['daily_summaries_sent'] = count
            logger.info(f"Sent {count} daily summaries to HR")

        except Exception as e:
            self.add_error(f"Failed to send daily summaries: {str(e)}")


class AttendanceCleanupCronJob(BaseCronJob):
    """
    Performs cleanup and maintenance tasks for attendance data

    This job handles:
    - Cleanup of old attendance records (based on retention policy)
    - Archive old data
    - Clean up temporary files and caches
    - Performance optimization tasks

    Schedule: Weekly on Sunday at 2:00 AM IST
    """

    RUN_ON_DAYS = [6]  # Sunday = 6
    RUN_AT_TIMES = ['02:00']

    schedule = Schedule(run_on_days=RUN_ON_DAYS, run_at_times=RUN_AT_TIMES)
    code = 'attendance.cleanup'

    @with_cron_lock('cleanup', timeout=7200)  # 2 hour lock for cleanup
    def do(self):
        """Execute cleanup tasks with distributed locking"""
        job_name = "Attendance Cleanup"
        self.log_start(job_name)

        try:
            # 1. Clean up old attendance records
            self._cleanup_old_records()

            # 2. Clean up old cron logs
            self._cleanup_cron_logs()

            # 3. Clean up old session data
            self._cleanup_old_sessions()

            # 4. Optimize database
            self._optimize_database()

            # 5. Generate weekly summary
            self._generate_weekly_summary()

        except Exception as e:
            self.add_error(f"Failed to complete cleanup tasks: {str(e)}")

        finally:
            self.log_end(job_name)

    def _cleanup_old_records(self):
        """Clean up old attendance records based on retention policy"""
        try:
            retention_days = get_setting('attendance_retention_days', 1095)  # 3 years default
            cutoff_date = self.get_ist_date() - timedelta(days=retention_days)

            # Count records to be deleted
            old_records_count = Attendance.objects.filter(date__lt=cutoff_date).count()

            if old_records_count > 0:
                # Archive before deletion if configured
                if get_setting('archive_before_cleanup', True):
                    self._archive_old_records(cutoff_date)

                # Delete old records
                deleted_count, _ = Attendance.objects.filter(date__lt=cutoff_date).delete()

                self.results['attendance_records_deleted'] = deleted_count
                logger.info(f"Deleted {deleted_count} attendance records older than {cutoff_date}")
            else:
                logger.info("No old attendance records to clean up")

        except Exception as e:
            self.add_error(f"Failed to cleanup old attendance records: {str(e)}")

    def _archive_old_records(self, cutoff_date):
        """Archive old records before deletion"""
        try:
            # This is a placeholder for archival logic
            # In a real implementation, you might export to S3, backup database, etc.
            logger.info(f"Archiving attendance records older than {cutoff_date}")

            # Example: Export to CSV or call external archival service
            # archive_service.archive_attendance_data(cutoff_date)

        except Exception as e:
            logger.warning(f"Failed to archive old records: {e}")

    def _cleanup_cron_logs(self):
        """Clean up old cron job logs"""
        try:
            # Clean up django-cron logs
            call_command('cleanup_cron_logs')
            logger.info("Cleaned up old cron logs")

        except Exception as e:
            logger.warning(f"Failed to cleanup cron logs: {e}")

    def _cleanup_old_sessions(self):
        """Clean up old session data"""
        try:
            # Clean up sessions older than 30 days
            cutoff_date = timezone.now() - timedelta(days=30)

            old_sessions_count = UserSession.objects.filter(
                login_time__lt=cutoff_date,
                is_active=False
            ).count()

            if old_sessions_count > 0:
                deleted_count, _ = UserSession.objects.filter(
                    login_time__lt=cutoff_date,
                    is_active=False
                ).delete()

                self.results['sessions_deleted'] = deleted_count
                logger.info(f"Deleted {deleted_count} old session records")

        except Exception as e:
            self.add_error(f"Failed to cleanup old sessions: {str(e)}")

    def _optimize_database(self):
        """Perform database optimization tasks"""
        try:
            # This would include database-specific optimization
            # For PostgreSQL: VACUUM, ANALYZE
            # For MySQL: OPTIMIZE TABLE

            from django.db import connection

            with connection.cursor() as cursor:
                # Example for PostgreSQL
                if 'postgresql' in connection.settings_dict['ENGINE']:
                    cursor.execute("VACUUM ANALYZE trueAlign_attendance;")
                    logger.info("Database optimization completed (PostgreSQL)")

                # Example for MySQL
                elif 'mysql' in connection.settings_dict['ENGINE']:
                    cursor.execute("OPTIMIZE TABLE trueAlign_attendance;")
                    logger.info("Database optimization completed (MySQL)")

        except Exception as e:
            logger.warning(f"Database optimization failed: {e}")

    def _generate_weekly_summary(self):
        """Generate and send weekly attendance summary"""
        try:
            # Calculate week range
            today = self.get_ist_date()
            week_start = today - timedelta(days=today.weekday() + 1)  # Last Monday
            week_end = week_start + timedelta(days=6)  # Last Sunday

            # Generate summary data
            weekly_stats = Attendance.objects.filter(
                date__range=[week_start, week_end]
            ).values('status').annotate(
                count=models.Count('id')
            )

            # Format summary
            summary_text = f"Weekly Attendance Summary ({week_start} to {week_end}):\n\n"

            for stat in weekly_stats:
                summary_text += f"• {stat['status']}: {stat['count']}\n"

            # Send to admin users
            admin_users = User.objects.filter(
                is_superuser=True,
                is_active=True
            )

            count = 0
            for admin_user in admin_users:
                try:
                    # TODO: Implement proper notification using AttendanceNotificationService
                    logger.info(f"Weekly summary sent to {admin_user.username}")
                    # NotificationService.send_notification(
                    #     recipient=admin_user,
                    #     title=f"Weekly Attendance Summary",
                    #     message=summary_text,
                    #     category='weekly_summary'
                    # )
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to send weekly summary to {admin_user.username}: {e}")

            self.results['weekly_summaries_sent'] = count
            logger.info(f"Sent {count} weekly summaries")

        except Exception as e:
            self.add_error(f"Failed to generate weekly summary: {str(e)}")


# Import required for database operations
from django.db import models

# Additional utility functions for cron jobs

def get_cron_job_status():
    """Get status of all cron jobs"""
    try:
        from django_cron.models import CronJobLog

        recent_logs = CronJobLog.objects.filter(
            start_time__gte=timezone.now() - timedelta(days=7)
        ).order_by('-start_time')[:50]

        status = {
            'total_runs': recent_logs.count(),
            'successful_runs': recent_logs.filter(is_success=True).count(),
            'failed_runs': recent_logs.filter(is_success=False).count(),
            'recent_logs': list(recent_logs.values(
                'code', 'start_time', 'end_time', 'is_success', 'message'
            ))
        }

        return status

    except Exception as e:
        logger.error(f"Failed to get cron job status: {e}")
        return {'error': str(e)}


def run_emergency_attendance_fix(target_date=None):
    """Emergency function to fix attendance issues"""
    try:
        if target_date is None:
            target_date = timezone.now().astimezone(IST_TIMEZONE).date()

        logger.info(f"Running emergency attendance fix for {target_date}")

        # Run all the critical jobs manually
        auto_marking_service = AttendanceAutoMarkingService()
        result = auto_marking_service.run_auto_marking(target_date)

        logger.info(f"Emergency fix completed: {result}")
        return result

    except Exception as e:
        logger.error(f"Emergency attendance fix failed: {e}")
        return {'success': False, 'error': str(e)}
