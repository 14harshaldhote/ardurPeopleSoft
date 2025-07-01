# attendance/services.py
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.db import transaction, models
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.conf import settings
from datetime import datetime, timedelta, date
import pytz
import logging
from decimal import Decimal
from trueAlign.models import (
    Attendance, UserSession, Holiday, ShiftAssignment,
    LeaveRequest, ShiftMaster
)

logger = logging.getLogger(__name__)
User = get_user_model()


class AttendanceAutoMarkingService:
    """
    Service to handle automatic attendance marking and updates
    """

    def __init__(self):
        self.IST = pytz.timezone('Asia/Kolkata')
        self.today = timezone.now().astimezone(self.IST).date()
        self.current_time = timezone.now().astimezone(self.IST).time()

    def run_auto_marking(self, date=None):
        """
        Main method to run automatic attendance marking
        """
        if not date:
            date = self.today

        logger.info(f"Starting auto attendance marking for {date}")

        try:
            with transaction.atomic():
                # Step 1: Create missing attendance records
                created_count = self._create_missing_attendance_records(date)

                # Step 2: Update existing records with session data
                updated_count = self._update_attendance_with_sessions(date)

                # Step 3: Process "Yet to Clock In" statuses
                processed_count = self._process_yet_to_clock_in_statuses(date)

                # Step 4: Calculate final statuses and hours
                calculated_count = self._recalculate_attendance_statuses(date)

                logger.info(
                    f"Auto marking completed for {date}: "
                    f"Created: {created_count}, Updated: {updated_count}, "
                    f"Processed: {processed_count}, Calculated: {calculated_count}"
                )

                return {
                    'success': True,
                    'date': date,
                    'created': created_count,
                    'updated': updated_count,
                    'processed': processed_count,
                    'calculated': calculated_count
                }

        except Exception as e:
            logger.error(f"Error in auto attendance marking: {e}")
            return {
                'success': False,
                'error': str(e)
            }

    def _create_missing_attendance_records(self, date):
        """
        Create attendance records for users who don't have them
        """
        users_without_attendance = Attendance.objects.get_users_without_attendance_today(date)
        created_count = 0

        for user in users_without_attendance:
            try:
                self._create_attendance_for_user(user, date)
                created_count += 1
            except Exception as e:
                logger.error(f"Error creating attendance for {user.username}: {e}")

        return created_count

    def _create_attendance_for_user(self, user, date):
        """
        Create attendance record for a specific user based on various conditions
        """
        # Check if user has any sessions for the date
        sessions = UserSession.objects.filter(
            user=user,
            login_time__date=date
        ).order_by('login_time')

        if sessions.exists():
            # User has sessions, create attendance based on first session
            first_session = sessions.first()
            attendance = Attendance.create_attendance_record(
                user=user,
                clock_in_time=first_session.login_time,
                location=getattr(first_session, 'location', 'Office'),
                ip_address=getattr(first_session, 'ip_address', None),
                device_info=getattr(first_session, 'device_info', None)
            )

            # Update with all session data
            self._update_attendance_with_user_sessions(attendance, sessions)

        else:
            # No sessions, determine status based on other factors
            self._create_attendance_without_session(user, date)

    def _create_attendance_without_session(self, user, date):
        """
        Create attendance record for user without any sessions
        """
        # Check for approved leave
        leave_request = LeaveRequest.objects.filter(
            user=user,
            status='Approved',
            start_date__lte=date,
            end_date__gte=date
        ).select_related('leave_type').first()

        if leave_request:
            Attendance.objects.create(
                user=user,
                date=date,
                status='On Leave',
                leave_type=leave_request.leave_type.name,
                regularization_reason=f"Auto-marked: On {leave_request.leave_type.name} leave"
            )
            return

        # Check for holiday
        holiday = Holiday.get_holiday(date)
        if holiday:
            Attendance.objects.create(
                user=user,
                date=date,
                status='Holiday',
                is_holiday=True,
                holiday_name=holiday.name,
                regularization_reason=f"Auto-marked: Holiday - {holiday.name}"
            )
            return

        # Get user's shift
        current_shift = ShiftAssignment.get_user_current_shift(user, date)

        # Check for weekend
        if self._is_weekend(date, current_shift):
            Attendance.objects.create(
                user=user,
                date=date,
                status='Weekend',
                is_weekend=True,
                shift=current_shift,
                regularization_reason="Auto-marked: Weekend"
            )
            return

        # Regular working day
        if current_shift:
            if date == self.today and not self._is_shift_ended(self.current_time, current_shift):
                # Shift still active for today
                Attendance.objects.create(
                    user=user,
                    date=date,
                    status='Yet to Clock In',
                    shift=current_shift,
                    regularization_reason="Auto-marked: Yet to clock in (shift in progress)"
                )
            else:
                # Shift ended or past date
                Attendance.objects.create(
                    user=user,
                    date=date,
                    status='Absent',
                    shift=current_shift,
                    regularization_reason="Auto-marked: Absent (no activity)"
                )
        else:
            # No shift assigned
            Attendance.objects.create(
                user=user,
                date=date,
                status='Not Marked',
                regularization_reason="Auto-marked: No shift assigned"
            )

    def _update_attendance_with_sessions(self, date):
        """
        Update existing attendance records with session data
        """
        attendances_to_update = Attendance.objects.filter(
            date=date,
            status__in=['Not Marked', 'Yet to Clock In']
        ).select_related('user')

        updated_count = 0

        for attendance in attendances_to_update:
            sessions = UserSession.objects.filter(
                user=attendance.user,
                login_time__date=date
            ).order_by('login_time')

            if sessions.exists():
                self._update_attendance_with_user_sessions(attendance, sessions)
                updated_count += 1

        return updated_count

    def _update_attendance_with_user_sessions(self, attendance, sessions):
        """
        Update single attendance record with session data
        """
        first_session = sessions.first()
        last_session = sessions.last()

        # Update session references
        attendance.first_session = first_session
        attendance.last_session = last_session
        attendance.total_sessions = sessions.count()

        # Update clock times
        attendance.clock_in_time = first_session.login_time

        # Set clock out time based on last session
        if last_session.logout_time:
            attendance.clock_out_time = last_session.logout_time
        elif last_session.last_activity and not last_session.is_active:
            attendance.clock_out_time = last_session.last_activity

        # Calculate total idle time
        total_idle_time = timedelta(0)
        for session in sessions:
            if hasattr(session, 'idle_time') and session.idle_time:
                total_idle_time += session.idle_time

        attendance.idle_time = total_idle_time

        # Update location and device info from latest session
        if hasattr(last_session, 'location'):
            attendance.location = last_session.location
        if hasattr(last_session, 'ip_address'):
            attendance.ip_address = last_session.ip_address
        if hasattr(last_session, 'device_info'):
            attendance.device_info = last_session.device_info

        attendance.save()

    def _process_yet_to_clock_in_statuses(self, date):
        """
        Process "Yet to Clock In" statuses and update to "Absent" if shift ended
        """
        if date != self.today:
            # For past dates, mark all "Yet to Clock In" as "Absent"
            return Attendance.objects.filter(
                date=date,
                status='Yet to Clock In'
            ).update(
                status='Absent',
                regularization_reason='Auto-updated: Absent (past date, no activity)'
            )

        # For today, check if shifts have ended
        yet_to_clock_in_attendances = Attendance.objects.filter(
            date=date,
            status='Yet to Clock In'
        ).select_related('shift')

        processed_count = 0

        for attendance in yet_to_clock_in_attendances:
            if attendance.shift and self._is_shift_ended(self.current_time, attendance.shift):
                attendance.status = 'Absent'
                attendance.regularization_reason = 'Auto-updated: Absent (shift ended, no activity)'
                attendance.save()
                processed_count += 1
                logger.info(f"Updated {attendance.user.username} from 'Yet to Clock In' to 'Absent'")

        return processed_count

    def _recalculate_attendance_statuses(self, date):
        """
        Recalculate attendance statuses based on updated data
        """
        attendances_to_recalculate = Attendance.objects.filter(
            date=date,
            clock_in_time__isnull=False
        ).exclude(status__in=['On Leave', 'Holiday', 'Weekend'])

        calculated_count = 0

        for attendance in attendances_to_recalculate:
            old_status = attendance.status
            # This will trigger the status calculation logic
            attendance.save()

            if attendance.status != old_status:
                calculated_count += 1
                logger.info(f"Updated {attendance.user.username} status from {old_status} to {attendance.status}")

        return calculated_count

    def _is_weekend(self, date, shift):
        """
        Check if date is weekend based on shift configuration
        """
        weekday = date.weekday()

        if shift:
            working_days = shift.get_working_days()
            day_names = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            current_day = day_names[weekday]
            return current_day not in working_days

        # Default weekend logic (Saturday, Sunday)
        return weekday >= 5

    def _is_shift_ended(self, current_time, shift):
        """
        Check if shift has ended
        """
        current_minutes = current_time.hour * 60 + current_time.minute
        start_minutes = shift.start_time.hour * 60 + shift.start_time.minute
        end_minutes = shift.end_time.hour * 60 + shift.end_time.minute

        # Handle night shifts (crosses midnight)
        if end_minutes < start_minutes:
            end_minutes += 24 * 60
            if current_minutes < start_minutes:
                current_minutes += 24 * 60

        return current_minutes > end_minutes


class AttendanceIntegrationService:
    """
    Service to handle integration with sessions, leaves, and other systems
    """

    def __init__(self):
        self.IST = pytz.timezone('Asia/Kolkata')

    def process_session_login(self, user, session):
        """
        Process user login session and update attendance
        """
        try:
            login_time = session.login_time.astimezone(self.IST)
            attendance_date = login_time.date()

            # Create or update attendance record
            attendance = Attendance.create_attendance_record(
                user=user,
                clock_in_time=login_time,
                location=getattr(session, 'location', 'Office'),
                ip_address=getattr(session, 'ip_address', None),
                device_info=getattr(session, 'device_info', None)
            )

            # Update session reference
            Attendance.update_session_data(user, session, attendance_date)

            logger.info(f"Processed login session for {user.username} at {login_time}")
            return attendance

        except Exception as e:
            logger.error(f"Error processing session login for {user.username}: {e}")
            return None

    def process_session_logout(self, user, session):
        """
        Process user logout session and update attendance
        """
        try:
            if session.logout_time:
                logout_time = session.logout_time.astimezone(self.IST)
                attendance_date = logout_time.date()

                # Record clock out
                attendance = Attendance.record_clock_out(
                    user=user,
                    clock_out_time=logout_time,
                    location=getattr(session, 'location', None)
                )

                # Update session reference
                Attendance.update_session_data(user, session, attendance_date)

                logger.info(f"Processed logout session for {user.username} at {logout_time}")
                return attendance

        except Exception as e:
            logger.error(f"Error processing session logout for {user.username}: {e}")
            return None

    def sync_leave_with_attendance(self, leave_request):
        """
        Synchronize leave request with attendance records
        """
        try:
            if leave_request.status != 'Approved':
                return

            current_date = leave_request.start_date
            end_date = leave_request.end_date

            while current_date <= end_date:
                attendance, created = Attendance.objects.get_or_create_today_attendance(
                    leave_request.user, current_date
                )

                # Update attendance for leave
                attendance.status = 'On Leave'
                attendance.leave_type = leave_request.leave_type.name
                attendance.regularization_reason = f"On {leave_request.leave_type.name} leave"
                attendance.save()

                current_date += timedelta(days=1)

            logger.info(f"Synced leave request for {leave_request.user.username} from {leave_request.start_date} to {leave_request.end_date}")

        except Exception as e:
            logger.error(f"Error syncing leave with attendance: {e}")

    def sync_holiday_with_attendance(self, holiday):
        """
        Synchronize holiday with attendance records for all users
        """
        try:
            users = User.objects.filter(is_active=True)

            for user in users:
                attendance, created = Attendance.objects.get_or_create_today_attendance(
                    user, holiday.date
                )

                # Only update if not on leave or other special status
                if attendance.status in ['Not Marked', 'Yet to Clock In', 'Absent']:
                    attendance.status = 'Holiday'
                    attendance.is_holiday = True
                    attendance.holiday_name = holiday.name
                    attendance.regularization_reason = f"Holiday: {holiday.name}"
                    attendance.save()

            logger.info(f"Synced holiday '{holiday.name}' for {holiday.date}")

        except Exception as e:
            logger.error(f"Error syncing holiday with attendance: {e}")


class AttendanceRegularizationService:
    """
    Service to handle attendance regularization requests
    """

    def __init__(self):
        self.notification_service = AttendanceNotificationService()

    def submit_regularization_request(self, attendance, requested_status, reason, requested_by=None):
        """
        Submit a regularization request
        """
        try:
            attendance.request_regularization(requested_status, reason, requested_by)

            # Send notification to HR
            self.notification_service.send_regularization_notification(
                attendance, 'new_request'
            )

            logger.info(f"Regularization request submitted for {attendance.user.username} on {attendance.date}")
            return {'success': True, 'message': 'Regularization request submitted successfully'}

        except ValidationError as e:
            logger.warning(f"Validation error in regularization request: {e}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Error submitting regularization request: {e}")
            return {'success': False, 'error': 'An error occurred while submitting the request'}

    def process_regularization_request(self, attendance, action, processed_by, comments=None):
        """
        Process (approve/reject) a regularization request
        """
        try:
            if action == 'approve':
                attendance.approve_regularization(processed_by, comments)
                message = 'Regularization request approved'
            elif action == 'reject':
                attendance.reject_regularization(processed_by, comments)
                message = 'Regularization request rejected'
            else:
                return {'success': False, 'error': 'Invalid action'}

            # Send notification to employee
            self.notification_service.send_regularization_notification(
                attendance, action
            )

            logger.info(f"Regularization request {action}ed for {attendance.user.username} on {attendance.date}")
            return {'success': True, 'message': message}

        except ValidationError as e:
            logger.warning(f"Validation error in processing regularization: {e}")
            return {'success': False, 'error': str(e)}
        except Exception as e:
            logger.error(f"Error processing regularization request: {e}")
            return {'success': False, 'error': 'An error occurred while processing the request'}

    def get_pending_regularizations(self, manager=None):
        """
        Get pending regularization requests
        """
        try:
            queryset = Attendance.objects.get_regularization_requests(status='Pending')

            if manager and not manager.is_superuser:
                # Filter by team members if manager is specified
                team_members = User.objects.filter(
                    profile__manager=manager,
                    is_active=True
                )
                queryset = queryset.filter(user__in=team_members)

            return list(queryset)

        except Exception as e:
            logger.error(f"Error getting pending regularizations: {e}")
            return []


class AttendanceReportService:
    """
    Service to generate various attendance reports
    """

    def generate_monthly_report(self, year, month, users=None):
        """
        Generate monthly attendance report
        """
        try:
            report_data = Attendance.objects.get_monthly_attendance_report(year, month, users)

            # Add summary statistics
            summary = {
                'total_employees': len(report_data),
                'avg_attendance_percentage': 0,
                'total_working_days': 0,
                'total_present_days': 0,
                'total_absent_days': 0,
                'total_late_days': 0,
                'total_overtime_hours': 0
            }

            if report_data:
                summary['avg_attendance_percentage'] = sum(
                    item['attendance_percentage'] for item in report_data
                ) / len(report_data)

                summary['total_working_days'] = sum(item['total_days'] for item in report_data)
                summary['total_present_days'] = sum(item['present_days'] for item in report_data)
                summary['total_absent_days'] = sum(item['absent_days'] for item in report_data)
                summary['total_late_days'] = sum(item['late_days'] for item in report_data)
                summary['total_overtime_hours'] = sum(
                    item['total_overtime'] or 0 for item in report_data
                )

            return {
                'success': True,
                'data': list(report_data),
                'summary': summary,
                'month': month,
                'year': year
            }

        except Exception as e:
            logger.error(f"Error generating monthly report: {e}")
            return {'success': False, 'error': str(e)}

    def generate_daily_report(self, date=None):
        """
        Generate daily attendance report
        """
        try:
            if not date:
                IST = pytz.timezone('Asia/Kolkata')
                date = timezone.now().astimezone(IST).date()

            summary = Attendance.objects.get_attendance_summary(date)
            attendance_records = Attendance.objects.filter(date=date).select_related(
                'user', 'shift'
            ).order_by('user__username')

            return {
                'success': True,
                'date': date,
                'summary': summary,
                'records': list(attendance_records.values(
                    'user__username', 'user__first_name', 'user__last_name',
                    'status', 'clock_in_time', 'clock_out_time', 'total_hours',
                    'late_minutes', 'overtime_hours', 'location'
                ))
            }

        except Exception as e:
            logger.error(f"Error generating daily report: {e}")
            return {'success': False, 'error': str(e)}

    def generate_user_summary(self, user, start_date, end_date):
        """
        Generate attendance summary for a specific user
        """
        try:
            attendances = Attendance.objects.get_user_attendance_for_period(
                user, start_date, end_date
            )

            # Calculate summary statistics
            total_days = attendances.count()
            present_days = attendances.filter(
                status__in=['Present', 'Present & Late', 'Work From Home']
            ).count()
            absent_days = attendances.filter(status='Absent').count()
            late_days = attendances.filter(
                status__in=['Present & Late', 'Late']
            ).count()
            leave_days = attendances.filter(status='On Leave').count()

            total_hours = sum(
                att.total_hours for att in attendances if att.total_hours
            ) or 0
            total_overtime = sum(
                att.overtime_hours for att in attendances if att.overtime_hours
            ) or 0

            attendance_percentage = (present_days / total_days * 100) if total_days > 0 else 0

            return {
                'success': True,
                'user': {
                    'username': user.username,
                    'name': user.get_full_name()
                },
                'period': {
                    'start_date': start_date,
                    'end_date': end_date
                },
                'summary': {
                    'total_days': total_days,
                    'present_days': present_days,
                    'absent_days': absent_days,
                    'late_days': late_days,
                    'leave_days': leave_days,
                    'total_hours': float(total_hours),
                    'total_overtime': float(total_overtime),
                    'attendance_percentage': round(attendance_percentage, 2)
                },
                'records': list(attendances.values(
                    'date', 'status', 'clock_in_time', 'clock_out_time',
                    'total_hours', 'late_minutes', 'overtime_hours'
                ))
            }

        except Exception as e:
            logger.error(f"Error generating user summary: {e}")
            return {'success': False, 'error': str(e)}


class AttendanceAnalyticsService:
    """
    Service to provide attendance analytics and insights
    """

    def get_attendance_trends(self, start_date, end_date, users=None):
        """
        Get attendance trends over time
        """
        try:
            trends = Attendance.objects.get_attendance_trends(start_date, end_date, users)
            return {
                'success': True,
                'trends': list(trends)
            }
        except Exception as e:
            logger.error(f"Error getting attendance trends: {e}")
            return {'success': False, 'error': str(e)}

    def get_department_analytics(self, date=None):
        """
        Get attendance analytics by department
        """
        try:
            analytics = Attendance.objects.get_department_attendance(date=date)
            return {
                'success': True,
                'analytics': list(analytics)
            }
        except Exception as e:
            logger.error(f"Error getting department analytics: {e}")
            return {'success': False, 'error': str(e)}

    def get_late_arrival_analysis(self, start_date, end_date):
        """
        Analyze late arrival patterns
        """
        try:
            late_attendances = Attendance.objects.filter(
                date__range=[start_date, end_date],
                status__in=['Present & Late', 'Late'],
                late_minutes__gt=0
            ).select_related('user', 'shift')

            # Group by user
            user_late_data = {}
            for attendance in late_attendances:
                username = attendance.user.username
                if username not in user_late_data:
                    user_late_data[username] = {
                        'user': attendance.user.get_full_name(),
                        'late_days': 0,
                        'total_late_minutes': 0,
                        'avg_late_minutes': 0
                    }

                user_late_data[username]['late_days'] += 1
                user_late_data[username]['total_late_minutes'] += attendance.late_minutes

            # Calculate averages
            for username, data in user_late_data.items():
                data['avg_late_minutes'] = data['total_late_minutes'] / data['late_days']

            return {
                'success': True,
                'analysis': list(user_late_data.values())
            }

        except Exception as e:
            logger.error(f"Error getting late arrival analysis: {e}")
            return {'success': False, 'error': str(e)}


class AttendanceNotificationService:
    """
    Service to handle attendance-related notifications
    """

    def send_regularization_notification(self, attendance, notification_type):
        """
        Send regularization-related notifications
        """
        try:
            if notification_type == 'new_request':
                # Notify HR about new regularization request
                self._notify_hr_new_regularization(attendance)

            elif notification_type == 'approve':
                # Notify employee about approval
                self._notify_employee_regularization_status(attendance, 'approved')

            elif notification_type == 'reject':
                # Notify employee about rejection
                self._notify_employee_regularization_status(attendance, 'rejected')

        except Exception as e:
            logger.error(f"Error sending regularization notification: {e}")

    def send_daily_attendance_reminder(self, users=None):
        """
        Send daily attendance reminder to users who haven't marked attendance
        """
        try:
            IST = pytz.timezone('Asia/Kolkata')
            today = timezone.now().astimezone(IST).date()

            if not users:
                users = User.objects.filter(is_active=True)

            # Get users who haven't marked attendance yet
            users_without_attendance = []
            for user in users:
                try:
                    attendance = Attendance.objects.get(user=user, date=today)
                    if attendance.status in ['Not Marked', 'Yet to Clock In']:
                        users_without_attendance.append(user)
                except Attendance.DoesNotExist:
                    users_without_attendance.append(user)

            # Send reminders
            for user in users_without_attendance:
                self._send_attendance_reminder_email(user)

            logger.info(f"Sent attendance reminders to {len(users_without_attendance)} users")

        except Exception as e:
            logger.error(f"Error sending attendance reminders: {e}")

    def _notify_hr_new_regularization(self, attendance):
        """
        Notify HR about new regularization request
        """
        # Implementation depends on your notification system
        # This could be email, in-app notification, Slack, etc.
        pass

    def _notify_employee_regularization_status(self, attendance, status):
        """
        Notify employee about regularization status change
        """
        # Implementation depends on your notification system
        pass

    def _send_attendance_reminder_email(self, user):
        """
        Send attendance reminder email to user
        """
        # Implementation depends on your email system
        pass


class AttendanceBulkOperationService:
    """
    Service to handle bulk attendance operations
    """

    def bulk_mark_attendance(self, users, date, status, reason=None, marked_by=None):
        """
        Bulk mark attendance for multiple users
        """
        try:
            with transaction.atomic():
                created_attendances = Attendance.objects.bulk_create_attendance_records(
                    users, date, status, reason
                )

                # Update existing records
                existing_attendances = Attendance.objects.filter(
                    user__in=users,
                    date=date
                ).exclude(status=status)

                updated_count = 0
                for attendance in existing_attendances:
                    attendance.status = status
                    if reason:
                        attendance.regularization_reason = reason
                    if marked_by:
                        attendance.modified_by = marked_by
                    attendance.save()
                    updated_count += 1

                return {
                    'success': True,
                    'created': len(created_attendances),
                    'updated': updated_count
                }

        except Exception as e:
            logger.error(f"Error in bulk mark attendance: {e}")
            return {'success': False, 'error': str(e)}

    def bulk_apply_leave(self, users, start_date, end_date, leave_type, applied_by=None):
        """
        Bulk apply leave for multiple users
        """
        try:
            with transaction.atomic():
                processed_count = 0

                for user in users:
                    current_date = start_date
                    while current_date <= end_date:
                        attendance, created = Attendance.objects.get_or_create_today_attendance(
                            user, current_date
                        )

                        attendance.status = 'On Leave'
                        attendance.leave_type = leave_type
                        attendance.regularization_reason = f"Bulk applied: {leave_type} leave"

                        if applied_by:
                            attendance.modified_by = applied_by

                        attendance.save()
                        processed_count += 1
                        current_date += timedelta(days=1)

                return {
                    'success': True,
                    'processed': processed_count
                }

        except Exception as e:
            logger.error(f"Error in bulk apply leave: {e}")
            return {'success': False, 'error': str(e)}

    def bulk_update_status(self, attendance_ids, new_status, reason=None, updated_by=None):
        """
        Bulk update status for multiple attendance records
        """
        try:
            updated_count = Attendance.objects.bulk_update_status(
                attendance_ids, new_status, reason, updated_by
            )

            return {
                'success': True,
                'updated': updated_count
            }

        except Exception as e:
            logger.error(f"Error in bulk update status: {e}")
            return {'success': False, 'error': str(e)}


class AttendanceValidationService:
    """
    Service to handle attendance data validation and business rules
    """

    @staticmethod
    def validate_attendance_data(attendance_data):
        """
        Validate attendance data before saving
        """
        errors = []

        # Check required fields
        if not attendance_data.get('user'):
            errors.append("User is required")

        if not attendance_data.get('date'):
            errors.append("Date is required")

        # Validate clock times
        clock_in = attendance_data.get('clock_in_time')
        clock_out = attendance_data.get('clock_out_time')

        if clock_in and clock_out:
            if clock_out <= clock_in:
                errors.append("Clock out time must be after clock in time")

        # Validate date is not in future
        if attendance_data.get('date'):
            if attendance_data['date'] > timezone.now().date():
                errors.append("Cannot create attendance for future dates")

        # Validate total hours
        total_hours = attendance_data.get('total_hours')
        if total_hours and total_hours > 24:
            errors.append("Total hours cannot exceed 24 hours")

        return errors

    @staticmethod
    def can_edit_attendance(attendance, user):
        """
        Check if user can edit attendance record
        """
        # Own attendance can be edited within 7 days
        if attendance.user == user:
            days_diff = (timezone.now().date() - attendance.date).days
            return days_diff <= 7

        # HR and managers can edit
        if user.groups.filter(name__in=['HR', 'Manager']).exists():
            return True

        # Superuser can edit
        if user.is_superuser:
            return True

        return False

    @staticmethod
    def can_request_regularization(attendance):
        """
        Check if regularization can be requested for attendance
        """
        return attendance.can_request_regularization()


# Utility function to initialize all services
def get_attendance_services():
    """
    Get all attendance services in a dictionary
    """
    return {
        'auto_marking': AttendanceAutoMarkingService(),
        'integration': AttendanceIntegrationService(),
        'regularization': AttendanceRegularizationService(),
        'reports': AttendanceReportService(),
        'analytics': AttendanceAnalyticsService(),
        'notifications': AttendanceNotificationService(),
        'bulk_operations': AttendanceBulkOperationService(),
        'validation': AttendanceValidationService(),
    }
