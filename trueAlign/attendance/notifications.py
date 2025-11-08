# attendance/notifications.py
"""
Optimized Attendance Notification Service

This module provides comprehensive notification services for attendance-related events with:
- Multi-channel notification support (email, in-app, SMS)
- Template-based messaging
- Batch notification processing
- Performance optimization
- Comprehensive error handling and logging
- Configurable notification preferences
"""

import logging
from datetime import date, time
from typing import List, Dict, Optional, TYPE_CHECKING
from dataclasses import dataclass
from collections import defaultdict

from django.contrib.auth import get_user_model
# from django.contrib.auth.models import AbstractUser  # Not needed
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from django.utils.html import strip_tags
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from django.db.models import Q
from django.urls import reverse

import pytz

from trueAlign.models import Attendance
from .config import get_setting

logger = logging.getLogger('trueAlign.attendance.notifications')
User = get_user_model()
IST = pytz.timezone('Asia/Kolkata')

if TYPE_CHECKING:
    from django.contrib.auth.models import User as UserType
else:
    UserType = User


@dataclass
class NotificationResult:
    """Result of a notification operation"""
    success: bool
    message: str
    channels_sent: List[str]
    failed_channels: List[str]
    recipient_count: int
    errors: Optional[List[str]] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


@dataclass
class NotificationRecipient:
    """Notification recipient with preferences"""
    user: 'UserType'
    email: bool = True
    sms: bool = False
    push: bool = True
    in_app: bool = True


class NotificationChannel:
    """Base class for notification channels"""

    def __init__(self, name: str):
        self.name = name
        self.enabled = get_setting(f'notification_{name}_enabled', True)

    def send(self, recipient: 'UserType', subject: str, message: str, context: Optional[Dict] = None) -> bool:
        """Send notification through this channel"""
        raise NotImplementedError

    def batch_send(self, recipients: List['UserType'], subject: str, message: str, context: Optional[Dict] = None) -> Dict[str, bool]:
        """Send notifications to multiple recipients"""
        results = {}
        for recipient in recipients:
            results[recipient.username] = self.send(recipient, subject, message, context)
        return results


class EmailNotificationChannel(NotificationChannel):
    """Email notification channel"""

    def __init__(self):
        super().__init__('email')
        self.from_email = getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@company.com')
        self.template_base_path = 'attendance/emails/'

    def send(self, recipient: 'UserType', subject: str, message: str, context: Optional[Dict] = None) -> bool:
        """Send email notification"""
        if not self.enabled or not recipient.email:
            return False

        try:
            context = context or {}
            context.update({
                'recipient': recipient,
                'subject': subject,
                'message': message,
                'company_name': getattr(settings, 'COMPANY_NAME', 'Company'),
                'site_url': getattr(settings, 'SITE_URL', 'http://localhost:8000')
            })

            # Use template if specified in context
            if context.get('template'):
                html_content = render_to_string(
                    f"{self.template_base_path}{context['template']}.html",
                    context
                )
                text_content = render_to_string(
                    f"{self.template_base_path}{context['template']}.txt",
                    context
                )
            else:
                # Use default template
                html_content = render_to_string(
                    f"{self.template_base_path}default.html",
                    context
                )
                text_content = strip_tags(html_content)

            email = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=self.from_email,
                to=[recipient.email]
            )
            email.attach_alternative(html_content, "text/html")
            email.send()

            logger.info(f"Email sent successfully to {recipient.email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send email to {recipient.email}: {e}")
            return False

    def batch_send(self, recipients: List['UserType'], subject: str, message: str, context: Optional[Dict] = None) -> Dict[str, bool]:
        """Optimized batch email sending"""
        results = {}
        valid_recipients = [r for r in recipients if r.email]

        if not valid_recipients:
            return results

        try:
            # For batch operations, we can optimize by preparing the content once
            context = context or {}

            for recipient in valid_recipients:
                recipient_context = {**context, 'recipient': recipient}
                success = self.send(recipient, subject, message, recipient_context)
                results[recipient.username] = success

        except Exception as e:
            logger.error(f"Error in batch email sending: {e}")
            for recipient in valid_recipients:
                results[recipient.username] = False

        return results


class InAppNotificationChannel(NotificationChannel):
    """In-app notification channel using Django messages or custom notification model"""

    def __init__(self):
        super().__init__('in_app')

    def send(self, recipient: 'UserType', subject: str, message: str, context: Optional[Dict] = None) -> bool:
        """Send in-app notification"""
        if not self.enabled:
            return False

        try:
            # This would integrate with your notification system
            # For now, we'll use a simple implementation
            notification_data = {
                'user': recipient,
                'title': subject,
                'message': message,
                'type': context.get('notification_type', 'info') if context else 'info',
                'created_at': timezone.now(),
                'read': False
            }

            # Store in cache for now - you might want to use a proper notification model
            cache_key = f"notifications_{recipient.pk}"
            notifications = cache.get(cache_key, [])
            notifications.append(notification_data)
            cache.set(cache_key, notifications, 86400)  # 24 hours

            logger.info(f"In-app notification sent to {recipient.username}")
            return True

        except Exception as e:
            logger.error(f"Failed to send in-app notification to {recipient.username}: {e}")
            return False


class SMSNotificationChannel(NotificationChannel):
    """SMS notification channel"""

    def __init__(self):
        super().__init__('sms')
        self.api_key = getattr(settings, 'SMS_API_KEY', None)
        self.sender_id = getattr(settings, 'SMS_SENDER_ID', 'COMPANY')

    def send(self, recipient: 'UserType', subject: str, message: str, context: Optional[Dict] = None) -> bool:
        """Send SMS notification"""
        if not self.enabled or not self.api_key:
            return False

        # Phone number would need to be stored in User model or custom profile
        # For now, SMS notifications are disabled
        phone_number = None

        if not phone_number:
            return False  # SMS not configured

        try:
            # Implement SMS API integration here
            # This is a placeholder - integrate with your SMS provider
            sms_content = f"{subject}: {message}"

            # Example integration (replace with your SMS provider)
            # sms_result = send_sms(phone_number, sms_content, self.api_key)

            logger.info(f"SMS would be sent to {phone_number} for {recipient.username}")
            return True  # Return False if SMS actually fails

        except Exception as e:
            logger.error(f"Failed to send SMS to {recipient.username}: {e}")
            return False


class AttendanceNotificationService:
    """
    Comprehensive notification service for attendance system with multi-channel support
    """

    def __init__(self):
        self.channels = {
            'email': EmailNotificationChannel(),
            'in_app': InAppNotificationChannel(),
            'sms': SMSNotificationChannel()
        }

        self.notification_types = {
            'REGULARIZATION_REQUEST': 'regularization_request',
            'REGULARIZATION_APPROVED': 'regularization_approved',
            'REGULARIZATION_REJECTED': 'regularization_rejected',
            'LATE_ARRIVAL': 'late_arrival',
            'ABSENT_NOTIFICATION': 'absent_notification',
            'ATTENDANCE_REMINDER': 'attendance_reminder',
            'OVERTIME_ALERT': 'overtime_alert',
            'BULK_OPERATION': 'bulk_operation',
            'DAILY_SUMMARY': 'daily_summary',
            'WEEKLY_REPORT': 'weekly_report'
        }

    def notify_regularization_request(self, attendance: Attendance, employee: 'UserType',
                                    request_details: Optional[Dict] = None) -> NotificationResult:
        """
        Notify HR users when a regularization request is submitted
        """
        try:
            # Get HR users
            hr_users = User.objects.filter(
                groups__name='HR',
                is_active=True
            )

            if not hr_users.exists():
                return NotificationResult(
                    success=False,
                    message="No HR users found to notify",
                    channels_sent=[],
                    failed_channels=[],
                    recipient_count=0,
                    errors=["No HR users available"]
                )

            # Prepare notification content
            subject = f"Regularization Request - {employee.get_full_name()}"

            context = {
                'template': 'regularization_request',
                'notification_type': 'regularization_request',
                'employee': employee,
                'attendance': attendance,
                'attendance_date': attendance.date,
                'current_status': attendance.status,
                'requested_status': attendance.requested_status,
                'reason': attendance.regularization_reason,
                'submitted_at': attendance.last_regularization_date,
                'request_details': request_details or {},
                'action_url': self._get_regularization_action_url(attendance.pk)
            }

            message = (f"{employee.get_full_name()} has requested regularization for "
                      f"attendance on {attendance.date}. Current status: {attendance.status}, "
                      f"Requested status: {attendance.requested_status}")

            # Send notifications through all enabled channels
            successful_channels = []
            failed_channels = []

            for channel_name, channel in self.channels.items():
                if channel.enabled:
                    try:
                        results = channel.batch_send(list(hr_users), subject, message, context)
                        success_count = sum(1 for success in results.values() if success)

                        if success_count > 0:
                            successful_channels.append(channel_name)
                            logger.info(f"Regularization request notification sent via {channel_name} to {success_count} HR users")
                        else:
                            failed_channels.append(channel_name)

                    except Exception as e:
                        failed_channels.append(channel_name)
                        logger.error(f"Error sending regularization notification via {channel_name}: {e}")

            # Log the notification
            self._log_notification(
                'regularization_request',
                employee.username,
                list(hr_users.values_list('username', flat=True)),
                successful_channels
            )

            return NotificationResult(
                success=len(successful_channels) > 0,
                message=f"Regularization request notification sent to {hr_users.count()} HR users",
                channels_sent=successful_channels,
                failed_channels=failed_channels,
                recipient_count=hr_users.count()
            )

        except Exception as e:
            logger.error(f"Error in notify_regularization_request: {e}")
            return NotificationResult(
                success=False,
                message="Failed to send regularization request notification",
                channels_sent=[],
                failed_channels=list(self.channels.keys()),
                recipient_count=0,
                errors=[str(e)]
            )

    def notify_regularization_status(self, attendance: Attendance, action: str,
                                   processed_by: 'UserType', comments: Optional[str] = None) -> NotificationResult:
        """
        Notify employee about regularization request status (approved/rejected)
        """
        try:
            employee = attendance.user

            if not employee or not employee.is_active:
                return NotificationResult(
                    success=False,
                    message="Employee not found or inactive",
                    channels_sent=[],
                    failed_channels=[],
                    recipient_count=0
                )

            # Prepare notification content
            subject = f"Regularization Request {action.title()} - {attendance.date}"

            context = {
                'template': 'regularization_status',
                'notification_type': f'regularization_{action}',
                'employee': employee,
                'attendance': attendance,
                'attendance_date': attendance.date,
                'action': action,
                'processed_by': processed_by,
                'comments': comments,
                'processed_at': timezone.now(),
                'current_status': attendance.status
            }

            if action == 'approve':
                message = (f"Your regularization request for {attendance.date} has been approved. "
                          f"Status updated to: {attendance.status}")
            else:
                message = (f"Your regularization request for {attendance.date} has been rejected. "
                          f"Reason: {comments or 'No reason provided'}")

            # Send notifications
            successful_channels = []
            failed_channels = []

            for channel_name, channel in self.channels.items():
                if channel.enabled:
                    try:
                        success = channel.send(employee, subject, message, context)
                        if success:
                            successful_channels.append(channel_name)
                        else:
                            failed_channels.append(channel_name)
                    except Exception as e:
                        failed_channels.append(channel_name)
                        logger.error(f"Error sending status notification via {channel_name}: {e}")

            self._log_notification(
                f'regularization_{action}',
                processed_by.username,
                [employee.username],
                successful_channels
            )

            return NotificationResult(
                success=len(successful_channels) > 0,
                message=f"Regularization status notification sent to {employee.username}",
                channels_sent=successful_channels,
                failed_channels=failed_channels,
                recipient_count=1
            )

        except Exception as e:
            logger.error(f"Error in notify_regularization_status: {e}")
            return NotificationResult(
                success=False,
                message="Failed to send regularization status notification",
                channels_sent=[],
                failed_channels=list(self.channels.keys()),
                recipient_count=0,
                errors=[str(e)]
            )

    def send_attendance_reminders(self, target_date: Optional[date] = None,
                                time_threshold: Optional[time] = None) -> NotificationResult:
        """
        Send attendance reminders to users who haven't marked attendance
        """
        if not target_date:
            target_date = timezone.now().astimezone(IST).date()

        if not time_threshold:
            time_threshold = time(9, 30)  # 9:30 AM default

        try:
            # Get users who haven't marked attendance or are "Yet to Clock In"
            users_to_remind = self._get_users_needing_reminder(target_date)

            if not users_to_remind:
                return NotificationResult(
                    success=True,
                    message="No users need attendance reminders",
                    channels_sent=[],
                    failed_channels=[],
                    recipient_count=0
                )

            # Prepare notification content
            subject = f"Attendance Reminder - {target_date.strftime('%B %d, %Y')}"
            message = (f"Please mark your attendance for today ({target_date}). "
                      f"Don't forget to clock in when you start your work.")

            context = {
                'template': 'attendance_reminder',
                'notification_type': 'attendance_reminder',
                'date': target_date,
                'attendance_url': self._get_attendance_url()
            }

            # Send notifications
            successful_channels = []
            failed_channels = []
            total_sent = 0

            for channel_name, channel in self.channels.items():
                if channel.enabled:
                    try:
                        results = channel.batch_send(users_to_remind, subject, message, context)
                        success_count = sum(1 for success in results.values() if success)

                        if success_count > 0:
                            successful_channels.append(channel_name)
                            total_sent = max(total_sent, success_count)
                        else:
                            failed_channels.append(channel_name)

                    except Exception as e:
                        failed_channels.append(channel_name)
                        logger.error(f"Error sending reminders via {channel_name}: {e}")

            logger.info(f"Sent attendance reminders to {len(users_to_remind)} users")

            return NotificationResult(
                success=len(successful_channels) > 0,
                message=f"Attendance reminders sent to {len(users_to_remind)} users",
                channels_sent=successful_channels,
                failed_channels=failed_channels,
                recipient_count=len(users_to_remind)
            )

        except Exception as e:
            logger.error(f"Error in send_attendance_reminders: {e}")
            return NotificationResult(
                success=False,
                message="Failed to send attendance reminders",
                channels_sent=[],
                failed_channels=list(self.channels.keys()),
                recipient_count=0,
                errors=[str(e)]
            )

    def notify_late_arrivals(self, target_date: Optional[date] = None,
                           threshold_minutes: int = 30) -> NotificationResult:
        """
        Notify managers about team members' late arrivals
        """
        if not target_date:
            target_date = timezone.now().astimezone(IST).date()

        try:
            # Get late arrivals
            late_attendances = Attendance.objects.filter(
                date=target_date,
                status__in=['Present & Late', 'Late'],
                late_minutes__gte=threshold_minutes
            ).select_related('user', 'shift')

            if not late_attendances.exists():
                return NotificationResult(
                    success=True,
                    message="No late arrivals to report",
                    channels_sent=[],
                    failed_channels=[],
                    recipient_count=0
                )

            # Send to HR users (no manager tracking in system)
            hr_users = User.objects.filter(groups__name='HR', is_active=True)
            
            if not hr_users.exists():
                return NotificationResult(
                    success=False,
                    message="No HR users found to notify",
                    channels_sent=[],
                    failed_channels=[],
                    recipient_count=0
                )

            # Send notifications to HR users
            successful_channels = []
            failed_channels = []
            
            subject = f"Late Arrival Alert - {target_date}"
            
            late_employees = []
            for att in late_attendances:
                late_employees.append({
                    'name': att.user.get_full_name(),
                    'username': att.user.username,
                    'late_minutes': att.late_minutes,
                    'clock_in_time': att.clock_in_time
                })

            message = (f"{late_attendances.count()} employees arrived late today "
                      f"(more than {threshold_minutes} minutes)")

            # Send to all HR users
            for hr_user in hr_users:
                context = {
                    'template': 'late_arrival_alert',
                    'notification_type': 'late_arrival',
                    'recipient': hr_user,
                    'date': target_date,
                    'late_employees': late_employees,
                    'threshold_minutes': threshold_minutes
                }

                for channel_name, channel in self.channels.items():
                    if channel.enabled:
                        try:
                            success = channel.send(hr_user, subject, message, context)
                            if success and channel_name not in successful_channels:
                                successful_channels.append(channel_name)
                        except Exception as e:
                            if channel_name not in failed_channels:
                                failed_channels.append(channel_name)
                            logger.error(f"Error sending late arrival alert via {channel_name}: {e}")

            return NotificationResult(
                success=len(successful_channels) > 0,
                message=f"Late arrival notifications sent to {hr_users.count()} HR users",
                channels_sent=successful_channels,
                failed_channels=failed_channels,
                recipient_count=hr_users.count()
            )

        except Exception as e:
            logger.error(f"Error in notify_late_arrivals: {e}")
            return NotificationResult(
                success=False,
                message="Failed to send late arrival notifications",
                channels_sent=[],
                failed_channels=list(self.channels.keys()),
                recipient_count=0,
                errors=[str(e)]
            )

    def send_daily_summary(self, target_date: Optional[date] = None, recipients: Optional[List['UserType']] = None) -> NotificationResult:
        """
        Send weekly attendance summary to HR and managers
        """
        if not target_date:
            target_date = timezone.now().astimezone(IST).date()

        try:
            if not recipients:
                # Get HR users and managers
                recipients = list(User.objects.filter(
                    Q(groups__name__in=['HR', 'Manager']) | Q(is_superuser=True),
                    is_active=True
                ).distinct())

            if not recipients:
                return NotificationResult(
                    success=False,
                    message="No recipients found for daily summary",
                    channels_sent=[],
                    failed_channels=[],
                    recipient_count=0
                )

            # Get attendance summary data
            summary_data = self._get_attendance_summary(target_date)

            subject = f"Daily Attendance Summary - {target_date.strftime('%B %d, %Y')}"

            context = {
                'template': 'daily_summary',
                'notification_type': 'daily_summary',
                'date': target_date,
                'summary': summary_data,
                'dashboard_url': self._get_dashboard_url()
            }

            message = (f"Daily attendance summary for {target_date}: "
                      f"{summary_data.get('present_count', 0)} present, "
                      f"{summary_data.get('absent_count', 0)} absent, "
                      f"{summary_data.get('late_count', 0)} late arrivals")

            # Send notifications
            successful_channels = []
            failed_channels = []

            for channel_name, channel in self.channels.items():
                if channel.enabled:
                    try:
                        results = channel.batch_send(recipients, subject, message, context)
                        success_count = sum(1 for success in results.values() if success)

                        if success_count > 0:
                            successful_channels.append(channel_name)
                        else:
                            failed_channels.append(channel_name)

                    except Exception as e:
                        failed_channels.append(channel_name)
                        logger.error(f"Error sending daily summary via {channel_name}: {e}")

            return NotificationResult(
                success=len(successful_channels) > 0,
                message=f"Daily summary sent to {len(recipients)} recipients",
                channels_sent=successful_channels,
                failed_channels=failed_channels,
                recipient_count=len(recipients)
            )

        except Exception as e:
            logger.error(f"Error in send_daily_summary: {e}")
            return NotificationResult(
                success=False,
                message="Failed to send daily summary",
                channels_sent=[],
                failed_channels=list(self.channels.keys()),
                recipient_count=0,
                errors=[str(e)]
            )

    def notify_bulk_operation(self, operation_type: str, performed_by: User,
                            affected_users: List[User], details: Dict) -> NotificationResult:
        """
        Notify about bulk attendance operations
        """
        try:
            # Notify affected users about the bulk operation
            subject = f"Attendance Update - {operation_type.replace('_', ' ').title()}"

            context = {
                'template': 'bulk_operation',
                'notification_type': 'bulk_operation',
                'operation_type': operation_type,
                'performed_by': performed_by,
                'details': details,
                'performed_at': timezone.now()
            }

            message = (f"Your attendance has been updated by {performed_by.get_full_name()} "
                      f"as part of a bulk {operation_type.replace('_', ' ')} operation.")

            # Send notifications to affected users
            successful_channels = []
            failed_channels = []

            for channel_name, channel in self.channels.items():
                if channel.enabled:
                    try:
                        results = channel.batch_send(affected_users, subject, message, context)
                        success_count = sum(1 for success in results.values() if success)

                        if success_count > 0:
                            successful_channels.append(channel_name)
                        else:
                            failed_channels.append(channel_name)

                    except Exception as e:
                        failed_channels.append(channel_name)
                        logger.error(f"Error sending bulk operation notification via {channel_name}: {e}")

            return NotificationResult(
                success=len(successful_channels) > 0,
                message=f"Bulk operation notifications sent to {len(affected_users)} users",
                channels_sent=successful_channels,
                failed_channels=failed_channels,
                recipient_count=len(affected_users)
            )

        except Exception as e:
            logger.error(f"Error in notify_bulk_operation: {e}")
            return NotificationResult(
                success=False,
                message="Failed to send bulk operation notifications",
                channels_sent=[],
                failed_channels=list(self.channels.keys()),
                recipient_count=0,
                errors=[str(e)]
            )

    # Helper methods
    def _get_users_needing_reminder(self, target_date: date) -> List[User]:
        """Get users who need attendance reminders"""
        # Users with no attendance record or "Yet to Clock In" status
        users_with_no_attendance = Attendance.objects.get_users_without_attendance(target_date)

        users_yet_to_clock = User.objects.filter(
            attendance_records__date=target_date,
            attendance_records__status='Yet to Clock In',
            is_active=True
        )

        # Combine and deduplicate
        all_users = list(users_with_no_attendance) + list(users_yet_to_clock)
        unique_users = list({user.id: user for user in all_users}.values())

        return unique_users

    def _get_attendance_summary(self, target_date: date) -> Dict:
        """Get attendance summary for a specific date"""
        return Attendance.objects.get_attendance_summary(target_date)

    def _get_regularization_action_url(self, attendance_id: int) -> str:
        """Get URL for regularization action"""
        try:
            return reverse('attendance:process_regularization', kwargs={'attendance_id': attendance_id})
        except Exception:
            return '/attendance/hr/regularization-requests/'

    def _get_attendance_url(self) -> str:
        """Get attendance dashboard URL"""
        try:
            return reverse('attendance:dashboard')
        except Exception:
            return '/attendance/'

    def _get_dashboard_url(self) -> str:
        """Get HR dashboard URL"""
        try:
            return reverse('attendance:hr_dashboard')
        except Exception:
            return '/attendance/hr/dashboard/'

    def _log_notification(self, notification_type: str, sender: str,
                         recipients: List[str], channels: List[str]):
        """Log notification details"""
        logger.info(
            f"Notification sent - Type: {notification_type}, "
            f"Sender: {sender}, Recipients: {len(recipients)}, "
            f"Channels: {', '.join(channels)}"
        )

    def get_notification_preferences(self, user: User) -> Dict[str, bool]:
        """Get user's notification preferences"""
        # This would integrate with your user preference system
        # For now, return default preferences
        return {
            'email': True,
            'in_app': True,
            'sms': False,
            'push': True
        }

    def update_notification_preferences(self, user: 'UserType', preferences: Dict[str, bool]) -> bool:
        """Update user's notification preferences"""
        try:
            # This would integrate with your user preference system
            # For now, store in cache
            cache_key = f"notification_prefs_{user.pk}"
            cache.set(cache_key, preferences, 86400 * 30)  # 30 days

            logger.info(f"Updated notification preferences for {user.username}")
            return True

        except Exception as e:
            logger.error(f"Error updating notification preferences for {user.username}: {e}")
            return False


# Utility functions
def send_test_notification(user: 'UserType', channel: str = 'email') -> NotificationResult:
    """Send a test notification to verify configuration"""
    try:
        service = AttendanceNotificationService()

        if channel not in service.channels:
            return NotificationResult(
                success=False,
                message=f"Unknown notification channel: {channel}",
                channels_sent=[],
                failed_channels=[channel],
                recipient_count=0
            )

        channel_obj = service.channels[channel]
        subject = "Test Notification - Attendance System"
        message = "This is a test notification to verify your notification settings."

        context = {
            'template': 'test_notification',
            'notification_type': 'test',
            'test_time': timezone.now()
        }

        success = channel_obj.send(user, subject, message, context)

        return NotificationResult(
            success=success,
            message=f"Test notification sent via {channel}",
            channels_sent=[channel] if success else [],
            failed_channels=[] if success else [channel],
            recipient_count=1
        )

    except Exception as e:
        logger.error(f"Error sending test notification: {e}")
        return NotificationResult(
            success=False,
            message=f"Failed to send test notification: {str(e)}",
            channels_sent=[],
            failed_channels=[channel],
            recipient_count=0,
            errors=[str(e)]
        )
