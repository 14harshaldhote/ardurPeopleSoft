"""
Enhanced notification system for leave management
"""
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.utils import timezone
from django.contrib.auth.models import User
from typing import List, Dict, Any
import logging

from trueAlign.models import LeaveRequest, CompOffRequest

logger = logging.getLogger(__name__)

class LeaveNotificationService:
    """Centralized notification service for leave management"""
    
    @staticmethod
    def send_leave_application_notification(leave_request: LeaveRequest):
        """Send notification when leave is applied"""
        if not leave_request.approver:
            return
        
        try:
            subject = f"New Leave Request - {leave_request.user.get_full_name()}"
            
            context = {
                'leave_request': leave_request,
                'employee': leave_request.user,
                'approver': leave_request.approver,
                'leave_type': leave_request.leave_type.name,
                'start_date': leave_request.start_date,
                'end_date': leave_request.end_date,
                'days': leave_request.leave_days,
                'reason': leave_request.reason,
            }
            
            # Render email templates
            html_message = render_to_string('leave_management/emails/leave_application.html', context)
            plain_message = render_to_string('leave_management/emails/leave_application.txt', context)
            
            send_mail(
                subject=subject,
                message=plain_message,
                html_message=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[leave_request.approver.email],
                fail_silently=False
            )
            
            logger.info(f"Leave application notification sent to {leave_request.approver.email}")
            
        except Exception as e:
            logger.error(f"Failed to send leave application notification: {str(e)}")
    
    @staticmethod
    def send_leave_approval_notification(leave_request: LeaveRequest, approver: User, comments: str = ""):
        """Send notification when leave is approved"""
        try:
            subject = f"Leave Request Approved - {leave_request.leave_type.name}"
            
            context = {
                'leave_request': leave_request,
                'employee': leave_request.user,
                'approver': approver,
                'comments': comments,
                'leave_type': leave_request.leave_type.name,
                'start_date': leave_request.start_date,
                'end_date': leave_request.end_date,
                'days': leave_request.leave_days,
            }
            
            html_message = render_to_string('leave_management/emails/leave_approved.html', context)
            plain_message = render_to_string('leave_management/emails/leave_approved.txt', context)
            
            send_mail(
                subject=subject,
                message=plain_message,
                html_message=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[leave_request.user.email],
                fail_silently=False
            )
            
            logger.info(f"Leave approval notification sent to {leave_request.user.email}")
            
        except Exception as e:
            logger.error(f"Failed to send leave approval notification: {str(e)}")
    
    @staticmethod
    def send_leave_rejection_notification(leave_request: LeaveRequest, approver: User, reason: str):
        """Send notification when leave is rejected"""
        try:
            subject = f"Leave Request Rejected - {leave_request.leave_type.name}"
            
            context = {
                'leave_request': leave_request,
                'employee': leave_request.user,
                'approver': approver,
                'rejection_reason': reason,
                'leave_type': leave_request.leave_type.name,
                'start_date': leave_request.start_date,
                'end_date': leave_request.end_date,
                'days': leave_request.leave_days,
            }
            
            html_message = render_to_string('leave_management/emails/leave_rejected.html', context)
            plain_message = render_to_string('leave_management/emails/leave_rejected.txt', context)
            
            send_mail(
                subject=subject,
                message=plain_message,
                html_message=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[leave_request.user.email],
                fail_silently=False
            )
            
            logger.info(f"Leave rejection notification sent to {leave_request.user.email}")
            
        except Exception as e:
            logger.error(f"Failed to send leave rejection notification: {str(e)}")
    
    @staticmethod
    def send_leave_cancellation_notification(leave_request: LeaveRequest, cancelled_by: User, reason: str = ""):
        """Send notification when leave is cancelled"""
        try:
            subject = f"Leave Request Cancelled - {leave_request.leave_type.name}"
            
            context = {
                'leave_request': leave_request,
                'employee': leave_request.user,
                'cancelled_by': cancelled_by,
                'cancellation_reason': reason,
                'leave_type': leave_request.leave_type.name,
                'start_date': leave_request.start_date,
                'end_date': leave_request.end_date,
                'days': leave_request.leave_days,
            }
            
            html_message = render_to_string('leave_management/emails/leave_cancelled.html', context)
            plain_message = render_to_string('leave_management/emails/leave_cancelled.txt', context)
            
            # Notify both employee and approver
            recipients = [leave_request.user.email]
            if leave_request.approver and leave_request.approver.email != leave_request.user.email:
                recipients.append(leave_request.approver.email)
            
            send_mail(
                subject=subject,
                message=plain_message,
                html_message=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=recipients,
                fail_silently=False
            )
            
            logger.info(f"Leave cancellation notification sent to {recipients}")
            
        except Exception as e:
            logger.error(f"Failed to send leave cancellation notification: {str(e)}")
    
    @staticmethod
    def send_leave_reminder_notifications():
        """Send reminder notifications for pending approvals"""
        try:
            # Get pending requests older than 2 days
            cutoff_date = timezone.now() - timezone.timedelta(days=2)
            pending_requests = LeaveRequest.objects.filter(
                status='Pending',
                created_at__lte=cutoff_date
            ).select_related('user', 'approver', 'leave_type')
            
            for leave_request in pending_requests:
                if not leave_request.approver:
                    continue
                
                subject = f"Reminder: Pending Leave Approval - {leave_request.user.get_full_name()}"
                
                context = {
                    'leave_request': leave_request,
                    'employee': leave_request.user,
                    'approver': leave_request.approver,
                    'days_pending': (timezone.now().date() - leave_request.created_at.date()).days,
                }
                
                html_message = render_to_string('leave_management/emails/leave_reminder.html', context)
                plain_message = render_to_string('leave_management/emails/leave_reminder.txt', context)
                
                send_mail(
                    subject=subject,
                    message=plain_message,
                    html_message=html_message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[leave_request.approver.email],
                    fail_silently=False
                )
            
            logger.info(f"Sent {pending_requests.count()} reminder notifications")
            
        except Exception as e:
            logger.error(f"Failed to send reminder notifications: {str(e)}")
    
    @staticmethod
    def send_balance_low_notification(user: User, leave_type, remaining_balance: float):
        """Send notification when leave balance is low"""
        try:
            if remaining_balance > 2:  # Only notify if balance is 2 days or less
                return
            
            subject = f"Low Leave Balance Alert - {leave_type.name}"
            
            context = {
                'user': user,
                'leave_type': leave_type.name,
                'remaining_balance': remaining_balance,
            }
            
            html_message = render_to_string('leave_management/emails/balance_low.html', context)
            plain_message = render_to_string('leave_management/emails/balance_low.txt', context)
            
            send_mail(
                subject=subject,
                message=plain_message,
                html_message=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                fail_silently=False
            )
            
            logger.info(f"Low balance notification sent to {user.email}")
            
        except Exception as e:
            logger.error(f"Failed to send low balance notification: {str(e)}")
    
    @staticmethod
    def send_comp_off_notification(comp_off_request: CompOffRequest, action: str):
        """Send comp-off related notifications"""
        try:
            if action == 'applied':
                subject = f"Comp-off Request Submitted - {comp_off_request.worked_date}"
                template_prefix = 'comp_off_applied'
                recipient = comp_off_request.approver.email if comp_off_request.approver else None
            elif action == 'approved':
                subject = f"Comp-off Request Approved - {comp_off_request.worked_date}"
                template_prefix = 'comp_off_approved'
                recipient = comp_off_request.user.email
            elif action == 'rejected':
                subject = f"Comp-off Request Rejected - {comp_off_request.worked_date}"
                template_prefix = 'comp_off_rejected'
                recipient = comp_off_request.user.email
            else:
                return
            
            if not recipient:
                return
            
            context = {
                'comp_off_request': comp_off_request,
                'user': comp_off_request.user,
                'approver': comp_off_request.approver,
            }
            
            html_message = render_to_string(f'leave_management/emails/{template_prefix}.html', context)
            plain_message = render_to_string(f'leave_management/emails/{template_prefix}.txt', context)
            
            send_mail(
                subject=subject,
                message=plain_message,
                html_message=html_message,
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[recipient],
                fail_silently=False
            )
            
            logger.info(f"Comp-off {action} notification sent to {recipient}")
            
        except Exception as e:
            logger.error(f"Failed to send comp-off notification: {str(e)}")

# Celery tasks for async notifications (if Celery is available)
try:
    from celery import shared_task
    
    @shared_task
    def send_leave_notification_async(notification_type: str, **kwargs):
        """Async task for sending notifications"""
        service = LeaveNotificationService()
        
        if notification_type == 'application':
            leave_request = LeaveRequest.objects.get(id=kwargs['leave_request_id'])
            service.send_leave_application_notification(leave_request)
        elif notification_type == 'approval':
            leave_request = LeaveRequest.objects.get(id=kwargs['leave_request_id'])
            approver = User.objects.get(id=kwargs['approver_id'])
            service.send_leave_approval_notification(leave_request, approver, kwargs.get('comments', ''))
        elif notification_type == 'rejection':
            leave_request = LeaveRequest.objects.get(id=kwargs['leave_request_id'])
            approver = User.objects.get(id=kwargs['approver_id'])
            service.send_leave_rejection_notification(leave_request, approver, kwargs['reason'])
        elif notification_type == 'cancellation':
            leave_request = LeaveRequest.objects.get(id=kwargs['leave_request_id'])
            cancelled_by = User.objects.get(id=kwargs['cancelled_by_id'])
            service.send_leave_cancellation_notification(leave_request, cancelled_by, kwargs.get('reason', ''))
    
    @shared_task
    def send_daily_reminders():
        """Daily task to send reminder notifications"""
        LeaveNotificationService.send_leave_reminder_notifications()
        
except ImportError:
    # Celery not available, notifications will be sent synchronously
    pass
