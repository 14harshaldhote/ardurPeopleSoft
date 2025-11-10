"""
Notification service for the Appraisal module.
Handles all notification-related functionality for the appraisal system.
"""
import logging
from typing import Optional, Dict, Any
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.core.exceptions import ValidationError

from trueAlign.models import Notification

User = get_user_model()
logger = logging.getLogger(__name__)


class NotificationChannel:
    """Base class for notification channels"""
    
    @classmethod
    def send_notification(
        cls,
        recipient: User,
        title: str,
        message: str,
        notification_type: str,
        reference_id: str = None,
        url: str = None
    ) -> bool:
        """
        Send a notification to a user
        
        Args:
            recipient: User who will receive the notification
            title: Notification title
            message: Notification message
            notification_type: Type of notification
            reference_id: Optional reference ID for the related object
            url: Optional URL for the notification action
            
        Returns:
            bool: True if notification was sent successfully, False otherwise
        """
        try:
            if not recipient or not recipient.is_active:
                logger.warning(f"Cannot send notification to inactive or invalid user")
                return False
                
            Notification.objects.create(
                recipient=recipient,
                title=title,
                message=message,
                module='appraisal',
                reference_id=reference_id,
                url=url
            )
            logger.info(f"{notification_type} notification sent to {recipient.username}")
            return True
        except Exception as e:
            logger.error(f"Error sending {notification_type} notification: {str(e)}")
            return False


class AppraisalNotificationService:
    """Service for handling all appraisal-related notifications"""
    
    @staticmethod
    def _get_appraisal_url(appraisal_id: int) -> str:
        """Generate URL for an appraisal"""
        try:
            return reverse('appraisal:appraisal_detail', kwargs={'pk': appraisal_id})
        except Exception:
            return f"/appraisal/{appraisal_id}/"
    
    @classmethod
    def notify_appraisal_created(
        cls,
        appraisal_id: int,
        recipient: User,
        creator: User,
        title: str
    ) -> bool:
        """Notify when a new appraisal is created"""
        try:
            url = cls._get_appraisal_url(appraisal_id)
            creator_name = creator.get_full_name() or creator.username
            message = f"A new appraisal '{title}' has been created by {creator_name}."
            
            return NotificationChannel.send_notification(
                recipient=recipient,
                title="New Appraisal Created",
                message=message,
                notification_type='appraisal_created',
                reference_id=str(appraisal_id),
                url=url
            )
        except Exception as e:
            logger.error(f"Error in notify_appraisal_created: {str(e)}")
            return False
    
    @classmethod
    def notify_appraisal_submitted(
        cls,
        appraisal_id: int,
        recipient: User,
        submitter: User,
        title: str
    ) -> bool:
        """Notify when an appraisal is submitted for review"""
        try:
            url = cls._get_appraisal_url(appraisal_id)
            submitter_name = submitter.get_full_name() or submitter.username
            message = f"Appraisal '{title}' has been submitted by {submitter_name} for your review."
            
            return NotificationChannel.send_notification(
                recipient=recipient,
                title="Appraisal Submitted for Review",
                message=message,
                notification_type='appraisal_submitted',
                reference_id=str(appraisal_id),
                url=url
            )
        except Exception as e:
            logger.error(f"Error in notify_appraisal_submitted: {str(e)}")
            return False
    
    @classmethod
    def notify_appraisal_approved(
        cls,
        appraisal_id: int,
        recipient: User,
        approver: User,
        title: str,
        stage: str = "Manager"
    ) -> bool:
        """Notify when an appraisal is approved at any stage"""
        try:
            url = cls._get_appraisal_url(appraisal_id)
            approver_name = approver.get_full_name() or approver.username
            message = f"Your appraisal '{title}' has been approved by {stage} ({approver_name})."
            
            return NotificationChannel.send_notification(
                recipient=recipient,
                title=f"Appraisal Approved by {stage}",
                message=message,
                notification_type='appraisal_approved',
                reference_id=str(appraisal_id),
                url=url
            )
        except Exception as e:
            logger.error(f"Error in notify_appraisal_approved: {str(e)}")
            return False
    
    @classmethod
    def notify_appraisal_rejected(
        cls,
        appraisal_id: int,
        recipient: User,
        rejector: User,
        title: str,
        comments: str = "",
        stage: str = "Manager"
    ) -> bool:
        """Notify when an appraisal is rejected"""
        try:
            url = cls._get_appraisal_url(appraisal_id)
            rejector_name = rejector.get_full_name() or rejector.username
            message = f"Your appraisal '{title}' has been rejected by {stage} ({rejector_name})."
            
            if comments:
                message += f"\n\nComments: {comments}"
            
            return NotificationChannel.send_notification(
                recipient=recipient,
                title=f"Appraisal Rejected by {stage}",
                message=message,
                notification_type='appraisal_rejected',
                reference_id=str(appraisal_id),
                url=url
            )
        except Exception as e:
            logger.error(f"Error in notify_appraisal_rejected: {str(e)}")
            return False
    
    @classmethod
    def notify_appraisal_final_approval(
        cls,
        appraisal_id: int,
        recipient: User,
        title: str
    ) -> bool:
        """Notify when an appraisal receives final approval"""
        try:
            url = cls._get_appraisal_url(appraisal_id)
            message = f"Congratulations! Your appraisal '{title}' has been fully approved and completed."
            
            return NotificationChannel.send_notification(
                recipient=recipient,
                title="Appraisal Fully Approved",
                message=message,
                notification_type='appraisal_final_approval',
                reference_id=str(appraisal_id),
                url=url
            )
        except Exception as e:
            logger.error(f"Error in notify_appraisal_final_approval: {str(e)}")
            return False
    
    @classmethod
    def notify_next_reviewer(
        cls,
        appraisal_id: int,
        recipient: User,
        title: str,
        stage: str
    ) -> bool:
        """Notify the next reviewer in the workflow"""
        try:
            url = cls._get_appraisal_url(appraisal_id)
            message = f"Appraisal '{title}' is now pending your review at the {stage} stage."
            
            return NotificationChannel.send_notification(
                recipient=recipient,
                title=f"New Appraisal for {stage} Review",
                message=message,
                notification_type='appraisal_review_pending',
                reference_id=str(appraisal_id),
                url=url
            )
        except Exception as e:
            logger.error(f"Error in notify_next_reviewer: {str(e)}")
            return False
    
    @classmethod
    def notify_appraisal_updated(
        cls,
        appraisal_id: int,
        recipient: User,
        updater: User,
        title: str
    ) -> bool:
        """Notify when an appraisal is updated"""
        try:
            url = cls._get_appraisal_url(appraisal_id)
            updater_name = updater.get_full_name() or updater.username
            message = f"Appraisal '{title}' has been updated by {updater_name}."
            
            return NotificationChannel.send_notification(
                recipient=recipient,
                title="Appraisal Updated",
                message=message,
                notification_type='appraisal_updated',
                reference_id=str(appraisal_id),
                url=url
            )
        except Exception as e:
            logger.error(f"Error in notify_appraisal_updated: {str(e)}")
            return False


# Singleton instance
appraisal_notification_service = AppraisalNotificationService()
