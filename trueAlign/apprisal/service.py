"""
Appraisal Service Layer
Handles business logic for appraisal operations with notification triggers
"""

import logging
from typing import Dict, List, Optional, Tuple, Union
from datetime import date
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.db import transaction
from django.db import models
from django.utils import timezone
from django.core.exceptions import ValidationError, PermissionDenied

from trueAlign.models import (
    Appraisal, AppraisalItem, AppraisalAttachment, AppraisalWorkflow, Notification
)
from .notifications import AppraisalNotificationService

logger = logging.getLogger('trueAlign.apprisal.service')
User = get_user_model()


class AppraisalService:
    """
    Service class for appraisal operations with business logic and notifications
    """
    
    def __init__(self):
        self.notification_service = AppraisalNotificationService()
    
    # Status Transition Logic
    VALID_TRANSITIONS = {
        'draft': ['submitted'],
        'submitted': ['manager_review', 'rejected'],
        'manager_review': ['hr_review', 'rejected'],
        'hr_review': ['approved', 'rejected']
    }
    
    def is_valid_transition(self, from_status: str, to_status: str) -> bool:
        """Validate status transition"""
        return to_status in self.VALID_TRANSITIONS.get(from_status, [])
    
    # Permission Checks
    def can_user_create_appraisal(self, user: User) -> bool:
        """Check if user can create appraisal"""
        return user.is_active
    
    def can_user_edit_appraisal(self, user: User, appraisal: Appraisal) -> bool:
        """Check if user can edit appraisal"""
        return user == appraisal.user and appraisal.status == 'draft'
    
    def can_user_submit_appraisal(self, user: User, appraisal: Appraisal) -> bool:
        """Check if user can submit appraisal"""
        return (
            user == appraisal.user and 
            appraisal.status == 'draft' and
            appraisal.items.exists()
        )
    
    def can_user_review_appraisal(self, user: User, appraisal: Appraisal) -> bool:
        """Check if user can review appraisal - Manager first, then HR"""
        # Manager can review if status is submitted AND they are the assigned manager
        if appraisal.status == 'submitted':
            return user == appraisal.manager
        
        # Manager can also review if status is manager_review AND they are the assigned manager
        if appraisal.status == 'manager_review':
            return user == appraisal.manager
        
        # HR can review if status is hr_review
        if appraisal.status == 'hr_review':
            return user.groups.filter(name='HR').exists()
        
        return False
    
    # Create Operations
    @transaction.atomic
    def create_appraisal(
        self, 
        user: User,
        manager: User,
        title: str,
        overview: str,
        period_start: date,
        period_end: date,
        items_data: List[Dict],
        attachments: Optional[List] = None
    ) -> Tuple[bool, str, Optional[Appraisal]]:
        """
        Create a new appraisal with items and attachments
        Returns: (success, message, appraisal_object)
        """
        try:
            # Validate inputs
            if not title or not overview:
                return False, "Title and overview are required", None
            
            if not manager:
                return False, "Manager selection is required", None
            
            if not items_data or len(items_data) == 0:
                return False, "At least one appraisal item is required", None
            
            # Validate manager is in Manager group
            if not manager.groups.filter(name='Manager').exists():
                return False, "Selected user is not a manager", None
            
            # Create appraisal
            appraisal = Appraisal.objects.create(
                user=user,
                manager=manager,
                title=title,
                overview=overview,
                period_start=period_start,
                period_end=period_end,
                status='draft'
            )
            
            # Create items
            for item_data in items_data:
                AppraisalItem.objects.create(
                    appraisal=appraisal,
                    category=item_data['category'],
                    title=item_data['title'],
                    description=item_data['description'],
                    date=item_data.get('date'),
                    employee_rating=item_data.get('employee_rating')
                )
            
            # Create attachments if provided
            if attachments:
                for file in attachments:
                    AppraisalAttachment.objects.create(
                        appraisal=appraisal,
                        file=file,
                        title=file.name,
                        uploaded_by=user
                    )
            
            # Create initial workflow entry
            AppraisalWorkflow.objects.create(
                appraisal=appraisal,
                from_status=None,
                to_status='draft',
                action_by=user,
                comments='Initial appraisal creation'
            )
            
            logger.info(f"Appraisal created: {appraisal.id} by {user.username}")
            return True, "Appraisal created successfully", appraisal
            
        except Exception as e:
            logger.error(f"Error creating appraisal: {str(e)}")
            return False, f"Error creating appraisal: {str(e)}", None

    @transaction.atomic
    def update_appraisal(
        self,
        user: User,
        appraisal: Appraisal,
        title: str = None,
        overview: str = None,
        period_start: date = None,
        period_end: date = None,
        items_data: List[Dict] = None,
        attachments: List = None,
        delete_attachment_ids: List[int] = None
    ) -> Tuple[bool, str]:
        """
        Update an existing appraisal
        Returns: (success, message)
        """
        try:
            if not self.can_user_edit_appraisal(user, appraisal):
                return False, "You don't have permission to edit this appraisal"
            
            # Update basic fields if provided
            if title is not None:
                appraisal.title = title
            if overview is not None:
                appraisal.overview = overview
            if period_start is not None:
                appraisal.period_start = period_start
            if period_end is not None:
                appraisal.period_end = period_end
            
            appraisal.save()
            
            # Update items if provided
            if items_data is not None:
                # Delete existing items and create new ones
                appraisal.items.all().delete()
                for item_data in items_data:
                    AppraisalItem.objects.create(
                        appraisal=appraisal,
                        category=item_data['category'],
                        title=item_data['title'],
                        description=item_data['description'],
                        date=item_data.get('date'),
                        employee_rating=item_data.get('employee_rating')
                    )
            
            # Add new attachments if provided
            if attachments:
                for file in attachments:
                    AppraisalAttachment.objects.create(
                        appraisal=appraisal,
                        file=file,
                        title=file.name,
                        uploaded_by=user
                    )
            
            # Delete attachments if requested
            if delete_attachment_ids:
                AppraisalAttachment.objects.filter(
                    id__in=delete_attachment_ids,
                    appraisal=appraisal
                ).delete()
            
            # Create workflow entry for update
            AppraisalWorkflow.objects.create(
                appraisal=appraisal,
                from_status=appraisal.status,
                to_status=appraisal.status,
                action_by=user,
                comments='Appraisal updated'
            )
            
            logger.info(f"Appraisal {appraisal.id} updated by {user.username}")
            return True, "Appraisal updated successfully"
            
        except Exception as e:
            logger.error(f"Error updating appraisal {appraisal.id}: {str(e)}")
            return False, f"Error updating appraisal: {str(e)}"

    @transaction.atomic
    def submit_appraisal(self, user: User, appraisal: Appraisal) -> Tuple[bool, str]:
        """
        Submit an appraisal for review
        Returns: (success, message)
        """
        try:
            if not self.can_user_submit_appraisal(user, appraisal):
                return False, "You cannot submit this appraisal"
            
            # Validate all required fields
            if not appraisal.manager:
                return False, "Cannot submit without an assigned manager"
            
            # Check all items have required fields
            for item in appraisal.items.all():
                if not item.employee_rating:
                    return False, f"Please provide a rating for '{item.title}'"
            
            # Update status
            old_status = appraisal.status
            appraisal.status = 'submitted'
            appraisal.submitted_at = timezone.now()
            appraisal.save()
            
            # Create workflow entry
            AppraisalWorkflow.objects.create(
                appraisal=appraisal,
                from_status=old_status,
                to_status='submitted',
                action_by=user,
                comments='Submitted for review'
            )
            
            # Send notification to manager
            if appraisal.manager:
                self.notification_service.notify_appraisal_submitted(
                    appraisal_id=appraisal.id,
                    recipient=appraisal.manager,
                    submitter=user,
                    title=appraisal.title
                )
            
            logger.info(f"Appraisal {appraisal.id} submitted by {user.username}")
            return True, "Appraisal submitted successfully"
            
        except Exception as e:
            logger.error(f"Error submitting appraisal {appraisal.id}: {str(e)}")
            return False, f"Error submitting appraisal: {str(e)}"

    @transaction.atomic
    def review_appraisal(
        self,
        user: User,
        appraisal: Appraisal,
        action: str,
        comments: str = "",
        item_ratings: Dict[int, int] = None,
        item_comments: Dict[int, str] = None
    ) -> Tuple[bool, str]:
        """
        Review an appraisal (approve/reject)
        Returns: (success, message)
        """
        try:
            # Validate permissions
            if not self.can_user_review_appraisal(user, appraisal):
                return False, "You don't have permission to review this appraisal"
            
            # Determine target status based on current status and action
            current_status = appraisal.status
            target_status = self._get_target_status(current_status, action)
            
            if not target_status:
                return False, f"Invalid action '{action}' for current status"
            
            # Update item ratings and comments if provided
            # Manager provides manager ratings, HR provides HR ratings
            if item_ratings or item_comments:
                for item in appraisal.items.all():
                    if item_ratings and str(item.id) in item_ratings:
                        # If manager is reviewing, update manager_rating
                        if appraisal.status in ['submitted', 'manager_review']:
                            item.manager_rating = item_ratings[str(item.id)]
                        # If HR is reviewing, update hr_rating
                        elif appraisal.status == 'hr_review':
                            item.hr_rating = item_ratings[str(item.id)]
                    if item_comments and str(item.id) in item_comments:
                        # If manager is reviewing, update manager_comments
                        if appraisal.status in ['submitted', 'manager_review']:
                            item.manager_comments = item_comments[str(item.id)]
                        # If HR is reviewing, update hr_comments
                        elif appraisal.status == 'hr_review':
                            item.hr_comments = item_comments[str(item.id)]
                    item.save()
            
            # Update appraisal status
            appraisal.status = target_status
            if target_status == 'approved':
                appraisal.approved_at = timezone.now()
            appraisal.save()
            
            # Create workflow entry
            AppraisalWorkflow.objects.create(
                appraisal=appraisal,
                from_status=current_status,
                to_status=target_status,
                action_by=user,
                comments=comments or f"Status changed to {target_status}"
            )
            
            # Send appropriate notification
            self._send_status_notification(appraisal, current_status, target_status, user, comments)
            
            logger.info(f"Appraisal {appraisal.id} {action} by {user.username}")
            return True, f"Appraisal {action} successfully"
            
        except Exception as e:
            logger.error(f"Error {action} appraisal {appraisal.id}: {str(e)}")
            return False, f"Error {action} appraisal: {str(e)}"
    
    def _get_target_status(self, current_status: str, action: str) -> Optional[str]:
        """Determine target status based on current status and action"""
        if action == 'approve':
            if current_status == 'submitted':
                return 'manager_review'
            elif current_status == 'manager_review':
                return 'hr_review'
            elif current_status == 'hr_review':
                return 'approved'
        elif action == 'reject':
            return 'rejected'
        return None
    
    def _send_status_notification(
        self,
        appraisal: Appraisal,
        old_status: str,
        new_status: str,
        action_by: User,
        comments: str = ""
    ) -> None:
        """Send appropriate notification based on status change"""
        if new_status == 'submitted':
            # Notify manager for review
            if appraisal.manager:
                self.notification_service.notify_appraisal_submitted(
                    appraisal_id=appraisal.id,
                    recipient=appraisal.manager,
                    submitter=appraisal.user,
                    title=appraisal.title
                )
        elif new_status == 'manager_review':
            # Notify employee that manager is reviewing
            self.notification_service.notify_appraisal_approved(
                appraisal_id=appraisal.id,
                recipient=appraisal.user,
                approver=action_by,
                title=appraisal.title,
                stage="Manager Review"
            )
        elif new_status == 'hr_review':
            # Notify employee that manager approved and HR is now reviewing
            self.notification_service.notify_appraisal_approved(
                appraisal_id=appraisal.id,
                recipient=appraisal.user,
                approver=action_by,
                title=appraisal.title,
                stage="Manager"
            )
            # Notify HR group
            hr_users = User.objects.filter(groups__name='HR', is_active=True)
            for hr_user in hr_users:
                self.notification_service.notify_next_reviewer(
                    appraisal_id=appraisal.id,
                    recipient=hr_user,
                    title=appraisal.title,
                    stage="HR"
                )
        elif new_status == 'approved':
            # Notify employee of final approval
            self.notification_service.notify_appraisal_final_approval(
                appraisal_id=appraisal.id,
                recipient=appraisal.user,
                title=appraisal.title
            )
        elif new_status == 'rejected':
            # Determine which stage rejected
            stage = "Manager"
            if old_status == 'manager_review':
                stage = "Manager"
            elif old_status == 'hr_review':
                stage = "HR"
            
            # Notify employee of rejection
            self.notification_service.notify_appraisal_rejected(
                appraisal_id=appraisal.id,
                recipient=appraisal.user,
                rejector=action_by,
                title=appraisal.title,
                comments=comments,
                stage=stage
            )
    
    # Query Methods
    def get_user_appraisals(
        self,
        user: User,
        status: str = None,
        year: int = None,
        page: int = 1,
        page_size: int = 10
    ) -> Dict[str, Union[int, List[Appraisal]]]:
        """
        Get appraisals for a user with pagination and filtering
        Returns: {total_count: int, results: List[Appraisal]}
        """
        try:
            queryset = Appraisal.objects.filter(user=user)
            
            # Apply filters
            if status:
                queryset = queryset.filter(status=status)
            
            if year:
                queryset = queryset.filter(period_start__year=year)
            
            # Order and paginate
            queryset = queryset.order_by('-created_at')
            total_count = queryset.count()
            
            # Apply pagination
            start = (page - 1) * page_size
            end = start + page_size
            results = list(queryset[start:end])
            
            return {
                'total_count': total_count,
                'results': results,
                'page': page,
                'page_size': page_size,
                'total_pages': (total_count + page_size - 1) // page_size
            }
            
        except Exception as e:
            logger.error(f"Error getting appraisals for user {user.id}: {str(e)}")
            return {'total_count': 0, 'results': []}
    
    def get_managed_appraisals(
        self,
        user: User,
        status: str = None,
        year: int = None,
        page: int = 1,
        page_size: int = 10
    ) -> Dict[str, Union[int, List[Appraisal]]]:
        """
        Get appraisals managed by a user (for managers and HR)
        Returns: {total_count: int, results: List[Appraisal]}
        """
        try:
            # Get base queryset based on user role
            if user.groups.filter(name='HR').exists():
                # HR can see appraisals pending HR review and completed ones
                queryset = Appraisal.objects.filter(status__in=['hr_review', 'approved', 'rejected'])
            elif user.groups.filter(name='Manager').exists():
                # Managers can review appraisals of their team members
                queryset = Appraisal.objects.filter(manager=user, status__in=['submitted', 'manager_review', 'hr_review', 'approved', 'rejected'])
            else:
                return {'total_count': 0, 'results': []}
            
            # Apply filters
            if status:
                queryset = queryset.filter(status=status)
            
            if year:
                queryset = queryset.filter(period_start__year=year)
            
            # Order and paginate
            queryset = queryset.order_by('-submitted_at', '-created_at')
            total_count = queryset.count()
            
            # Apply pagination
            start = (page - 1) * page_size
            end = start + page_size
            results = list(queryset[start:end])
            
            return {
                'total_count': total_count,
                'results': results,
                'page': page,
                'page_size': page_size,
                'total_pages': (total_count + page_size - 1) // page_size
            }
            
        except Exception as e:
            logger.error(f"Error getting managed appraisals for user {user.id}: {str(e)}")
            return {'total_count': 0, 'results': []}
    
    def get_appraisal_summary(self, user: User, year: int = None) -> Dict:
        """
        Get summary statistics for appraisals
        Returns: Dict with summary data
        """
        if not year:
            year = timezone.now().year
        
        try:
            # Get base querysets
            user_appraisals = Appraisal.objects.filter(
                user=user,
                period_start__year=year
            )
            
            # Count by status
            status_counts = dict(user_appraisals.values_list('status').annotate(
                count=models.Count('id')
            ))
            
            # Get average ratings
            avg_employee_rating = user_appraisals.aggregate(
                avg=models.Avg('average_employee_rating')
            )['avg'] or 0
            
            avg_manager_rating = user_appraisals.filter(
                status='approved'
            ).aggregate(
                avg=models.Avg('average_manager_rating')
            )['avg'] or 0
            
            # Get recent activity
            recent_activity = AppraisalWorkflow.objects.filter(
                models.Q(appraisal__user=user) | 
                models.Q(appraisal__manager=user)
            ).order_by('-timestamp')[:5]
            
            return {
                'total_appraisals': user_appraisals.count(),
                'status_counts': status_counts,
                'avg_employee_rating': round(avg_employee_rating, 1),
                'avg_manager_rating': round(avg_manager_rating, 1),
                'recent_activity': recent_activity,
                'year': year
            }
            
        except Exception as e:
            logger.error(f"Error getting appraisal summary for user {user.id}: {str(e)}")
            return {
                'total_appraisals': 0,
                'status_counts': {},
                'avg_employee_rating': 0,
                'avg_manager_rating': 0,
                'recent_activity': [],
                'year': year
            }


# Singleton instance for easy import
appraisal_service = AppraisalService()