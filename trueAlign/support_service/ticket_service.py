# your_django_app/services/ticket_service.py

import uuid
import logging
from datetime import timedelta
from typing import List, Dict, Any, Optional, Tuple, Union
from django.utils import timezone
from django.contrib.auth.models import User
from django.db import transaction, models
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import InMemoryUploadedFile, TemporaryUploadedFile
from django.db.models import Q, Count, Avg, Max, Min
from django.conf import settings

from ..models import (
    Support, TicketComment, TicketAttachment, TicketTag, TicketTagging,
    TicketActivity, StatusLog, TicketFieldChange, EscalationRule
)
from .sla_service import SLAService
from .notification_service import NotificationService
from .exceptions import (
    TicketCreationError, TicketNotFoundError, TicketUpdateError,
    PermissionDeniedError, InvalidActionError, AttachmentError,
    SLAViolationError, EscalationError
)

logger = logging.getLogger(__name__)


class TicketService:
    """
    Enhanced service layer for managing support tickets.
    Provides comprehensive business logic for ticket lifecycle management,
    including advanced features like bulk operations, analytics, and automation.
    """

    def __init__(
        self,
        sla_service: Optional[SLAService] = None,
        notification_service: Optional[NotificationService] = None
    ):
        """Initialize TicketService with dependency injection for better testability."""
        self.sla_service = sla_service or SLAService()
        self.notification_service = notification_service or NotificationService()
        self.logger = logger

    # ==================== CORE TICKET OPERATIONS ====================

    def get_ticket_by_id(
        self,
        ticket_id: Union[uuid.UUID, str],
        include_deleted: bool = False,
        user: Optional[User] = None
    ) -> Support:
        """
        Retrieve a ticket by its UUID with enhanced security and validation.

        Args:
            ticket_id: UUID of the ticket
            include_deleted: Whether to include soft-deleted tickets
            user: User requesting the ticket (for permission checks)

        Returns:
            Support ticket instance

        Raises:
            TicketNotFoundError: If ticket doesn't exist
            PermissionDeniedError: If user lacks permission to view ticket
        """
        try:
            # Convert string to UUID if necessary
            if isinstance(ticket_id, str):
                ticket_id = uuid.UUID(ticket_id)

            # Get ticket with appropriate manager
            manager = Support.all_objects if include_deleted else Support.objects
            ticket = manager.get(ticket_id=ticket_id)

            # Check permissions if user is provided
            if user and not self._can_view_ticket(user, ticket):
                raise PermissionDeniedError(f"User {user.username} cannot view ticket {ticket_id}")

            self.logger.info(f"Retrieved ticket {ticket_id} by user {user.username if user else 'system'}")
            return ticket

        except ValueError:
            raise TicketNotFoundError(f"Invalid ticket ID format: {ticket_id}")
        except Support.DoesNotExist:
            raise TicketNotFoundError(f"Ticket with ID {ticket_id} not found")

    @transaction.atomic
    def create_ticket(
        self,
        user: User,
        subject: str,
        description: str,
        issue_type: str,
        priority: str = Support.Priority.MEDIUM,
        department: Optional[str] = None,
        location: Optional[str] = None,
        asset_id: Optional[str] = None,
        cc_users: Optional[List[User]] = None,
        parent_ticket_id: Optional[uuid.UUID] = None,
        tags: Optional[List[str]] = None,
        attachments: Optional[List[Any]] = None,
        due_date: Optional[timezone.datetime] = None,
        custom_fields: Optional[Dict[str, Any]] = None
    ) -> Support:
        """
        Create a new support ticket with comprehensive validation and setup.

        Args:
            user: User creating the ticket
            subject: Ticket subject
            description: Detailed description
            issue_type: Type of issue
            priority: Priority level
            department: User's department
            location: User's location
            asset_id: Related asset identifier
            cc_users: List of users to CC
            parent_ticket_id: ID of parent ticket for sub-tickets
            tags: List of tag names to add
            attachments: List of file attachments
            due_date: Custom due date
            custom_fields: Additional custom field values

        Returns:
            Created Support ticket

        Raises:
            TicketCreationError: If ticket creation fails
            ValidationError: If validation fails
        """
        # Enhanced validation
        self._validate_ticket_creation_data(
            user, subject, description, issue_type, priority, parent_ticket_id
        )

        try:
            # Handle parent ticket relationship
            parent_ticket = None
            if parent_ticket_id:
                parent_ticket = self.get_ticket_by_id(parent_ticket_id)
                # Prevent infinite nesting
                if parent_ticket.parent_ticket:
                    raise TicketCreationError("Cannot create sub-ticket of a sub-ticket")

            # Create ticket instance
            ticket = Support(
                user=user,
                subject=subject.strip(),
                description=description.strip(),
                issue_type=issue_type,
                priority=priority,
                department=department or '',
                location=location or '',
                asset_id=asset_id or '',
                parent_ticket=parent_ticket,
                due_date=due_date
            )

            # Apply custom fields if provided
            if custom_fields:
                self._apply_custom_fields(ticket, custom_fields)

            # Save ticket (triggers auto-assignment and SLA calculation)
            ticket.save(user=user)

            # Handle CC users
            if cc_users:
                ticket.cc_users.set(cc_users)

            # Add tags
            if tags:
                self.add_tags_to_ticket(ticket, tags, user)

            # Handle attachments
            if attachments:
                for attachment in attachments:
                    self.add_attachment_to_ticket(ticket, user, attachment)

            # Log ticket creation
            self.logger.info(
                f"Ticket {ticket.ticket_id} created by {user.username} "
                f"with priority {priority} and type {issue_type}"
            )

            # Send notifications
            self._send_creation_notifications(ticket)

            return ticket

        except Exception as e:
            self.logger.error(f"Failed to create ticket: {str(e)}")
            raise TicketCreationError(f"Could not create ticket: {str(e)}")

    @transaction.atomic
    def update_ticket_details(
        self,
        ticket: Support,
        updating_user: User,
        data: Dict[str, Any],
        notify: bool = True
    ) -> Support:
        """
        Update ticket details with comprehensive validation and change tracking.

        Args:
            ticket: Ticket to update
            updating_user: User performing the update
            data: Dictionary of fields to update
            notify: Whether to send notifications

        Returns:
            Updated ticket

        Raises:
            TicketUpdateError: If update fails
            PermissionDeniedError: If user lacks permission
        """
        # Check permissions
        if not self._can_edit_ticket(updating_user, ticket):
            raise PermissionDeniedError("User cannot edit this ticket")

        # Define allowed fields and their validation
        allowed_fields = {
            'subject': self._validate_subject,
            'description': self._validate_description,
            'priority': self._validate_priority,
            'issue_type': self._validate_issue_type,
            'department': self._validate_department,
            'location': self._validate_location,
            'asset_id': self._validate_asset_id,
            'due_date': self._validate_due_date,
        }

        changes = {}
        updated = False

        for field, value in data.items():
            if field in allowed_fields:
                # Validate the field value
                validator = allowed_fields[field]
                validated_value = validator(value) if validator else value

                # Check if value actually changed
                current_value = getattr(ticket, field)
                if current_value != validated_value:
                    changes[field] = {'old': current_value, 'new': validated_value}
                    setattr(ticket, field, validated_value)
                    updated = True

        if updated:
            ticket.save(user=updating_user)

            # Log the update
            self.logger.info(
                f"Ticket {ticket.ticket_id} updated by {updating_user.username}. "
                f"Changes: {list(changes.keys())}"
            )

            # Send notifications if requested
            if notify:
                self.notification_service.send_ticket_update_notification(
                    ticket, updating_user, changes
                )

        return ticket

    @transaction.atomic
    def change_ticket_status(
        self,
        ticket: Support,
        new_status: str,
        user: User,
        resolution_summary: Optional[str] = None,
        reason: Optional[str] = None,
        notify: bool = True
    ) -> Support:
        """
        Change ticket status with comprehensive validation and side effects.

        Args:
            ticket: Ticket to update
            new_status: New status value
            user: User changing the status
            resolution_summary: Required for RESOLVED status
            reason: Reason for status change
            notify: Whether to send notifications

        Returns:
            Updated ticket

        Raises:
            InvalidActionError: If status change is invalid
            TicketUpdateError: If required fields are missing
            PermissionDeniedError: If user lacks permission
        """
        # Validate status
        if new_status not in Support.Status.values:
            raise InvalidActionError(f"Invalid status: {new_status}")

        # Check permissions
        if not self._can_change_status(user, ticket, new_status):
            raise PermissionDeniedError(f"User cannot change ticket to {new_status}")

        # Validate status transition
        if not self._is_valid_status_transition(ticket.status, new_status):
            raise InvalidActionError(
                f"Invalid status transition from {ticket.status} to {new_status}"
            )

        old_status = ticket.status

        # Handle specific status requirements
        if new_status == Support.Status.RESOLVED:
            if not resolution_summary:
                raise TicketUpdateError("Resolution summary is required to resolve a ticket")
            ticket.resolution_summary = resolution_summary

        elif new_status == Support.Status.CLOSED:
            # Ensure ticket was resolved first (unless admin override)
            if old_status not in [Support.Status.RESOLVED] and not user.is_superuser:
                raise InvalidActionError("Ticket must be resolved before closing")

        # Update status
        ticket.status = new_status
        ticket.save(user=user)

        # Create detailed activity log
        TicketActivity.objects.create(
            ticket=ticket,
            action=self._get_activity_action_for_status(new_status),
            user=user,
            details=f"Status changed from {old_status} to {new_status}. Reason: {reason or 'No reason provided'}"
        )

        # Log the status change
        self.logger.info(
            f"Ticket {ticket.ticket_id} status changed from {old_status} to {new_status} "
            f"by {user.username}"
        )

        # Send notifications if requested
        if notify:
            self._send_status_change_notifications(ticket, old_status, new_status, user)

        return ticket

    # ==================== ASSIGNMENT OPERATIONS ====================

    @transaction.atomic
    def assign_ticket(
        self,
        ticket: Support,
        assigned_to_user: Optional[User] = None,
        assigned_group: Optional[str] = None,
        assigning_user: User = None,
        notify: bool = True
    ) -> Support:
        """
        Assign ticket to user and/or group with validation and notifications.

        Args:
            ticket: Ticket to assign
            assigned_to_user: User to assign to (can be None to unassign)
            assigned_group: Group to assign to
            assigning_user: User performing the assignment
            notify: Whether to send notifications

        Returns:
            Updated ticket

        Raises:
            PermissionDeniedError: If user lacks permission
            ValidationError: If assignment is invalid
        """
        # Check permissions
        if not self._can_assign_ticket(assigning_user, ticket):
            raise PermissionDeniedError("User cannot assign this ticket")

        # Validate assignment
        if assigned_to_user and assigned_group:
            # Ensure user belongs to the assigned group
            if not self._user_belongs_to_group(assigned_to_user, assigned_group):
                raise ValidationError(f"User {assigned_to_user.username} does not belong to group {assigned_group}")

        old_assignee = ticket.assigned_to_user
        old_group = ticket.assigned_group

        # Update assignment
        ticket.assigned_to_user = assigned_to_user
        ticket.assigned_group = assigned_group
        ticket.save(user=assigning_user)

        # Create activity log
        assignment_details = self._format_assignment_details(
            assigned_to_user, assigned_group, old_assignee, old_group
        )

        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.ASSIGNED,
            user=assigning_user,
            details=assignment_details
        )

        # Log the assignment
        self.logger.info(
            f"Ticket {ticket.ticket_id} assigned to user {assigned_to_user.username if assigned_to_user else 'None'} "
            f"and group {assigned_group or 'None'} by {assigning_user.username}"
        )

        # Send notifications if requested
        if notify:
            self.notification_service.send_assignment_notification(
                ticket, old_assignee, assigning_user
            )

        return ticket

    def bulk_assign_tickets(
        self,
        ticket_ids: List[uuid.UUID],
        assigned_to_user: Optional[User] = None,
        assigned_group: Optional[str] = None,
        assigning_user: User = None
    ) -> Dict[str, List[uuid.UUID]]:
        """
        Bulk assign multiple tickets with error handling.

        Args:
            ticket_ids: List of ticket IDs to assign
            assigned_to_user: User to assign to
            assigned_group: Group to assign to
            assigning_user: User performing the assignment

        Returns:
            Dictionary with 'success' and 'failed' lists of ticket IDs
        """
        results = {'success': [], 'failed': []}

        for ticket_id in ticket_ids:
            try:
                ticket = self.get_ticket_by_id(ticket_id)
                self.assign_ticket(
                    ticket=ticket,
                    assigned_to_user=assigned_to_user,
                    assigned_group=assigned_group,
                    assigning_user=assigning_user,
                    notify=False  # Bulk operations shouldn't spam notifications
                )
                results['success'].append(ticket_id)
            except Exception as e:
                self.logger.error(f"Failed to assign ticket {ticket_id}: {str(e)}")
                results['failed'].append(ticket_id)

        # Send summary notification for bulk assignment
        if results['success']:
            self.notification_service.send_bulk_assignment_notification(
                results['success'], assigned_to_user, assigning_user
            )

        return results

    # ==================== COMMENT OPERATIONS ====================

    @transaction.atomic
    def add_comment_to_ticket(
        self,
        ticket: Support,
        user: User,
        content: str,
        is_internal: bool = False,
        attachments: Optional[List[Any]] = None,
        notify: bool = True
    ) -> TicketComment:
        """
        Add comment to ticket with enhanced attachment handling and validation.

        Args:
            ticket: Ticket to comment on
            user: User adding the comment
            content: Comment content
            is_internal: Whether comment is internal
            attachments: List of file attachments
            notify: Whether to send notifications

        Returns:
            Created comment

        Raises:
            TicketUpdateError: If comment creation fails
            PermissionDeniedError: If user lacks permission
        """
        # Validate content
        if not content or not content.strip():
            raise TicketUpdateError("Comment content cannot be empty")

        # Check permissions
        if not self._can_comment_on_ticket(user, ticket, is_internal):
            raise PermissionDeniedError("User cannot comment on this ticket")

        # Validate content length
        if len(content) > getattr(settings, 'MAX_COMMENT_LENGTH', 10000):
            raise TicketUpdateError("Comment content is too long")

        # Create comment
        comment = TicketComment.objects.create(
            ticket=ticket,
            user=user,
            content=content.strip(),
            is_internal=is_internal
        )

        # Handle attachments
        if attachments:
            for attachment in attachments:
                try:
                    self.add_attachment_to_ticket(
                        ticket=ticket,
                        user=user,
                        file_object=attachment,
                        comment_id=comment.id
                    )
                except Exception as e:
                    self.logger.error(f"Failed to attach file to comment {comment.id}: {str(e)}")
                    # Continue with other attachments

        # Log the comment
        self.logger.info(
            f"Comment added to ticket {ticket.ticket_id} by {user.username} "
            f"({'internal' if is_internal else 'public'})"
        )

        # Send notifications if requested
        if notify:
            if is_internal:
                self.notification_service.send_internal_note_notification(comment)
            else:
                self.notification_service.send_new_comment_notification(comment)

        return comment

    def get_ticket_comments(
        self,
        ticket: Support,
        user: User,
        include_internal: bool = None
    ) -> models.QuerySet:
        """
        Get ticket comments with appropriate filtering based on user permissions.

        Args:
            ticket: Ticket to get comments for
            user: User requesting comments
            include_internal: Whether to include internal comments (auto-determined if None)

        Returns:
            QuerySet of comments
        """
        comments = ticket.comments.all()

        # Determine if user can see internal comments
        if include_internal is None:
            include_internal = self._can_view_internal_comments(user, ticket)

        if not include_internal:
            comments = comments.filter(is_internal=False)

        return comments.order_by('created_at')

    # ==================== ATTACHMENT OPERATIONS ====================

    @transaction.atomic
    def add_attachment_to_ticket(
        self,
        ticket: Support,
        user: User,
        file_object: Union[InMemoryUploadedFile, TemporaryUploadedFile],
        description: Optional[str] = None,
        comment_id: Optional[int] = None
    ) -> TicketAttachment:
        """
        Add file attachment to ticket with comprehensive validation.

        Args:
            ticket: Ticket to attach file to
            user: User uploading the file
            file_object: File to attach
            description: Optional description
            comment_id: Optional comment to associate with

        Returns:
            Created attachment

        Raises:
            AttachmentError: If attachment fails validation or upload
            PermissionDeniedError: If user lacks permission
        """
        # Check permissions
        if not self._can_attach_to_ticket(user, ticket):
            raise PermissionDeniedError("User cannot attach files to this ticket")

        # Validate file
        self._validate_attachment(file_object)

        # Handle comment association
        comment = None
        if comment_id:
            try:
                comment = TicketComment.objects.get(id=comment_id, ticket=ticket)
            except TicketComment.DoesNotExist:
                raise AttachmentError("Associated comment not found for this ticket")

        try:
            # Create attachment
            attachment = TicketAttachment.objects.create(
                ticket=ticket,
                comment=comment,
                file=file_object,
                uploaded_by=user,
                description=description or ''
            )

            # Log the attachment
            self.logger.info(
                f"File {file_object.name} attached to ticket {ticket.ticket_id} by {user.username}"
            )

            # Send notification
            self.notification_service.send_attachment_added_notification(attachment)

            return attachment

        except Exception as e:
            self.logger.error(f"Failed to attach file to ticket {ticket.ticket_id}: {str(e)}")
            raise AttachmentError(f"Could not attach file: {str(e)}")

    def remove_attachment(
        self,
        attachment: TicketAttachment,
        user: User,
        reason: Optional[str] = None
    ) -> bool:
        """
        Remove attachment with proper validation and logging.

        Args:
            attachment: Attachment to remove
            user: User removing the attachment
            reason: Reason for removal

        Returns:
            True if successful

        Raises:
            PermissionDeniedError: If user lacks permission
        """
        # Check permissions
        if not self._can_remove_attachment(user, attachment):
            raise PermissionDeniedError("User cannot remove this attachment")

        # Soft delete by marking as inactive
        attachment.is_active = False
        attachment.save()

        # Create activity log
        TicketActivity.objects.create(
            ticket=attachment.ticket,
            action=TicketActivity.Action.UPDATED,
            user=user,
            details=f"Attachment removed: {attachment.original_filename}. Reason: {reason or 'No reason provided'}"
        )

        # Log the removal
        self.logger.info(
            f"Attachment {attachment.original_filename} removed from ticket {attachment.ticket.ticket_id} "
            f"by {user.username}"
        )

        return True

    # ==================== ADVANCED TICKET OPERATIONS ====================

    @transaction.atomic
    def escalate_ticket(
        self,
        ticket: Support,
        user: User,
        reason: Optional[str] = None,
        notify: bool = True
    ) -> Support:
        """
        Escalate ticket with enhanced logic and validation.

        Args:
            ticket: Ticket to escalate
            user: User performing escalation
            reason: Reason for escalation
            notify: Whether to send notifications

        Returns:
            Escalated ticket

        Raises:
            EscalationError: If escalation fails
            PermissionDeniedError: If user lacks permission
        """
        # Check permissions
        if not self._can_escalate_ticket(user, ticket):
            raise PermissionDeniedError("User cannot escalate this ticket")

        # Check if already at maximum escalation level
        max_escalation_level = getattr(settings, 'MAX_ESCALATION_LEVEL', 3)
        if ticket.escalation_level >= max_escalation_level:
            raise EscalationError(f"Ticket is already at maximum escalation level ({max_escalation_level})")

        # Perform escalation
        ticket.escalate(user=user, reason=reason)

        # Log the escalation
        self.logger.warning(
            f"Ticket {ticket.ticket_id} escalated to level {ticket.escalation_level} "
            f"by {user.username}. Reason: {reason or 'No reason provided'}"
        )

        # Send notifications if requested
        if notify:
            self.notification_service.send_ticket_escalated_notification(ticket, user)

        return ticket

    @transaction.atomic
    def reopen_ticket(
        self,
        ticket: Support,
        user: User,
        reason: Optional[str] = None,
        notify: bool = True
    ) -> Support:
        """
        Reopen a closed or resolved ticket with validation.

        Args:
            ticket: Ticket to reopen
            user: User reopening the ticket
            reason: Reason for reopening
            notify: Whether to send notifications

        Returns:
            Reopened ticket

        Raises:
            InvalidActionError: If ticket cannot be reopened
            PermissionDeniedError: If user lacks permission
        """
        # Check permissions
        if not self._can_reopen_ticket(user, ticket):
            raise PermissionDeniedError("User cannot reopen this ticket")

        # Check reopen limit
        max_reopens = getattr(settings, 'MAX_TICKET_REOPENS', 5)
        if ticket.reopen_count >= max_reopens:
            raise InvalidActionError(f"Ticket has reached maximum reopen limit ({max_reopens})")

        # Perform reopen
        ticket.reopen(user=user, reason=reason)

        # Log the reopen
        self.logger.info(
            f"Ticket {ticket.ticket_id} reopened by {user.username} "
            f"(reopen #{ticket.reopen_count}). Reason: {reason or 'No reason provided'}"
        )

        # Send notifications if requested
        if notify:
            self.notification_service.send_ticket_reopened_notification(ticket, user)

        return ticket

    @transaction.atomic
    def soft_delete_ticket(
        self,
        ticket: Support,
        user: User,
        reason: Optional[str] = None
    ) -> Support:
        """
        Soft delete ticket with proper validation and logging.

        Args:
            ticket: Ticket to delete
            user: User deleting the ticket
            reason: Reason for deletion

        Returns:
            Deleted ticket

        Raises:
            PermissionDeniedError: If user lacks permission
        """
        # Check permissions
        if not self._can_delete_ticket(user, ticket):
            raise PermissionDeniedError("User cannot delete this ticket")

        # Perform soft delete
        ticket.soft_delete(user=user)

        # Create activity log
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.DELETED,
            user=user,
            details=f"Ticket soft deleted. Reason: {reason or 'No reason provided'}"
        )

        # Log the deletion
        self.logger.warning(
            f"Ticket {ticket.ticket_id} soft deleted by {user.username}. "
            f"Reason: {reason or 'No reason provided'}"
        )

        # Send notification
        self.notification_service.send_ticket_deleted_notification(ticket, user)

        return ticket

    @transaction.atomic
    def restore_ticket(
        self,
        ticket: Support,
        user: User,
        reason: Optional[str] = None
    ) -> Support:
        """
        Restore a soft-deleted ticket.

        Args:
            ticket: Ticket to restore
            user: User restoring the ticket
            reason: Reason for restoration

        Returns:
            Restored ticket

        Raises:
            InvalidActionError: If ticket is not deleted
            PermissionDeniedError: If user lacks permission
        """
        # Check if ticket is actually deleted
        if not ticket.is_deleted:
            raise InvalidActionError("Ticket is not deleted")

        # Check permissions
        if not self._can_restore_ticket(user, ticket):
            raise PermissionDeniedError("User cannot restore this ticket")

        # Perform restoration
        ticket.restore()

        # Create activity log
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.RESTORED,
            user=user,
            details=f"Ticket restored. Reason: {reason or 'No reason provided'}"
        )

        # Log the restoration
        self.logger.info(
            f"Ticket {ticket.ticket_id} restored by {user.username}. "
            f"Reason: {reason or 'No reason provided'}"
        )

        # Send notification
        self.notification_service.send_ticket_restored_notification(ticket, user)

        return ticket

    # ==================== TAGGING OPERATIONS ====================

    def add_tags_to_ticket(
        self,
        ticket: Support,
        tag_names: List[str],
        user: User
    ) -> List[TicketTagging]:
        """
        Add tags to ticket with enhanced validation and creation.

        Args:
            ticket: Ticket to add tags to
            tag_names: List of tag names
            user: User adding the tags

        Returns:
            List of created TicketTagging instances
        """
        # Validate and clean tag names
        validated_tags = []
        for name in tag_names:
            cleaned_name = name.strip().lower()
            if cleaned_name and len(cleaned_name) <= 50:  # Max tag length
                validated_tags.append(cleaned_name)

        # Create or get tag instances
        tag_instances = []
        for name in validated_tags:
            tag, created = TicketTag.objects.get_or_create(
                name=name,
                defaults={'description': f'Auto-created tag: {name}'}
            )
            tag_instances.append(tag)

        # Create tagging relationships
        ticket_taggings = []
        for tag in tag_instances:
            tagging, created = TicketTagging.objects.get_or_create(
                ticket=ticket,
                tag=tag,
                defaults={'tagged_by': user}
            )
            if created:
                ticket_taggings.append(tagging)

        # Log tag addition
        if ticket_taggings:
            tag_names_added = [tt.tag.name for tt in ticket_taggings]
            self.logger.info(
                f"Tags added to ticket {ticket.ticket_id} by {user.username}: {tag_names_added}"
            )

        return ticket_taggings


    @transaction.atomic
    def remove_tags_from_ticket(
            self,
            ticket: Support,
            tag_names: List[str],
            user: User,
            notify: bool = True
        ) -> int:
            """
            Remove tags from ticket with enhanced validation and tracking.

            Args:
                ticket: Ticket to remove tags from
                tag_names: List of tag names to remove
                user: User removing the tags
                notify: Whether to send notifications

            Returns:
                Number of tags removed

            Raises:
                PermissionDeniedError: If user lacks permission to remove tags
                TicketUpdateError: If validation fails
            """
            # Check permissions
            if not self._can_edit_ticket(user, ticket):
                raise PermissionDeniedError("User cannot remove tags from this ticket")

            # Validate input
            if not tag_names:
                return 0

            if not isinstance(tag_names, list):
                raise TicketUpdateError("tag_names must be a list")

            # Clean and validate tag names
            validated_tags = []
            for name in tag_names:
                if not isinstance(name, str):
                    continue
                cleaned_name = name.strip().lower()
                if cleaned_name and len(cleaned_name) <= 50:  # Max tag length
                    validated_tags.append(cleaned_name)

            if not validated_tags:
                self.logger.warning(
                    f"No valid tags provided for removal from ticket {ticket.ticket_id} by {user.username}"
                )
                return 0

            try:
                # Find existing taggings to remove
                taggings_to_remove = TicketTagging.objects.filter(
                    ticket=ticket,
                    tag__name__in=validated_tags
                ).select_related('tag')

                # Get the actual tag names that will be removed
                removed_tag_names = list(taggings_to_remove.values_list('tag__name', flat=True))
                count = len(removed_tag_names)

                if count > 0:
                    # Delete the taggings
                    taggings_to_remove.delete()

                    # Create activity log
                    TicketActivity.objects.create(
                        ticket=ticket,
                        action=TicketActivity.Action.UPDATED,
                        user=user,
                        details=f"Tags removed: {', '.join(removed_tag_names)}"
                    )

                    # Log tag removal
                    self.logger.info(
                        f"Tags removed from ticket {ticket.ticket_id} by {user.username}: {removed_tag_names}"
                    )

                    # Send notification if requested
                    if notify:
                        self.notification_service.send_ticket_tags_updated_notification(
                            ticket, user, removed_tags=removed_tag_names
                        )

                return count

            except Exception as e:
                self.logger.error(
                    f"Failed to remove tags from ticket {ticket.ticket_id}: {str(e)}"
                )
                raise TicketUpdateError(f"Could not remove tags: {str(e)}")
