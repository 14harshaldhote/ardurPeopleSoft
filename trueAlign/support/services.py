"""
Support Services Module
Handles all business logic for the support ticket system
"""

import os
import mimetypes
from datetime import timedelta
from django.db import transaction
from django.db.models import Q, Count, Avg, Case, When, IntegerField
from django.utils import timezone
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError, PermissionDenied
from django.core.files.storage import default_storage
from trueAlign.models import (
    Support, StatusLog, TicketComment, TicketAttachment,
    TicketActivity, CommentAttachment
)


class SupportTicketService:
    """Service class for handling support ticket operations"""

    @staticmethod
    def get_user_roles(user):
        """Get user roles and permissions"""
        return {
            'is_admin': user.groups.filter(name='Admin').exists() or user.is_superuser,
            'is_hr': user.groups.filter(name='HR').exists(),
            'is_manager': user.groups.filter(name='Manager').exists(),
            'is_employee': user.groups.filter(name='Employee').exists(),
            'is_staff': user.is_staff
        }

    @staticmethod
    def calculate_sla_target(priority, created_at=None):
        """Calculate SLA target date based on priority"""
        if not created_at:
            created_at = timezone.now()

        sla_targets = {
            Support.Priority.CRITICAL: 4,    # 4 hours
            Support.Priority.HIGH: 8,        # 8 hours
            Support.Priority.MEDIUM: 24,     # 24 hours
            Support.Priority.LOW: 48,        # 48 hours
        }

        target_hours = sla_targets.get(priority, 24)
        return created_at + timedelta(hours=target_hours)

    @staticmethod
    def get_ticket_permissions(user, ticket, user_roles=None):
        """Calculate user permissions for a specific ticket"""
        if not user_roles:
            user_roles = SupportTicketService.get_user_roles(user)

        permissions = {
            'can_view': False,
            'can_edit': False,
            'can_comment': False,
            'can_change_status': False,
            'can_assign': False,
            'can_view_internal': False,
            'can_add_internal_comment': False,
            'can_delete_attachments': False,
            'can_escalate': False,
            'can_reopen': False,
        }

        # Basic view permission
        permissions['can_view'] = (
            user_roles['is_admin'] or
            ticket.user == user or
            ticket.assigned_to_user == user or
            user in ticket.cc_users.all() or
            (user_roles['is_hr'] and ticket.assigned_group == Support.AssignedGroup.HR)
        )

        if not permissions['can_view']:
            return permissions

        # Advanced permissions
        is_ticket_owner = ticket.user == user
        is_assigned_user = ticket.assigned_to_user == user
        is_hr_ticket = ticket.assigned_group == Support.AssignedGroup.HR

        permissions.update({
            'can_edit': (
                user_roles['is_admin'] or
                is_assigned_user or
                (user_roles['is_hr'] and is_hr_ticket)
            ),
            'can_comment': permissions['can_view'],
            'can_change_status': (
                user_roles['is_admin'] or
                is_assigned_user or
                (user_roles['is_hr'] and is_hr_ticket) or
                (is_ticket_owner and ticket.status in [Support.Status.PENDING_USER])
            ),
            'can_assign': (
                user_roles['is_admin'] or
                (user_roles['is_hr'] and is_hr_ticket)
            ),
            'can_view_internal': user_roles['is_admin'] or user_roles['is_hr'],
            'can_add_internal_comment': user_roles['is_admin'] or user_roles['is_hr'],
            'can_delete_attachments': (
                user_roles['is_admin'] or
                is_assigned_user or
                (user_roles['is_hr'] and is_hr_ticket)
            ),
            'can_escalate': (
                user_roles['is_admin'] or
                is_assigned_user or
                (user_roles['is_hr'] and is_hr_ticket)
            ),
            'can_reopen': (
                user_roles['is_admin'] or
                is_ticket_owner or
                is_assigned_user
            ),
        })

        return permissions

    @staticmethod
    def get_tickets_queryset(user, user_roles=None):
        """Get base queryset for tickets based on user permissions"""
        if not user_roles:
            user_roles = SupportTicketService.get_user_roles(user)

        if user_roles['is_admin']:
            return Support.objects.filter(is_deleted=False)
        elif user_roles['is_hr']:
            return Support.objects.filter(
                Q(assigned_group=Support.AssignedGroup.HR) | Q(assigned_to_user=user),
                is_deleted=False
            )
        else:
            return Support.objects.filter(
                Q(user=user) | Q(assigned_to_user=user) | Q(cc_users=user),
                is_deleted=False
            ).distinct()

    @staticmethod
    @transaction.atomic
    def create_ticket(user, data, files=None):
        """Create a new support ticket with attachments"""
        # Validate required fields
        required_fields = ['subject', 'description', 'issue_type']
        for field in required_fields:
            if not data.get(field, '').strip():
                raise ValidationError(f'{field.replace("_", " ").title()} is required.')

        # Create ticket
        ticket = Support.objects.create(
            user=user,
            subject=data['subject'].strip(),
            description=data['description'].strip(),
            priority=data.get('priority', Support.Priority.MEDIUM),
            issue_type=data['issue_type'],
            assigned_group=data.get('assigned_group'),
            status=Support.Status.NEW,
            sla_target_date=SupportTicketService.calculate_sla_target(
                data.get('priority', Support.Priority.MEDIUM)
            ),
        )

        # Create initial activity log
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.CREATED,
            user=user,
            details="Ticket created"
        )

        # Handle file attachments
        attachment_count = 0
        if files:
            for file in files:
                if file.size > 0:
                    try:
                        content_type, _ = mimetypes.guess_type(file.name)
                        TicketAttachment.objects.create(
                            ticket=ticket,
                            file=file,
                            uploaded_by=user,
                            file_type=content_type or 'application/octet-stream'
                        )
                        attachment_count += 1
                    except Exception as e:
                        # Log error but don't fail ticket creation
                        pass

        return ticket, attachment_count

    @staticmethod
    @transaction.atomic
    def add_comment(ticket, user, content, is_internal=False, files=None):
        """Add a comment to a ticket with optional attachments"""
        if not content or not content.strip():
            raise ValidationError('Comment content cannot be empty.')

        # Create comment
        comment = TicketComment.objects.create(
            ticket=ticket,
            user=user,
            content=content.strip(),
            is_internal=is_internal
        )

        # Create activity log for comment
        activity = TicketActivity.objects.create(
            ticket=ticket,
            user=user,
            action=TicketActivity.Action.COMMENTED,
            details=f"{'Internal' if is_internal else 'Public'} comment added"
        )

        # Handle attachments
        attachment_count = 0
        if files:
            for file in files:
                if file and file.size > 0:
                    try:
                        import mimetypes
                        content_type, _ = mimetypes.guess_type(file.name)

                        # Create attachment linked to both comment and activity
                        attachment = CommentAttachment.objects.create(
                            comment=comment,
                            ticket_activity=activity,
                            file=file,
                            uploaded_by=user,
                            content_type=content_type or 'application/octet-stream',
                            file_size=file.size
                        )
                        attachment_count += 1
                    except Exception as e:
                        logger.error(f"Error creating attachment: {e}")
                        # Don't fail comment creation for attachment errors
                        pass

        # Update ticket timestamp
        ticket.updated_at = timezone.now()
        ticket.save(update_fields=['updated_at'])

        return comment, attachment_count

    @staticmethod
    @transaction.atomic
    def update_ticket_status(ticket, user, new_status, resolution_summary=None):
        """Update ticket status with proper validation and logging"""
        old_status = ticket.status

        if new_status not in dict(Support.Status.choices):
            raise ValidationError('Invalid status selected.')

        # Validate status transition
        if not SupportTicketService.is_valid_status_transition(old_status, new_status):
            raise ValidationError(f'Invalid status transition from {old_status} to {new_status}.')

        ticket.status = new_status

        # Handle resolution
        if new_status == Support.Status.RESOLVED:
            if not resolution_summary:
                raise ValidationError('Resolution summary is required when resolving a ticket.')
            ticket.resolution_summary = resolution_summary
            ticket.resolved_at = timezone.now()
            if ticket.created_at:
                ticket.resolution_time = ticket.resolved_at - ticket.created_at

        # Handle closure
        elif new_status == Support.Status.CLOSED:
            if not ticket.resolved_at:
                ticket.resolved_at = timezone.now()
            if ticket.created_at and not ticket.time_to_close:
                ticket.time_to_close = timezone.now() - ticket.created_at
            if not ticket.resolution_summary and resolution_summary:
                ticket.resolution_summary = resolution_summary

        # Handle reopening
        elif (old_status in [Support.Status.RESOLVED, Support.Status.CLOSED] and
              new_status in [Support.Status.OPEN, Support.Status.IN_PROGRESS]):
            ticket.reopen_count += 1
            ticket.resolved_at = None
            ticket.resolution_time = None

            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.REOPENED,
                user=user,
                details=f"Ticket reopened from {old_status} status (Reopen #{ticket.reopen_count})"
            )

        ticket.save(user=user)
        return ticket

    @staticmethod
    def is_valid_status_transition(old_status, new_status):
        """Validate if status transition is allowed"""
        allowed_transitions = {
            Support.Status.NEW: [Support.Status.OPEN, Support.Status.IN_PROGRESS],
            Support.Status.OPEN: [Support.Status.IN_PROGRESS, Support.Status.PENDING_USER, Support.Status.ON_HOLD],
            Support.Status.IN_PROGRESS: [Support.Status.PENDING_USER, Support.Status.RESOLVED, Support.Status.ON_HOLD],
            Support.Status.PENDING_USER: [Support.Status.OPEN, Support.Status.IN_PROGRESS],
            Support.Status.PENDING_THIRD_PARTY: [Support.Status.IN_PROGRESS],
            Support.Status.ON_HOLD: [Support.Status.OPEN, Support.Status.IN_PROGRESS],
            Support.Status.RESOLVED: [Support.Status.CLOSED, Support.Status.OPEN],
            Support.Status.CLOSED: [Support.Status.OPEN],
        }
        return new_status in allowed_transitions.get(old_status, [])

    @staticmethod
    @transaction.atomic
    def assign_ticket(ticket, user, assigned_to_user=None, assigned_group=None):
        """Assign ticket to user or group"""
        old_assigned_user = ticket.assigned_to_user
        old_assigned_group = ticket.assigned_group

        if assigned_to_user:
            if not User.objects.filter(pk=assigned_to_user).exists():
                raise ValidationError('Invalid user selected for assignment.')
            ticket.assigned_to_user_id = assigned_to_user

        if assigned_group and assigned_group in dict(Support.AssignedGroup.choices):
            ticket.assigned_group = assigned_group

        ticket.save(user=user)

        # Create activity log
        details = []
        if old_assigned_user != ticket.assigned_to_user:
            old_user = old_assigned_user.get_full_name() if old_assigned_user else 'Unassigned'
            new_user = ticket.assigned_to_user.get_full_name() if ticket.assigned_to_user else 'Unassigned'
            details.append(f"Assigned user changed from {old_user} to {new_user}")

        if old_assigned_group != ticket.assigned_group:
            details.append(f"Assigned group changed from {old_assigned_group or 'None'} to {ticket.assigned_group or 'None'}")

        if details:
            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.ASSIGNED,
                user=user,
                details="; ".join(details)
            )

        return ticket

    @staticmethod
    def calculate_sla_info(ticket):
        """Calculate SLA status and time remaining"""
        sla_info = {
            'status': 'Unknown',
            'time_remaining': None,
            'is_breached': False,
            'percentage_used': 0,
        }

        if not ticket.sla_target_date:
            return sla_info

        now = timezone.now()

        if ticket.resolved_at:
            # Ticket is resolved
            if ticket.resolved_at <= ticket.sla_target_date:
                sla_info['status'] = 'Met'
                sla_info['is_breached'] = False
            else:
                sla_info['status'] = 'Breached'
                sla_info['is_breached'] = True
        else:
            # Ticket is still open
            if now > ticket.sla_target_date:
                sla_info['status'] = 'Breached'
                sla_info['is_breached'] = True
            else:
                sla_info['status'] = 'On Track'
                sla_info['time_remaining'] = ticket.sla_target_date - now

        # Calculate percentage of SLA time used
        if ticket.created_at:
            total_sla_time = ticket.sla_target_date - ticket.created_at
            elapsed_time = now - ticket.created_at
            sla_info['percentage_used'] = min(100, (elapsed_time.total_seconds() / total_sla_time.total_seconds()) * 100)

        return sla_info

    @staticmethod
    def get_ticket_statistics(user, user_roles=None):
        """Get ticket statistics for dashboard"""
        if not user_roles:
            user_roles = SupportTicketService.get_user_roles(user)

        base_tickets = SupportTicketService.get_tickets_queryset(user, user_roles)

        stats = {
            'total_tickets': base_tickets.count(),
            'open_tickets': base_tickets.filter(
                status__in=[Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS]
            ).count(),
            'resolved_tickets': base_tickets.filter(status=Support.Status.RESOLVED).count(),
            'closed_tickets': base_tickets.filter(status=Support.Status.CLOSED).count(),
            'high_priority': base_tickets.filter(priority=Support.Priority.HIGH).count(),
            'critical_priority': base_tickets.filter(priority=Support.Priority.CRITICAL).count(),
            'overdue_tickets': base_tickets.filter(
                due_date__lt=timezone.now(),
                status__in=[Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS]
            ).count(),
            'my_assigned': base_tickets.filter(assigned_to_user=user).count(),
        }

        # Priority distribution
        priority_stats = list(base_tickets.values('priority').annotate(count=Count('id')))

        # Status distribution
        status_stats = list(base_tickets.values('status').annotate(count=Count('id')))

        # Issue type distribution
        issue_type_stats = list(base_tickets.values('issue_type').annotate(count=Count('id')))

        # SLA performance
        sla_breached = base_tickets.filter(sla_breach=True).count()
        sla_within = base_tickets.filter(sla_breach=False, resolved_at__isnull=False).count()

        return {
            'stats': stats,
            'priority_stats': priority_stats,
            'status_stats': status_stats,
            'issue_type_stats': issue_type_stats,
            'sla_breached': sla_breached,
            'sla_within': sla_within,
        }

    @staticmethod
    @transaction.atomic
    def escalate_ticket(ticket, user):
        """Escalate a ticket to higher level"""
        ticket.escalation_level += 1

        # Increase priority
        if ticket.priority == Support.Priority.MEDIUM:
            ticket.priority = Support.Priority.HIGH
        elif ticket.priority == Support.Priority.HIGH:
            ticket.priority = Support.Priority.CRITICAL

        ticket.save(user=user)

        # Create activity log
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.ESCALATED,
            user=user,
            details=f"Ticket escalated to level {ticket.escalation_level}, priority changed to {ticket.priority}"
        )

        return ticket

    @staticmethod
    @transaction.atomic
    def reopen_ticket(ticket, user):
        """Reopen a closed or resolved ticket"""
        if ticket.status not in [Support.Status.RESOLVED, Support.Status.CLOSED]:
            raise ValidationError('Ticket cannot be reopened from current status.')

        old_status = ticket.status
        ticket.status = Support.Status.OPEN
        ticket.resolved_at = None
        ticket.resolution_time = None
        ticket.reopen_count += 1
        ticket.save(user=user)

        # Create activity log
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.REOPENED,
            user=user,
            details=f"Ticket reopened from {old_status} status (Reopen #{ticket.reopen_count})"
        )

        return ticket


class FileAttachmentService:
    """Service for handling file attachments"""

    @staticmethod
    def get_file_type_category(content_type):
        """Determine file category from MIME type"""
        if not content_type:
            return 'unknown'

        content_type = content_type.lower()

        if content_type.startswith('image/'):
            return 'image'
        elif content_type.startswith('video/'):
            return 'video'
        elif content_type.startswith('audio/'):
            return 'audio'
        elif content_type in ['application/pdf']:
            return 'pdf'
        elif content_type in [
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.oasis.opendocument.text'
        ]:
            return 'document'
        elif content_type in [
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'text/csv'
        ]:
            return 'spreadsheet'
        elif content_type.startswith('text/'):
            return 'text'
        elif content_type in ['application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed']:
            return 'archive'
        else:
            return 'file'

    @staticmethod
    def is_image_attachment(attachment):
        """Check if attachment is an image"""
        content_type = getattr(attachment, 'content_type', None) or getattr(attachment, 'file_type', None)
        if content_type and content_type.startswith('image/'):
            return True

        # Fallback to file extension check
        filename = getattr(attachment, 'original_filename', '') or ''
        return filename.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.svg'))

    @staticmethod
    def process_attachments(attachments):
        """Process attachments to add file type information"""
        if not attachments:
            return

        # Convert to list if it's a queryset
        if hasattr(attachments, 'all'):
            attachments = attachments.all()

        # Ensure it's iterable
        if not hasattr(attachments, '__iter__'):
            return

        try:
            for attachment in attachments:
                if not attachment:
                    continue

                # Set file type category
                content_type = getattr(attachment, 'content_type', None) or getattr(attachment, 'file_type', None)
                attachment.file_category = FileAttachmentService.get_file_type_category(content_type)
                attachment.is_image = FileAttachmentService.is_image_attachment(attachment)

                # Fix missing original filename
                if not hasattr(attachment, 'original_filename') or not attachment.original_filename:
                    if hasattr(attachment, 'file') and attachment.file:
                        attachment.original_filename = os.path.basename(attachment.file.name)

                # Fix missing file size
                if not hasattr(attachment, 'file_size') or not attachment.file_size:
                    if hasattr(attachment, 'file') and attachment.file:
                        try:
                            attachment.file_size = attachment.file.size
                            attachment.save(update_fields=['file_size'])
                        except (OSError, ValueError, AttributeError):
                            attachment.file_size = 0
        except Exception as e:
            logger.error(f"Error processing attachments: {e}")


    @staticmethod
    @transaction.atomic
    def delete_attachment(attachment, user, ticket):
        """Soft delete an attachment"""
        if isinstance(attachment, TicketAttachment):
            attachment.is_deleted = True
            attachment_type = 'ticket'
        elif isinstance(attachment, CommentAttachment):
            attachment.is_active = False
            attachment_type = 'comment'

        attachment.save()

        # Create activity log
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.UPDATED,
            user=user,
            details=f"{attachment_type.title()} attachment '{attachment.original_filename}' deleted"
        )

        return attachment_type


class BulkTicketService:
    """Service for handling bulk ticket operations"""

    @staticmethod
    @transaction.atomic
    def bulk_assign(tickets, user, assigned_to_user=None, assigned_group=None):
        """Bulk assign tickets"""
        success_count = 0

        if assigned_to_user:
            try:
                assigned_user = User.objects.get(pk=assigned_to_user)
            except User.DoesNotExist:
                raise ValidationError('Invalid user selected for assignment.')

        for ticket in tickets:
            user_roles = SupportTicketService.get_user_roles(user)
            permissions = SupportTicketService.get_ticket_permissions(user, ticket, user_roles)

            if permissions['can_assign']:
                if assigned_to_user:
                    ticket.assigned_to_user = assigned_user
                if assigned_group:
                    ticket.assigned_group = assigned_group

                ticket.save(user=user)

                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.ASSIGNED,
                    user=user,
                    details=f"Bulk assigned to {assigned_user.get_full_name() if assigned_to_user else 'group'}"
                )
                success_count += 1

        return success_count

    @staticmethod
    @transaction.atomic
    def bulk_status_change(tickets, user, new_status):
        """Bulk change ticket status"""
        success_count = 0

        if new_status not in dict(Support.Status.choices):
            raise ValidationError('Invalid status selected.')

        for ticket in tickets:
            user_roles = SupportTicketService.get_user_roles(user)
            permissions = SupportTicketService.get_ticket_permissions(user, ticket, user_roles)

            if permissions['can_change_status']:
                old_status = ticket.status
                if SupportTicketService.is_valid_status_transition(old_status, new_status):
                    ticket.status = new_status
                    ticket.save(user=user)

                    TicketActivity.objects.create(
                        ticket=ticket,
                        action=TicketActivity.Action.UPDATED,
                        user=user,
                        details=f"Bulk status change: {old_status} → {new_status}"
                    )
                    success_count += 1

        return success_count

    @staticmethod
    @transaction.atomic
    def bulk_priority_change(tickets, user, new_priority):
        """Bulk change ticket priority"""
        success_count = 0

        if new_priority not in dict(Support.Priority.choices):
            raise ValidationError('Invalid priority selected.')

        for ticket in tickets:
            user_roles = SupportTicketService.get_user_roles(user)
            permissions = SupportTicketService.get_ticket_permissions(user, ticket, user_roles)

            if permissions['can_edit']:
                old_priority = ticket.priority
                ticket.priority = new_priority
                ticket.save(user=user)

                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.UPDATED,
                    user=user,
                    details=f"Bulk priority change: {old_priority} → {new_priority}"
                )
                success_count += 1

        return success_count

    @staticmethod
    @transaction.atomic
    def bulk_delete(tickets, user):
        """Bulk delete tickets (admin only)"""
        user_roles = SupportTicketService.get_user_roles(user)
        if not user_roles['is_admin']:
            raise PermissionDenied('Only administrators can delete tickets.')

        success_count = 0

        for ticket in tickets:
            ticket.is_deleted = True
            ticket.save()

            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.UPDATED,
                user=user,
                details="Ticket deleted via bulk action"
            )
            success_count += 1

        return success_count
