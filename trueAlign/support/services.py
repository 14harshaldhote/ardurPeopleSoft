from django.db import transaction
from django.contrib.auth.models import User
from django.core.exceptions import PermissionDenied
from django.utils import timezone
from django.shortcuts import get_object_or_404
from django.db.models import Q
from typing import Optional, List, Dict, Any

from trueAlign.models import (
    Support, TicketComment, TicketAttachment, TicketActivity
)


class SupportTicketService:
    """Service class for handling support ticket operations"""

    # Group IDs based on requirements
    ADMIN_GROUP_ID = 2
    EMPLOYEE_GROUP_ID = 5
    HR_GROUP_ID = 4
    MANAGER_GROUP_ID = 11

    # Groups that can resolve tickets
    RESOLVER_GROUPS = [ADMIN_GROUP_ID, HR_GROUP_ID]

    @classmethod
    def can_resolve_tickets(cls, user: User) -> bool:
        """Check if user can resolve tickets (Admin or HR only)"""
        return user.groups.filter(id__in=cls.RESOLVER_GROUPS).exists()

    @classmethod
    def can_reassign_tickets(cls, user: User) -> bool:
        """Check if user can reassign tickets (Admin only)"""
        return user.groups.filter(id=cls.ADMIN_GROUP_ID).exists()

    @classmethod
    def is_admin(cls, user: User) -> bool:
        """Check if user is Admin"""
        return user.groups.filter(id=cls.ADMIN_GROUP_ID).exists()

    @classmethod
    def is_hr(cls, user: User) -> bool:
        """Check if user is HR"""
        return user.groups.filter(id=cls.HR_GROUP_ID).exists()

    @classmethod
    @transaction.atomic
    def create_ticket(cls, user: User, ticket_data: Dict[str, Any]) -> Support:
        """Create a new support ticket"""
        # All groups can create tickets
        ticket = Support.objects.create(
            user=user,
            issue_type=ticket_data['issue_type'],
            subject=ticket_data['subject'],
            description=ticket_data['description'],
            priority=ticket_data.get('priority', Support.Priority.MEDIUM),
            location=ticket_data.get('location', ''),
            asset_id=ticket_data.get('asset_id', ''),
        )

        # Create activity log
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.CREATED,
            user=user,
            details=f"Ticket created with subject: {ticket.subject}"
        )

        return ticket

    @classmethod
    def get_tickets_for_user(cls, user: User, status_filter: Optional[str] = None):
        """Get tickets accessible to user based on their role"""
        base_query = Support.objects.filter(is_deleted=False).select_related(
            'user', 'assigned_to_user'
        ).prefetch_related('cc_users', 'comments', 'attachments')

        if cls.is_admin(user):
            # Admin can see all tickets
            queryset = base_query
        elif cls.is_hr(user):
            # HR can see all tickets
            queryset = base_query
        else:
            # Other users can only see their own tickets or tickets they're CC'd on
            queryset = base_query.filter(
                Q(user=user) | Q(cc_users=user) | Q(assigned_to_user=user)
            ).distinct()

        # Apply status filter if provided
        if status_filter:
            queryset = queryset.filter(status=status_filter)

        return queryset.order_by('-created_at')

    @classmethod
    @transaction.atomic
    def update_ticket_status(cls, ticket_id: int, new_status: str, user: User,
                           comment: Optional[str] = None) -> Support:
        """Update ticket status with proper permission checking"""
        ticket = get_object_or_404(Support, id=ticket_id, is_deleted=False)

        # Check permissions for status changes
        if new_status in [Support.Status.RESOLVED, Support.Status.CLOSED]:
            if not cls.can_resolve_tickets(user):
                raise PermissionDenied("Only Admin and HR can resolve/close tickets")

        old_status = ticket.status
        ticket.status = new_status

        # Handle resolved timestamp
        if new_status == Support.Status.RESOLVED and not ticket.resolved_at:
            ticket.resolved_at = timezone.now()
            if ticket.created_at:
                ticket.resolution_time = ticket.resolved_at - ticket.created_at

        # Handle reopen count
        if old_status in [Support.Status.RESOLVED, Support.Status.CLOSED] and \
           new_status not in [Support.Status.RESOLVED, Support.Status.CLOSED]:
            ticket.reopen_count += 1

        ticket.save(user=user)

        # Create activity log
        TicketActivity.objects.create(
            ticket=ticket,
            action=cls._get_activity_action_for_status(new_status),
            user=user,
            details=f"Status changed from {old_status} to {new_status}"
        )

        # Add comment if provided
        if comment:
            cls.add_comment(ticket.pk, user, comment)

        return ticket

    @classmethod
    @transaction.atomic
    def reassign_ticket(cls, ticket_id: int, assigned_to_user_id: Optional[int],
                       assigned_group: Optional[str], reassigning_user: User) -> Support:
        """Reassign ticket to different user or group (Admin only)"""
        if not cls.can_reassign_tickets(reassigning_user):
            raise PermissionDenied("Only Admin can reassign tickets")

        ticket = get_object_or_404(Support, id=ticket_id, is_deleted=False)

        old_assigned_to = ticket.assigned_to_user
        old_assigned_group = ticket.assigned_group

        # Update assignment
        if assigned_to_user_id:
            ticket.assigned_to_user = get_object_or_404(User, id=assigned_to_user_id)
        else:
            ticket.assigned_to_user = None

        if assigned_group:
            ticket.assigned_group = assigned_group

        ticket.save(user=reassigning_user)

        # Create activity log
        assignment_details = []
        if old_assigned_to != ticket.assigned_to_user:
            old_name = old_assigned_to.get_full_name() if old_assigned_to else "Unassigned"
            new_name = ticket.assigned_to_user.get_full_name() if ticket.assigned_to_user else "Unassigned"
            assignment_details.append(f"User: {old_name} -> {new_name}")

        if old_assigned_group != ticket.assigned_group:
            assignment_details.append(f"Group: {old_assigned_group or 'None'} -> {ticket.assigned_group or 'None'}")

        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.ASSIGNED,
            user=reassigning_user,
            details="Reassigned - " + "; ".join(assignment_details)
        )

        return ticket

    @classmethod
    @transaction.atomic
    def add_comment(cls, ticket_id: int, user: User, content: str,
                   is_internal: bool = False) -> TicketComment:
        """Add comment to ticket"""
        ticket = get_object_or_404(Support, id=ticket_id, is_deleted=False)

        # Check if user can access this ticket
        if not cls._can_access_ticket(ticket, user):
            raise PermissionDenied("You don't have permission to comment on this ticket")

        comment = TicketComment.objects.create(
            ticket=ticket,
            user=user,
            content=content,
            is_internal=is_internal
        )

        # Create activity log
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.COMMENTED,
            user=user,
            details=f"Added comment: {content[:50]}{'...' if len(content) > 50 else ''}"
        )

        return comment

    @classmethod
    @transaction.atomic
    def add_attachment(cls, ticket_id: int, user: User, file_obj,
                      description: str = "") -> TicketAttachment:
        """Add file attachment to ticket"""
        ticket = get_object_or_404(Support, id=ticket_id, is_deleted=False)

        # Check if user can access this ticket
        if not cls._can_access_ticket(ticket, user):
            raise PermissionDenied("You don't have permission to add attachments to this ticket")

        attachment = TicketAttachment.objects.create(
            ticket=ticket,
            file=file_obj,
            uploaded_by=user,
            description=description
        )

        # Create activity log
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.UPDATED,
            user=user,
            details=f"Added attachment: {attachment.original_filename}"
        )

        return attachment

    @classmethod
    def get_ticket_detail(cls, ticket_id: int, user: User) -> Support:
        """Get detailed ticket information with permission checking"""
        ticket = get_object_or_404(Support, id=ticket_id, is_deleted=False)

        if not cls._can_access_ticket(ticket, user):
            raise PermissionDenied("You don't have permission to view this ticket")

        return ticket

    @classmethod
    def get_dashboard_stats(cls, user: User) -> Dict[str, Any]:
        """Get dashboard statistics based on user role"""
        if cls.is_admin(user) or cls.is_hr(user):
            # Admin and HR see all tickets stats
            total_tickets = Support.objects.filter(is_deleted=False).count()
            open_tickets = Support.objects.filter(
                is_deleted=False,
                status__in=[Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS]
            ).count()
            pending_tickets = Support.objects.filter(
                is_deleted=False,
                status__in=[Support.Status.PENDING_USER, Support.Status.PENDING_THIRD_PARTY]
            ).count()
            resolved_tickets = Support.objects.filter(
                is_deleted=False,
                status=Support.Status.RESOLVED
            ).count()
        else:
            # Other users see only their tickets stats
            user_tickets = Support.objects.filter(
                Q(user=user) | Q(cc_users=user) | Q(assigned_to_user=user),
                is_deleted=False
            ).distinct()

            total_tickets = user_tickets.count()
            open_tickets = user_tickets.filter(
                status__in=[Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS]
            ).count()
            pending_tickets = user_tickets.filter(
                status__in=[Support.Status.PENDING_USER, Support.Status.PENDING_THIRD_PARTY]
            ).count()
            resolved_tickets = user_tickets.filter(status=Support.Status.RESOLVED).count()

        return {
            'total_tickets': total_tickets,
            'open_tickets': open_tickets,
            'pending_tickets': pending_tickets,
            'resolved_tickets': resolved_tickets,
            'can_resolve': cls.can_resolve_tickets(user),
            'can_reassign': cls.can_reassign_tickets(user),
        }

    @classmethod
    def _can_access_ticket(cls, ticket: Support, user: User) -> bool:
        """Check if user can access the ticket"""
        # Admin and HR can access all tickets
        if cls.is_admin(user) or cls.is_hr(user):
            return True

        # Users can access tickets they created, are assigned to, or are CC'd on
        return (ticket.user == user or
                ticket.assigned_to_user == user or
                ticket.cc_users.filter(id=user.id).exists())

    @classmethod
    def _get_activity_action_for_status(cls, status: str) -> str:
        """Get appropriate activity action for status change"""
        status_to_action = {
            'Resolved': TicketActivity.Action.RESOLVED,
            'Closed': TicketActivity.Action.CLOSED,
        }
        return status_to_action.get(status, TicketActivity.Action.UPDATED)

    @classmethod
    def get_available_assignees(cls, user: User) -> List[Dict[str, Any]]:
        """Get list of users that can be assigned tickets (for reassignment)"""
        if not cls.can_reassign_tickets(user):
            return []

        # Get Admin and HR users for assignment
        assignable_users = User.objects.filter(
            groups__id__in=cls.RESOLVER_GROUPS,
            is_active=True
        ).distinct().order_by('first_name', 'last_name')

        return [
            {
                'id': u.id,
                'name': u.get_full_name() or u.username,
                'username': u.username,
                'groups': list(u.groups.values_list('name', flat=True))
            }
            for u in assignable_users
        ]

    @classmethod
    @transaction.atomic
    def escalate_ticket(cls, ticket_id: int, user: User, reason: str = "") -> Support:
        """Escalate ticket to higher priority"""
        ticket = get_object_or_404(Support, id=ticket_id, is_deleted=False)

        if not cls._can_access_ticket(ticket, user):
            raise PermissionDenied("You don't have permission to escalate this ticket")

        # Increase escalation level
        ticket.escalation_level += 1

        # Auto-increase priority if not already critical
        if ticket.priority != 'Critical':
            if ticket.priority == 'Low':
                ticket.priority = 'Medium'
            elif ticket.priority == 'Medium':
                ticket.priority = 'High'
            elif ticket.priority == 'High':
                ticket.priority = 'Critical'

        ticket.save(user=user)

        # Create activity log
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.ESCALATED,
            user=user,
            details=f"Escalated to level {ticket.escalation_level}. Reason: {reason}"
        )

        return ticket
