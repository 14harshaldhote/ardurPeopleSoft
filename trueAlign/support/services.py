"""
Comprehensive Services Layer for Smart Ticketing System
Provides high-level business logic and orchestration for ticket operations
"""

import logging
import json
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from django.contrib.auth.models import User, Group
from django.db import transaction, models
from django.db.models import Q, Count, Avg, F, Sum
from django.utils import timezone
from django.core.cache import cache
from django.core.mail import send_mail
from django.conf import settings
from django.core.exceptions import ValidationError, PermissionDenied
from trueAlign.models import Support, UserDetails, TicketActivity, TicketComment, TicketAttachment
from .logging_system import ticket_logger, AuditLog
from .assignment_engine import assignment_engine
from .prioritization_engine import prioritization_engine
from .sla_engine import sla_engine


class TicketService:
    """
    Main service class for ticket operations
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def create_ticket(self, user: User, ticket_data: Dict, attachments: List = None) -> Support:
        """
        Create a new ticket with intelligent assignment and prioritization
        """
        try:
            with transaction.atomic():
                # Create ticket instance
                ticket = Support.objects.create(
                    user=user,
                    issue_type=ticket_data.get('issue_type'),
                    subject=ticket_data.get('subject'),
                    description=ticket_data.get('description'),
                    department=ticket_data.get('department', ''),
                    location=ticket_data.get('location', ''),
                    asset_id=ticket_data.get('asset_id', ''),
                    priority=ticket_data.get('priority', Support.Priority.MEDIUM)
                )

                # Calculate smart priority
                smart_priority, priority_details = prioritization_engine.calculate_priority(ticket, user)
                if smart_priority != ticket.priority:
                    ticket.priority = smart_priority
                    ticket.save()

                # Set SLA target
                ticket.sla_target_date = sla_engine.calculate_sla_target(ticket)
                ticket.save()

                # Auto-assign ticket
                if ticket.assigned_group and not ticket.assigned_to_user:
                    try:
                        assigned_agent, assignment_reason = assignment_engine.assign_ticket(ticket, user)
                        ticket.assigned_to_user = assigned_agent
                        ticket.save()
                    except Exception as e:
                        self.logger.warning(f"Auto-assignment failed for ticket {ticket.ticket_id}: {str(e)}")

                # Process attachments
                if attachments:
                    for attachment in attachments:
                        TicketAttachment.objects.create(
                            ticket=ticket,
                            file=attachment,
                            uploaded_by=user,
                            description=f"Initial attachment for {ticket.ticket_id}"
                        )

                # Create initial activity
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.CREATED,
                    user=user,
                    details=f"Ticket created with priority {ticket.priority}"
                )

                # Log ticket creation
                ticket_logger.log_ticket_creation(user, ticket)

                return ticket

        except Exception as e:
            self.logger.error(f"Ticket creation failed: {str(e)}")
            ticket_logger.log_error(user, "TICKET_CREATION", e)
            raise

    def update_ticket(self, ticket: Support, user: User, updates: Dict) -> Support:
        """
        Update ticket with validation and logging
        """
        try:
            with transaction.atomic():
                old_values = {
                    'status': ticket.status,
                    'priority': ticket.priority,
                    'assigned_to': ticket.assigned_to_user
                }

                # Validate permissions
                if not self._can_update_ticket(ticket, user):
                    raise PermissionDenied("Insufficient permissions to update ticket")

                # Update fields
                for field, value in updates.items():
                    if hasattr(ticket, field):
                        setattr(ticket, field, value)

                # Handle status changes
                if 'status' in updates and updates['status'] != old_values['status']:
                    self._handle_status_change(ticket, old_values['status'], updates['status'], user)

                # Handle priority changes
                if 'priority' in updates and updates['priority'] != old_values['priority']:
                    self._handle_priority_change(ticket, old_values['priority'], updates['priority'], user)

                # Handle assignment changes
                if 'assigned_to_user' in updates and updates['assigned_to_user'] != old_values['assigned_to']:
                    self._handle_assignment_change(ticket, old_values['assigned_to'], updates['assigned_to_user'], user)

                # Update SLA if priority changed
                if 'priority' in updates:
                    ticket.sla_target_date = sla_engine.calculate_sla_target(ticket)

                ticket.save()

                # Log changes
                self._log_ticket_changes(ticket, old_values, updates, user)

                return ticket

        except Exception as e:
            self.logger.error(f"Ticket update failed for {ticket.ticket_id}: {str(e)}")
            ticket_logger.log_error(user, "TICKET_UPDATE", e, ticket.ticket_id)
            raise

    def add_comment(self, ticket: Support, user: User, content: str,
                   is_internal: bool = False, attachments: List = None) -> TicketComment:
        """
        Add comment to ticket with optional attachments
        """
        try:
            with transaction.atomic():
                # Create comment
                comment = TicketComment.objects.create(
                    ticket=ticket,
                    user=user,
                    content=content,
                    is_internal=is_internal
                )

                # Create activity
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.COMMENTED,
                    user=user,
                    details=f"{'Internal' if is_internal else 'Public'} comment added"
                )

                # Process attachments
                if attachments:
                    for attachment in attachments:
                        from trueAlign.models import CommentAttachment
                        CommentAttachment.objects.create(
                            comment=comment,
                            ticket_activity=TicketActivity.objects.filter(
                                ticket=ticket,
                                action=TicketActivity.Action.COMMENTED
                            ).latest('timestamp'),
                            file=attachment,
                            uploaded_by=user
                        )

                # Update response time if this is first response
                if not ticket.response_time and user != ticket.user:
                    ticket.response_time = timezone.now() - ticket.created_at
                    ticket.save()

                # Log comment
                ticket_logger.log_user_activity(
                    user,
                    'COMMENT_ADDED',
                    {
                        'ticket_id': ticket.ticket_id,
                        'is_internal': is_internal,
                        'has_attachments': bool(attachments)
                    }
                )

                return comment

        except Exception as e:
            self.logger.error(f"Comment addition failed for {ticket.ticket_id}: {str(e)}")
            ticket_logger.log_error(user, "COMMENT_ADD", e, ticket.ticket_id)
            raise

    def bulk_update_tickets(self, ticket_ids: List[str], updates: Dict, user: User) -> Dict:
        """
        Perform bulk updates on multiple tickets
        """
        results = {
            'success_count': 0,
            'error_count': 0,
            'errors': [],
            'updated_tickets': []
        }

        try:
            with transaction.atomic():
                tickets = Support.objects.filter(ticket_id__in=ticket_ids, is_deleted=False)

                for ticket in tickets:
                    try:
                        # Validate permissions
                        if not self._can_update_ticket(ticket, user):
                            results['errors'].append({
                                'ticket_id': ticket.ticket_id,
                                'error': 'Insufficient permissions'
                            })
                            results['error_count'] += 1
                            continue

                        # Update ticket
                        updated_ticket = self.update_ticket(ticket, user, updates)
                        results['updated_tickets'].append(updated_ticket.ticket_id)
                        results['success_count'] += 1

                    except Exception as e:
                        results['errors'].append({
                            'ticket_id': ticket.ticket_id,
                            'error': str(e)
                        })
                        results['error_count'] += 1

                # Log bulk operation
                ticket_logger.log_bulk_operation(
                    user,
                    'UPDATE',
                    ticket_ids,
                    results
                )

        except Exception as e:
            self.logger.error(f"Bulk update failed: {str(e)}")
            ticket_logger.log_error(user, "BULK_UPDATE", e)
            results['errors'].append({'system_error': str(e)})

        return results

    def escalate_ticket(self, ticket: Support, user: User, escalation_level: int = None) -> bool:
        """
        Escalate ticket to next level or specified level
        """
        try:
            if escalation_level is None:
                escalation_level = ticket.escalation_level + 1

            # Use SLA engine for escalation
            success = sla_engine.escalate_ticket(ticket, escalation_level, user)

            if success:
                # Create activity
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.ESCALATED,
                    user=user,
                    details=f"Ticket escalated to level {escalation_level}"
                )

            return success

        except Exception as e:
            self.logger.error(f"Escalation failed for {ticket.ticket_id}: {str(e)}")
            ticket_logger.log_error(user, "ESCALATION", e, ticket.ticket_id)
            return False

    def reopen_ticket(self, ticket: Support, user: User, reason: str = None) -> bool:
        """
        Reopen a closed or resolved ticket
        """
        try:
            if ticket.status not in ['Resolved', 'Closed']:
                raise ValidationError("Only resolved or closed tickets can be reopened")

            with transaction.atomic():
                # Update ticket
                ticket.status = Support.Status.OPEN
                ticket.reopen_count += 1
                ticket.resolved_at = None
                ticket.resolution_time = None
                ticket.save()

                # Create activity
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.REOPENED,
                    user=user,
                    details=f"Ticket reopened. Reason: {reason or 'No reason provided'}"
                )

                # Recalculate SLA
                ticket.sla_target_date = sla_engine.calculate_sla_target(ticket)
                ticket.save()

                # Log reopening
                ticket_logger.log_user_activity(
                    user,
                    'TICKET_REOPENED',
                    {
                        'ticket_id': ticket.ticket_id,
                        'reason': reason,
                        'reopen_count': ticket.reopen_count
                    }
                )

                return True

        except Exception as e:
            self.logger.error(f"Reopen failed for {ticket.ticket_id}: {str(e)}")
            ticket_logger.log_error(user, "REOPEN", e, ticket.ticket_id)
            return False

    def close_ticket(self, ticket: Support, user: User, resolution_summary: str = None) -> bool:
        """
        Close a ticket with resolution summary
        """
        try:
            if ticket.status == Support.Status.CLOSED:
                raise ValidationError("Ticket is already closed")

            with transaction.atomic():
                # Update ticket
                ticket.status = Support.Status.CLOSED
                ticket.resolved_at = timezone.now()
                ticket.resolution_summary = resolution_summary or ""

                # Calculate resolution time
                if ticket.created_at:
                    ticket.resolution_time = ticket.resolved_at - ticket.created_at

                # Update SLA status
                sla_engine.update_ticket_sla_status(ticket)

                ticket.save()

                # Create activity
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.CLOSED,
                    user=user,
                    details=f"Ticket closed with resolution: {resolution_summary or 'No summary provided'}"
                )

                # Log closure
                ticket_logger.log_user_activity(
                    user,
                    'TICKET_CLOSED',
                    {
                        'ticket_id': ticket.ticket_id,
                        'resolution_summary': resolution_summary,
                        'resolution_time_hours': ticket.resolution_time.total_seconds() / 3600 if ticket.resolution_time else None
                    }
                )

                return True

        except Exception as e:
            self.logger.error(f"Close failed for {ticket.ticket_id}: {str(e)}")
            ticket_logger.log_error(user, "CLOSE", e, ticket.ticket_id)
            return False

    def get_user_tickets(self, user: User, filters: Dict = None) -> models.QuerySet:
        """
        Get tickets based on user role and filters
        """
        queryset = Support.objects.filter(is_deleted=False)

        # Apply role-based filtering
        user_groups = [g.name for g in user.groups.all()]

        # Debug logging
        print(f"User: {user.username}")
        print(f"User groups: {user_groups}")
        print(f"Is superuser: {user.is_superuser}")
        print(f"Total tickets in DB: {Support.objects.filter(is_deleted=False).count()}")

        if user.is_superuser:
            # Admin can see all tickets
            print("User is superuser - showing all tickets")
            pass
        elif 'Manager' in user_groups:
            # Managers can see all tickets in their groups
            manager_groups = user.groups.all()
            queryset = queryset.filter(
                Q(assigned_group__in=[g.name for g in manager_groups]) |
                Q(user=user) |
                Q(assigned_to_user=user)
            )
            print(f"User is Manager - filtered by groups: {[g.name for g in manager_groups]}")
        elif 'HR' in user_groups:
            # HR can see HR tickets and their own tickets
            queryset = queryset.filter(
                Q(assigned_group='HR') |
                Q(user=user) |
                Q(assigned_to_user=user)
            )
            print("User is HR - showing HR tickets and own tickets")
        elif 'Admin' in user_groups:
            # Admin group can see admin tickets and their own tickets
            queryset = queryset.filter(
                Q(assigned_group='Admin') |
                Q(user=user) |
                Q(assigned_to_user=user)
            )
            print("User is Admin - showing Admin tickets and own tickets")
        else:
            # Employees can only see their own tickets
            queryset = queryset.filter(
                Q(user=user) |
                Q(assigned_to_user=user)
            )
            print("User is Employee - showing only own tickets")

        # Apply additional filters
        if filters:
            if 'status' in filters:
                queryset = queryset.filter(status=filters['status'])
            if 'priority' in filters:
                queryset = queryset.filter(priority=filters['priority'])
            if 'issue_type' in filters:
                queryset = queryset.filter(issue_type=filters['issue_type'])
            if 'assigned_to' in filters:
                queryset = queryset.filter(assigned_to_user=filters['assigned_to'])
            if 'date_from' in filters:
                queryset = queryset.filter(created_at__gte=filters['date_from'])
            if 'date_to' in filters:
                queryset = queryset.filter(created_at__lte=filters['date_to'])

        final_count = queryset.count()
        print(f"Final filtered queryset count: {final_count}")

        return queryset.order_by('-created_at')


    def get_ticket_statistics(self, user: User, days: int = 30) -> Dict:
        """
        Get comprehensive ticket statistics
        """
        start_date = timezone.now() - timedelta(days=days)
        tickets = self.get_user_tickets(user, {'date_from': start_date})

        stats = {
            'total_tickets': tickets.count(),
            'status_breakdown': {},
            'priority_breakdown': {},
            'issue_type_breakdown': {},
            'sla_metrics': sla_engine.get_sla_metrics(days),
            'assignment_metrics': assignment_engine.get_assignment_statistics(days),
            'user_activity': self._get_user_activity_stats(user, days)
        }

        # Status breakdown
        for status in Support.Status.choices:
            count = tickets.filter(status=status[0]).count()
            stats['status_breakdown'][status[0]] = count

        # Priority breakdown
        for priority in Support.Priority.choices:
            count = tickets.filter(priority=priority[0]).count()
            stats['priority_breakdown'][priority[0]] = count

        # Issue type breakdown
        for issue_type in Support.IssueType.choices:
            count = tickets.filter(issue_type=issue_type[0]).count()
            stats['issue_type_breakdown'][issue_type[0]] = count

        return stats

    def _can_update_ticket(self, ticket: Support, user: User) -> bool:
        """
        Check if user can update the ticket
        """
        user_groups = [g.name for g in user.groups.all()]

        # Admin and managers can update any ticket
        if user.is_superuser or 'Manager' in user_groups:
            return True

        # Users can update their own tickets
        if ticket.user == user:
            return True

        # Assigned agents can update their tickets
        if ticket.assigned_to_user == user:
            return True

        # Group members can update tickets in their group
        if ticket.assigned_group in user_groups:
            return True

        return False

    def _handle_status_change(self, ticket: Support, old_status: str, new_status: str, user: User):
        """
        Handle ticket status changes
        """
        # Log status change
        ticket_logger.log_status_change(ticket, user, old_status, new_status)

        # Handle specific status changes
        if new_status == Support.Status.RESOLVED:
            ticket.resolved_at = timezone.now()
            if ticket.created_at:
                ticket.resolution_time = ticket.resolved_at - ticket.created_at

        elif new_status == Support.Status.CLOSED:
            if not ticket.resolved_at:
                ticket.resolved_at = timezone.now()
                if ticket.created_at:
                    ticket.resolution_time = ticket.resolved_at - ticket.created_at

        # Update SLA status
        sla_engine.update_ticket_sla_status(ticket)

    def _handle_priority_change(self, ticket: Support, old_priority: str, new_priority: str, user: User):
        """
        Handle ticket priority changes
        """
        # Log priority change
        ticket_logger.log_user_activity(
            user,
            'PRIORITY_CHANGED',
            {
                'ticket_id': ticket.ticket_id,
                'old_priority': old_priority,
                'new_priority': new_priority
            }
        )

        # Create activity
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.UPDATED,
            user=user,
            details=f"Priority changed from {old_priority} to {new_priority}"
        )

    def _handle_assignment_change(self, ticket: Support, old_assignee: User, new_assignee: User, user: User):
        """
        Handle ticket assignment changes
        """
        # Log assignment change
        if new_assignee:
            ticket_logger.log_assignment(user, ticket, new_assignee)

        # Create activity
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.ASSIGNED,
            user=user,
            details=f"Assigned to {new_assignee.get_full_name() if new_assignee else 'Unassigned'}"
        )

    def _log_ticket_changes(self, ticket: Support, old_values: Dict, updates: Dict, user: User):
        """
        Log all ticket changes
        """
        changes = {}
        for field, new_value in updates.items():
            if field in old_values and old_values[field] != new_value:
                changes[field] = {
                    'old': str(old_values[field]),
                    'new': str(new_value)
                }

        if changes:
            ticket_logger.log_user_activity(
                user,
                'TICKET_UPDATED',
                {
                    'ticket_id': ticket.ticket_id,
                    'changes': changes
                }
            )

    def _get_user_activity_stats(self, user: User, days: int) -> Dict:
        """
        Get user activity statistics
        """
        start_date = timezone.now() - timedelta(days=days)

        activities = AuditLog.objects.filter(
            user=user,
            timestamp__gte=start_date
        ).values('action').annotate(
            count=Count('id')
        ).order_by('-count')

        return {
            'total_activities': sum(activity['count'] for activity in activities),
            'activity_breakdown': list(activities)[:10]  # Top 10 activities
        }


class NotificationService:
    """
    Service for handling ticket notifications
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def send_ticket_notification(self, ticket: Support, notification_type: str,
                               recipients: List[User], context: Dict = None):
        """
        Send ticket notification to recipients
        """
        try:
            subject = self._get_notification_subject(ticket, notification_type)
            message = self._get_notification_message(ticket, notification_type, context)

            for recipient in recipients:
                send_mail(
                    subject,
                    message,
                    settings.DEFAULT_FROM_EMAIL,
                    [recipient.email],
                    fail_silently=True
                )

            # Log notification
            ticket_logger.log_user_activity(
                None,  # System activity
                'NOTIFICATION_SENT',
                {
                    'ticket_id': ticket.ticket_id,
                    'notification_type': notification_type,
                    'recipient_count': len(recipients)
                }
            )

        except Exception as e:
            self.logger.error(f"Notification failed for ticket {ticket.ticket_id}: {str(e)}")

    def _get_notification_subject(self, ticket: Support, notification_type: str) -> str:
        """
        Get notification subject based on type
        """
        subjects = {
            'created': f"New Ticket Created - {ticket.ticket_id}",
            'assigned': f"Ticket Assigned - {ticket.ticket_id}",
            'updated': f"Ticket Updated - {ticket.ticket_id}",
            'escalated': f"Ticket Escalated - {ticket.ticket_id}",
            'resolved': f"Ticket Resolved - {ticket.ticket_id}",
            'closed': f"Ticket Closed - {ticket.ticket_id}",
            'sla_warning': f"SLA Warning - {ticket.ticket_id}"
        }

        return subjects.get(notification_type, f"Ticket Notification - {ticket.ticket_id}")

    def _get_notification_message(self, ticket: Support, notification_type: str, context: Dict = None) -> str:
        """
        Get notification message based on type
        """
        base_info = f"""
        Ticket ID: {ticket.ticket_id}
        Subject: {ticket.subject}
        Priority: {ticket.priority}
        Status: {ticket.status}
        Created: {ticket.created_at}
        Assigned to: {ticket.assigned_to_user.get_full_name() if ticket.assigned_to_user else 'Unassigned'}
        """

        messages = {
            'created': f"A new ticket has been created.{base_info}",
            'assigned': f"A ticket has been assigned to you.{base_info}",
            'updated': f"A ticket has been updated.{base_info}",
            'escalated': f"A ticket has been escalated.{base_info}",
            'resolved': f"A ticket has been resolved.{base_info}",
            'closed': f"A ticket has been closed.{base_info}",
            'sla_warning': f"SLA warning for ticket.{base_info}"
        }

        return messages.get(notification_type, f"Ticket notification.{base_info}")


# Global service instances
ticket_service = TicketService()
notification_service = NotificationService()
