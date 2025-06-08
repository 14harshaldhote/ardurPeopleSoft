from django.utils import timezone
from django.contrib.auth.models import User
from django.db.models import Q, Count, Avg
from datetime import timedelta
from ..models import Support, TicketActivity, TicketComment, StatusLog
from django.core.mail import send_mail
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class SupportTicketService:
    """Service class for ticket operations"""
    
    @staticmethod
    def create_ticket(user, issue_type, subject, description, priority=Support.Priority.MEDIUM, **kwargs):
        """Create a new ticket with automatic assignment"""
        ticket = Support.objects.create(
            user=user,
            issue_type=issue_type,
            subject=subject,
            description=description,
            priority=priority,
            department=kwargs.get('department', ''),
            location=kwargs.get('location', ''),
            asset_id=kwargs.get('asset_id', ''),
        )
        
        # Log creation
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.CREATED,
            user=user,
            details=f"Ticket created with priority {priority}"
        )
        
        # Auto-assign if possible
        SupportTicketService.auto_assign_ticket(ticket)
        
        # Send notification
        SupportTicketService.send_ticket_notification(
            ticket, 
            'created', 
            f"New ticket #{ticket.ticket_id} has been created"
        )
        
        return ticket
    
    @staticmethod
    def auto_assign_ticket(ticket):
        """Automatically assign ticket based on issue type and workload"""
        # Determine group based on issue type
        if ticket.issue_type in [Support.IssueType.HR_POLICY, Support.IssueType.PAYROLL]:
            ticket.assigned_group = Support.AssignedGroup.HR
            group_name = 'HR'
        else:
            ticket.assigned_group = Support.AssignedGroup.ADMIN
            group_name = 'Admin'
        
        # Get appropriate group users
        available_users = User.objects.filter(
            groups__name=group_name,
            is_active=True
        )
        
        if not available_users.exists():
            return
        
        # Find user with least active tickets
        user_workloads = []
        for user in available_users:
            active_tickets = Support.objects.filter(
                assigned_to_user=user,
                status__in=[Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS]
            ).count()
            user_workloads.append((user, active_tickets))
        
        # Assign to user with minimum workload
        if user_workloads:
            assigned_user = min(user_workloads, key=lambda x: x[1])[0]
            ticket.assigned_to_user = assigned_user
            
            # Update status if it's new
            if ticket.status == Support.Status.NEW:
                ticket.status = Support.Status.OPEN
            
            ticket.save()
            
            # Log assignment
            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.ASSIGNED,
                user=None,  # System assignment
                details=f"Auto-assigned to {assigned_user.get_full_name()}"
            )
    
    @staticmethod
    def update_ticket_status(ticket, new_status, user, resolution_summary=''):
        """Update ticket status with proper logging"""
        old_status = ticket.status
        ticket.status = new_status
        
        # Handle status-specific logic
        if new_status == Support.Status.RESOLVED:
            ticket.resolved_at = timezone.now()
            ticket.resolution_summary = resolution_summary
            if ticket.created_at:
                ticket.resolution_time = ticket.resolved_at - ticket.created_at
        
        elif new_status == Support.Status.CLOSED:
            if not ticket.resolved_at:
                ticket.resolved_at = timezone.now()
            if ticket.created_at:
                ticket.time_to_close = timezone.now() - ticket.created_at
        
        ticket.save(user=user)
        
        # Log status change
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.UPDATED,
            user=user,
            details=f"Status changed from {old_status} to {new_status}"
        )
        
        # Send notification
        SupportTicketService.send_ticket_notification(
            ticket,
            'status_updated',
            f"Ticket #{ticket.ticket_id} status updated to {new_status}"
        )
    
    @staticmethod
    def escalate_ticket(ticket, user, reason=''):
        """Escalate ticket to higher priority/level"""
        old_level = ticket.escalation_level
        old_priority = ticket.priority
        
        # Increase escalation level
        ticket.escalation_level += 1
        
        # Increase priority if not already critical
        if ticket.priority != Support.Priority.CRITICAL:
            if ticket.priority == Support.Priority.LOW:
                ticket.priority = Support.Priority.MEDIUM
            elif ticket.priority == Support.Priority.MEDIUM:
                ticket.priority = Support.Priority.HIGH
            else:
                ticket.priority = Support.Priority.CRITICAL
        
        ticket.save(user=user)
        
        # Log escalation
        details = f"Escalated from level {old_level} to {ticket.escalation_level}"
        if old_priority != ticket.priority:
            details += f", priority changed from {old_priority} to {ticket.priority}"
        if reason:
            details += f". Reason: {reason}"
        
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.ESCALATED,
            user=user,
            details=details
        )
        
        # Send escalation notification
        TicketService.send_ticket_notification(
            ticket,
            'escalated',
            f"Ticket #{ticket.ticket_id} has been escalated to level {ticket.escalation_level}"
        )
    
    @staticmethod
    def assign_ticket(ticket, assigned_user, assigned_group, user):
        """Assign ticket to user/group with validation"""
        old_user = ticket.assigned_to_user
        old_group = ticket.assigned_group
        
        # Validate assignment
        if assigned_user and assigned_group:
            # Check if user belongs to the group
            if not assigned_user.groups.filter(name=assigned_group.replace('_', ' ').title()).exists():
                raise ValueError(f"User {assigned_user.username} does not belong to {assigned_group} group")
        
        # Update assignment
        ticket.assigned_to_user = assigned_user
        ticket.assigned_group = assigned_group
        
        # Update status if needed
        if ticket.status == Support.Status.NEW:
            ticket.status = Support.Status.OPEN
        
        ticket.save(user=user)
        
        # Log assignment
        assignment_details = []
        if old_user != assigned_user:
            assignment_details.append(
                f"Assigned to: {assigned_user.get_full_name() if assigned_user else 'Unassigned'}"
            )
        if old_group != assigned_group:
            assignment_details.append(f"Group: {assigned_group or 'Unassigned'}")
        
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.ASSIGNED,
            user=user,
            details="; ".join(assignment_details)
        )
        
        # Send assignment notification
        if assigned_user:
            TicketService.send_ticket_notification(
                ticket,
                'assigned',
                f"Ticket #{ticket.ticket_id} has been assigned to you"
            )
    
    @staticmethod
    def add_comment(ticket, user, content, is_internal=False, attachments=None):
        """Add comment to ticket with optional attachments"""
        comment = TicketComment.objects.create(
            ticket=ticket,
            user=user,
            content=content,
            is_internal=is_internal
        )
        
        # Handle attachments if provided
        if attachments:
            from .models import CommentAttachment
            activity = TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.UPDATED,
                user=user,
                details=f"Added comment with {len(attachments)} attachment(s)"
            )
            
            for file in attachments:
                CommentAttachment.objects.create(
                    ticket_activity=activity,
                    file=file,
                    original_filename=file.name,
                    file_size=file.size,
                    content_type=file.content_type,
                    uploaded_by=user,
                )
        
        # Log comment
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.COMMENTED,
            user=user,
            details=f"{'Internal' if is_internal else 'Public'} comment added"
        )
        
        # Send notification (only for public comments)
        if not is_internal:
            TicketService.send_ticket_notification(
                ticket,
                'commented',
                f"New comment added to ticket #{ticket.ticket_id}"
            )
        
        return comment
    
    @staticmethod
    def reopen_ticket(ticket, user, reason=''):
        """Reopen a closed or resolved ticket"""
        if ticket.status not in [Support.Status.RESOLVED, Support.Status.CLOSED]:
            raise ValueError("Only resolved or closed tickets can be reopened")
        
        old_status = ticket.status
        ticket.status = Support.Status.OPEN
        ticket.resolved_at = None
        ticket.resolution_time = None
        ticket.save(user=user)
        
        # Log reopening
        details = f"Ticket reopened from {old_status} status"
        if reason:
            details += f". Reason: {reason}"
        
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.REOPENED,
            user=user,
            details=details
        )
        
        # Send notification
        TicketService.send_ticket_notification(
            ticket,
            'reopened',
            f"Ticket #{ticket.ticket_id} has been reopened"
        )
    
    @staticmethod
    def check_sla_breach(ticket):
        """Check if ticket has breached SLA"""
        if not ticket.due_date:
            return False
        
        current_time = timezone.now()
        
        # Check if overdue
        if current_time > ticket.due_date and not ticket.sla_breach:
            ticket.sla_breach = True
            ticket.sla_breach_time = current_time
            ticket.save()
            
            # Log SLA breach
            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.UPDATED,
                user=None,
                details="SLA breached - ticket is overdue"
            )
            
            # Send SLA breach notification
            TicketService.send_ticket_notification(
                ticket,
                'sla_breach',
                f"SLA BREACH: Ticket #{ticket.ticket_id} is overdue"
            )
            
            return True
        
        return ticket.sla_breach
    
    @staticmethod
    def send_ticket_notification(ticket, notification_type, message):
        """Send email notifications for ticket events"""
        try:
            # Determine recipients based on notification type
            recipients = set()
            
            # Always include ticket creator
            if ticket.user.email:
                recipients.add(ticket.user.email)
            
            # Include assigned user
            if ticket.assigned_to_user and ticket.assigned_to_user.email:
                recipients.add(ticket.assigned_to_user.email)
            
            # Include CC users
            for cc_user in ticket.cc_users.all():
                if cc_user.email:
                    recipients.add(cc_user.email)
            
            # For escalations and SLA breaches, include managers
            if notification_type in ['escalated', 'sla_breach']:
                admin_users = User.objects.filter(
                    groups__name='Admin',
                    is_active=True,
                    email__isnull=False
                )
                for admin in admin_users:
                    recipients.add(admin.email)
            
            if not recipients:
                return
            
            # Compose email
            subject = f"[Ticket #{ticket.ticket_id}] {message}"
            email_body = f"""
            Ticket Details:
            - ID: #{ticket.ticket_id}
            - Subject: {ticket.subject}
            - Status: {ticket.get_status_display()}
            - Priority: {ticket.get_priority_display()}
            - Created: {ticket.created_at.strftime('%Y-%m-%d %H:%M')}
            - Assigned to: {ticket.assigned_to_user.get_full_name() if ticket.assigned_to_user else 'Unassigned'}
            
            Description:
            {ticket.description}
            
            ---
            This is an automated notification from the Support System.
            """
            
            # Send email
            send_mail(
                subject=subject,
                message=email_body,
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@company.com'),
                recipient_list=list(recipients),
                fail_silently=True
            )
            
        except Exception as e:
            logger.error(f"Failed to send notification for ticket {ticket.ticket_id}: {str(e)}")
    
    @staticmethod
    def get_ticket_statistics(user=None, days=30):
        """Get ticket statistics for dashboard"""
        end_date = timezone.now()
        start_date = end_date - timedelta(days=days)
        
        # Base queryset
        tickets = Support.objects.filter(is_deleted=False)
        
        # Filter by user if provided
        if user:
            user_roles = SupportTicketService.get_user_roles(user)
            if not user_roles['is_admin']:
                tickets = tickets.filter(
                    Q(user=user) |
                    Q(assigned_to_user=user) |
                    Q(cc_users=user)
                ).distinct()
        
        # Filter by date range
        period_tickets = tickets.filter(created_at__gte=start_date)
        
        stats = {
            'total_tickets': tickets.count(),
            'period_tickets': period_tickets.count(),
            'open_tickets': tickets.filter(
                status__in=[Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS]
            ).count(),
            'resolved_tickets': tickets.filter(status=Support.Status.RESOLVED).count(),
            'closed_tickets': tickets.filter(status=Support.Status.CLOSED).count(),
            'overdue_tickets': tickets.filter(
                due_date__lt=timezone.now(),
                status__in=[Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS]
            ).count(),
            'sla_breached': tickets.filter(sla_breach=True).count(),
            'avg_resolution_time': tickets.filter(
                resolution_time__isnull=False
            ).aggregate(avg_time=Avg('resolution_time'))['avg_time'],
            'priority_distribution': list(tickets.values('priority').annotate(count=Count('id'))),
            'status_distribution': list(tickets.values('status').annotate(count=Count('id'))),
        }
        
        return stats
    
    @staticmethod
    def get_user_roles(user):
        """Helper function to get user roles"""
        return {
            'is_admin': user.groups.filter(name='Admin').exists() or user.is_superuser,
            'is_hr': user.groups.filter(name='HR').exists(),
            'is_manager': user.groups.filter(name='Manager').exists(),
            'is_employee': user.groups.filter(name='Employee').exists()
        }
    
    @staticmethod
    def bulk_update_tickets(ticket_ids, updates, user):
        """Bulk update multiple tickets"""
        tickets = Support.objects.filter(id__in=ticket_ids, is_deleted=False)
        updated_count = 0
        
        for ticket in tickets:
            # Check permissions
            user_roles = SupportTicketService.get_user_roles(user)
            can_edit = (
                user_roles['is_admin'] or
                ticket.assigned_to_user == user or
                (user_roles['is_hr'] and ticket.assigned_group == Support.AssignedGroup.HR)
            )
            
            if not can_edit:
                continue
            
            # Apply updates
            updated_fields = []
            
            if 'status' in updates:
                old_status = ticket.status
                ticket.status = updates['status']
                updated_fields.append(f"Status: {old_status} → {ticket.status}")
            
            if 'priority' in updates:
                old_priority = ticket.priority
                ticket.priority = updates['priority']
                updated_fields.append(f"Priority: {old_priority} → {ticket.priority}")
            
            if 'assigned_to_user' in updates:
                old_user = ticket.assigned_to_user
                ticket.assigned_to_user = updates['assigned_to_user']
                updated_fields.append(
                    f"Assigned to: {old_user.get_full_name() if old_user else 'None'} → "
                    f"{ticket.assigned_to_user.get_full_name() if ticket.assigned_to_user else 'None'}"
                )
            
            if updated_fields:
                ticket.save(user=user)
                
                # Log bulk update
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.UPDATED,
                    user=user,
                    details=f"Bulk update: {'; '.join(updated_fields)}"
                )
                
                updated_count += 1
        
        return updated_count
    
    @staticmethod
    def delete_ticket(ticket, user):
        """Soft delete a ticket"""
        user_roles = TicketService.get_user_roles(user)
        
        # Only admin or ticket creator can delete
        if not (user_roles['is_admin'] or ticket.user == user):
            raise ValueError("You don't have permission to delete this ticket")
        
        # Soft delete
        ticket.is_deleted = True
        ticket.deleted_at = timezone.now()
        ticket.deleted_by = user
        ticket.save()
        
        # Log deletion
        TicketActivity.objects.create(
            ticket=ticket,
            action=TicketActivity.Action.UPDATED,
            user=user,
            details="Ticket deleted"
        )
        
        return True