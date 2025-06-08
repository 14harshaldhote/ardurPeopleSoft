from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db.models import Q, Count
from .models import ChatGroup, GroupMember, DirectMessage, Message, MessageRead

def get_chat_history(chat_id, user, chat_type='group', limit=50):
    """
    Fetch chat history efficiently with pagination
    Args:
        chat_id: ID of the chat (group or direct message)
        user: Requesting user
        chat_type: Type of chat ('group' or 'direct')
        limit: Number of messages to return (default 50)
    Returns:
        QuerySet of messages
    """
    try:
        if chat_type == 'group':
            chat_group = ChatGroup.objects.get(id=chat_id)
            
            if not GroupMember.objects.filter(group=chat_group, user=user, is_active=True).exists():
                raise ValidationError("User is not an active member of this group")
                
            messages = Message.objects.filter(group=chat_group, is_deleted=False)
            
        else:
            direct_message = DirectMessage.objects.get(id=chat_id, is_active=True)
            
            if not direct_message.participants.filter(id=user.id).exists():
                raise ValidationError("User is not a participant in this conversation")
                
            messages = Message.objects.filter(direct_message=direct_message, is_deleted=False)
        
        result = messages.select_related('sender').order_by('-sent_at')[:limit]
        return result
        
    except (ChatGroup.DoesNotExist, DirectMessage.DoesNotExist) as e:
        raise ValidationError(f"Chat not found: {str(e)}")
    
def mark_messages_as_read(chat_id, user, chat_type):
    """Mark all messages in a chat as read for a user"""
    try:
        current_time = timezone.now()
        
        # Get all unread messages in this chat for this user
        if chat_type == 'group':
            # For group messages
            read_receipts = MessageRead.objects.filter(
                message__group_id=chat_id,
                message__is_deleted=False,
                user=user,
                read_at__isnull=True
            )
        else:
            # For direct messages
            read_receipts = MessageRead.objects.filter(
                message__direct_message_id=chat_id,
                message__is_deleted=False,
                user=user,
                read_at__isnull=True
            )
        
        # Update read_at timestamp for all unread messages at once
        updated_count = read_receipts.update(read_at=current_time)
        
        return updated_count
    except Exception as e:
        import logging
        logger = logging.getLogger(__name__)
        logger.error(f"Error marking messages as read: {str(e)}")
        return 0

# def mark_messages_as_read(chat_id, user, chat_type='group'):
#     """
#     Mark all unread messages in a chat as read
#     Args:
#         chat_id: ID of the chat
#         user: User marking messages as read
#         chat_type: Type of chat ('group' or 'direct')
#     """
#     try:
#         if chat_type == 'group':
#             chat_group = ChatGroup.objects.get(id=chat_id, is_active=True)
#             if not GroupMember.objects.filter(group=chat_group, user=user, is_active=True).exists():
#                 raise ValidationError("User is not an active member of this group")
#             messages = Message.objects.filter(group=chat_group, is_deleted=False)
#         else:
#             direct_message = DirectMessage.objects.get(id=chat_id, is_active=True)
#             if not direct_message.participants.filter(id=user.id).exists():
#                 raise ValidationError("User is not a participant in this conversation")
#             messages = Message.objects.filter(direct_message=direct_message, is_deleted=False)

#         now = timezone.now()
#         MessageRead.objects.filter(
#             message__in=messages,
#             user=user,
#             read_at__isnull=True
#         ).update(read_at=now)
        
#         unread_messages = messages.exclude(read_receipts__user=user)
        
#         read_receipts = [
#             MessageRead(message=msg, user=user, read_at=now)
#             for msg in unread_messages
#         ]
#         MessageRead.objects.bulk_create(read_receipts, ignore_conflicts=True)

#     except (ChatGroup.DoesNotExist, DirectMessage.DoesNotExist) as e:
#         raise ValidationError(f"Chat not found: {str(e)}")

def get_unread_counts(user):
    """
    Get unread message counts for all user's chats
    Args:
        user: User to get counts for
    Returns:
        Dict with chat_id: unread_count mapping
    """
    # Get unread counts for groups
    group_counts = ChatGroup.objects.filter(
        memberships__user=user,
        memberships__is_active=True,
        is_active=True
    ).annotate(
        unread=Count(
            'messages',
            filter=Q(messages__is_deleted=False) & 
                  Q(messages__read_receipts__user=user, 
                    messages__read_receipts__read_at__isnull=True)
        )
    ).values('id', 'unread')

    # Get unread counts for direct messages
    dm_counts = DirectMessage.objects.filter(
        participants=user,
        is_active=True
    ).annotate(
        unread=Count(
            'messages',
            filter=Q(messages__is_deleted=False) &
                  Q(messages__read_receipts__user=user,
                    messages__read_receipts__read_at__isnull=True)
        )
    ).values('id', 'unread')

    # Combine into single dictionary
    unread_counts = {
        chat['id']: chat['unread'] 
        for chat in list(group_counts) + list(dm_counts)
    }
    
    return unread_counts

def create_group(name, created_by, description=""):
    """
    Create a new chat group
    Args:
        name: Group name
        created_by: User creating the group
        description: Optional group description
    Returns:
        Created ChatGroup instance
    """
    # Validate creator permissions
    if not created_by.groups.filter(name__in=['Admin', 'Manager']).exists():
        raise ValidationError("Only managers and administrators can create chat groups")
        
    group = ChatGroup.objects.create(
        name=name,
        description=description,
        created_by=created_by,
        is_active=True
    )

    # Add creator as admin member
    GroupMember.objects.create(
        group=group,
        user=created_by,
        role='admin',
        is_active=True
    )

    return group


'''---------------------------------- SUpoted Features ----------------------------------'''
# services.py
from django.db import transaction
from django.utils import timezone
from django.db.models import Avg, Count, Q, F
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib.auth.models import User
from datetime import timedelta
import logging

from .models import Support, TicketActivity, StatusLog, TicketComment

logger = logging.getLogger(__name__)


class SupportTicketService:
    """Service layer for support ticket operations"""

    @staticmethod
    def create_ticket(user, ticket_data, attachments=None):
        """Create a new support ticket with proper validation and logging"""
        
        try:
            with transaction.atomic():
                # Create the ticket
                ticket = Support.objects.create(
                    user=user,
                    **ticket_data
                )
                
                # Log creation activity
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.CREATED,
                    user=user,
                    details=f"New {ticket.issue_type} ticket created with {ticket.priority} priority"
                )
                
                # Handle attachments if provided
                if attachments:
                    SupportTicketService._handle_attachments(ticket, attachments, user)
                
                # Send notifications
                SupportTicketService.send_creation_notification(ticket)
                
                logger.info(f"Ticket {ticket.ticket_id} created successfully by {user.username}")
                return ticket, None
                
        except Exception as e:
            logger.error(f"Error creating ticket: {str(e)}")
            return None, str(e)

    @staticmethod
    def update_ticket_status(ticket, new_status, user, comment=None):
        """Update ticket status with proper validation and logging"""
        
        if new_status not in dict(Support.Status.choices):
            return False, "Invalid status"
        
        old_status = ticket.status
        
        if old_status == new_status:
            return True, "Status unchanged"
        
        try:
            with transaction.atomic():
                ticket.status = new_status
                ticket.save(user=user)
                
                # Determine action type
                action = TicketActivity.Action.UPDATED
                if new_status == Support.Status.RESOLVED:
                    action = TicketActivity.Action.RESOLVED
                elif new_status == Support.Status.CLOSED:
                    action = TicketActivity.Action.CLOSED
                elif old_status in [Support.Status.RESOLVED, Support.Status.CLOSED]:
                    action = TicketActivity.Action.REOPENED
                
                # Log the status change
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=action,
                    user=user,
                    details=f"Status changed from {old_status} to {new_status}"
                )
                
                # Add comment if provided
                if comment:
                    TicketComment.objects.create(
                        ticket=ticket,
                        user=user,
                        content=comment,
                        is_internal=False
                    )
                
                # Send notifications
                SupportTicketService.send_status_change_notification(ticket, old_status, new_status)
                
                logger.info(f"Ticket {ticket.ticket_id} status changed from {old_status} to {new_status} by {user.username}")
                return True, f"Status updated to {new_status}"
                
        except Exception as e:
            logger.error(f"Error updating ticket status: {str(e)}")
            return False, str(e)

    @staticmethod
    def assign_ticket(ticket, assigned_to_user=None, assigned_group=None, user=None):
        """Assign ticket to user or group"""
        
        old_assigned_user = ticket.assigned_to_user
        old_assigned_group = ticket.assigned_group
        
        try:
            with transaction.atomic():
                ticket.assigned_to_user = assigned_to_user
                ticket.assigned_group = assigned_group
                ticket.save(user=user)
                
                # Log assignment changes
                assignment_details = []
                if old_assigned_user != assigned_to_user:
                    old_user = old_assigned_user.username if old_assigned_user else 'Unassigned'
                    new_user = assigned_to_user.username if assigned_to_user else 'Unassigned'
                    assignment_details.append(f"User: {old_user} → {new_user}")
                    
                if old_assigned_group != assigned_group:
                    assignment_details.append(f"Group: {old_assigned_group or 'None'} → {assigned_group or 'None'}")
                
                if assignment_details:
                    TicketActivity.objects.create(
                        ticket=ticket,
                        action=TicketActivity.Action.ASSIGNED,
                        user=user,
                        details="; ".join(assignment_details)
                    )
                    
                    # Send assignment notification
                    if assigned_to_user:
                        SupportTicketService.send_assignment_notification(ticket, assigned_to_user)
                
                logger.info(f"Ticket {ticket.ticket_id} assignment updated by {user.username if user else 'System'}")
                return True, "Assignment updated successfully"
                
        except Exception as e:
            logger.error(f"Error assigning ticket: {str(e)}")
            return False, str(e)

    @staticmethod
    def escalate_ticket(ticket, escalation_reason, user):
        """Escalate ticket to higher level"""
        
        try:
            with transaction.atomic():
                ticket.escalation_level += 1
                
                # Auto-escalate priority if needed
                if ticket.priority != Support.Priority.CRITICAL:
                    old_priority = ticket.priority
                    ticket.priority = Support.Priority.CRITICAL
                    ticket.save(user=user)
                    
                    priority_change = f"Priority escalated from {old_priority} to {ticket.priority}"
                else:
                    ticket.save(user=user)
                    priority_change = ""
                
                # Log escalation
                details = f"Escalated to level {ticket.escalation_level}. Reason: {escalation_reason}"
                if priority_change:
                    details += f". {priority_change}"
                
                TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.ESCALATED,
                    user=user,
                    details=details
                )
                
                # Send escalation notifications
                SupportTicketService.send_escalation_notification(ticket, escalation_reason)
                
                logger.info(f"Ticket {ticket.ticket_id} escalated to level {ticket.escalation_level} by {user.username}")
                return True, f"Ticket escalated to level {ticket.escalation_level}"
                
        except Exception as e:
            logger.error(f"Error escalating ticket: {str(e)}")
            return False, str(e)

    @staticmethod
    def add_comment_with_attachments(ticket, user, content, is_internal=False, attachments=None):
        """Add comment to ticket with optional attachments"""
        
        try:
            with transaction.atomic():
                # Create comment
                comment = TicketComment.objects.create(
                    ticket=ticket,
                    user=user,
                    content=content,
                    is_internal=is_internal
                )
                
                # Log activity
                activity = TicketActivity.objects.create(
                    ticket=ticket,
                    action=TicketActivity.Action.COMMENTED,
                    user=user,
                    details=f"{'Internal' if is_internal else 'Public'} comment added"
                )
                
                # Handle attachments
                if attachments:
                    SupportTicketService._handle_comment_attachments(activity, attachments, user)
                
                # Send notifications for public comments
                if not is_internal:
                    SupportTicketService.send_comment_notification(ticket, comment)
                
                logger.info(f"Comment added to ticket {ticket.ticket_id} by {user.username}")
                return comment, None
                
        except Exception as e:
            logger.error(f"Error adding comment: {str(e)}")
            return None, str(e)

    @staticmethod
    def get_ticket_statistics(date_range_days=30):
        """Get comprehensive ticket statistics"""
        
        end_date = timezone.now()
        start_date = end_date - timedelta(days=date_range_days)
        
        base_queryset = Support.objects.filter(
            created_at__gte=start_date,
            is_deleted=False
        )
        
        stats = {
            'total_tickets': base_queryset.count(),
            'open_tickets': base_queryset.filter(
                status__in=[Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS]
            ).count(),
            'resolved_tickets': base_queryset.filter(status=Support.Status.RESOLVED).count(),
            'closed_tickets': base_queryset.filter(status=Support.Status.CLOSED).count(),
            'overdue_tickets': base_queryset.filter(due_date__lt=timezone.now()).count(),
            'critical_tickets': base_queryset.filter(priority=Support.Priority.CRITICAL).count(),
            'sla_breached': base_queryset.filter(sla_breach=True).count(),
            
            # Group by status
            'by_status': dict(
                base_queryset.values('status').annotate(count=Count('id')).values_list('status', 'count')
            ),
            
            # Group by priority
            'by_priority': dict(
                base_queryset.values('priority').annotate(count=Count('id')).values_list('priority', 'count')
            ),
            
            # Group by issue type
            'by_issue_type': dict(
                base_queryset.values('issue_type').annotate(count=Count('id')).values_list('issue_type', 'count')
            ),
            
            # Average resolution time
            'avg_resolution_time': SupportTicketService.calculate_avg_resolution_time(base_queryset),
            
            # Top assignees
            'top_assignees': list(
                base_queryset.filter(assigned_to_user__isnull=False)
                .values('assigned_to_user__username')
                .annotate(count=Count('id'))
                .order_by('-count')[:5]
            ),
            
            # Daily ticket creation trend
            'daily_trend': SupportTicketService._get_daily_trend(start_date, end_date),
        }
        
        return stats

    @staticmethod
    def calculate_avg_resolution_time(queryset):
        """Calculate average resolution time for tickets"""
        
        resolved_tickets = queryset.filter(
            status=Support.Status.RESOLVED,
            resolution_time__isnull=False
        ).aggregate(avg_time=Avg('resolution_time'))
        
        avg_seconds = resolved_tickets.get('avg_time')
        if avg_seconds:
            return {
                'total_seconds': int(avg_seconds.total_seconds()),
                'hours': int(avg_seconds.total_seconds() // 3600),
                'days': int(avg_seconds.total_seconds() // 86400),
                'formatted': SupportTicketService._format_duration(avg_seconds)
            }
        return None

    @staticmethod
    def get_sla_compliance_report(date_range_days=30):
        """Generate SLA compliance report"""
        
        end_date = timezone.now()
        start_date = end_date - timedelta(days=date_range_days)
        
        tickets = Support.objects.filter(
            created_at__gte=start_date,
            is_deleted=False
        )
        
        total_tickets = tickets.count()
        if total_tickets == 0:
            return None
        
        within_sla = tickets.filter(sla_status=Support.SLAStatus.WITHIN_SLA).count()
        breached_sla = tickets.filter(sla_status=Support.SLAStatus.BREACHED).count()
        
        compliance_rate = (within_sla / total_tickets) * 100 if total_tickets > 0 else 0
        
        return {
            'total_tickets': total_tickets,
            'within_sla': within_sla,
            'breached_sla': breached_sla,
            'compliance_rate': round(compliance_rate, 2),
            'by_priority': {
                priority: {
                    'total': tickets.filter(priority=priority).count(),
                    'within_sla': tickets.filter(priority=priority, sla_status=Support.SLAStatus.WITHIN_SLA).count(),
                    'breached': tickets.filter(priority=priority, sla_status=Support.SLAStatus.BREACHED).count()
                }
                for priority, _ in Support.Priority.choices
            }
        }

    @staticmethod
    def auto_assign_tickets():
        """Auto-assign new tickets based on workload and expertise"""
        
        unassigned_tickets = Support.objects.filter(
            status=Support.Status.NEW,
            assigned_to_user__isnull=True,
            is_deleted=False
        ).order_by('created_at')
        
        # Get available assignees
        available_users = User.objects.filter(
            is_active=True,
            is_staff=True
        ).annotate(
            active_tickets=Count('assigned_tickets', filter=Q(
                assigned_tickets__status__in=[
                    Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS
                ],
                assigned_tickets__is_deleted=False
            ))
        ).order_by('active_tickets')
        
        assigned_count = 0
        
        for ticket in unassigned_tickets:
            # Find best assignee based on workload and group
            best_assignee = None
            
            if ticket.assigned_group == Support.AssignedGroup.HR:
                # Look for HR staff first
                hr_users = available_users.filter(groups__name='HR')
                if hr_users.exists():
                    best_assignee = hr_users.first()
            elif ticket.assigned_group == Support.AssignedGroup.ADMIN:
                # Look for Admin staff
                admin_users = available_users.filter(groups__name='Admin')
                if admin_users.exists():
                    best_assignee = admin_users.first()
            
            # Fallback to least loaded user
            if not best_assignee and available_users.exists():
                best_assignee = available_users.first()
            
            if best_assignee:
                success, message = SupportTicketService.assign_ticket(
                    ticket, assigned_to_user=best_assignee
                )
                if success:
                    assigned_count += 1
                    logger.info(f"Auto-assigned ticket {ticket.ticket_id} to {best_assignee.username}")
        
        return assigned_count

    @staticmethod
    def check_sla_breaches():
        """Check for SLA breaches and update status"""
        
        # Get tickets that might have breached SLA
        active_tickets = Support.objects.filter(
            status__in=[Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS],
            sla_target_date__lt=timezone.now(),
            sla_breach=False,
            is_deleted=False
        )
        
        breached_count = 0
        
        for ticket in active_tickets:
            ticket.sla_breach = True
            ticket.sla_status = Support.SLAStatus.BREACHED
            ticket.save()
            
            # Log SLA breach
            TicketActivity.objects.create(
                ticket=ticket,
                action=TicketActivity.Action.UPDATED,
                details=f"SLA breach detected. Target date was {ticket.sla_target_date}"
            )
            
            # Send SLA breach notification
            SupportTicketService.send_sla_breach_notification(ticket)
            
            breached_count += 1
            logger.warning(f"SLA breach detected for ticket {ticket.ticket_id}")
        
        return breached_count

    @staticmethod
    def generate_user_workload_report(user_id=None):
        """Generate workload report for user(s)"""
        
        users_query = User.objects.filter(is_active=True)
        if user_id:
            users_query = users_query.filter(id=user_id)
        
        report = []
        
        for user in users_query:
            user_tickets = Support.objects.filter(
                assigned_to_user=user,
                is_deleted=False
            )
            
            active_tickets = user_tickets.filter(
                status__in=[Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS]
            )
            
            overdue_tickets = active_tickets.filter(due_date__lt=timezone.now())
            
            report.append({
                'user': user,
                'total_tickets': user_tickets.count(),
                'active_tickets': active_tickets.count(),
                'overdue_tickets': overdue_tickets.count(),
                'resolved_tickets': user_tickets.filter(status=Support.Status.RESOLVED).count(),
                'critical_tickets': active_tickets.filter(priority=Support.Priority.CRITICAL).count(),
                'avg_resolution_time': SupportTicketService.calculate_avg_resolution_time(user_tickets),
            })
        
        return report

    # Notification methods
    @staticmethod
    def send_creation_notification(ticket):
        """Send notification when ticket is created"""
        
        try:
            # Send to assigned user if exists
            if ticket.assigned_to_user:
                SupportTicketService._send_email_notification(
                    ticket.assigned_to_user.email,
                    f'New Ticket Assigned: {ticket.ticket_id}',
                    'support/emails/ticket_assigned.html',
                    {'ticket': ticket}
                )
            
            # Send to CC users
            for cc_user in ticket.cc_users.all():
                SupportTicketService._send_email_notification(
                    cc_user.email,
                    f'New Ticket Created: {ticket.ticket_id}',
                    'support/emails/ticket_created.html',
                    {'ticket': ticket}
                )
                
        except Exception as e:
            logger.error(f"Error sending creation notification: {str(e)}")

    @staticmethod
    def send_status_change_notification(ticket, old_status, new_status):
        """Send notification when ticket status changes"""
        
        try:
            recipients = [ticket.user.email]
            
            if ticket.assigned_to_user:
                recipients.append(ticket.assigned_to_user.email)
            
            recipients.extend([user.email for user in ticket.cc_users.all()])
            
            for email in set(recipients):  # Remove duplicates
                SupportTicketService._send_email_notification(
                    email,
                    f'Ticket Status Updated: {ticket.ticket_id}',
                    'support/emails/status_changed.html',
                    {
                        'ticket': ticket,
                        'old_status': old_status,
                        'new_status': new_status
                    }
                )
                
        except Exception as e:
            logger.error(f"Error sending status change notification: {str(e)}")

    @staticmethod
    def send_assignment_notification(ticket, assigned_user):
        """Send notification when ticket is assigned"""
        
        try:
            SupportTicketService._send_email_notification(
                assigned_user.email,
                f'Ticket Assigned to You: {ticket.ticket_id}',
                'support/emails/ticket_assigned.html',
                {'ticket': ticket}
            )
            
        except Exception as e:
            logger.error(f"Error sending assignment notification: {str(e)}")

    @staticmethod
    def send_comment_notification(ticket, comment):
        """Send notification when comment is added"""
        
        try:
            recipients = [ticket.user.email]
            
            if ticket.assigned_to_user:
                recipients.append(ticket.assigned_to_user.email)
            
            recipients.extend([user.email for user in ticket.cc_users.all()])
            
            # Remove comment author from recipients
            if comment.user.email in recipients:
                recipients.remove(comment.user.email)
            
            for email in set(recipients):
                SupportTicketService._send_email_notification(
                    email,
                    f'New Comment on Ticket: {ticket.ticket_id}',
                    'support/emails/comment_added.html',
                    {
                        'ticket': ticket,
                        'comment': comment
                    }
                )
                
        except Exception as e:
            logger.error(f"Error sending comment notification: {str(e)}")

    @staticmethod
    def send_escalation_notification(ticket, reason):
        """Send notification when ticket is escalated"""
        
        try:
            # Send to managers/supervisors
            managers = User.objects.filter(is_staff=True, groups__name='Manager')
            
            for manager in managers:
                SupportTicketService._send_email_notification(
                    manager.email,
                    f'Ticket Escalated: {ticket.ticket_id}',
                    'support/emails/ticket_escalated.html',
                    {
                        'ticket': ticket,
                        'reason': reason
                    }
                )
                
        except Exception as e:
            logger.error(f"Error sending escalation notification: {str(e)}")

    @staticmethod
    def send_sla_breach_notification(ticket):
        """Send notification when SLA is breached"""
        
        try:
            # Send to assigned user and managers
            recipients = []
            
            if ticket.assigned_to_user:
                recipients.append(ticket.assigned_to_user.email)
            
            managers = User.objects.filter(is_staff=True, groups__name='Manager')
            recipients.extend([manager.email for manager in managers])
            
            for email in set(recipients):
                SupportTicketService._send_email_notification(
                    email,
                    f'SLA Breach Alert: {ticket.ticket_id}',
                    'support/emails/sla_breach.html',
                    {'ticket': ticket}
                )
                
        except Exception as e:
            logger.error(f"Error sending SLA breach notification: {str(e)}")

    # Private helper methods
    @staticmethod
    def _send_email_notification(email, subject, template, context):
        """Send email notification"""
        
        try:
            html_content = render_to_string(template, context)
            send_mail(
                subject=subject,
                message='',  # Plain text version
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                html_message=html_content,
                fail_silently=False
            )
            
        except Exception as e:
            logger.error(f"Error sending email to {email}: {str(e)}")

    @staticmethod
    def _handle_attachments(ticket, attachments, user):
        """Handle file attachments for tickets"""
        
        from .models import TicketAttachment
        
        for attachment in attachments:
            TicketAttachment.objects.create(
                ticket=ticket,
                file=attachment,
                uploaded_by=user,
                file_size=attachment.size,
                file_type=attachment.content_type
            )

    @staticmethod
    def _handle_comment_attachments(activity, attachments, user):
        """Handle file attachments for comments"""
        
        from .models import CommentAttachment
        
        for attachment in attachments:
            CommentAttachment.objects.create(
                ticket_activity=activity,
                file=attachment,
                original_filename=attachment.name,
                file_size=attachment.size,
                content_type=attachment.content_type,
                uploaded_by=user
            )

    @staticmethod
    def _get_daily_trend(start_date, end_date):
        """Get daily ticket creation trend"""
        
        from django.db.models import Count
        from django.db.models.functions import TruncDate
        
        daily_counts = Support.objects.filter(
            created_at__date__gte=start_date.date(),
            created_at__date__lte=end_date.date(),
            is_deleted=False
        ).annotate(
            date=TruncDate('created_at')
        ).values('date').annotate(
            count=Count('id')
        ).order_by('date')
        
        return list(daily_counts)

    @staticmethod
    def _format_duration(duration):
        """Format duration to human readable string"""
        
        if not duration:
            return "N/A"
        
        total_seconds = int(duration.total_seconds())
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60
        
        if days > 0:
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m"
        else:
            return f"{minutes}m"


class TicketSearchService:
    """Service for advanced ticket searching and filtering"""

    @staticmethod
    def search_tickets(query, filters=None, user=None):
        """Advanced ticket search with multiple criteria"""
        
        # Base queryset
        tickets = Support.objects.select_related(
            'user', 'assigned_to_user'
        ).filter(is_deleted=False)
        
        # Apply user permissions
        if user and not user.is_staff:
            tickets = tickets.filter(
                Q(user=user) |
                Q(assigned_to_user=user) |
                Q(cc_users=user)
            ).distinct()
        
        # Apply text search
        if query:
            tickets = tickets.filter(
                Q(subject__icontains=query) |
                Q(description__icontains=query) |
                Q(ticket_id__icontains=query) |
                Q(user__username__icontains=query) |
                Q(user__first_name__icontains=query) |
                Q(user__last_name__icontains=query)
            )
        
        # Apply filters
        if filters:
            tickets = TicketSearchService._apply_filters(tickets, filters)
        
        return tickets

    @staticmethod
    def _apply_filters(queryset, filters):
        """Apply various filters to the queryset"""
        
        # Status filter
        if filters.get('status'):
            queryset = queryset.filter(status__in=filters['status'])
        
        # Priority filter
        if filters.get('priority'):
            queryset = queryset.filter(priority__in=filters['priority'])
        
        # Issue type filter
        if filters.get('issue_type'):
            queryset = queryset.filter(issue_type__in=filters['issue_type'])
        
        # Assigned user filter
        if filters.get('assigned_to'):
            queryset = queryset.filter(assigned_to_user__in=filters['assigned_to'])
        
        # Date range filter
        if filters.get('date_from'):
            queryset = queryset.filter(created_at__gte=filters['date_from'])
        
        if filters.get('date_to'):
            queryset = queryset.filter(created_at__lte=filters['date_to'])
        
        # Overdue filter
        if filters.get('overdue'):
            queryset = queryset.filter(due_date__lt=timezone.now())
        
        # SLA breach filter
        if filters.get('sla_breached'):
            queryset = queryset.filter(sla_breach=True)
        
        return queryset