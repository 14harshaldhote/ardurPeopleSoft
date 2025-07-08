"""
Support Utilities Module
Utility functions for the support ticket system
"""

import os
import mimetypes
from datetime import datetime, timedelta
from django.utils import timezone
from django.core.mail import send_mail, EmailMultiAlternatives
from django.template.loader import render_to_string
from django.conf import settings
from django.contrib.auth.models import User
from django.db.models import Q, Count, Avg, Case, When
from django.utils.html import strip_tags
from trueAlign.models import Support, TicketActivity


class SLACalculator:
    """Utility class for SLA calculations"""

    # SLA target times in hours
    SLA_TARGETS = {
        Support.Priority.CRITICAL: 4,    # 4 hours
        Support.Priority.HIGH: 8,        # 8 hours
        Support.Priority.MEDIUM: 24,     # 24 hours
        Support.Priority.LOW: 48,        # 48 hours
    }

    @classmethod
    def calculate_sla_target_date(cls, priority, created_at=None):
        """Calculate SLA target date based on priority"""
        if not created_at:
            created_at = timezone.now()

        target_hours = cls.SLA_TARGETS.get(priority, 24)
        return created_at + timedelta(hours=target_hours)

    @classmethod
    def get_sla_status(cls, ticket):
        """Get comprehensive SLA status for a ticket"""
        if not ticket.sla_target_date:
            return {
                'status': 'No SLA Set',
                'time_remaining': None,
                'is_breached': False,
                'percentage_used': 0,
                'days_remaining': 0,
                'hours_remaining': 0,
            }

        now = timezone.now()
        sla_info = {
            'status': 'Unknown',
            'time_remaining': None,
            'is_breached': False,
            'percentage_used': 0,
            'days_remaining': 0,
            'hours_remaining': 0,
        }

        if ticket.resolved_at:
            # Ticket is resolved
            if ticket.resolved_at <= ticket.sla_target_date:
                sla_info['status'] = 'Met'
                sla_info['is_breached'] = False
            else:
                sla_info['status'] = 'Breached'
                sla_info['is_breached'] = True
                # Calculate how long it was overdue
                overdue_time = ticket.resolved_at - ticket.sla_target_date
                sla_info['overdue_hours'] = overdue_time.total_seconds() / 3600
        else:
            # Ticket is still open
            if now > ticket.sla_target_date:
                sla_info['status'] = 'Breached'
                sla_info['is_breached'] = True
                # Calculate how long it's been overdue
                overdue_time = now - ticket.sla_target_date
                sla_info['overdue_hours'] = overdue_time.total_seconds() / 3600
            else:
                sla_info['status'] = 'On Track'
                sla_info['time_remaining'] = ticket.sla_target_date - now

                # Calculate days and hours remaining
                total_seconds = sla_info['time_remaining'].total_seconds()
                sla_info['days_remaining'] = int(total_seconds // 86400)
                sla_info['hours_remaining'] = int((total_seconds % 86400) // 3600)

        # Calculate percentage of SLA time used
        if ticket.created_at:
            total_sla_time = ticket.sla_target_date - ticket.created_at
            elapsed_time = (ticket.resolved_at or now) - ticket.created_at
            sla_info['percentage_used'] = min(100, (elapsed_time.total_seconds() / total_sla_time.total_seconds()) * 100)

        return sla_info

    @classmethod
    def get_sla_color_class(cls, sla_info):
        """Get CSS color class based on SLA status"""
        if sla_info['is_breached']:
            return 'text-danger'
        elif sla_info['percentage_used'] > 80:
            return 'text-warning'
        else:
            return 'text-success'


class FileUtilities:
    """File handling utility functions"""

    # Maximum file size (10MB)
    MAX_FILE_SIZE = 10 * 1024 * 1024

    # Allowed file extensions
    ALLOWED_EXTENSIONS = {
        'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.svg'],
        'document': ['.pdf', '.doc', '.docx', '.txt', '.rtf', '.odt'],
        'spreadsheet': ['.xls', '.xlsx', '.csv', '.ods'],
        'archive': ['.zip', '.rar', '.7z', '.tar', '.gz'],
        'other': ['.log', '.json', '.xml']
    }

    @classmethod
    def validate_file(cls, file):
        """Validate uploaded file"""
        errors = []

        # Check file size
        if file.size > cls.MAX_FILE_SIZE:
            errors.append(f'File size exceeds maximum limit of {cls.MAX_FILE_SIZE / (1024*1024):.1f}MB')

        # Check file extension
        file_ext = os.path.splitext(file.name)[1].lower()
        allowed_exts = []
        for ext_list in cls.ALLOWED_EXTENSIONS.values():
            allowed_exts.extend(ext_list)

        if file_ext not in allowed_exts:
            errors.append(f'File type "{file_ext}" is not allowed')

        return errors

    @classmethod
    def get_file_type_category(cls, filename_or_content_type):
        """Determine file category from filename or content type"""
        if filename_or_content_type.startswith('image/'):
            return 'image'
        elif filename_or_content_type.startswith('video/'):
            return 'video'
        elif filename_or_content_type.startswith('audio/'):
            return 'audio'
        elif 'pdf' in filename_or_content_type.lower():
            return 'pdf'
        elif any(doc_type in filename_or_content_type.lower() for doc_type in ['word', 'document', 'text']):
            return 'document'
        elif any(sheet_type in filename_or_content_type.lower() for sheet_type in ['excel', 'spreadsheet', 'csv']):
            return 'spreadsheet'
        elif any(arch_type in filename_or_content_type.lower() for arch_type in ['zip', 'rar', 'archive']):
            return 'archive'
        else:
            # Check by file extension
            if isinstance(filename_or_content_type, str):
                ext = os.path.splitext(filename_or_content_type)[1].lower()
                for category, extensions in cls.ALLOWED_EXTENSIONS.items():
                    if ext in extensions:
                        return category

        return 'file'

    @classmethod
    def format_file_size(cls, size_bytes):
        """Format file size in human readable format"""
        if size_bytes == 0:
            return "0 B"

        size_names = ["B", "KB", "MB", "GB", "TB"]
        size_bytes = float(size_bytes)
        i = 0

        while size_bytes >= 1024.0 and i < len(size_names) - 1:
            size_bytes /= 1024.0
            i += 1

        return f"{size_bytes:.1f} {size_names[i]}"

    @classmethod
    def get_file_icon_class(cls, file_category):
        """Get FontAwesome icon class for file category"""
        icon_mapping = {
            'image': 'fas fa-image',
            'video': 'fas fa-video',
            'audio': 'fas fa-music',
            'pdf': 'fas fa-file-pdf',
            'document': 'fas fa-file-word',
            'spreadsheet': 'fas fa-file-excel',
            'archive': 'fas fa-file-archive',
            'text': 'fas fa-file-alt',
            'file': 'fas fa-file',
        }
        return icon_mapping.get(file_category, 'fas fa-file')


class NotificationService:
    """Email notification service for support tickets"""

    @classmethod
    def send_ticket_notification(cls, ticket, action, user=None, additional_context=None):
        """Send email notification for ticket events"""
        if not getattr(settings, 'EMAIL_NOTIFICATIONS_ENABLED', False):
            return

        # Get recipients
        recipients = cls._get_notification_recipients(ticket, action)

        if not recipients:
            return

        # Prepare context
        context = {
            'ticket': ticket,
            'action': action,
            'user': user,
            'site_name': getattr(settings, 'SITE_NAME', 'Support System'),
            'site_url': getattr(settings, 'SITE_URL', 'http://localhost:8000'),
        }

        if additional_context:
            context.update(additional_context)

        # Generate email content
        subject = cls._generate_email_subject(ticket, action)
        html_content = render_to_string('support/emails/ticket_notification.html', context)
        text_content = strip_tags(html_content)

        # Send email
        try:
            msg = EmailMultiAlternatives(
                subject=subject,
                body=text_content,
                from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', 'noreply@example.com'),
                to=recipients
            )
            msg.attach_alternative(html_content, "text/html")
            msg.send()
        except Exception as e:
            # Log error but don't raise
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to send notification email: {str(e)}")

    @classmethod
    def _get_notification_recipients(cls, ticket, action):
        """Get list of email recipients for notification"""
        recipients = set()

        # Always notify ticket creator (unless they performed the action)
        if ticket.user.email:
            recipients.add(ticket.user.email)

        # Notify assigned user
        if ticket.assigned_to_user and ticket.assigned_to_user.email:
            recipients.add(ticket.assigned_to_user.email)

        # Notify CC users
        for cc_user in ticket.cc_users.all():
            if cc_user.email:
                recipients.add(cc_user.email)

        # For certain actions, notify managers/admins
        if action in ['CREATED', 'ESCALATED']:
            admin_emails = User.objects.filter(
                Q(is_superuser=True) | Q(groups__name__in=['Admin', 'HR']),
                email__isnull=False
            ).values_list('email', flat=True)
            recipients.update(admin_emails)

        return list(recipients)

    @classmethod
    def _generate_email_subject(cls, ticket, action):
        """Generate email subject for notification"""
        action_subjects = {
            'CREATED': f'New Support Ticket: {ticket.ticket_id}',
            'UPDATED': f'Ticket Updated: {ticket.ticket_id}',
            'ASSIGNED': f'Ticket Assigned: {ticket.ticket_id}',
            'COMMENTED': f'New Comment: {ticket.ticket_id}',
            'RESOLVED': f'Ticket Resolved: {ticket.ticket_id}',
            'CLOSED': f'Ticket Closed: {ticket.ticket_id}',
            'REOPENED': f'Ticket Reopened: {ticket.ticket_id}',
            'ESCALATED': f'Ticket Escalated: {ticket.ticket_id}',
        }

        return action_subjects.get(action, f'Ticket Update: {ticket.ticket_id}')


class ReportGenerator:
    """Generate various reports for support tickets"""

    @classmethod
    def generate_summary_report(cls, tickets_queryset):
        """Generate summary statistics report"""
        total_tickets = tickets_queryset.count()

        if total_tickets == 0:
            return {
                'total_tickets': 0,
                'status_breakdown': {},
                'priority_breakdown': {},
                'sla_performance': {},
                'avg_resolution_time': None,
            }

        # Status breakdown
        status_breakdown = {}
        for status_choice in Support.Status.choices:
            count = tickets_queryset.filter(status=status_choice[0]).count()
            status_breakdown[status_choice[1]] = {
                'count': count,
                'percentage': (count / total_tickets) * 100
            }

        # Priority breakdown
        priority_breakdown = {}
        for priority_choice in Support.Priority.choices:
            count = tickets_queryset.filter(priority=priority_choice[0]).count()
            priority_breakdown[priority_choice[1]] = {
                'count': count,
                'percentage': (count / total_tickets) * 100
            }

        # SLA Performance
        sla_met = tickets_queryset.filter(sla_breach=False, resolved_at__isnull=False).count()
        sla_breached = tickets_queryset.filter(sla_breach=True).count()

        sla_performance = {
            'met': sla_met,
            'breached': sla_breached,
            'met_percentage': (sla_met / total_tickets) * 100 if total_tickets > 0 else 0,
            'breached_percentage': (sla_breached / total_tickets) * 100 if total_tickets > 0 else 0,
        }

        # Average resolution time
        resolved_tickets = tickets_queryset.filter(resolution_time__isnull=False)
        avg_resolution_time = resolved_tickets.aggregate(
            avg_time=Avg('resolution_time')
        )['avg_time']

        return {
            'total_tickets': total_tickets,
            'status_breakdown': status_breakdown,
            'priority_breakdown': priority_breakdown,
            'sla_performance': sla_performance,
            'avg_resolution_time': avg_resolution_time,
        }

    @classmethod
    def generate_agent_performance_report(cls, tickets_queryset):
        """Generate agent performance report"""
        # Get tickets assigned to users
        assigned_tickets = tickets_queryset.filter(assigned_to_user__isnull=False)

        # Group by assigned user
        agent_stats = {}
        for ticket in assigned_tickets.select_related('assigned_to_user'):
            agent = ticket.assigned_to_user
            agent_name = agent.get_full_name() or agent.username

            if agent_name not in agent_stats:
                agent_stats[agent_name] = {
                    'total_assigned': 0,
                    'resolved': 0,
                    'in_progress': 0,
                    'sla_met': 0,
                    'sla_breached': 0,
                    'avg_resolution_time': None,
                }

            stats = agent_stats[agent_name]
            stats['total_assigned'] += 1

            if ticket.status == Support.Status.RESOLVED:
                stats['resolved'] += 1
            elif ticket.status in [Support.Status.IN_PROGRESS, Support.Status.OPEN]:
                stats['in_progress'] += 1

            if ticket.resolved_at:
                if ticket.sla_breach:
                    stats['sla_breached'] += 1
                else:
                    stats['sla_met'] += 1

        return agent_stats


class SearchHelper:
    """Helper functions for searching and filtering tickets"""

    @classmethod
    def build_search_query(cls, search_params):
        """Build Django Q object for search parameters"""
        query = Q()

        # Text search
        if search_params.get('q'):
            text_query = search_params['q']
            query &= (
                Q(ticket_id__icontains=text_query) |
                Q(subject__icontains=text_query) |
                Q(description__icontains=text_query) |
                Q(user__first_name__icontains=text_query) |
                Q(user__last_name__icontains=text_query) |
                Q(user__username__icontains=text_query)
            )

        # Status filter
        if search_params.get('status'):
            if isinstance(search_params['status'], list):
                query &= Q(status__in=search_params['status'])
            else:
                query &= Q(status=search_params['status'])

        # Priority filter
        if search_params.get('priority'):
            if isinstance(search_params['priority'], list):
                query &= Q(priority__in=search_params['priority'])
            else:
                query &= Q(priority=search_params['priority'])

        # Date range filter
        if search_params.get('date_from'):
            query &= Q(created_at__gte=search_params['date_from'])

        if search_params.get('date_to'):
            query &= Q(created_at__lte=search_params['date_to'])

        # Assigned user filter
        if search_params.get('assigned_to'):
            if search_params['assigned_to'] == 'unassigned':
                query &= Q(assigned_to_user__isnull=True)
            else:
                query &= Q(assigned_to_user_id=search_params['assigned_to'])

        # Issue type filter
        if search_params.get('issue_type'):
            query &= Q(issue_type=search_params['issue_type'])

        return query


class PermissionHelper:
    """Helper functions for permission checking"""

    @classmethod
    def get_user_role_hierarchy(cls, user):
        """Get user's role hierarchy level (higher number = more permissions)"""
        if user.is_superuser:
            return 100
        elif user.groups.filter(name='Admin').exists():
            return 90
        elif user.groups.filter(name='HR').exists():
            return 80
        elif user.groups.filter(name='Manager').exists():
            return 70
        elif user.is_staff:
            return 60
        else:
            return 10

    @classmethod
    def can_user_access_ticket(cls, user, ticket):
        """Check if user can access a specific ticket"""
        # Superuser and admin can access all
        if user.is_superuser or user.groups.filter(name='Admin').exists():
            return True

        # HR can access HR tickets
        if (user.groups.filter(name='HR').exists() and
            ticket.assigned_group == Support.AssignedGroup.HR):
            return True

        # User can access their own tickets
        if ticket.user == user:
            return True

        # User can access tickets assigned to them
        if ticket.assigned_to_user == user:
            return True

        # User can access tickets they're CC'd on
        if user in ticket.cc_users.all():
            return True

        return False


class DateTimeHelper:
    """Helper functions for date/time operations"""

    @classmethod
    def format_duration(cls, duration):
        """Format timedelta in human readable format"""
        if not duration:
            return "N/A"

        total_seconds = int(duration.total_seconds())
        days = total_seconds // 86400
        hours = (total_seconds % 86400) // 3600
        minutes = (total_seconds % 3600) // 60

        parts = []
        if days > 0:
            parts.append(f"{days} day{'s' if days != 1 else ''}")
        if hours > 0:
            parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
        if minutes > 0 and days == 0:  # Only show minutes if less than a day
            parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")

        if not parts:
            return "Less than a minute"

        return ", ".join(parts)

    @classmethod
    def get_business_hours_between(cls, start_date, end_date):
        """Calculate business hours between two dates (Mon-Fri, 9-17)"""
        # This is a simplified version - you might want to use a library like
        # python-business-time for more complex business hour calculations

        if not start_date or not end_date:
            return 0

        current_date = start_date
        business_hours = 0

        while current_date < end_date:
            # Check if it's a weekday (0=Monday, 6=Sunday)
            if current_date.weekday() < 5:  # Monday to Friday
                # Calculate hours for this day
                day_start = current_date.replace(hour=9, minute=0, second=0, microsecond=0)
                day_end = current_date.replace(hour=17, minute=0, second=0, microsecond=0)

                # Adjust for partial days
                actual_start = max(current_date, day_start)
                actual_end = min(end_date, day_end)

                if actual_start < actual_end:
                    day_hours = (actual_end - actual_start).total_seconds() / 3600
                    business_hours += day_hours

            # Move to next day
            current_date = current_date.replace(hour=0, minute=0, second=0, microsecond=0)
            current_date += timedelta(days=1)

        return business_hours
