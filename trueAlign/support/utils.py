"""
Comprehensive Utils Module for Smart Ticketing System
Contains helper functions, permissions, validators, and utility classes
"""

import re
import json
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set # <-- Add Set here!
from django.contrib.auth.models import User, Group
from django.core.exceptions import ValidationError, PermissionDenied
from django.utils import timezone
from django.db.models import Q, Count, Avg, QuerySet
from django.core.cache import cache
from django.conf import settings
from django.db.models import F # For get_dashboard_stats example
from trueAlign.models import Support, UserDetails


class PermissionManager:
    """
    Centralized permission management for ticket operations
    """

    @staticmethod
    def get_user_roles(user: User) -> Dict[str, bool]:
        """
        Get user roles and permissions using Django groups efficiently.
        Checks directly for group membership.
        """
        if not user.is_authenticated:
            return {
                'is_admin': False,
                'is_manager': False,
                'is_hr': False,
                'is_employee': False,
                'is_staff': False
            }

        # Directly check for group existence using .filter().exists()
        # This is very efficient as it performs a single EXISTS query for each check.
        return {
            'is_admin': bool(user.is_superuser or Group.objects.filter(name='Admin', user=user).exists()),
            'is_manager': bool(Group.objects.filter(name='Manager', user=user).exists()),
            'is_hr': bool(Group.objects.filter(name='HR', user=user).exists()),
            'is_employee': bool(Group.objects.filter(name='Employee', user=user).exists()),
            'is_staff': bool(user.is_staff)
        }

    @staticmethod
    def user_has_group(user: User, group_name: str) -> bool:
        """
        Check if user belongs to a specific group efficiently
        """
        return user.groups.filter(name=group_name).exists()

    @staticmethod
    def user_has_any_group(user: User, group_names: List[str]) -> bool:
        """
        Check if user belongs to any of the specified groups
        """
        return user.groups.filter(name__in=group_names).exists()

    @staticmethod
    def get_user_group_names(user: User) -> List[str]:
        """
        Get list of group names for a user with caching
        """
        if not user.is_authenticated:
            return []

        cache_key = f"user_groups_{user.id}"
        cached_groups = cache.get(cache_key)

        if cached_groups is not None:
            return cached_groups

        group_names = list(user.groups.values_list('name', flat=True))
        cache.set(cache_key, group_names, 300)  # Cache for 5 minutes

        return group_names

    @staticmethod
    def can_view_ticket(user: User, ticket: Support) -> bool:
        """
        Check if user can view a specific ticket
        """
        if not user.is_authenticated:
            return False

        # Admin can view all tickets
        if user.is_superuser or PermissionManager.user_has_group(user, 'Admin'):
            return True

        # Users can view their own tickets
        if ticket.user == user:
            return True

        # Assigned agent can view ticket
        if ticket.assigned_to_user == user:
            return True

        # CC users can view ticket
        if user in ticket.cc_users.all():
            return True

        # Get user groups once for efficiency
        user_group_names = PermissionManager.get_user_group_names(user)

        # Managers can view tickets in their groups
        if 'Manager' in user_group_names or user.is_staff:
            if ticket.assigned_group in user_group_names:
                return True

        # HR can view HR tickets
        if 'HR' in user_group_names and ticket.assigned_group == 'HR':
            return True

        return False

    @staticmethod
    def can_edit_ticket(user: User, ticket: Support) -> bool:
        """
        Check if user can edit a specific ticket
        """
        if not user.is_authenticated:
            return False

        # Admin can edit all tickets
        if user.is_superuser or PermissionManager.user_has_group(user, 'Admin'):
            return True

        # Assigned agent can edit ticket
        if ticket.assigned_to_user == user:
            return True

        # Get user groups once for efficiency
        user_group_names = PermissionManager.get_user_group_names(user)

        # Managers can edit tickets in their groups
        if 'Manager' in user_group_names or user.is_staff:
            if ticket.assigned_group in user_group_names:
                return True

        # HR can edit HR tickets
        if 'HR' in user_group_names and ticket.assigned_group == 'HR':
            return True

        # Ticket creator can edit their own ticket (with restrictions)
        if ticket.user == user and ticket.status not in ['Resolved', 'Closed']:
            return True

        return False

    @staticmethod
    def can_assign_ticket(user: User, ticket: Support) -> bool:
        """
        Check if user can assign a ticket
        """
        if not user.is_authenticated:
            return False

        # Admin can assign all tickets
        if user.is_superuser or PermissionManager.user_has_group(user, 'Admin'):
            return True

        # Get user groups once for efficiency
        user_group_names = PermissionManager.get_user_group_names(user)

        # Managers can assign tickets in their groups
        if 'Manager' in user_group_names or user.is_staff:
            if ticket.assigned_group in user_group_names:
                return True

        # HR can assign HR tickets
        if 'HR' in user_group_names and ticket.assigned_group == 'HR':
            return True

        return False

    @staticmethod
    def can_change_status(user: User, ticket: Support, new_status: str) -> bool:
        """
        Check if user can change ticket status
        """
        if not user.is_authenticated:
            return False

        # Admin can change any status
        if user.is_superuser or PermissionManager.user_has_group(user, 'Admin'):
            return True

        # Assigned agent can change status
        if ticket.assigned_to_user == user:
            return True

        # Get user groups once for efficiency
        user_group_names = PermissionManager.get_user_group_names(user)

        # Managers can change status in their groups
        if 'Manager' in user_group_names or user.is_staff:
            if ticket.assigned_group in user_group_names:
                return True

        # HR can change status of HR tickets
        if 'HR' in user_group_names and ticket.assigned_group == 'HR':
            return True

        # Ticket creator can respond to pending status
        if ticket.user == user and ticket.status == Support.Status.PENDING_USER:
            return new_status in [Support.Status.OPEN, Support.Status.IN_PROGRESS]

        return False

    @staticmethod
    def can_escalate_ticket(user: User, ticket: Support) -> bool:
        """
        Check if user can escalate a ticket
        """
        if not user.is_authenticated:
            return False

        # Admin can escalate any ticket
        if user.is_superuser or PermissionManager.user_has_group(user, 'Admin'):
            return True

        # Assigned agent can escalate their tickets
        if ticket.assigned_to_user == user:
            return True

        # Get user groups once for efficiency
        user_group_names = PermissionManager.get_user_group_names(user)

        # Managers can escalate tickets in their groups
        if 'Manager' in user_group_names or user.is_staff:
            if ticket.assigned_group in user_group_names:
                return True

        # HR can escalate HR tickets
        if 'HR' in user_group_names and ticket.assigned_group == 'HR':
            return True

        return False

    @staticmethod
    def can_delete_ticket(user: User, ticket: Support) -> bool:
        """
        Check if user can delete a ticket
        """
        if not user.is_authenticated:
            return False

        # Only admin can delete tickets
        return user.is_superuser or PermissionManager.user_has_group(user, 'Admin')

    @staticmethod
    def can_view_internal_comments(user: User, ticket: Support) -> bool:
        """
        Check if user can view internal comments
        """
        if not user.is_authenticated:
            return False

        # Admin can view internal comments
        if user.is_superuser or PermissionManager.user_has_group(user, 'Admin'):
            return True

        # Assigned agent can view internal comments
        if ticket.assigned_to_user == user:
            return True

        # Get user groups once for efficiency
        user_group_names = PermissionManager.get_user_group_names(user)

        # Managers can view internal comments
        if 'Manager' in user_group_names or user.is_staff:
            return True

        # HR can view internal comments on HR tickets
        if 'HR' in user_group_names and ticket.assigned_group == 'HR':
            return True

        return False

    @staticmethod
    def get_assignable_users(user: User, ticket: Support) -> List[User]:
        """
        Get list of users that can be assigned to a ticket
        """
        if not PermissionManager.can_assign_ticket(user, ticket):
            return []

        assignable_users = []

        # Admin can assign to any active user
        if user.is_superuser or PermissionManager.user_has_group(user, 'Admin'):
            assignable_users = list(User.objects.filter(is_active=True))
        else:
            # Get users in the ticket's assigned group
            if ticket.assigned_group:
                try:
                    group = Group.objects.get(name=ticket.assigned_group)
                    assignable_users = list(group.user_set.filter(is_active=True))
                except Group.DoesNotExist:
                    pass

        return assignable_users

    @staticmethod
    def get_user_accessible_groups(user: User) -> List[str]:
        """
        Get list of groups/departments that user can access based on their role
        """
        if not user.is_authenticated:
            return []

        # Admin can access all groups
        if user.is_superuser or PermissionManager.user_has_group(user, 'Admin'):
            return list(Group.objects.values_list('name', flat=True))

        # Get user's own groups
        user_group_names = PermissionManager.get_user_group_names(user)

        # Managers can access their own groups
        if 'Manager' in user_group_names or user.is_staff:
            return user_group_names

        # HR can access HR group
        if 'HR' in user_group_names:
            return ['HR']

        # Employees can only access their own groups
        return user_group_names

    @staticmethod
    def get_filtered_tickets_queryset(user: User, base_queryset=None):
        """
        Get tickets queryset filtered by user permissions
        """
        if base_queryset is None:
            base_queryset = Support.objects.all()

        if not user.is_authenticated:
            return base_queryset.none()

        # Get user groups for group-based filtering
        user_group_names = PermissionManager.get_user_group_names(user)

        # Admin can see all tickets
        if user.is_superuser or PermissionManager.user_has_group(user, 'Admin'):
            return base_queryset

        # Manager can see all tickets (not just their group)
        if PermissionManager.user_has_group(user, 'Manager') or PermissionManager.user_has_group(user, 'Management'):
            return base_queryset

        # HR can see all tickets (not just HR tickets)
        if PermissionManager.user_has_group(user, 'HR'):
            return base_queryset

        # Staff members can see all tickets
        if user.is_staff:
            return base_queryset

        # Build filter conditions for regular users (Employee, Client, etc.)
        q_objects = Q()

        # User's own tickets
        q_objects |= Q(user=user)

        # Assigned tickets
        q_objects |= Q(assigned_to_user=user)

        # CC tickets
        q_objects |= Q(cc_users=user)

        # For other groups, they can see tickets assigned to their groups
        if user_group_names:
            q_objects |= Q(assigned_group__in=user_group_names)

        return base_queryset.filter(q_objects).distinct()


    @staticmethod
    def clear_user_cache(user: User):
        """
        Clear cached data for a user (useful when user groups change)
        """
        cache.delete(f"user_groups_{user.id}")

    @staticmethod
    def get_user_role_display(user: User) -> str:
        """
        Get user's primary role for display purposes
        """
        if not user.is_authenticated:
            return "Guest"

        if user.is_superuser:
            return "Super Admin"

        user_group_names = PermissionManager.get_user_group_names(user)

        # Priority order for role display
        role_priority = ['Admin', 'Manager', 'HR', 'Employee']

        for role in role_priority:
            if role in user_group_names:
                return role

        return "User"



class TicketValidator:
    """
    Validation utilities for ticket operations
    """

    @staticmethod
    def validate_ticket_data(data: Dict) -> Dict[str, str]:
        """
        Validate ticket creation/update data
        """
        errors = {}

        # Required fields
        required_fields = ['subject', 'description', 'issue_type']
        for field in required_fields:
            if not data.get(field, '').strip():
                errors[field] = f'{field.replace("_", " ").title()} is required'

        # Subject validation
        if 'subject' in data:
            subject = data['subject'].strip()
            if len(subject) < 5:
                errors['subject'] = 'Subject must be at least 5 characters long'
            elif len(subject) > 200:
                errors['subject'] = 'Subject cannot exceed 200 characters'

        # Description validation
        if 'description' in data:
            description = data['description'].strip()
            if len(description) < 10:
                errors['description'] = 'Description must be at least 10 characters long'
            elif len(description) > 5000:
                errors['description'] = 'Description cannot exceed 5000 characters'

        # Priority validation
        if 'priority' in data:
            valid_priorities = [choice[0] for choice in Support.Priority.choices]
            if data['priority'] not in valid_priorities:
                errors['priority'] = 'Invalid priority selected'

        # Issue type validation
        if 'issue_type' in data:
            valid_issue_types = [choice[0] for choice in Support.IssueType.choices]
            if data['issue_type'] not in valid_issue_types:
                errors['issue_type'] = 'Invalid issue type selected'

        # Status validation
        if 'status' in data:
            valid_statuses = [choice[0] for choice in Support.Status.choices]
            if data['status'] not in valid_statuses:
                errors['status'] = 'Invalid status selected'

        # Asset ID validation
        if 'asset_id' in data and data['asset_id']:
            asset_id = data['asset_id'].strip()
            if not re.match(r'^[A-Z0-9-]+$', asset_id):
                errors['asset_id'] = 'Asset ID must contain only uppercase letters, numbers, and hyphens'

        return errors

    @staticmethod
    def validate_status_transition(old_status: str, new_status: str) -> bool:
        """
        Validate if status transition is allowed
        """
        allowed_transitions = {
            Support.Status.NEW: [
                Support.Status.OPEN,
                Support.Status.IN_PROGRESS,
                Support.Status.ASSIGNED
            ],
            Support.Status.OPEN: [
                Support.Status.IN_PROGRESS,
                Support.Status.PENDING_USER,
                Support.Status.PENDING_THIRD_PARTY,
                Support.Status.ON_HOLD,
                Support.Status.RESOLVED
            ],
            Support.Status.IN_PROGRESS: [
                Support.Status.PENDING_USER,
                Support.Status.PENDING_THIRD_PARTY,
                Support.Status.ON_HOLD,
                Support.Status.RESOLVED
            ],
            Support.Status.PENDING_USER: [
                Support.Status.OPEN,
                Support.Status.IN_PROGRESS,
                Support.Status.RESOLVED
            ],
            Support.Status.PENDING_THIRD_PARTY: [
                Support.Status.IN_PROGRESS,
                Support.Status.RESOLVED
            ],
            Support.Status.ON_HOLD: [
                Support.Status.OPEN,
                Support.Status.IN_PROGRESS,
                Support.Status.RESOLVED
            ],
            Support.Status.RESOLVED: [
                Support.Status.CLOSED,
                Support.Status.OPEN  # Reopening
            ],
            Support.Status.CLOSED: [
                Support.Status.OPEN  # Reopening
            ]
        }

        return new_status in allowed_transitions.get(old_status, [])

    @staticmethod
    def validate_attachment(file) -> Optional[str]:
        """
        Validate file attachment
        """
        if not file:
            return None

        # Check file size (max 10MB)
        max_size = 10 * 1024 * 1024  # 10MB
        if file.size > max_size:
            return f'File size cannot exceed {max_size / (1024 * 1024):.1f}MB'

        # Check file extension
        allowed_extensions = [
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
            '.txt', '.csv', '.png', '.jpg', '.jpeg', '.gif', '.bmp',
            '.zip', '.rar', '.7z', '.log'
        ]

        file_extension = file.name.lower().split('.')[-1]
        if f'.{file_extension}' not in allowed_extensions:
            return f'File type .{file_extension} is not allowed'

        return None


class TicketHelper:
    """
    Helper functions for ticket operations
    """

    @staticmethod
    def generate_ticket_id(issue_type: str) -> str:
        """
        Generate unique ticket ID
        """
        # Get issue type prefix
        issue_type_prefixes = {
            Support.IssueType.HARDWARE: 'HW',
            Support.IssueType.SOFTWARE: 'SW',
            Support.IssueType.NETWORK: 'NET',
            Support.IssueType.INTERNET: 'INT',
            Support.IssueType.APPLICATION: 'APP',
            Support.IssueType.HR: 'HR',
            Support.IssueType.ACCESS: 'ACC',
            Support.IssueType.SECURITY: 'SEC',
            Support.IssueType.SERVICE: 'SRV'
        }

        prefix = issue_type_prefixes.get(issue_type, 'TKT')

        # Get current date
        date_str = timezone.now().strftime('%Y%m%d')

        # Get next sequence number for today
        today_start = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + timedelta(days=1)

        today_count = Support.objects.filter(
            created_at__gte=today_start,
            created_at__lt=today_end,
            issue_type=issue_type
        ).count()

        sequence = str(today_count + 1).zfill(3)

        return f"{prefix}-{date_str}-{sequence}"

    @staticmethod
    def get_priority_color(priority: str) -> str:
        """
        Get color code for priority
        """
        colors = {
            Support.Priority.LOW: '#28a745',      # Green
            Support.Priority.MEDIUM: '#ffc107',   # Yellow
            Support.Priority.HIGH: '#fd7e14',     # Orange
            Support.Priority.CRITICAL: '#dc3545'  # Red
        }
        return colors.get(priority, '#6c757d')

    @staticmethod
    def get_status_color(status: str) -> str:
        """
        Get color code for status
        """
        colors = {
            Support.Status.NEW: '#17a2b8',              # Info
            Support.Status.OPEN: '#007bff',             # Primary
            Support.Status.IN_PROGRESS: '#ffc107',      # Warning
            Support.Status.PENDING_USER: '#fd7e14',     # Orange
            Support.Status.PENDING_THIRD_PARTY: '#6f42c1', # Purple
            Support.Status.ON_HOLD: '#6c757d',          # Secondary
            Support.Status.RESOLVED: '#28a745',         # Success
            Support.Status.CLOSED: '#343a40'            # Dark
        }
        return colors.get(status, '#6c757d')

    @staticmethod
    def format_duration(duration) -> str:
        """
        Format timedelta to human readable string
        """
        if not duration:
            return 'N/A'

        total_seconds = int(duration.total_seconds())

        if total_seconds < 60:
            return f"{total_seconds} seconds"
        elif total_seconds < 3600:
            minutes = total_seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''}"
        elif total_seconds < 86400:
            hours = total_seconds // 3600
            minutes = (total_seconds % 3600) // 60
            if minutes > 0:
                return f"{hours}h {minutes}m"
            return f"{hours} hour{'s' if hours != 1 else ''}"
        else:
            days = total_seconds // 86400
            hours = (total_seconds % 86400) // 3600
            if hours > 0:
                return f"{days}d {hours}h"
            return f"{days} day{'s' if days != 1 else ''}"

    @staticmethod
    def calculate_business_hours_between(start_time: datetime, end_time: datetime) -> float:
        """
        Calculate business hours between two datetimes
        """
        business_hours = 0
        current_time = start_time

        # Business hours configuration
        business_start = 9  # 9 AM
        business_end = 18   # 6 PM
        weekdays = [0, 1, 2, 3, 4]  # Monday to Friday

        while current_time < end_time:
            # Check if current day is a weekday
            if current_time.weekday() in weekdays:
                # Calculate start and end times for this day
                day_start = current_time.replace(hour=business_start, minute=0, second=0, microsecond=0)
                day_end = current_time.replace(hour=business_end, minute=0, second=0, microsecond=0)

                # Adjust for actual start and end times
                actual_start = max(current_time, day_start)
                actual_end = min(end_time, day_end)

                # Add business hours for this day
                if actual_start < actual_end:
                    business_hours += (actual_end - actual_start).total_seconds() / 3600

            # Move to next day
            current_time = (current_time + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)

        return business_hours

    @staticmethod
    def get_ticket_age_category(created_at: datetime) -> str:
        """
        Get ticket age category
        """
        if not created_at:
            return 'Unknown'

        age = timezone.now() - created_at
        hours = age.total_seconds() / 3600

        if hours < 4:
            return 'New'
        elif hours < 24:
            return 'Recent'
        elif hours < 72:
            return 'Aging'
        else:
            return 'Old'

    @staticmethod
    def get_workload_indicator(assigned_user: User) -> Dict:
        """
        Get workload indicator for a user
        """
        if not assigned_user:
            return {'level': 'none', 'count': 0, 'color': '#6c757d'}

        active_tickets = Support.objects.filter(
            assigned_to_user=assigned_user,
            status__in=[Support.Status.NEW, Support.Status.OPEN, Support.Status.IN_PROGRESS],
            is_deleted=False
        ).count()

        if active_tickets == 0:
            return {'level': 'none', 'count': 0, 'color': '#28a745'}
        elif active_tickets <= 3:
            return {'level': 'low', 'count': active_tickets, 'color': '#28a745'}
        elif active_tickets <= 7:
            return {'level': 'medium', 'count': active_tickets, 'color': '#ffc107'}
        elif active_tickets <= 12:
            return {'level': 'high', 'count': active_tickets, 'color': '#fd7e14'}
        else:
            return {'level': 'critical', 'count': active_tickets, 'color': '#dc3545'}


class CacheManager:
    """
    Cache management utilities
    """

    @staticmethod
    def get_cache_key(prefix: str, *args) -> str:
        """
        Generate cache key
        """
        key_parts = [prefix] + [str(arg) for arg in args]
        return ':'.join(key_parts)

    @staticmethod
    def cache_ticket_stats(user: User, stats: Dict, timeout: int = 300):
        """
        Cache ticket statistics
        """
        cache_key = CacheManager.get_cache_key('ticket_stats', user.id)
        cache.set(cache_key, stats, timeout)

    @staticmethod
    def get_cached_ticket_stats(user: User) -> Optional[Dict]:
        """
        Get cached ticket statistics
        """
        cache_key = CacheManager.get_cache_key('ticket_stats', user.id)
        return cache.get(cache_key)

    @staticmethod
    def invalidate_ticket_cache(user: User):
        """
        Invalidate ticket cache for user
        """
        cache_key = CacheManager.get_cache_key('ticket_stats', user.id)
        cache.delete(cache_key)

    @staticmethod
    def cache_user_permissions(user: User, permissions: Dict, timeout: int = 600):
        """
        Cache user permissions
        """
        cache_key = CacheManager.get_cache_key('user_permissions', user.id)
        cache.set(cache_key, permissions, timeout)

    @staticmethod
    def get_cached_user_permissions(user: User) -> Optional[Dict]:
        """
        Get cached user permissions
        """
        cache_key = CacheManager.get_cache_key('user_permissions', user.id)
        return cache.get(cache_key)


class ReportGenerator:
    """
    Report generation utilities
    """

    @staticmethod
    def generate_ticket_summary(tickets) -> Dict:
        """
        Generate ticket summary report
        """
        if not tickets:
            return {}

        total_tickets = tickets.count()

        # Status distribution
        status_counts = {}
        for status in Support.Status.choices:
            count = tickets.filter(status=status[0]).count()
            status_counts[status[1]] = count

        # Priority distribution
        priority_counts = {}
        for priority in Support.Priority.choices:
            count = tickets.filter(priority=priority[0]).count()
            priority_counts[priority[1]] = count

        # Issue type distribution
        issue_type_counts = {}
        for issue_type in Support.IssueType.choices:
            count = tickets.filter(issue_type=issue_type[0]).count()
            issue_type_counts[issue_type[1]] = count

        # Calculate average resolution time
        resolved_tickets = tickets.filter(
            status__in=[Support.Status.RESOLVED, Support.Status.CLOSED],
            resolution_time__isnull=False
        )

        avg_resolution_time = None
        if resolved_tickets.exists():
            avg_resolution = resolved_tickets.aggregate(
                avg_time=Avg('resolution_time')
            )['avg_time']
            if avg_resolution:
                avg_resolution_time = TicketHelper.format_duration(avg_resolution)

        # SLA compliance
        sla_compliant = tickets.filter(sla_status=Support.SLAStatus.WITHIN_SLA).count()
        sla_breached = tickets.filter(sla_status=Support.SLAStatus.BREACHED).count()

        return {
            'total_tickets': total_tickets,
            'status_distribution': status_counts,
            'priority_distribution': priority_counts,
            'issue_type_distribution': issue_type_counts,
            'average_resolution_time': avg_resolution_time,
            'sla_compliance': {
                'compliant': sla_compliant,
                'breached': sla_breached,
                'compliance_rate': (sla_compliant / total_tickets * 100) if total_tickets > 0 else 0
            }
        }

    @staticmethod
    def generate_agent_performance_report(user: User, days: int = 30) -> Dict:
        """
        Generate agent performance report
        """
        start_date = timezone.now() - timedelta(days=days)

        # Get tickets assigned to the user
        tickets = Support.objects.filter(
            assigned_to_user=user,
            created_at__gte=start_date,
            is_deleted=False
        )

        total_tickets = tickets.count()
        resolved_tickets = tickets.filter(status__in=[Support.Status.RESOLVED, Support.Status.CLOSED])

        # Calculate metrics
        resolution_rate = (resolved_tickets.count() / total_tickets * 100) if total_tickets > 0 else 0

        avg_resolution_time = None
        if resolved_tickets.exists():
            avg_resolution = resolved_tickets.aggregate(
                avg_time=Avg('resolution_time')
            )['avg_time']
            if avg_resolution:
                avg_resolution_time = TicketHelper.format_duration(avg_resolution)

        # SLA performance
        sla_compliant = resolved_tickets.filter(sla_status=Support.SLAStatus.WITHIN_SLA).count()
        sla_breached = resolved_tickets.filter(sla_status=Support.SLAStatus.BREACHED).count()

        return {
            'agent': user.get_full_name(),
            'period_days': days,
            'total_tickets': total_tickets,
            'resolved_tickets': resolved_tickets.count(),
            'resolution_rate': resolution_rate,
            'average_resolution_time': avg_resolution_time,
            'sla_performance': {
                'compliant': sla_compliant,
                'breached': sla_breached,
                'compliance_rate': (sla_compliant / resolved_tickets.count() * 100) if resolved_tickets.count() > 0 else 0
            }
        }


class MessageBuilder:
    """
    Message building utilities for notifications and user guidance
    """

    @staticmethod
    def get_status_message(status: str) -> str:
        """
        Get user-friendly status message
        """
        messages = {
            Support.Status.NEW: "Your ticket has been created and is waiting to be assigned.",
            Support.Status.OPEN: "Your ticket is open and being reviewed.",
            Support.Status.IN_PROGRESS: "Your ticket is being actively worked on.",
            Support.Status.PENDING_USER: "Your ticket is waiting for your response.",
            Support.Status.PENDING_THIRD_PARTY: "Your ticket is waiting for third-party response.",
            Support.Status.ON_HOLD: "Your ticket has been put on hold temporarily.",
            Support.Status.RESOLVED: "Your ticket has been resolved. Please verify the solution.",
            Support.Status.CLOSED: "Your ticket has been closed."
        }
        return messages.get(status, "Status unknown")

    @staticmethod
    def get_priority_guidance(priority: str) -> str:
        """
        Get priority guidance message
        """
        guidance = {
            Support.Priority.LOW: "This is a low priority ticket. Expected resolution within 48 hours.",
            Support.Priority.MEDIUM: "This is a medium priority ticket. Expected resolution within 24 hours.",
            Support.Priority.HIGH: "This is a high priority ticket. Expected resolution within 8 hours.",
            Support.Priority.CRITICAL: "This is a critical priority ticket. Expected resolution within 4 hours."
        }
        return guidance.get(priority, "Priority guidance not available")

    @staticmethod
    def get_next_action_message(ticket: Support, user: User) -> str:
        """
        Get next action message for user
        """
        if ticket.status == Support.Status.PENDING_USER:
            return "Please provide the requested information or response."
        elif ticket.status == Support.Status.RESOLVED:
            return "Please verify that the issue has been resolved to your satisfaction."
        elif ticket.status in [Support.Status.NEW, Support.Status.OPEN]:
            return "Your ticket is being reviewed. You will be notified of any updates."
        elif ticket.status == Support.Status.IN_PROGRESS:
            return "Your ticket is being actively worked on. Please be patient."
        elif ticket.status == Support.Status.CLOSED:
            return "Your ticket has been closed. You can reopen it if needed."
        else:
            return "Please wait for further updates on your ticket."

    @staticmethod
    def build_escalation_message(ticket: Support, escalation_level: int) -> str:
        """
        Build escalation message
        """
        return f"""
        Ticket {ticket.ticket_id} has been escalated to Level {escalation_level}.

        Subject: {ticket.subject}
        Priority: {ticket.priority}
        Current Status: {ticket.status}

        This ticket requires immediate attention due to:
        - SLA breach risk or actual breach
        - High priority and extended resolution time
        - Customer escalation request

        Please take appropriate action to resolve this ticket promptly.
        """

    @staticmethod
    def build_sla_warning_message(ticket: Support, time_remaining: timedelta) -> str:
        """
        Build SLA warning message
        """
        return f"""
        SLA WARNING: Ticket {ticket.ticket_id} is approaching its SLA deadline.

        Subject: {ticket.subject}
        Priority: {ticket.priority}
        Time Remaining: {TicketHelper.format_duration(time_remaining)}

        Please take immediate action to prevent SLA breach.
        """
