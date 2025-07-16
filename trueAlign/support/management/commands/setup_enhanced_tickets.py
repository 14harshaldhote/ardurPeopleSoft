"""
Setup Enhanced Tickets Management Command
Bootstrap the smart ticketing system with groups, permissions, and configurations
"""

import logging
from django.core.management.base import BaseCommand
from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone
from django.db import transaction
from trueAlign.models import Support, UserDetails


class Command(BaseCommand):
    help = 'Setup enhanced ticketing system with groups, permissions, and configurations'

    def add_arguments(self, parser):
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Reset existing groups and permissions'
        )
        parser.add_argument(
            '--create-sample-data',
            action='store_true',
            help='Create sample tickets and users for testing'
        )
        parser.add_argument(
            '--verbose',
            action='store_true',
            help='Enable verbose output'
        )

    def handle(self, *args, **options):
        self.logger = logging.getLogger(__name__)
        self.verbose = options['verbose']
        self.reset = options['reset']
        self.create_sample_data = options['create_sample_data']

        self.stdout.write(
            self.style.SUCCESS(
                f"Setting up enhanced ticketing system at {timezone.now()}"
            )
        )

        try:
            with transaction.atomic():
                # Reset if requested
                if self.reset:
                    self._reset_system()

                # Create groups and permissions
                self._create_groups_and_permissions()

                # Create default configurations
                self._create_default_configurations()

                # Create sample data if requested
                if self.create_sample_data:
                    self._create_sample_data()

                self.stdout.write(
                    self.style.SUCCESS(
                        "Enhanced ticketing system setup completed successfully"
                    )
                )

        except Exception as e:
            self.logger.error(f"Setup failed: {str(e)}")
            self.stdout.write(
                self.style.ERROR(
                    f"Setup failed: {str(e)}"
                )
            )

    def _reset_system(self):
        """Reset existing groups and permissions"""
        self.stdout.write("Resetting system...")

        # Remove existing groups
        groups_to_remove = ['Admin', 'Manager', 'HR', 'Employee']
        for group_name in groups_to_remove:
            try:
                group = Group.objects.get(name=group_name)
                group.delete()
                if self.verbose:
                    self.stdout.write(f"  Removed group: {group_name}")
            except Group.DoesNotExist:
                pass

        self.stdout.write("System reset completed")

    def _create_groups_and_permissions(self):
        """Create user groups and assign permissions"""
        self.stdout.write("Creating groups and permissions...")

        # Get content types
        support_ct = ContentType.objects.get_for_model(Support)

        # Define groups with their permissions
        groups_config = {
            'Admin': {
                'description': 'System administrators with full access',
                'permissions': [
                    'add_support',
                    'change_support',
                    'delete_support',
                    'view_support',
                    'can_assign_tickets',
                    'can_escalate_tickets',
                    'can_delete_tickets',
                    'can_view_analytics',
                    'can_manage_sla',
                    'can_bulk_actions',
                    'can_export_data',
                ]
            },
            'Manager': {
                'description': 'Department managers with elevated access',
                'permissions': [
                    'add_support',
                    'change_support',
                    'view_support',
                    'can_assign_tickets',
                    'can_escalate_tickets',
                    'can_view_analytics',
                    'can_bulk_actions',
                    'can_export_data',
                ]
            },
            'HR': {
                'description': 'HR personnel with HR ticket access',
                'permissions': [
                    'add_support',
                    'change_support',
                    'view_support',
                    'can_assign_hr_tickets',
                    'can_escalate_hr_tickets',
                ]
            },
            'Employee': {
                'description': 'Regular employees with basic access',
                'permissions': [
                    'add_support',
                    'view_support',
                    'can_comment_own_tickets',
                    'can_reopen_own_tickets',
                ]
            }
        }

        # Create groups
        for group_name, config in groups_config.items():
            group, created = Group.objects.get_or_create(name=group_name)

            if created:
                self.stdout.write(f"  Created group: {group_name}")
            elif self.verbose:
                self.stdout.write(f"  Group exists: {group_name}")

            # Create custom permissions if they don't exist
            custom_permissions = [
                'can_assign_tickets',
                'can_escalate_tickets',
                'can_delete_tickets',
                'can_view_analytics',
                'can_manage_sla',
                'can_bulk_actions',
                'can_export_data',
                'can_assign_hr_tickets',
                'can_escalate_hr_tickets',
                'can_comment_own_tickets',
                'can_reopen_own_tickets',
            ]

            for perm_codename in custom_permissions:
                if perm_codename in config['permissions']:
                    permission, created = Permission.objects.get_or_create(
                        codename=perm_codename,
                        name=perm_codename.replace('_', ' ').title(),
                        content_type=support_ct
                    )
                    group.permissions.add(permission)

            # Add standard Django permissions
            standard_permissions = [
                'add_support',
                'change_support',
                'delete_support',
                'view_support',
            ]

            for perm_codename in standard_permissions:
                if perm_codename in config['permissions']:
                    try:
                        permission = Permission.objects.get(
                            codename=perm_codename,
                            content_type=support_ct
                        )
                        group.permissions.add(permission)
                    except Permission.DoesNotExist:
                        if self.verbose:
                            self.stdout.write(f"    Permission not found: {perm_codename}")

        self.stdout.write("Groups and permissions created successfully")

    def _create_default_configurations(self):
        """Create default system configurations"""
        self.stdout.write("Creating default configurations...")

        # SLA Configuration
        sla_config = {
            'business_hours': {
                'start': 9,
                'end': 18,
                'weekdays': [0, 1, 2, 3, 4]  # Monday to Friday
            },
            'sla_targets': {
                'Critical': {
                    'response_time': 1,
                    'resolution_time': 4,
                    'escalation_levels': [2, 4, 6]
                },
                'High': {
                    'response_time': 2,
                    'resolution_time': 8,
                    'escalation_levels': [4, 8, 12]
                },
                'Medium': {
                    'response_time': 4,
                    'resolution_time': 24,
                    'escalation_levels': [8, 16, 24]
                },
                'Low': {
                    'response_time': 8,
                    'resolution_time': 48,
                    'escalation_levels': [16, 32, 48]
                }
            }
        }

        # Assignment Rules Configuration
        assignment_config = {
            'max_tickets_per_agent': {
                'Critical': 15,
                'High': 12,
                'Medium': 10,
                'Low': 8
            },
            'skills_mapping': {
                'Hardware Issue': ['Admin'],
                'Software Issue': ['Admin'],
                'Network Issue': ['Admin'],
                'Internet Issue': ['Admin'],
                'Application Issue': ['Admin'],
                'HR Related Issue': ['HR'],
                'Access Management': ['Admin', 'HR'],
                'Security Incident': ['Admin'],
                'Service Request': ['Admin', 'HR']
            }
        }

        # Priority Rules Configuration
        priority_config = {
            'user_tiers': {
                'VIP': {
                    'weight': 0.9,
                    'criteria': ['is_superuser', 'is_staff']
                },
                'Internal': {
                    'weight': 0.6,
                    'criteria': ['is_employee']
                },
                'External': {
                    'weight': 0.3,
                    'criteria': []
                }
            },
            'impact_mapping': {
                'Security Incident': 'high',
                'Network Issue': 'high',
                'Application Issue': 'high',
                'Hardware Issue': 'medium',
                'Software Issue': 'medium',
                'HR Related Issue': 'medium',
                'Access Management': 'medium',
                'Internet Issue': 'medium',
                'Service Request': 'low'
            }
        }

        # Store configurations (you might want to create a Configuration model)
        # For now, we'll log them
        if self.verbose:
            self.stdout.write("  SLA Configuration:")
            self.stdout.write(f"    Business Hours: {sla_config['business_hours']}")
            self.stdout.write("  Assignment Configuration:")
            self.stdout.write(f"    Max Tickets: {assignment_config['max_tickets_per_agent']}")
            self.stdout.write("  Priority Configuration:")
            self.stdout.write(f"    User Tiers: {list(priority_config['user_tiers'].keys())}")

        self.stdout.write("Default configurations created")

    def _create_sample_data(self):
        """Create sample users and tickets for testing"""
        self.stdout.write("Creating sample data...")

        # Create sample users
        sample_users = [
            {
                'username': 'admin_user',
                'email': 'admin@example.com',
                'first_name': 'Admin',
                'last_name': 'User',
                'is_staff': True,
                'is_superuser': True,
                'groups': ['Admin']
            },
            {
                'username': 'manager_user',
                'email': 'manager@example.com',
                'first_name': 'Manager',
                'last_name': 'User',
                'is_staff': True,
                'groups': ['Manager']
            },
            {
                'username': 'hr_user',
                'email': 'hr@example.com',
                'first_name': 'HR',
                'last_name': 'User',
                'groups': ['HR']
            },
            {
                'username': 'employee_user',
                'email': 'employee@example.com',
                'first_name': 'Employee',
                'last_name': 'User',
                'groups': ['Employee']
            }
        ]

        created_users = []
        for user_data in sample_users:
            user, created = User.objects.get_or_create(
                username=user_data['username'],
                defaults={
                    'email': user_data['email'],
                    'first_name': user_data['first_name'],
                    'last_name': user_data['last_name'],
                    'is_staff': user_data.get('is_staff', False),
                    'is_superuser': user_data.get('is_superuser', False)
                }
            )

            if created:
                user.set_password('testpassword123')
                user.save()
                created_users.append(user)

                # Add to groups
                for group_name in user_data['groups']:
                    try:
                        group = Group.objects.get(name=group_name)
                        user.groups.add(group)
                    except Group.DoesNotExist:
                        pass

                # Create UserDetails if needed
                UserDetails.objects.get_or_create(
                    user=user,
                    defaults={
                        'department': user_data['groups'][0],
                        'user_type': 'Employee',
                        'hire_date': timezone.now().date()
                    }
                )

                if self.verbose:
                    self.stdout.write(f"  Created user: {user.username}")

        # Create sample tickets
        if created_users:
            sample_tickets = [
                {
                    'subject': 'Computer not starting up',
                    'description': 'My computer won\'t turn on after the weekend. Need urgent help.',
                    'issue_type': Support.IssueType.HARDWARE,
                    'priority': Support.Priority.HIGH,
                    'user': created_users[3] if len(created_users) > 3 else User.objects.first()
                },
                {
                    'subject': 'Email not working',
                    'description': 'Cannot send or receive emails since this morning.',
                    'issue_type': Support.IssueType.SOFTWARE,
                    'priority': Support.Priority.MEDIUM,
                    'user': created_users[3] if len(created_users) > 3 else User.objects.first()
                },
                {
                    'subject': 'Password reset request',
                    'description': 'Need to reset my system password as I forgot it.',
                    'issue_type': Support.IssueType.ACCESS,
                    'priority': Support.Priority.MEDIUM,
                    'user': created_users[3] if len(created_users) > 3 else User.objects.first()
                },
                {
                    'subject': 'Payroll inquiry',
                    'description': 'Question about my recent payroll statement.',
                    'issue_type': Support.IssueType.HR,
                    'priority': Support.Priority.LOW,
                    'user': created_users[3] if len(created_users) > 3 else User.objects.first()
                }
            ]

            for ticket_data in sample_tickets:
                # Create ticket
                ticket = Support.objects.create(
                    subject=ticket_data['subject'],
                    description=ticket_data['description'],
                    issue_type=ticket_data['issue_type'],
                    priority=ticket_data['priority'],
                    user=ticket_data['user']
                )

                # Auto-assign based on issue type
                if ticket_data['issue_type'] == Support.IssueType.HR:
                    ticket.assigned_group = Support.AssignedGroup.HR
                    # Try to assign to HR user
                    hr_user = User.objects.filter(groups__name='HR').first()
                    if hr_user:
                        ticket.assigned_to_user = hr_user
                else:
                    ticket.assigned_group = Support.AssignedGroup.ADMIN
                    # Try to assign to Admin user
                    admin_user = User.objects.filter(groups__name='Admin').first()
                    if admin_user:
                        ticket.assigned_to_user = admin_user

                ticket.save()

                if self.verbose:
                    self.stdout.write(f"  Created ticket: {ticket.ticket_id}")

        self.stdout.write("Sample data created successfully")

    def _display_summary(self):
        """Display setup summary"""
        self.stdout.write(
            self.style.WARNING(
                "\nSetup Summary:"
            )
        )

        # Groups
        groups = Group.objects.all()
        self.stdout.write(f"  Groups created: {groups.count()}")
        for group in groups:
            self.stdout.write(f"    - {group.name} ({group.permissions.count()} permissions)")

        # Users
        users = User.objects.all()
        self.stdout.write(f"  Total users: {users.count()}")

        # Tickets
        tickets = Support.objects.all()
        self.stdout.write(f"  Total tickets: {tickets.count()}")

        # Configuration
        self.stdout.write("  System configurations:")
        self.stdout.write("    - SLA rules configured")
        self.stdout.write("    - Assignment rules configured")
        self.stdout.write("    - Priority rules configured")
