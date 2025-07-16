from django.core.management.base import BaseCommand
from django.contrib.auth.models import User, Group, Permission
from django.contrib.contenttypes.models import ContentType
from trueAlign.models import Support


class Command(BaseCommand):
    help = 'Setup support system groups and permissions'

    def handle(self, *args, **options):
        # Get content type for Support model
        support_content_type = ContentType.objects.get_for_model(Support)

        # Define permissions for Support model
        permissions_data = [
            ('can_view_all_tickets', 'Can view all tickets'),
            ('can_edit_all_tickets', 'Can edit all tickets'),
            ('can_assign_tickets', 'Can assign tickets'),
            ('can_escalate_tickets', 'Can escalate tickets'),
            ('can_delete_tickets', 'Can delete tickets'),
            ('can_view_internal_comments', 'Can view internal comments'),
            ('can_manage_sla', 'Can manage SLA settings'),
            ('can_generate_reports', 'Can generate reports'),
            ('can_view_analytics', 'Can view analytics'),
            ('can_manage_ticket_categories', 'Can manage ticket categories'),
        ]

        # Create custom permissions
        for codename, name in permissions_data:
            permission, created = Permission.objects.get_or_create(
                codename=codename,
                name=name,
                content_type=support_content_type
            )
            if created:
                self.stdout.write(f"Created permission: {name}")

        # Define groups and their permissions
        groups_data = {
            'Support_Admin': [
                'can_view_all_tickets',
                'can_edit_all_tickets',
                'can_assign_tickets',
                'can_escalate_tickets',
                'can_delete_tickets',
                'can_view_internal_comments',
                'can_manage_sla',
                'can_generate_reports',
                'can_view_analytics',
                'can_manage_ticket_categories',
            ],
            'Support_Manager': [
                'can_view_all_tickets',
                'can_edit_all_tickets',
                'can_assign_tickets',
                'can_escalate_tickets',
                'can_view_internal_comments',
                'can_generate_reports',
                'can_view_analytics',
            ],
            'HR_Support': [
                'can_assign_tickets',
                'can_escalate_tickets',
                'can_view_internal_comments',
                'can_generate_reports',
            ],
            'Support_Agent': [
                'can_assign_tickets',
                'can_escalate_tickets',
                'can_view_internal_comments',
            ],
            'Employee': [
                # Basic permissions for regular employees
            ],
        }

        # Create groups and assign permissions
        for group_name, permission_codenames in groups_data.items():
            group, created = Group.objects.get_or_create(name=group_name)
            if created:
                self.stdout.write(f"Created group: {group_name}")

            # Clear existing permissions and add new ones
            group.permissions.clear()
            for codename in permission_codenames:
                try:
                    permission = Permission.objects.get(
                        codename=codename,
                        content_type=support_content_type
                    )
                    group.permissions.add(permission)
                    self.stdout.write(f"Added {codename} to {group_name}")
                except Permission.DoesNotExist:
                    self.stdout.write(f"Permission {codename} not found")

        # Create department-specific groups
        departments = ['IT', 'HR', 'Finance', 'Operations', 'Sales', 'Marketing']
        for dept in departments:
            dept_group, created = Group.objects.get_or_create(name=f"{dept}_Department")
            if created:
                self.stdout.write(f"Created department group: {dept}_Department")

        self.stdout.write(
            self.style.SUCCESS('Successfully set up support permissions and groups')
        )
