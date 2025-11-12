"""
Django Management Command for Leave Policy Management
Provides comprehensive tools for managing leave policies, allocations, and monitoring
"""
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth.models import User, Group
from django.utils import timezone
from django.db import transaction
from django.db.models import Count, Sum
from datetime import datetime, timedelta
import json

from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance,
    LeaveRequest
)
from trueAlign.leave_management.services.leave_service import LeaveService


class Command(BaseCommand):
    help = 'Manage leave policies, allocations, and monitoring'

    def add_arguments(self, parser):
        subparsers = parser.add_subparsers(dest='action', help='Available actions')

        # Status command
        status_parser = subparsers.add_parser('status', help='Show policy allocation status')
        status_parser.add_argument('--year', type=int, default=timezone.now().year,
                                 help='Year to check (default: current year)')

        # Allocate command
        allocate_parser = subparsers.add_parser('allocate', help='Allocate leaves to users')
        allocate_parser.add_argument('--group', type=str, help='Group name to allocate to')
        allocate_parser.add_argument('--user', type=str, help='Username to allocate to')
        allocate_parser.add_argument('--year', type=int, default=timezone.now().year,
                                   help='Year to allocate for (default: current year)')
        allocate_parser.add_argument('--force', action='store_true',
                                   help='Force reallocation even if balances exist')

        # Monitor command
        monitor_parser = subparsers.add_parser('monitor', help='Monitor policy expiration and usage')
        monitor_parser.add_argument('--days', type=int, default=30,
                                  help='Days ahead to check for expiring policies')

        # Setup command
        setup_parser = subparsers.add_parser('setup', help='Setup default policies and leave types')
        setup_parser.add_argument('--sample', action='store_true',
                                help='Create sample data for testing')

        # Analytics command
        analytics_parser = subparsers.add_parser('analytics', help='Show leave usage analytics')
        analytics_parser.add_argument('--year', type=int, default=timezone.now().year,
                                    help='Year to analyze (default: current year)')

    def handle(self, *args, **options):
        action = options['action']

        if action == 'status':
            self.show_status(options)
        elif action == 'allocate':
            self.allocate_leaves(options)
        elif action == 'monitor':
            self.monitor_policies(options)
        elif action == 'setup':
            self.setup_policies(options)
        elif action == 'analytics':
            self.show_analytics(options)
        else:
            self.print_help('manage_leave_policies', '')

    def show_status(self, options):
        """Show policy allocation status"""
        year = options['year']
        
        self.stdout.write(self.style.SUCCESS(f'\n=== Leave Policy Status for {year} ===\n'))

        # Get all active policies
        policies = LeavePolicy.objects.filter(is_active=True).prefetch_related(
            'allocations__leave_type', 'group'
        )

        if not policies.exists():
            self.stdout.write(self.style.WARNING('No active policies found!'))
            return

        total_users = User.objects.filter(is_active=True).count()
        users_with_balances = UserLeaveBalance.objects.filter(
            year=year
        ).values('user').distinct().count()

        self.stdout.write(f'Total Active Users: {total_users}')
        self.stdout.write(f'Users with Leave Balances: {users_with_balances}')
        self.stdout.write(f'Coverage: {(users_with_balances/total_users*100):.1f}%\n')

        for policy in policies:
            users_in_group = User.objects.filter(
                groups=policy.group, 
                is_active=True
            ).count()
            
            allocated_users = UserLeaveBalance.objects.filter(
                user__groups=policy.group,
                year=year
            ).values('user').distinct().count()

            coverage = (allocated_users / users_in_group * 100) if users_in_group > 0 else 0

            self.stdout.write(f'Policy: {policy.name}')
            self.stdout.write(f'  Group: {policy.group.name}')
            self.stdout.write(f'  Users in Group: {users_in_group}')
            self.stdout.write(f'  Allocated Users: {allocated_users}')
            self.stdout.write(f'  Coverage: {coverage:.1f}%')
            
            # Show allocations
            for allocation in policy.allocations.all():
                self.stdout.write(f'    {allocation.leave_type.name}: {allocation.annual_days} days')
            self.stdout.write('')

    def allocate_leaves(self, options):
        """Allocate leaves to users"""
        year = options['year']
        group_name = options.get('group')
        username = options.get('user')
        force = options.get('force', False)

        if not group_name and not username:
            raise CommandError('Either --group or --user must be specified')

        try:
            with transaction.atomic():
                if username:
                    # Allocate to specific user
                    try:
                        user = User.objects.get(username=username, is_active=True)
                        result = LeaveService.allocate_leaves_to_user(user, {}, year)
                        self.stdout.write(
                            self.style.SUCCESS(f'Successfully allocated leaves to {username}')
                        )
                        for allocation in result['allocations']:
                            self.stdout.write(f"  {allocation['leave_type']}: {allocation['allocated']} days")
                    except User.DoesNotExist:
                        raise CommandError(f'User "{username}" not found')

                elif group_name:
                    # Allocate to group
                    try:
                        group = Group.objects.get(name=group_name)
                        users = User.objects.filter(groups=group, is_active=True)
                        
                        if not users.exists():
                            raise CommandError(f'No active users found in group "{group_name}"')

                        self.stdout.write(f'Allocating leaves to {users.count()} users in group "{group_name}"...')
                        
                        result = LeaveService.bulk_allocate_leaves(list(users), year)
                        
                        successful = sum(1 for r in result['results'] if r['success'])
                        failed = len(result['results']) - successful
                        
                        self.stdout.write(
                            self.style.SUCCESS(f'Allocation completed: {successful} successful, {failed} failed')
                        )
                        
                        if failed > 0:
                            self.stdout.write(self.style.WARNING('Failed allocations:'))
                            for r in result['results']:
                                if not r['success']:
                                    self.stdout.write(f"  {r['user']}: {r['message']}")

                    except Group.DoesNotExist:
                        raise CommandError(f'Group "{group_name}" not found')

        except Exception as e:
            raise CommandError(f'Allocation failed: {str(e)}')

    def monitor_policies(self, options):
        """Monitor policy expiration and usage"""
        days_ahead = options['days']
        
        self.stdout.write(self.style.SUCCESS(f'\n=== Policy Monitoring (Next {days_ahead} days) ===\n'))

        # Check for expiring policies (if your model has end_date field)
        # This is a placeholder - you may need to add end_date to LeavePolicy model
        self.stdout.write('Policy Expiration Monitoring:')
        self.stdout.write('  (Note: Add end_date field to LeavePolicy model for expiration tracking)')

        # Check pending requests
        pending_requests = LeaveRequest.objects.filter(status='Pending').count()
        if pending_requests > 0:
            self.stdout.write(self.style.WARNING(f'  {pending_requests} pending leave requests need attention'))

        # Check users without balances
        current_year = timezone.now().year
        total_users = User.objects.filter(is_active=True).count()
        users_with_balances = UserLeaveBalance.objects.filter(
            year=current_year
        ).values('user').distinct().count()
        
        users_without_balances = total_users - users_with_balances
        if users_without_balances > 0:
            self.stdout.write(
                self.style.WARNING(f'  {users_without_balances} users don\'t have leave balances for {current_year}')
            )

        # Check for overused balances
        overused_balances = UserLeaveBalance.objects.filter(
            year=current_year
        ).extra(where=["used > (allocated + carried_forward + additional)"])
        
        if overused_balances.exists():
            self.stdout.write(self.style.ERROR(f'  {overused_balances.count()} users have overused their leave balance'))

    def setup_policies(self, options):
        """Setup default policies and leave types"""
        sample = options.get('sample', False)
        
        self.stdout.write(self.style.SUCCESS('\n=== Setting up Leave Management System ===\n'))

        try:
            with transaction.atomic():
                # Create default leave types
                leave_types = [
                    {
                        'name': 'Annual Leave',
                        'is_paid': True,
                        'requires_approval': True,
                        'requires_documentation': False,
                        'count_weekends': False,
                        'can_be_half_day': True
                    },
                    {
                        'name': 'Sick Leave',
                        'is_paid': True,
                        'requires_approval': True,
                        'requires_documentation': True,
                        'count_weekends': False,
                        'can_be_half_day': True
                    },
                    {
                        'name': 'Casual Leave',
                        'is_paid': True,
                        'requires_approval': True,
                        'requires_documentation': False,
                        'count_weekends': False,
                        'can_be_half_day': True
                    },
                    {
                        'name': 'Loss of Pay',
                        'is_paid': False,
                        'requires_approval': True,
                        'requires_documentation': False,
                        'count_weekends': True,
                        'can_be_half_day': True
                    }
                ]

                created_types = []
                for lt_data in leave_types:
                    leave_type, created = LeaveType.objects.get_or_create(
                        name=lt_data['name'],
                        defaults=lt_data
                    )
                    if created:
                        created_types.append(leave_type.name)
                        self.stdout.write(f'Created leave type: {leave_type.name}')

                # Create default groups
                groups = ['Employee', 'Manager', 'HR', 'Admin']
                created_groups = []
                for group_name in groups:
                    group, created = Group.objects.get_or_create(name=group_name)
                    if created:
                        created_groups.append(group_name)
                        self.stdout.write(f'Created group: {group_name}')

                # Create default policies
                employee_group = Group.objects.get(name='Employee')
                manager_group = Group.objects.get(name='Manager')

                # Employee policy
                emp_policy, created = LeavePolicy.objects.get_or_create(
                    name='Standard Employee Policy',
                    group=employee_group,
                    defaults={
                        'is_active': True
                    }
                )
                if created:
                    self.stdout.write('Created Employee policy')

                # Manager policy
                mgr_policy, created = LeavePolicy.objects.get_or_create(
                    name='Manager Policy',
                    group=manager_group,
                    defaults={
                        'is_active': True
                    }
                )
                if created:
                    self.stdout.write('Created Manager policy')

                # Create allocations
                allocations = [
                    # Employee allocations
                    {'policy': emp_policy, 'leave_type': 'Annual Leave', 'days': 21, 'consecutive': 10, 'notice': 7, 'carry': 5},
                    {'policy': emp_policy, 'leave_type': 'Sick Leave', 'days': 12, 'consecutive': 0, 'notice': 0, 'carry': 0},
                    {'policy': emp_policy, 'leave_type': 'Casual Leave', 'days': 6, 'consecutive': 3, 'notice': 1, 'carry': 0},
                    
                    # Manager allocations (more generous)
                    {'policy': mgr_policy, 'leave_type': 'Annual Leave', 'days': 25, 'consecutive': 15, 'notice': 5, 'carry': 7},
                    {'policy': mgr_policy, 'leave_type': 'Sick Leave', 'days': 15, 'consecutive': 0, 'notice': 0, 'carry': 0},
                    {'policy': mgr_policy, 'leave_type': 'Casual Leave', 'days': 8, 'consecutive': 5, 'notice': 1, 'carry': 2},
                ]

                for alloc_data in allocations:
                    leave_type = LeaveType.objects.get(name=alloc_data['leave_type'])
                    allocation, created = LeaveAllocation.objects.get_or_create(
                        policy=alloc_data['policy'],
                        leave_type=leave_type,
                        defaults={
                            'annual_days': alloc_data['days'],
                            'max_consecutive_days': alloc_data['consecutive'],
                            'advance_notice_days': alloc_data['notice'],
                            'carryforward_limit': alloc_data['carry']
                        }
                    )
                    if created:
                        self.stdout.write(f'Created allocation: {alloc_data["policy"].name} - {leave_type.name}')

                self.stdout.write(self.style.SUCCESS('\nSetup completed successfully!'))

        except Exception as e:
            raise CommandError(f'Setup failed: {str(e)}')

    def show_analytics(self, options):
        """Show leave usage analytics"""
        year = options['year']
        
        self.stdout.write(self.style.SUCCESS(f'\n=== Leave Analytics for {year} ===\n'))

        # Leave requests by status
        statuses = ['Pending', 'Approved', 'Rejected', 'Cancelled']
        self.stdout.write('Leave Requests by Status:')
        for status in statuses:
            count = LeaveRequest.objects.filter(
                start_date__year=year,
                status=status
            ).count()
            self.stdout.write(f'  {status}: {count}')

        # Leave usage by type
        self.stdout.write('\nLeave Usage by Type:')
        leave_types = LeaveType.objects.filter(is_active=True)
        for leave_type in leave_types:
            usage = LeaveRequest.objects.filter(
                start_date__year=year,
                status='Approved',
                leave_type=leave_type
            ).aggregate(
                total_requests=Count('id'),
                total_days=Sum('leave_days')
            )
            
            requests = usage['total_requests'] or 0
            days = float(usage['total_days'] or 0)
            self.stdout.write(f'  {leave_type.name}: {requests} requests, {days:.1f} days')

        # Top requesters
        self.stdout.write('\nTop Leave Requesters:')
        top_users = LeaveRequest.objects.filter(
            start_date__year=year,
            status='Approved'
        ).values(
            'user__username', 'user__first_name', 'user__last_name'
        ).annotate(
            total_requests=Count('id'),
            total_days=Sum('leave_days')
        ).order_by('-total_days')[:10]

        for user_data in top_users:
            name = f"{user_data['user__first_name']} {user_data['user__last_name']}".strip()
            if not name:
                name = user_data['user__username']
            self.stdout.write(f'  {name}: {user_data["total_requests"]} requests, {float(user_data["total_days"]):.1f} days')
