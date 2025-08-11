#!/usr/bin/env python
"""
Leave Management Data Setup Script
=====================================

This script sets up initial data for the Leave Management system including:
- Leave Types (Annual, Sick, Personal, etc.)
- Leave Policies for different employee groups
- Leave Allocations within policies
- User Leave Balances for all active users
- Sample leave requests for testing

Usage:
    python setup_leave_data.py
"""

import os
import sys
import django
from datetime import datetime, timedelta
from decimal import Decimal

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User, Group
from django.utils import timezone
from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance,
    LeaveRequest, CompOffRequest
)

def create_leave_types():
    """Create basic leave types"""
    print("Creating Leave Types...")

    leave_types_data = [
        {
            'name': 'Annual Leave',
            'description': 'Yearly vacation leave',
            'is_paid': True,
            'requires_approval': True,
            'requires_documentation': False,
            'count_weekends': False,
            'can_be_half_day': True,
            'max_days_allowed': 21,
            'carry_forward_allowed': True,
        },
        {
            'name': 'Sick Leave',
            'description': 'Medical leave for illness',
            'is_paid': True,
            'requires_approval': False,
            'requires_documentation': True,
            'count_weekends': False,
            'can_be_half_day': True,
            'max_days_allowed': 12,
            'carry_forward_allowed': False,
        },
        {
            'name': 'Personal Leave',
            'description': 'Personal time off',
            'is_paid': True,
            'requires_approval': True,
            'requires_documentation': False,
            'count_weekends': False,
            'can_be_half_day': True,
            'max_days_allowed': 5,
            'carry_forward_allowed': False,
        },
        {
            'name': 'Maternity Leave',
            'description': 'Maternity leave for new mothers',
            'is_paid': True,
            'requires_approval': True,
            'requires_documentation': True,
            'count_weekends': True,
            'can_be_half_day': False,
            'max_days_allowed': 180,
            'carry_forward_allowed': False,
        },
        {
            'name': 'Paternity Leave',
            'description': 'Paternity leave for new fathers',
            'is_paid': True,
            'requires_approval': True,
            'requires_documentation': True,
            'count_weekends': True,
            'can_be_half_day': False,
            'max_days_allowed': 15,
            'carry_forward_allowed': False,
        },
        {
            'name': 'Emergency Leave',
            'description': 'Emergency situations requiring immediate leave',
            'is_paid': True,
            'requires_approval': False,
            'requires_documentation': True,
            'count_weekends': False,
            'can_be_half_day': True,
            'max_days_allowed': 3,
            'carry_forward_allowed': False,
        },
        {
            'name': 'Unpaid Leave',
            'description': 'Leave without pay',
            'is_paid': False,
            'requires_approval': True,
            'requires_documentation': True,
            'count_weekends': True,
            'can_be_half_day': False,
            'max_days_allowed': 30,
            'carry_forward_allowed': False,
        }
    ]

    created_types = []
    for data in leave_types_data:
        leave_type, created = LeaveType.objects.get_or_create(
            name=data['name'],
            defaults=data
        )
        if created:
            print(f"  ✓ Created leave type: {leave_type.name}")
        else:
            print(f"  → Leave type already exists: {leave_type.name}")
        created_types.append(leave_type)

    return created_types

def create_employee_groups():
    """Create employee groups if they don't exist"""
    print("Creating Employee Groups...")

    groups_data = [
        'Employee',
        'Manager',
        'HR',
        'Senior Employee',
        'Trainee'
    ]

    created_groups = []
    for group_name in groups_data:
        group, created = Group.objects.get_or_create(name=group_name)
        if created:
            print(f"  ✓ Created group: {group.name}")
        else:
            print(f"  → Group already exists: {group.name}")
        created_groups.append(group)

    return created_groups

def create_leave_policies(groups, leave_types):
    """Create leave policies for different groups"""
    print("Creating Leave Policies...")

    # Create policies for different groups
    policies_data = [
        {
            'name': 'Standard Employee Policy',
            'group': 'Employee',
            'effective_from': timezone.now().date(),
            'allocations': [
                ('Annual Leave', 21.0, 7.0, 30, 7),
                ('Sick Leave', 12.0, 0.0, 5, 0),
                ('Personal Leave', 5.0, 0.0, 3, 1),
                ('Emergency Leave', 3.0, 0.0, 3, 0),
            ]
        },
        {
            'name': 'Senior Employee Policy',
            'group': 'Senior Employee',
            'effective_from': timezone.now().date(),
            'allocations': [
                ('Annual Leave', 25.0, 10.0, 30, 5),
                ('Sick Leave', 15.0, 0.0, 7, 0),
                ('Personal Leave', 7.0, 0.0, 5, 1),
                ('Emergency Leave', 5.0, 0.0, 5, 0),
            ]
        },
        {
            'name': 'Manager Policy',
            'group': 'Manager',
            'effective_from': timezone.now().date(),
            'allocations': [
                ('Annual Leave', 25.0, 10.0, 30, 3),
                ('Sick Leave', 15.0, 0.0, 10, 0),
                ('Personal Leave', 10.0, 2.0, 7, 1),
                ('Emergency Leave', 5.0, 0.0, 5, 0),
            ]
        },
        {
            'name': 'Trainee Policy',
            'group': 'Trainee',
            'effective_from': timezone.now().date(),
            'allocations': [
                ('Annual Leave', 15.0, 3.0, 15, 10),
                ('Sick Leave', 10.0, 0.0, 3, 0),
                ('Personal Leave', 3.0, 0.0, 2, 2),
                ('Emergency Leave', 2.0, 0.0, 2, 0),
            ]
        }
    ]

    created_policies = []
    group_dict = {g.name: g for g in groups}
    leave_type_dict = {lt.name: lt for lt in leave_types}

    for policy_data in policies_data:
        group = group_dict.get(policy_data['group'])
        if not group:
            print(f"  ⚠ Group {policy_data['group']} not found, skipping policy")
            continue

        policy, created = LeavePolicy.objects.get_or_create(
            name=policy_data['name'],
            defaults={
                'group': group,
                'effective_from': policy_data['effective_from'],
                'is_active': True
            }
        )

        if created:
            print(f"  ✓ Created policy: {policy.name}")

            # Create allocations for this policy
            for allocation_data in policy_data['allocations']:
                leave_type_name, annual_days, carryforward, max_consecutive, advance_notice = allocation_data
                leave_type = leave_type_dict.get(leave_type_name)

                if leave_type:
                    allocation, alloc_created = LeaveAllocation.objects.get_or_create(
                        policy=policy,
                        leave_type=leave_type,
                        defaults={
                            'annual_days': Decimal(str(annual_days)),
                            'carryforward_limit': Decimal(str(carryforward)),
                            'max_consecutive_days': max_consecutive,
                            'advance_notice_days': advance_notice,
                        }
                    )
                    if alloc_created:
                        print(f"    ✓ Added allocation: {leave_type.name} - {annual_days} days")
        else:
            print(f"  → Policy already exists: {policy.name}")

        created_policies.append(policy)

    return created_policies

def assign_users_to_groups():
    """Assign users to appropriate groups"""
    print("Assigning Users to Groups...")

    users = User.objects.filter(is_active=True)
    groups = Group.objects.all()

    # Get or create basic groups
    employee_group, _ = Group.objects.get_or_create(name='Employee')
    manager_group, _ = Group.objects.get_or_create(name='Manager')
    hr_group, _ = Group.objects.get_or_create(name='HR')

    assignments = 0
    for user in users:
        if user.is_superuser:
            # Superusers get HR access
            user.groups.add(hr_group)
            assignments += 1
            print(f"  ✓ Assigned {user.username} to HR group")
        elif 'manager' in user.username.lower() or 'mgr' in user.username.lower():
            user.groups.add(manager_group)
            assignments += 1
            print(f"  ✓ Assigned {user.username} to Manager group")
        elif 'hr' in user.username.lower():
            user.groups.add(hr_group)
            assignments += 1
            print(f"  ✓ Assigned {user.username} to HR group")
        else:
            # Default to employee group
            user.groups.add(employee_group)
            assignments += 1
            print(f"  ✓ Assigned {user.username} to Employee group")

    print(f"  Total assignments: {assignments}")

def create_user_leave_balances(policies):
    """Create leave balances for all users based on their group policies"""
    print("Creating User Leave Balances...")

    users = User.objects.filter(is_active=True)
    current_year = timezone.now().year

    created_balances = 0
    for user in users:
        user_groups = user.groups.all()

        # Find applicable policy (take the first matching group policy)
        applicable_policy = None
        for group in user_groups:
            policy = LeavePolicy.objects.filter(group=group, is_active=True).first()
            if policy:
                applicable_policy = policy
                break

        if not applicable_policy:
            # Use default employee policy
            employee_group = Group.objects.filter(name='Employee').first()
            if employee_group:
                applicable_policy = LeavePolicy.objects.filter(group=employee_group, is_active=True).first()

        if applicable_policy:
            # Create balances for each allocation in the policy
            for allocation in applicable_policy.allocations.all():
                balance, created = UserLeaveBalance.objects.get_or_create(
                    user=user,
                    leave_type=allocation.leave_type,
                    year=current_year,
                    defaults={
                        'allocated': allocation.annual_days,
                        'used': Decimal('0.0'),
                        'additional': Decimal('0.0'),
                        'carried_forward': Decimal('0.0'),
                    }
                )

                if created:
                    created_balances += 1
                    print(f"  ✓ Created balance for {user.username}: {allocation.leave_type.name} - {allocation.annual_days} days")
        else:
            print(f"  ⚠ No applicable policy found for user: {user.username}")

    print(f"  Total balances created: {created_balances}")

def create_sample_leave_requests():
    """Create some sample leave requests for testing"""
    print("Creating Sample Leave Requests...")

    users = User.objects.filter(is_active=True)[:3]  # Get first 3 users
    leave_types = LeaveType.objects.all()

    if not users or not leave_types:
        print("  ⚠ No users or leave types available for sample requests")
        return

    sample_requests = [
        {
            'user_index': 0,
            'leave_type': 'Annual Leave',
            'start_offset': 10,  # days from now
            'duration': 3,
            'reason': 'Family vacation',
            'status': 'Pending'
        },
        {
            'user_index': 1,
            'leave_type': 'Personal Leave',
            'start_offset': -2,  # 2 days ago
            'duration': 1,
            'reason': 'Personal appointment',
            'status': 'Approved'
        },
        {
            'user_index': 2,
            'leave_type': 'Personal Leave',
            'start_offset': 20,
            'duration': 2,
            'reason': 'Personal matters',
            'status': 'Pending'
        }
    ]

    leave_type_dict = {lt.name: lt for lt in leave_types}
    created_requests = 0

    for req_data in sample_requests:
        if req_data['user_index'] < len(users):
            user = users[req_data['user_index']]
            leave_type = leave_type_dict.get(req_data['leave_type'])

            if leave_type:
                start_date = timezone.now().date() + timedelta(days=req_data['start_offset'])
                end_date = start_date + timedelta(days=req_data['duration'] - 1)

                request, created = LeaveRequest.objects.get_or_create(
                    user=user,
                    leave_type=leave_type,
                    start_date=start_date,
                    end_date=end_date,
                    defaults={
                        'reason': req_data['reason'],
                        'status': req_data['status'],
                        'leave_days': Decimal(str(req_data['duration'])),
                    }
                )

                if created:
                    created_requests += 1
                    print(f"  ✓ Created leave request for {user.username}: {leave_type.name} ({start_date} to {end_date})")

    print(f"  Total sample requests created: {created_requests}")

def main():
    """Main setup function"""
    print("="*60)
    print("LEAVE MANAGEMENT DATA SETUP")
    print("="*60)

    try:
        # Step 1: Create leave types
        leave_types = create_leave_types()
        print(f"✓ Leave Types: {len(leave_types)} total")

        # Step 2: Create employee groups
        groups = create_employee_groups()
        print(f"✓ Employee Groups: {len(groups)} total")

        # Step 3: Assign users to groups
        assign_users_to_groups()

        # Step 4: Create leave policies
        policies = create_leave_policies(groups, leave_types)
        print(f"✓ Leave Policies: {len(policies)} total")

        # Step 5: Create user leave balances
        create_user_leave_balances(policies)

        # Step 6: Create sample leave requests
        create_sample_leave_requests()

        print("\n" + "="*60)
        print("✅ SETUP COMPLETED SUCCESSFULLY!")
        print("="*60)

        # Print summary
        print("\nSUMMARY:")
        print(f"• Leave Types: {LeaveType.objects.count()}")
        print(f"• Leave Policies: {LeavePolicy.objects.count()}")
        print(f"• Leave Allocations: {LeaveAllocation.objects.count()}")
        print(f"• User Leave Balances: {UserLeaveBalance.objects.count()}")
        print(f"• Leave Requests: {LeaveRequest.objects.count()}")
        print(f"• Groups: {Group.objects.count()}")
        print(f"• Active Users: {User.objects.filter(is_active=True).count()}")

        print("\n🚀 You can now run the leave management tests again!")

    except Exception as e:
        print(f"\n❌ Setup failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
