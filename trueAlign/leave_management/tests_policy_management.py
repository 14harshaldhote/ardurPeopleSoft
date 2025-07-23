"""
Comprehensive Test Suite for Leave Policy and Allocation Management
Tests all aspects of policy creation, allocation, and leave balance management
"""
from django.test import TestCase
from django.contrib.auth.models import User, Group
from django.utils import timezone
from django.core.exceptions import ValidationError
from decimal import Decimal
import datetime

from django.db import transaction
from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance
)
from trueAlign.leave_management.services.leave_service import LeaveService
from trueAlign.leave_management.utils import (
    can_manage_leave_policies, can_manage_leave_types, is_hr, is_admin
)


class LeavePolicyManagementTests(TestCase):
    """Test case for leave policy management functionality"""

    def setUp(self):
        """Set up test data"""
        # Create groups/roles
        self.employee_group = Group.objects.create(name='Employee')
        self.manager_group = Group.objects.create(name='Manager')
        self.hr_group = Group.objects.create(name='HR')
        self.admin_group = Group.objects.create(name='Admin')
        self.finance_group = Group.objects.create(name='Finance')

        # Create test users
        self.employee_user = User.objects.create_user(
            username='employee1',
            email='employee1@test.com',
            password='testpass123',
            first_name='John',
            last_name='Employee'
        )
        self.employee_user.groups.add(self.employee_group)

        self.manager_user = User.objects.create_user(
            username='manager1',
            email='manager1@test.com',
            password='testpass123',
            first_name='Jane',
            last_name='Manager'
        )
        self.manager_user.groups.add(self.manager_group)

        self.hr_user = User.objects.create_user(
            username='hr1',
            email='hr1@test.com',
            password='testpass123',
            first_name='Emily',
            last_name='HR'
        )
        self.hr_user.groups.add(self.hr_group)

        self.admin_user = User.objects.create_user(
            username='admin1',
            email='admin1@test.com',
            password='testpass123',
            first_name='Alex',
            last_name='Admin'
        )
        self.admin_user.groups.add(self.admin_group)

        # Create leave service instance
        self.leave_service = LeaveService()

        # Create leave types
        self.casual_leave = LeaveType.objects.create(
            name='Casual Leave',
            description='Short leaves for personal work',
            is_paid=True,
            requires_approval=True,
            can_be_half_day=True,
            is_active=True
        )

        self.sick_leave = LeaveType.objects.create(
            name='Sick Leave',
            description='Leave for health issues',
            is_paid=True,
            requires_approval=True,
            requires_documentation=True,
            can_be_half_day=True,
            is_active=True
        )

        self.paternity_leave = LeaveType.objects.create(
            name='Paternity Leave',
            description='Leave for new fathers',
            is_paid=True,
            requires_approval=True,
            requires_documentation=True,
            can_be_half_day=False,
            is_active=True
        )

        self.lop_leave = LeaveType.objects.create(
            name='Loss of Pay',
            description='Leave without pay',
            is_paid=False,
            requires_approval=True,
            can_be_half_day=True,
            is_active=True
        )

        # Create leave policies
        self.standard_policy = LeavePolicy.objects.create(
            name='Standard Policy',
            group=self.employee_group,
            is_active=True
        )

        self.manager_policy = LeavePolicy.objects.create(
            name='Manager Policy',
            group=self.manager_group,
            is_active=True
        )

        # Create current year for testing
        self.current_year = timezone.now().year

    def test_leave_policy_creation(self):
        """Test creating a leave policy"""
        policy = LeavePolicy.objects.create(
            name='Executive Policy',
            group=self.admin_group,
            is_active=True
        )

        self.assertEqual(policy.name, 'Executive Policy')
        self.assertEqual(policy.group, self.admin_group)
        self.assertTrue(policy.is_active)
        self.assertIsNotNone(policy.created_at)
        self.assertIsNotNone(policy.updated_at)

    def test_leave_allocation_creation(self):
        """Test creating leave allocations for a policy"""
        # Create allocation for casual leave
        casual_allocation = LeaveAllocation.objects.create(
            policy=self.standard_policy,
            leave_type=self.casual_leave,
            annual_days=Decimal('10.0'),
            carry_forward_limit=Decimal('5.0'),
            max_consecutive_days=5,
            advance_notice_days=1
        )

        # Create allocation for sick leave
        sick_allocation = LeaveAllocation.objects.create(
            policy=self.standard_policy,
            leave_type=self.sick_leave,
            annual_days=Decimal('7.0'),
            carry_forward_limit=Decimal('3.5'),
            max_consecutive_days=7,
            advance_notice_days=0
        )

        # Verify the allocations
        self.assertEqual(casual_allocation.annual_days, Decimal('10.0'))
        self.assertEqual(casual_allocation.carry_forward_limit, Decimal('5.0'))
        self.assertEqual(casual_allocation.max_consecutive_days, 5)
        self.assertEqual(casual_allocation.advance_notice_days, 1)

        self.assertEqual(sick_allocation.annual_days, Decimal('7.0'))
        self.assertEqual(sick_allocation.carry_forward_limit, Decimal('3.5'))
        self.assertEqual(sick_allocation.max_consecutive_days, 7)
        self.assertEqual(sick_allocation.advance_notice_days, 0)

        # Check that the policy has two allocations
        self.assertEqual(self.standard_policy.allocations.count(), 2)

    def test_policy_unique_allocation_constraint(self):
        """Test that allocations for the same leave type are unique per policy"""
        # Create first allocation
        LeaveAllocation.objects.create(
            policy=self.standard_policy,
            leave_type=self.casual_leave,
            annual_days=Decimal('10.0')
        )

        # Attempt to create a duplicate allocation should raise IntegrityError
        with self.assertRaises(Exception):
            LeaveAllocation.objects.create(
                policy=self.standard_policy,
                leave_type=self.casual_leave,
                annual_days=Decimal('15.0')
            )

    def test_leave_allocation_modification(self):
        """Test modifying existing leave allocations"""
        # Create initial allocation
        allocation = LeaveAllocation.objects.create(
            policy=self.standard_policy,
            leave_type=self.casual_leave,
            annual_days=Decimal('10.0'),
            carry_forward_limit=Decimal('5.0')
        )

        # Modify the allocation
        allocation.annual_days = Decimal('12.0')
        allocation.carry_forward_limit = Decimal('6.0')
        allocation.save()

        # Refresh from database
        allocation.refresh_from_db()

        # Verify changes
        self.assertEqual(allocation.annual_days, Decimal('12.0'))
        self.assertEqual(allocation.carry_forward_limit, Decimal('6.0'))

    def test_user_leave_balance_creation(self):
        """Test creating a leave balance for a user"""
        # Create leave allocation first
        LeaveAllocation.objects.create(
            policy=self.standard_policy,
            leave_type=self.casual_leave,
            annual_days=Decimal('10.0')
        )

        # Create user balance
        balance = UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.casual_leave,
            year=self.current_year,
            allocated=Decimal('10.0')
        )

        self.assertEqual(balance.user, self.employee_user)
        self.assertEqual(balance.leave_type, self.casual_leave)
        self.assertEqual(balance.year, self.current_year)
        self.assertEqual(balance.allocated, Decimal('10.0'))
        self.assertEqual(balance.used, Decimal('0.0'))
        self.assertEqual(balance.carried_forward, Decimal('0.0'))
        self.assertEqual(balance.additional, Decimal('0.0'))

        # Test available property
        self.assertEqual(balance.available, Decimal('10.0'))

    def test_user_leave_balance_updates(self):
        """Test updating a user's leave balance"""
        # Create user balance
        balance = UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.casual_leave,
            year=self.current_year,
            allocated=Decimal('10.0')
        )

        # Update used days
        balance.used = Decimal('3.5')
        balance.save()

        # Refresh from database
        balance.refresh_from_db()

        # Verify available balance
        self.assertEqual(balance.used, Decimal('3.5'))
        self.assertEqual(balance.available, Decimal('6.5'))

        # Add carried forward days
        balance.carried_forward = Decimal('2.0')
        balance.save()

        # Refresh from database
        balance.refresh_from_db()

        # Verify updated available balance
        self.assertEqual(balance.available, Decimal('8.5'))

    def test_bulk_leave_allocation(self):
        """Test bulk allocation of leaves to users"""
        # Create allocations for standard policy
        LeaveAllocation.objects.create(
            policy=self.standard_policy,
            leave_type=self.casual_leave,
            annual_days=Decimal('10.0')
        )

        LeaveAllocation.objects.create(
            policy=self.standard_policy,
            leave_type=self.sick_leave,
            annual_days=Decimal('7.0')
        )

        # Create a few more employee users
        employee2 = User.objects.create_user(
            username='employee2',
            email='employee2@test.com',
            password='testpass123'
        )
        employee2.groups.add(self.employee_group)

        employee3 = User.objects.create_user(
            username='employee3',
            email='employee3@test.com',
            password='testpass123'
        )
        employee3.groups.add(self.employee_group)

        # Get users with employee role
        employee_users = User.objects.filter(groups=self.employee_group)
        self.assertEqual(employee_users.count(), 3)

        # Perform bulk allocation
        for user in employee_users:
            for allocation in self.standard_policy.allocations.all():
                UserLeaveBalance.objects.create(
                    user=user,
                    leave_type=allocation.leave_type,
                    year=self.current_year,
                    allocated=allocation.annual_days
                )

        # Verify all users got their allocations
        casual_balances = UserLeaveBalance.objects.filter(
            leave_type=self.casual_leave,
            year=self.current_year
        )
        self.assertEqual(casual_balances.count(), 3)

        sick_balances = UserLeaveBalance.objects.filter(
            leave_type=self.sick_leave,
            year=self.current_year
        )
        self.assertEqual(sick_balances.count(), 3)

        # Verify allocation amounts
        for balance in casual_balances:
            self.assertEqual(balance.allocated, Decimal('10.0'))

        for balance in sick_balances:
            self.assertEqual(balance.allocated, Decimal('7.0'))

    def test_leave_carry_forward(self):
        """Test carrying forward leave balances from one year to the next"""
        # Create allocation with carry-forward limit
        LeaveAllocation.objects.create(
            policy=self.standard_policy,
            leave_type=self.casual_leave,
            annual_days=Decimal('10.0'),
            carry_forward_limit=Decimal('5.0')
        )

        # Create previous year balance with unused days
        previous_year = self.current_year - 1
        previous_balance = UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.casual_leave,
            year=previous_year,
            allocated=Decimal('10.0'),
            used=Decimal('3.0')  # 7 days unused
        )

        # Create current year balance with carried forward days
        current_balance = UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.casual_leave,
            year=self.current_year,
            allocated=Decimal('10.0'),
            carried_forward=Decimal('5.0')  # Limited to 5 days by policy
        )

        # Verify carried forward amount (should be limited by policy)
        self.assertEqual(current_balance.carried_forward, Decimal('5.0'))
        self.assertEqual(current_balance.available, Decimal('15.0'))

        # Test another scenario where unused days are less than limit
        employee2 = User.objects.create_user(username='employee2', password='testpass123')
        employee2.groups.add(self.employee_group)

        previous_balance2 = UserLeaveBalance.objects.create(
            user=employee2,
            leave_type=self.casual_leave,
            year=previous_year,
            allocated=Decimal('10.0'),
            used=Decimal('8.0')  # 2 days unused
        )

        current_balance2 = UserLeaveBalance.objects.create(
            user=employee2,
            leave_type=self.casual_leave,
            year=self.current_year,
            allocated=Decimal('10.0'),
            carried_forward=Decimal('2.0')  # Only 2 days to carry forward
        )

        self.assertEqual(current_balance2.carried_forward, Decimal('2.0'))
        self.assertEqual(current_balance2.available, Decimal('12.0'))

    def test_policy_permission_checks(self):
        """Test permission checks for policy management"""
        # HR should be able to manage policies
        self.assertTrue(can_manage_leave_policies(self.hr_user))
        self.assertTrue(can_manage_leave_types(self.hr_user))

        # Admin should be able to manage policies
        self.assertTrue(can_manage_leave_policies(self.admin_user))
        self.assertTrue(can_manage_leave_types(self.admin_user))

        # Manager should not be able to manage policies
        self.assertFalse(can_manage_leave_policies(self.manager_user))
        self.assertFalse(can_manage_leave_types(self.manager_user))

        # Employee should not be able to manage policies
        self.assertFalse(can_manage_leave_policies(self.employee_user))
        self.assertFalse(can_manage_leave_types(self.employee_user))

    def test_user_balance_unique_constraint(self):
        """Test that user balance entries are unique per user, leave type, and year"""
        # Create first balance entry
        UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.casual_leave,
            year=self.current_year,
            allocated=Decimal('10.0')
        )

        # Attempt to create a duplicate entry should raise IntegrityError
        with transaction.atomic():
            with self.assertRaises(Exception):
                UserLeaveBalance.objects.create(
                    user=self.employee_user,
                    leave_type=self.casual_leave,
                    year=self.current_year,
                    allocated=Decimal('12.0')
                )

        # Different year should be allowed
        next_year = self.current_year + 1
        UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.casual_leave,
            year=next_year,
            allocated=Decimal('12.0')
        )

        # Different leave type should be allowed
        UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.sick_leave,
            year=self.current_year,
            allocated=Decimal('7.0')
        )


class LeaveServiceAllocationTests(TestCase):
    """Test case for the allocation methods in LeaveService"""

    def setUp(self):
        """Set up test data"""
        # Create groups/roles
        self.employee_group = Group.objects.create(name='Employee')
        self.manager_group = Group.objects.create(name='Manager')
        self.hr_group = Group.objects.create(name='HR')

        # Create test users
        self.employee_user = User.objects.create_user(
            username='employee1',
            email='employee1@test.com',
            password='testpass123'
        )
        self.employee_user.groups.add(self.employee_group)

        self.hr_user = User.objects.create_user(
            username='hr1',
            email='hr1@test.com',
            password='testpass123'
        )
        self.hr_user.groups.add(self.hr_group)

        # Create leave types
        self.casual_leave = LeaveType.objects.create(
            name='Casual Leave',
            is_paid=True,
            requires_approval=True,
            is_active=True
        )

        self.sick_leave = LeaveType.objects.create(
            name='Sick Leave',
            is_paid=True,
            requires_approval=True,
            is_active=True
        )

        # Create leave policy
        self.standard_policy = LeavePolicy.objects.create(
            name='Standard Policy',
            group=self.employee_group,
            is_active=True
        )

        # Create allocations
        self.casual_allocation = LeaveAllocation.objects.create(
            policy=self.standard_policy,
            leave_type=self.casual_leave,
            annual_days=Decimal('10.0'),
            carry_forward_limit=Decimal('5.0')
        )

        self.sick_allocation = LeaveAllocation.objects.create(
            policy=self.standard_policy,
            leave_type=self.sick_leave,
            annual_days=Decimal('7.0'),
            carry_forward_limit=Decimal('3.0')
        )

        # Create leave service
        self.leave_service = LeaveService()

        # Current year
        self.current_year = timezone.now().year

    def test_allocate_leaves_to_user(self):
        """Test allocating leaves to a single user"""
        # Allocate leaves to user
        allocation_result = self.leave_service.allocate_leaves_to_user(
            user=self.employee_user,
            allocations={},  # Empty dict as per implementation
            year=self.current_year
        )

        # Verify allocations were created
        self.assertTrue(allocation_result['success'])
        self.assertEqual(len(allocation_result['allocations']), 2)

        # Verify user leave balances were created
        balances = UserLeaveBalance.objects.filter(
            user=self.employee_user,
            year=self.current_year
        )
        self.assertEqual(balances.count(), 2)

        # Check balance amounts
        casual_balance = balances.get(leave_type=self.casual_leave)
        self.assertEqual(casual_balance.allocated, Decimal('10.0'))

        sick_balance = balances.get(leave_type=self.sick_leave)
        self.assertEqual(sick_balance.allocated, Decimal('7.0'))

    def test_bulk_allocate_leaves(self):
        """Test bulk allocation of leaves to multiple users"""
        # Create additional employees
        employee2 = User.objects.create_user(username='employee2', password='testpass123')
        employee2.groups.add(self.employee_group)

        employee3 = User.objects.create_user(username='employee3', password='testpass123')
        employee3.groups.add(self.employee_group)

        # Get all employees
        employees = User.objects.filter(groups=self.employee_group)
        self.assertEqual(employees.count(), 3)

        # Get all employees
        employee_list = list(employees)

        # Perform bulk allocation
        result = self.leave_service.bulk_allocate_leaves(
            user_list=employee_list,
            year=self.current_year
        )

        # Verify all users got allocations
        self.assertTrue(result['success'])
        # 3 users should have results
        self.assertEqual(len(result['results']), 3)

        # Verify balances in database
        balances = UserLeaveBalance.objects.filter(year=self.current_year)
        self.assertEqual(balances.count(), 6)

        # Verify each user has both leave types
        for user in employees:
            user_balances = UserLeaveBalance.objects.filter(
                user=user,
                year=self.current_year
            )
            self.assertEqual(user_balances.count(), 2)

            # Verify correct allocation amounts
            casual = user_balances.get(leave_type=self.casual_leave)
            self.assertEqual(casual.allocated, Decimal('10.0'))

            sick = user_balances.get(leave_type=self.sick_leave)
            self.assertEqual(sick.allocated, Decimal('7.0'))

    def test_get_user_leave_balance(self):
        """Test retrieving a user's leave balance"""
        # Create user balance
        UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.casual_leave,
            year=self.current_year,
            allocated=Decimal('10.0'),
            used=Decimal('2.5')
        )

        UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.sick_leave,
            year=self.current_year,
            allocated=Decimal('7.0'),
            used=Decimal('0.0')
        )

        # Get user balance
        balance_result = self.leave_service.get_user_leave_balance(
            user=self.employee_user,
            year=self.current_year
        )

        # Verify balances
        self.assertTrue(balance_result['success'])
        self.assertEqual(len(balance_result['balances']), 2)

        # Check specific balance details
        casual_balance = next(b for b in balance_result['balances'] if b['leave_type'] == 'Casual Leave')
        self.assertEqual(casual_balance['allocated'], 10.0)
        self.assertEqual(casual_balance['used'], 2.5)
        self.assertEqual(casual_balance['available'], 7.5)

        sick_balance = next(b for b in balance_result['balances'] if b['leave_type'] == 'Sick Leave')
        self.assertEqual(sick_balance['allocated'], 7.0)
        self.assertEqual(sick_balance['used'], 0.0)
        self.assertEqual(sick_balance['available'], 7.0)

    def test_allocate_additional_leaves(self):
        """Test allocating additional leaves to a user"""
        # Create initial balance
        balance = UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.casual_leave,
            year=self.current_year,
            allocated=Decimal('10.0')
        )

        # Add additional leaves
        balance.additional = Decimal('2.0')
        balance.save()

        # Verify updated balance
        balance.refresh_from_db()
        self.assertEqual(balance.additional, Decimal('2.0'))
        self.assertEqual(balance.available, Decimal('12.0'))

        # Get balance via service
        balance_result = self.leave_service.get_user_leave_balance(
            user=self.employee_user,
            year=self.current_year
        )

        casual_balance = next(b for b in balance_result['balances'] if b['leave_type'] == 'Casual Leave')
        self.assertEqual(casual_balance['allocated'], 10.0)
        self.assertEqual(casual_balance['additional'], 2.0)
        self.assertEqual(casual_balance['available'], 12.0)
