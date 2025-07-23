from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from trueAlign.leave_management.services.leave_service import LeaveService
from trueAlign.models import LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance

class LeaveAllocationTests(TestCase):
    def setUp(self):
        # Create user groups
        self.admin_group = Group.objects.create(name="Admin")
        self.hr_group = Group.objects.create(name="HR")
        self.manager_group = Group.objects.create(name="Manager")
        self.employee_group = Group.objects.create(name="Employee")

        # Create test users
        self.admin_user = User.objects.create_user(username="admin", email="admin@example.com", password="password")
        self.admin_user.groups.add(self.admin_group)

        self.hr_user = User.objects.create_user(username="hr", email="hr@example.com", password="password")
        self.hr_user.groups.add(self.hr_group)

        self.employee1 = User.objects.create_user(username="employee1", email="emp1@example.com", password="password")
        self.employee1.groups.add(self.employee_group)

        self.employee2 = User.objects.create_user(username="employee2", email="emp2@example.com", password="password")
        self.employee2.groups.add(self.employee_group)

        # Create leave types
        self.annual_leave = LeaveType.objects.create(
            name="Annual Leave",
            is_paid=True,
            requires_approval=True,
            can_be_half_day=True
        )

        self.sick_leave = LeaveType.objects.create(
            name="Sick Leave",
            is_paid=True,
            requires_approval=True,
            can_be_half_day=True
        )

        # Create leave policy
        self.standard_policy = LeavePolicy.objects.create(
            name="Standard Policy",
            group=self.employee_group,
            is_active=True
        )

        # Create leave allocations
        self.annual_allocation = LeaveAllocation.objects.create(
            policy=self.standard_policy,
            leave_type=self.annual_leave,
            annual_days=20,
            carry_forward_limit=5,
            max_consecutive_days=10,
            advance_notice_days=3
        )

        self.sick_allocation = LeaveAllocation.objects.create(
            policy=self.standard_policy,
            leave_type=self.sick_leave,
            annual_days=10,
            carry_forward_limit=0,
            max_consecutive_days=5,
            advance_notice_days=0
        )

        # Create service instance
        self.leave_service = LeaveService()

        # Create test client
        self.client = Client()

    def test_allocation_creation(self):
        """Test creating leave allocations for a policy"""
        # Login as HR
        self.client.login(username="hr", password="password")

        # Create a new leave type
        paternity_leave = LeaveType.objects.create(
            name="Paternity Leave",
            is_paid=True,
            requires_approval=True,
            can_be_half_day=False
        )

        # Create allocation for the leave type
        allocation_data = {
            'policy': self.standard_policy.id,
            'leave_type': paternity_leave.id,
            'annual_days': 14,
            'carry_forward_limit': 0,
            'max_consecutive_days': 14,
            'advance_notice_days': 30
        }

        response = self.client.post(reverse('leave_management:create_allocation'), allocation_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify allocation was created
        self.assertTrue(LeaveAllocation.objects.filter(
            policy=self.standard_policy,
            leave_type=paternity_leave
        ).exists())

        # Verify allocation data
        allocation = LeaveAllocation.objects.get(
            policy=self.standard_policy,
            leave_type=paternity_leave
        )
        self.assertEqual(allocation.annual_days, 14)
        self.assertEqual(allocation.carry_forward_limit, 0)
        self.assertEqual(allocation.max_consecutive_days, 14)
        self.assertEqual(allocation.advance_notice_days, 30)

    def test_allocation_update(self):
        """Test updating an existing leave allocation"""
        # Login as HR
        self.client.login(username="hr", password="password")

        # Update existing allocation
        update_data = {
            'policy': self.standard_policy.id,
            'leave_type': self.annual_leave.id,
            'annual_days': 25,  # Increased from 20
            'carry_forward_limit': 7,  # Increased from 5
            'max_consecutive_days': 15,
            'advance_notice_days': 5
        }

        response = self.client.post(
            reverse('leave_management:update_allocation', args=[self.annual_allocation.id]),
            update_data
        )
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify update
        self.annual_allocation.refresh_from_db()
        self.assertEqual(self.annual_allocation.annual_days, 25)
        self.assertEqual(self.annual_allocation.carry_forward_limit, 7)
        self.assertEqual(self.annual_allocation.max_consecutive_days, 15)
        self.assertEqual(self.annual_allocation.advance_notice_days, 5)

    def test_allocation_deletion(self):
        """Test deleting a leave allocation"""
        # Login as Admin
        self.client.login(username="admin", password="password")

        # Delete allocation
        response = self.client.post(
            reverse('leave_management:delete_allocation', args=[self.sick_allocation.id])
        )
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify deletion
        self.assertFalse(LeaveAllocation.objects.filter(id=self.sick_allocation.id).exists())

    def test_bulk_allocation(self):
        """Test bulk allocation of leaves to users"""
        # Login as HR
        self.client.login(username="hr", password="password")

        # Bulk allocate leaves based on policy
        bulk_data = {
            'policy': self.standard_policy.id,
            'year': 2025
        }

        response = self.client.post(reverse('leave_management:bulk_allocate'), bulk_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify allocations were created for both employees
        self.assertTrue(UserLeaveBalance.objects.filter(
            user=self.employee1,
            leave_type=self.annual_leave,
            year=2025
        ).exists())

        self.assertTrue(UserLeaveBalance.objects.filter(
            user=self.employee2,
            leave_type=self.annual_leave,
            year=2025
        ).exists())

        # Verify allocated days match policy
        balance1 = UserLeaveBalance.objects.get(
            user=self.employee1,
            leave_type=self.annual_leave,
            year=2025
        )
        self.assertEqual(balance1.allocated_days, 20)

        balance2 = UserLeaveBalance.objects.get(
            user=self.employee2,
            leave_type=self.sick_leave,
            year=2025
        )
        self.assertEqual(balance2.allocated_days, 10)

    def test_manual_balance_adjustment(self):
        """Test manually adjusting a user's leave balance"""
        # First allocate some leave to the user
        self.leave_service.allocate_leaves_to_user(
            user=self.employee1,
            leave_type=self.annual_leave,
            days=20,
            year=2025
        )

        # Login as HR
        self.client.login(username="hr", password="password")

        # Adjust the balance
        adjustment_data = {
            'user': self.employee1.id,
            'leave_type': self.annual_leave.id,
            'year': 2025,
            'adjustment_days': 5,
            'adjustment_type': 'add',
            'reason': 'Performance bonus'
        }

        response = self.client.post(reverse('leave_management:adjust_balance'), adjustment_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify adjustment
        balance = UserLeaveBalance.objects.get(
            user=self.employee1,
            leave_type=self.annual_leave,
            year=2025
        )
        self.assertEqual(balance.allocated_days, 25)  # 20 original + 5 adjustment

    def test_carry_forward(self):
        """Test year-end carry forward of unused leave"""
        # Setup balance for previous year with unused days
        self.leave_service.allocate_leaves_to_user(
            user=self.employee1,
            leave_type=self.annual_leave,
            days=20,
            year=2024
        )

        # Use 10 days, leaving 10 unused (with carry forward limit of 5)
        balance = UserLeaveBalance.objects.get(
            user=self.employee1,
            leave_type=self.annual_leave,
            year=2024
        )
        balance.used_days = 10
        balance.save()

        # Login as HR
        self.client.login(username="hr", password="password")

        # Process carry forward
        carry_forward_data = {
            'from_year': 2024,
            'to_year': 2025
        }

        response = self.client.post(reverse('leave_management:process_carry_forward'), carry_forward_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify carry forward to new year
        new_balance = UserLeaveBalance.objects.get(
            user=self.employee1,
            leave_type=self.annual_leave,
            year=2025
        )
        self.assertEqual(new_balance.carried_forward_days, 5)  # Should be limited to policy's limit
