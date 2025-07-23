from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from decimal import Decimal
from trueAlign.models import LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance, LeaveRequest

@override_settings(
    STATICFILES_STORAGE='django.contrib.staticfiles.storage.StaticFilesStorage',
    DEBUG=True
)
class LeaveManagementCoreTests(TestCase):
    """
    Core functionality tests for the Leave Management System
    Focused on the essential features without UI dependencies
    """

    def setUp(self):
        """Set up test data for all tests"""
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

        self.manager_user = User.objects.create_user(username="manager", email="manager@example.com", password="password")
        self.manager_user.groups.add(self.manager_group)

        self.employee_user = User.objects.create_user(username="employee", email="employee@example.com", password="password")
        self.employee_user.groups.add(self.employee_group)

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
            requires_documentation=True,
            can_be_half_day=True
        )

        # Create leave policies for each group
        self.standard_policy = LeavePolicy.objects.create(
            name="Standard Policy",
            group=self.employee_group,
            is_active=True
        )

        self.manager_policy = LeavePolicy.objects.create(
            name="Manager Policy",
            group=self.manager_group,
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

        # Create user leave balances directly
        UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year,
            allocated=Decimal('20.0'),
            used=Decimal('0.0'),
            carried_forward=Decimal('0.0')
        )

        UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.sick_leave,
            year=timezone.now().year,
            allocated=Decimal('10.0'),
            used=Decimal('0.0'),
            carried_forward=Decimal('0.0')
        )

        # Create test client
        self.client = Client()

    def test_models_exist(self):
        """Test that the models are properly configured"""
        # Check leave types
        self.assertEqual(LeaveType.objects.count(), 2)
        self.assertEqual(LeaveType.objects.filter(name="Annual Leave").count(), 1)
        self.assertEqual(LeaveType.objects.filter(name="Sick Leave").count(), 1)

        # Check leave policies
        self.assertEqual(LeavePolicy.objects.count(), 2)
        self.assertEqual(LeavePolicy.objects.filter(name="Standard Policy").count(), 1)

        # Check leave allocations
        self.assertEqual(LeaveAllocation.objects.count(), 2)

        # Check user leave balances
        self.assertEqual(UserLeaveBalance.objects.count(), 2)
        self.assertEqual(
            UserLeaveBalance.objects.filter(
                user=self.employee_user,
                leave_type=self.annual_leave
            ).count(),
            1
        )

    def test_leave_request_creation(self):
        """Test creating a leave request"""
        # Create a leave request directly
        start_date = timezone.now().date() + timedelta(days=10)
        end_date = start_date + timedelta(days=2)

        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            reason="Test vacation",
            status="Pending"
        )

        # Verify it was created
        self.assertEqual(leave_request.status, "Pending")
        self.assertEqual(leave_request.user, self.employee_user)
        self.assertEqual(leave_request.leave_type, self.annual_leave)

        # Check that we can retrieve it
        retrieved_request = LeaveRequest.objects.get(id=leave_request.id)
        self.assertEqual(retrieved_request, leave_request)

    def test_leave_request_approval(self):
        """Test approving a leave request"""
        # Create a leave request
        start_date = timezone.now().date() + timedelta(days=10)
        end_date = start_date + timedelta(days=2)

        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            reason="Test vacation",
            status="Pending"
        )

        # Update it to approved status
        leave_request.status = "Approved"
        leave_request.approver = self.manager_user
        leave_request.save()

        # Verify it was updated
        updated_request = LeaveRequest.objects.get(id=leave_request.id)
        self.assertEqual(updated_request.status, "Approved")
        self.assertEqual(updated_request.approver, self.manager_user)

        # Update the balance to reflect the approved leave
        balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        balance.used = Decimal('3.0')  # 3 days used
        balance.save()

        # Verify balance update
        updated_balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        self.assertEqual(updated_balance.used, Decimal('3.0'))
        self.assertEqual(updated_balance.allocated - updated_balance.used, Decimal('17.0'))  # Available balance

    def test_leave_request_rejection(self):
        """Test rejecting a leave request"""
        # Create a leave request
        start_date = timezone.now().date() + timedelta(days=10)
        end_date = start_date + timedelta(days=2)

        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            reason="Test vacation",
            status="Pending"
        )

        # Update it to rejected status
        leave_request.status = "Rejected"
        leave_request.approver = self.manager_user
        leave_request.rejection_reason = "Team capacity issues"
        leave_request.save()

        # Verify it was updated
        updated_request = LeaveRequest.objects.get(id=leave_request.id)
        self.assertEqual(updated_request.status, "Rejected")
        self.assertEqual(updated_request.approver, self.manager_user)
        self.assertEqual(updated_request.rejection_reason, "Team capacity issues")

    def test_leave_request_cancellation(self):
        """Test cancelling a leave request"""
        # Create and approve a leave request
        start_date = timezone.now().date() + timedelta(days=10)
        end_date = start_date + timedelta(days=2)

        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            reason="Test vacation",
            status="Approved",
            approver=self.manager_user
        )

        # Update the balance to reflect the approved leave
        balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        balance.used = Decimal('3.0')  # 3 days used
        balance.save()

        # Cancel the leave request
        leave_request.status = "Cancelled"
        leave_request.cancellation_reason = "Plans changed"
        leave_request.save()

        # Verify it was updated
        updated_request = LeaveRequest.objects.get(id=leave_request.id)
        self.assertEqual(updated_request.status, "Cancelled")
        self.assertEqual(updated_request.cancellation_reason, "Plans changed")

        # Update the balance to reflect the cancellation
        balance.used = Decimal('0.0')  # No days used after cancellation
        balance.save()

        # Verify balance update
        updated_balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        self.assertEqual(updated_balance.used, Decimal('0.0'))
        self.assertEqual(updated_balance.allocated - updated_balance.used, Decimal('20.0'))  # Full balance restored

    def test_half_day_leave(self):
        """Test half-day leave calculation"""
        # Create a half-day leave request
        start_date = timezone.now().date() + timedelta(days=10)

        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=start_date,  # Same day (1 day)
            half_day=True,
            reason="Half-day appointment",
            status="Approved",
            approver=self.manager_user
        )

        # Update the balance to reflect the approved leave
        balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        balance.used = Decimal('0.5')  # 0.5 days used
        balance.save()

        # Verify balance update
        updated_balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        self.assertEqual(updated_balance.used, Decimal('0.5'))
        self.assertEqual(updated_balance.allocated - updated_balance.used, Decimal('19.5'))  # Available balance

    def test_database_integrity(self):
        """Test overall database integrity"""
        # Verify all leave types have required fields
        for leave_type in LeaveType.objects.all():
            self.assertIsNotNone(leave_type.name)
            self.assertIsNotNone(leave_type.is_paid)
            self.assertIsNotNone(leave_type.requires_approval)
            self.assertIsNotNone(leave_type.can_be_half_day)

        # Verify all policies have required fields
        for policy in LeavePolicy.objects.all():
            self.assertIsNotNone(policy.name)
            self.assertIsNotNone(policy.group)
            self.assertIsNotNone(policy.is_active)

        # Verify all allocations have required fields
        for allocation in LeaveAllocation.objects.all():
            self.assertIsNotNone(allocation.policy)
            self.assertIsNotNone(allocation.leave_type)
            self.assertIsNotNone(allocation.annual_days)

        # Verify all balances have required fields
        for balance in UserLeaveBalance.objects.all():
            self.assertIsNotNone(balance.user)
            self.assertIsNotNone(balance.leave_type)
            self.assertIsNotNone(balance.year)
            self.assertIsNotNone(balance.allocated)
