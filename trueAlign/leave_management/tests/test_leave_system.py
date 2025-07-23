from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from trueAlign.leave_management.services.leave_service import LeaveService
from trueAlign.models import LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance, LeaveRequest

class LeaveManagementComprehensiveTests(TestCase):
    """
    Comprehensive test suite for the Leave Management System
    Tests core functionality, workflows, and edge cases
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

        # Create service instance
        self.leave_service = LeaveService()

        # Create user leave balances directly instead of using the service
        # This avoids potential issues with the leave service implementation
        UserLeaveBalance.objects.create(
                user=self.employee_user,
                leave_type=self.annual_leave,
                year=timezone.now().year,
                allocated=20,
                used=0,
                carried_forward=0
            )

        UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.sick_leave,
            year=timezone.now().year,
            allocated=10,
            used=0,
            carried_forward=0
        )

        UserLeaveBalance.objects.create(
            user=self.manager_user,
            leave_type=self.annual_leave,
            year=timezone.now().year,
            allocated=20,
            used=0,
            carried_forward=0
        )

        UserLeaveBalance.objects.create(
            user=self.manager_user,
            leave_type=self.sick_leave,
            year=timezone.now().year,
            allocated=10,
            used=0,
            carried_forward=0
        )

        # Create test client
        self.client = Client()

    def test_dashboard_access(self):
        """Test role-based dashboard access permissions"""
        # Employee can access employee dashboard only
        self.client.login(username="employee", password="password")

        response = self.client.get(reverse('leave_management:employee_dashboard'))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse('leave_management:manager_dashboard'))
        self.assertEqual(response.status_code, 403)  # Forbidden

        # Manager can access employee and manager dashboards
        self.client.login(username="manager", password="password")

        response = self.client.get(reverse('leave_management:employee_dashboard'))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse('leave_management:manager_dashboard'))
        self.assertEqual(response.status_code, 200)

        # HR can access employee, manager, and HR dashboards
        self.client.login(username="hr", password="password")

        response = self.client.get(reverse('leave_management:hr_dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_leave_application_workflow(self):
        """Test the complete leave application and approval workflow"""
        # 1. Employee applies for leave
        self.client.login(username="employee", password="password")

        start_date = timezone.now().date() + timedelta(days=5)
        end_date = start_date + timedelta(days=2)  # 3 days total

        leave_data = {
            'leave_type': self.annual_leave.id,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'half_day': False,
            'reason': 'Test vacation',
        }

        response = self.client.post(reverse('leave_management:apply_leave'), leave_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify leave request was created
        leave_request = LeaveRequest.objects.get(
            user=self.employee_user,
            start_date=start_date,
            end_date=end_date
        )
        self.assertEqual(leave_request.status, 'Pending')
        self.assertEqual(leave_request.leave_type, self.annual_leave)

        # 2. Manager approves the leave
        self.client.login(username="manager", password="password")

        approval_data = {
            'comments': 'Approved, enjoy your vacation!'
        }

        response = self.client.post(reverse('leave_management:approve_leave', args=[leave_request.id]), approval_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify leave was approved
        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Approved')
        self.assertEqual(leave_request.approver, self.manager_user)

        # 3. Check balance was updated
        balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        self.assertEqual(balance.used_days, 3)  # 3 days used

    def test_half_day_leave(self):
        """Test half-day leave application and calculation"""
        # Apply for half-day leave
        self.client.login(username="employee", password="password")

        start_date = timezone.now().date() + timedelta(days=5)

        leave_data = {
            'leave_type': self.annual_leave.id,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': start_date.strftime('%Y-%m-%d'),
            'half_day': True,
            'reason': 'Half-day appointment',
        }

        response = self.client.post(reverse('leave_management:apply_leave'), leave_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify leave request was created with half day
        leave_request = LeaveRequest.objects.get(
            user=self.employee_user,
            start_date=start_date,
            end_date=start_date,
            half_day=True
        )
        self.assertEqual(leave_request.status, 'Pending')

        # Approve the leave
        self.client.login(username="manager", password="password")

        approval_data = {
            'comments': 'Approved'
        }

        response = self.client.post(reverse('leave_management:approve_leave', args=[leave_request.id]), approval_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Check that balance was deducted correctly (0.5 days)
        balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        self.assertEqual(balance.used_days, 0.5)  # Should deduct half a day

    def test_leave_rejection(self):
        """Test leave rejection workflow"""
        # Create a leave request directly using service
        start_date = timezone.now().date() + timedelta(days=10)
        end_date = start_date + timedelta(days=2)

        leave_request = self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            reason="Vacation"
        )

        # HR rejects the leave
        self.client.login(username="hr", password="password")

        rejection_data = {
            'rejection_reason': 'Critical project deadline during this period'
        }

        response = self.client.post(reverse('leave_management:reject_leave', args=[leave_request.id]), rejection_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify leave was rejected
        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Rejected')
        self.assertEqual(leave_request.approver, self.hr_user)
        self.assertEqual(leave_request.rejection_reason, 'Critical project deadline during this period')

        # Check that balance was not affected
        balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        self.assertEqual(balance.used_days, 0)  # No days should be deducted for rejected leave

    def test_leave_cancellation(self):
        """Test leave cancellation workflow"""
        # Create and approve a leave request
        start_date = timezone.now().date() + timedelta(days=15)
        end_date = start_date + timedelta(days=2)

        leave_request = self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            reason="Vacation"
        )

        # Approve it
        self.leave_service.approve_leave(
            leave_request=leave_request,
            approver=self.manager_user,
            comments="Approved"
        )

        # Verify initial state
        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Approved')

        initial_balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        initial_used_days = initial_balance.used_days
        self.assertTrue(initial_used_days > 0)  # Should have used some days

        # Cancel the leave
        self.client.login(username="employee", password="password")

        cancellation_data = {
            'cancellation_reason': 'Plans changed'
        }

        response = self.client.post(reverse('leave_management:cancel_leave', args=[leave_request.id]), cancellation_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify cancellation and balance restoration
        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Cancelled')

        final_balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        self.assertEqual(final_balance.used_days, 0)  # Balance should be restored

    def test_api_endpoints(self):
        """Test API endpoints"""
        # Login as employee
        self.client.login(username="employee", password="password")

        # Test leave balance API
        response = self.client.get(reverse('leave_management:api_leave_balance'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'balances')

        # Test leave types API
        response = self.client.get(reverse('leave_management:api_leave_types'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Annual Leave')
        self.assertContains(response, 'Sick Leave')

    def test_leave_balance_view(self):
        """Test leave balance view"""
        self.client.login(username="employee", password="password")

        response = self.client.get(reverse('leave_management:leave_balance'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Annual Leave')
        self.assertContains(response, '20')  # Allocated days

    def test_edge_case_zero_balance(self):
        """Test applying for leave with exactly 0 balance remaining"""
        # Use up all available leave by setting the balance directly
        balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        balance.used = balance.allocated
        balance.save()

        # Try to apply for one more day through the form
        self.client.login(username="employee", password="password")

        start_date = timezone.now().date() + timedelta(days=60)
        end_date = start_date

        leave_data = {
            'leave_type': self.annual_leave.id,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'half_day': False,
            'reason': 'One more day',
        }

        response = self.client.post(reverse('leave_management:apply_leave'), leave_data)
        self.assertEqual(response.status_code, 200)  # Form should show validation error
        self.assertContains(response, 'insufficient')  # Error message about balance

    def test_team_leave_view(self):
        """Test team leave view for managers"""
        # Create a leave request for employee
        leave_request = self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=timezone.now().date() + timedelta(days=5),
            end_date=timezone.now().date() + timedelta(days=7),
            reason="Team view test"
        )

        # Login as manager and check team view
        self.client.login(username="manager", password="password")

        response = self.client.get(reverse('leave_management:team_leaves'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Team view test')  # Should show employee's leave

        # Employee should not have access to team view
        self.client.login(username="employee", password="password")

        response = self.client.get(reverse('leave_management:team_leaves'))
        self.assertEqual(response.status_code, 403)  # Forbidden

    def test_health_check(self):
        """Test overall health of the leave management system"""
        # Check database integrity
        leave_types_count = LeaveType.objects.count()
        self.assertGreaterEqual(leave_types_count, 2)

        policies_count = LeavePolicy.objects.count()
        self.assertGreaterEqual(policies_count, 1)

        allocations_count = LeaveAllocation.objects.count()
        self.assertGreaterEqual(allocations_count, 2)

        balances_count = UserLeaveBalance.objects.count()
        self.assertGreaterEqual(balances_count, 3)  # At least 3 balances created in setup

        # Check URL configuration
        self.client.login(username="admin", password="password")

        for url_name in ['dashboard', 'employee_dashboard', 'manager_dashboard',
                         'hr_dashboard', 'admin_dashboard', 'apply_leave',
                         'my_leaves', 'team_leaves', 'leave_balance']:
            url = reverse(f'leave_management:{url_name}')
            response = self.client.get(url)
            self.assertIn(response.status_code, [200, 302])  # Should be successful or redirect
