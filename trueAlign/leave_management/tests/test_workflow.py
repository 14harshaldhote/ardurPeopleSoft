from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from trueAlign.leave_management.services.leave_service import LeaveService
from trueAlign.models import LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance, LeaveRequest

class LeaveWorkflowTests(TestCase):
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

        # Allocate leaves to employee
        self.leave_service = LeaveService()
        self.leave_service.allocate_leaves_to_user(
            user=self.employee_user,
            leave_type=self.annual_leave,
            days=20,
            year=timezone.now().year
        )

        self.leave_service.allocate_leaves_to_user(
            user=self.employee_user,
            leave_type=self.sick_leave,
            days=10,
            year=timezone.now().year
        )

        # Create test client
        self.client = Client()

    def test_complete_leave_workflow(self):
        """Test the entire leave request and approval workflow"""
        # 1. Employee applies for leave
        self.client.login(username="employee", password="password")

        start_date = timezone.now().date() + timedelta(days=5)
        end_date = start_date + timedelta(days=2)  # 3 days total

        leave_data = {
            'leave_type': self.annual_leave.id,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'half_day': False,
            'reason': 'Vacation',
        }

        response = self.client.post(reverse('leave_management:apply_leave'), leave_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after successful submission

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
        self.assertEqual(balance.used_days, 3)  # Should reflect the 3 days used

        # 4. Verify leave shows up in calendar/dashboard
        self.client.login(username="employee", password="password")
        response = self.client.get(reverse('leave_management:my_leaves'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Vacation')  # Reason should be displayed
        self.assertContains(response, 'Approved')  # Status should be displayed

    def test_leave_rejection_workflow(self):
        """Test leave rejection workflow"""
        # 1. Employee applies for leave with insufficient notice
        self.client.login(username="employee", password="password")

        start_date = timezone.now().date() + timedelta(days=1)  # Only 1 day notice (policy requires 3)
        end_date = start_date + timedelta(days=5)

        leave_data = {
            'leave_type': self.annual_leave.id,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'half_day': False,
            'reason': 'Last minute trip',
        }

        response = self.client.post(reverse('leave_management:apply_leave'), leave_data)
        self.assertEqual(response.status_code, 200)  # Form should show validation error
        self.assertContains(response, 'notice')  # Error message about insufficient notice

        # 2. Employee applies with proper notice but HR rejects
        start_date = timezone.now().date() + timedelta(days=5)  # Proper notice
        end_date = start_date + timedelta(days=5)

        leave_data = {
            'leave_type': self.annual_leave.id,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'half_day': False,
            'reason': 'Trip',
        }

        response = self.client.post(reverse('leave_management:apply_leave'), leave_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after submission

        # Get the created leave request
        leave_request = LeaveRequest.objects.get(
            user=self.employee_user,
            start_date=start_date,
            end_date=end_date
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

        # 3. Check that balance was not affected
        balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        self.assertEqual(balance.used_days, 0)  # No days should be deducted for rejected leave

    def test_leave_cancellation_workflow(self):
        """Test leave cancellation workflow"""
        # 1. Apply and approve leave first
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

        # Approve it
        self.leave_service.approve_leave(
            leave_request=leave_request,
            approver=self.manager_user,
            comments="Approved"
        )

        # Verify it's approved and balance is updated
        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Approved')

        balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        initial_used_days = balance.used_days
        self.assertTrue(initial_used_days > 0)  # Should have used some days

        # 2. Cancel the approved leave
        self.client.login(username="employee", password="password")

        cancellation_data = {
            'cancellation_reason': 'Plans changed'
        }

        response = self.client.post(reverse('leave_management:cancel_leave', args=[leave_request.id]), cancellation_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # 3. Verify cancellation and balance restoration
        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Cancelled')

        balance.refresh_from_db()
        self.assertEqual(balance.used_days, 0)  # Balance should be restored

    def test_half_day_leave_workflow(self):
        """Test half-day leave workflow"""
        # 1. Employee applies for half-day leave
        self.client.login(username="employee", password="password")

        start_date = timezone.now().date() + timedelta(days=5)
        end_date = start_date  # Same day (1 day)

        leave_data = {
            'leave_type': self.annual_leave.id,
            'start_date': start_date.strftime('%Y-%m-%d'),
            'end_date': end_date.strftime('%Y-%m-%d'),
            'half_day': True,  # Half day
            'reason': 'Afternoon appointment',
        }

        response = self.client.post(reverse('leave_management:apply_leave'), leave_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after submission

        # Verify leave request was created with half day
        leave_request = LeaveRequest.objects.get(
            user=self.employee_user,
            start_date=start_date,
            end_date=end_date,
            half_day=True
        )
        self.assertEqual(leave_request.status, 'Pending')

        # 2. Manager approves the half-day leave
        self.client.login(username="manager", password="password")

        approval_data = {
            'comments': 'Approved'
        }

        response = self.client.post(reverse('leave_management:approve_leave', args=[leave_request.id]), approval_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # 3. Check that balance was deducted correctly (0.5 days)
        balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        self.assertEqual(balance.used_days, 0.5)  # Should deduct half a day

    def test_overlapping_leave_validation(self):
        """Test validation for overlapping leave requests"""
        # 1. Create an approved leave first
        start_date = timezone.now().date() + timedelta(days=20)
        end_date = start_date + timedelta(days=4)  # 5 days

        leave_request = self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            reason="Vacation"
        )

        self.leave_service.approve_leave(
            leave_request=leave_request,
            approver=self.manager_user,
            comments="Approved"
        )

        # 2. Try to apply for leave that overlaps
        self.client.login(username="employee", password="password")

        # Overlapping dates
        overlap_start = start_date + timedelta(days=2)
        overlap_end = end_date + timedelta(days=2)

        overlap_data = {
            'leave_type': self.annual_leave.id,
            'start_date': overlap_start.strftime('%Y-%m-%d'),
            'end_date': overlap_end.strftime('%Y-%m-%d'),
            'half_day': False,
            'reason': 'Overlapping trip',
        }

        response = self.client.post(reverse('leave_management:apply_leave'), overlap_data)
        self.assertEqual(response.status_code, 200)  # Form should show validation error
        self.assertContains(response, 'overlap')  # Error message about overlapping dates

        # 3. Verify no new leave request was created
        self.assertEqual(
            LeaveRequest.objects.filter(
                user=self.employee_user,
                start_date=overlap_start,
                end_date=overlap_end
            ).count(),
            0
        )
