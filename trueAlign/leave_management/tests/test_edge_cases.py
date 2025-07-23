from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.utils import timezone
from datetime import timedelta
from trueAlign.leave_management.services.leave_service import LeaveService, LeaveServiceError
from trueAlign.models import LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance, LeaveRequest

class LeaveEdgeCaseTests(TestCase):
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

    def test_exactly_zero_leave_balance(self):
        """Test applying for leave with exactly 0 balance remaining"""
        # Use up all available leave
        start_date = timezone.now().date() + timedelta(days=5)
        end_date = start_date + timedelta(days=19)  # 20 days total

        # Apply leave to use up balance
        self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            reason="Using all my leave"
        )

        # Try to apply for one more day
        new_start = end_date + timedelta(days=5)
        new_end = new_start

        with self.assertRaises(LeaveServiceError):
            self.leave_service.apply_leave(
                user=self.employee_user,
                leave_type=self.annual_leave,
                start_date=new_start,
                end_date=new_end,
                reason="Trying to use more leave"
            )

    def test_leave_spanning_multiple_years(self):
        """Test leave application spanning across different years"""
        # Create a leave request that spans across Dec 31 to Jan 2
        current_year = timezone.now().year
        start_date = timezone.datetime(current_year, 12, 30).date()
        end_date = timezone.datetime(current_year + 1, 1, 2).date()

        # This should use 2 days from current year and 2 days from next year
        # Check if the system correctly handles this case
        leave_request = self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            reason="Year-end leave"
        )

        # Should succeed and deduct from current year's balance
        self.assertEqual(leave_request.status, 'Pending')
        self.assertEqual(leave_request.leave_days, 4)  # 4 working days total

    def test_backdated_leave_request(self):
        """Test applying for leave with dates in the past"""
        # Try to apply for leave with start date in the past
        past_start = timezone.now().date() - timedelta(days=5)
        past_end = past_start + timedelta(days=2)

        # This should fail or require special handling
        with self.assertRaises(LeaveServiceError):
            self.leave_service.apply_leave(
                user=self.employee_user,
                leave_type=self.annual_leave,
                start_date=past_start,
                end_date=past_end,
                reason="Backdated leave",
                is_retroactive=False  # Not marked as retroactive
            )

        # Now try with retroactive flag
        leave_request = self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=past_start,
            end_date=past_end,
            reason="Backdated leave",
            is_retroactive=True  # Marked as retroactive
        )

        # Should succeed with retroactive flag
        self.assertEqual(leave_request.status, 'Pending')
        self.assertTrue(leave_request.is_retroactive)

    def test_weekend_only_leave(self):
        """Test applying for leave that only includes weekends"""
        # Find a Saturday
        start_date = timezone.now().date()
        while start_date.weekday() != 5:  # 5 = Saturday
            start_date += timedelta(days=1)

        # Saturday and Sunday only
        end_date = start_date + timedelta(days=1)

        leave_request = self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            reason="Weekend leave"
        )

        # Should be 0 working days
        self.assertEqual(leave_request.leave_days, 0)

        # Check balance wasn't affected
        balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        self.assertEqual(balance.used_days, 0)

    def test_one_hour_leave(self):
        """Test applying for very short leave (1 hour)"""
        # One hour leave should be treated as half day
        start_date = timezone.now().date() + timedelta(days=5)
        end_date = start_date

        # Create leave with half_day flag and specify hours
        leave_request = self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            half_day=True,
            reason="Doctor appointment (1 hour)"
        )

        # Should be calculated as 0.5 days
        self.assertEqual(leave_request.leave_days, 0.5)

    def test_maximum_consecutive_days(self):
        """Test applying for leave exceeding max consecutive days"""
        # Policy allows max 10 consecutive days
        start_date = timezone.now().date() + timedelta(days=5)
        end_date = start_date + timedelta(days=10)  # 11 days total

        # Should fail validation
        with self.assertRaises(LeaveServiceError):
            self.leave_service.apply_leave(
                user=self.employee_user,
                leave_type=self.annual_leave,
                start_date=start_date,
                end_date=end_date,
                reason="Too long vacation"
            )

        # Try with exactly the maximum allowed
        end_date = start_date + timedelta(days=9)  # 10 days total

        # Should succeed
        leave_request = self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            reason="Max length vacation"
        )

        self.assertEqual(leave_request.status, 'Pending')

    def test_multiple_half_day_requests(self):
        """Test applying for multiple half-day leaves on same day"""
        # Create a half-day leave in the morning
        start_date = timezone.now().date() + timedelta(days=5)

        morning_leave = self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=start_date,
            half_day=True,
            reason="Morning appointment"
        )

        # Should succeed
        self.assertEqual(morning_leave.status, 'Pending')

        # Try to apply for another half-day on same date
        with self.assertRaises(LeaveServiceError):
            self.leave_service.apply_leave(
                user=self.employee_user,
                leave_type=self.sick_leave,
                start_date=start_date,
                end_date=start_date,
                half_day=True,
                reason="Afternoon appointment"
            )

    def test_negative_leave_duration(self):
        """Test applying for leave with end date before start date"""
        # Invalid date range
        start_date = timezone.now().date() + timedelta(days=10)
        end_date = start_date - timedelta(days=2)  # End before start

        # Should fail validation
        with self.assertRaises(LeaveServiceError):
            self.leave_service.apply_leave(
                user=self.employee_user,
                leave_type=self.annual_leave,
                start_date=start_date,
                end_date=end_date,
                reason="Invalid date range"
            )

    def test_leave_cancellation_after_date_passed(self):
        """Test cancelling leave after it has already started/passed"""
        # Create leave for future
        start_date = timezone.now().date() + timedelta(days=5)
        end_date = start_date + timedelta(days=2)

        leave_request = self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=end_date,
            reason="Future leave"
        )

        # Approve it
        self.leave_service.approve_leave(
            leave_request=leave_request,
            approver=self.manager_user,
            comments="Approved"
        )

        # Time travel: simulate the leave has started
        leave_request.start_date = timezone.now().date() - timedelta(days=1)
        leave_request.save()

        # Try to cancel after it started
        # Should still allow cancellation but with partial balance restoration
        self.leave_service.cancel_leave(
            leave_request=leave_request,
            cancellation_reason="Emergency cancellation",
            cancelled_by=self.employee_user
        )

        # Verify it's cancelled
        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Cancelled')

    def test_decimal_leave_balance(self):
        """Test handling decimal leave balances (half days)"""
        # Set balance to a decimal value
        balance = UserLeaveBalance.objects.get(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year
        )
        balance.used_days = 5.5  # Used 5.5 days
        balance.save()

        # Verify available balance is calculated correctly
        self.assertEqual(balance.available_days, 14.5)  # 20 - 5.5

        # Apply for half day leave
        start_date = timezone.now().date() + timedelta(days=5)

        leave_request = self.leave_service.apply_leave(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=start_date,
            end_date=start_date,
            half_day=True,
            reason="Half day leave"
        )

        # Approve it
        self.leave_service.approve_leave(
            leave_request=leave_request,
            approver=self.manager_user,
            comments="Approved"
        )

        # Verify balance is updated correctly
        balance.refresh_from_db()
        self.assertEqual(balance.used_days, 6.0)  # 5.5 + 0.5
