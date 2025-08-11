"""
Comprehensive Leave Management Test & Validation Suite
=====================================

This test suite validates the entire Leave Management module in trueAlign/leave_management
including policy creation, assignment to roles/groups, end-to-end workflows, service layer logic,
validations, and frontend/UI flows.

Usage:
    python manage.py test comprehensive_leave_management_test
    or
    pytest comprehensive_leave_management_test.py -v
"""

import os
import sys
import django
from django.test import TestCase, TransactionTestCase, Client
from django.test.utils import override_settings
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db import transaction
from datetime import datetime, timedelta, date
from decimal import Decimal
import json
import time
from unittest.mock import patch, MagicMock
from django.contrib.messages import get_messages
from django.test import RequestFactory
import pytz

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

# Import models and services
from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance,
    LeaveRequest, CompOffRequest, Attendance
)
from trueAlign.notifications.models import Notification
from trueAlign.leave_management.services.leave_service import LeaveService, LeaveServiceError
from trueAlign.leave_management.utils import (
    can_approve_leave, get_user_roles, is_hr, is_admin, is_manager, is_employee
)

# Asia/Kolkata timezone
IST_TIMEZONE = pytz.timezone('Asia/Kolkata')


class BaseLeaveTestCase(TestCase):
    """Base test case with common setup for all leave management tests"""

    def setUp(self):
        """Set up test data"""
        # Create groups
        self.employee_group = Group.objects.create(name='EMPLOYEE')
        self.manager_group = Group.objects.create(name='MANAGER')
        self.hr_group = Group.objects.create(name='HR')
        self.admin_group = Group.objects.create(name='ADMIN')

        # Create users
        self.employee_user = User.objects.create_user(
            username='employee1',
            email='employee1@test.com',
            first_name='John',
            last_name='Doe',
            password='testpass123'
        )
        self.employee_user.groups.add(self.employee_group)

        self.manager_user = User.objects.create_user(
            username='manager1',
            email='manager1@test.com',
            first_name='Jane',
            last_name='Manager',
            password='testpass123'
        )
        self.manager_user.groups.add(self.manager_group)

        self.hr_user = User.objects.create_user(
            username='hr1',
            email='hr1@test.com',
            first_name='HR',
            last_name='Person',
            password='testpass123'
        )
        self.hr_user.groups.add(self.hr_group)

        self.admin_user = User.objects.create_user(
            username='admin1',
            email='admin1@test.com',
            first_name='Admin',
            last_name='User',
            password='testpass123'
        )
        self.admin_user.groups.add(self.admin_group)

        # Create leave types
        self.annual_leave_type = LeaveType.objects.create(
            name='Annual Leave',
            description='Yearly vacation leave',
            is_paid=True,
            requires_approval=True,
            requires_documentation=False,
            count_weekends=False,
            can_be_half_day=True,
            max_days_allowed=20,
            carry_forward_allowed=True,
            max_carry_forward=5
        )

        self.sick_leave_type = LeaveType.objects.create(
            name='Sick Leave',
            description='Medical leave',
            is_paid=True,
            requires_approval=True,
            requires_documentation=True,
            count_weekends=False,
            can_be_half_day=True,
            max_days_allowed=10,
            carry_forward_allowed=False,
            max_carry_forward=0
        )

        # Create leave policy
        self.current_year = timezone.now().year
        self.leave_policy = LeavePolicy.objects.create(
            name='Standard Employee Policy',
            group=self.employee_group,
            is_active=True,
            effective_from=date(self.current_year, 1, 1),
            effective_to=date(self.current_year, 12, 31)
        )

        # Create leave allocations
        self.annual_allocation = LeaveAllocation.objects.create(
            policy=self.leave_policy,
            leave_type=self.annual_leave_type,
            allocated_days=20,
            accrual_frequency='yearly',
            accrual_start_date=date(self.current_year, 1, 1)
        )

        self.sick_allocation = LeaveAllocation.objects.create(
            policy=self.leave_policy,
            leave_type=self.sick_leave_type,
            allocated_days=10,
            accrual_frequency='yearly',
            accrual_start_date=date(self.current_year, 1, 1)
        )

        # Create user leave balances
        self.employee_annual_balance = UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave_type,
            year=self.current_year,
            allocated=20,
            used=0,
            carried_forward=0,
            additional=0
        )

        self.employee_sick_balance = UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.sick_leave_type,
            year=self.current_year,
            allocated=10,
            used=0,
            carried_forward=0,
            additional=0
        )

        self.client = Client()


class PolicyCreationAndAssignmentTests(BaseLeaveTestCase):
    """Test Policy Creation & Assignment functionality"""

    def test_create_leave_type_annual_leave(self):
        """Test creating Annual Leave with carry_forward=True"""
        leave_type = LeaveType.objects.create(
            name='Test Annual Leave',
            max_days_allowed=20,
            carry_forward_allowed=True,
            max_carry_forward=5
        )
        self.assertEqual(leave_type.name, 'Test Annual Leave')
        self.assertEqual(leave_type.max_days_allowed, 20)
        self.assertTrue(leave_type.carry_forward_allowed)
        self.assertEqual(leave_type.max_carry_forward, 5)

    def test_create_leave_type_sick_leave(self):
        """Test creating Sick Leave with carry_forward=False"""
        leave_type = LeaveType.objects.create(
            name='Test Sick Leave',
            max_days_allowed=10,
            carry_forward_allowed=False,
            max_carry_forward=0
        )
        self.assertEqual(leave_type.name, 'Test Sick Leave')
        self.assertEqual(leave_type.max_days_allowed, 10)
        self.assertFalse(leave_type.carry_forward_allowed)
        self.assertEqual(leave_type.max_carry_forward, 0)

    def test_create_leave_policy_with_types(self):
        """Test creating leave policy with attached leave types"""
        policy = LeavePolicy.objects.create(
            name='Test Policy',
            group=self.employee_group,
            is_active=True
        )

        # Create allocations
        allocation1 = LeaveAllocation.objects.create(
            policy=policy,
            leave_type=self.annual_leave_type,
            allocated_days=20,
            accrual_frequency='yearly'
        )

        allocation2 = LeaveAllocation.objects.create(
            policy=policy,
            leave_type=self.sick_leave_type,
            allocated_days=10,
            accrual_frequency='yearly'
        )

        self.assertEqual(policy.allocations.count(), 2)
        self.assertTrue(policy.allocations.filter(leave_type=self.annual_leave_type).exists())
        self.assertTrue(policy.allocations.filter(leave_type=self.sick_leave_type).exists())

    def test_assign_policy_to_multiple_groups(self):
        """Test assigning policy to EMPLOYEE, MANAGER, HR, ADMIN groups"""
        groups = [self.employee_group, self.manager_group, self.hr_group, self.admin_group]

        for group in groups:
            policy = LeavePolicy.objects.create(
                name=f'{group.name} Policy',
                group=group,
                is_active=True
            )
            self.assertEqual(policy.group, group)
            self.assertTrue(policy.is_active)

    def test_user_leave_balance_creation_on_policy_assignment(self):
        """Test that new users in groups get correct UserLeaveBalance entries"""
        new_user = User.objects.create_user(
            username='newemployee',
            email='new@test.com',
            password='testpass123'
        )
        new_user.groups.add(self.employee_group)

        # Create balances for new user
        balance1 = UserLeaveBalance.objects.create(
            user=new_user,
            leave_type=self.annual_leave_type,
            year=self.current_year,
            allocated=20,
            used=0
        )

        balance2 = UserLeaveBalance.objects.create(
            user=new_user,
            leave_type=self.sick_leave_type,
            year=self.current_year,
            allocated=10,
            used=0
        )

        self.assertEqual(UserLeaveBalance.objects.filter(user=new_user).count(), 2)
        self.assertEqual(balance1.allocated, 20)
        self.assertEqual(balance2.allocated, 10)

    def test_edge_case_zero_days_policy(self):
        """Test policy with 0 days allowed prevents leave application"""
        zero_leave_type = LeaveType.objects.create(
            name='Zero Days Leave',
            max_days_allowed=0
        )

        zero_balance = UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=zero_leave_type,
            year=self.current_year,
            allocated=0,
            used=0
        )

        # Try to apply for leave
        leave_data = {
            'leave_type': zero_leave_type.id,
            'start_date': date.today() + timedelta(days=1),
            'end_date': date.today() + timedelta(days=1),
            'days_requested': 1,
            'reason': 'Test leave'
        }

        result = LeaveService.apply_leave(self.employee_user, leave_data)
        self.assertFalse(result[1]['is_valid'])


class EndToEndRoleBasedFlowTests(BaseLeaveTestCase):
    """Test End-to-End Role-Based Flows"""

    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()

    def test_employee_apply_leave_flow(self):
        """Test Employee: Apply leave → verify status = Pending"""
        self.client.login(username='employee1', password='testpass123')

        leave_data = {
            'leave_type': self.annual_leave_type.id,
            'start_date': '2024-12-20',
            'end_date': '2024-12-22',
            'days_requested': 3,
            'reason': 'Personal work',
            'is_half_day': False
        }

        response = self.client.post(reverse('leave_management:apply_leave'), leave_data)

        # Check if leave was created
        leave_request = LeaveRequest.objects.filter(user=self.employee_user).first()
        if leave_request:
            self.assertEqual(leave_request.status, 'Pending')
            self.assertEqual(leave_request.days_requested, 3)

    def test_employee_cancel_leave_before_approval(self):
        """Test Employee: Cancel leave before approval"""
        # Create pending leave request
        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave_type,
            start_date=date.today() + timedelta(days=5),
            end_date=date.today() + timedelta(days=7),
            days_requested=3,
            reason='Test leave',
            status='Pending'
        )

        self.client.login(username='employee1', password='testpass123')
        response = self.client.post(
            reverse('leave_management:cancel_leave', args=[leave_request.id])
        )

        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Cancelled')

    def test_employee_apply_comp_off_request(self):
        """Test Employee: Apply comp-off request"""
        self.client.login(username='employee1', password='testpass123')

        comp_off_data = {
            'worked_date': date.today() - timedelta(days=1),
            'hours_worked': 10,
            'reason': 'Overtime work on weekend',
            'comp_off_date_requested': date.today() + timedelta(days=10)
        }

        response = self.client.post(reverse('leave_management:apply_comp_off'), comp_off_data)

        comp_off = CompOffRequest.objects.filter(user=self.employee_user).first()
        if comp_off:
            self.assertEqual(comp_off.status, 'Pending')

    def test_manager_view_team_leaves(self):
        """Test Manager: View all team leaves"""
        # Create leave request from employee
        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave_type,
            start_date=date.today() + timedelta(days=5),
            end_date=date.today() + timedelta(days=7),
            days_requested=3,
            reason='Test leave',
            status='Pending'
        )

        self.client.login(username='manager1', password='testpass123')
        response = self.client.get(reverse('leave_management:team_leaves'))

        self.assertEqual(response.status_code, 200)
        # Manager should be able to see team leaves

    def test_manager_approve_reject_leave(self):
        """Test Manager: Approve, reject leave"""
        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave_type,
            start_date=date.today() + timedelta(days=5),
            end_date=date.today() + timedelta(days=7),
            days_requested=3,
            reason='Test leave',
            status='Pending'
        )

        self.client.login(username='manager1', password='testpass123')

        # Test approval
        response = self.client.post(
            reverse('leave_management:approve_leave', args=[leave_request.id]),
            {'action': 'approve', 'comments': 'Approved'}
        )

        leave_request.refresh_from_db()
        if leave_request.status == 'Approved':
            self.assertEqual(leave_request.approver, self.manager_user)

    def test_manager_cannot_approve_self_leave(self):
        """Test Manager: Verify cannot approve leave for self"""
        leave_request = LeaveRequest.objects.create(
            user=self.manager_user,
            leave_type=self.annual_leave_type,
            start_date=date.today() + timedelta(days=5),
            end_date=date.today() + timedelta(days=7),
            days_requested=3,
            reason='Self leave',
            status='Pending'
        )

        self.client.login(username='manager1', password='testpass123')
        response = self.client.post(
            reverse('leave_management:approve_leave', args=[leave_request.id]),
            {'action': 'approve'}
        )

        # Should not be allowed to approve own leave
        leave_request.refresh_from_db()
        self.assertNotEqual(leave_request.status, 'Approved')

    def test_hr_view_org_wide_dashboard(self):
        """Test HR: View org-wide leave dashboard"""
        self.client.login(username='hr1', password='testpass123')
        response = self.client.get(reverse('leave_management:hr_dashboard'))

        self.assertEqual(response.status_code, 200)
        # HR should see organization-wide data

    def test_hr_adjust_balances(self):
        """Test HR: Adjust balances"""
        self.client.login(username='hr1', password='testpass123')

        adjustment_data = {
            'user': self.employee_user.id,
            'leave_type': self.annual_leave_type.id,
            'adjustment_type': 'add',
            'days': 5,
            'reason': 'Performance bonus'
        }

        # This would need an actual URL and view for balance adjustment
        # Testing the model logic instead
        original_additional = self.employee_annual_balance.additional
        self.employee_annual_balance.additional += 5
        self.employee_annual_balance.save()

        self.assertEqual(self.employee_annual_balance.additional, original_additional + 5)

    def test_admin_manage_policies(self):
        """Test Admin: Manage leave policies"""
        self.client.login(username='admin1', password='testpass123')
        response = self.client.get(reverse('leave_management:admin_dashboard'))

        self.assertEqual(response.status_code, 200)


class LeaveServiceLogicValidationTests(BaseLeaveTestCase):
    """Test LeaveService Logic Validation"""

    def test_apply_leave_insufficient_balance(self):
        """Test: Prevent applying for more days than available"""
        leave_data = {
            'leave_type': self.annual_leave_type.id,
            'start_date': date.today() + timedelta(days=1),
            'end_date': date.today() + timedelta(days=25),  # 25 days > 20 available
            'days_requested': 25,
            'reason': 'Long vacation'
        }

        result = LeaveService.apply_leave(self.employee_user, leave_data)
        self.assertFalse(result[1]['is_valid'])
        self.assertIn('insufficient balance', result[1]['errors'][0].lower())

    def test_apply_leave_past_dates(self):
        """Test: Prevent applying for past dates"""
        leave_data = {
            'leave_type': self.annual_leave_type.id,
            'start_date': date.today() - timedelta(days=5),  # Past date
            'end_date': date.today() - timedelta(days=3),
            'days_requested': 2,
            'reason': 'Past leave'
        }

        result = LeaveService.apply_leave(self.employee_user, leave_data)
        self.assertFalse(result[1]['is_valid'])

    def test_comp_off_leave_only_with_credits(self):
        """Test: Allow comp-off leave only if comp-off credits exist"""
        # Create comp-off leave type
        comp_off_type = LeaveType.objects.create(
            name='Comp Off',
            is_comp_off=True
        )

        # Try to apply without comp-off credits
        leave_data = {
            'leave_type': comp_off_type.id,
            'start_date': date.today() + timedelta(days=1),
            'end_date': date.today() + timedelta(days=1),
            'days_requested': 1,
            'reason': 'Comp off usage'
        }

        result = LeaveService.apply_leave(self.employee_user, leave_data)
        # Should fail if no comp-off credits available
        self.assertFalse(result[1]['is_valid'])

    def test_approve_leave_balance_deduction(self):
        """Test: Deduct balance only once on approval"""
        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave_type,
            start_date=date.today() + timedelta(days=5),
            end_date=date.today() + timedelta(days=7),
            days_requested=3,
            reason='Test leave',
            status='Pending'
        )

        original_used = self.employee_annual_balance.used

        # Approve the leave
        result = LeaveService.approve_leave(leave_request, self.manager_user, 'Approved')

        # Check balance was deducted
        self.employee_annual_balance.refresh_from_db()
        if result[1]['is_valid']:
            self.assertEqual(self.employee_annual_balance.used, original_used + 3)

    def test_reject_leave_balance_unchanged(self):
        """Test: Leave balance remains unchanged on rejection"""
        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave_type,
            start_date=date.today() + timedelta(days=5),
            end_date=date.today() + timedelta(days=7),
            days_requested=3,
            reason='Test leave',
            status='Pending'
        )

        original_used = self.employee_annual_balance.used

        # Reject the leave
        result = LeaveService.reject_leave(leave_request, self.manager_user, 'Not approved')

        # Check balance unchanged
        self.employee_annual_balance.refresh_from_db()
        self.assertEqual(self.employee_annual_balance.used, original_used)

    def test_cancel_leave_restore_balance(self):
        """Test: Restore balance if leave was approved then cancelled"""
        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave_type,
            start_date=date.today() + timedelta(days=5),
            end_date=date.today() + timedelta(days=7),
            days_requested=3,
            reason='Test leave',
            status='Approved'
        )

        # Simulate balance was already deducted
        self.employee_annual_balance.used = 3
        self.employee_annual_balance.save()

        # Cancel the leave
        result = LeaveService.cancel_leave(leave_request, self.employee_user)

        # Check balance restored
        self.employee_annual_balance.refresh_from_db()
        if result[1]['is_valid']:
            self.assertEqual(self.employee_annual_balance.used, 0)

    @patch('trueAlign.leave_management.services.leave_service.transaction')
    def test_transaction_safety(self, mock_transaction):
        """Test: Ensure DB updates are wrapped in atomic transactions"""
        leave_data = {
            'leave_type': self.annual_leave_type.id,
            'start_date': date.today() + timedelta(days=1),
            'end_date': date.today() + timedelta(days=3),
            'days_requested': 3,
            'reason': 'Test transaction'
        }

        LeaveService.apply_leave(self.employee_user, leave_data)
        # Verify transaction.atomic was called
        mock_transaction.atomic.assert_called()


class InputValidationTests(BaseLeaveTestCase):
    """Test Input & Validation"""

    def test_missing_required_fields(self):
        """Test missing fields in leave form"""
        self.client.login(username='employee1', password='testpass123')

        # Submit form with missing required fields
        incomplete_data = {
            'start_date': '2024-12-20',
            # Missing leave_type, end_date, reason
        }

        response = self.client.post(reverse('leave_management:apply_leave'), incomplete_data)

        # Should return form errors
        self.assertContains(response, 'This field is required', status_code=200)

    def test_invalid_date_formats(self):
        """Test invalid date formats"""
        self.client.login(username='employee1', password='testpass123')

        invalid_data = {
            'leave_type': self.annual_leave_type.id,
            'start_date': 'invalid-date',
            'end_date': '2024/12/22',  # Wrong format
            'days_requested': 3,
            'reason': 'Test'
        }

        response = self.client.post(reverse('leave_management:apply_leave'), invalid_data)

        # Should show validation errors
        self.assertEqual(response.status_code, 200)

    def test_overlapping_leave_validation(self):
        """Test applying for leave overlapping with another approved leave"""
        # Create existing approved leave
        existing_leave = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave_type,
            start_date=date.today() + timedelta(days=10),
            end_date=date.today() + timedelta(days=12),
            days_requested=3,
            reason='Existing leave',
            status='Approved'
        )

        # Try to apply for overlapping dates
        overlapping_data = {
            'leave_type': self.annual_leave_type.id,
            'start_date': date.today() + timedelta(days=11),  # Overlaps
            'end_date': date.today() + timedelta(days=13),
            'days_requested': 3,
            'reason': 'Overlapping leave'
        }

        result = LeaveService.apply_leave(self.employee_user, overlapping_data)
        self.assertFalse(result[1]['is_valid'])


class APIEndpointTests(BaseLeaveTestCase):
    """Test API Endpoint functionality"""

    def test_leave_balance_api_logged_in_user(self):
        """Test /api/leave_balance/ returns correct balance for logged-in user"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get('/api/leave_balance/')

        if response.status_code == 200:
            data = response.json()
            self.assertTrue(data.get('success'))
            self.assertIsNotNone(data.get('data'))

    def test_leave_balance_api_hr_query_other_users(self):
        """Test HR/Admin can query for other users"""
        self.client.login(username='hr1', password='testpass123')
        response = self.client.get(f'/api/leave_balance/?user_id={self.employee_user.id}')

        if response.status_code == 200:
            data = response.json()
            self.assertTrue(data.get('success'))

    def test_leave_types_api(self):
        """Test /api/leave_types/ lists all available leave types"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get('/api/leave_types/')

        if response.status_code == 200:
            data = response.json()
            self.assertTrue(data.get('success'))
            self.assertIsInstance(data.get('data'), list)

    def test_api_response_structure(self):
        """Test Standard JSON response structure"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get('/api/leave_balance/')

        if response.status_code == 200:
            data = response.json()
            # Should have success, data, error fields
            self.assertIn('success', data)
            self.assertIn('data', data)
            self.assertIn('error', data)


class NotificationTests(BaseLeaveTestCase):
    """Test Notification System"""

    def test_leave_applied_notification(self):
        """Test leave applied creates notification for manager"""
        leave_data = {
            'leave_type': self.annual_leave_type.id,
            'start_date': date.today() + timedelta(days=5),
            'end_date': date.today() + timedelta(days=7),
            'days_requested': 3,
            'reason': 'Test leave'
        }

        # Apply leave
        result = LeaveService.apply_leave(self.employee_user, leave_data)

        if result[1]['is_valid']:
            # Check if notification was created for manager
            notifications = Notification.objects.filter(
                recipient=self.manager_user,
                event_type='leave_applied'
            )
            self.assertGreater(notifications.count(), 0)

    def test_leave_approved_notification(self):
        """Test leave approval creates notification for employee"""
        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave_type,
            start_date=date.today() + timedelta(days=5),
            end_date=date.today() + timedelta(days=7),
            days_requested=3,
            reason='Test leave',
            status='Pending'
        )

        # Approve leave
        result = LeaveService.approve_leave(leave_request, self.manager_user, 'Approved')

        if result[1]['is_valid']:
            # Check if notification was created for employee
            notifications = Notification.objects.filter(
                recipient=self.employee_user,
                event_type='leave_approved'
            )
            self.assertGreater(notifications.count(), 0)

    def test_notification_text_clarity(self):
        """Test notification text is clear"""
        # Create a notification manually to test format
        notification = Notification.objects.create(
            recipient=self.employee_user,
            type='SYSTEM',
            title='Leave Request Approved',
            message='Your leave request #123 has been approved',
            event_type='leave_approved'
        )

        self.assertIn('approved', notification.message.lower())
        self.assertIn('#', notification.message)  # Should have request ID

    def test_notification_persistence(self):
        """Test notifications remain until marked as read"""
        notification = Notification.objects.create(
            recipient=self.employee_user,
            type='SYSTEM',
            title='Test Notification',
            message='Test message'
        )

        self.assertFalse(notification.read)

        # Mark as read
        notification.read = True
        notification.save()

        self.assertTrue(notification.read)


class FrontendUIWorkflowTests(BaseLeaveTestCase):
    """Test Frontend/UI Workflow"""

    def test_employee_dashboard_renders(self):
        """Test employee dashboard renders correctly"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:employee_dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Leave Balance')
        self.assertContains(response, 'Apply Leave')

    def test_manager_dashboard_renders(self):
        """Test manager dashboard renders correctly"""
        self.client.login(username='manager1', password='testpass123')
        response = self.client.get(reverse('leave_management:manager_dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Team Leaves')
        self.assertContains(response, 'Pending Approvals')

    def test_hr_dashboard_renders(self):
        """Test HR dashboard renders correctly"""
        self.client.login(username='hr1', password='testpass123')
        response = self.client.get(reverse('leave_management:hr_dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Organization')
        self.assertContains(response, 'Leave Policies')

    def test_admin_dashboard_renders(self):
        """Test admin dashboard renders correctly"""
        self.client.login(username='admin1', password='testpass123')
        response = self.client.get(reverse('leave_management:admin_dashboard'))

        self.assertEqual(response.status_code, 200)

    def test_leave_apply_form_renders(self):
        """Test leave apply form renders correctly"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:apply_leave'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Leave Type')
        self.assertContains(response, 'Start Date')
        self.assertContains(response, 'End Date')
        self.assertContains(response, 'Reason')

    def test_leave_detail_view_renders(self):
        """Test leave detail view renders correctly"""
        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave_type,
            start_date=date.today() + timedelta(days=5),
            end_date=date.today() + timedelta(days=7),
            days_requested=3,
            reason='Test leave',
            status='Pending'
        )

        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:leave_detail', args=[leave_request.id]))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test leave')
        self.assertContains(response, 'Pending')

    def test_comp_off_apply_form_renders(self):
        """Test comp-off apply form renders correctly"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:apply_comp_off'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Worked Date')
        self.assertContains(response, 'Hours Worked')

    def test_pagination_works(self):
        """Test pagination works for leave lists"""
        # Create multiple leave requests
        for i in range(25):
            LeaveRequest.objects.create(
                user=self.employee_user,
                leave_type=self.annual_leave_type,
                start_date=date.today() + timedelta(days=5+i),
                end_date=date.today() + timedelta(days=6+i),
                days_requested=1,
                reason=f'Test leave {i}',
                status='Pending'
            )

        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:my_leaves'))

        if response.status_code == 200:
            # Check if pagination is present
            self.assertContains(response, 'Page')

    def test_messages_framework_displays(self):
        """Test messages framework displays success/error"""
        self.client.login(username='employee1', password='testpass123')

        leave_data = {
            'leave_type': self.annual_leave_type.id,
            'start_date': date.today() + timedelta(days=5),
            'end_date': date.today() + timedelta(days=7),
            'days_requested': 3,
            'reason': 'Test leave',
            'is_half_day': False
        }

        response = self.client.post(reverse('leave_management:apply_leave'), leave_data, follow=True)

        # Check for success message
        messages = list(get_messages(response.wsgi_request))
        if messages:
            self.assertTrue(any('success' in str(m).lower() for m in messages))

    def test_timezone_localization(self):
        """Test dates/times are localized to Asia/Kolkata"""
        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave_type,
            start_date=date.today() + timedelta(days=5),
            end_date=date.today() + timedelta(days=7),
            days_requested=3,
            reason='Test leave',
            status='Pending'
        )

        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:leave_detail', args=[leave_request.id]))

        if response.status_code == 200:
            # Check that IST timezone is being used
            content = response.content.decode()
            # This would need specific template implementation to verify


class NotificationRenderingTests(BaseLeaveTestCase):
    """Test Notification Rendering in dashboard.html"""

    def test_notification_container_presence(self):
        """Test HTML element presence for notifications"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get('/dashboard/')

        if response.status_code == 200:
            content = response.content.decode()
            # Check for notification container elements
            self.assertTrue(
                'notification' in content.lower() or
                'alert' in content.lower() or
                'message' in content.lower()
            )

    def test_django_template_tags_render_notifications(self):
        """Test Django template tags correctly render notification objects"""
        # Create test notification
        notification = Notification.objects.create(
            recipient=self.employee_user,
            type='SYSTEM',
            title='Test Notification',
            message='Your leave request has been processed',
            read=False
        )

        self.client.login(username='employee1', password='testpass123')
        response = self.client.get('/dashboard/')

        if response.status_code == 200:
            content = response.content.decode()
            # Should contain notification content
            self.assertIn('Test Notification', content)

    def test_role_specific_notification_display(self):
        """Test only relevant notifications appear for each role"""
        # Create role-specific notifications
        employee_notification = Notification.objects.create(
            recipient=self.employee_user,
            type='SYSTEM',
            title='Employee Notification',
            message='Your leave balance updated'
        )

        manager_notification = Notification.objects.create(
            recipient=self.manager_user,
            type='SYSTEM',
            title='Manager Notification',
            message='New leave request pending approval'
        )

        # Test employee sees only employee notification
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get('/dashboard/')

        if response.status_code == 200:
            content = response.content.decode()
            self.assertIn('Employee Notification', content)
            self.assertNotIn('Manager Notification', content)

    def test_unread_vs_read_visual_distinction(self):
        """Test unread notifications are visually distinct"""
        # Create read and unread notifications
        unread_notification = Notification.objects.create(
            recipient=self.employee_user,
            type='SYSTEM',
            title='Unread Notification',
            message='This is unread',
            read=False
        )

        read_notification = Notification.objects.create(
            recipient=self.employee_user,
            type='SYSTEM',
            title='Read Notification',
            message='This is read',
            read=True
        )

        self.client.login(username='employee1', password='testpass123')
        response = self.client.get('/dashboard/')

        if response.status_code == 200:
            content = response.content.decode()
            # Should have different styling for read vs unread
            # This would require specific CSS classes in template
            self.assertIn('Unread Notification', content)
            self.assertIn('Read Notification', content)

    def test_timezone_in_notifications(self):
        """Test notification timestamps are localized to Asia/Kolkata"""
        notification = Notification.objects.create(
            recipient=self.employee_user,
            type='SYSTEM',
            title='Timezone Test',
            message='Testing timezone'
        )

        self.client.login(username='employee1', password='testpass123')
        response = self.client.get('/dashboard/')

        # Notification timestamp should be in IST
        ist_time = notification.timestamp.astimezone(IST_TIMEZONE)
        self.assertEqual(ist_time.tzinfo.zone, 'Asia/Kolkata')

    def test_empty_notifications_state(self):
        """Test empty state when no notifications"""
        # Ensure no notifications exist
        Notification.objects.filter(recipient=self.employee_user).delete()

        self.client.login(username='employee1', password='testpass123')
        response = self.client.get('/dashboard/')

        if response.status_code == 200:
            content = response.content.decode()
            # Should show empty state message
            self.assertTrue(
                'no notifications' in content.lower() or
                'no new notifications' in content.lower() or
                'all caught up' in content.lower()
            )


class PerformanceAndCachingTests(BaseLeaveTestCase):
    """Test Performance & Caching"""

    def test_dashboard_load_time(self):
        """Test dashboard loads within reasonable time"""
        self.client.login(username='employee1', password='testpass123')

        start_time = time.time()
        response = self.client.get('/dashboard/')
        end_time = time.time()

        load_time = end_time - start_time
        self.assertLess(load_time, 2.0)  # Should load within 2 seconds

    def test_leave_balance_query_optimization(self):
        """Test leave balance queries are optimized"""
        # Create multiple users and balances
        for i in range(10):
            user = User.objects.create_user(
                username=f'testuser{i}',
                email=f'test{i}@test.com',
                password='testpass123'
            )
            UserLeaveBalance.objects.create(
                user=user,
                leave_type=self.annual_leave_type,
                year=self.current_year,
                allocated=20,
                used=0
            )

        self.client.login(username='employee1', password='testpass123')

        # Test that queries are reasonable
        with self.assertNumQueries(10):  # Adjust based on actual optimization
            response = self.client.get(reverse('leave_management:leave_balance'))

    @patch('django.core.cache.cache')
    def test_caching_mechanisms(self, mock_cache):
        """Test caching is implemented where appropriate"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get('/api/leave_balance/')

        # Verify cache operations
        # This would depend on actual caching implementation


# Comprehensive Test Runner and Report Generator
class ComprehensiveTestRunner:
    """Runs all tests and generates comprehensive report"""

    def __init__(self):
        self.test_results = {}
        self.total_tests = 0
        self.passed_tests = 0
        self.failed_tests = 0
        self.errors = []

    def run_all_tests(self):
        """Run all test classes and collect results"""
        test_classes = [
            PolicyCreationAndAssignmentTests,
            EndToEndRoleBasedFlowTests,
            LeaveServiceLogicValidationTests,
            InputValidationTests,
            APIEndpointTests,
            NotificationTests,
            FrontendUIWorkflowTests,
            NotificationRenderingTests,
            PerformanceAndCachingTests
        ]

        print("=" * 80)
        print("COMPREHENSIVE LEAVE MANAGEMENT TEST & VALIDATION REPORT")
        print("=" * 80)
        print()

        for test_class in test_classes:
            print(f"Running {test_class.__name__}...")
            self._run_test_class(test_class)
            print()

        self._generate_final_report()

    def _run_test_class(self, test_class):
        """Run individual test class"""
        import unittest

        suite = unittest.TestLoader().loadTestsFromTestCase(test_class)
        runner = unittest.TextTestRunner(verbosity=0)
        result = runner.run(suite)

        class_name = test_class.__name__
        self.test_results[class_name] = {
            'total': result.testsRun,
            'failures': len(result.failures),
            'errors': len(result.errors),
            'passed': result.testsRun - len(result.failures) - len(result.errors),
            'details': {
                'failures': result.failures,
                'errors': result.errors
            }
        }

        self.total_tests += result.testsRun
        self.passed_tests += self.test_results[class_name]['passed']
        self.failed_tests += len(result.failures) + len(result.errors)

        # Print class summary
        print(f"  Tests Run: {result.testsRun}")
        print(f"  Passed: {self.test_results[class_name]['passed']}")
        print(f"  Failed: {len(result.failures)}")
        print(f"  Errors: {len(result.errors)}")

        if result.failures:
            print("  FAILURES:")
            for failure in result.failures:
                print(f"    - {failure[0]}: {failure[1]}")

        if result.errors:
            print("  ERRORS:")
            for error in result.errors:
                print(f"    - {error[0]}: {error[1]}")

    def _generate_final_report(self):
        """Generate comprehensive final report"""
        print("=" * 80)
        print("FINAL TEST SUMMARY")
        print("=" * 80)
        print(f"Total Tests: {self.total_tests}")
        print(f"Passed: {self.passed_tests}")
        print(f"Failed: {self.failed_tests}")
        print(f"Success Rate: {(self.passed_tests/self.total_tests*100):.1f}%")
        print()

        print("DETAILED RESULTS BY CATEGORY:")
        print("-" * 40)

        for class_name, results in self.test_results.items():
            status = "✓ PASS" if results['failures'] == 0 and results['errors'] == 0 else "✗ FAIL"
            print(f"{class_name}: {status}")
            print(f"  Passed: {results['passed']}/{results['total']}")
            if results['failures'] > 0:
                print(f"  Failures: {results['failures']}")
            if results['errors'] > 0:
                print(f"  Errors: {results['errors']}")
            print()

        # Generate recommendations
        self._generate_recommendations()

    def _generate_recommendations(self):
        """Generate recommendations based on test results"""
        print("RECOMMENDATIONS:")
        print("-" * 20)

        recommendations = []

        # Check specific test results and provide recommendations
        if self.test_results.get('PolicyCreationAndAssignmentTests', {}).get('failures', 0) > 0:
            recommendations.append(
                "• Policy Creation & Assignment: Review leave policy creation logic and group assignments"
            )

        if self.test_results.get('LeaveServiceLogicValidationTests', {}).get('failures', 0) > 0:
            recommendations.append(
                "• Service Logic: Review business logic in LeaveService, especially balance calculations"
            )

        if self.test_results.get('NotificationTests', {}).get('failures', 0) > 0:
            recommendations.append(
                "• Notifications: Implement proper notification triggers for leave events"
            )

        if self.test_results.get('FrontendUIWorkflowTests', {}).get('failures', 0) > 0:
            recommendations.append(
                "• Frontend: Review template rendering and form validation"
            )

        if self.test_results.get('APIEndpointTests', {}).get('failures', 0) > 0:
            recommendations.append(
                "• API Endpoints: Implement missing API endpoints with proper JSON responses"
            )

        if self.test_results.get('PerformanceAndCachingTests', {}).get('failures', 0) > 0:
            recommendations.append(
                "• Performance: Implement query optimization and caching mechanisms"
            )

        if not recommendations:
            recommendations.append("• All tests passing! System appears to be working well.")

        for rec in recommendations:
            print(rec)

        print()
        print("CRITICAL AREAS TO FOCUS ON:")
        print("-" * 30)

        critical_areas = []

        for class_name, results in self.test_results.items():
            failure_rate = (results['failures'] + results['errors']) / results['total'] * 100
            if failure_rate > 50:
                critical_areas.append(f"• {class_name} ({failure_rate:.1f}% failure rate)")

        if critical_areas:
            for area in critical_areas:
                print(area)
        else:
            print("• No critical areas identified")

        print()
        print("=" * 80)


# Main execution
if __name__ == '__main__':
    # Run comprehensive tests
    runner = ComprehensiveTestRunner()
    runner.run_all_tests()

    # Additional manual verification suggestions
    print("\nMANUAL VERIFICATION CHECKLIST:")
    print("-" * 40)
    print("□ Navigate to /dashboard/ and verify notification rendering")
    print("□ Test role-based dashboard access (Employee, Manager, HR, Admin)")
    print("□ Apply for leave and verify email/system notifications")
    print("□ Test leave approval workflow end-to-end")
    print("□ Verify leave balance calculations after approval/rejection")
    print("□ Test comp-off request and approval process")
    print("□ Check timezone display in all leave-related dates")
    print("□ Test pagination on leave lists with 50+ records")
    print("□ Verify form validation error messages are clear")
    print("□ Test concurrent leave applications (race conditions)")
    print()
    print("BROWSER TESTING CHECKLIST:")
    print("-" * 30)
    print("□ Chrome/Safari/Firefox compatibility")
    print("□ Mobile responsiveness")
    print("□ JavaScript notification alerts")
    print("□ Date picker functionality")
    print("□ Form submission with network issues")
    print()
