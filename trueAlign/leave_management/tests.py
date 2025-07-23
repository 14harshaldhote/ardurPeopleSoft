"""
Comprehensive Test Suite for Leave Management System
Tests all core functionality including applications, approvals, balances, and permissions
"""
from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.utils import timezone
from django.core.exceptions import ValidationError
from datetime import datetime, timedelta
from decimal import Decimal
import json

from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance,
    LeaveRequest, CompOffRequest
)
from trueAlign.leave_management.services.leave_service import LeaveService, LeaveServiceError
from trueAlign.leave_management.utils import (
    can_approve_leave, get_potential_approvers, is_employee, is_manager, is_hr, is_admin
)


class LeaveManagementTestCase(TestCase):
    """Base test case with common setup for leave management tests"""

    def setUp(self):
        """Set up test data"""
        # Create groups/roles
        self.employee_group = Group.objects.create(name='Employee')
        self.manager_group = Group.objects.create(name='Manager')
        self.hr_group = Group.objects.create(name='HR')
        self.admin_group = Group.objects.create(name='Admin')

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
            first_name='Bob',
            last_name='HR'
        )
        self.hr_user.groups.add(self.hr_group)

        self.admin_user = User.objects.create_user(
            username='admin1',
            email='admin1@test.com',
            password='testpass123',
            first_name='Alice',
            last_name='Admin'
        )
        self.admin_user.groups.add(self.admin_group)

        # Create leave types
        self.annual_leave = LeaveType.objects.create(
            name='Annual Leave',
            description='Annual vacation leave',
            is_paid=True,
            requires_approval=True,
            requires_documentation=False,
            count_weekends=False,
            can_be_half_day=True,
            is_active=True
        )

        self.sick_leave = LeaveType.objects.create(
            name='Sick Leave',
            description='Medical leave',
            is_paid=True,
            requires_approval=True,
            requires_documentation=True,
            count_weekends=False,
            can_be_half_day=True,
            is_active=True
        )

        self.loss_of_pay = LeaveType.objects.create(
            name='Loss of Pay',
            description='Unpaid leave',
            is_paid=False,
            requires_approval=True,
            requires_documentation=False,
            count_weekends=False,
            can_be_half_day=True,
            is_active=True
        )

        self.comp_off_type = LeaveType.objects.create(
            name='Comp Off',
            description='Compensation off',
            is_paid=True,
            requires_approval=True,
            requires_documentation=False,
            count_weekends=False,
            can_be_half_day=True,
            is_active=True
        )

        # Create leave policy
        self.employee_policy = LeavePolicy.objects.create(
            name='Employee Policy',
            group=self.employee_group,
            is_active=True
        )

        # Create leave allocations
        self.annual_allocation = LeaveAllocation.objects.create(
            policy=self.employee_policy,
            leave_type=self.annual_leave,
            annual_days=Decimal('20.0'),
            carry_forward_limit=Decimal('5.0'),
            max_consecutive_days=10,
            advance_notice_days=3
        )

        self.sick_allocation = LeaveAllocation.objects.create(
            policy=self.employee_policy,
            leave_type=self.sick_leave,
            annual_days=Decimal('10.0'),
            carry_forward_limit=Decimal('0.0'),
            max_consecutive_days=5,
            advance_notice_days=0
        )

        # Create user leave balances
        self.employee_annual_balance = UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            year=timezone.now().year,
            allocated=Decimal('20.0'),
            used=Decimal('5.0'),
            carried_forward=Decimal('2.0'),
            additional=Decimal('0.0')
        )

        self.employee_sick_balance = UserLeaveBalance.objects.create(
            user=self.employee_user,
            leave_type=self.sick_leave,
            year=timezone.now().year,
            allocated=Decimal('10.0'),
            used=Decimal('1.0'),
            carried_forward=Decimal('0.0'),
            additional=Decimal('0.0')
        )

        self.client = Client()


class LeaveModelTests(LeaveManagementTestCase):
    """Test leave-related models"""

    def test_leave_type_creation(self):
        """Test leave type model creation"""
        self.assertEqual(str(self.annual_leave), 'Annual Leave')
        self.assertTrue(self.annual_leave.is_paid)
        self.assertTrue(self.annual_leave.can_be_half_day)

    def test_leave_policy_creation(self):
        """Test leave policy model creation"""
        self.assertEqual(str(self.employee_policy), 'Employee Policy for Employee')
        self.assertTrue(self.employee_policy.is_active)

    def test_leave_allocation_creation(self):
        """Test leave allocation model creation"""
        self.assertEqual(self.annual_allocation.annual_days, Decimal('20.0'))
        self.assertEqual(self.annual_allocation.max_consecutive_days, 10)

    def test_user_leave_balance_available_property(self):
        """Test UserLeaveBalance available property calculation"""
        # Available = allocated + carried_forward + additional - used
        # 20.0 + 2.0 + 0.0 - 5.0 = 17.0
        self.assertEqual(self.employee_annual_balance.available, Decimal('17.0'))

    def test_leave_request_calculate_days(self):
        """Test leave request day calculation"""
        # Create a leave request
        tomorrow = timezone.now().date() + timedelta(days=1)
        day_after = tomorrow + timedelta(days=2)  # 3 days total

        leave_request = LeaveRequest(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=tomorrow,
            end_date=day_after,
            half_day=False,
            reason='Test leave'
        )

        # Should be 3 days (excluding weekends if they fall in range)
        days = leave_request.calculate_leave_days()
        self.assertGreaterEqual(days, 1)  # At least 1 day
        self.assertLessEqual(days, 3)     # At most 3 days

    def test_leave_request_half_day_calculation(self):
        """Test half-day leave calculation"""
        tomorrow = timezone.now().date() + timedelta(days=1)

        leave_request = LeaveRequest(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=tomorrow,
            end_date=tomorrow,
            half_day=True,
            reason='Half day test'
        )

        days = leave_request.calculate_leave_days()
        self.assertEqual(days, 0.5)


class LeaveValidationTests(LeaveManagementTestCase):
    """Test leave request validation"""

    def test_leave_request_validation_success(self):
        """Test successful leave request validation"""
        tomorrow = timezone.now().date() + timedelta(days=5)  # Future date with advance notice

        leave_request = LeaveRequest(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=tomorrow,
            end_date=tomorrow,
            half_day=False,
            reason='Valid leave request',
            is_retroactive=False
        )

        # Should not raise ValidationError
        try:
            leave_request.clean()
        except ValidationError:
            self.fail("Valid leave request raised ValidationError")

    def test_invalid_date_range(self):
        """Test validation fails for invalid date range"""
        tomorrow = timezone.now().date() + timedelta(days=1)
        yesterday = tomorrow - timedelta(days=2)

        leave_request = LeaveRequest(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=tomorrow,
            end_date=yesterday,  # End before start
            reason='Invalid date range'
        )

        with self.assertRaises(ValidationError):
            leave_request.clean()

    def test_half_day_not_allowed(self):
        """Test validation fails when half-day not allowed"""
        # Create leave type that doesn't allow half day
        no_half_day_type = LeaveType.objects.create(
            name='No Half Day',
            can_be_half_day=False,
            is_active=True
        )

        tomorrow = timezone.now().date() + timedelta(days=1)

        leave_request = LeaveRequest(
            user=self.employee_user,
            leave_type=no_half_day_type,
            start_date=tomorrow,
            end_date=tomorrow,
            half_day=True,
            reason='Half day test'
        )

        with self.assertRaises(ValidationError):
            leave_request.clean()

    def test_insufficient_balance_validation(self):
        """Test validation fails for insufficient balance"""
        tomorrow = timezone.now().date() + timedelta(days=5)

        # Create leave request for more days than available
        leave_request = LeaveRequest(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=tomorrow,
            end_date=tomorrow + timedelta(days=20),  # More than available balance
            reason='Too many days'
        )

        leave_request.leave_days = leave_request.calculate_leave_days()

        with self.assertRaises(ValidationError):
            leave_request.clean()

    def test_advance_notice_requirement(self):
        """Test advance notice validation"""
        tomorrow = timezone.now().date() + timedelta(days=1)  # Less than 3 days notice

        leave_request = LeaveRequest(
            user=self.employee_user,
            leave_type=self.annual_leave,  # Requires 3 days advance notice
            start_date=tomorrow,
            end_date=tomorrow,
            reason='Short notice',
            is_retroactive=False
        )

        with self.assertRaises(ValidationError):
            leave_request.clean()


class LeaveServiceTests(LeaveManagementTestCase):
    """Test leave service layer"""

    def test_apply_leave_success(self):
        """Test successful leave application"""
        tomorrow = timezone.now().date() + timedelta(days=5)

        leave_data = {
            'leave_type': self.annual_leave.id,
            'start_date': tomorrow,
            'end_date': tomorrow,
            'half_day': False,
            'reason': 'Service test leave',
            'is_retroactive': False
        }

        leave_request, result = LeaveService.apply_leave(self.employee_user, leave_data)

        self.assertTrue(result['is_valid'])
        self.assertIsNotNone(leave_request.id)
        self.assertEqual(leave_request.status, 'Pending')

    def test_apply_leave_insufficient_balance(self):
        """Test leave application with insufficient balance"""
        tomorrow = timezone.now().date() + timedelta(days=5)

        leave_data = {
            'leave_type': self.annual_leave.id,
            'start_date': tomorrow,
            'end_date': tomorrow + timedelta(days=20),  # More than available
            'half_day': False,
            'reason': 'Too many days',
            'is_retroactive': False
        }

        leave_request, result = LeaveService.apply_leave(self.employee_user, leave_data)

        self.assertFalse(result['is_valid'])
        self.assertIn('Insufficient', ' '.join(result.get('errors', [])))

    def test_approve_leave_success(self):
        """Test successful leave approval"""
        # Create a pending leave request
        tomorrow = timezone.now().date() + timedelta(days=5)

        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=tomorrow,
            end_date=tomorrow,
            half_day=False,
            reason='Test approval',
            status='Pending'
        )

        result = LeaveService.approve_leave(leave_request, self.manager_user)

        self.assertTrue(result['success'])
        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Approved')
        self.assertEqual(leave_request.approver, self.manager_user)

    def test_reject_leave_success(self):
        """Test successful leave rejection"""
        tomorrow = timezone.now().date() + timedelta(days=5)

        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=tomorrow,
            end_date=tomorrow,
            half_day=False,
            reason='Test rejection',
            status='Pending'
        )

        result = LeaveService.reject_leave(leave_request, self.manager_user, 'Not needed')

        self.assertTrue(result['success'])
        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Rejected')
        self.assertEqual(leave_request.rejection_reason, 'Not needed')

    def test_cancel_leave_success(self):
        """Test successful leave cancellation"""
        tomorrow = timezone.now().date() + timedelta(days=5)

        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=tomorrow,
            end_date=tomorrow,
            half_day=False,
            reason='Test cancellation',
            status='Pending'
        )

        result = LeaveService.cancel_leave(leave_request, self.employee_user, 'Changed mind')

        self.assertTrue(result['success'])
        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Cancelled')

    def test_get_leave_balance(self):
        """Test getting user leave balance"""
        result = LeaveService.get_user_leave_balance(self.employee_user)

        self.assertTrue(result['success'])
        self.assertEqual(len(result['balances']), 2)  # Annual and sick leave

        annual_balance = next(b for b in result['balances'] if b['leave_type'] == 'Annual Leave')
        self.assertEqual(annual_balance['available'], 17.0)  # 20 + 2 - 5

    def test_allocate_leaves_to_user(self):
        """Test leave allocation to user"""
        new_user = User.objects.create_user(
            username='newemployee',
            email='new@test.com',
            password='testpass123'
        )
        new_user.groups.add(self.employee_group)

        result = LeaveService.allocate_leaves_to_user(new_user, {})

        self.assertTrue(result['success'])

        # Check if balances were created
        balances = UserLeaveBalance.objects.filter(user=new_user)
        self.assertEqual(balances.count(), 2)  # Annual and sick leave


class LeavePermissionTests(LeaveManagementTestCase):
    """Test role-based permissions"""

    def test_employee_role_check(self):
        """Test employee role identification"""
        self.assertTrue(is_employee(self.employee_user))
        self.assertFalse(is_manager(self.employee_user))
        self.assertFalse(is_hr(self.employee_user))
        self.assertFalse(is_admin(self.employee_user))

    def test_manager_role_check(self):
        """Test manager role identification"""
        self.assertTrue(is_manager(self.manager_user))
        self.assertFalse(is_employee(self.manager_user))
        self.assertFalse(is_hr(self.manager_user))
        self.assertFalse(is_admin(self.manager_user))

    def test_hr_role_check(self):
        """Test HR role identification"""
        self.assertTrue(is_hr(self.hr_user))
        self.assertFalse(is_employee(self.hr_user))
        self.assertFalse(is_manager(self.hr_user))
        self.assertFalse(is_admin(self.hr_user))

    def test_admin_role_check(self):
        """Test admin role identification"""
        self.assertTrue(is_admin(self.admin_user))
        self.assertFalse(is_employee(self.admin_user))
        self.assertFalse(is_manager(self.admin_user))
        self.assertFalse(is_hr(self.admin_user))

    def test_manager_can_approve_employee_leave(self):
        """Test manager can approve employee leave"""
        self.assertTrue(can_approve_leave(self.manager_user, self.employee_user))

    def test_hr_can_approve_employee_leave(self):
        """Test HR can approve employee leave"""
        self.assertTrue(can_approve_leave(self.hr_user, self.employee_user))

    def test_hr_can_approve_manager_leave(self):
        """Test HR can approve manager leave"""
        self.assertTrue(can_approve_leave(self.hr_user, self.manager_user))

    def test_admin_can_approve_hr_leave(self):
        """Test admin can approve HR leave"""
        self.assertTrue(can_approve_leave(self.admin_user, self.hr_user))

    def test_employee_cannot_approve_leave(self):
        """Test employee cannot approve any leave"""
        self.assertFalse(can_approve_leave(self.employee_user, self.manager_user))
        self.assertFalse(can_approve_leave(self.employee_user, self.employee_user))

    def test_get_potential_approvers(self):
        """Test getting potential approvers"""
        approvers = get_potential_approvers(self.employee_user)

        # Employee can be approved by manager, HR, or admin
        approver_ids = [a.id for a in approvers]
        self.assertIn(self.manager_user.id, approver_ids)
        self.assertIn(self.hr_user.id, approver_ids)
        self.assertIn(self.admin_user.id, approver_ids)


class LeaveViewTests(LeaveManagementTestCase):
    """Test leave management views"""

    def test_employee_dashboard_access(self):
        """Test employee can access their dashboard"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:employee_dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_apply_leave_get(self):
        """Test leave application form display"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:apply_leave'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Apply for Leave')

    def test_apply_leave_post_success(self):
        """Test successful leave application submission"""
        self.client.login(username='employee1', password='testpass123')

        tomorrow = timezone.now().date() + timedelta(days=5)

        response = self.client.post(reverse('leave_management:apply_leave'), {
            'leave_type': self.annual_leave.id,
            'start_date': tomorrow.strftime('%Y-%m-%d'),
            'end_date': tomorrow.strftime('%Y-%m-%d'),
            'half_day': False,
            'reason': 'Test leave application',
            'is_retroactive': False
        })

        # Should redirect on success
        self.assertEqual(response.status_code, 302)

        # Check leave request was created
        self.assertTrue(
            LeaveRequest.objects.filter(
                user=self.employee_user,
                reason='Test leave application'
            ).exists()
        )

    def test_my_leaves_view(self):
        """Test my leaves view"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:my_leaves'))
        self.assertEqual(response.status_code, 200)

    def test_leave_detail_view(self):
        """Test leave detail view"""
        tomorrow = timezone.now().date() + timedelta(days=5)

        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=tomorrow,
            end_date=tomorrow,
            reason='Test detail view',
            status='Pending'
        )

        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(
            reverse('leave_management:leave_detail', args=[leave_request.id])
        )
        self.assertEqual(response.status_code, 200)

    def test_team_leaves_manager_access(self):
        """Test manager can access team leaves"""
        self.client.login(username='manager1', password='testpass123')
        response = self.client.get(reverse('leave_management:team_leaves'))
        self.assertEqual(response.status_code, 200)

    def test_team_leaves_employee_no_access(self):
        """Test employee cannot access team leaves"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:team_leaves'))
        self.assertEqual(response.status_code, 403)  # Should be forbidden

    def test_leave_balance_view(self):
        """Test leave balance view"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:leave_balance'))
        self.assertEqual(response.status_code, 200)


class LeaveAPITests(LeaveManagementTestCase):
    """Test leave management API endpoints"""

    def test_api_leave_balance(self):
        """Test leave balance API endpoint"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:api_leave_balance'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertTrue(data['success'])
        self.assertEqual(len(data['balances']), 2)

    def test_api_leave_types(self):
        """Test leave types API endpoint"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:api_leave_types'))
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertIn('leave_types', data)
        self.assertGreaterEqual(len(data['leave_types']), 3)


class CompOffTests(LeaveManagementTestCase):
    """Test comp-off functionality"""

    def test_apply_comp_off(self):
        """Test comp-off application"""
        self.client.login(username='employee1', password='testpass123')

        worked_date = timezone.now().date() - timedelta(days=5)

        response = self.client.post(reverse('leave_management:apply_comp_off'), {
            'worked_date': worked_date.strftime('%Y-%m-%d'),
            'reason': 'Weekend work',
            'hours_worked': '8.0'
        })

        self.assertEqual(response.status_code, 302)  # Redirect on success

        # Check comp-off request was created
        self.assertTrue(
            CompOffRequest.objects.filter(
                user=self.employee_user,
                reason='Weekend work'
            ).exists()
        )

    def test_my_comp_off_view(self):
        """Test my comp-off requests view"""
        self.client.login(username='employee1', password='testpass123')
        response = self.client.get(reverse('leave_management:my_comp_off'))
        self.assertEqual(response.status_code, 200)


class LeaveIntegrationTests(LeaveManagementTestCase):
    """Integration tests for complete leave workflows"""

    def test_complete_leave_workflow(self):
        """Test complete leave application to approval workflow"""
        # 1. Employee applies for leave
        self.client.login(username='employee1', password='testpass123')

        tomorrow = timezone.now().date() + timedelta(days=5)

        response = self.client.post(reverse('leave_management:apply_leave'), {
            'leave_type': self.annual_leave.id,
            'start_date': tomorrow.strftime('%Y-%m-%d'),
            'end_date': tomorrow.strftime('%Y-%m-%d'),
            'half_day': False,
            'reason': 'Integration test leave',
            'is_retroactive': False
        })

        self.assertEqual(response.status_code, 302)

        # Get the created leave request
        leave_request = LeaveRequest.objects.get(reason='Integration test leave')
        self.assertEqual(leave_request.status, 'Pending')

        # 2. Manager approves the leave
        self.client.login(username='manager1', password='testpass123')

        response = self.client.post(
            reverse('leave_management:approve_leave', args=[leave_request.id])
        )

        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Approved')
        self.assertEqual(leave_request.approver, self.manager_user)

        # 3. Check balance was updated
        self.employee_annual_balance.refresh_from_db()
        self.assertEqual(self.employee_annual_balance.used, Decimal('6.0'))  # Was 5.0, now 6.0

    def test_leave_cancellation_workflow(self):
        """Test leave cancellation workflow"""
        # Create approved leave
        tomorrow = timezone.now().date() + timedelta(days=5)

        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=tomorrow,
            end_date=tomorrow,
            reason='To be cancelled',
            status='Approved',
            approver=self.manager_user,
            leave_days=Decimal('1.0')
        )

        # Update balance to reflect approval
        self.employee_annual_balance.used += Decimal('1.0')
        self.employee_annual_balance.save()

        original_used = self.employee_annual_balance.used

        # Employee cancels leave
        self.client.login(username='employee1', password='testpass123')

        response = self.client.post(
            reverse('leave_management:cancel_leave', args=[leave_request.id]),
            {'cancellation_reason': 'Changed plans'}
        )

        leave_request.refresh_from_db()
        self.assertEqual(leave_request.status, 'Cancelled')

        # Check balance was reverted
        self.employee_annual_balance.refresh_from_db()
        self.assertEqual(self.employee_annual_balance.used, original_used - Decimal('1.0'))

    def test_auto_conversion_to_lop(self):
        """Test automatic conversion to Loss of Pay when insufficient balance"""
        # Use up all annual leave balance
        self.employee_annual_balance.used = self.employee_annual_balance.allocated + self.employee_annual_balance.carried_forward
        self.employee_annual_balance.save()

        tomorrow = timezone.now().date() + timedelta(days=5)

        leave_data = {
            'leave_type': self.annual_leave.id,
            'start_date': tomorrow,
            'end_date': tomorrow,
            'half_day': False,
            'reason': 'Should convert to LOP',
            'is_retroactive': False
        }

        leave_request, result = LeaveService.apply_leave(self.employee_user, leave_data)

        # Should fail due to insufficient balance
        self.assertFalse(result['is_valid'])


class LeaveErrorHandlingTests(LeaveManagementTestCase):
    """Test error handling and edge cases"""

    def test_approve_already_processed_leave(self):
        """Test approving already processed leave"""
        tomorrow = timezone.now().date() + timedelta(days=5)

        leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=tomorrow,
            end_date=tomorrow,
            reason='Already processed',
            status='Approved'  # Already approved
        )

        with self.assertRaises(LeaveServiceError):
            LeaveService.approve_leave(leave_request, self.manager_user)

    def test_unauthorized_approval_attempt(self):
        """Test unauthorized user trying to approve leave"""
        tomorrow = timezone.now().date() + timedelta(days=5)

        leave_request = LeaveRequest.objects.create(
            user=self.manager_user,  # Manager's leave
            leave_type=self.annual_leave,
            start_date=tomorrow,
            end_date=tomorrow,
            reason='Manager leave',
            status='Pending'
        )

        # Employee trying to approve manager's leave
        with self.assertRaises(LeaveServiceError):
            LeaveService.approve_leave(leave_request, self.employee_user)

    def test_overlapping_leave_validation(self):
        """Test overlapping leave request validation"""
        tomorrow = timezone.now().date() + timedelta(days=5)

        # Create first approved leave
        LeaveRequest.objects.create(
            user=self.employee
