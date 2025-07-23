from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from trueAlign.leave_management.utils import (
    is_employee, is_manager, is_hr, is_admin,
    can_approve_leave, can_view_leave_request,
    can_edit_leave_request, can_cancel_leave_request
)
from trueAlign.models import LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance, LeaveRequest
from django.utils import timezone
from datetime import timedelta

class LeavePermissionTests(TestCase):
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

        # Create test client
        self.client = Client()

        # Create a leave request for permission testing
        self.leave_request = LeaveRequest.objects.create(
            user=self.employee_user,
            leave_type=self.annual_leave,
            start_date=timezone.now().date() + timedelta(days=5),
            end_date=timezone.now().date() + timedelta(days=7),
            reason="Test leave",
            status="Pending"
        )

    def test_dashboard_access_restrictions(self):
        """Test that users can only access their appropriate dashboards"""
        # Employee should only access employee dashboard
        self.client.login(username="employee", password="password")

        response = self.client.get(reverse('leave_management:employee_dashboard'))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse('leave_management:manager_dashboard'))
        self.assertEqual(response.status_code, 403)

        response = self.client.get(reverse('leave_management:hr_dashboard'))
        self.assertEqual(response.status_code, 403)

        response = self.client.get(reverse('leave_management:admin_dashboard'))
        self.assertEqual(response.status_code, 403)

        # Manager should access employee and manager dashboards
        self.client.login(username="manager", password="password")

        response = self.client.get(reverse('leave_management:employee_dashboard'))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse('leave_management:manager_dashboard'))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse('leave_management:hr_dashboard'))
        self.assertEqual(response.status_code, 403)

        # HR should access all but admin
        self.client.login(username="hr", password="password")

        response = self.client.get(reverse('leave_management:employee_dashboard'))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse('leave_management:manager_dashboard'))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse('leave_management:hr_dashboard'))
        self.assertEqual(response.status_code, 200)

        # Admin should access all dashboards
        self.client.login(username="admin", password="password")

        response = self.client.get(reverse('leave_management:employee_dashboard'))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse('leave_management:manager_dashboard'))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse('leave_management:hr_dashboard'))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse('leave_management:admin_dashboard'))
        self.assertEqual(response.status_code, 200)

    def test_role_utilities(self):
        """Test role utility functions"""
        self.assertTrue(is_employee(self.employee_user))
        self.assertFalse(is_manager(self.employee_user))
        self.assertFalse(is_hr(self.employee_user))
        self.assertFalse(is_admin(self.employee_user))

        self.assertTrue(is_manager(self.manager_user))
        self.assertFalse(is_employee(self.manager_user))

        self.assertTrue(is_hr(self.hr_user))
        self.assertFalse(is_employee(self.hr_user))

        self.assertTrue(is_admin(self.admin_user))
        self.assertFalse(is_employee(self.admin_user))

    def test_approval_permissions(self):
        """Test who can approve whose leave"""
        # Manager can approve employee leave
        self.assertTrue(can_approve_leave(self.manager_user, self.employee_user))

        # HR can approve employee and manager leave
        self.assertTrue(can_approve_leave(self.hr_user, self.employee_user))
        self.assertTrue(can_approve_leave(self.hr_user, self.manager_user))

        # Admin can approve HR leave
        self.assertTrue(can_approve_leave(self.admin_user, self.hr_user))

        # Employee cannot approve any leave
        self.assertFalse(can_approve_leave(self.employee_user, self.employee_user))
        self.assertFalse(can_approve_leave(self.employee_user, self.manager_user))

        # Manager cannot approve manager, HR or admin leave
        self.assertFalse(can_approve_leave(self.manager_user, self.manager_user))
        self.assertFalse(can_approve_leave(self.manager_user, self.hr_user))
        self.assertFalse(can_approve_leave(self.manager_user, self.admin_user))

        # Users cannot approve their own leave
        self.assertFalse(can_approve_leave(self.employee_user, self.employee_user))
        self.assertFalse(can_approve_leave(self.manager_user, self.manager_user))
        self.assertFalse(can_approve_leave(self.hr_user, self.hr_user))
        self.assertFalse(can_approve_leave(self.admin_user, self.admin_user))

    def test_view_leave_permissions(self):
        """Test who can view leave requests"""
        # Employee can view own leave
        self.assertTrue(can_view_leave_request(self.employee_user, self.leave_request))

        # Create a leave request for a different employee
        other_employee = User.objects.create_user(username="other_emp", email="other@example.com", password="password")
        other_employee.groups.add(self.employee_group)

        other_leave = LeaveRequest.objects.create(
            user=other_employee,
            leave_type=self.annual_leave,
            start_date=timezone.now().date() + timedelta(days=5),
            end_date=timezone.now().date() + timedelta(days=7),
            reason="Other leave",
            status="Pending"
        )

        # Employee cannot view other employee's leave
        self.assertFalse(can_view_leave_request(self.employee_user, other_leave))

        # Manager can view employee leave
        self.assertTrue(can_view_leave_request(self.manager_user, self.leave_request))
        self.assertTrue(can_view_leave_request(self.manager_user, other_leave))

        # HR and admin can view all leave
        self.assertTrue(can_view_leave_request(self.hr_user, self.leave_request))
        self.assertTrue(can_view_leave_request(self.hr_user, other_leave))
        self.assertTrue(can_view_leave_request(self.admin_user, self.leave_request))
        self.assertTrue(can_view_leave_request(self.admin_user, other_leave))

    def test_edit_leave_permissions(self):
        """Test who can edit leave requests"""
        # Pending leave can be edited by owner
        self.assertTrue(can_edit_leave_request(self.employee_user, self.leave_request))

        # HR can edit pending leave
        self.assertTrue(can_edit_leave_request(self.hr_user, self.leave_request))

        # Manager cannot edit leave (they can only approve/reject)
        self.assertFalse(can_edit_leave_request(self.manager_user, self.leave_request))

        # Once approved, no one can edit it
        self.leave_request.status = "Approved"
        self.leave_request.approver = self.manager_user
        self.leave_request.save()

        self.assertFalse(can_edit_leave_request(self.employee_user, self.leave_request))
        self.assertFalse(can_edit_leave_request(self.hr_user, self.leave_request))

    def test_cancel_leave_permissions(self):
        """Test who can cancel leave requests"""
        # Employee can cancel their own pending leave
        self.assertTrue(can_cancel_leave_request(self.employee_user, self.leave_request))

        # HR can cancel any pending leave
        self.assertTrue(can_cancel_leave_request(self.hr_user, self.leave_request))

        # Manager cannot cancel leave directly
        self.assertFalse(can_cancel_leave_request(self.manager_user, self.leave_request))

        # Once approved, employee can still cancel
        self.leave_request.status = "Approved"
        self.leave_request.approver = self.manager_user
        self.leave_request.save()

        self.assertTrue(can_cancel_leave_request(self.employee_user, self.leave_request))

        # Once cancelled, no one can cancel again
        self.leave_request.status = "Cancelled"
        self.leave_request.save()

        self.assertFalse(can_cancel_leave_request(self.employee_user, self.leave_request))
        self.assertFalse(can_cancel_leave_request(self.hr_user, self.leave_request))

    def test_protected_urls(self):
        """Test URL protection with decorators"""
        # Test team leaves view (should be accessible only to manager+)
        self.client.login(username="employee", password="password")
        response = self.client.get(reverse('leave_management:team_leaves'))
        self.assertEqual(response.status_code, 403)

        self.client.login(username="manager", password="password")
        response = self.client.get(reverse('leave_management:team_leaves'))
        self.assertEqual(response.status_code, 200)

        # Test approving leave
        self.client.login(username="employee", password="password")
        response = self.client.post(reverse('leave_management:approve_leave', args=[self.leave_request.id]), {'comments': 'Approved'})
        self.assertEqual(response.status_code, 403)

        self.client.login(username="manager", password="password")
        response = self.client.post(reverse('leave_management:approve_leave', args=[self.leave_request.id]), {'comments': 'Approved'})
        self.assertEqual(response.status_code, 302)  # Should redirect after success
