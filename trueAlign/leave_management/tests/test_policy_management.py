from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from trueAlign.leave_management.services.leave_service import LeaveService
from trueAlign.models import LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance

class LeavePolicyManagementTests(TestCase):
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
            description="Standard annual leave",
            is_paid=True,
            requires_approval=True,
            can_be_half_day=True
        )

        self.sick_leave = LeaveType.objects.create(
            name="Sick Leave",
            description="Medical leave",
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

        # Create test client
        self.client = Client()

    def test_create_policy(self):
        """Test that HR and Admin can create leave policies"""
        # Login as HR
        self.client.login(username="hr", password="password")

        policy_data = {
            'name': 'Executive Policy',
            'group': self.manager_group.id,
            'is_active': True
        }

        response = self.client.post(reverse('leave_management:create_policy'), policy_data)
        self.assertEqual(response.status_code, 302)  # Should redirect after success
        self.assertTrue(LeavePolicy.objects.filter(name='Executive Policy').exists())

        # Now try as employee (should fail)
        self.client.login(username="employee", password="password")
        policy_data = {
            'name': 'Employee Policy',
            'group': self.employee_group.id,
            'is_active': True
        }

        response = self.client.post(reverse('leave_management:create_policy'), policy_data)
        self.assertEqual(response.status_code, 403)  # Should be forbidden

    def test_policy_update(self):
        """Test that HR and Admin can update policies but others cannot"""
        # Login as HR
        self.client.login(username="hr", password="password")

        # Update existing policy
        update_data = {
            'name': 'Updated Standard Policy',
            'group': self.employee_group.id,
            'is_active': True
        }

        response = self.client.post(
            reverse('leave_management:update_policy', args=[self.standard_policy.id]),
            update_data
        )
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify update
        self.standard_policy.refresh_from_db()
        self.assertEqual(self.standard_policy.name, 'Updated Standard Policy')

        # Try as employee (should fail)
        self.client.login(username="employee", password="password")
        update_data = {
            'name': 'Employee Updated Policy',
            'group': self.employee_group.id,
            'is_active': True
        }

        response = self.client.post(
            reverse('leave_management:update_policy', args=[self.standard_policy.id]),
            update_data
        )
        self.assertEqual(response.status_code, 403)  # Should be forbidden

    def test_policy_deactivation(self):
        """Test that HR and Admin can deactivate policies"""
        # Login as Admin
        self.client.login(username="admin", password="password")

        # Deactivate policy
        response = self.client.post(
            reverse('leave_management:toggle_policy', args=[self.standard_policy.id])
        )
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify deactivation
        self.standard_policy.refresh_from_db()
        self.assertFalse(self.standard_policy.is_active)

        # Try as manager (should fail)
        self.client.login(username="manager", password="password")
        response = self.client.post(
            reverse('leave_management:toggle_policy', args=[self.standard_policy.id])
        )
        self.assertEqual(response.status_code, 403)  # Should be forbidden

    def test_policy_deletion(self):
        """Test that HR and Admin can delete policies but others cannot"""
        # Create a policy to delete
        test_policy = LeavePolicy.objects.create(
            name="Test Delete Policy",
            group=self.employee_group,
            is_active=True
        )

        # Login as Admin
        self.client.login(username="admin", password="password")

        # Delete policy
        response = self.client.post(
            reverse('leave_management:delete_policy', args=[test_policy.id])
        )
        self.assertEqual(response.status_code, 302)  # Should redirect after success

        # Verify deletion
        self.assertFalse(LeavePolicy.objects.filter(id=test_policy.id).exists())

        # Create another policy
        test_policy2 = LeavePolicy.objects.create(
            name="Test Delete Policy 2",
            group=self.employee_group,
            is_active=True
        )

        # Try as employee (should fail)
        self.client.login(username="employee", password="password")
        response = self.client.post(
            reverse('leave_management:delete_policy', args=[test_policy2.id])
        )
        self.assertEqual(response.status_code, 403)  # Should be forbidden

        # Verify policy still exists
        self.assertTrue(LeavePolicy.objects.filter(id=test_policy2.id).exists())
