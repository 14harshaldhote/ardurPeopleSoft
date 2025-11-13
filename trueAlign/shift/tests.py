"""
Comprehensive Test Suite for Shift Management System
Tests all functionality: CRUD operations, assignments, conflicts, bulk operations, etc.
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.urls import reverse
from django.contrib.messages import get_messages
from datetime import time, date, timedelta
from decimal import Decimal
import json

from trueAlign.models import ShiftMaster, ShiftAssignment, ShiftConflict, ShiftValidationRule
from .validators import ShiftAssignmentValidator, BulkAssignmentValidator
from .services import ShiftService, ShiftAssignmentService, ConflictDetectionService


class BaseTestCase(TestCase):
    """Base test case with common setup"""
    
    def setUp(self):
        # Create users with different roles
        self.admin_user = User.objects.create_user(
            username='admin',
            email='admin@test.com',
            password='testpass123',
            is_staff=True,
            is_superuser=True
        )
        
        self.hr_user = User.objects.create_user(
            username='hr_user',
            email='hr@test.com',
            password='testpass123'
        )
        
        self.manager_user = User.objects.create_user(
            username='manager',
            email='manager@test.com',
            password='testpass123'
        )
        
        self.employee_user = User.objects.create_user(
            username='employee',
            email='employee@test.com',
            password='testpass123'
        )
        
        # Create groups
        self.admin_group = Group.objects.create(name='Admin')
        self.hr_group = Group.objects.create(name='HR')
        self.manager_group = Group.objects.create(name='Manager')
        
        # Assign users to groups
        self.hr_user.groups.add(self.hr_group)
        self.manager_user.groups.add(self.manager_group)
        
        # Create test shifts
        self.day_shift = ShiftMaster.objects.create(
            name='Day Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            work_days='Weekdays',
            break_duration=timedelta(minutes=30),
            grace_period=timedelta(minutes=15),
            color_code='#3B82F6',
            is_active=True,
            created_by=self.admin_user
        )
        
        self.night_shift = ShiftMaster.objects.create(
            name='Night Shift',
            start_time=time(22, 0),
            end_time=time(6, 0),
            work_days='All Days',
            break_duration=timedelta(minutes=45),
            grace_period=timedelta(minutes=10),
            color_code='#1F2937',
            is_active=True,
            created_by=self.admin_user
        )
        
        self.client = Client()


class ShiftCRUDTestCase(BaseTestCase):
    """Test CRUD operations for shifts"""
    
    def test_shift_create_success(self):
        """Test successful shift creation"""
        self.client.login(username='admin', password='testpass123')
        
        response = self.client.post(reverse('shift:shift_create'), {
            'name': 'Evening Shift',
            'start_time': '14:00',
            'end_time': '22:00',
            'work_days': 'Weekdays',
            'description': 'Evening work shift',
            'color_code': '#F59E0B',
            'break_duration': '30',
            'grace_period': '15',
            'requires_approval': 'on',
            'is_active': 'on'
        })
        
        self.assertEqual(response.status_code, 302)  # Redirect after success
        self.assertTrue(ShiftMaster.objects.filter(name='Evening Shift').exists())
        
        shift = ShiftMaster.objects.get(name='Evening Shift')
        self.assertEqual(shift.start_time, time(14, 0))
        self.assertEqual(shift.end_time, time(22, 0))
        self.assertTrue(shift.requires_approval)
        self.assertTrue(shift.is_active)
    
    def test_shift_create_permission_denied(self):
        """Test shift creation with insufficient permissions"""
        self.client.login(username='employee', password='testpass123')
        
        response = self.client.post(reverse('shift:shift_create'), {
            'name': 'Unauthorized Shift',
            'start_time': '09:00',
            'end_time': '17:00'
        })
        
        self.assertEqual(response.status_code, 302)  # Redirect to shift list
        self.assertFalse(ShiftMaster.objects.filter(name='Unauthorized Shift').exists())
    
    def test_shift_edit_success(self):
        """Test successful shift editing"""
        self.client.login(username='admin', password='testpass123')
        
        response = self.client.post(reverse('shift:shift_edit', args=[self.day_shift.pk]), {
            'name': 'Updated Day Shift',
            'start_time': '08:30',
            'end_time': '16:30',
            'work_days': 'All Days',
            'description': 'Updated description',
            'color_code': '#10B981',
            'break_duration': '45',
            'grace_period': '20',
            'is_active': 'on'
        })
        
        self.assertEqual(response.status_code, 302)
        
        updated_shift = ShiftMaster.objects.get(pk=self.day_shift.pk)
        self.assertEqual(updated_shift.name, 'Updated Day Shift')
        self.assertEqual(updated_shift.start_time, time(8, 30))
        self.assertEqual(updated_shift.work_days, 'All Days')
    
    def test_shift_delete_success(self):
        """Test successful shift deletion"""
        self.client.login(username='admin', password='testpass123')
        
        response = self.client.post(reverse('shift:shift_delete', args=[self.day_shift.pk]))
        
        self.assertEqual(response.status_code, 302)
        self.assertFalse(ShiftMaster.objects.filter(pk=self.day_shift.pk).exists())
    
    def test_shift_delete_with_active_assignments(self):
        """Test shift deletion with active assignments (should fail)"""
        # Create an active assignment
        assignment = ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            status='ACTIVE',
            created_by=self.admin_user
        )
        
        self.client.login(username='admin', password='testpass123')
        
        response = self.client.post(reverse('shift:shift_delete', args=[self.day_shift.pk]))
        
        # Should redirect back to shift detail with error message
        self.assertEqual(response.status_code, 302)
        self.assertTrue(ShiftMaster.objects.filter(pk=self.day_shift.pk).exists())


class AssignmentTestCase(BaseTestCase):
    """Test assignment operations"""
    
    def test_single_assignment_create_success(self):
        """Test successful single assignment creation"""
        self.client.login(username='admin', password='testpass123')
        
        response = self.client.post(reverse('shift:assignment_create'), {
            'user': self.employee_user.pk,
            'shift': self.day_shift.pk,
            'effective_from': date.today().strftime('%Y-%m-%d'),
            'status': 'ACTIVE'
        })
        
        self.assertEqual(response.status_code, 302)
        self.assertTrue(ShiftAssignment.objects.filter(
            user=self.employee_user,
            shift=self.day_shift
        ).exists())
    
    def test_assignment_end_success(self):
        """Test successful assignment ending"""
        assignment = ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            status='ACTIVE',
            created_by=self.admin_user
        )
        
        self.client.login(username='admin', password='testpass123')
        
        response = self.client.post(
            reverse('shift:assignment_end', args=[assignment.pk]),
            {
                'end_date': (date.today() + timedelta(days=1)).strftime('%Y-%m-%d'),
                'reason': 'Testing end assignment'
            }
        )
        
        self.assertEqual(response.status_code, 302)
        
        assignment.refresh_from_db()
        self.assertIsNotNone(assignment.effective_to)
        self.assertFalse(assignment.is_current)
    
    def test_bulk_assignment_create_success(self):
        """Test successful bulk assignment creation"""
        # Create additional users
        user2 = User.objects.create_user(
            username='employee2',
            email='employee2@test.com',
            password='testpass123'
        )
        user3 = User.objects.create_user(
            username='employee3',
            email='employee3@test.com',
            password='testpass123'
        )
        
        self.client.login(username='admin', password='testpass123')
        
        response = self.client.post(reverse('shift:bulk_assignment_create'), {
            'users': [self.employee_user.pk, user2.pk, user3.pk],
            'shift': self.day_shift.pk,
            'effective_from': date.today().strftime('%Y-%m-%d'),
            'status': 'ACTIVE'
        })
        
        self.assertEqual(response.status_code, 302)
        
        # Check that assignments were created for all users
        assignments = ShiftAssignment.objects.filter(
            shift=self.day_shift,
            effective_from=date.today()
        )
        self.assertEqual(assignments.count(), 3)


class APIEndpointTestCase(BaseTestCase):
    """Test API endpoints"""
    
    def test_shifts_list_api(self):
        """Test shifts list API endpoint"""
        self.client.login(username='admin', password='testpass123')
        
        response = self.client.get(reverse('shift:api_shifts_list'))
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('shifts', data)
        self.assertEqual(len(data['shifts']), 2)  # day_shift and night_shift
    
    def test_assignments_list_api(self):
        """Test assignments list API endpoint"""
        # Create test assignment
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            status='ACTIVE',
            created_by=self.admin_user
        )
        
        self.client.login(username='admin', password='testpass123')
        
        response = self.client.get(reverse('shift:api_assignments_list'))
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('assignments', data)
        self.assertEqual(len(data['assignments']), 1)
    
    def test_dashboard_stats_api(self):
        """Test dashboard statistics API endpoint"""
        self.client.login(username='admin', password='testpass123')
        
        response = self.client.get(reverse('shift:api_dashboard_stats'))
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        
        # Check required fields
        required_fields = ['total_shifts', 'active_shifts', 'active_assignments', 
                          'pending_approvals', 'unresolved_conflicts']
        for field in required_fields:
            self.assertIn(field, data)
    
    def test_duplicate_shift_api(self):
        """Test shift duplication API endpoint"""
        self.client.login(username='admin', password='testpass123')
        
        response = self.client.post(
            reverse('shift:duplicate_shift', args=[self.day_shift.pk]),
            data=json.dumps({
                'new_name': 'Duplicated Day Shift'
            }),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        
        # Check that new shift was created
        self.assertTrue(ShiftMaster.objects.filter(name='Duplicated Day Shift').exists())


class PermissionTestCase(BaseTestCase):
    """Test permission-based access control"""
    
    def test_admin_full_access(self):
        """Test admin has full access to all features"""
        self.client.login(username='admin', password='testpass123')
        
        # Test access to all major views
        views_to_test = [
            'shift:dashboard',
            'shift:shift_list',
            'shift:shift_create',
            'shift:assignment_list',
            'shift:assignment_create',
            'shift:bulk_assignment_create',
            'shift:conflict_list',
            'shift:team_assignments',
            'shift:utilization_reports'
        ]
        
        for view_name in views_to_test:
            response = self.client.get(reverse(view_name))
            self.assertIn(response.status_code, [200, 302])  # 200 OK or 302 redirect (not 403)
    
    def test_employee_restricted_access(self):
        """Test employee has restricted access"""
        self.client.login(username='employee', password='testpass123')
        
        # Test access to dashboard (should work)
        response = self.client.get(reverse('shift:dashboard'))
        self.assertEqual(response.status_code, 200)
        
        # Test access to shift creation (should be denied)
        response = self.client.get(reverse('shift:shift_create'))
        self.assertEqual(response.status_code, 302)  # Redirect due to permission denied
    
    def test_hr_manager_access(self):
        """Test HR and Manager have appropriate access"""
        for username in ['hr_user', 'manager']:
            self.client.login(username=username, password='testpass123')
            
            # Should have access to most features
            response = self.client.get(reverse('shift:shift_create'))
            self.assertEqual(response.status_code, 200)
            
            response = self.client.get(reverse('shift:assignment_create'))
            self.assertEqual(response.status_code, 200)


class IntegrationTestCase(BaseTestCase):
    """Integration tests for complete workflows"""
    
    def test_complete_shift_lifecycle(self):
        """Test complete shift lifecycle: create -> assign -> reassign -> end"""
        self.client.login(username='admin', password='testpass123')
        
        # 1. Create shift
        response = self.client.post(reverse('shift:shift_create'), {
            'name': 'Integration Test Shift',
            'start_time': '10:00',
            'end_time': '18:00',
            'work_days': 'Weekdays',
            'break_duration': '30',
            'grace_period': '15',
            'is_active': 'on'
        })
        self.assertEqual(response.status_code, 302)
        
        shift = ShiftMaster.objects.get(name='Integration Test Shift')
        
        # 2. Assign to employee
        response = self.client.post(reverse('shift:assignment_create'), {
            'user': self.employee_user.pk,
            'shift': shift.pk,
            'effective_from': date.today().strftime('%Y-%m-%d'),
            'status': 'ACTIVE'
        })
        self.assertEqual(response.status_code, 302)
        
        assignment = ShiftAssignment.objects.get(user=self.employee_user, shift=shift)
        
        # 3. End assignment
        response = self.client.post(
            reverse('shift:assignment_end', args=[assignment.pk]),
            {
                'end_date': (date.today() + timedelta(days=7)).strftime('%Y-%m-%d'),
                'reason': 'Integration test completion'
            }
        )
        self.assertEqual(response.status_code, 302)
        
        # Verify final state
        assignment.refresh_from_db()
        self.assertIsNotNone(assignment.effective_to)
        self.assertFalse(assignment.is_current)
    
    def test_bulk_operations_workflow(self):
        """Test bulk operations workflow"""
        # Create multiple users
        users = []
        for i in range(5):
            user = User.objects.create_user(
                username=f'bulk_user_{i}',
                email=f'bulk{i}@test.com',
                password='testpass123'
            )
            users.append(user)
        
        self.client.login(username='admin', password='testpass123')
        
        # Bulk assign
        response = self.client.post(reverse('shift:bulk_assignment_create'), {
            'users': [u.pk for u in users],
            'shift': self.day_shift.pk,
            'effective_from': date.today().strftime('%Y-%m-%d'),
            'status': 'ACTIVE'
        })
        self.assertEqual(response.status_code, 302)
        
        # Verify assignments created
        assignments = ShiftAssignment.objects.filter(
            shift=self.day_shift,
            effective_from=date.today()
        )
        self.assertEqual(assignments.count(), 5)
        
        # Test bulk end (would be done via JavaScript in real scenario)
        for assignment in assignments:
            response = self.client.post(
                reverse('shift:assignment_end', args=[assignment.pk]),
                {
                    'end_date': (date.today() + timedelta(days=30)).strftime('%Y-%m-%d'),
                    'reason': 'Bulk end test'
                }
            )
            self.assertEqual(response.status_code, 302)
        
        # Verify all assignments ended
        ended_assignments = ShiftAssignment.objects.filter(
            shift=self.day_shift,
            effective_to__isnull=False
        )
        self.assertEqual(ended_assignments.count(), 5)
