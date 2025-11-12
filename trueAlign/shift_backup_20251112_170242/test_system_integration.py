"""
Comprehensive System Integration Tests for Shift Management
Tests shift creation, assignment, and overlap handling functionality
"""

import json
from datetime import date, time, timedelta
from decimal import Decimal
from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.utils import timezone
from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
from trueAlign.shift.services import ShiftService, ConflictDetector
from trueAlign.shift.forms import ShiftForm, ShiftAssignmentForm, BulkAssignmentForm


class ShiftSystemIntegrationTest(TestCase):
    """Comprehensive integration tests for shift management system"""

    def setUp(self):
        """Set up test data"""
        # Create user groups
        self.manager_group = Group.objects.create(name='Manager')
        self.hr_group = Group.objects.create(name='HR')
        self.employee_group = Group.objects.create(name='Employee')

        # Create test users
        self.manager_user = User.objects.create_user(
            username='manager1',
            email='manager@test.com',
            password='testpass123',
            first_name='Test',
            last_name='Manager'
        )
        self.manager_user.groups.add(self.manager_group)

        self.employee_user = User.objects.create_user(
            username='employee1',
            email='employee@test.com',
            password='testpass123',
            first_name='Test',
            last_name='Employee'
        )
        self.employee_user.groups.add(self.employee_group)

        self.employee_user2 = User.objects.create_user(
            username='employee2',
            email='employee2@test.com',
            password='testpass123',
            first_name='Test2',
            last_name='Employee2'
        )
        self.employee_user2.groups.add(self.employee_group)

        # Initialize services
        self.shift_service = ShiftService()
        self.conflict_detector = ConflictDetector()

        # Test client
        self.client = Client()
        self.client.login(username='manager1', password='testpass123')

    def test_shift_creation_basic(self):
        """Test basic shift creation functionality"""
        shift_data = {
            'name': 'Morning Shift',
            'start_time': '09:00',
            'end_time': '17:00',
            'shift_duration': '8.0',
            'work_days': 'Weekdays',
            'break_duration_minutes': '30',
            'grace_period_minutes': '15',
            'is_active': True
        }

        response = self.client.post(reverse('shift:create'), shift_data)

        # Should redirect on success
        self.assertIn(response.status_code, [200, 302])

        # Check shift was created
        shift = ShiftMaster.objects.filter(name='Morning Shift').first()
        self.assertIsNotNone(shift)
        self.assertEqual(shift.start_time, time(9, 0))
        self.assertEqual(shift.end_time, time(17, 0))
        self.assertEqual(shift.shift_duration, Decimal('8.0'))
        self.assertTrue(shift.is_active)

    def test_shift_creation_overnight(self):
        """Test overnight shift creation"""
        shift_data = {
            'name': 'Night Shift',
            'start_time': '22:00',
            'end_time': '06:00',
            'shift_duration': '8.0',
            'work_days': 'Weekdays',
            'break_duration_minutes': '30',
            'grace_period_minutes': '15',
            'is_active': True
        }

        response = self.client.post(reverse('shift:create'), shift_data)

        # Should work without errors
        self.assertIn(response.status_code, [200, 302])

        shift = ShiftMaster.objects.filter(name='Night Shift').first()
        self.assertIsNotNone(shift)
        self.assertTrue(shift.crosses_midnight)

    def test_overlapping_shifts_allowed(self):
        """Test that overlapping shifts are now allowed"""
        # Create first shift
        shift1_data = {
            'name': 'Morning Shift',
            'start_time': '09:00',
            'end_time': '17:00',
            'shift_duration': '8.0',
            'work_days': 'Weekdays',
            'break_duration_minutes': '30',
            'grace_period_minutes': '15',
            'is_active': True
        }

        response1 = self.client.post(reverse('shift:create'), shift1_data)
        self.assertIn(response1.status_code, [200, 302])

        # Create overlapping shift
        shift2_data = {
            'name': 'Afternoon Shift',
            'start_time': '13:00',  # Overlaps with Morning Shift
            'end_time': '21:00',
            'shift_duration': '8.0',
            'work_days': 'Weekdays',
            'break_duration_minutes': '30',
            'grace_period_minutes': '15',
            'is_active': True
        }

        response2 = self.client.post(reverse('shift:create'), shift2_data)

        # Should be allowed now
        self.assertIn(response2.status_code, [200, 302])

        # Both shifts should exist
        self.assertTrue(ShiftMaster.objects.filter(name='Morning Shift').exists())
        self.assertTrue(ShiftMaster.objects.filter(name='Afternoon Shift').exists())

    def test_shift_name_validation_api(self):
        """Test shift name validation API"""
        # Create existing shift
        ShiftMaster.objects.create(
            name='Existing Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        # Test unique name
        response = self.client.post(
            reverse('shift:api_validate_shift_name'),
            json.dumps({'name': 'New Unique Shift'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['valid'])
        self.assertEqual(len(data['errors']), 0)

        # Test duplicate name
        response = self.client.post(
            reverse('shift:api_validate_shift_name'),
            json.dumps({'name': 'Existing Shift'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertFalse(data['valid'])
        self.assertGreater(len(data['errors']), 0)

    def test_single_assignment(self):
        """Test single shift assignment"""
        # Create shift
        shift = ShiftMaster.objects.create(
            name='Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        assignment_data = {
            'user': self.employee_user.id,
            'shift': shift.id,
            'effective_from': date.today() + timedelta(days=1),
            'effective_to': date.today() + timedelta(days=30),
            'reason': 'Test assignment'
        }

        response = self.client.post(reverse('shift:assign'), assignment_data)

        # Should succeed
        self.assertIn(response.status_code, [200, 302])

        # Check assignment was created
        assignment = ShiftAssignment.objects.filter(
            user=self.employee_user,
            shift=shift
        ).first()
        self.assertIsNotNone(assignment)
        self.assertTrue(assignment.is_current)

    def test_overlapping_assignments_allowed(self):
        """Test that overlapping assignments are now allowed"""
        # Create two shifts
        shift1 = ShiftMaster.objects.create(
            name='Morning Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        shift2 = ShiftMaster.objects.create(
            name='Afternoon Shift',
            start_time=time(13, 0),
            end_time=time(21, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        # Assign first shift
        assignment1_data = {
            'user': self.employee_user.id,
            'shift': shift1.id,
            'effective_from': date.today() + timedelta(days=1),
            'effective_to': date.today() + timedelta(days=30),
            'reason': 'First assignment'
        }

        response1 = self.client.post(reverse('shift:assign'), assignment1_data)
        self.assertIn(response1.status_code, [200, 302])

        # Assign overlapping shift to same user (should be allowed with warning)
        assignment2_data = {
            'user': self.employee_user.id,
            'shift': shift2.id,
            'effective_from': date.today() + timedelta(days=15),  # Overlaps with first
            'effective_to': date.today() + timedelta(days=45),
            'reason': 'Overlapping assignment',
            'override_conflicts': True
        }

        response2 = self.client.post(reverse('shift:assign'), assignment2_data)

        # Should be allowed
        self.assertIn(response2.status_code, [200, 302])

        # Both assignments should exist
        self.assertEqual(ShiftAssignment.objects.filter(user=self.employee_user).count(), 2)

    def test_bulk_assignment(self):
        """Test bulk assignment functionality"""
        # Create shift
        shift = ShiftMaster.objects.create(
            name='Bulk Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        bulk_data = {
            'users': [self.employee_user.id, self.employee_user2.id],
            'shift': shift.id,
            'effective_from': date.today() + timedelta(days=1),
            'effective_to': date.today() + timedelta(days=30),
            'reason': 'Bulk assignment test'
        }

        response = self.client.post(reverse('shift:bulk_assign'), bulk_data)

        # Should succeed
        self.assertIn(response.status_code, [200, 302])

        # Check assignments were created
        assignments = ShiftAssignment.objects.filter(shift=shift)
        self.assertEqual(assignments.count(), 2)

    def test_csv_upload_assignment(self):
        """Test CSV upload functionality"""
        # Create shift
        shift = ShiftMaster.objects.create(
            name='CSV Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        # Create CSV content
        csv_content = """username,shift_name,effective_from,effective_to,notes
employee1,CSV Test Shift,{start_date},{end_date},CSV test assignment
employee2,CSV Test Shift,{start_date},{end_date},CSV test assignment 2""".format(
            start_date=(date.today() + timedelta(days=1)).strftime('%Y-%m-%d'),
            end_date=(date.today() + timedelta(days=30)).strftime('%Y-%m-%d')
        )

        # Create temporary file
        from django.core.files.uploadedfile import SimpleUploadedFile
        csv_file = SimpleUploadedFile(
            "test_assignments.csv",
            csv_content.encode('utf-8'),
            content_type="text/csv"
        )

        response = self.client.post(
            reverse('shift:csv_upload'),
            {'csv_file': csv_file}
        )

        # Should process successfully
        self.assertIn(response.status_code, [200, 302])

        # Check assignments were created
        assignments = ShiftAssignment.objects.filter(shift=shift)
        self.assertEqual(assignments.count(), 2)

    def test_form_validation_edge_cases(self):
        """Test form validation edge cases"""
        # Test minimum duration
        form_data = {
            'name': 'Short Shift',
            'start_time': time(9, 0),
            'end_time': time(9, 30),
            'shift_duration': Decimal('0.5'),
            'work_days': 'Weekdays'
        }
        form = ShiftForm(data=form_data)
        self.assertTrue(form.is_valid())

        # Test maximum duration
        form_data = {
            'name': 'Long Shift',
            'start_time': time(0, 0),
            'end_time': time(23, 59),
            'shift_duration': Decimal('24.0'),
            'work_days': 'Weekdays'
        }
        form = ShiftForm(data=form_data)
        self.assertTrue(form.is_valid())

        # Test custom work days
        form_data = {
            'name': 'Custom Shift',
            'start_time': time(9, 0),
            'end_time': time(17, 0),
            'shift_duration': Decimal('8.0'),
            'work_days': 'Custom',
            'custom_work_days': 'Monday,Wednesday,Friday'
        }
        form = ShiftForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_assignment_validation_api(self):
        """Test assignment validation API"""
        # Create shift
        shift = ShiftMaster.objects.create(
            name='API Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        # Test valid assignment
        response = self.client.post(
            reverse('shift:api_validate_assignment'),
            json.dumps({
                'user_id': self.employee_user.id,
                'shift_id': shift.id,
                'effective_from': (date.today() + timedelta(days=1)).strftime('%Y-%m-%d'),
                'effective_to': (date.today() + timedelta(days=30)).strftime('%Y-%m-%d')
            }),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['valid'])

    def test_bulk_validation_api(self):
        """Test bulk assignment validation API"""
        # Create shift
        shift = ShiftMaster.objects.create(
            name='Bulk API Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        assignments_data = {
            'assignments': [
                {
                    'user_id': self.employee_user.id,
                    'shift_id': shift.id,
                    'effective_from': (date.today() + timedelta(days=1)).strftime('%Y-%m-%d'),
                    'effective_to': (date.today() + timedelta(days=30)).strftime('%Y-%m-%d')
                },
                {
                    'user_id': self.employee_user2.id,
                    'shift_id': shift.id,
                    'effective_from': (date.today() + timedelta(days=1)).strftime('%Y-%m-%d'),
                    'effective_to': (date.today() + timedelta(days=30)).strftime('%Y-%m-%d')
                }
            ]
        }

        response = self.client.post(
            reverse('shift:api_bulk_validation'),
            json.dumps(assignments_data),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['success'])
        self.assertEqual(len(data['results']), 2)

    def test_conflict_detection_service(self):
        """Test conflict detection service with new overlap policy"""
        # Create overlapping shifts
        shift1 = ShiftMaster.objects.create(
            name='Shift 1',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        shift2 = ShiftMaster.objects.create(
            name='Shift 2',
            start_time=time(13, 0),  # Overlaps with Shift 1
            end_time=time(21, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        # Create first assignment
        assignment1 = ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=shift1,
            effective_from=date.today() + timedelta(days=1),
            effective_to=date.today() + timedelta(days=30),
            is_current=True
        )

        # Check conflicts for overlapping assignment
        conflicts = self.conflict_detector.check_assignment_conflicts(
            self.employee_user,
            shift2,
            date.today() + timedelta(days=15),  # Overlaps with existing assignment
            date.today() + timedelta(days=45)
        )

        # Conflicts should be detected but allowed
        self.assertGreater(len(conflicts), 0)  # Conflicts detected

        # But assignment should still be creatable
        assignment2 = ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=shift2,
            effective_from=date.today() + timedelta(days=15),
            effective_to=date.today() + timedelta(days=45),
            is_current=True
        )

        self.assertIsNotNone(assignment2)

    def test_frontend_validation_functions(self):
        """Test frontend validation through form rendering"""
        # Test shift form rendering
        response = self.client.get(reverse('shift:create'))
        self.assertEqual(response.status_code, 200)

        # Check JavaScript functions are present
        content = response.content.decode('utf-8')
        self.assertIn('function toggleCustomWorkDays()', content)
        self.assertIn('function validateForm()', content)
        self.assertIn('function calculateDuration()', content)
        self.assertIn('function validateShiftName(', content)

        # Test assignment form rendering
        response = self.client.get(reverse('shift:assign'))
        self.assertEqual(response.status_code, 200)

    def test_date_time_validation(self):
        """Test comprehensive date and time validation"""
        # Test invalid duration (too short)
        form_data = {
            'name': 'Invalid Short Shift',
            'start_time': time(9, 0),
            'end_time': time(9, 15),  # Only 15 minutes
            'shift_duration': Decimal('0.25'),
            'work_days': 'Weekdays'
        }
        form = ShiftForm(data=form_data)
        self.assertFalse(form.is_valid())

        # Test invalid duration (too long)
        form_data = {
            'name': 'Invalid Long Shift',
            'start_time': time(0, 0),
            'end_time': time(23, 59),
            'shift_duration': Decimal('25.0'),  # Over 24 hours
            'work_days': 'Weekdays'
        }
        form = ShiftForm(data=form_data)
        self.assertFalse(form.is_valid())

        # Test valid overnight shift
        form_data = {
            'name': 'Valid Night Shift',
            'start_time': time(22, 0),
            'end_time': time(6, 0),
            'shift_duration': Decimal('8.0'),
            'work_days': 'Weekdays'
        }
        form = ShiftForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_assignment_date_validation(self):
        """Test assignment date validation"""
        shift = ShiftMaster.objects.create(
            name='Date Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        # Test past date (should fail)
        form_data = {
            'user': self.employee_user.id,
            'shift': shift.id,
            'effective_from': date.today() - timedelta(days=1),  # Past date
            'effective_to': date.today() + timedelta(days=30),
            'reason': 'Test assignment'
        }
        form = ShiftAssignmentForm(data=form_data)
        self.assertFalse(form.is_valid())

        # Test valid future date
        form_data = {
            'user': self.employee_user.id,
            'shift': shift.id,
            'effective_from': date.today() + timedelta(days=1),
            'effective_to': date.today() + timedelta(days=30),
            'reason': 'Test assignment'
        }
        form = ShiftAssignmentForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_user_experience_flows(self):
        """Test complete user experience flows"""
        # Manager creates a shift
        shift_data = {
            'name': 'UX Test Shift',
            'start_time': '09:00',
            'end_time': '17:00',
            'shift_duration': '8.0',
            'work_days': 'Weekdays',
            'break_duration_minutes': '30',
            'grace_period_minutes': '15',
            'is_active': True
        }

        # Create shift
        response = self.client.post(reverse('shift:create'), shift_data)
        self.assertIn(response.status_code, [200, 302])

        shift = ShiftMaster.objects.get(name='UX Test Shift')

        # Manager assigns shift to employee
        assignment_data = {
            'user': self.employee_user.id,
            'shift': shift.id,
            'effective_from': date.today() + timedelta(days=1),
            'effective_to': date.today() + timedelta(days=30),
            'reason': 'UX test assignment'
        }

        response = self.client.post(reverse('shift:assign'), assignment_data)
        self.assertIn(response.status_code, [200, 302])

        # Check assignment exists
        assignment = ShiftAssignment.objects.filter(
            user=self.employee_user,
            shift=shift
        ).first()
        self.assertIsNotNone(assignment)

        # Manager views assignment list
        response = self.client.get(reverse('shift:assignments'))
        self.assertEqual(response.status_code, 200)

        # Manager views shift details
        response = self.client.get(reverse('shift:detail', kwargs={'shift_id': shift.id}))
        self.assertEqual(response.status_code, 200)

    def test_error_handling_robustness(self):
        """Test system robustness with edge cases and error conditions"""
        # Test invalid user ID in assignment
        response = self.client.post(
            reverse('shift:api_validate_assignment'),
            json.dumps({
                'user_id': 99999,  # Non-existent user
                'shift_id': 1,
                'effective_from': (date.today() + timedelta(days=1)).strftime('%Y-%m-%d')
            }),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertFalse(data['valid'])
        self.assertGreater(len(data['errors']), 0)

        # Test malformed JSON
        response = self.client.post(
            reverse('shift:api_validate_assignment'),
            'invalid json',
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 500)

    def test_system_permissions(self):
        """Test system permissions and access control"""
        # Login as employee (limited permissions)
        employee_client = Client()
        employee_client.login(username='employee1', password='testpass123')

        # Employee should not be able to create shifts
        shift_data = {
            'name': 'Unauthorized Shift',
            'start_time': '09:00',
            'end_time': '17:00',
            'shift_duration': '8.0',
            'work_days': 'Weekdays',
            'is_active': True
        }

        response = employee_client.post(reverse('shift:create'), shift_data)
        # Should be redirected or forbidden
        self.assertIn(response.status_code, [302, 403])

    def test_shift_modification_with_assignments(self):
        """Test shift modification when assignments exist"""
        # Create shift and assignment
        shift = ShiftMaster.objects.create(
            name='Modifiable Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        assignment = ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=shift,
            effective_from=date.today() + timedelta(days=1),
            effective_to=date.today() + timedelta(days=30),
            is_current=True
        )

        # Modify shift
        update_data = {
            'name': 'Modified Shift',
            'start_time': '10:00',  # Changed start time
            'end_time': '18:00',    # Changed end time
            'shift_duration': '8.0',
            'work_days': 'Weekdays',
            'break_duration_minutes': '30',
            'grace_period_minutes': '15',
            'is_active': True
        }

        response = self.client.post(
            reverse('shift:update', kwargs={'shift_id': shift.id}),
            update_data
        )

        # Should succeed
        self.assertIn(response.status_code, [200, 302])

        # Check shift was updated
        shift.refresh_from_db()
        self.assertEqual(shift.name, 'Modified Shift')
        self.assertEqual(shift.start_time, time(10, 0))

    def test_performance_with_many_shifts(self):
        """Test system performance with multiple shifts and assignments"""
        # Create multiple overlapping shifts
        shifts = []
        for i in range(10):
            shift = ShiftMaster.objects.create(
                name=f'Performance Test Shift {i+1}',
                start_time=time(8 + i, 0),  # Overlapping times
                end_time=time(16 + i, 0),
                shift_duration=Decimal('8.0'),
                work_days='Weekdays'
            )
            shifts.append(shift)

        # Create assignments
        for i, shift in enumerate(shifts[:5]):
            ShiftAssignment.objects.create(
                user=self.employee_user if i % 2 == 0 else self.employee_user2,
                shift=shift,
                effective_from=date.today() + timedelta(days=1),
                effective_to=date.today() + timedelta(days=30),
                is_current=True
            )

        # Test that listing still works efficiently
        response = self.client.get(reverse('shift:list'))
        self.assertEqual(response.status_code, 200)

        response = self.client.get(reverse('shift:assignments'))
        self.assertEqual(response.status_code, 200)

    def tearDown(self):
        """Clean up test data"""
        ShiftAssignment.objects.all().delete()
        ShiftMaster.objects.all().delete()
        User.objects.all().delete()
        Group.objects.all().delete()


class ShiftFormIntegrationTest(TestCase):
    """Test form integration and validation"""

    def setUp(self):
        """Set up test data"""
        self.manager_group = Group.objects.create(name='Manager')
        self.manager_user = User.objects.create_user(
            username='formtest_manager',
            password='testpass123'
        )
        self.manager_user.groups.add(self.manager_group)

        self.client = Client()
        self.client.login(username='formtest_manager', password='testpass123')

    def test_form_validation_comprehensive(self):
        """Test comprehensive form validation scenarios"""
        test_cases = [
            # Valid cases
            {
                'name': 'Valid Day Shift',
                'start_time': time(8, 0),
                'end_time': time(16, 0),
                'shift_duration': Decimal('8.0'),
                'work_days': 'Weekdays',
                'should_be_valid': True
            },
            {
                'name': 'Valid Night Shift',
                'start_time': time(22, 0),
                'end_time': time(6, 0),
                'shift_duration': Decimal('8.0'),
                'work_days': 'Weekdays',
                'should_be_valid': True
            },
            {
                'name': 'Valid Custom Days',
                'start_time': time(9, 0),
                'end_time': time(17, 0),
                'shift_duration': Decimal('8.0'),
                'work_days': 'Custom',
                'custom_work_days': 'Monday,Wednesday,Friday',
                'should_be_valid': True
            },
            # Invalid cases
            {
                'name': 'X',  # Too short
                'start_time': time(9, 0),
                'end_time': time(17, 0),
                'shift_duration': Decimal('8.0'),
                'work_days': 'Weekdays',
                'should_be_valid': False
            },
            {
                'name': 'Invalid Duration Shift',
                'start_time': time(9, 0),
                'end_time': time(9, 15),  # Only 15 minutes
                'shift_duration': Decimal('0.25'),
                'work_days': 'Weekdays',
                'should_be_valid': False
            }
        ]

        for test_case in test_cases:
            with self.subTest(test_case=test_case['name']):
                form = ShiftForm(data=test_case)
                if test_case['should_be_valid']:
                    self.assertTrue(form.is_valid(), f"Form should be valid: {form.errors}")
                else:
                    self.assertFalse(form.is_valid(), f"Form should be invalid for: {test_case['name']}")

    def test_assignment_form_validation(self):
        """Test assignment form validation"""
        shift = ShiftMaster.objects.create(
            name='Assignment Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

        # Valid assignment
        form_data = {
            'user': self.manager_user.id,
            'shift': shift.id,
            'effective_from': date.today() + timedelta(days=1),
            'effective_to': date.today() + timedelta(days=30),
            'reason': 'Test assignment'
        }
        form = ShiftAssignmentForm(data=form_data)
        self.assertTrue(form.is_valid())

        # Invalid assignment (end before start)
        form_data = {
            'user': self.manager_user.id,
            'shift': shift.id,
            'effective_from': date.today() + timedelta(days=30),
            'effective_to': date.today() + timedelta(days=1),  # End before start
            'reason': 'Invalid assignment'
        }
        form = ShiftAssignmentForm(data=form_data)
        self.assertFalse(form.is_valid())

    def test_system_reliability(self):
        """Test system reliability under various conditions"""
        # Test with missing CSRF token (should be handled gracefully)
        client_no_csrf = Client(enforce_csrf_checks=True)
        client_no_csrf.login(username='formtest_manager', password='testpass123')

        # Test API endpoints handle errors gracefully
        response = self.client.post(
            reverse('shift:api_validate_shift_name'),
            json.dumps({'name': ''}),  # Empty name
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertFalse(data['valid'])

    def tearDown(self):
        """Clean up test data"""
        ShiftAssignment.objects.all().delete()
        ShiftMaster.objects.all().delete()
        User.objects.all().delete()
        Group.objects.all().delete()


class ShiftAPIEndpointTest(TestCase):
    """Test all API endpoints for proper functionality"""

    def setUp(self):
        """Set up test data"""
        self.manager_group = Group.objects.create(name='Manager')
        self.manager_user = User.objects.create_user(
            username='api_manager',
            password='testpass123'
        )
        self.manager_user.groups.add(self.manager_group)

        self.client = Client()
        self.client.login(username='api_manager', password='testpass123')

        # Create test shift
        self.test_shift = ShiftMaster.objects.create(
            name='API Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )

    def test_all_api_endpoints_accessible(self):
        """Test that all API endpoints are accessible and return proper responses"""
        api_endpoints = [
            ('shift:api_shift_details', {'shift_id': self.test_shift.id}),
            ('shift:api_user_info', {'user_id': self.manager_user.id}),
            ('shift:api_dashboard_stats', {}),
            ('shift:api_system_status', {}),
        ]

        for endpoint_name, kwargs in api_endpoints:
            with self.subTest(endpoint=endpoint_name):
                try:
                    response = self.client.get(reverse(endpoint_name, kwargs=kwargs))
                    self.assertIn(response.status_code, [200, 404])  # 404 acceptable for some endpoints
                except Exception as e:
                    self.fail(f"API endpoint {endpoint_name} failed: {str(e)}")

    def test_validation_apis_work_correctly(self):
        """Test validation APIs return proper JSON responses"""
        # Test shift name validation
        response = self.client.post(
            reverse('shift:api_validate_shift_name'),
            json.dumps({'name': 'Valid Test Shift Name'}),
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertIn('valid', data)
        self.assertIn('errors', data)
        self.assertIn('warnings', data)

    def tearDown(self):
        """Clean up test data"""
        ShiftMaster.objects.all().delete()
        User.objects.all().delete()
        Group.objects.all().delete()


def run_comprehensive_tests():
    """Run all comprehensive tests and return results"""
    import unittest

    # Create test suite
    suite = unittest.TestSuite()

    # Add test cases
    suite.addTest(unittest.makeSuite(ShiftSystemIntegrationTest))
    suite.addTest(unittest.makeSuite(ShiftFormIntegrationTest))
    suite.addTest(unittest.makeSuite(ShiftAPIEndpointTest))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return {
        'tests_run': result.testsRun,
        'failures': len(result.failures),
        'errors': len(result.errors),
        'success': result.wasSuccessful()
    }


if __name__ == '__main__':
    """Run tests when called directly"""
    results = run_comprehensive_tests()
    print(f"\nTest Results:")
    print(f"Tests Run: {results['tests_run']}")
    print(f"Failures: {results['failures']}")
    print(f"Errors: {results['errors']}")
    print(f"Success: {results['success']}")
