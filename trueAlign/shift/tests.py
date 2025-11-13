"""
Comprehensive Test Suite for Shift Management
"""

from django.test import TestCase
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import time, date, timedelta
from decimal import Decimal

from .models import ShiftMaster, ShiftAssignment, ShiftConflict, ShiftValidationRule
from .validators import ShiftAssignmentValidator, BulkAssignmentValidator
from .services import ShiftService, ShiftAssignmentService, ConflictDetectionService


class ShiftMasterTestCase(TestCase):
    """Test cases for ShiftMaster model"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
    
    def test_create_basic_shift(self):
        """Test creating a basic shift"""
        shift = ShiftMaster.objects.create(
            name='Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            created_by=self.user
        )
        
        self.assertEqual(shift.name, 'Test Shift')
        self.assertEqual(shift.shift_duration, Decimal('8.0'))
        self.assertFalse(shift.crosses_midnight)
        self.assertEqual(shift.shift_type, 'MORNING')
    
    def test_midnight_crossing_shift(self):
        """Test shift that crosses midnight"""
        shift = ShiftMaster.objects.create(
            name='Night Shift',
            start_time=time(22, 0),
            end_time=time(6, 0),
            created_by=self.user
        )
        
        self.assertTrue(shift.crosses_midnight)
        self.assertEqual(shift.shift_type, 'NIGHT')
        self.assertEqual(shift.shift_duration, Decimal('8.0'))
    
    def test_shift_validation(self):
        """Test shift validation"""
        # Test duplicate name
        ShiftMaster.objects.create(
            name='Duplicate Test',
            start_time=time(9, 0),
            end_time=time(17, 0)
        )
        
        with self.assertRaises(ValidationError):
            duplicate_shift = ShiftMaster(
                name='Duplicate Test',
                start_time=time(10, 0),
                end_time=time(18, 0)
            )
            duplicate_shift.full_clean()
    
    def test_working_days_list(self):
        """Test working days functionality"""
        # Test weekdays
        shift = ShiftMaster.objects.create(
            name='Weekday Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            work_days='WEEKDAYS'
        )
        self.assertEqual(shift.working_days_list, [0, 1, 2, 3, 4])
        
        # Test custom days
        shift.work_days = 'CUSTOM'
        shift.custom_work_days = 'Monday,Wednesday,Friday'
        shift.save()
        self.assertEqual(shift.working_days_list, [0, 2, 4])
    
    def test_expected_work_hours(self):
        """Test expected work hours calculation"""
        shift = ShiftMaster.objects.create(
            name='Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 30),
            shift_duration=Decimal('8.5'),
            break_duration=timedelta(minutes=30)
        )
        
        expected_hours = Decimal('8.0')  # 8.5 - 0.5 break
        self.assertEqual(shift.expected_work_hours, expected_hours)


class ShiftAssignmentTestCase(TestCase):
    """Test cases for ShiftAssignment model"""
    
    def setUp(self):
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='testpass123'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='testpass123'
        )
        
        self.shift = ShiftMaster.objects.create(
            name='Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            created_by=self.user1
        )
    
    def test_create_assignment(self):
        """Test creating a shift assignment"""
        assignment = ShiftAssignment.objects.create(
            user=self.user1,
            shift=self.shift,
            effective_from=date.today(),
            created_by=self.user2
        )
        
        self.assertEqual(assignment.user, self.user1)
        self.assertEqual(assignment.shift, self.shift)
        self.assertEqual(assignment.status, 'ACTIVE')
        self.assertTrue(assignment.is_current)
    
    def test_assignment_validation(self):
        """Test assignment validation"""
        # Test invalid date range
        with self.assertRaises(ValidationError):
            assignment = ShiftAssignment(
                user=self.user1,
                shift=self.shift,
                effective_from=date.today(),
                effective_to=date.today() - timedelta(days=1)
            )
            assignment.full_clean()
    
    def test_overlapping_assignments(self):
        """Test overlapping assignment detection"""
        # Create first assignment
        assignment1 = ShiftAssignment.objects.create(
            user=self.user1,
            shift=self.shift,
            effective_from=date.today(),
            effective_to=date.today() + timedelta(days=10)
        )
        
        # Try to create overlapping assignment
        with self.assertRaises(ValidationError):
            assignment2 = ShiftAssignment(
                user=self.user1,
                shift=self.shift,
                effective_from=date.today() + timedelta(days=5),
                effective_to=date.today() + timedelta(days=15)
            )
            assignment2.full_clean()
    
    def test_current_assignment_logic(self):
        """Test current assignment logic"""
        # Create first assignment
        assignment1 = ShiftAssignment.objects.create(
            user=self.user1,
            shift=self.shift,
            effective_from=date.today() - timedelta(days=5),
            is_current=True
        )
        
        # Create new current assignment
        assignment2 = ShiftAssignment.objects.create(
            user=self.user1,
            shift=self.shift,
            effective_from=date.today(),
            is_current=True
        )
        
        # First assignment should no longer be current
        assignment1.refresh_from_db()
        self.assertFalse(assignment1.is_current)
        self.assertIsNotNone(assignment1.effective_to)
    
    def test_get_user_current_shift(self):
        """Test getting user's current shift"""
        assignment = ShiftAssignment.objects.create(
            user=self.user1,
            shift=self.shift,
            effective_from=date.today() - timedelta(days=1),
            effective_to=date.today() + timedelta(days=5)
        )
        
        current_shift = ShiftAssignment.get_user_current_shift(self.user1)
        self.assertEqual(current_shift, self.shift)
        
        # Test with no assignment
        no_shift = ShiftAssignment.get_user_current_shift(self.user2)
        self.assertIsNotNone(no_shift)  # Should return default shift


class ShiftValidatorTestCase(TestCase):
    """Test cases for shift validators"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.shift = ShiftMaster.objects.create(
            name='Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0)
        )
    
    def test_assignment_validator(self):
        """Test shift assignment validator"""
        assignment = ShiftAssignment(
            user=self.user,
            shift=self.shift,
            effective_from=date.today()
        )
        
        validator = ShiftAssignmentValidator(assignment)
        warnings = validator.validate()  # Should not raise exception
        self.assertIsInstance(warnings, list)
    
    def test_bulk_assignment_validator(self):
        """Test bulk assignment validator"""
        assignments_data = [
            {
                'user_id': self.user.id,
                'shift_id': self.shift.id,
                'effective_from': date.today()
            }
        ]
        
        validator = BulkAssignmentValidator(assignments_data)
        warnings = validator.validate()  # Should not raise exception
        self.assertIsInstance(warnings, list)
    
    def test_invalid_bulk_data(self):
        """Test bulk validator with invalid data"""
        invalid_data = [
            {
                'user_id': 999,  # Non-existent user
                'shift_id': self.shift.id,
                'effective_from': date.today()
            }
        ]
        
        validator = BulkAssignmentValidator(invalid_data)
        with self.assertRaises(ValidationError):
            validator.validate()


class ShiftServiceTestCase(TestCase):
    """Test cases for shift services"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.shift = ShiftMaster.objects.create(
            name='Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0)
        )
    
    def test_create_shift_service(self):
        """Test shift creation service"""
        shift_data = {
            'name': 'Service Test Shift',
            'start_time': time(10, 0),
            'end_time': time(18, 0),
            'shift_type': 'MORNING'
        }
        
        shift = ShiftService.create_shift(shift_data, self.user)
        self.assertEqual(shift.name, 'Service Test Shift')
        self.assertEqual(shift.created_by, self.user)
    
    def test_duplicate_shift_service(self):
        """Test shift duplication service"""
        new_shift = ShiftService.duplicate_shift(
            self.shift.id,
            'Duplicated Shift',
            self.user
        )
        
        self.assertEqual(new_shift.name, 'Duplicated Shift')
        self.assertEqual(new_shift.start_time, self.shift.start_time)
        self.assertEqual(new_shift.end_time, self.shift.end_time)
        self.assertEqual(new_shift.created_by, self.user)
    
    def test_shift_utilization(self):
        """Test shift utilization calculation"""
        # Create some assignments
        ShiftAssignment.objects.create(
            user=self.user,
            shift=self.shift,
            effective_from=date.today() - timedelta(days=10),
            effective_to=date.today() - timedelta(days=5)
        )
        
        utilization = ShiftService.get_shift_utilization(
            self.shift.id,
            date.today() - timedelta(days=15),
            date.today()
        )
        
        self.assertIn('utilization_rate', utilization)
        self.assertIn('total_assignments', utilization)
        self.assertGreaterEqual(utilization['utilization_rate'], 0)


class ShiftAssignmentServiceTestCase(TestCase):
    """Test cases for shift assignment services"""
    
    def setUp(self):
        self.user1 = User.objects.create_user(
            username='user1',
            email='user1@example.com',
            password='testpass123'
        )
        self.user2 = User.objects.create_user(
            username='user2',
            email='user2@example.com',
            password='testpass123'
        )
        
        self.shift1 = ShiftMaster.objects.create(
            name='Shift 1',
            start_time=time(9, 0),
            end_time=time(17, 0)
        )
        self.shift2 = ShiftMaster.objects.create(
            name='Shift 2',
            start_time=time(14, 0),
            end_time=time(22, 0)
        )
    
    def test_create_assignment_service(self):
        """Test assignment creation service"""
        assignment_data = {
            'user': self.user1,
            'shift': self.shift1,
            'effective_from': date.today(),
            'notes': 'Test assignment'
        }
        
        result = ShiftAssignmentService.create_assignment(assignment_data, self.user2)
        
        self.assertIn('assignment', result)
        self.assertIn('warnings', result)
        self.assertIn('conflicts', result)
        
        assignment = result['assignment']
        self.assertEqual(assignment.user, self.user1)
        self.assertEqual(assignment.shift, self.shift1)
        self.assertEqual(assignment.created_by, self.user2)
    
    def test_bulk_create_assignments(self):
        """Test bulk assignment creation"""
        assignments_data = [
            {
                'user_id': self.user1.id,
                'shift_id': self.shift1.id,
                'effective_from': date.today(),
                'notes': 'Bulk assignment 1'
            },
            {
                'user_id': self.user2.id,
                'shift_id': self.shift2.id,
                'effective_from': date.today(),
                'notes': 'Bulk assignment 2'
            }
        ]
        
        result = ShiftAssignmentService.bulk_create_assignments(
            assignments_data, self.user1
        )
        
        self.assertIn('assignments', result)
        self.assertEqual(len(result['assignments']), 2)
    
    def test_reassign_shift(self):
        """Test shift reassignment"""
        # Create initial assignment
        assignment = ShiftAssignment.objects.create(
            user=self.user1,
            shift=self.shift1,
            effective_from=date.today() - timedelta(days=5),
            created_by=self.user2
        )
        
        # Reassign to different shift
        result = ShiftAssignmentService.reassign_shift(
            assignment.id,
            self.shift2.id,
            date.today(),
            "Better fit for user"
        )
        
        # Check old assignment ended
        assignment.refresh_from_db()
        self.assertIsNotNone(assignment.effective_to)
        self.assertFalse(assignment.is_current)
        
        # Check new assignment created
        new_assignment = result['assignment']
        self.assertEqual(new_assignment.shift, self.shift2)
        self.assertEqual(new_assignment.user, self.user1)
    
    def test_user_shift_timeline(self):
        """Test user shift timeline"""
        # Create multiple assignments
        ShiftAssignment.objects.create(
            user=self.user1,
            shift=self.shift1,
            effective_from=date.today() - timedelta(days=30),
            effective_to=date.today() - timedelta(days=15)
        )
        
        ShiftAssignment.objects.create(
            user=self.user1,
            shift=self.shift2,
            effective_from=date.today() - timedelta(days=10),
            effective_to=date.today() + timedelta(days=10)
        )
        
        timeline = ShiftAssignmentService.get_user_shift_timeline(self.user1.id)
        
        self.assertGreaterEqual(len(timeline), 2)
        for item in timeline:
            self.assertIn('assignment', item)
            self.assertIn('start_date', item)
            self.assertIn('end_date', item)


class ConflictDetectionTestCase(TestCase):
    """Test cases for conflict detection"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.shift = ShiftMaster.objects.create(
            name='Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            min_rest_hours=Decimal('8.0')
        )
    
    def test_overlap_conflict_detection(self):
        """Test overlap conflict detection"""
        # Create first assignment
        assignment1 = ShiftAssignment.objects.create(
            user=self.user,
            shift=self.shift,
            effective_from=date.today(),
            effective_to=date.today() + timedelta(days=10)
        )
        
        # Create overlapping assignment
        assignment2 = ShiftAssignment(
            user=self.user,
            shift=self.shift,
            effective_from=date.today() + timedelta(days=5),
            effective_to=date.today() + timedelta(days=15)
        )
        
        conflicts = ConflictDetectionService.detect_conflicts(assignment2)
        self.assertGreater(len(conflicts), 0)
        
        overlap_conflicts = [c for c in conflicts if c.conflict_type == 'OVERLAP']
        self.assertGreater(len(overlap_conflicts), 0)
    
    def test_conflict_resolution(self):
        """Test conflict resolution"""
        assignment = ShiftAssignment.objects.create(
            user=self.user,
            shift=self.shift,
            effective_from=date.today()
        )
        
        conflict = ShiftConflict.objects.create(
            assignment=assignment,
            conflict_type='OVERLAP',
            severity='HIGH',
            description='Test conflict'
        )
        
        resolved_conflict = ConflictDetectionService.resolve_conflict(
            conflict.id,
            self.user,
            'Resolved for testing'
        )
        
        self.assertTrue(resolved_conflict.is_resolved)
        self.assertEqual(resolved_conflict.resolved_by, self.user)
        self.assertIsNotNone(resolved_conflict.resolved_at)


class APITestCase(TestCase):
    """Test cases for API endpoints"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.shift = ShiftMaster.objects.create(
            name='API Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0)
        )
    
    def test_shift_list_endpoint(self):
        """Test shift list API endpoint"""
        self.client.force_login(self.user)
        response = self.client.get('/shift/api/shifts/')
        
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn('results', data)
    
    def test_assignment_creation_endpoint(self):
        """Test assignment creation API endpoint"""
        self.client.force_login(self.user)
        
        assignment_data = {
            'user': self.user.id,
            'shift': self.shift.id,
            'effective_from': date.today().isoformat(),
            'notes': 'API test assignment'
        }
        
        response = self.client.post(
            '/shift/api/assignments/',
            data=assignment_data,
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertEqual(data['user'], self.user.id)
        self.assertEqual(data['shift'], self.shift.id)
