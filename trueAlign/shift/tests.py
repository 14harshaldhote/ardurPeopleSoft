import json
import tempfile
from datetime import datetime, date, time, timedelta
from decimal import Decimal
from django.test import TestCase, Client, override_settings
from django.contrib.auth.models import User, Group
from django.core.files.uploadedfile import SimpleUploadedFile
from django.urls import reverse
from django.utils import timezone
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
from trueAlign.shift.services import ShiftService
from trueAlign.shift.forms import (
    ShiftForm, ShiftAssignmentForm, BulkAssignmentForm,
    HolidayForm, CSVUploadForm
)


class ShiftTestBase(TestCase):
    """Base test class with common setup for shift tests."""

    def setUp(self):
        """Set up test data."""
        # Create groups
        self.manager_group = Group.objects.create(name='Manager')
        self.employee_group = Group.objects.create(name='Employee')
        self.hr_group = Group.objects.create(name='HR')

        # Create users
        self.manager_user = User.objects.create_user(
            username='manager',
            email='manager@test.com',
            password='testpass123',
            first_name='Test',
            last_name='Manager'
        )
        self.manager_user.groups.add(self.manager_group)

        self.employee_user = User.objects.create_user(
            username='employee',
            email='employee@test.com',
            password='testpass123',
            first_name='Test',
            last_name='Employee'
        )
        self.employee_user.groups.add(self.employee_group)

        self.hr_user = User.objects.create_user(
            username='hr',
            email='hr@test.com',
            password='testpass123',
            first_name='Test',
            last_name='HR'
        )
        self.hr_user.groups.add(self.hr_group)

        self.superuser = User.objects.create_superuser(
            username='admin',
            email='admin@test.com',
            password='adminpass123'
        )

        # Create test shifts
        self.day_shift = ShiftMaster.objects.create(
            name='Day Shift',
            start_time=time(9, 0),
            end_time=time(17, 30),
            shift_duration=Decimal('8.5'),
            break_duration=timedelta(minutes=30),
            grace_period=timedelta(minutes=15),
            work_days='Weekdays',
            is_active=True
        )

        self.night_shift = ShiftMaster.objects.create(
            name='Night Shift',
            start_time=time(22, 0),
            end_time=time(6, 0),
            shift_duration=Decimal('8.0'),
            break_duration=timedelta(minutes=30),
            grace_period=timedelta(minutes=15),
            work_days='All Days',
            is_active=True
        )

        # Create test holiday
        self.holiday = Holiday.objects.create(
            name='Test Holiday',
            date=date.today() + timedelta(days=30),
            recurring_yearly=True
        )

        # Initialize service
        self.shift_service = ShiftService()

        # Initialize client
        self.client = Client()


class ShiftMasterModelTest(ShiftTestBase):
    """Test ShiftMaster model functionality."""

    def test_shift_creation(self):
        """Test basic shift creation."""
        shift = ShiftMaster.objects.create(
            name='Test Shift',
            start_time=time(8, 0),
            end_time=time(16, 0),
            shift_duration=Decimal('8.0')
        )
        self.assertEqual(shift.name, 'Test Shift')
        self.assertTrue(shift.is_active)

    def test_crosses_midnight_property(self):
        """Test midnight crossing detection."""
        # Regular shift (doesn't cross midnight)
        self.assertFalse(self.day_shift.crosses_midnight)

        # Night shift (crosses midnight)
        self.assertTrue(self.night_shift.crosses_midnight)

    def test_working_days_list_property(self):
        """Test working days list generation."""
        # Weekdays shift
        self.assertEqual(self.day_shift.working_days_list, [0, 1, 2, 3, 4])

        # All days shift
        self.assertEqual(self.night_shift.working_days_list, [0, 1, 2, 3, 4, 5])

    def test_custom_working_days(self):
        """Test custom working days functionality."""
        custom_shift = ShiftMaster.objects.create(
            name='Custom Shift',
            start_time=time(10, 0),
            end_time=time(18, 0),
            shift_duration=Decimal('8.0'),
            work_days='Custom',
            custom_work_days='Monday,Wednesday,Friday'
        )
        self.assertEqual(custom_shift.working_days_list, [0, 2, 4])

    def test_is_working_day(self):
        """Test working day check."""
        # Test with a Monday (weekday 0)
        monday = date(2024, 1, 1)  # This is a Monday
        self.assertTrue(self.day_shift.is_working_day(monday))

        # Test with a Sunday (weekday 6)
        sunday = date(2024, 1, 7)  # This is a Sunday
        self.assertFalse(self.day_shift.is_working_day(sunday))

    def test_expected_hours_calculation(self):
        """Test expected hours calculation."""
        expected_hours = self.day_shift.expected_hours()
        # 8.5 hours - 0.5 hours break = 8.0 hours
        self.assertEqual(expected_hours, 8.0)

    def test_shift_string_representation(self):
        """Test string representation of shift."""
        expected = f"{self.day_shift.name} (09:00 - 17:30)"
        self.assertEqual(str(self.day_shift), expected)


class ShiftAssignmentModelTest(ShiftTestBase):
    """Test ShiftAssignment model functionality."""

    def test_assignment_creation(self):
        """Test basic assignment creation."""
        assignment = ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            is_current=True
        )
        self.assertEqual(assignment.user, self.employee_user)
        self.assertEqual(assignment.shift, self.day_shift)
        self.assertTrue(assignment.is_current)

    def test_is_active_on_method(self):
        """Test is_active_on method."""
        assignment = ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            effective_to=date.today() + timedelta(days=30)
        )

        # Should be active today
        self.assertTrue(assignment.is_active_on(date.today()))

        # Should not be active before start date
        self.assertFalse(assignment.is_active_on(date.today() - timedelta(days=1)))

        # Should not be active after end date
        self.assertFalse(assignment.is_active_on(date.today() + timedelta(days=31)))

    def test_days_remaining_method(self):
        """Test days remaining calculation."""
        assignment = ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            effective_to=date.today() + timedelta(days=10)
        )

        days_remaining = assignment.days_remaining()
        self.assertEqual(days_remaining, 10)

    def test_has_ended_method(self):
        """Test has_ended method."""
        # Assignment that has ended
        ended_assignment = ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today() - timedelta(days=10),
            effective_to=date.today() - timedelta(days=1)
        )
        self.assertTrue(ended_assignment.has_ended())

        # Current assignment
        current_assignment = ShiftAssignment.objects.create(
            user=self.manager_user,
            shift=self.day_shift,
            effective_from=date.today(),
            effective_to=date.today() + timedelta(days=10)
        )
        self.assertFalse(current_assignment.has_ended())

    def test_get_user_current_shift(self):
        """Test getting user's current shift."""
        # Create assignment
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            is_current=True
        )

        current_shift = ShiftAssignment.get_user_current_shift(self.employee_user)
        self.assertEqual(current_shift, self.day_shift)

    def test_automatic_deactivation_on_new_assignment(self):
        """Test that old assignments are deactivated when new one is created."""
        # Create first assignment
        assignment1 = ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            is_current=True
        )

        # Create second assignment
        assignment2 = ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.night_shift,
            effective_from=date.today() + timedelta(days=1),
            is_current=True
        )

        # Refresh first assignment
        assignment1.refresh_from_db()

        # First assignment should be deactivated
        self.assertFalse(assignment1.is_current)
        self.assertEqual(assignment1.effective_to, date.today())


class HolidayModelTest(ShiftTestBase):
    """Test Holiday model functionality."""

    def test_holiday_creation(self):
        """Test basic holiday creation."""
        holiday = Holiday.objects.create(
            name='New Year',
            date=date(2024, 1, 1),
            recurring_yearly=True
        )
        self.assertEqual(holiday.name, 'New Year')
        self.assertTrue(holiday.recurring_yearly)

    def test_is_holiday_class_method(self):
        """Test is_holiday class method."""
        # Test exact date match
        self.assertTrue(Holiday.is_holiday(self.holiday.date))

        # Test recurring yearly match
        next_year_date = date(self.holiday.date.year + 1,
                             self.holiday.date.month,
                             self.holiday.date.day)
        self.assertTrue(Holiday.is_holiday(next_year_date))

        # Test non-holiday date
        self.assertFalse(Holiday.is_holiday(date.today() + timedelta(days=1)))

    def test_holiday_string_representation(self):
        """Test string representation of holiday."""
        expected = f"{self.holiday.name} ({self.holiday.date.strftime('%d-%b')})"
        self.assertEqual(str(self.holiday), expected)


class ShiftServiceTest(ShiftTestBase):
    """Test ShiftService functionality."""

    def test_get_all_shifts(self):
        """Test getting all shifts."""
        shifts_data = self.shift_service.get_all_shifts()

        self.assertIsInstance(shifts_data, dict)
        self.assertIn('shifts', shifts_data)
        self.assertIn('pagination', shifts_data)
        self.assertEqual(len(shifts_data['shifts']), 2)  # day_shift and night_shift

    def test_get_shift_by_id(self):
        """Test getting shift by ID."""
        shift = self.shift_service.get_shift_by_id(self.day_shift.id)
        self.assertEqual(shift, self.day_shift)

        # Test non-existent ID
        non_existent = self.shift_service.get_shift_by_id(9999)
        self.assertIsNone(non_existent)

    def test_get_shift_by_name(self):
        """Test getting shift by name."""
        shift = self.shift_service.get_shift_by_name('Day Shift')
        self.assertEqual(shift, self.day_shift)

        # Test non-existent name
        non_existent = self.shift_service.get_shift_by_name('Non-existent Shift')
        self.assertIsNone(non_existent)

    def test_create_shift(self):
        """Test shift creation through service."""
        shift_data = {
            'name': 'Evening Shift',
            'start_time': time(14, 0),
            'end_time': time(22, 0),
            'shift_duration': Decimal('8.0'),
            'work_days': 'Weekdays',
            'is_active': True
        }

        success, result = self.shift_service.create_shift(shift_data)

        self.assertTrue(success)
        self.assertIsInstance(result, ShiftMaster)
        self.assertEqual(result.name, 'Evening Shift')

    def test_create_shift_duplicate_name(self):
        """Test creating shift with duplicate name."""
        shift_data = {
            'name': 'Day Shift',  # Already exists
            'start_time': time(8, 0),
            'end_time': time(16, 0),
            'shift_duration': Decimal('8.0')
        }

        success, result = self.shift_service.create_shift(shift_data)

        self.assertFalse(success)
        self.assertIn('already exists', result)

    def test_update_shift(self):
        """Test shift update through service."""
        update_data = {
            'name': 'Updated Day Shift',
            'start_time': time(8, 30),
        }

        success, result = self.shift_service.update_shift(self.day_shift.id, update_data)

        self.assertTrue(success)
        self.assertEqual(result.name, 'Updated Day Shift')
        self.assertEqual(result.start_time, time(8, 30))

    def test_assign_shift_to_user(self):
        """Test assigning shift to user."""
        success, result = self.shift_service.assign_shift_to_user(
            self.employee_user.id,
            self.day_shift.id,
            date.today()
        )

        self.assertTrue(success)
        self.assertIsInstance(result, ShiftAssignment)
        self.assertEqual(result.user, self.employee_user)
        self.assertEqual(result.shift, self.day_shift)

    def test_assign_shifts_to_users(self):
        """Test bulk assignment to multiple users."""
        user_ids = [self.employee_user.id, self.manager_user.id]

        success_count, error_count, errors = self.shift_service.assign_shifts_to_users(
            user_ids,
            self.day_shift.id,
            date.today()
        )

        self.assertEqual(success_count, 2)
        self.assertEqual(error_count, 0)
        self.assertEqual(len(errors), 0)

    def test_validate_shift_assignment(self):
        """Test shift assignment validation."""
        # Valid assignment
        is_valid, message = self.shift_service.validate_shift_assignment(
            self.employee_user.id,
            self.day_shift.id,
            date.today()
        )
        self.assertTrue(is_valid)

    def test_get_current_shift(self):
        """Test getting current shift for user."""
        # Create assignment
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            is_current=True
        )

        current_shift = self.shift_service.get_current_shift(self.employee_user)
        self.assertEqual(current_shift, self.day_shift)

    def test_is_working_day_for_user(self):
        """Test checking if date is working day for user."""
        # Create assignment
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            is_current=True
        )

        # Test with Monday (should be working day for weekdays shift)
        monday = date(2024, 1, 1)
        is_working = self.shift_service.is_working_day_for_user(self.employee_user, monday)
        self.assertTrue(is_working)

    def test_is_user_on_shift_now(self):
        """Test checking if user is currently on shift."""
        # Create assignment
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            is_current=True
        )

        shift_status = self.shift_service.is_user_on_shift_now(self.employee_user)

        self.assertIsInstance(shift_status, dict)
        self.assertIn('on_shift', shift_status)
        self.assertIn('shift', shift_status)

    def test_get_shift_statistics(self):
        """Test getting shift statistics."""
        stats = self.shift_service.get_shift_statistics()

        self.assertIsInstance(stats, dict)
        self.assertIn('overview', stats)
        self.assertIn('users', stats)
        self.assertIn('shift_distribution', stats)

    def test_create_holiday(self):
        """Test creating holiday through service."""
        holiday_data = {
            'name': 'Service Holiday',
            'date': date.today() + timedelta(days=60),
            'recurring_yearly': False
        }

        success, result = self.shift_service.create_holiday(holiday_data)

        self.assertTrue(success)
        self.assertIsInstance(result, Holiday)
        self.assertEqual(result.name, 'Service Holiday')

    def test_assign_shifts_from_csv(self):
        """Test CSV import functionality."""
        csv_content = """username,shift_name,effective_from,effective_to
employee,Day Shift,2024-01-01,2024-12-31
manager,Night Shift,2024-01-01,"""

        csv_file = SimpleUploadedFile(
            "test.csv",
            csv_content.encode('utf-8'),
            content_type="text/csv"
        )

        results = self.shift_service.assign_shifts_from_csv(csv_file)

        self.assertTrue(results['success'])
        self.assertEqual(results['success_count'], 2)
        self.assertEqual(results['error_count'], 0)


class ShiftFormTest(ShiftTestBase):
    """Test ShiftForm functionality."""

    def test_valid_form(self):
        """Test valid form submission."""
        form_data = {
            'name': 'Test Form Shift',
            'start_time': '09:00',
            'end_time': '17:00',
            'shift_duration': '8.0',
            'break_duration_minutes': 30,
            'grace_period_minutes': 15,
            'work_days': 'Weekdays',
            'is_active': True
        }

        form = ShiftForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_duplicate_name_validation(self):
        """Test duplicate name validation."""
        form_data = {
            'name': 'Day Shift',  # Already exists
            'start_time': '08:00',
            'end_time': '16:00',
            'shift_duration': '8.0',
            'break_duration_minutes': 30,
            'grace_period_minutes': 15,
            'work_days': 'Weekdays',
            'is_active': True
        }

        form = ShiftForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('name', form.errors)

    def test_invalid_duration_validation(self):
        """Test invalid duration validation."""
        form_data = {
            'name': 'Invalid Duration Shift',
            'start_time': '09:00',
            'end_time': '17:00',
            'shift_duration': '25.0',  # Invalid - over 24 hours
            'break_duration_minutes': 30,
            'grace_period_minutes': 15,
            'work_days': 'Weekdays',
            'is_active': True
        }

        form = ShiftForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('shift_duration', form.errors)

    def test_custom_work_days_validation(self):
        """Test custom work days validation."""
        # Valid custom work days
        form_data = {
            'name': 'Custom Days Shift',
            'start_time': '09:00',
            'end_time': '17:00',
            'shift_duration': '8.0',
            'break_duration_minutes': 30,
            'grace_period_minutes': 15,
            'work_days': 'Custom',
            'custom_work_days': 'Monday,Wednesday,Friday',
            'is_active': True
        }

        form = ShiftForm(data=form_data)
        self.assertTrue(form.is_valid())

        # Invalid custom work days
        form_data['custom_work_days'] = 'InvalidDay,Monday'
        form = ShiftForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('custom_work_days', form.errors)


class ShiftAssignmentFormTest(ShiftTestBase):
    """Test ShiftAssignmentForm functionality."""

    def test_valid_assignment_form(self):
        """Test valid assignment form."""
        form_data = {
            'user': self.employee_user.id,
            'shift': self.day_shift.id,
            'effective_from': date.today(),
            'effective_to': date.today() + timedelta(days=30)
        }

        form = ShiftAssignmentForm(data=form_data)
        self.assertTrue(form.is_valid())

    def test_past_date_validation(self):
        """Test past date validation."""
        form_data = {
            'user': self.employee_user.id,
            'shift': self.day_shift.id,
            'effective_from': date.today() - timedelta(days=1),  # Past date
            'effective_to': date.today() + timedelta(days=30)
        }

        form = ShiftAssignmentForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('effective_from', form.errors)

    def test_date_range_validation(self):
        """Test date range validation."""
        form_data = {
            'user': self.employee_user.id,
            'shift': self.day_shift.id,
            'effective_from': date.today() + timedelta(days=10),
            'effective_to': date.today() + timedelta(days=5)  # Before start date
        }

        form = ShiftAssignmentForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('effective_to', form.errors)


class CSVUploadFormTest(ShiftTestBase):
    """Test CSVUploadForm functionality."""

    def test_valid_csv_file(self):
        """Test valid CSV file upload."""
        csv_content = """username,shift_name,effective_from,effective_to
employee,Day Shift,2024-01-01,2024-12-31"""

        csv_file = SimpleUploadedFile(
            "test.csv",
            csv_content.encode('utf-8'),
            content_type="text/csv"
        )

        form = CSVUploadForm(files={'csv_file': csv_file})
        self.assertTrue(form.is_valid())

    def test_invalid_file_type(self):
        """Test invalid file type."""
        txt_file = SimpleUploadedFile(
            "test.txt",
            b"This is not a CSV file",
            content_type="text/plain"
        )

        form = CSVUploadForm(files={'csv_file': txt_file})
        self.assertFalse(form.is_valid())
        self.assertIn('csv_file', form.errors)

    def test_missing_headers(self):
        """Test CSV with missing required headers."""
        csv_content = """username,shift_name
employee,Day Shift"""

        csv_file = SimpleUploadedFile(
            "test.csv",
            csv_content.encode('utf-8'),
            content_type="text/csv"
        )

        form = CSVUploadForm(files={'csv_file': csv_file})
        self.assertFalse(form.is_valid())
        self.assertIn('csv_file', form.errors)

    def test_empty_csv_file(self):
        """Test empty CSV file."""
        csv_file = SimpleUploadedFile(
            "empty.csv",
            b"",
            content_type="text/csv"
        )

        form = CSVUploadForm(files={'csv_file': csv_file})
        self.assertFalse(form.is_valid())
        self.assertIn('csv_file', form.errors)


class ShiftViewTest(ShiftTestBase):
    """Test shift management views."""

    def test_dashboard_access(self):
        """Test dashboard access with different user types."""
        # Manager access
        self.client.login(username='manager', password='testpass123')
        response = self.client.get(reverse('shift:dashboard'))
        self.assertEqual(response.status_code, 200)

        # Employee access
        self.client.login(username='employee', password='testpass123')
        response = self.client.get(reverse('shift:dashboard'))
        self.assertEqual(response.status_code, 200)

        # HR access
        self.client.login(username='hr', password='testpass123')
        response = self.client.get(reverse('shift:dashboard'))
        self.assertEqual(response.status_code, 200)

        # Unauthenticated access should redirect
        self.client.logout()
        response = self.client.get(reverse('shift:dashboard'))
        self.assertEqual(response.status_code, 302)

    def test_shift_list_view(self):
        """Test shift list view."""
        self.client.login(username='manager', password='testpass123')
        response = self.client.get(reverse('shift:list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Day Shift')
        self.assertContains(response, 'Night Shift')

    def test_shift_detail_view(self):
        """Test shift detail view."""
        self.client.login(username='manager', password='testpass123')
        response = self.client.get(reverse('shift:detail', kwargs={'shift_id': self.day_shift.id}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.day_shift.name)

    def test_create_shift_view_manager(self):
        """Test shift creation by manager."""
        self.client.login(username='manager', password='testpass123')

        # GET request
        response = self.client.get(reverse('shift:create'))
        self.assertEqual(response.status_code, 200)

        # POST request
        form_data = {
            'name': 'Test View Shift',
            'start_time': '10:00',
            'end_time': '18:00',
            'shift_duration': '8.0',
            'break_duration_minutes': 30,
            'grace_period_minutes': 15,
            'work_days': 'Weekdays',
            'is_active': True
        }

        response = self.client.post(reverse('shift:create'), data=form_data)
        self.assertEqual(response.status_code, 302)  # Redirect on success

        # Verify shift was created
        self.assertTrue(ShiftMaster.objects.filter(name='Test View Shift').exists())

    def test_create_shift_view_employee_denied(self):
        """Test that employees cannot create shifts."""
        self.client.login(username='employee', password='testpass123')
        response = self.client.get(reverse('shift:create'))
        self.assertEqual(response.status_code, 302)  # Redirect due to permission denial

    def test_update_shift_view(self):
        """Test shift update view."""
        self.client.login(username='manager', password='testpass123')

        # GET request
        response = self.client.get(reverse('shift:update', kwargs={'shift_id': self.day_shift.id}))
        self.assertEqual(response.status_code, 200)

        # POST request
        form_data = {
            'name': 'Updated Day Shift',
            'start_time': '08:30',
            'end_time': '17:30',
            'shift_duration': '9.0',
            'break_duration_minutes': 30,
            'grace_period_minutes': 15,
            'work_days': 'Weekdays',
            'is_active': True
        }

        response = self.client.post(reverse('shift:update', kwargs={'shift_id': self.day_shift.id}), data=form_data)
        self.assertEqual(response.status_code, 302)

        # Verify shift was updated
        self.day_shift.refresh_from_db()
        self.assertEqual(self.day_shift.name, 'Updated Day Shift')

    def test_delete_shift_view(self):
        """Test shift deletion view."""
        self.client.login(username='manager', password='testpass123')

        # Create a shift to delete
        test_shift = ShiftMaster.objects.create(
            name='To Delete',
            start_time=time(12, 0),
            end_time=time(20, 0),
            shift_duration=Decimal('8.0')
        )

        response = self.client.post(reverse('shift:delete', kwargs={'shift_id': test_shift.id}))
        self.assertEqual(response.status_code, 302)

        # Verify shift was deleted
        self.assertFalse(ShiftMaster.objects.filter(id=test_shift.id).exists())

    def test_assignment_list_view(self):
        """Test assignment list view."""
        # Create test assignment
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            is_current=True
        )

        self.client.login(username='manager', password='testpass123')
        response = self.client.get(reverse('shift:assignments'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.employee_user.username)

    def test_assign_shift_view(self):
        """Test shift assignment view."""
        self.client.login(username='manager', password='testpass123')

        # GET request
        response = self.client.get(reverse('shift:assign'))
        self.assertEqual(response.status_code, 200)

        # POST request
        form_data = {
            'user': self.employee_user.id,
            'shift': self.day_shift.id,
            'effective_from': date.today().strftime('%Y-%m-%d'),
            'effective_to': (date.today() + timedelta(days=30)).strftime('%Y-%m-%d')
        }

        response = self.client.post(reverse('shift:assign'), data=form_data)
        self.assertEqual(response.status_code, 302)

        # Verify assignment was created
        self.assertTrue(ShiftAssignment.objects.filter(
            user=self.employee_user,
            shift=self.day_shift
        ).exists())

    def test_bulk_assign_view(self):
        """Test bulk assignment view."""
        self.client.login(username='manager', password='testpass123')

        # GET request
        response = self.client.get(reverse('shift:bulk_assign'))
        self.assertEqual(response.status_code, 200)

        # POST request
        form_data = {
            'users': [self.employee_user.id, self.hr_user.id],
            'shift': self.day_shift.id,
            'effective_from': date.today().strftime('%Y-%m-%d')
        }

        response = self.client.post(reverse('shift:bulk_assign'), data=form_data)
        self.assertEqual(response.status_code, 302)

        # Verify assignments were created
        self.assertEqual(ShiftAssignment.objects.filter(shift=self.day_shift).count(), 2)

    def test_csv_upload_view(self):
        """Test CSV upload view."""
        self.client.login(username='manager', password='testpass123')

        # GET request
        response = self.client.get(reverse('shift:csv_upload'))
        self.assertEqual(response.status_code, 200)

        # POST request with valid CSV
        csv_content = """username,shift_name,effective_from
employee,Day Shift,2024-01-01
hr,Night Shift,2024-01-01"""

        csv_file = SimpleUploadedFile(
            "assignments.csv",
            csv_content.encode('utf-8'),
            content_type="text/csv"
        )

        response = self.client.post(reverse('shift:csv_upload'), {'csv_file': csv_file})
        self.assertEqual(response.status_code, 302)

    def test_user_calendar_view(self):
        """Test user calendar view."""
        # Create assignment
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            is_current=True
        )

        self.client.login(username='employee', password='testpass123')
        response = self.client.get(reverse('shift:user_calendar'))
        self.assertEqual(response.status_code, 200)

        # Test with specific month/year
        response = self.client.get(reverse('shift:user_calendar'), {
            'month': '1',
            'year': '2024'
        })
        self.assertEqual(response.status_code, 200)

    def test_schedule_view(self):
        """Test schedule view (managers only)."""
        self.client.login(username='manager', password='testpass123')
        response = self.client.get(reverse('shift:schedule'))
        self.assertEqual(response.status_code, 200)

        # Test with specific date
        response = self.client.get(reverse('shift:schedule'), {
            'date': '2024-01-01'
        })
        self.assertEqual(response.status_code, 200)

    def test_holiday_list_view(self):
        """Test holiday list view."""
        self.client.login(username='manager', password='testpass123')
        response = self.client.get(reverse('shift:holidays'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.holiday.name)

    def test_create_holiday_view(self):
        """Test holiday creation view."""
        self.client.login(username='manager', password='testpass123')

        # GET request
        response = self.client.get(reverse('shift:create_holiday'))
        self.assertEqual(response.status_code, 200)

        # POST request
        form_data = {
            'name': 'Test Holiday',
            'date': '2024-07-04',
            'recurring_yearly': True
        }

        response = self.client.post(reverse('shift:create_holiday'), data=form_data)
        self.assertEqual(response.status_code, 302)

        # Verify holiday was created
        self.assertTrue(Holiday.objects.filter(name='Test Holiday').exists())


class ShiftAPITest(ShiftTestBase):
    """Test shift API endpoints."""

    def test_api_shift_details(self):
        """Test shift details API."""
        self.client.login(username='manager', password='testpass123')
        response = self.client.get(reverse('shift:api_shift_details', kwargs={'shift_id': self.day_shift.id}))

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['data']['name'], self.day_shift.name)

    def test_api_user_assignments(self):
        """Test user assignments API."""
        # Create assignment
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            is_current=True
        )

        self.client.login(username='manager', password='testpass123')
        response = self.client.get(reverse('shift:api_user_assignments', kwargs={'user_id': self.employee_user.id}))

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertEqual(data['data']['user']['username'], self.employee_user.username)

    def test_api_user_shift_status(self):
        """Test user shift status API."""
        # Create assignment
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            is_current=True
        )

        self.client.login(username='employee', password='testpass123')
        response = self.client.get(reverse('shift:api_user_shift_status'))

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertIn('on_shift', data['data'])

    def test_api_upcoming_changes(self):
        """Test upcoming changes API."""
        # Create assignment ending soon
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            effective_to=date.today() + timedelta(days=3),
            is_current=True
        )

        self.client.login(username='manager', password='testpass123')
        response = self.client.get(reverse('shift:api_upcoming_changes'))

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertIsInstance(data['data'], list)

    def test_api_schedule_for_date(self):
        """Test schedule for date API."""
        self.client.login(username='manager', password='testpass123')
        response = self.client.get(reverse('shift:api_schedule_for_date'), {
            'date': '2024-01-01'
        })

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertIn('shifts', data['data'])

    def test_api_is_holiday(self):
        """Test is holiday API."""
        self.client.login(username='employee', password='testpass123')

        # Test with holiday date
        response = self.client.get(reverse('shift:api_is_holiday'), {
            'date': self.holiday.date.strftime('%Y-%m-%d')
        })

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'success')
        self.assertTrue(data['data']['is_holiday'])

    def test_api_permission_denied(self):
        """Test API permission restrictions."""
        # Employee trying to access manager-only API
        self.client.login(username='employee', password='testpass123')
        response = self.client.get(reverse('shift:api_upcoming_changes'))

        self.assertEqual(response.status_code, 302)  # Redirect due to permission denial

    def test_api_invalid_parameters(self):
        """Test API with invalid parameters."""
        self.client.login(username='manager', password='testpass123')

        # Invalid date format
        response = self.client.get(reverse('shift:api_schedule_for_date'), {
            'date': 'invalid-date'
        })

        self.assertEqual(response.status_code, 400)
        data = json.loads(response.content)
        self.assertEqual(data['status'], 'error')


class ShiftPermissionTest(ShiftTestBase):
    """Test permission system for shift management."""

    def test_manager_permissions(self):
        """Test manager permissions."""
        self.client.login(username='manager', password='testpass123')

        # Managers can access all views
        urls_to_test = [
            'shift:dashboard',
            'shift:list',
            'shift:create',
            'shift:assign',
            'shift:bulk_assign',
            'shift:holidays',
            'shift:statistics'
        ]

        for url_name in urls_to_test:
            response = self.client.get(reverse(url_name))
            self.assertIn(response.status_code, [200, 302])  # 200 for GET, 302 for redirect

    def test_employee_permissions(self):
        """Test employee permissions."""
        self.client.login(username='employee', password='testpass123')

        # Employees can access limited views
        allowed_urls = [
            'shift:dashboard',
            'shift:list',
            'shift:assignments',
            'shift:user_calendar'
        ]

        for url_name in allowed_urls:
            response = self.client.get(reverse(url_name))
            self.assertEqual(response.status_code, 200)

        # Employees cannot access management views
        restricted_urls = [
            'shift:create',
            'shift:assign',
            'shift:bulk_assign',
            'shift:create_holiday'
        ]

        for url_name in restricted_urls:
            response = self.client.get(reverse(url_name))
            self.assertEqual(response.status_code, 302)  # Redirect due to permission denial

    def test_hr_permissions(self):
        """Test HR permissions."""
        self.client.login(username='hr', password='testpass123')

        # HR should have same permissions as managers
        management_urls = [
            'shift:create',
            'shift:assign',
            'shift:bulk_assign',
            'shift:create_holiday'
        ]

        for url_name in management_urls:
            response = self.client.get(reverse(url_name))
            self.assertEqual(response.status_code, 200)

    def test_unauthenticated_access(self):
        """Test unauthenticated access is denied."""
        urls_to_test = [
            'shift:dashboard',
            'shift:list',
            'shift:create',
            'shift:assign'
        ]

        for url_name in urls_to_test:
            response = self.client.get(reverse(url_name))
            self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_superuser_access(self):
        """Test superuser has access to everything."""
        self.client.login(username='admin', password='adminpass123')

        all_urls = [
            'shift:dashboard',
            'shift:list',
            'shift:create',
            'shift:assign',
            'shift:bulk_assign',
            'shift:statistics',
            'shift:holidays'
        ]

        for url_name in all_urls:
            response = self.client.get(reverse(url_name))
            self.assertEqual(response.status_code, 200)


class ShiftIntegrationTest(ShiftTestBase):
    """Integration tests for complete shift management workflows."""

    def test_complete_shift_management_workflow(self):
        """Test complete workflow from shift creation to assignment."""
        self.client.login(username='manager', password='testpass123')

        # 1. Create a new shift
        shift_data = {
            'name': 'Integration Test Shift',
            'start_time': '10:00',
            'end_time': '18:00',
            'shift_duration': '8.0',
            'break_duration_minutes': 45,
            'grace_period_minutes': 10,
            'work_days': 'Weekdays',
            'is_active': True
        }

        response = self.client.post(reverse('shift:create'), data=shift_data)
        self.assertEqual(response.status_code, 302)

        # Verify shift was created
        new_shift = ShiftMaster.objects.get(name='Integration Test Shift')
        self.assertIsNotNone(new_shift)

        # 2. Assign the shift to a user
        assignment_data = {
            'user': self.employee_user.id,
            'shift': new_shift.id,
            'effective_from': date.today().strftime('%Y-%m-%d'),
            'effective_to': (date.today() + timedelta(days=60)).strftime('%Y-%m-%d')
        }

        response = self.client.post(reverse('shift:assign'), data=assignment_data)
        self.assertEqual(response.status_code, 302)

        # Verify assignment was created
        assignment = ShiftAssignment.objects.get(user=self.employee_user, shift=new_shift)
        self.assertIsNotNone(assignment)
        self.assertTrue(assignment.is_current)

        # 3. Check that user's current shift is updated
        current_shift = self.shift_service.get_current_shift(self.employee_user)
        self.assertEqual(current_shift, new_shift)

        # 4. End the assignment
        response = self.client.post(reverse('shift:end_assignment', kwargs={'assignment_id': assignment.id}), {
            'end_date': date.today().strftime('%Y-%m-%d')
        })
        self.assertEqual(response.status_code, 302)

        # Verify assignment was ended
        assignment.refresh_from_db()
        self.assertFalse(assignment.is_current)
        self.assertEqual(assignment.effective_to, date.today())

    def test_bulk_assignment_workflow(self):
        """Test bulk assignment workflow."""
        self.client.login(username='hr', password='testpass123')

        # Create additional users for bulk assignment
        user1 = User.objects.create_user(username='bulk1', password='test123')
        user2 = User.objects.create_user(username='bulk2', password='test123')
        user1.groups.add(self.employee_group)
        user2.groups.add(self.employee_group)

        # Bulk assign shift
        bulk_data = {
            'users': [user1.id, user2.id, self.employee_user.id],
            'shift': self.day_shift.id,
            'effective_from': date.today().strftime('%Y-%m-%d')
        }

        response = self.client.post(reverse('shift:bulk_assign'), data=bulk_data)
        self.assertEqual(response.status_code, 302)

        # Verify all assignments were created
        assignments = ShiftAssignment.objects.filter(shift=self.day_shift, is_current=True)
        self.assertEqual(assignments.count(), 3)

    def test_csv_import_workflow(self):
        """Test CSV import workflow."""
        self.client.login(username='manager', password='testpass123')

        # Create CSV content
        csv_content = f"""username,shift_name,effective_from,effective_to
{self.employee_user.username},{self.day_shift.name},2024-01-01,2024-12-31
{self.hr_user.username},{self.night_shift.name},2024-01-01,"""

        csv_file = SimpleUploadedFile(
            "bulk_assignments.csv",
            csv_content.encode('utf-8'),
            content_type="text/csv"
        )

        # Upload CSV
        response = self.client.post(reverse('shift:csv_upload'), {'csv_file': csv_file})
        self.assertEqual(response.status_code, 302)

        # Check results page
        response = self.client.get(reverse('shift:csv_results'))
        self.assertEqual(response.status_code, 200)

        # Verify assignments were created
        self.assertTrue(ShiftAssignment.objects.filter(
            user=self.employee_user,
            shift=self.day_shift
        ).exists())
        self.assertTrue(ShiftAssignment.objects.filter(
            user=self.hr_user,
            shift=self.night_shift
        ).exists())

    def test_holiday_integration(self):
        """Test holiday integration with shift management."""
        self.client.login(username='manager', password='testpass123')

        # Create holiday
        holiday_data = {
            'name': 'Integration Holiday',
            'date': date.today().strftime('%Y-%m-%d'),
            'recurring_yearly': False
        }

        response = self.client.post(reverse('shift:create_holiday'), data=holiday_data)
        self.assertEqual(response.status_code, 302)

        # Create assignment
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            is_current=True
        )

        # Check that today is not a working day due to holiday
        is_working = self.shift_service.is_working_day_for_user(self.employee_user, date.today())
        self.assertFalse(is_working)  # Should be False due to holiday

    def test_shift_statistics_integration(self):
        """Test statistics integration with real data."""
        # Create multiple assignments
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            is_current=True
        )
        ShiftAssignment.objects.create(
            user=self.manager_user,
            shift=self.night_shift,
            effective_from=date.today(),
            is_current=True
        )

        # Get statistics
        stats = self.shift_service.get_shift_statistics()

        # Verify statistics reflect the data
        self.assertEqual(stats['overview']['active_shifts'], 2)
        self.assertEqual(stats['overview']['current_assignments'], 2)
        self.assertGreater(stats['users']['users_with_shifts'], 0)
        self.assertGreater(stats['users']['coverage_percentage'], 0)


class ShiftEdgeCaseTest(ShiftTestBase):
    """Test edge cases and error conditions."""

    def test_midnight_crossing_shift_logic(self):
        """Test midnight crossing shift edge cases."""
        # Create assignment for night shift
        assignment = ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.night_shift,
            effective_from=date.today(),
            is_current=True
        )

        # Test shift status during night hours
        shift_status = self.shift_service.is_user_on_shift_now(self.employee_user)
        self.assertIn('crosses_midnight', shift_status['shift'])
        self.assertTrue(shift_status['shift']['crosses_midnight'])

    def test_overlapping_assignment_prevention(self):
        """Test prevention of overlapping assignments."""
        # Create first assignment
        ShiftAssignment.objects.create(
            user=self.employee_user,
            shift=self.day_shift,
            effective_from=date.today(),
            effective_to=date.today() + timedelta(days=30),
            is_current=True
        )

        # Try to create overlapping assignment
        is_valid, message = self.shift_service.validate_shift_assignment(
            self.employee_user.id,
            self.night_shift.id,
            date.today() + timedelta(days=15),
            date.today() + timedelta(days=45)
        )

        self.assertFalse(is_valid)
        self.assertIn('Overlapping', message)

    def test_invalid_date_ranges(self):
        """Test handling of invalid date ranges."""
        # Test assignment with end date before start date
        form_data = {
            'user': self.employee_user.id,
            'shift': self.day_shift.id,
            'effective_from': date.today() + timedelta(days=10),
            'effective_to': date.today() + timedelta(days=5)
        }

        form = ShiftAssignmentForm(data=form_data)
        self.assertFalse(form.is_valid())

    def test_large_dataset_performance(self):
        """Test performance with larger datasets."""
        # Create multiple shifts and assignments
        shifts = []
        for i in range(10):
            shift = ShiftMaster.objects.create(
                name=f'Perf Test Shift {i}',
                start_time=time(8 + i, 0),
                end_time=time(16 + i, 0),
                shift_duration=Decimal('8.0')
            )
            shifts.append(shift)

        # Create multiple users and assignments
        users = []
        for i in range(50):
            user = User.objects.create_user(
                username=f'perfuser{i}',
                password='test123'
            )
            users.append(user)

        # Bulk assign shifts
        user_ids = [user.id for user in users[:25]]
        success_count, error_count, errors = self.shift_service.assign_shifts_to_users(
            user_ids,
            shifts[0].id,
            date.today()
        )

        self.assertEqual(success_count, 25)
        self.assertEqual(error_count, 0)

        # Test statistics with larger dataset
        stats = self.shift_service.get_shift_statistics()
        self.assertIsInstance(stats, dict)
        self.assertGreater(stats['overview']['total_shifts'], 10)

    def test_timezone_handling(self):
        """Test timezone-aware operations."""
        # This test ensures timezone-aware datetime operations work correctly
        now = timezone.now()
        shift_status = self.shift_service.is_user_on_shift_now(self.employee_user)

        # Should handle timezone-aware datetime without errors
        self.assertIsInstance(shift_status, dict)
        self.assertIn('current_time', shift_status)

    def test_error_recovery(self):
        """Test error recovery and graceful failure handling."""
        # Test service methods with invalid parameters
        result = self.shift_service.get_shift_by_id(99999)
        self.assertIsNone(result)

        # Test assignment to non-existent user
        success, message = self.shift_service.assign_shift_to_user(
            99999,  # Non-existent user
            self.day_shift.id,
            date.today()
        )
        self.assertFalse(success)
        self.assertIn('not found', message)

        # Test CSV with malformed data
        csv_content = "invalid,csv,content\nwith,wrong,headers"
        csv_file = SimpleUploadedFile(
            "invalid.csv",
            csv_content.encode('utf-8'),
            content_type="text/csv"
        )

        results = self.shift_service.assign_shifts_from_csv(csv_file)
        self.assertFalse(results['success'])
        self.assertIn('Missing required headers', results['message'])


# Test runner configuration
class ShiftTestRunner:
    """Helper class for running specific test categories."""

    @staticmethod
    def run_model_tests():
        """Run only model tests."""
        from django.test.utils import get_runner
        from django.conf import settings

        TestRunner = get_runner(settings)
        test_runner = TestRunner()
        failures = test_runner.run_tests([
            'trueAlign.shift.tests.ShiftMasterModelTest',
            'trueAlign.shift.tests.ShiftAssignmentModelTest',
            'trueAlign.shift.tests.HolidayModelTest'
        ])
        return failures == 0

    @staticmethod
    def run_service_tests():
        """Run only service tests."""
        from django.test.utils import get_runner
        from django.conf import settings

        TestRunner = get_runner(settings)
        test_runner = TestRunner()
        failures = test_runner.run_tests([
            'trueAlign.shift.tests.ShiftServiceTest'
        ])
        return failures == 0

    @staticmethod
    def run_view_tests():
        """Run only view tests."""
        from django.test.utils import get_runner
        from django.conf import settings

        TestRunner = get_runner(settings)
        test_runner = TestRunner()
        failures = test_runner.run_tests([
            'trueAlign.shift.tests.ShiftViewTest',
            'trueAlign.shift.tests.ShiftAPITest'
        ])
        return failures == 0

    @staticmethod
    def run_all_tests():
        """Run all shift app tests."""
        from django.test.utils import get_runner
        from django.conf import settings

        TestRunner = get_runner(settings)
        test_runner = TestRunner()
        failures = test_runner.run_tests(['trueAlign.shift.tests'])
        return failures == 0
