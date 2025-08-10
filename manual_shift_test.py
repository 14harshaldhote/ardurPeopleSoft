#!/usr/bin/env python3
"""
Manual Testing Script for ShiftMaster and ShiftAssignment Modules
================================================================

This script performs manual testing of all ShiftMaster and ShiftAssignment
functionality including models, views, forms, and business logic.

Usage:
    python manual_shift_test.py

Requirements:
    - Django environment properly configured
    - Asia/Kolkata timezone
    - Database accessible
"""

import os
import sys
import django
import json
from datetime import datetime, date, time, timedelta
from decimal import Decimal
import traceback

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.utils import timezone
from django.test import Client
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.db import transaction, IntegrityError
import pytz

from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
from trueAlign.shift.forms import ShiftForm, ShiftAssignmentForm, BulkAssignmentForm, HolidayForm


class ManualShiftTester:
    """Manual testing class for comprehensive shift system testing"""

    def __init__(self):
        self.results = {
            'model_tests': [],
            'form_tests': [],
            'view_tests': [],
            'business_logic_tests': [],
            'edge_case_tests': [],
            'timezone_tests': [],
            'integration_tests': []
        }
        self.test_data = {}
        self.client = Client()

        # Set timezone to Asia/Kolkata
        self.ist = pytz.timezone('Asia/Kolkata')
        timezone.activate(self.ist)

        print("Manual Shift System Testing - Asia/Kolkata Timezone")
        print("=" * 60)
        print(f"Current time: {timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')}")
        print("=" * 60)

    def log_test(self, category, test_name, status, details=""):
        """Log test results"""
        result = {
            'test_name': test_name,
            'status': status,
            'details': details,
            'timestamp': timezone.now().isoformat()
        }
        self.results[category].append(result)

        status_icon = "✓" if status == "PASS" else "✗" if status == "FAIL" else "⚠"
        print(f"{status_icon} {test_name}: {status}")
        if details and status != "PASS":
            print(f"  Details: {details}")

    def setup_test_data(self):
        """Setup test data for testing"""
        print("\n1. SETTING UP TEST DATA")
        print("-" * 40)

        try:
            # Create test users
            self.test_data['users'] = {}

            # Admin user
            admin_user, created = User.objects.get_or_create(
                username='manual_test_admin',
                defaults={
                    'email': 'admin@manualtest.com',
                    'is_staff': True,
                    'is_superuser': True
                }
            )
            if created:
                admin_user.set_password('testpass123')
                admin_user.save()
            self.test_data['users']['admin'] = admin_user

            # Regular users
            for i in range(1, 4):
                user, created = User.objects.get_or_create(
                    username=f'manual_test_user{i}',
                    defaults={
                        'email': f'user{i}@manualtest.com',
                        'first_name': f'Test',
                        'last_name': f'User{i}'
                    }
                )
                if created:
                    user.set_password('testpass123')
                    user.save()
                self.test_data['users'][f'user{i}'] = user

            # Inactive user
            inactive_user, created = User.objects.get_or_create(
                username='manual_test_inactive',
                defaults={
                    'email': 'inactive@manualtest.com',
                    'is_active': False
                }
            )
            if created:
                inactive_user.set_password('testpass123')
                inactive_user.save()
            self.test_data['users']['inactive'] = inactive_user

            print("✓ Test users created successfully")

            # Clean up any existing test shifts to avoid conflicts
            ShiftMaster.objects.filter(name__startswith='Manual Test').delete()

            print("✓ Test data setup completed")

        except Exception as e:
            print(f"✗ Test data setup failed: {str(e)}")
            raise

    def test_shift_master_models(self):
        """Test ShiftMaster model functionality"""
        print("\n2. TESTING SHIFTMASTER MODEL")
        print("-" * 40)

        # Test 1: Basic shift creation
        try:
            shift = ShiftMaster(
                name='Manual Test Basic Shift',
                start_time=time(9, 0),
                end_time=time(17, 0),
                shift_duration=Decimal('8.0'),
                work_days='Weekdays'
            )
            shift.save()
            self.test_data['basic_shift'] = shift
            self.log_test('model_tests', 'Basic ShiftMaster Creation', 'PASS')
        except Exception as e:
            self.log_test('model_tests', 'Basic ShiftMaster Creation', 'FAIL', str(e))

        # Test 2: Shift with custom work days
        try:
            custom_shift = ShiftMaster(
                name='Manual Test Custom Shift',
                start_time=time(14, 0),
                end_time=time(22, 0),
                shift_duration=Decimal('8.0'),
                work_days='Custom',
                custom_work_days='Monday,Wednesday,Friday'
            )
            custom_shift.save()
            self.test_data['custom_shift'] = custom_shift

            # Test working days functionality
            working_days = custom_shift.working_days_list
            expected_days = [0, 2, 4]  # Monday, Wednesday, Friday
            if working_days == expected_days:
                self.log_test('model_tests', 'Custom Working Days', 'PASS')
            else:
                self.log_test('model_tests', 'Custom Working Days', 'FAIL',
                            f'Expected {expected_days}, got {working_days}')
        except Exception as e:
            self.log_test('model_tests', 'Custom Working Days Shift', 'FAIL', str(e))

        # Test 3: Night shift (crosses midnight)
        try:
            night_shift = ShiftMaster(
                name='Manual Test Night Shift',
                start_time=time(22, 0),
                end_time=time(6, 0),
                shift_duration=Decimal('8.0'),
                work_days='Weekdays'
            )
            night_shift.save()
            self.test_data['night_shift'] = night_shift

            # Test midnight crossover detection
            if night_shift.crosses_midnight:
                self.log_test('model_tests', 'Midnight Crossover Detection', 'PASS')
            else:
                self.log_test('model_tests', 'Midnight Crossover Detection', 'FAIL',
                            'Night shift should cross midnight')
        except Exception as e:
            self.log_test('model_tests', 'Night Shift Creation', 'FAIL', str(e))

        # Test 4: Invalid shift validation
        try:
            invalid_shift = ShiftMaster(
                name='',  # Empty name should fail
                start_time=time(9, 0),
                end_time=time(17, 0)
            )
            invalid_shift.full_clean()
            self.log_test('model_tests', 'Empty Name Validation', 'FAIL',
                        'Should have raised ValidationError for empty name')
        except ValidationError:
            self.log_test('model_tests', 'Empty Name Validation', 'PASS')
        except Exception as e:
            self.log_test('model_tests', 'Empty Name Validation', 'FAIL', str(e))

        # Test 5: Duplicate shift name validation
        try:
            duplicate_shift = ShiftMaster(
                name='Manual Test Basic Shift',  # Same as existing
                start_time=time(10, 0),
                end_time=time(18, 0)
            )
            duplicate_shift.full_clean()
            self.log_test('model_tests', 'Duplicate Name Validation', 'FAIL',
                        'Should have raised ValidationError for duplicate name')
        except ValidationError:
            self.log_test('model_tests', 'Duplicate Name Validation', 'PASS')
        except Exception as e:
            self.log_test('model_tests', 'Duplicate Name Validation', 'FAIL', str(e))

        # Test 6: String representation
        try:
            if hasattr(self.test_data, 'basic_shift'):
                shift_str = str(self.test_data['basic_shift'])
                if 'Manual Test Basic Shift' in shift_str and '09:00' in shift_str:
                    self.log_test('model_tests', 'String Representation', 'PASS')
                else:
                    self.log_test('model_tests', 'String Representation', 'FAIL',
                                f'Unexpected string representation: {shift_str}')
        except Exception as e:
            self.log_test('model_tests', 'String Representation', 'FAIL', str(e))

    def test_shift_assignment_models(self):
        """Test ShiftAssignment model functionality"""
        print("\n3. TESTING SHIFTASSIGNMENT MODEL")
        print("-" * 40)

        # Test 1: Basic assignment creation
        try:
            if 'basic_shift' in self.test_data and 'user1' in self.test_data['users']:
                assignment = ShiftAssignment(
                    user=self.test_data['users']['user1'],
                    shift=self.test_data['basic_shift'],
                    effective_from=date.today(),
                    is_current=True
                )
                assignment.save()
                self.test_data['basic_assignment'] = assignment
                self.log_test('model_tests', 'Basic Assignment Creation', 'PASS')
        except Exception as e:
            self.log_test('model_tests', 'Basic Assignment Creation', 'FAIL', str(e))

        # Test 2: Assignment with end date
        try:
            if 'basic_shift' in self.test_data and 'user2' in self.test_data['users']:
                dated_assignment = ShiftAssignment(
                    user=self.test_data['users']['user2'],
                    shift=self.test_data['basic_shift'],
                    effective_from=date.today() + timedelta(days=1),
                    effective_to=date.today() + timedelta(days=30),
                    is_current=False
                )
                dated_assignment.save()
                self.test_data['dated_assignment'] = dated_assignment
                self.log_test('model_tests', 'Assignment with End Date', 'PASS')
        except Exception as e:
            self.log_test('model_tests', 'Assignment with End Date', 'FAIL', str(e))

        # Test 3: Past date validation
        try:
            if 'basic_shift' in self.test_data and 'user3' in self.test_data['users']:
                past_assignment = ShiftAssignment(
                    user=self.test_data['users']['user3'],
                    shift=self.test_data['basic_shift'],
                    effective_from=date.today() - timedelta(days=5)
                )
                past_assignment.full_clean()
                self.log_test('model_tests', 'Past Date Validation', 'FAIL',
                            'Should have raised ValidationError for past date')
        except ValidationError:
            self.log_test('model_tests', 'Past Date Validation', 'PASS')
        except Exception as e:
            self.log_test('model_tests', 'Past Date Validation', 'FAIL', str(e))

        # Test 4: Invalid date range validation
        try:
            if 'basic_shift' in self.test_data and 'user3' in self.test_data['users']:
                invalid_range = ShiftAssignment(
                    user=self.test_data['users']['user3'],
                    shift=self.test_data['basic_shift'],
                    effective_from=date.today() + timedelta(days=10),
                    effective_to=date.today() + timedelta(days=5)  # End before start
                )
                invalid_range.full_clean()
                self.log_test('model_tests', 'Invalid Date Range Validation', 'FAIL',
                            'Should have raised ValidationError for invalid date range')
        except ValidationError:
            self.log_test('model_tests', 'Invalid Date Range Validation', 'PASS')
        except Exception as e:
            self.log_test('model_tests', 'Invalid Date Range Validation', 'FAIL', str(e))

        # Test 5: Assignment status methods
        try:
            if 'basic_assignment' in self.test_data:
                assignment = self.test_data['basic_assignment']

                # Test is_active_on
                active_today = assignment.is_active_on(date.today())
                active_future = assignment.is_active_on(date.today() + timedelta(days=365))

                if active_today and not active_future:
                    self.log_test('model_tests', 'Assignment Status Methods', 'PASS')
                else:
                    self.log_test('model_tests', 'Assignment Status Methods', 'FAIL',
                                f'active_today: {active_today}, active_future: {active_future}')
        except Exception as e:
            self.log_test('model_tests', 'Assignment Status Methods', 'FAIL', str(e))

        # Test 6: Get user current shift
        try:
            if 'user1' in self.test_data['users']:
                current_shift = ShiftAssignment.get_user_current_shift(
                    self.test_data['users']['user1']
                )
                if current_shift is not None:
                    self.log_test('model_tests', 'Get User Current Shift', 'PASS')
                else:
                    self.log_test('model_tests', 'Get User Current Shift', 'FAIL',
                                'Should return a shift for user with assignment')
        except Exception as e:
            self.log_test('model_tests', 'Get User Current Shift', 'FAIL', str(e))

    def test_forms(self):
        """Test form functionality"""
        print("\n4. TESTING FORMS")
        print("-" * 40)

        # Test 1: Valid ShiftForm
        try:
            valid_data = {
                'name': 'Manual Test Form Shift',
                'start_time': '10:00',
                'end_time': '18:00',
                'shift_duration': '8.0',
                'break_duration_minutes': '30',
                'grace_period_minutes': '15',
                'work_days': 'Weekdays',
                'is_active': True
            }
            form = ShiftForm(data=valid_data)
            if form.is_valid():
                self.log_test('form_tests', 'Valid ShiftForm', 'PASS')
                saved_shift = form.save()
                self.test_data['form_shift'] = saved_shift
            else:
                self.log_test('form_tests', 'Valid ShiftForm', 'FAIL',
                            f'Form errors: {form.errors}')
        except Exception as e:
            self.log_test('form_tests', 'Valid ShiftForm', 'FAIL', str(e))

        # Test 2: Invalid ShiftForm (empty name)
        try:
            invalid_data = {
                'name': '',
                'start_time': '10:00',
                'end_time': '18:00',
            }
            form = ShiftForm(data=invalid_data)
            if not form.is_valid():
                self.log_test('form_tests', 'Invalid ShiftForm (Empty Name)', 'PASS')
            else:
                self.log_test('form_tests', 'Invalid ShiftForm (Empty Name)', 'FAIL',
                            'Form should be invalid with empty name')
        except Exception as e:
            self.log_test('form_tests', 'Invalid ShiftForm (Empty Name)', 'FAIL', str(e))

        # Test 3: Valid ShiftAssignmentForm
        try:
            if 'basic_shift' in self.test_data and 'user2' in self.test_data['users']:
                assignment_data = {
                    'user': self.test_data['users']['user2'].id,
                    'shift': self.test_data['basic_shift'].id,
                    'effective_from': (date.today() + timedelta(days=7)).strftime('%Y-%m-%d'),
                    'is_current': False,
                    'notes': 'Manual test assignment'
                }
                form = ShiftAssignmentForm(data=assignment_data)
                if form.is_valid():
                    self.log_test('form_tests', 'Valid ShiftAssignmentForm', 'PASS')
                    saved_assignment = form.save()
                    self.test_data['form_assignment'] = saved_assignment
                else:
                    self.log_test('form_tests', 'Valid ShiftAssignmentForm', 'FAIL',
                                f'Form errors: {form.errors}')
        except Exception as e:
            self.log_test('form_tests', 'Valid ShiftAssignmentForm', 'FAIL', str(e))

        # Test 4: HolidayForm
        try:
            holiday_data = {
                'name': 'Manual Test Holiday',
                'date': (date.today() + timedelta(days=30)).strftime('%Y-%m-%d'),
                'is_recurring': False
            }
            form = HolidayForm(data=holiday_data)
            if form.is_valid():
                self.log_test('form_tests', 'Valid HolidayForm', 'PASS')
                saved_holiday = form.save()
                self.test_data['form_holiday'] = saved_holiday
            else:
                self.log_test('form_tests', 'Valid HolidayForm', 'FAIL',
                            f'Form errors: {form.errors}')
        except Exception as e:
            self.log_test('form_tests', 'Valid HolidayForm', 'FAIL', str(e))

    def test_views(self):
        """Test view functionality"""
        print("\n5. TESTING VIEWS")
        print("-" * 40)

        # Login as admin
        if 'admin' in self.test_data['users']:
            login_success = self.client.login(
                username='manual_test_admin',
                password='testpass123'
            )
            if not login_success:
                self.log_test('view_tests', 'Admin Login', 'FAIL', 'Could not login')
                return
            else:
                self.log_test('view_tests', 'Admin Login', 'PASS')

        # Test 1: Dashboard view
        try:
            response = self.client.get(reverse('shift:dashboard'))
            if response.status_code == 200:
                self.log_test('view_tests', 'Dashboard View', 'PASS')
            else:
                self.log_test('view_tests', 'Dashboard View', 'FAIL',
                            f'Status code: {response.status_code}')
        except Exception as e:
            self.log_test('view_tests', 'Dashboard View', 'FAIL', str(e))

        # Test 2: Shift list view
        try:
            response = self.client.get(reverse('shift:list'))
            if response.status_code == 200:
                self.log_test('view_tests', 'Shift List View', 'PASS')
            else:
                self.log_test('view_tests', 'Shift List View', 'FAIL',
                            f'Status code: {response.status_code}')
        except Exception as e:
            self.log_test('view_tests', 'Shift List View', 'FAIL', str(e))

        # Test 3: Create shift view
        try:
            # GET request
            response = self.client.get(reverse('shift:create'))
            if response.status_code == 200:
                # POST request
                data = {
                    'name': 'Manual Test View Shift',
                    'start_time': '11:00',
                    'end_time': '19:00',
                    'shift_duration': '8.0',
                    'break_duration_minutes': '30',
                    'grace_period_minutes': '15',
                    'work_days': 'Weekdays',
                    'is_active': True
                }
                post_response = self.client.post(reverse('shift:create'), data)
                if post_response.status_code in [200, 302]:
                    self.log_test('view_tests', 'Create Shift View', 'PASS')
                else:
                    self.log_test('view_tests', 'Create Shift View', 'FAIL',
                                f'POST status code: {post_response.status_code}')
            else:
                self.log_test('view_tests', 'Create Shift View', 'FAIL',
                            f'GET status code: {response.status_code}')
        except Exception as e:
            self.log_test('view_tests', 'Create Shift View', 'FAIL', str(e))

        # Test 4: Assignments view
        try:
            response = self.client.get(reverse('shift:assignments'))
            if response.status_code == 200:
                self.log_test('view_tests', 'Assignments View', 'PASS')
            else:
                self.log_test('view_tests', 'Assignments View', 'FAIL',
                            f'Status code: {response.status_code}')
        except Exception as e:
            self.log_test('view_tests', 'Assignments View', 'FAIL', str(e))

        # Test 5: Assign shift view
        try:
            response = self.client.get(reverse('shift:assign'))
            if response.status_code == 200:
                self.log_test('view_tests', 'Assign Shift View', 'PASS')
            else:
                self.log_test('view_tests', 'Assign Shift View', 'FAIL',
                            f'Status code: {response.status_code}')
        except Exception as e:
            self.log_test('view_tests', 'Assign Shift View', 'FAIL', str(e))

        # Test 6: Holidays view
        try:
            response = self.client.get(reverse('shift:holidays'))
            if response.status_code == 200:
                self.log_test('view_tests', 'Holidays View', 'PASS')
            else:
                self.log_test('view_tests', 'Holidays View', 'FAIL',
                            f'Status code: {response.status_code}')
        except Exception as e:
            self.log_test('view_tests', 'Holidays View', 'FAIL', str(e))

        # Test 7: Calendar view
        try:
            response = self.client.get(reverse('shift:user_calendar'))
            if response.status_code == 200:
                self.log_test('view_tests', 'Calendar View', 'PASS')
            else:
                self.log_test('view_tests', 'Calendar View', 'FAIL',
                            f'Status code: {response.status_code}')
        except Exception as e:
            self.log_test('view_tests', 'Calendar View', 'FAIL', str(e))

    def test_api_endpoints(self):
        """Test API endpoints"""
        print("\n6. TESTING API ENDPOINTS")
        print("-" * 40)

        # Test 1: Dashboard stats API
        try:
            response = self.client.get(reverse('shift:api_dashboard_stats'))
            if response.status_code == 200:
                data = response.json()
                if isinstance(data, dict):
                    self.log_test('view_tests', 'Dashboard Stats API', 'PASS')
                else:
                    self.log_test('view_tests', 'Dashboard Stats API', 'FAIL',
                                'Response is not JSON dict')
            else:
                self.log_test('view_tests', 'Dashboard Stats API', 'FAIL',
                            f'Status code: {response.status_code}')
        except Exception as e:
            self.log_test('view_tests', 'Dashboard Stats API', 'FAIL', str(e))

        # Test 2: User shift status API
        try:
            response = self.client.get(reverse('shift:api_user_shift_status'))
            if response.status_code == 200:
                self.log_test('view_tests', 'User Shift Status API', 'PASS')
            else:
                self.log_test('view_tests', 'User Shift Status API', 'FAIL',
                            f'Status code: {response.status_code}')
        except Exception as e:
            self.log_test('view_tests', 'User Shift Status API', 'FAIL', str(e))

        # Test 3: Validate shift name API
        try:
            response = self.client.post(reverse('shift:api_validate_shift_name'), {
                'name': 'Unique Test Shift Name'
            })
            if response.status_code == 200:
                self.log_test('view_tests', 'Validate Shift Name API', 'PASS')
            else:
                self.log_test('view_tests', 'Validate Shift Name API', 'FAIL',
                            f'Status code: {response.status_code}')
        except Exception as e:
            self.log_test('view_tests', 'Validate Shift Name API', 'FAIL', str(e))

    def test_business_logic(self):
        """Test business logic and rules"""
        print("\n7. TESTING BUSINESS LOGIC")
        print("-" * 40)

        # Test 1: Overlapping shift prevention
        try:
            if 'basic_shift' in self.test_data:
                # Try to create overlapping shift
                overlapping_shift = ShiftMaster(
                    name='Manual Test Overlapping Shift',
                    start_time=time(8, 0),  # Overlaps with basic shift
                    end_time=time(18, 0),
                    shift_duration=Decimal('10.0'),
                    work_days='Weekdays'
                )
                overlapping_shift.full_clean()
                self.log_test('business_logic_tests', 'Overlapping Shift Prevention', 'FAIL',
                            'Should have prevented overlapping shift creation')
        except ValidationError as e:
            if 'overlaps' in str(e).lower():
                self.log_test('business_logic_tests', 'Overlapping Shift Prevention', 'PASS')
            else:
                self.log_test('business_logic_tests', 'Overlapping Shift Prevention', 'FAIL',
                            f'Wrong validation error: {str(e)}')
        except Exception as e:
            self.log_test('business_logic_tests', 'Overlapping Shift Prevention', 'FAIL', str(e))

        # Test 2: Assignment conflict prevention
        try:
            if 'basic_assignment' in self.test_data:
                user = self.test_data['basic_assignment'].user
                # Try to create overlapping assignment
                conflicting_assignment = ShiftAssignment(
                    user=user,
                    shift=self.test_data['basic_shift'],
                    effective_from=date.today() - timedelta(days=1),
                    effective_to=date.today() + timedelta(days=1),
                    is_current=False
                )
                conflicting_assignment.full_clean()
                self.log_test('business_logic_tests', 'Assignment Conflict Prevention', 'FAIL',
                            'Should have prevented overlapping assignment')
        except ValidationError as e:
            if 'overlap' in str(e).lower():
                self.log_test('business_logic_tests', 'Assignment Conflict Prevention', 'PASS')
            else:
                self.log_test('business_logic_tests', 'Assignment Conflict Prevention', 'FAIL',
                            f'Wrong validation error: {str(e)}')
        except Exception as e:
            self.log_test('business_logic_tests', 'Assignment Conflict Prevention', 'FAIL', str(e))

        # Test 3: Inactive user assignment prevention
        try:
            if 'basic_shift' in self.test_data and 'inactive' in self.test_data['users']:
                inactive_assignment = ShiftAssignment(
                    user=self.test_data['users']['inactive'],
                    shift=self.test_data['basic_shift'],
                    effective_from=date.today() + timedelta(days=1)
                )
                inactive_assignment.full_clean()
                self.log_test('business_logic_tests', 'Inactive User Assignment Prevention', 'FAIL',
                            'Should have prevented assignment to inactive user')
        except ValidationError as e:
            if 'inactive' in str(e).lower():
                self.log_test('business_logic_tests', 'Inactive User Assignment Prevention', 'PASS')
            else:
                self.log_test('business_logic_tests', 'Inactive User Assignment Prevention', 'FAIL',
                            f'Wrong validation error: {str(e)}')
        except Exception as e:
            self.log_test('business_logic_tests', 'Inactive User Assignment Prevention', 'FAIL', str(e))

    def test_timezone_functionality(self):
        """Test timezone-specific functionality"""
        print("\n8. TESTING TIMEZONE FUNCTIONALITY (Asia/Kolkata)")
        print("-" * 40)

        # Test 1: Timezone awareness
        try:
            current_time = timezone.now()
            ist_time = current_time.astimezone(self.ist)

            if ist_time.tzinfo.zone == 'Asia/Kolkata':
                self.log_test('timezone_tests', 'IST Timezone Active', 'PASS')
            else:
                self.log_test('timezone_tests', 'IST Timezone Active', 'FAIL',
                            f'Expected Asia/Kolkata, got {ist_time.tzinfo.zone}')
        except Exception as e:
            self.log_test('timezone_tests', 'IST Timezone Active', 'FAIL', str(e))

        # Test 2: Shift time calculations in IST
        try:
            if 'night_shift' in self.test_data:
                night_shift = self.test_data['night_shift']
                test_date = date.today()

                # Create IST datetime for shift start
                shift_start_dt = timezone.make_aware(
                    datetime.combine(test_date, night_shift.start_time),
                    timezone=self.ist
                )

                is_within = night_shift.is_within_shift_hours(shift_start_dt, test_date)
                if isinstance(is_within, bool):
                    self.log_test('timezone_tests', 'IST Time Calculations', 'PASS')
                else:
                    self.log_test('timezone_tests', 'IST Time Calculations', 'FAIL',
                                'is_within_shift_hours should return boolean')
        except Exception as e:
            self.log_test('timezone_tests', 'IST Time Calculations', 'FAIL', str(e))

    def test_edge_cases(self):
        """Test edge cases and boundary conditions"""
        print("\n9. TESTING EDGE CASES")
        print("-" * 40)

        # Test 1: Extremely short shift
        try:
            short_shift = ShiftMaster(
                name='Manual Test Short Shift',
                start_time=time(12, 0),
                end_time=time(12, 30),
                shift_duration=Decimal('0.5'),
                work_days='Weekdays'
            )
            short_shift.save()
            self.log_test('edge_case_tests', 'Minimum Duration Shift', 'PASS')
        except Exception as e:
            self.log_test('edge_case_tests', 'Minimum Duration Shift', 'FAIL', str(e))

        # Test 2: Assignment ending today
        try:
            if 'basic_shift' in self.test_data and 'user3' in self.test_data['users']:
                ending_assignment = ShiftAssignment(
                    user=self.test_data['users']['user3'],
                    shift=self.test_data['basic_shift'],
                    effective_from=date.today() - timedelta(days=10),
                    effective_to=date.today(),
                    is_current=False
                )
                ending_assignment.save()

                # Test has_ended method
                if ending_assignment.has_ended():
                    self.log_test('edge_case_tests', 'Assignment Ending Today', 'PASS')
                else:
                    self.log_test('edge_case_tests', 'Assignment Ending Today', 'FAIL',
                                'Assignment should be marked as ended')
        except Exception as e:
            self.log_test('edge_case_tests', 'Assignment Ending Today', 'FAIL', str(e))

        # Test 3: Weekend-only shift
        try:
            weekend_shift = ShiftMaster(
                name='Manual Test Weekend Shift',
                start_time=time(10, 0),
                end_time=time(14, 0),
                shift_duration=Decimal('4.0'),
                work_days='Custom',
                custom_work_days='Saturday,Sunday'
            )
            weekend_shift.save()

            # Test working days
            saturday_working = weekend_shift.is_working_day(date(2024, 8, 10))  # Assume Saturday
            if isinstance(saturday_working, bool):
                self.log_test('edge_case_tests', 'Weekend-Only Shift', 'PASS')
            else:
                self.log_test('edge_case_tests', 'Weekend-Only Shift', 'FAIL',
                            'is_working_day should return boolean')
        except Exception as e:
            self.log_test('edge_case_tests', 'Weekend-Only Shift', 'FAIL', str(e))

    def test_integration_scenarios(self):
        """Test integration scenarios"""
        print("\n10. TESTING INTEGRATION SCENARIOS")
        print("-" * 40)

        # Test 1: Complete workflow - Create shift, assign, then modify
        try:
            workflow_passed = True
            workflow_details = []

            # Step 1: Create shift via form
            form_data = {
                'name': 'Manual Test Workflow Shift',
                'start_time': '13:00',
                'end_time': '21:00',
                'shift_duration': '8.0',
                'break_duration_minutes': '60',
                'grace_period_minutes': '10',
                'work_days': 'All Days',
                'is_active': True
            }
            shift_form = ShiftForm(data=form_data)
            if shift_form.is_valid():
                workflow_shift = shift_form.save()
                workflow_details.append("Shift created successfully")
            else:
                workflow_passed = False
                workflow_details.append(f"Shift creation failed: {shift_form.errors}")

            # Step 2: Assign shift to user
            if workflow_passed and 'user1' in self.test_data['users']:
                assignment_data = {
                    'user': self.test_data['users']['user1'].id,
                    'shift': workflow_shift.id,
                    'effective_from': (date.today() + timedelta(days=14)).strftime('%Y-%m-%d'),
                    'is_current': False,
                    'notes': 'Workflow test assignment'
                }
                assignment_form = ShiftAssignmentForm(data=assignment_data)
                if assignment_form.is_valid():
                    workflow_assignment = assignment_form.save()
                    workflow_details.append("Assignment created successfully")
                else:
                    workflow_passed = False
                    workflow_details.append(f"Assignment creation failed: {assignment_form.errors}")

            # Step 3: Verify assignment is retrievable
            if workflow_passed:
                user_shift = ShiftAssignment.get_user_current_shift(
                    self.test_data['users']['user1'],
                    date.today() + timedelta(days=14)
                )
                if user_shift:
                    workflow_details.append("Assignment retrieval successful")
                else:
                    workflow_passed = False
                    workflow_details.append("Could not retrieve assigned shift")

            if workflow_passed:
                self.log_test('integration_tests', 'Complete Workflow', 'PASS',
                            '; '.join(workflow_details))
            else:
                self.log_test('integration_tests', 'Complete Workflow', 'FAIL',
                            '; '.join(workflow_details))
        except Exception as e:
            self.log_test('integration_tests', 'Complete Workflow', 'FAIL', str(e))

        # Test 2: Holiday integration
        try:
            if 'form_holiday' in self.test_data:
                holiday = self.test_data['form_holiday']
                is_holiday_result = Holiday.is_holiday(holiday.date)
                if is_holiday_result:
                    self.log_test('integration_tests', 'Holiday Integration', 'PASS')
                else:
                    self.log_test('integration_tests', 'Holiday Integration', 'FAIL',
                                'Holiday.is_holiday() should return True for holiday dates')
        except Exception as e:
            self.log_test('integration_tests', 'Holiday Integration', 'FAIL', str(e))

    def cleanup_test_data(self):
        """Clean up test data"""
        print("\n11. CLEANING UP TEST DATA")
        print("-" * 40)

        try:
            # Delete test assignments
            ShiftAssignment.objects.filter(
                user__username__startswith='manual_test_'
            ).delete()
            print("✓ Test assignments deleted")

            # Delete test shifts
            ShiftMaster.objects.filter(name__startswith='Manual Test').delete()
            print("✓ Test shifts deleted")

            # Delete test holidays
            Holiday.objects.filter(name__startswith='Manual Test').delete()
            print("✓ Test holidays deleted")

            # Delete test users
            User.objects.filter(username__startswith='manual_test_').delete()
            print("✓ Test users deleted")

            print("✓ Cleanup completed successfully")

        except Exception as e:
            print(f"✗ Cleanup failed: {str(e)}")

    def generate_test_report(self):
        """Generate comprehensive test report"""
        print("\n" + "="*60)
        print("COMPREHENSIVE MANUAL TEST REPORT")
        print("="*60)

        total_tests = 0
        passed_tests = 0
        failed_tests = 0

        for category, tests in self.results.items():
            if not tests:
                continue

            print(f"\n{category.upper().replace('_', ' ')}:")
            print("-" * 40)

            category_passed = 0
            category_total = len(tests)

            for test in tests:
                total_tests += 1
                status_icon = "✓" if test['status'] == "PASS" else "✗" if test['status'] == "FAIL" else "⚠"

                if test['status'] == "PASS":
                    passed_tests += 1
                    category_passed += 1
                elif test['status'] == "FAIL":
                    failed_tests += 1

                print(f"{status_icon} {test['test_name']}: {test['status']}")
                if test['details'] and test['status'] != "PASS":
                    print(f"  Details: {test['details']}")

            if category_total > 0:
                success_rate = (category_passed / category_total) * 100
                print(f"Category Success Rate: {success_rate:.1f}% ({category_passed}/{category_total})")

        print(f"\n{'='*60}")
        print(f"OVERALL SUMMARY:")
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        if total_tests > 0:
            overall_success = (passed_tests / total_tests) * 100
            print(f"Overall Success Rate: {overall_success:.1f}%")

        # Save detailed report
        try:
            report_data = {
                'timestamp': timezone.now().isoformat(),
                'timezone': 'Asia/Kolkata',
                'test_results': self.results,
                'summary': {
                    'total_tests': total_tests,
                    'passed_tests': passed_tests,
                    'failed_tests': failed_tests,
                    'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0
                }
            }

            with open('manual_shift_test_report.json', 'w') as f:
                json.dump(report_data, f, indent=2, default=str)

            print(f"\n✓ Detailed report saved to: manual_shift_test_report.json")

        except Exception as e:
            print(f"✗ Failed to save report: {str(e)}")

        return {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': failed_tests,
            'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0
        }

    def run_all_tests(self):
        """Run all test suites"""
        try:
            # Setup
            self.setup_test_data()

            # Run test suites in order
            self.test_shift_master_models()
            self.test_shift_assignment_models()
            self.test_forms()
            self.test_views()
            self.test_api_endpoints()
            self.test_business_logic()
            self.test_timezone_functionality()
            self.test_edge_cases()
            self.test_integration_scenarios()

            # Generate report
            return self.generate_test_report()

        except Exception as e:
            print(f"✗ Test execution failed: {str(e)}")
            traceback.print_exc()
            return None

        finally:
            # Cleanup
            self.cleanup_test_data()


def main():
    """Main function to run manual tests"""
    print("ShiftMaster & ShiftAssignment Manual Testing Suite")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Timezone: Asia/Kolkata (IST)")
    print("=" * 60)

    # Verify Django settings
    try:
        from django.conf import settings
        print(f"Django TIME_ZONE: {getattr(settings, 'TIME_ZONE', 'Not set')}")
        print(f"Django USE_TZ: {getattr(settings, 'USE_TZ', 'Not set')}")
    except:
        print("Warning: Could not verify Django settings")

    # Initialize and run tester
    tester = ManualShiftTester()
    results = tester.run_all_tests()

    if results:
        print(f"\nTesting completed with {results['success_rate']:.1f}% success rate")
        if results['success_rate'] >= 80:
            print("🎉 Excellent! Most tests passed successfully.")
        elif results['success_rate'] >= 60:
            print("⚠️  Good progress, but some issues need attention.")
        else:
            print("❌ Multiple issues found. Please review the failures.")
    else:
        print("❌ Testing failed to complete properly.")

    print(f"\nCompleted at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


if __name__ == "__main__":
    main()
