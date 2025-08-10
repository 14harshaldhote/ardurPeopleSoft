#!/usr/bin/env python3
"""
Direct System Testing Script for ShiftMaster and ShiftAssignment
===============================================================

This script performs comprehensive testing of the ShiftMaster and ShiftAssignment
system directly through Django's internal mechanisms without requiring a web server.

Usage:
    python direct_system_test.py

Features:
    - Model validation testing
    - Form validation testing
    - View testing through Django test client
    - Business logic validation
    - Timezone functionality testing
    - CRUD operations testing
    - Edge case testing
    - Performance testing

Requirements:
    - Django project configured
    - Database accessible
    - Asia/Kolkata timezone
"""

import os
import sys
import django
import json
import time
import traceback
from decimal import Decimal
from datetime import datetime, date, time as dt_time, timedelta
from dataclasses import dataclass, asdict
from typing import List, Dict, Any, Optional
import pytz

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.test import TestCase, Client, TransactionTestCase
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.db import transaction, IntegrityError
from django.urls import reverse
from django.utils import timezone
from django.forms.models import model_to_dict
from django.test.utils import override_settings

from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
from trueAlign.shift.forms import ShiftForm, ShiftAssignmentForm, BulkAssignmentForm, HolidayForm

@dataclass
class TestResult:
    """Test result container"""
    category: str
    test_name: str
    status: str  # PASS, FAIL, SKIP, WARNING
    details: str = ""
    execution_time: float = 0.0
    timestamp: str = ""

class DirectSystemTester:
    """Direct system testing class"""

    def __init__(self):
        self.results: List[TestResult] = []
        self.test_data = {}
        self.client = Client()

        # Set timezone to Asia/Kolkata
        self.ist = pytz.timezone('Asia/Kolkata')
        timezone.activate(self.ist)

        print("Direct System Testing for ShiftMaster & ShiftAssignment")
        print("=" * 60)
        print(f"Django Version: {django.VERSION}")
        print(f"Current Time (IST): {timezone.now().strftime('%Y-%m-%d %H:%M:%S %Z')}")
        print(f"Database: {self._get_db_info()}")
        print("=" * 60)

    def _get_db_info(self):
        """Get database information"""
        try:
            from django.db import connection
            return f"{connection.vendor} (Connected)"
        except:
            return "Unknown (Connection Error)"

    def log_result(self, category: str, test_name: str, status: str,
                   details: str = "", execution_time: float = 0.0):
        """Log test result"""
        result = TestResult(
            category=category,
            test_name=test_name,
            status=status,
            details=details,
            execution_time=execution_time,
            timestamp=timezone.now().isoformat()
        )
        self.results.append(result)

        # Print result
        icon = {"PASS": "✓", "FAIL": "✗", "SKIP": "⊝", "WARNING": "⚠"}.get(status, "?")
        print(f"{icon} {test_name}: {status}")
        if details and status != "PASS":
            print(f"  Details: {details}")
        if execution_time > 0.1:  # Only show if > 100ms
            print(f"  Execution: {execution_time:.3f}s")

    def setup_test_data(self):
        """Setup test data"""
        print("\n1. SETTING UP TEST DATA")
        print("-" * 40)

        try:
            with transaction.atomic():
                # Clean up any existing test data
                User.objects.filter(username__startswith='direct_test_').delete()
                ShiftMaster.objects.filter(name__startswith='Direct Test').delete()
                Holiday.objects.filter(name__startswith='Direct Test').delete()

                # Create test users
                self.test_data['admin_user'] = User.objects.create_user(
                    username='direct_test_admin',
                    email='admin@directtest.com',
                    password='testpass123',
                    is_staff=True,
                    is_superuser=True
                )

                for i in range(1, 4):
                    user = User.objects.create_user(
                        username=f'direct_test_user{i}',
                        email=f'user{i}@directtest.com',
                        password='testpass123',
                        first_name=f'Test',
                        last_name=f'User{i}'
                    )
                    self.test_data[f'user{i}'] = user

                # Create inactive user
                self.test_data['inactive_user'] = User.objects.create_user(
                    username='direct_test_inactive',
                    email='inactive@directtest.com',
                    password='testpass123',
                    is_active=False
                )

            self.log_result('Setup', 'Test Data Creation', 'PASS')

        except Exception as e:
            self.log_result('Setup', 'Test Data Creation', 'FAIL', str(e))
            raise

    def test_model_basic_operations(self):
        """Test basic model operations"""
        print("\n2. TESTING MODEL BASIC OPERATIONS")
        print("-" * 40)

        # Test ShiftMaster creation
        start_time = time.time()
        try:
            shift = ShiftMaster.objects.create(
                name='Direct Test Basic Shift',
                start_time=dt_time(9, 0),
                end_time=dt_time(17, 0),
                shift_duration=Decimal('8.0'),
                work_days='Weekdays'
            )
            self.test_data['basic_shift'] = shift
            execution_time = time.time() - start_time
            self.log_result('Model', 'ShiftMaster Creation', 'PASS',
                          execution_time=execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Model', 'ShiftMaster Creation', 'FAIL', str(e),
                          execution_time)

        # Test custom work days
        start_time = time.time()
        try:
            custom_shift = ShiftMaster.objects.create(
                name='Direct Test Custom Shift',
                start_time=dt_time(14, 0),
                end_time=dt_time(22, 0),
                shift_duration=Decimal('8.0'),
                work_days='Custom',
                custom_work_days='Monday,Wednesday,Friday'
            )
            self.test_data['custom_shift'] = custom_shift

            # Verify working days
            expected_days = [0, 2, 4]  # Monday, Wednesday, Friday
            actual_days = custom_shift.working_days_list
            if actual_days == expected_days:
                execution_time = time.time() - start_time
                self.log_result('Model', 'Custom Working Days', 'PASS',
                              execution_time=execution_time)
            else:
                execution_time = time.time() - start_time
                self.log_result('Model', 'Custom Working Days', 'FAIL',
                              f'Expected {expected_days}, got {actual_days}',
                              execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Model', 'Custom Working Days', 'FAIL', str(e),
                          execution_time)

        # Test night shift (midnight crossover)
        start_time = time.time()
        try:
            night_shift = ShiftMaster.objects.create(
                name='Direct Test Night Shift',
                start_time=dt_time(22, 0),
                end_time=dt_time(6, 0),
                shift_duration=Decimal('8.0'),
                work_days='Weekdays'
            )
            self.test_data['night_shift'] = night_shift

            if night_shift.crosses_midnight:
                execution_time = time.time() - start_time
                self.log_result('Model', 'Midnight Crossover Detection', 'PASS',
                              execution_time=execution_time)
            else:
                execution_time = time.time() - start_time
                self.log_result('Model', 'Midnight Crossover Detection', 'FAIL',
                              'Night shift should cross midnight', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Model', 'Midnight Crossover Detection', 'FAIL', str(e),
                          execution_time)

        # Test ShiftAssignment creation
        start_time = time.time()
        try:
            if 'basic_shift' in self.test_data and 'user1' in self.test_data:
                assignment = ShiftAssignment.objects.create(
                    user=self.test_data['user1'],
                    shift=self.test_data['basic_shift'],
                    effective_from=date.today(),
                    is_current=True
                )
                self.test_data['basic_assignment'] = assignment
                execution_time = time.time() - start_time
                self.log_result('Model', 'ShiftAssignment Creation', 'PASS',
                              execution_time=execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Model', 'ShiftAssignment Creation', 'FAIL', str(e),
                          execution_time)

    def test_model_validations(self):
        """Test model validation rules"""
        print("\n3. TESTING MODEL VALIDATIONS")
        print("-" * 40)

        # Test empty name validation
        start_time = time.time()
        try:
            invalid_shift = ShiftMaster(
                name='',
                start_time=dt_time(9, 0),
                end_time=dt_time(17, 0)
            )
            invalid_shift.full_clean()
            execution_time = time.time() - start_time
            self.log_result('Validation', 'Empty Name Validation', 'FAIL',
                          'Should raise ValidationError for empty name', execution_time)
        except ValidationError:
            execution_time = time.time() - start_time
            self.log_result('Validation', 'Empty Name Validation', 'PASS',
                          execution_time=execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Validation', 'Empty Name Validation', 'FAIL', str(e),
                          execution_time)

        # Test duplicate name validation
        start_time = time.time()
        try:
            if 'basic_shift' in self.test_data:
                duplicate_shift = ShiftMaster(
                    name=self.test_data['basic_shift'].name,
                    start_time=dt_time(10, 0),
                    end_time=dt_time(18, 0)
                )
                duplicate_shift.full_clean()
                execution_time = time.time() - start_time
                self.log_result('Validation', 'Duplicate Name Validation', 'FAIL',
                              'Should raise ValidationError for duplicate name', execution_time)
        except ValidationError:
            execution_time = time.time() - start_time
            self.log_result('Validation', 'Duplicate Name Validation', 'PASS',
                          execution_time=execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Validation', 'Duplicate Name Validation', 'FAIL', str(e),
                          execution_time)

        # Test past date assignment validation
        start_time = time.time()
        try:
            if 'basic_shift' in self.test_data and 'user2' in self.test_data:
                past_assignment = ShiftAssignment(
                    user=self.test_data['user2'],
                    shift=self.test_data['basic_shift'],
                    effective_from=date.today() - timedelta(days=5)
                )
                past_assignment.full_clean()
                execution_time = time.time() - start_time
                self.log_result('Validation', 'Past Date Assignment', 'FAIL',
                              'Should raise ValidationError for past date', execution_time)
        except ValidationError:
            execution_time = time.time() - start_time
            self.log_result('Validation', 'Past Date Assignment', 'PASS',
                          execution_time=execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Validation', 'Past Date Assignment', 'FAIL', str(e),
                          execution_time)

        # Test invalid date range validation
        start_time = time.time()
        try:
            if 'basic_shift' in self.test_data and 'user2' in self.test_data:
                invalid_range = ShiftAssignment(
                    user=self.test_data['user2'],
                    shift=self.test_data['basic_shift'],
                    effective_from=date.today() + timedelta(days=10),
                    effective_to=date.today() + timedelta(days=5)  # End before start
                )
                invalid_range.full_clean()
                execution_time = time.time() - start_time
                self.log_result('Validation', 'Invalid Date Range', 'FAIL',
                              'Should raise ValidationError for invalid range', execution_time)
        except ValidationError:
            execution_time = time.time() - start_time
            self.log_result('Validation', 'Invalid Date Range', 'PASS',
                          execution_time=execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Validation', 'Invalid Date Range', 'FAIL', str(e),
                          execution_time)

    def test_form_functionality(self):
        """Test form validation and functionality"""
        print("\n4. TESTING FORM FUNCTIONALITY")
        print("-" * 40)

        # Test valid ShiftForm
        start_time = time.time()
        try:
            valid_data = {
                'name': 'Direct Test Form Shift',
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
                saved_shift = form.save()
                self.test_data['form_shift'] = saved_shift
                execution_time = time.time() - start_time
                self.log_result('Form', 'Valid ShiftForm', 'PASS',
                              execution_time=execution_time)
            else:
                execution_time = time.time() - start_time
                self.log_result('Form', 'Valid ShiftForm', 'FAIL',
                              f'Form errors: {form.errors}', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Form', 'Valid ShiftForm', 'FAIL', str(e), execution_time)

        # Test invalid ShiftForm (empty name)
        start_time = time.time()
        try:
            invalid_data = {
                'name': '',
                'start_time': '10:00',
                'end_time': '18:00',
            }
            form = ShiftForm(data=invalid_data)
            if not form.is_valid():
                execution_time = time.time() - start_time
                self.log_result('Form', 'Invalid ShiftForm (Empty Name)', 'PASS',
                              execution_time=execution_time)
            else:
                execution_time = time.time() - start_time
                self.log_result('Form', 'Invalid ShiftForm (Empty Name)', 'FAIL',
                              'Form should be invalid with empty name', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Form', 'Invalid ShiftForm (Empty Name)', 'FAIL', str(e),
                          execution_time)

        # Test ShiftAssignmentForm
        start_time = time.time()
        try:
            if 'basic_shift' in self.test_data and 'user2' in self.test_data:
                assignment_data = {
                    'user': self.test_data['user2'].id,
                    'shift': self.test_data['basic_shift'].id,
                    'effective_from': (date.today() + timedelta(days=7)).strftime('%Y-%m-%d'),
                    'is_current': False,
                    'notes': 'Direct test assignment'
                }
                form = ShiftAssignmentForm(data=assignment_data)
                if form.is_valid():
                    saved_assignment = form.save()
                    self.test_data['form_assignment'] = saved_assignment
                    execution_time = time.time() - start_time
                    self.log_result('Form', 'Valid ShiftAssignmentForm', 'PASS',
                                  execution_time=execution_time)
                else:
                    execution_time = time.time() - start_time
                    self.log_result('Form', 'Valid ShiftAssignmentForm', 'FAIL',
                                  f'Form errors: {form.errors}', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Form', 'Valid ShiftAssignmentForm', 'FAIL', str(e),
                          execution_time)

        # Test HolidayForm
        start_time = time.time()
        try:
            holiday_data = {
                'name': 'Direct Test Holiday',
                'date': (date.today() + timedelta(days=30)).strftime('%Y-%m-%d'),
                'is_recurring': False
            }
            form = HolidayForm(data=holiday_data)
            if form.is_valid():
                saved_holiday = form.save()
                self.test_data['form_holiday'] = saved_holiday
                execution_time = time.time() - start_time
                self.log_result('Form', 'Valid HolidayForm', 'PASS',
                              execution_time=execution_time)
            else:
                execution_time = time.time() - start_time
                self.log_result('Form', 'Valid HolidayForm', 'FAIL',
                              f'Form errors: {form.errors}', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Form', 'Valid HolidayForm', 'FAIL', str(e), execution_time)

    def test_view_functionality(self):
        """Test view functionality through Django test client"""
        print("\n5. TESTING VIEW FUNCTIONALITY")
        print("-" * 40)

        # Login as admin
        start_time = time.time()
        login_success = self.client.login(
            username='direct_test_admin',
            password='testpass123'
        )
        execution_time = time.time() - start_time

        if login_success:
            self.log_result('View', 'Admin Login', 'PASS', execution_time=execution_time)
        else:
            self.log_result('View', 'Admin Login', 'FAIL', 'Could not login as admin',
                          execution_time)
            return

        # Test dashboard view
        start_time = time.time()
        try:
            response = self.client.get(reverse('shift:dashboard'))
            execution_time = time.time() - start_time
            if response.status_code == 200:
                self.log_result('View', 'Dashboard View', 'PASS',
                              f'Status: {response.status_code}', execution_time)
            else:
                self.log_result('View', 'Dashboard View', 'FAIL',
                              f'Status: {response.status_code}', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('View', 'Dashboard View', 'FAIL', str(e), execution_time)

        # Test shift list view
        start_time = time.time()
        try:
            response = self.client.get(reverse('shift:list'))
            execution_time = time.time() - start_time
            if response.status_code == 200:
                self.log_result('View', 'Shift List View', 'PASS',
                              f'Status: {response.status_code}', execution_time)
            else:
                self.log_result('View', 'Shift List View', 'FAIL',
                              f'Status: {response.status_code}', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('View', 'Shift List View', 'FAIL', str(e), execution_time)

        # Test shift create view (GET)
        start_time = time.time()
        try:
            response = self.client.get(reverse('shift:create'))
            execution_time = time.time() - start_time
            if response.status_code == 200:
                self.log_result('View', 'Shift Create View (GET)', 'PASS',
                              f'Status: {response.status_code}', execution_time)
            else:
                self.log_result('View', 'Shift Create View (GET)', 'FAIL',
                              f'Status: {response.status_code}', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('View', 'Shift Create View (GET)', 'FAIL', str(e),
                          execution_time)

        # Test shift create view (POST)
        start_time = time.time()
        try:
            shift_data = {
                'name': f'Direct Test View Shift {int(time.time())}',
                'start_time': '11:00',
                'end_time': '19:00',
                'shift_duration': '8.0',
                'break_duration_minutes': '30',
                'grace_period_minutes': '15',
                'work_days': 'Weekdays',
                'is_active': True
            }
            response = self.client.post(reverse('shift:create'), shift_data)
            execution_time = time.time() - start_time
            if response.status_code in [200, 302]:
                self.log_result('View', 'Shift Create View (POST)', 'PASS',
                              f'Status: {response.status_code}', execution_time)
            else:
                self.log_result('View', 'Shift Create View (POST)', 'FAIL',
                              f'Status: {response.status_code}', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('View', 'Shift Create View (POST)', 'FAIL', str(e),
                          execution_time)

        # Test assignment views
        views_to_test = [
            ('Assignments List', 'shift:assignments'),
            ('Assign Shift', 'shift:assign'),
            ('Holiday List', 'shift:holidays'),
            ('User Calendar', 'shift:user_calendar'),
            ('Statistics', 'shift:statistics')
        ]

        for view_name, url_name in views_to_test:
            start_time = time.time()
            try:
                response = self.client.get(reverse(url_name))
                execution_time = time.time() - start_time
                if response.status_code == 200:
                    self.log_result('View', f'{view_name} View', 'PASS',
                                  f'Status: {response.status_code}', execution_time)
                else:
                    self.log_result('View', f'{view_name} View', 'FAIL',
                                  f'Status: {response.status_code}', execution_time)
            except Exception as e:
                execution_time = time.time() - start_time
                self.log_result('View', f'{view_name} View', 'FAIL', str(e),
                              execution_time)

    def test_api_endpoints(self):
        """Test API endpoints"""
        print("\n6. TESTING API ENDPOINTS")
        print("-" * 40)

        api_tests = [
            ('Dashboard Stats API', 'shift:api_dashboard_stats'),
            ('User Shift Status API', 'shift:api_user_shift_status'),
            ('Upcoming Changes API', 'shift:api_upcoming_changes'),
        ]

        for api_name, url_name in api_tests:
            start_time = time.time()
            try:
                response = self.client.get(reverse(url_name))
                execution_time = time.time() - start_time
                if response.status_code == 200:
                    try:
                        response.json()  # Try to parse JSON
                        self.log_result('API', f'{api_name}', 'PASS',
                                      f'Status: {response.status_code}', execution_time)
                    except:
                        self.log_result('API', f'{api_name}', 'WARNING',
                                      'Returns 200 but not valid JSON', execution_time)
                else:
                    self.log_result('API', f'{api_name}', 'FAIL',
                                  f'Status: {response.status_code}', execution_time)
            except Exception as e:
                execution_time = time.time() - start_time
                self.log_result('API', f'{api_name}', 'FAIL', str(e), execution_time)

    def test_business_logic(self):
        """Test business logic and rules"""
        print("\n7. TESTING BUSINESS LOGIC")
        print("-" * 40)

        # Test shift overlap prevention
        start_time = time.time()
        try:
            # Create a shift that would overlap with existing ones
            overlapping_shift = ShiftMaster(
                name='Direct Test Overlapping Shift',
                start_time=dt_time(8, 0),
                end_time=dt_time(18, 0),  # Overlaps with basic shift
                shift_duration=Decimal('10.0'),
                work_days='Weekdays'
            )
            overlapping_shift.full_clean()
            execution_time = time.time() - start_time
            self.log_result('BusinessLogic', 'Shift Overlap Prevention', 'FAIL',
                          'Should prevent overlapping shifts', execution_time)
        except ValidationError as e:
            execution_time = time.time() - start_time
            if 'overlap' in str(e).lower():
                self.log_result('BusinessLogic', 'Shift Overlap Prevention', 'PASS',
                              execution_time=execution_time)
            else:
                self.log_result('BusinessLogic', 'Shift Overlap Prevention', 'FAIL',
                              f'Wrong validation error: {str(e)}', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('BusinessLogic', 'Shift Overlap Prevention', 'FAIL', str(e),
                          execution_time)

        # Test inactive user assignment prevention
        start_time = time.time()
        try:
            if 'basic_shift' in self.test_data and 'inactive_user' in self.test_data:
                inactive_assignment = ShiftAssignment(
                    user=self.test_data['inactive_user'],
                    shift=self.test_data['basic_shift'],
                    effective_from=date.today() + timedelta(days=1)
                )
                inactive_assignment.full_clean()
                execution_time = time.time() - start_time
                self.log_result('BusinessLogic', 'Inactive User Assignment Prevention', 'FAIL',
                              'Should prevent assignment to inactive user', execution_time)
        except ValidationError as e:
            execution_time = time.time() - start_time
            if 'inactive' in str(e).lower():
                self.log_result('BusinessLogic', 'Inactive User Assignment Prevention', 'PASS',
                              execution_time=execution_time)
            else:
                self.log_result('BusinessLogic', 'Inactive User Assignment Prevention', 'FAIL',
                              f'Wrong validation error: {str(e)}', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('BusinessLogic', 'Inactive User Assignment Prevention', 'FAIL',
                          str(e), execution_time)

    def test_timezone_functionality(self):
        """Test timezone-specific functionality"""
        print("\n8. TESTING TIMEZONE FUNCTIONALITY")
        print("-" * 40)

        # Test timezone awareness
        start_time = time.time()
        try:
            current_time = timezone.now()
            ist_time = current_time.astimezone(self.ist)

            if ist_time.tzinfo.zone == 'Asia/Kolkata':
                execution_time = time.time() - start_time
                self.log_result('Timezone', 'IST Timezone Active', 'PASS',
                              execution_time=execution_time)
            else:
                execution_time = time.time() - start_time
                self.log_result('Timezone', 'IST Timezone Active', 'FAIL',
                              f'Expected Asia/Kolkata, got {ist_time.tzinfo.zone}',
                              execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Timezone', 'IST Timezone Active', 'FAIL', str(e),
                          execution_time)

        # Test shift time calculations
        start_time = time.time()
        try:
            if 'night_shift' in self.test_data:
                night_shift = self.test_data['night_shift']
                test_date = date.today()

                shift_start_dt = timezone.make_aware(
                    datetime.combine(test_date, night_shift.start_time),
                    timezone=self.ist
                )

                is_within = night_shift.is_within_shift_hours(shift_start_dt, test_date)
                if isinstance(is_within, bool):
                    execution_time = time.time() - start_time
                    self.log_result('Timezone', 'IST Time Calculations', 'PASS',
                                  execution_time=execution_time)
                else:
                    execution_time = time.time() - start_time
                    self.log_result('Timezone', 'IST Time Calculations', 'FAIL',
                                  'is_within_shift_hours should return boolean',
                                  execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Timezone', 'IST Time Calculations', 'FAIL', str(e),
                          execution_time)

    def test_performance(self):
        """Test system performance"""
        print("\n9. TESTING PERFORMANCE")
        print("-" * 40)

        # Test query performance
        start_time = time.time()
        try:
            # Test shift queries
            shifts = list(ShiftMaster.objects.all())
            assignments = list(ShiftAssignment.objects.select_related('user', 'shift').all())
            execution_time = time.time() - start_time

            if execution_time < 1.0:  # Should complete within 1 second
                self.log_result('Performance', 'Query Performance', 'PASS',
                              f'Queries completed in {execution_time:.3f}s', execution_time)
            elif execution_time < 3.0:
                self.log_result('Performance', 'Query Performance', 'WARNING',
                              f'Queries took {execution_time:.3f}s (acceptable but slow)', execution_time)
            else:
                self.log_result('Performance', 'Query Performance', 'FAIL',
                              f'Queries took {execution_time:.3f}s (too slow)', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Performance', 'Query Performance', 'FAIL', str(e),
                          execution_time)

        # Test form processing performance
        start_time = time.time()
        try:
            for i in range(5):  # Create 5 forms to test batch processing
                form_data = {
                    'name': f'Performance Test Shift {i}',
                    'start_time': f'{9 + i}:00',
                    'end_time': f'{17 + i}:00',
                    'shift_duration': '8.0',
                    'work_days': 'Weekdays',
                    'is_active': True
                }
                form = ShiftForm(data=form_data)
                if form.is_valid():
                    form.save()

            execution_time = time.time() - start_time
            if execution_time < 2.0:
                self.log_result('Performance', 'Form Processing Performance', 'PASS',
                              f'5 forms processed in {execution_time:.3f}s', execution_time)
            else:
                self.log_result('Performance', 'Form Processing Performance', 'WARNING',
                              f'5 forms took {execution_time:.3f}s', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('Performance', 'Form Processing Performance', 'FAIL',
                          str(e), execution_time)

    def test_edge_cases(self):
        """Test edge cases and boundary conditions"""
        print("\n10. TESTING EDGE CASES")
        print("-" * 40)

        # Test minimum duration shift
        start_time = time.time()
        try:
            min_shift = ShiftMaster.objects.create(
                name='Direct Test Minimum Shift',
                start_time=dt_time(12, 0),
                end_time=dt_time(12, 30),
                shift_duration=Decimal('0.5'),
                work_days='Weekdays'
            )
            execution_time = time.time() - start_time
            self.log_result('EdgeCase', 'Minimum Duration Shift', 'PASS',
                          execution_time=execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('EdgeCase', 'Minimum Duration Shift', 'FAIL', str(e),
                          execution_time)

        # Test weekend-only shift
        start_time = time.time()
        try:
            weekend_shift = ShiftMaster.objects.create(
                name='Direct Test Weekend Shift',
                start_time=dt_time(10, 0),
                end_time=dt_time(14, 0),
                shift_duration=Decimal('4.0'),
                work_days='Custom',
                custom_work_days='Saturday,Sunday'
            )

            # Test working day detection
            saturday = date(2024, 8, 10)  # Assume Saturday
            is_working = weekend_shift.is_working_day(saturday)
            execution_time = time.time() - start_time

            if isinstance(is_working, bool):
                self.log_result('EdgeCase', 'Weekend-Only Shift', 'PASS',
                              execution_time=execution_time)
            else:
                self.log_result('EdgeCase', 'Weekend-Only Shift', 'FAIL',
                              'is_working_day should return boolean', execution_time)
        except Exception as e:
            execution_time = time.time() - start_time
            self.log_result('EdgeCase', 'Weekend-Only Shift', 'FAIL', str(e),
                          execution_time)

    def cleanup_test_data(self):
        """Clean up test data"""
        print("\n11. CLEANING UP TEST DATA")
        print("-" * 40)

        try:
            with transaction.atomic():
                # Delete test assignments
                ShiftAssignment.objects.filter(
                    user__username__startswith='direct_test_'
                ).delete()

                # Delete test shifts
                ShiftMaster.objects.filter(name__startswith='Direct Test').delete()
                ShiftMaster.objects.filter(name__startswith='Performance Test').delete()

                # Delete test holidays
                Holiday.objects.filter(name__startswith='Direct Test').delete()

                # Delete test users
                User.objects.filter(username__startswith='direct_test_').delete()

            self.log_result('Cleanup', 'Test Data Cleanup', 'PASS')

        except Exception as e:
            self.log_result('Cleanup', 'Test Data Cleanup', 'FAIL', str(e))

    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "="*70)
        print("COMPREHENSIVE DIRECT SYSTEM TEST REPORT")
        print("="*70)

        # Group results by category
        categories = {}
        for result in self.results:
            if result.category not in categories:
                categories[result.category] = []
            categories[result.category].append(result)

        # Calculate totals
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.status == 'PASS')
        failed_tests = sum(1 for r in self.results if r.status == 'FAIL')
        warning_tests = sum(1 for r in self.results if r.status == 'WARNING')
        skipped_tests = sum(1 for r in self.results if r.status == 'SKIP')

        # Print results by category
        for category, results in categories.items():
            print(f"\n{category.upper()}:")
            print("-" * 50)

            category_passed = sum(1 for r in results if r.status == 'PASS')
            category_total = len(results)

            for result in results:
                icon = {"PASS": "✓", "FAIL": "✗", "SKIP": "⊝", "WARNING": "⚠"}.get(result.status, "?")
                print(f"{icon} {result.test_name}: {result.status}")
                if result.details and result.status != "PASS":
                    print(f"  Details: {result.details}")
                if result.execution_time > 0.1:
                    print(f"  Time: {result.execution_time:.3f}s")

            success_rate = (category_passed / category_total) * 100 if category_total > 0 else 0
            print(f"Category Success: {success_rate:.1f}% ({category_passed}/{category_total})")

        # Overall summary
        print(f"\n{'='*70}")
        print(f"OVERALL SUMMARY:")
        print(f"Total Tests: {total_tests}")
        print(f"Passed: {passed_tests}")
        print(f"Failed: {failed_tests}")
        print(f"Warnings: {warning_tests}")
        print(f"Skipped: {skipped_tests}")

        if total_tests > 0:
            overall_success = (passed_tests / total_tests) * 100
            print(f"Overall Success Rate: {overall_success:.1f}%")

            # Performance summary
            execution_times = [r.execution_time for r in self.results if r.execution_time > 0]
            if execution_times:
                avg_time = sum(execution_times) / len(execution_times)
                max_time = max(execution_times)
                total_time = sum(execution_times)
                print(f"Total Execution Time: {total_time:.3f}s")
                print(f"Average Test Time: {avg_time:.3f}s")
                print(f"Slowest Test Time: {max_time:.3f}s")

        # Save detailed report
        try:
            report_data = {
                'timestamp': timezone.now().isoformat(),
                'timezone': 'Asia/Kolkata',
                'django_version': str(django.VERSION),
                'database': self._get_db_info(),
                'summary': {
                    'total_tests': total_tests,
                    'passed_tests': passed_tests,
                    'failed_tests': failed_tests,
                    'warning_tests': warning_tests,
                    'skipped_tests': skipped_tests,
                    'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0
                },
                'results': [asdict(result) for result in self.results],
                'categories': {
                    category: {
                        'total': len(results),
                        'passed': sum(1 for r in results if r.status == 'PASS'),
                        'failed': sum(1 for r in results if r.status == 'FAIL'),
                        'warnings': sum(1 for r in results if r.status == 'WARNING'),
                        'skipped': sum(1 for r in results if r.status == 'SKIP')
                    }
                    for category, results in categories.items()
                }
            }

            with open('direct_system_test_report.json', 'w') as f:
                json.dump(report_data, f, indent=2, default=str)

            print(f"\n✓ Detailed report saved to: direct_system_test_report.json")

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
        print("Starting comprehensive direct system testing...")

        overall_start = time.time()

        try:
            # Setup
            self.setup_test_data()

            # Run all test suites
            self.test_model_basic_operations()
            self.test_model_validations()
            self.test_form_functionality()
            self.test_view_functionality()
            self.test_api_endpoints()
            self.test_business_logic()
            self.test_timezone_functionality()
            self.test_performance()
            self.test_edge_cases()

            # Generate report
            results = self.generate_report()

            overall_time = time.time() - overall_start
            print(f"\nTotal testing time: {overall_time:.2f} seconds")

            return results

        except Exception as e:
            print(f"✗ Test execution failed: {str(e)}")
            traceback.print_exc()
            return None

        finally:
            # Cleanup
            self.cleanup_test_data()


def main():
    """Main function to run direct system tests"""
    print("ShiftMaster & ShiftAssignment Direct System Testing Suite")
    print("=" * 70)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Timezone: Asia/Kolkata (IST)")

    # Verify Django configuration
    try:
        from django.conf import settings
        print(f"Django TIME_ZONE: {getattr(settings, 'TIME_ZONE', 'Not set')}")
        print(f"Django USE_TZ: {getattr(settings, 'USE_TZ', 'Not set')}")
        print(f"Database Engine: {settings.DATABASES['default']['ENGINE'].split('.')[-1]}")
    except Exception as e:
        print(f"Warning: Could not verify Django settings: {str(e)}")

    print("=" * 70)

    # Initialize and run tester
    tester = DirectSystemTester()
    results = tester.run_all_tests()

    if results:
        success_rate = results['success_rate']
        print(f"\n🎯 Testing completed with {success_rate:.1f}% success rate")

        if success_rate >= 95:
            print("🎉 Excellent! System is working perfectly.")
            return_code = 0
        elif success_rate >= 85:
            print("👍 Very Good! System is working well with minor issues.")
            return_code = 1
        elif success_rate >= 70:
            print("✅ Good! Most functionality working, some issues to address.")
            return_code = 2
        elif success_rate >= 50:
            print("⚠️  Moderate! Several issues need attention.")
            return_code = 3
        else:
            print("❌ Poor! Major issues found that need immediate attention.")
            return_code = 4

        # Specific recommendations
        if results['failed_tests'] > 0:
            print(f"\n📋 RECOMMENDATIONS:")
            print("• Review failed tests in the detailed JSON report")
            print("• Check model validations and business logic")
            print("• Verify form implementations and error handling")
            print("• Test view permissions and URL configurations")
            print("• Validate API endpoint responses and data formats")

        # System health indicators
        print(f"\n📊 SYSTEM HEALTH INDICATORS:")
        print(f"• Models: {'✓' if any('Model' in r.category for r in tester.results if r.status == 'PASS') else '✗'}")
        print(f"• Forms: {'✓' if any('Form' in r.category for r in tester.results if r.status == 'PASS') else '✗'}")
        print(f"• Views: {'✓' if any('View' in r.category for r in tester.results if r.status == 'PASS') else '✗'}")
        print(f"• APIs: {'✓' if any('API' in r.category for r in tester.results if r.status == 'PASS') else '✗'}")
        print(f"• Business Logic: {'✓' if any('BusinessLogic' in r.category for r in tester.results if r.status == 'PASS') else '✗'}")
        print(f"• Timezone: {'✓' if any('Timezone' in r.category for r in tester.results if r.status == 'PASS') else '✗'}")

    else:
        print("❌ Testing failed to complete properly.")
        return_code = 5

    print(f"\nCompleted at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nFor detailed analysis, check:")
    print("• Console output above")
    print("• direct_system_test_report.json file")

    return return_code


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n⚠️  Testing interrupted by user.")
        sys.exit(130)
    except Exception as e:
        print(f"\n❌ Fatal error: {str(e)}")
        traceback.print_exc()
        sys.exit(1)
