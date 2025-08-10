#!/usr/bin/env python3
"""
Frontend Testing Script for ShiftMaster and ShiftAssignment Modules
==================================================================

This script performs comprehensive frontend testing of the ShiftMaster and
ShiftAssignment modules, including all HTML pages, forms, CRUD operations,
and user interface elements.

Usage:
    python frontend_shift_test.py

Requirements:
    - Django server running on localhost:8000
    - Admin user credentials
    - Asia/Kolkata timezone configured
"""

import os
import sys
import requests
import json
import time
from datetime import datetime, date, timedelta
from urllib.parse import urljoin, urlparse
import re
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

@dataclass
class TestResult:
    """Test result data class"""
    test_name: str
    status: str  # PASS, FAIL, SKIP, WARNING
    details: str = ""
    response_time: float = 0.0
    status_code: int = 0
    timestamp: str = ""

class FrontendShiftTester:
    """Comprehensive frontend testing for shift management system"""

    def __init__(self, base_url="http://localhost:8000", username="admin", password="admin"):
        self.base_url = base_url.rstrip('/')
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.csrf_token = None
        self.results: List[TestResult] = []
        self.test_data = {}

        # Configure session
        self.session.headers.update({
            'User-Agent': 'ShiftSystemTester/1.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

        print("Frontend Shift System Testing")
        print("=" * 50)
        print(f"Base URL: {self.base_url}")
        print(f"Timezone: Asia/Kolkata (IST)")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 50)

    def log_result(self, test_name: str, status: str, details: str = "",
                   response_time: float = 0.0, status_code: int = 0):
        """Log test result"""
        result = TestResult(
            test_name=test_name,
            status=status,
            details=details,
            response_time=response_time,
            status_code=status_code,
            timestamp=datetime.now().isoformat()
        )
        self.results.append(result)

        # Print result
        icon = {"PASS": "✓", "FAIL": "✗", "SKIP": "⊝", "WARNING": "⚠"}.get(status, "?")
        print(f"{icon} {test_name}: {status}")
        if details and status != "PASS":
            print(f"  Details: {details}")
        if response_time > 0:
            print(f"  Response time: {response_time:.2f}s")

    def get_csrf_token(self, html_content: str) -> Optional[str]:
        """Extract CSRF token from HTML content"""
        csrf_match = re.search(r'name=[\'"]csrfmiddlewaretoken[\'"] value=[\'"]([^\'"]+)[\'"]', html_content)
        if csrf_match:
            return csrf_match.group(1)

        # Alternative pattern
        csrf_match = re.search(r'csrfmiddlewaretoken[\'"] value=[\'"]([^\'"]+)[\'"]', html_content)
        if csrf_match:
            return csrf_match.group(1)

        return None

    def make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """Make HTTP request with error handling"""
        full_url = urljoin(self.base_url, url)
        start_time = time.time()

        try:
            response = self.session.request(method, full_url, timeout=30, **kwargs)
            response_time = time.time() - start_time
            return response, response_time
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            # Create mock response for error cases
            class MockResponse:
                status_code = 0
                text = str(e)
                content = b""
                def json(self):
                    return {"error": str(e)}
            return MockResponse(), response_time

    def test_server_accessibility(self):
        """Test if the Django server is accessible"""
        print("\n1. SERVER ACCESSIBILITY TESTS")
        print("-" * 40)

        # Test server root
        response, response_time = self.make_request('GET', '/')
        if response.status_code == 200:
            self.log_result("Server Root Access", "PASS",
                          response_time=response_time, status_code=response.status_code)
        else:
            self.log_result("Server Root Access", "FAIL",
                          f"Server not accessible: {response.status_code}",
                          response_time, response.status_code)
            return False

        # Test shift app root
        response, response_time = self.make_request('GET', '/shift/')
        if response.status_code in [200, 302]:  # 302 might redirect to login
            self.log_result("Shift App Access", "PASS",
                          response_time=response_time, status_code=response.status_code)
            return True
        else:
            self.log_result("Shift App Access", "FAIL",
                          f"Shift app not accessible: {response.status_code}",
                          response_time, response.status_code)
            return False

    def test_authentication(self):
        """Test login functionality"""
        print("\n2. AUTHENTICATION TESTS")
        print("-" * 40)

        # Get login page
        response, response_time = self.make_request('GET', '/admin/login/')
        if response.status_code != 200:
            self.log_result("Login Page Access", "FAIL",
                          f"Cannot access login page: {response.status_code}",
                          response_time, response.status_code)
            return False

        self.log_result("Login Page Access", "PASS",
                      response_time=response_time, status_code=response.status_code)

        # Extract CSRF token
        self.csrf_token = self.get_csrf_token(response.text)
        if not self.csrf_token:
            self.log_result("CSRF Token Extraction", "FAIL", "No CSRF token found")
            return False

        self.log_result("CSRF Token Extraction", "PASS")

        # Attempt login
        login_data = {
            'username': self.username,
            'password': self.password,
            'csrfmiddlewaretoken': self.csrf_token,
            'next': '/shift/'
        }

        response, response_time = self.make_request('POST', '/admin/login/', data=login_data)

        # Check if login was successful (redirect or success page)
        if response.status_code in [200, 302]:
            # Check if we can access a protected page
            test_response, _ = self.make_request('GET', '/shift/')
            if test_response.status_code == 200:
                self.log_result("Admin Login", "PASS",
                              response_time=response_time, status_code=response.status_code)
                return True
            else:
                self.log_result("Admin Login", "FAIL", "Login appeared to succeed but cannot access protected pages")
                return False
        else:
            self.log_result("Admin Login", "FAIL",
                          f"Login failed: {response.status_code}",
                          response_time, response.status_code)
            return False

    def test_shift_pages(self):
        """Test all shift-related pages"""
        print("\n3. SHIFT PAGES TESTS")
        print("-" * 40)

        pages_to_test = [
            ('Dashboard', '/shift/'),
            ('Shift List', '/shift/shifts/'),
            ('Create Shift', '/shift/shifts/create/'),
            ('Statistics', '/shift/statistics/'),
        ]

        for page_name, url in pages_to_test:
            response, response_time = self.make_request('GET', url)

            if response.status_code == 200:
                # Check if page contains expected content
                if 'shift' in response.text.lower() or 'dashboard' in response.text.lower():
                    self.log_result(f"{page_name} Page", "PASS",
                                  response_time=response_time, status_code=response.status_code)
                else:
                    self.log_result(f"{page_name} Page", "WARNING",
                                  "Page loads but may not contain expected content",
                                  response_time, response.status_code)
            else:
                self.log_result(f"{page_name} Page", "FAIL",
                              f"HTTP {response.status_code}",
                              response_time, response.status_code)

    def test_assignment_pages(self):
        """Test assignment-related pages"""
        print("\n4. ASSIGNMENT PAGES TESTS")
        print("-" * 40)

        pages_to_test = [
            ('Assignment List', '/shift/assignments/'),
            ('Assign Shift', '/shift/assignments/assign/'),
            ('Bulk Assign', '/shift/assignments/bulk/'),
        ]

        for page_name, url in pages_to_test:
            response, response_time = self.make_request('GET', url)

            if response.status_code == 200:
                self.log_result(f"{page_name} Page", "PASS",
                              response_time=response_time, status_code=response.status_code)
            else:
                self.log_result(f"{page_name} Page", "FAIL",
                              f"HTTP {response.status_code}",
                              response_time, response.status_code)

    def test_calendar_and_schedule_pages(self):
        """Test calendar and schedule pages"""
        print("\n5. CALENDAR & SCHEDULE TESTS")
        print("-" * 40)

        pages_to_test = [
            ('User Calendar', '/shift/calendar/'),
            ('Schedule View', '/shift/schedule/'),
        ]

        for page_name, url in pages_to_test:
            response, response_time = self.make_request('GET', url)

            if response.status_code == 200:
                self.log_result(f"{page_name} Page", "PASS",
                              response_time=response_time, status_code=response.status_code)
            else:
                self.log_result(f"{page_name} Page", "FAIL",
                              f"HTTP {response.status_code}",
                              response_time, response.status_code)

    def test_holiday_pages(self):
        """Test holiday management pages"""
        print("\n6. HOLIDAY MANAGEMENT TESTS")
        print("-" * 40)

        pages_to_test = [
            ('Holiday List', '/shift/holidays/'),
            ('Create Holiday', '/shift/holidays/create/'),
        ]

        for page_name, url in pages_to_test:
            response, response_time = self.make_request('GET', url)

            if response.status_code == 200:
                self.log_result(f"{page_name} Page", "PASS",
                              response_time=response_time, status_code=response.status_code)
            else:
                self.log_result(f"{page_name} Page", "FAIL",
                              f"HTTP {response.status_code}",
                              response_time, response.status_code)

    def test_shift_crud_operations(self):
        """Test CRUD operations for shifts"""
        print("\n7. SHIFT CRUD OPERATIONS")
        print("-" * 40)

        # Test CREATE operation
        self._test_shift_create()

        # Test READ operations (already tested in page tests)
        self._test_shift_read()

        # Test UPDATE operation
        if 'test_shift_id' in self.test_data:
            self._test_shift_update()

        # Test DELETE operation
        if 'test_shift_id' in self.test_data:
            self._test_shift_delete()

    def _test_shift_create(self):
        """Test shift creation"""
        # Get create form
        response, response_time = self.make_request('GET', '/shift/shifts/create/')
        if response.status_code != 200:
            self.log_result("Shift Create Form", "FAIL", f"Cannot access create form: {response.status_code}")
            return

        # Extract CSRF token from form
        csrf_token = self.get_csrf_token(response.text)
        if not csrf_token:
            self.log_result("Shift Create CSRF", "FAIL", "No CSRF token in create form")
            return

        # Test valid shift creation
        shift_data = {
            'name': f'Frontend Test Shift {int(time.time())}',
            'start_time': '09:00',
            'end_time': '17:00',
            'shift_duration': '8.0',
            'break_duration_minutes': '30',
            'grace_period_minutes': '15',
            'work_days': 'Weekdays',
            'is_active': 'on',
            'csrfmiddlewaretoken': csrf_token
        }

        response, response_time = self.make_request('POST', '/shift/shifts/create/', data=shift_data)

        if response.status_code in [200, 302]:
            if response.status_code == 302:
                # Successful creation usually redirects
                self.log_result("Shift Creation (Valid Data)", "PASS",
                              "Redirected after creation", response_time, response.status_code)

                # Try to extract shift ID from redirect or list page
                if 'Location' in response.headers:
                    location = response.headers['Location']
                    shift_id_match = re.search(r'/shifts/(\d+)/', location)
                    if shift_id_match:
                        self.test_data['test_shift_id'] = shift_id_match.group(1)
            else:
                # Check if form has errors
                if 'error' in response.text.lower() or 'invalid' in response.text.lower():
                    self.log_result("Shift Creation (Valid Data)", "FAIL",
                                  "Form returned with errors", response_time, response.status_code)
                else:
                    self.log_result("Shift Creation (Valid Data)", "PASS",
                                  response_time=response_time, status_code=response.status_code)
        else:
            self.log_result("Shift Creation (Valid Data)", "FAIL",
                          f"HTTP {response.status_code}", response_time, response.status_code)

        # Test invalid shift creation (empty name)
        invalid_data = shift_data.copy()
        invalid_data['name'] = ''

        response, response_time = self.make_request('POST', '/shift/shifts/create/', data=invalid_data)

        if response.status_code == 200 and ('error' in response.text.lower() or 'required' in response.text.lower()):
            self.log_result("Shift Creation (Invalid Data)", "PASS",
                          "Form correctly rejected invalid data", response_time, response.status_code)
        else:
            self.log_result("Shift Creation (Invalid Data)", "FAIL",
                          "Form should reject empty name", response_time, response.status_code)

    def _test_shift_read(self):
        """Test shift detail view"""
        if 'test_shift_id' not in self.test_data:
            self.log_result("Shift Detail View", "SKIP", "No test shift ID available")
            return

        shift_id = self.test_data['test_shift_id']
        response, response_time = self.make_request('GET', f'/shift/shifts/{shift_id}/')

        if response.status_code == 200:
            self.log_result("Shift Detail View", "PASS",
                          response_time=response_time, status_code=response.status_code)
        else:
            self.log_result("Shift Detail View", "FAIL",
                          f"HTTP {response.status_code}", response_time, response.status_code)

    def _test_shift_update(self):
        """Test shift update"""
        shift_id = self.test_data['test_shift_id']

        # Get update form
        response, response_time = self.make_request('GET', f'/shift/shifts/{shift_id}/update/')
        if response.status_code != 200:
            self.log_result("Shift Update Form", "FAIL",
                          f"Cannot access update form: {response.status_code}")
            return

        csrf_token = self.get_csrf_token(response.text)
        if not csrf_token:
            self.log_result("Shift Update CSRF", "FAIL", "No CSRF token in update form")
            return

        # Submit update
        update_data = {
            'name': f'Updated Frontend Test Shift {int(time.time())}',
            'start_time': '09:30',  # Changed time
            'end_time': '17:30',
            'shift_duration': '8.0',
            'break_duration_minutes': '30',
            'grace_period_minutes': '15',
            'work_days': 'Weekdays',
            'is_active': 'on',
            'csrfmiddlewaretoken': csrf_token
        }

        response, response_time = self.make_request('POST', f'/shift/shifts/{shift_id}/update/', data=update_data)

        if response.status_code in [200, 302]:
            self.log_result("Shift Update", "PASS",
                          response_time=response_time, status_code=response.status_code)
        else:
            self.log_result("Shift Update", "FAIL",
                          f"HTTP {response.status_code}", response_time, response.status_code)

    def _test_shift_delete(self):
        """Test shift deletion"""
        shift_id = self.test_data['test_shift_id']

        # Get delete confirmation
        response, response_time = self.make_request('GET', f'/shift/shifts/{shift_id}/delete/')
        if response.status_code != 200:
            self.log_result("Shift Delete Form", "FAIL",
                          f"Cannot access delete form: {response.status_code}")
            return

        csrf_token = self.get_csrf_token(response.text)
        if not csrf_token:
            self.log_result("Shift Delete CSRF", "FAIL", "No CSRF token in delete form")
            return

        # Confirm deletion
        delete_data = {'csrfmiddlewaretoken': csrf_token}
        response, response_time = self.make_request('POST', f'/shift/shifts/{shift_id}/delete/', data=delete_data)

        if response.status_code in [200, 302]:
            self.log_result("Shift Deletion", "PASS",
                          response_time=response_time, status_code=response.status_code)
        else:
            self.log_result("Shift Deletion", "FAIL",
                          f"HTTP {response.status_code}", response_time, response.status_code)

    def test_api_endpoints(self):
        """Test API endpoints"""
        print("\n8. API ENDPOINTS TESTS")
        print("-" * 40)

        api_endpoints = [
            ('Dashboard Stats API', '/shift/api/dashboard-stats/'),
            ('User Shift Status API', '/shift/api/user-shift-status/'),
            ('Upcoming Changes API', '/shift/api/upcoming-changes/'),
        ]

        for endpoint_name, url in api_endpoints:
            response, response_time = self.make_request('GET', url)

            if response.status_code == 200:
                try:
                    response.json()  # Try to parse JSON
                    self.log_result(f"{endpoint_name}", "PASS",
                                  response_time=response_time, status_code=response.status_code)
                except:
                    self.log_result(f"{endpoint_name}", "WARNING",
                                  "Returns 200 but not valid JSON", response_time, response.status_code)
            else:
                self.log_result(f"{endpoint_name}", "FAIL",
                              f"HTTP {response.status_code}", response_time, response.status_code)

    def test_form_validations(self):
        """Test form validation scenarios"""
        print("\n9. FORM VALIDATION TESTS")
        print("-" * 40)

        # Get create form for CSRF token
        response, _ = self.make_request('GET', '/shift/shifts/create/')
        if response.status_code != 200:
            self.log_result("Form Validation Setup", "FAIL", "Cannot access create form")
            return

        csrf_token = self.get_csrf_token(response.text)
        if not csrf_token:
            self.log_result("Form Validation CSRF", "FAIL", "No CSRF token")
            return

        # Test cases for validation
        validation_tests = [
            {
                'name': 'Empty Name Validation',
                'data': {
                    'name': '',
                    'start_time': '09:00',
                    'end_time': '17:00',
                    'shift_duration': '8.0',
                    'csrfmiddlewaretoken': csrf_token
                },
                'should_fail': True
            },
            {
                'name': 'Invalid Time Range Validation',
                'data': {
                    'name': 'Invalid Time Test',
                    'start_time': '17:00',
                    'end_time': '09:00',  # End before start (same day)
                    'shift_duration': '8.0',
                    'csrfmiddlewaretoken': csrf_token
                },
                'should_fail': True
            },
            {
                'name': 'Negative Duration Validation',
                'data': {
                    'name': 'Negative Duration Test',
                    'start_time': '09:00',
                    'end_time': '17:00',
                    'shift_duration': '-1.0',
                    'csrfmiddlewaretoken': csrf_token
                },
                'should_fail': True
            },
        ]

        for test_case in validation_tests:
            response, response_time = self.make_request('POST', '/shift/shifts/create/', data=test_case['data'])

            if test_case['should_fail']:
                # Should return form with errors (200) not redirect (302)
                if response.status_code == 200 and ('error' in response.text.lower() or 'invalid' in response.text.lower()):
                    self.log_result(test_case['name'], "PASS",
                                  "Form correctly rejected invalid data", response_time, response.status_code)
                else:
                    self.log_result(test_case['name'], "FAIL",
                                  "Form should reject invalid data", response_time, response.status_code)
            else:
                if response.status_code in [200, 302]:
                    self.log_result(test_case['name'], "PASS",
                                  response_time=response_time, status_code=response.status_code)
                else:
                    self.log_result(test_case['name'], "FAIL",
                                  f"HTTP {response.status_code}", response_time, response.status_code)

    def test_responsive_design(self):
        """Test responsive design elements"""
        print("\n10. RESPONSIVE DESIGN TESTS")
        print("-" * 40)

        # Test with different user agents (simulate mobile, tablet, desktop)
        user_agents = [
            ('Mobile', 'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15'),
            ('Tablet', 'Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15'),
            ('Desktop', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        ]

        test_pages = ['/shift/', '/shift/shifts/', '/shift/assignments/']

        for device, user_agent in user_agents:
            original_ua = self.session.headers.get('User-Agent')
            self.session.headers['User-Agent'] = user_agent

            device_results = []
            for page in test_pages:
                response, response_time = self.make_request('GET', page)
                if response.status_code == 200:
                    # Check for responsive indicators
                    has_viewport = 'viewport' in response.text
                    has_responsive_css = 'media' in response.text or 'responsive' in response.text
                    device_results.append(response.status_code == 200)
                else:
                    device_results.append(False)

            # Restore original user agent
            self.session.headers['User-Agent'] = original_ua

            if all(device_results):
                self.log_result(f"Responsive Design ({device})", "PASS",
                              f"All test pages accessible on {device.lower()}")
            else:
                self.log_result(f"Responsive Design ({device})", "FAIL",
                              f"Some pages not accessible on {device.lower()}")

    def test_timezone_functionality(self):
        """Test timezone-related functionality"""
        print("\n11. TIMEZONE FUNCTIONALITY TESTS")
        print("-" * 40)

        # Test if pages handle IST correctly
        response, response_time = self.make_request('GET', '/shift/')
        if response.status_code == 200:
            # Look for timezone indicators
            has_timezone_info = any(tz in response.text for tz in ['IST', 'Asia/Kolkata', 'GMT+5:30'])

            if has_timezone_info:
                self.log_result("Timezone Display", "PASS", "Timezone information found")
            else:
                self.log_result("Timezone Display", "WARNING", "No explicit timezone information found")
        else:
            self.log_result("Timezone Display", "FAIL", f"Cannot access dashboard: {response.status_code}")

        # Test time formatting
        response, response_time = self.make_request('GET', '/shift/shifts/')
        if response.status_code == 200:
            # Look for time patterns that suggest proper formatting
            time_patterns = re.findall(r'\d{1,2}:\d{2}(?:\s*[AP]M)?', response.text)
            if time_patterns:
                self.log_result("Time Format Display", "PASS", f"Found {len(time_patterns)} time displays")
            else:
                self.log_result("Time Format Display", "WARNING", "No time patterns found")
        else:
            self.log_result("Time Format Display", "FAIL", f"Cannot access shift list: {response.status_code}")

    def test_error_handling(self):
        """Test error handling and edge cases"""
        print("\n12. ERROR HANDLING TESTS")
        print("-" * 40)

        # Test 404 handling
        response, response_time = self.make_request('GET', '/shift/shifts/99999/')
        if response.status_code == 404:
            self.log_result("404 Error Handling", "PASS", "Correctly returns 404 for non-existent resource")
        else:
            self.log_result("404 Error Handling", "FAIL", f"Expected 404, got {response.status_code}")

        # Test invalid form submission (missing CSRF)
        invalid_data = {'name': 'Test Shift', 'start_time': '09:00', 'end_time': '17:00'}
        response, response_time = self.make_request('POST', '/shift/shifts/create/', data=invalid_data)

        if response.status_code in [403, 400]:
            self.log_result("CSRF Protection", "PASS", "CSRF protection working")
        else:
            self.log_result("CSRF Protection", "WARNING", f"Expected 403/400 for missing CSRF, got {response.status_code}")

        # Test malformed data
        malformed_data = {
            'name': 'Test',
            'start_time': 'invalid_time',
            'end_time': '17:00',
            'csrfmiddlewaretoken': 'invalid_token'
        }
        response, response_time = self.make_request('POST', '/shift/shifts/create/', data=malformed_data)

        if response.status_code in [400, 403, 200]:  # 200 if form shows validation errors
            self.log_result("Malformed Data Handling", "PASS", "Server handles malformed data gracefully")
        else:
            self.log_result("Malformed Data Handling", "WARNING", f"Unexpected response: {response.status_code}")

    def generate_report(self):
        """Generate comprehensive test report"""
        print("\n" + "="*60)
        print("COMPREHENSIVE FRONTEND TEST REPORT")
        print("="*60)

        # Categorize results
        categories = {
            'Server & Auth': ['Server Root Access', 'Shift App Access', 'Login Page Access', 'CSRF Token Extraction', 'Admin Login'],
            'Page Access': [r'.*Page$', 'Dashboard View', 'Shift Detail View'],
            'CRUD Operations': ['Shift Creation', 'Shift Update', 'Shift Deletion'],
            'Form Validation': [r'.*Validation$'],
            'API Endpoints': [r'.*API$'],
            'UI/UX': ['Responsive Design', 'Timezone', 'Error Handling'],
        }

        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if r.status == 'PASS')
        failed_tests = sum(1 for r in self.results if r.status == 'FAIL')
        warning_tests = sum(1 for r in self.results if r.status == 'WARNING')
        skipped_tests = sum(1 for r in self.results if r.status == 'SKIP')

        # Print summary by category
        for category, patterns in categories.items():
            print(f"\n{category.upper()}:")
            print("-" * 40)

            category_results = []
            for result in self.results:
                for pattern in patterns:
                    if re.match(pattern, result.test_name) or pattern in result.test_name:
                        category_results.append(result)
                        break

            if category_results:
                category_passed = sum(1 for r in category_results if r.status == 'PASS')
                category_total = len(category_results)

                for result in category_results:
                    icon = {"PASS": "✓", "FAIL": "✗", "SKIP": "⊝", "WARNING": "⚠"}.get(result.status, "?")
                    print(f"{icon} {result.test_name}: {result.status}")
                    if result.details and result.status != "PASS":
                        print(f"  Details: {result.details}")

                success_rate = (category_passed / category_total) * 100 if category_total > 0 else 0
                print(f"Category Success: {success_rate:.1f}% ({category_passed}/{category_total})")

        # Overall summary
        print(f"\n{'='*60}")
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
            response_times = [r.response_time for r in self.results if r.response_time > 0]
            if response_times:
                avg_response = sum(response_times) / len(response_times)
                max_response = max(response_times)
                print(f"Average Response Time: {avg_response:.2f}s")
                print(f"Maximum Response Time: {max_response:.2f}s")

        # Save detailed report
        try:
            report_data = {
                'timestamp': datetime.now().isoformat(),
                'base_url': self.base_url,
                'total_tests': total_tests,
                'passed_tests': passed_tests,
                'failed_tests': failed_tests,
                'warning_tests': warning_tests,
                'skipped_tests': skipped_tests,
                'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0,
                'results': [
                    {
                        'test_name': r.test_name,
                        'status': r.status,
                        'details': r.details,
                        'response_time': r.response_time,
                        'status_code': r.status_code,
                        'timestamp': r.timestamp
                    } for r in self.results
                ]
            }

            with open('frontend_shift_test_report.json', 'w') as f:
                json.dump(report_data, f, indent=2, default=str)

            print(f"\n✓ Detailed report saved to: frontend_shift_test_report.json")

        except Exception as e:
            print(f"✗ Failed to save report: {str(e)}")

        return {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'failed_tests': failed_tests,
            'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0
        }

    def run_all_tests(self):
        """Run all frontend tests"""
        try:
            # Test server accessibility first
            if not self.test_server_accessibility():
                print("❌ Server is not accessible. Cannot continue with tests.")
                return self.generate_report()

            # Test authentication
            if not self.test_authentication():
                print("❌ Authentication failed. Some tests may not work properly.")

            # Run all test suites
            self.test_shift_pages()
            self.test_assignment_pages()
            self.test_calendar_and_schedule_pages()
            self.test_holiday_pages()
            self.test_shift_crud_operations()
            self.test_api_endpoints()
            self.test_form_validations()
            self.test_responsive_design()
            self.test_timezone_functionality()
            self.test_error_handling()

            # Generate and return report
            return self.generate_report()

        except Exception as e:
            print(f"❌ Test execution failed: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def cleanup(self):
        """Clean up test session"""
        try:
            self.session.close()
        except:
            pass


def main():
    """Main function to run frontend tests"""
    import argparse

    parser = argparse.ArgumentParser(description='Frontend testing for Shift Management System')
    parser.add_argument('--url', default='http://localhost:8000',
                       help='Base URL of the Django server (default: http://localhost:8000)')
    parser.add_argument('--username', default='admin',
                       help='Admin username for testing (default: admin)')
    parser.add_argument('--password', default='admin',
                       help='Admin password for testing (default: admin)')

    args = parser.parse_args()

    print("ShiftMaster & ShiftAssignment Frontend Testing Suite")
    print("=" * 60)
    print(f"Target URL: {args.url}")
    print(f"Username: {args.username}")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("Timezone: Asia/Kolkata (IST)")
    print("=" * 60)

    # Initialize tester
    tester = FrontendShiftTester(
        base_url=args.url,
        username=args.username,
        password=args.password
    )

    try:
        # Run all tests
        results = tester.run_all_tests()

        if results:
            print(f"\n🎯 Testing completed with {results['success_rate']:.1f}% success rate")

            if results['success_rate'] >= 90:
                print("🎉 Excellent! Almost all tests passed successfully.")
                exit_code = 0
            elif results['success_rate'] >= 70:
                print("👍 Good! Most tests passed with some minor issues.")
                exit_code = 1
            elif results['success_rate'] >= 50:
                print("⚠️  Moderate success. Several issues need attention.")
                exit_code = 2
            else:
                print("❌ Many tests failed. Significant issues found.")
                exit_code = 3

            # Specific recommendations based on results
            failed_count = results['failed_tests']
            if failed_count > 0:
                print(f"\n📋 Recommendations:")
                if any('Server' in r.test_name or 'Auth' in r.test_name for r in tester.results if r.status == 'FAIL'):
                    print("• Check if Django server is running and accessible")
                    print("• Verify admin credentials are correct")
                if any('Page' in r.test_name for r in tester.results if r.status == 'FAIL'):
                    print("• Review URL configurations and view implementations")
                if any('CRUD' in r.test_name or 'Form' in r.test_name for r in tester.results if r.status == 'FAIL'):
                    print("• Check form validations and CSRF token handling")
                if any('API' in r.test_name for r in tester.results if r.status == 'FAIL'):
                    print("• Verify API endpoint implementations and permissions")

        else:
            print("❌ Testing failed to complete properly.")
            exit_code = 4

    except KeyboardInterrupt:
        print("\n⚠️  Testing interrupted by user.")
        exit_code = 130
    except Exception as e:
        print(f"\n❌ Testing failed with error: {str(e)}")
        exit_code = 5
    finally:
        # Cleanup
        tester.cleanup()

    print(f"\nCompleted at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("\nFor detailed results, check the JSON report file and console output above.")

    return exit_code


if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
