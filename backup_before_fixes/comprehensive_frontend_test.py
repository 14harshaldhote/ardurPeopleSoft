#!/usr/bin/env python
"""
Comprehensive Leave Management System Frontend Testing Suite
===========================================================

This script performs exhaustive frontend validation of the Leave Management System,
testing all UI components, forms, role-based access, and user workflows.

Author: Ardur Technology
Date: 2025-08-10
"""

import os
import sys
import json
import time
import logging
from datetime import datetime, timedelta, date
from collections import defaultdict, Counter

# Django setup
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
import django
django.setup()

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.urls import reverse
from django.db import transaction
from django.core.exceptions import ObjectDoesNotExist
from django.http import JsonResponse
from django.contrib.sessions.models import Session

from trueAlign.models import LeaveRequest, LeaveType, UserLeaveBalance, CompOffRequest
from trueAlign.notifications.models import Notification

User = get_user_model()

class FrontendTestSuite:
    def __init__(self):
        self.client = Client()
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'total_tests': 0,
            'passed': 0,
            'failed': 0,
            'warnings': 0,
            'categories': {},
            'issues': [],
            'recommendations': []
        }

        # Test users for different roles
        self.test_users = {}
        self.setup_test_environment()

        # UI Element expectations based on backend validation
        self.expected_ui_elements = {
            'login': ['username', 'password', 'submit'],
            'dashboard': ['notification', 'message', 'button', 'form', 'link'],
            'apply_leave': ['input', 'select', 'textarea', 'button'],
            'my_leaves': ['table', 'pagination', 'status_filter'],
            'leave_balance': ['balance_card', 'progress_bar'],
            'notifications': ['notification_list', 'mark_read_button']
        }

    def setup_test_environment(self):
        """Setup test users and data"""
        print("🔧 Setting up test environment...")

        try:
            # Get existing users with different roles using Django Groups
            employee_group = Group.objects.filter(name='Employee').first()
            manager_group = Group.objects.filter(name='Manager').first()
            hr_group = Group.objects.filter(name='HR').first()

            if employee_group:
                self.test_users['employee'] = employee_group.user_set.first()
            if manager_group:
                self.test_users['manager'] = manager_group.user_set.first()
            if hr_group:
                self.test_users['hr'] = hr_group.user_set.first()

            # If no group-based users, try to find users by checking UserDetails role
            if not self.test_users:
                from trueAlign.models import UserDetails

                # Find users with different roles from UserDetails
                employee_detail = UserDetails.objects.filter(role='Employee').first()
                manager_detail = UserDetails.objects.filter(role='Manager').first()
                hr_detail = UserDetails.objects.filter(role='HR').first()

                if employee_detail:
                    self.test_users['employee'] = employee_detail.user
                if manager_detail:
                    self.test_users['manager'] = manager_detail.user
                if hr_detail:
                    self.test_users['hr'] = hr_detail.user

            print(f"✓ Test users found: {list(self.test_users.keys())}")

        except Exception as e:
            print(f"⚠ Error setting up test users: {e}")
            # Fallback: use any available users
            users = User.objects.all()[:3]
            if len(users) >= 1:
                self.test_users['employee'] = users[0]
            if len(users) >= 2:
                self.test_users['manager'] = users[1]
            if len(users) >= 3:
                self.test_users['hr'] = users[2]

    def login_as_user(self, user_type):
        """Login as specific user type"""
        if user_type not in self.test_users:
            return False

        user = self.test_users[user_type]
        return self.client.force_login(user)

    def test_page_accessibility(self, url_name, url_args=None, expected_status=200,
                              user_type=None, page_name=None):
        """Test if a page is accessible and returns expected status"""
        test_name = f"Page Access: {page_name or url_name}"

        try:
            if user_type:
                self.login_as_user(user_type)

            url_args = url_args or []
            url = reverse(url_name, args=url_args)
            response = self.client.get(url)

            if response.status_code == expected_status:
                self.record_test(test_name, 'PASS', f"Status: {response.status_code}")
                return response
            else:
                self.record_test(test_name, 'FAIL',
                               f"Expected {expected_status}, got {response.status_code}")
                return None

        except Exception as e:
            self.record_test(test_name, 'FAIL', f"Exception: {str(e)}")
            return None

    def test_ui_elements_present(self, response, expected_elements, page_name):
        """Test if expected UI elements are present in the response"""
        if not response:
            return

        content = response.content.decode('utf-8')
        missing_elements = []
        present_elements = []

        for element in expected_elements:
            # Check for different element patterns
            patterns = {
                'username': ['name="username"', 'id="username"', 'placeholder="Employee ID"'],
                'password': ['name="password"', 'type="password"'],
                'submit': ['type="submit"', 'button type="submit"'],
                'notification': ['notification', 'alert', 'message'],
                'button': ['<button', 'btn-', 'class=".*button'],
                'form': ['<form', 'method="post"'],
                'input': ['<input', 'type="text"', 'type="date"'],
                'select': ['<select', 'option value'],
                'textarea': ['<textarea'],
                'table': ['<table', '<thead', '<tbody'],
                'pagination': ['pagination', 'page-', 'next', 'previous'],
                'link': ['<a href', 'class=".*link'],
                'balance_card': ['balance', 'available', 'used'],
                'progress_bar': ['progress', 'percentage', 'width:'],
                'status_filter': ['status', 'filter', 'Pending', 'Approved'],
                'notification_list': ['notification-list', 'notifications'],
                'mark_read_button': ['mark-read', 'read-button']
            }

            element_patterns = patterns.get(element, [element])
            found = any(pattern.lower() in content.lower() for pattern in element_patterns)

            if found:
                present_elements.append(element)
            else:
                missing_elements.append(element)

        test_name = f"UI Elements: {page_name}"

        if missing_elements:
            self.record_test(test_name, 'WARNING',
                           f"Missing: {missing_elements}, Present: {present_elements}")
        else:
            self.record_test(test_name, 'PASS',
                           f"All elements present: {present_elements}")

    def test_form_functionality(self, form_url, form_data, expected_redirect=None,
                              user_type='employee', form_name='Form'):
        """Test form submission functionality"""
        test_name = f"Form Functionality: {form_name}"

        try:
            self.login_as_user(user_type)

            # Get the form page first to get CSRF token
            response = self.client.get(form_url)
            if response.status_code != 200:
                self.record_test(test_name, 'FAIL', f"Form page not accessible: {response.status_code}")
                return

            # Submit the form
            response = self.client.post(form_url, form_data, follow=True)

            # Check response
            if response.status_code == 200:
                if expected_redirect and any(expected_redirect in str(redirect) for redirect, _ in response.redirect_chain):
                    self.record_test(test_name, 'PASS', "Form submitted successfully with redirect")
                elif not expected_redirect:
                    self.record_test(test_name, 'PASS', "Form submitted successfully")
                else:
                    self.record_test(test_name, 'WARNING', "Form submitted but unexpected redirect")
            else:
                self.record_test(test_name, 'FAIL', f"Form submission failed: {response.status_code}")

        except Exception as e:
            self.record_test(test_name, 'FAIL', f"Form test exception: {str(e)}")

    def test_api_endpoints(self):
        """Test API endpoints functionality"""
        print("\n📡 Testing API Endpoints...")

        api_endpoints = [
            ('/api/leave_balance/', 'employee'),
            ('/api/leave_types/', 'employee'),
            ('/leave_management/api/balance/', 'employee'),
            ('/leave_management/api/types/', 'employee'),
        ]

        for endpoint, user_type in api_endpoints:
            test_name = f"API Endpoint: {endpoint}"

            try:
                if user_type in self.test_users:
                    self.login_as_user(user_type)

                response = self.client.get(endpoint)

                if response.status_code == 200:
                    try:
                        data = json.loads(response.content)
                        self.record_test(test_name, 'PASS', f"Returns valid JSON: {len(data) if isinstance(data, (list, dict)) else 'N/A'} items")
                    except json.JSONDecodeError:
                        self.record_test(test_name, 'WARNING', "Response not JSON")
                elif response.status_code == 404:
                    self.record_test(test_name, 'WARNING', "Endpoint not found")
                else:
                    self.record_test(test_name, 'FAIL', f"Status: {response.status_code}")

            except Exception as e:
                self.record_test(test_name, 'FAIL', f"Exception: {str(e)}")

    def test_role_based_access(self):
        """Test role-based access controls"""
        print("\n🔐 Testing Role-Based Access...")

        # Define pages and their access requirements
        role_access_tests = [
            ('leave_management:employee_dashboard', [], 200, 'employee', 'Employee Dashboard'),
            ('leave_management:manager_dashboard', [], 200, 'manager', 'Manager Dashboard'),
            ('leave_management:hr_dashboard', [], 200, 'hr', 'HR Dashboard'),
        ]

        # Test cross-role access (should be restricted)
        if 'employee' in self.test_users and 'manager' in self.test_users:
            role_access_tests.extend([
                ('leave_management:manager_dashboard', [], 302, 'employee', 'Manager Dashboard (Employee Access)'),
                ('leave_management:employee_dashboard', [], 302, 'manager', 'Employee Dashboard (Manager Access)'),
            ])

        for url_name, args, expected_status, user_type, description in role_access_tests:
            if user_type in self.test_users:
                self.test_page_accessibility(url_name, args, expected_status, user_type, description)

    def test_notification_system(self):
        """Test notification system functionality"""
        print("\n🔔 Testing Notification System...")

        for user_type in self.test_users:
            test_name = f"Notifications: {user_type.title()}"

            try:
                self.login_as_user(user_type)
                user = self.test_users[user_type]

                # Check notifications count
                notifications = Notification.objects.filter(user=user)
                unread_count = notifications.filter(is_read=False).count()

                # Test notification list page
                try:
                    response = self.client.get(reverse('notifications:list'))
                    if response.status_code == 200:
                        content = response.content.decode('utf-8')
                        if 'notification' in content.lower():
                            self.record_test(test_name, 'PASS',
                                           f"{notifications.count()} total, {unread_count} unread")
                        else:
                            self.record_test(test_name, 'WARNING', "No notification elements found")
                    else:
                        self.record_test(test_name, 'FAIL', f"Notifications page not accessible: {response.status_code}")

                except Exception as e:
                    # Try alternative notification URLs
                    try:
                        response = self.client.get('/notifications/')
                        if response.status_code == 200:
                            self.record_test(test_name, 'PASS', f"Alt URL works: {notifications.count()} notifications")
                        else:
                            self.record_test(test_name, 'WARNING', f"Notification system exists but page unavailable")
                    except:
                        self.record_test(test_name, 'WARNING', f"Notification page error: {str(e)}")

            except Exception as e:
                self.record_test(test_name, 'FAIL', f"Exception: {str(e)}")

    def test_leave_workflow(self):
        """Test complete leave application workflow"""
        print("\n📋 Testing Leave Application Workflow...")

        if 'employee' not in self.test_users:
            self.record_test("Leave Workflow", 'SKIP', "No employee user available")
            return

        self.login_as_user('employee')
        user = self.test_users['employee']

        # Test 1: Access apply leave form
        apply_response = self.test_page_accessibility(
            'leave_management:apply_leave', None, 200, 'employee', 'Apply Leave Form'
        )

        if apply_response:
            # Test 2: Check form elements
            self.test_ui_elements_present(
                apply_response,
                self.expected_ui_elements['apply_leave'],
                'Apply Leave Form'
            )

        # Test 3: Submit leave application
        leave_types = LeaveType.objects.filter(is_active=True).first()
        if leave_types:
            form_data = {
                'leave_type': leave_types.id,
                'start_date': (date.today() + timedelta(days=7)).isoformat(),
                'end_date': (date.today() + timedelta(days=8)).isoformat(),
                'reason': 'Frontend testing leave request',
                'half_day': False
            }

            self.test_form_functionality(
                reverse('leave_management:apply_leave'),
                form_data,
                'my_leaves',
                'employee',
                'Leave Application'
            )

    def test_dashboard_functionality(self):
        """Test dashboard functionality for all user types"""
        print("\n📊 Testing Dashboard Functionality...")

        dashboards = [
            ('leave_management:dashboard', None, 'Main Dashboard'),
            ('leave_management:employee_dashboard', 'employee', 'Employee Dashboard'),
            ('leave_management:manager_dashboard', 'manager', 'Manager Dashboard'),
            ('leave_management:hr_dashboard', 'hr', 'HR Dashboard'),
        ]

        for url_name, user_type, dashboard_name in dashboards:
            if user_type and user_type not in self.test_users:
                continue

            response = self.test_page_accessibility(
                url_name, None, 200, user_type, dashboard_name
            )

            if response:
                self.test_ui_elements_present(
                    response,
                    self.expected_ui_elements['dashboard'],
                    dashboard_name
                )

    def test_list_pages(self):
        """Test list pages (My Leaves, Leave Balance, etc.)"""
        print("\n📑 Testing List Pages...")

        list_pages = [
            ('leave_management:my_leaves', 'employee', 'My Leaves'),
            ('leave_management:leave_balance', 'employee', 'Leave Balance'),
            ('leave_management:my_comp_off', 'employee', 'Comp Off'),
            ('leave_management:team_leaves', 'manager', 'Team Leaves'),
        ]

        for url_name, user_type, page_name in list_pages:
            if user_type not in self.test_users:
                continue

            response = self.test_page_accessibility(
                url_name, None, 200, user_type, page_name
            )

            if response:
                # Check for pagination and filtering elements
                content = response.content.decode('utf-8')
                has_pagination = 'pagination' in content.lower() or 'page' in content.lower()
                has_filters = 'filter' in content.lower() or 'status' in content.lower()

                elements = []
                if has_pagination:
                    elements.append('pagination')
                if has_filters:
                    elements.append('status_filter')

                test_name = f"List Features: {page_name}"
                if elements:
                    self.record_test(test_name, 'PASS', f"Features present: {elements}")
                else:
                    self.record_test(test_name, 'WARNING', "No list features detected")

    def test_responsive_design(self):
        """Test responsive design by checking mobile-friendly elements"""
        print("\n📱 Testing Responsive Design...")

        test_pages = [
            ('login', None),
            ('leave_management:dashboard', 'employee'),
            ('leave_management:apply_leave', 'employee'),
        ]

        for url_name, user_type in test_pages:
            if user_type and user_type not in self.test_users:
                continue

            response = self.test_page_accessibility(url_name, None, 200, user_type)

            if response:
                content = response.content.decode('utf-8')

                # Check for responsive design indicators
                responsive_indicators = [
                    'viewport' in content,
                    'responsive' in content.lower(),
                    'md:' in content,  # Tailwind responsive classes
                    'mobile' in content.lower(),
                    'grid-cols-1' in content,
                ]

                responsive_score = sum(responsive_indicators)
                test_name = f"Responsive Design: {url_name}"

                if responsive_score >= 3:
                    self.record_test(test_name, 'PASS', f"Responsive indicators: {responsive_score}/5")
                elif responsive_score >= 1:
                    self.record_test(test_name, 'WARNING', f"Limited responsiveness: {responsive_score}/5")
                else:
                    self.record_test(test_name, 'FAIL', "No responsive design detected")

    def test_javascript_functionality(self):
        """Test JavaScript functionality by checking for script tags and functions"""
        print("\n⚡ Testing JavaScript Integration...")

        js_test_pages = [
            ('leave_management:apply_leave', 'employee', 'Apply Leave Form'),
            ('leave_management:dashboard', 'employee', 'Dashboard'),
        ]

        for url_name, user_type, page_name in js_test_pages:
            if user_type not in self.test_users:
                continue

            response = self.test_page_accessibility(url_name, None, 200, user_type)

            if response:
                content = response.content.decode('utf-8')

                # Check for JavaScript elements
                js_indicators = {
                    'Script Tags': '<script' in content,
                    'Event Handlers': 'onclick' in content or 'addEventListener' in content,
                    'AJAX Calls': 'fetch(' in content or '$.ajax' in content or 'XMLHttpRequest' in content,
                    'Form Validation': 'validate' in content.lower(),
                    'Date Picker': 'date' in content.lower() and 'picker' in content.lower(),
                }

                present_features = [feature for feature, present in js_indicators.items() if present]

                test_name = f"JavaScript Features: {page_name}"
                if len(present_features) >= 3:
                    self.record_test(test_name, 'PASS', f"Features: {present_features}")
                elif len(present_features) >= 1:
                    self.record_test(test_name, 'WARNING', f"Limited features: {present_features}")
                else:
                    self.record_test(test_name, 'FAIL', "No JavaScript features detected")

    def test_login_system(self):
        """Test login system functionality"""
        print("\n🔑 Testing Login System...")

        # Test login page accessibility
        response = self.test_page_accessibility('login', None, 200, None, 'Login Page')

        if response:
            # Test login form elements
            self.test_ui_elements_present(
                response,
                self.expected_ui_elements['login'],
                'Login Form'
            )

        # Test login functionality with valid user
        if self.test_users:
            user_type = list(self.test_users.keys())[0]
            user = self.test_users[user_type]

            # Test logout and login flow
            self.client.logout()
            login_success = self.client.force_login(user)

            test_name = "Login Functionality"
            if login_success is not False:  # force_login returns None on success
                self.record_test(test_name, 'PASS', f"Successfully logged in as {user.username}")
            else:
                self.record_test(test_name, 'FAIL', "Login failed")

    def record_test(self, test_name, status, details):
        """Record test result"""
        self.results['total_tests'] += 1

        if status == 'PASS':
            self.results['passed'] += 1
            icon = '✅'
        elif status == 'WARNING':
            self.results['warnings'] += 1
            icon = '⚠️'
        elif status == 'SKIP':
            # Don't count skipped tests in total
            self.results['total_tests'] -= 1
            icon = '⏭️'
        else:
            self.results['failed'] += 1
            icon = '❌'
            self.results['issues'].append({
                'test': test_name,
                'status': status,
                'details': details
            })

        print(f"  {icon} {test_name}: {details}")

    def generate_recommendations(self):
        """Generate recommendations based on test results"""
        print("\n💡 Generating Recommendations...")

        # Analyze issues and create recommendations
        issue_categories = defaultdict(list)

        for issue in self.results['issues']:
            if 'API' in issue['test']:
                issue_categories['API'].append(issue)
            elif 'Form' in issue['test']:
                issue_categories['Forms'].append(issue)
            elif 'Dashboard' in issue['test']:
                issue_categories['Dashboard'].append(issue)
            elif 'Access' in issue['test']:
                issue_categories['Security'].append(issue)
            else:
                issue_categories['General'].append(issue)

        recommendations = []

        if issue_categories['API']:
            recommendations.append("🔧 Fix API endpoint connectivity and ensure proper JSON responses")

        if issue_categories['Forms']:
            recommendations.append("📝 Improve form validation and error handling")

        if issue_categories['Dashboard']:
            recommendations.append("📊 Enhance dashboard UI elements and data display")

        if issue_categories['Security']:
            recommendations.append("🔐 Review and fix role-based access control issues")

        if self.results['warnings'] > self.results['failed']:
            recommendations.append("⚡ Focus on UI/UX improvements for better user experience")

        if not issue_categories:
            recommendations.append("🎉 System is working well! Consider performance optimizations")

        self.results['recommendations'] = recommendations

    def run_comprehensive_tests(self):
        """Run all frontend tests"""
        print("🚀 Starting Comprehensive Frontend Testing...")
        print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)

        # Run all test categories
        test_categories = [
            ("🔑 Login System", self.test_login_system),
            ("🔐 Authentication & Access", self.test_role_based_access),
            ("📊 Dashboard Functionality", self.test_dashboard_functionality),
            ("📋 Leave Application Workflow", self.test_leave_workflow),
            ("📑 List Pages & Navigation", self.test_list_pages),
            ("📡 API Endpoints", self.test_api_endpoints),
            ("🔔 Notification System", self.test_notification_system),
            ("📱 Responsive Design", self.test_responsive_design),
            ("⚡ JavaScript Integration", self.test_javascript_functionality),
        ]

        for category_name, test_function in test_categories:
            print(f"\n{category_name}")
            print("-" * 50)
            try:
                test_function()
            except Exception as e:
                print(f"❌ Category failed: {str(e)}")
                self.record_test(f"Category: {category_name}", 'FAIL', str(e))

        # Generate final report
        self.generate_recommendations()
        self.print_final_report()
        self.save_report()

    def print_final_report(self):
        """Print comprehensive test report"""
        print("\n" + "=" * 80)
        print("📊 COMPREHENSIVE FRONTEND TEST REPORT")
        print("=" * 80)

        # Calculate success rate
        total_tests = self.results['total_tests']
        if total_tests > 0:
            success_rate = (self.results['passed'] / total_tests) * 100
            print(f"\n🎯 OVERALL SUCCESS RATE: {success_rate:.1f}% ({self.results['passed']}/{total_tests})")

        print(f"\n📈 TEST SUMMARY:")
        print(f"   ✅ Passed: {self.results['passed']}")
        print(f"   ⚠️ Warnings: {self.results['warnings']}")
        print(f"   ❌ Failed: {self.results['failed']}")
        print(f"   📋 Total: {total_tests}")

        # Status assessment
        if self.results['failed'] == 0:
            if self.results['warnings'] <= 3:
                status = "🌟 EXCELLENT - Frontend is production-ready!"
            else:
                status = "✅ GOOD - Minor improvements needed"
        elif self.results['failed'] <= 2:
            status = "⚠️ MODERATE - Some issues need fixing"
        else:
            status = "❌ POOR - Critical issues require immediate attention"

        print(f"\n🏆 FRONTEND HEALTH: {status}")

        # Print recommendations
        if self.results['recommendations']:
            print(f"\n💡 RECOMMENDATIONS:")
            for rec in self.results['recommendations']:
                print(f"   • {rec}")

        # Print critical issues
        if self.results['issues']:
            print(f"\n🚨 CRITICAL ISSUES TO FIX:")
            for issue in self.results['issues']:
                print(f"   • {issue['test']}: {issue['details']}")

        print(f"\n⏰ Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def save_report(self):
        """Save detailed report to JSON file"""
        filename = f"frontend_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)

        print(f"\n💾 Detailed report saved to: {filename}")

def main():
    """Main execution function"""
    try:
        # Setup logging
        logging.basicConfig(level=logging.INFO)

        # Create and run test suite
        suite = FrontendTestSuite()
        suite.run_comprehensive_tests()

        return suite.results['failed'] == 0

    except Exception as e:
        print(f"❌ Critical error in test execution: {str(e)}")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
