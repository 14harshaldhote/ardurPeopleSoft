#!/usr/bin/env python
"""
Comprehensive Leave Management Test & Validation Report
====================================================

This script analyzes the Leave Management module in trueAlign/leave_management
and provides a detailed assessment of its current state, functionality coverage,
and recommendations for improvement.

Usage:
    python run_leave_management_tests.py
"""

import os
import sys
import django
import json
from datetime import datetime, timedelta, date
from pathlib import Path

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

# Now we can import Django models
from django.contrib.auth.models import User, Group
from django.test import Client
from django.urls import reverse
from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance,
    LeaveRequest, CompOffRequest
)
from trueAlign.notifications.models import Notification

class LeaveManagementAnalyzer:
    """Comprehensive analyzer for Leave Management system"""

    def __init__(self):
        self.client = Client()
        self.test_results = {
            'policy_creation': {'status': 'UNKNOWN', 'tests': [], 'score': 0},
            'role_based_flows': {'status': 'UNKNOWN', 'tests': [], 'score': 0},
            'service_logic': {'status': 'UNKNOWN', 'tests': [], 'score': 0},
            'input_validation': {'status': 'UNKNOWN', 'tests': [], 'score': 0},
            'api_endpoints': {'status': 'UNKNOWN', 'tests': [], 'score': 0},
            'frontend_ui': {'status': 'UNKNOWN', 'tests': [], 'score': 0},
            'notifications': {'status': 'UNKNOWN', 'tests': [], 'score': 0},
            'dashboard_rendering': {'status': 'UNKNOWN', 'tests': [], 'score': 0},
            'performance': {'status': 'UNKNOWN', 'tests': [], 'score': 0}
        }
        self.setup_test_data()

    def setup_test_data(self):
        """Set up test users and data"""
        try:
            # Create groups if they don't exist
            self.employee_group, _ = Group.objects.get_or_create(name='EMPLOYEE')
            self.manager_group, _ = Group.objects.get_or_create(name='MANAGER')
            self.hr_group, _ = Group.objects.get_or_create(name='HR')
            self.admin_group, _ = Group.objects.get_or_create(name='ADMIN')

            # Create test users if they don't exist
            self.employee_user, created = User.objects.get_or_create(
                username='test_employee',
                defaults={
                    'email': 'employee@test.com',
                    'first_name': 'Test',
                    'last_name': 'Employee'
                }
            )
            if created:
                self.employee_user.set_password('testpass123')
                self.employee_user.save()
                self.employee_user.groups.add(self.employee_group)

            self.manager_user, created = User.objects.get_or_create(
                username='test_manager',
                defaults={
                    'email': 'manager@test.com',
                    'first_name': 'Test',
                    'last_name': 'Manager'
                }
            )
            if created:
                self.manager_user.set_password('testpass123')
                self.manager_user.save()
                self.manager_user.groups.add(self.manager_group)

            self.hr_user, created = User.objects.get_or_create(
                username='test_hr',
                defaults={
                    'email': 'hr@test.com',
                    'first_name': 'Test',
                    'last_name': 'HR'
                }
            )
            if created:
                self.hr_user.set_password('testpass123')
                self.hr_user.save()
                self.hr_user.groups.add(self.hr_group)

            print("✓ Test data setup completed")
        except Exception as e:
            print(f"✗ Test data setup failed: {e}")

    def test_policy_creation_and_assignment(self):
        """Test Policy Creation & Assignment"""
        print("\n" + "="*60)
        print("1. TESTING POLICY CREATION & ASSIGNMENT")
        print("="*60)

        tests = []
        score = 0

        # Test 1: Check if LeaveType model exists and works
        try:
            annual_leave = LeaveType.objects.filter(name__icontains='annual').first()
            if annual_leave:
                tests.append("✓ LeaveType model exists and has data")
                score += 20
            else:
                # Try to create one
                annual_leave = LeaveType.objects.create(
                    name='Test Annual Leave',
                    max_days_allowed=20,
                    carry_forward_allowed=True
                )
                tests.append("✓ LeaveType creation works")
                score += 15
        except Exception as e:
            tests.append(f"✗ LeaveType model issue: {e}")

        # Test 2: Check if LeavePolicy model exists
        try:
            policies = LeavePolicy.objects.all()
            if policies.exists():
                tests.append(f"✓ LeavePolicy model exists ({policies.count()} policies found)")
                score += 20
            else:
                tests.append("⚠ No leave policies found")
                score += 5
        except Exception as e:
            tests.append(f"✗ LeavePolicy model issue: {e}")

        # Test 3: Check UserLeaveBalance
        try:
            balances = UserLeaveBalance.objects.all()
            if balances.exists():
                tests.append(f"✓ UserLeaveBalance exists ({balances.count()} balances)")
                score += 20
            else:
                tests.append("⚠ No user leave balances found")
                score += 5
        except Exception as e:
            tests.append(f"✗ UserLeaveBalance issue: {e}")

        # Test 4: Check policy assignment to groups
        try:
            group_policies = LeavePolicy.objects.select_related('group').all()
            groups_with_policies = set(p.group.name for p in group_policies if p.group)

            if groups_with_policies:
                tests.append(f"✓ Policies assigned to groups: {', '.join(groups_with_policies)}")
                score += 20
            else:
                tests.append("⚠ No group policy assignments found")
                score += 5
        except Exception as e:
            tests.append(f"✗ Group policy assignment check failed: {e}")

        # Test 5: Check accrual rules
        try:
            allocations = LeaveAllocation.objects.all()
            if allocations.exists():
                tests.append(f"✓ Leave allocations exist ({allocations.count()} allocations)")
                score += 20
            else:
                tests.append("⚠ No leave allocations found")
                score += 5
        except Exception as e:
            tests.append(f"✗ Leave allocation check failed: {e}")

        self.test_results['policy_creation'] = {
            'status': 'PASS' if score >= 60 else 'PARTIAL' if score >= 30 else 'FAIL',
            'tests': tests,
            'score': score
        }

        for test in tests:
            print(f"  {test}")
        print(f"\nScore: {score}/100")

    def test_role_based_flows(self):
        """Test End-to-End Role-Based Flows"""
        print("\n" + "="*60)
        print("2. TESTING ROLE-BASED FLOWS")
        print("="*60)

        tests = []
        score = 0

        # Test Employee Dashboard Access
        try:
            self.client.login(username='test_employee', password='testpass123')

            # Try to access leave management dashboard
            try:
                response = self.client.get('/leave_management/dashboard/')
                if response.status_code == 200:
                    tests.append("✓ Employee can access leave dashboard")
                    score += 15
                elif response.status_code == 302:
                    tests.append("✓ Employee dashboard redirects properly")
                    score += 10
                else:
                    tests.append(f"⚠ Employee dashboard returns {response.status_code}")
                    score += 5
            except Exception as e:
                tests.append(f"✗ Employee dashboard access failed: {e}")

            # Try to access employee-specific dashboard
            try:
                response = self.client.get('/leave_management/employee/')
                if response.status_code == 200:
                    tests.append("✓ Employee-specific dashboard accessible")
                    score += 15
                else:
                    tests.append(f"⚠ Employee dashboard returns {response.status_code}")
                    score += 5
            except Exception as e:
                tests.append(f"✗ Employee dashboard check failed: {e}")

        except Exception as e:
            tests.append(f"✗ Employee login failed: {e}")

        # Test Manager Dashboard Access
        try:
            self.client.login(username='test_manager', password='testpass123')

            try:
                response = self.client.get('/leave_management/manager/')
                if response.status_code == 200:
                    tests.append("✓ Manager dashboard accessible")
                    score += 15
                else:
                    tests.append(f"⚠ Manager dashboard returns {response.status_code}")
                    score += 5
            except Exception as e:
                tests.append(f"✗ Manager dashboard access failed: {e}")

        except Exception as e:
            tests.append(f"✗ Manager login failed: {e}")

        # Test HR Dashboard Access
        try:
            self.client.login(username='test_hr', password='testpass123')

            try:
                response = self.client.get('/leave_management/hr/')
                if response.status_code == 200:
                    tests.append("✓ HR dashboard accessible")
                    score += 15
                else:
                    tests.append(f"⚠ HR dashboard returns {response.status_code}")
                    score += 5
            except Exception as e:
                tests.append(f"✗ HR dashboard access failed: {e}")

        except Exception as e:
            tests.append(f"✗ HR login failed: {e}")

        # Test Leave Application Flow
        try:
            self.client.login(username='test_employee', password='testpass123')

            try:
                response = self.client.get('/leave_management/apply/')
                if response.status_code == 200:
                    tests.append("✓ Leave application form accessible")
                    score += 10
                else:
                    tests.append(f"⚠ Leave application form returns {response.status_code}")
                    score += 5
            except Exception as e:
                tests.append(f"✗ Leave application form failed: {e}")

        except Exception as e:
            tests.append(f"✗ Leave application test failed: {e}")

        # Test existing leave requests
        try:
            leave_requests = LeaveRequest.objects.all()
            if leave_requests.exists():
                tests.append(f"✓ Leave requests exist in system ({leave_requests.count()} found)")
                score += 20

                # Check status distribution
                statuses = {}
                for req in leave_requests:
                    statuses[req.status] = statuses.get(req.status, 0) + 1
                tests.append(f"  Status distribution: {statuses}")

            else:
                tests.append("⚠ No leave requests found in system")
                score += 5
        except Exception as e:
            tests.append(f"✗ Leave request check failed: {e}")

        self.test_results['role_based_flows'] = {
            'status': 'PASS' if score >= 70 else 'PARTIAL' if score >= 40 else 'FAIL',
            'tests': tests,
            'score': score
        }

        for test in tests:
            print(f"  {test}")
        print(f"\nScore: {score}/100")

    def test_service_logic_validation(self):
        """Test LeaveService Logic"""
        print("\n" + "="*60)
        print("3. TESTING SERVICE LOGIC VALIDATION")
        print("="*60)

        tests = []
        score = 0

        # Check if LeaveService exists
        try:
            from trueAlign.leave_management.services.leave_service import LeaveService
            tests.append("✓ LeaveService module exists")
            score += 20

            # Check service methods
            methods = ['apply_leave', 'approve_leave', 'reject_leave', 'cancel_leave']
            existing_methods = []
            for method in methods:
                if hasattr(LeaveService, method):
                    existing_methods.append(method)

            if existing_methods:
                tests.append(f"✓ Service methods found: {', '.join(existing_methods)}")
                score += len(existing_methods) * 15
            else:
                tests.append("⚠ No service methods found")

        except ImportError as e:
            tests.append(f"✗ LeaveService import failed: {e}")
        except Exception as e:
            tests.append(f"✗ LeaveService check failed: {e}")

        # Test business logic through model relationships
        try:
            # Check if leave requests have proper relationships
            leave_requests = LeaveRequest.objects.select_related('user', 'leave_type', 'approver').all()

            valid_requests = 0
            for req in leave_requests[:5]:  # Check first 5
                if req.user and req.leave_type:
                    valid_requests += 1

            if valid_requests > 0:
                tests.append(f"✓ Leave requests have proper relationships ({valid_requests} valid)")
                score += 15
            else:
                tests.append("⚠ No valid leave request relationships found")
                score += 5

        except Exception as e:
            tests.append(f"✗ Business logic check failed: {e}")

        # Check balance calculations
        try:
            balances = UserLeaveBalance.objects.all()
            valid_balances = 0

            for balance in balances[:5]:  # Check first 5
                available = balance.allocated + balance.carried_forward + balance.additional - balance.used
                if available >= 0:
                    valid_balances += 1

            if valid_balances > 0:
                tests.append(f"✓ Balance calculations appear valid ({valid_balances} checked)")
                score += 15
            else:
                tests.append("⚠ No valid balance calculations found")
                score += 5

        except Exception as e:
            tests.append(f"✗ Balance calculation check failed: {e}")

        self.test_results['service_logic'] = {
            'status': 'PASS' if score >= 60 else 'PARTIAL' if score >= 30 else 'FAIL',
            'tests': tests,
            'score': score
        }

        for test in tests:
            print(f"  {test}")
        print(f"\nScore: {score}/100")

    def test_input_validation(self):
        """Test Input & Validation"""
        print("\n" + "="*60)
        print("4. TESTING INPUT & VALIDATION")
        print("="*60)

        tests = []
        score = 0

        # Test form existence
        try:
            from trueAlign.leave_management.forms.leave_forms import LeaveApplicationForm
            tests.append("✓ LeaveApplicationForm exists")
            score += 25
        except ImportError:
            tests.append("✗ LeaveApplicationForm not found")
        except Exception as e:
            tests.append(f"✗ Form import failed: {e}")

        # Test model validation
        try:
            # Test LeaveRequest model constraints
            future_date = date.today() + timedelta(days=30)

            # Check if model has proper field constraints
            leave_request_fields = [field.name for field in LeaveRequest._meta.get_fields()]
            required_fields = ['user', 'leave_type', 'start_date', 'end_date', 'status']

            missing_fields = [f for f in required_fields if f not in leave_request_fields]
            if not missing_fields:
                tests.append("✓ LeaveRequest has all required fields")
                score += 20
            else:
                tests.append(f"⚠ Missing fields in LeaveRequest: {missing_fields}")
                score += 10

        except Exception as e:
            tests.append(f"✗ Model validation check failed: {e}")

        # Check existing data for validation patterns
        try:
            leave_requests = LeaveRequest.objects.all()

            # Check for data integrity
            valid_dates = 0
            total_checked = 0

            for req in leave_requests[:10]:
                total_checked += 1
                if req.start_date and req.end_date and req.start_date <= req.end_date:
                    valid_dates += 1

            if total_checked > 0:
                validation_rate = (valid_dates / total_checked) * 100
                if validation_rate >= 90:
                    tests.append(f"✓ Date validation appears strong ({validation_rate:.0f}% valid)")
                    score += 25
                elif validation_rate >= 70:
                    tests.append(f"⚠ Date validation needs improvement ({validation_rate:.0f}% valid)")
                    score += 15
                else:
                    tests.append(f"✗ Poor date validation ({validation_rate:.0f}% valid)")
                    score += 5
            else:
                tests.append("⚠ No data to validate")
                score += 10

        except Exception as e:
            tests.append(f"✗ Data validation check failed: {e}")

        # Test overlap detection logic
        try:
            overlapping_leaves = []
            leave_requests = LeaveRequest.objects.filter(
                status__in=['Approved', 'Pending']
            ).order_by('user', 'start_date')

            # Simple overlap detection
            user_leaves = {}
            for req in leave_requests:
                if req.user.id not in user_leaves:
                    user_leaves[req.user.id] = []
                user_leaves[req.user.id].append(req)

            overlap_found = False
            for user_id, leaves in user_leaves.items():
                for i, leave1 in enumerate(leaves):
                    for leave2 in leaves[i+1:]:
                        if (leave1.start_date <= leave2.end_date and
                            leave2.start_date <= leave1.end_date):
                            overlap_found = True
                            break

            if not overlap_found:
                tests.append("✓ No overlapping leaves detected")
                score += 30
            else:
                tests.append("⚠ Overlapping leaves found - validation may be weak")
                score += 10

        except Exception as e:
            tests.append(f"✗ Overlap detection check failed: {e}")

        self.test_results['input_validation'] = {
            'status': 'PASS' if score >= 70 else 'PARTIAL' if score >= 40 else 'FAIL',
            'tests': tests,
            'score': score
        }

        for test in tests:
            print(f"  {test}")
        print(f"\nScore: {score}/100")

    def test_api_endpoints(self):
        """Test API Endpoints"""
        print("\n" + "="*60)
        print("5. TESTING API ENDPOINTS")
        print("="*60)

        tests = []
        score = 0

        self.client.login(username='test_employee', password='testpass123')

        # Test leave balance API
        endpoints_to_test = [
            '/api/leave_balance/',
            '/api/leave_types/',
            '/leave_management/api/balance/',
            '/leave_management/api/types/'
        ]

        working_endpoints = []
        for endpoint in endpoints_to_test:
            try:
                response = self.client.get(endpoint)
                if response.status_code == 200:
                    working_endpoints.append(endpoint)
                    try:
                        data = response.json()
                        if isinstance(data, dict) and 'success' in data:
                            tests.append(f"✓ {endpoint} returns proper JSON structure")
                            score += 25
                        else:
                            tests.append(f"⚠ {endpoint} returns JSON but wrong structure")
                            score += 15
                    except:
                        tests.append(f"⚠ {endpoint} returns non-JSON response")
                        score += 10
                elif response.status_code == 404:
                    tests.append(f"✗ {endpoint} not found (404)")
                else:
                    tests.append(f"⚠ {endpoint} returns {response.status_code}")
                    score += 5
            except Exception as e:
                tests.append(f"✗ {endpoint} test failed: {e}")

        if not working_endpoints:
            tests.append("✗ No API endpoints are working")
        else:
            tests.append(f"✓ Working endpoints: {len(working_endpoints)}")

        # Test API authentication
        self.client.logout()
        try:
            response = self.client.get('/api/leave_balance/')
            if response.status_code in [401, 403, 302]:
                tests.append("✓ API properly requires authentication")
                score += 25
            else:
                tests.append("⚠ API authentication may be weak")
                score += 10
        except Exception as e:
            tests.append(f"✗ Authentication test failed: {e}")

        self.test_results['api_endpoints'] = {
            'status': 'PASS' if score >= 60 else 'PARTIAL' if score >= 30 else 'FAIL',
            'tests': tests,
            'score': score
        }

        for test in tests:
            print(f"  {test}")
        print(f"\nScore: {score}/100")

    def test_frontend_ui_workflow(self):
        """Test Frontend/UI Workflow"""
        print("\n" + "="*60)
        print("6. TESTING FRONTEND/UI WORKFLOW")
        print("="*60)

        tests = []
        score = 0

        self.client.login(username='test_employee', password='testpass123')

        # Test template existence by checking responses
        template_tests = [
            ('/leave_management/dashboard/', 'Dashboard'),
            ('/leave_management/apply/', 'Apply Leave Form'),
            ('/leave_management/my_leaves/', 'My Leaves'),
            ('/leave_management/balance/', 'Leave Balance'),
            ('/leave_management/comp_off/', 'Comp Off')
        ]

        accessible_pages = 0
        for url, name in template_tests:
            try:
                response = self.client.get(url)
                if response.status_code == 200:
                    accessible_pages += 1
                    tests.append(f"✓ {name} page accessible")
                    score += 15

                    # Check for basic elements
                    content = response.content.decode().lower()
                    if 'form' in content or 'table' in content or 'card' in content:
                        tests.append(f"  ✓ {name} has UI elements")
                        score += 5

                elif response.status_code == 302:
                    tests.append(f"⚠ {name} redirects (may be normal)")
                    score += 10
                else:
                    tests.append(f"✗ {name} returns {response.status_code}")

            except Exception as e:
                tests.append(f"✗ {name} test failed: {e}")

        if accessible_pages == 0:
            tests.append("✗ No UI pages are accessible")
        else:
            tests.append(f"✓ {accessible_pages}/{len(template_tests)} pages accessible")

        # Test form rendering
        try:
            response = self.client.get('/leave_management/apply/')
            if response.status_code == 200:
                content = response.content.decode().lower()
                form_elements = ['input', 'select', 'textarea', 'button']
                found_elements = [elem for elem in form_elements if elem in content]

                if len(found_elements) >= 3:
                    tests.append(f"✓ Form has proper elements: {found_elements}")
                    score += 20
                else:
                    tests.append(f"⚠ Form may be incomplete: {found_elements}")
                    score += 10
        except Exception as e:
            tests.append(f"✗ Form rendering test failed: {e}")

        self.test_results['frontend_ui'] = {
            'status': 'PASS' if score >= 70 else 'PARTIAL' if score >= 40 else 'FAIL',
            'tests': tests,
            'score': score
        }

        for test in tests:
            print(f"  {test}")
        print(f"\nScore: {score}/100")

    def test_notifications(self):
        """Test Notifications"""
        print("\n" + "="*60)
        print("7. TESTING NOTIFICATIONS")
        print("="*60)

        tests = []
        score = 0

        # Check notification model
        try:
            notifications = Notification.objects.all()
            if notifications.exists():
                tests.append(f"✓ Notification system exists ({notifications.count()} notifications)")
                score += 25

                # Check notification types
                types = set(n.type for n in notifications)
                if types:
                    tests.append(f"✓ Notification types: {', '.join(types)}")
                    score += 15

                # Check read/unread status
                unread_count = notifications.filter(read=False).count()
                read_count = notifications.filter(read=True).count()
                tests.append(f"  Read: {read_count}, Unread: {unread_count}")
                score += 10

            else:
                tests.append("⚠ No notifications found in system")
                score += 5
        except Exception as e:
            tests.append(f"✗ Notification system check failed: {e}")

        # Check for leave-related notifications
        try:
            leave_notifications = Notification.objects.filter(
                message__icontains='leave'
            )
            if leave_notifications.exists():
                tests.append(f"✓ Leave-related notifications exist ({leave_notifications.count()})")
                score += 20
            else:
                tests.append("⚠ No leave-related notifications found")
                score += 5
        except Exception as e:
            tests.append(f"✗ Leave notification check failed: {e}")

        # Test notification triggers (check if recent leave requests have notifications)
        try:
            recent_leaves = LeaveRequest.objects.order_by('-created_at')[:5]
            notifications_for_leaves = 0

            for leave in recent_leaves:
                related_notifications = Notification.objects.filter(
                    event_reference_id=str(leave.id)
                )
                if related_notifications.exists():
                    notifications_for_leaves += 1

            if notifications_for_leaves > 0:
                tests.append(f"✓ Leave requests trigger notifications ({notifications_for_leaves}/{len(recent_leaves)})")
                score += 25
            else:
                tests.append("⚠ Leave requests may not trigger notifications")
                score += 5

        except Exception as e:
            tests.append(f"✗ Notification trigger check failed: {e}")

        # Check notification recipients
        try:
            user_notifications = {}
            for notif in Notification.objects.select_related('recipient')[:20]:
                user_type = 'Unknown'
                if notif.recipient.groups.filter(name='EMPLOYEE').exists():
                    user_type = 'Employee'
                elif notif.recipient.groups.filter(name='MANAGER').exists():
                    user_type = 'Manager'
                elif notif.recipient.groups.filter(name='HR').exists():
                    user_type = 'HR'
                elif notif.recipient.groups.filter(name='ADMIN').exists():
                    user_type = 'Admin'

                user_notifications[user_type] = user_notifications.get(user_type, 0) + 1

            if user_notifications:
                tests.append(f"✓ Notifications sent to: {user_notifications}")
                score += 15

        except Exception as e:
            tests.append(f"✗ Notification recipient check failed: {e}")

        self.test_results['notifications'] = {
            'status': 'PASS' if score >= 70 else 'PARTIAL' if score >= 35 else 'FAIL',
            'tests': tests,
            'score': score
        }

        for test in tests:
            print(f"  {test}")
        print(f"\nScore: {score}/100")

    def test_dashboard_rendering(self):
        """Test Dashboard Rendering"""
        print("\n" + "="*60)
        print("8. TESTING DASHBOARD RENDERING")
        print("="*60)

        tests = []
        score = 0

        # Test main dashboard
        self.client.login(username='test_employee', password='testpass123')

        try:
            response = self.client.get('/dashboard/')
            if response.status_code == 200:
                tests.append("✓ Main dashboard accessible")
                score += 20

                content = response.content.decode().lower()

                # Check for notification elements
                notification_indicators = ['notification', 'alert', 'message', 'badge']
                found_indicators = [ind for ind in notification_indicators if ind in content]

                if found_indicators:
                    tests.append(f"✓ Dashboard has notification elements: {found_indicators}")
                    score += 25
                else:
                    tests.append("⚠ No notification elements found in dashboard")
                    score += 5

                # Check for role-specific content
                if 'leave' in content:
                    tests.append("✓ Dashboard includes leave-related content")
                    score += 15
                else:
                    tests.append("⚠ No leave content found in dashboard")
                    score += 5

                # Check for interactive elements
                interactive_elements = ['button', 'form', 'input', 'link']
                found_elements = [elem for elem in interactive_elements if elem in content]

                if len(found_elements) >= 2:
                    tests.append(f"✓ Dashboard has interactive elements: {found_elements}")
                    score += 15
                else:
                    tests.append("⚠ Limited interactive elements in dashboard")
                    score += 5

                # Check for time/timezone display
                if any(time_word in content for time_word in ['time', 'date', 'clock']):
                    tests.append("✓ Dashboard shows time/date information")
                    score += 10
                else:
                    tests.append("⚠ No time information in dashboard")
                    score += 5

            else:
                tests.append(f"✗ Dashboard returns {response.status_code}")

        except Exception as e:
            tests.append(f"✗ Dashboard test failed: {e}")

        # Test notification rendering specifically
        try:
            # Create a test notification
            test_notification = Notification.objects.create(
                recipient=self.employee_user,
                type='SYSTEM',
                title='Test Dashboard Notification',
                message='Testing dashboard notification rendering',
                read=False
            )

            response = self.client.get('/dashboard/')
            if response.status_code == 200:
                content = response.content.decode()
                if 'Test Dashboard Notification' in content:
                    tests.append("✓ Notifications render in dashboard")
                    score += 20
                else:
                    tests.append("⚠ Test notification not found in dashboard")
                    score += 5

            # Clean up test notification
            test_notification.delete()

        except Exception as e:
            tests.append(f"✗ Notification rendering test failed: {e}")

        self.test_results['dashboard_rendering'] = {
            'status': 'PASS' if score >= 70 else 'PARTIAL' if score >= 40 else 'FAIL',
            'tests': tests,
            'score': score
        }

        for test in tests:
            print(f"  {test}")
        print(f"\nScore: {score}/100")

    def test_performance(self):
        """Test Performance & Caching"""
        print("\n" + "="*60)
        print("9. TESTING PERFORMANCE")
        print("="*60)

        tests = []
        score = 0

        # Test database query efficiency
        try:
            from django.db import connection
            from django.test.utils import override_settings

            self.client.login(username='test_employee', password='testpass123')

            # Reset query log
            connection.queries_log.clear()

            # Test dashboard load
            response = self.client.get('/dashboard/')

            query_count = len(connection.queries)
            if query_count <= 20:
                tests.append(f"✓ Dashboard uses reasonable queries ({query_count})")
                score += 25
            elif query_count <= 50:
                tests.append(f"⚠ Dashboard query count acceptable ({query_count})")
                score += 15
            else:
                tests.append(f"✗ Dashboard uses too many queries ({query_count})")
                score += 5

        except Exception as e:
            tests.append(f"✗ Query performance test failed: {e}")

        # Test data volume handling
        try:
            # Count total records
            total_leave_requests = LeaveRequest.objects.count()
            total_balances = UserLeaveBalance.objects.count()
            total_users = User.objects.count()

            tests.append(f"Data volume: {total_users} users, {total_leave_requests} requests, {total_balances} balances")

            if total_leave_requests > 100:
                tests.append("✓ System has substantial test data")
                score += 20
            elif total_leave_requests > 10:
                tests.append("⚠ System has moderate test data")
                score += 10
            else:
                tests.append("⚠ System has limited test data")
                score += 5

        except Exception as e:
            tests.append(f"✗ Data volume test failed: {e}")

        # Test response time (basic)
        try:
            import time
            self.client.login(username='test_employee', password='testpass123')

            start_time = time.time()
            response = self.client.get('/leave_management/dashboard/')
            end_time = time.time()

            response_time = end_time - start_time

            if response_time < 1.0:
                tests.append(f"✓ Fast response time ({response_time:.2f}s)")
                score += 25
            elif response_time < 3.0:
                tests.append(f"⚠ Acceptable response time ({response_time:.2f}s)")
                score += 15
            else:
                tests.append(f"✗ Slow response time ({response_time:.2f}s)")
                score += 5

        except Exception as e:
            tests.append(f"✗ Response time test failed: {e}")

        # Test caching (check for cache-related code)
        try:
            from django.core.cache import cache
            cache.set('test_key', 'test_value', 30)
            cached_value = cache.get('test_key')

            if cached_value == 'test_value':
                tests.append("✓ Caching system functional")
                score += 25
            else:
                tests.append("⚠ Caching system may not be working")
                score += 10

            cache.delete('test_key')

        except Exception as e:
            tests.append(f"✗ Caching test failed: {e}")

        self.test_results['performance'] = {
            'status': 'PASS' if score >= 60 else 'PARTIAL' if score >= 30 else 'FAIL',
            'tests': tests,
            'score': score
        }

        for test in tests:
            print(f"  {test}")
        print(f"\nScore: {score}/100")

    def generate_comprehensive_report(self):
        """Generate final comprehensive report"""
        print("\n" + "="*80)
        print("COMPREHENSIVE LEAVE MANAGEMENT VALIDATION REPORT")
        print("="*80)

        # Calculate overall scores
        total_score = sum(result['score'] for result in self.test_results.values())
        max_possible = len(self.test_results) * 100
        overall_percentage = (total_score / max_possible) * 100

        print(f"\nOVERALL SYSTEM SCORE: {overall_percentage:.1f}% ({total_score}/{max_possible})")
        print("="*50)

        # Status summary
        status_counts = {'PASS': 0, 'PARTIAL': 0, 'FAIL': 0, 'UNKNOWN': 0}
        for category, result in self.test_results.items():
            status_counts[result['status']] += 1

        print(f"✓ PASS: {status_counts['PASS']}")
        print(f"⚠ PARTIAL: {status_counts['PARTIAL']}")
        print(f"✗ FAIL: {status_counts['FAIL']}")
        print(f"? UNKNOWN: {status_counts['UNKNOWN']}")

        # Detailed results
        print("\nDETAILED RESULTS BY CATEGORY:")
        print("-" * 50)

        for category, result in self.test_results.items():
            status_icon = {
                'PASS': '✓',
                'PARTIAL': '⚠',
                'FAIL': '✗',
                'UNKNOWN': '?'
            }[result['status']]

            category_name = category.replace('_', ' ').title()
            print(f"\n{status_icon} {category_name}: {result['status']} ({result['score']}/100)")

            if result['tests']:
                for test in result['tests'][:3]:  # Show first 3 tests
                    print(f"    {test}")
                if len(result['tests']) > 3:
                    print(f"    ... and {len(result['tests']) - 3} more")

        # Recommendations
        print("\n" + "="*60)
        print("RECOMMENDATIONS")
        print("="*60)

        recommendations = []

        if self.test_results['policy_creation']['status'] != 'PASS':
            recommendations.append(
                "🔧 POLICY CREATION: Set up proper leave types and policies with group assignments"
            )

        if self.test_results['role_based_flows']['status'] != 'PASS':
            recommendations.append(
                "🔧 ROLE-BASED ACCESS: Implement proper role-based dashboard routing and permissions"
            )

        if self.test_results['service_logic']['status'] != 'PASS':
            recommendations.append(
                "🔧 SERVICE LOGIC: Complete LeaveService implementation with all business rules"
            )

        if self.test_results['api_endpoints']['status'] != 'PASS':
            recommendations.append(
                "🔧 API ENDPOINTS: Implement /api/leave_balance/ and /api/leave_types/ endpoints"
            )

        if self.test_results['notifications']['status'] != 'PASS':
            recommendations.append(
                "🔧 NOTIFICATIONS: Set up automatic notifications for leave events"
            )

        if self.test_results['frontend_ui']['status'] != 'PASS':
            recommendations.append(
                "🔧 FRONTEND: Complete UI templates and form implementations"
            )

        if self.test_results['performance']['status'] != 'PASS':
            recommendations.append(
                "🔧 PERFORMANCE: Optimize database queries and implement caching"
            )

        if not recommendations:
            recommendations.append("🎉 EXCELLENT: All major components are working well!")

        for rec in recommendations:
            print(f"  {rec}")

        # Priority actions
        print(f"\n{'='*60}")
        print("PRIORITY ACTIONS")
        print("="*60)

        critical_failures = [
            category for category, result in self.test_results.items()
            if result['status'] == 'FAIL'
        ]

        if critical_failures:
            print("🚨 CRITICAL (Fix immediately):")
            for category in critical_failures:
                category_name = category.replace('_', ' ').title()
                print(f"   • {category_name}")
        else:
            print("✅ No critical failures found")

        partial_items = [
            category for category, result in self.test_results.items()
            if result['status'] == 'PARTIAL'
        ]

        if partial_items:
            print("\n⚠️  IMPROVEMENT NEEDED:")
            for category in partial_items:
                category_name = category.replace('_', ' ').title()
                print(f"   • {category_name}")

        # Implementation status
        print(f"\n{'='*60}")
        print("IMPLEMENTATION STATUS")
        print("="*60)

        implementation_status = {
            'Fully Implemented': [k for k, v in self.test_results.items() if v['status'] == 'PASS'],
            'Partially Implemented': [k for k, v in self.test_results.items() if v['status'] == 'PARTIAL'],
            'Not Implemented': [k for k, v in self.test_results.items() if v['status'] == 'FAIL'],
            'Unknown Status': [k for k, v in self.test_results.items() if v['status'] == 'UNKNOWN']
        }

        for status, categories in implementation_status.items():
            if categories:
                print(f"\n{status}:")
                for category in categories:
                    category_name = category.replace('_', ' ').title()
                    print(f"   • {category_name}")

        # Final verdict
        print(f"\n{'='*60}")
        print("FINAL ASSESSMENT")
        print("="*60)

        if overall_percentage >= 80:
            verdict = "🌟 EXCELLENT - System is production-ready with minor improvements needed"
        elif overall_percentage >= 60:
            verdict = "✅ GOOD - System is functional but needs some improvements"
        elif overall_percentage >= 40:
            verdict = "⚠️  FAIR - System has basic functionality but needs significant work"
        else:
            verdict = "❌ POOR - System needs major development before deployment"

        print(f"{verdict}")
        print(f"\nOverall Score: {overall_percentage:.1f}%")

        # Save report to file
        self.save_report_to_file(overall_percentage, verdict)

    def save_report_to_file(self, overall_percentage, verdict):
        """Save the test report to a JSON file"""
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'overall_score': overall_percentage,
            'verdict': verdict,
            'test_results': self.test_results,
            'summary': {
                'total_categories': len(self.test_results),
                'passing': len([r for r in self.test_results.values() if r['status'] == 'PASS']),
                'partial': len([r for r in self.test_results.values() if r['status'] == 'PARTIAL']),
                'failing': len([r for r in self.test_results.values() if r['status'] == 'FAIL']),
                'unknown': len([r for r in self.test_results.values() if r['status'] == 'UNKNOWN'])
            }
        }

        try:
            with open('leave_management_test_report.json', 'w') as f:
                json.dump(report_data, f, indent=2)
            print(f"\n📄 Detailed report saved to: leave_management_test_report.json")
        except Exception as e:
            print(f"\n❌ Could not save report to file: {e}")

    def run_all_tests(self):
        """Run all test categories"""
        print("🚀 Starting Comprehensive Leave Management Tests...")
        print(f"⏰ Test started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        try:
            self.test_policy_creation_and_assignment()
            self.test_role_based_flows()
            self.test_service_logic_validation()
            self.test_input_validation()
            self.test_api_endpoints()
            self.test_frontend_ui_workflow()
            self.test_notifications()
            self.test_dashboard_rendering()
            self.test_performance()

        except KeyboardInterrupt:
            print("\n❌ Tests interrupted by user")
            return
        except Exception as e:
            print(f"\n❌ Test execution failed: {e}")
            return

        self.generate_comprehensive_report()

        print(f"\n⏰ Test completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("\n" + "="*80)


def main():
    """Main execution function"""
    print("Comprehensive Leave Management Test & Validation Suite")
    print("="*60)

    try:
        analyzer = LeaveManagementAnalyzer()
        analyzer.run_all_tests()

        print("\n📋 MANUAL TESTING CHECKLIST:")
        print("-" * 40)
        print("□ Test leave application form with various date ranges")
        print("□ Test manager approval workflow")
        print("□ Test HR dashboard with organization-wide view")
        print("□ Test notification display in dashboard")
        print("□ Test role-based access restrictions")
        print("□ Test leave balance calculations after approval/rejection")
        print("□ Test comp-off request and approval")
        print("□ Test overlapping leave validation")
        print("□ Test timezone display (Asia/Kolkata)")
        print("□ Test pagination on leave lists")
        print("□ Test API endpoints with proper authentication")
        print("□ Test mobile responsiveness")

        print("\n🌐 BROWSER TESTING:")
        print("-" * 20)
        print("□ Chrome compatibility")
        print("□ Firefox compatibility")
        print("□ Safari compatibility")
        print("□ Mobile browser testing")

    except Exception as e:
        print(f"❌ Error running tests: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
