#!/usr/bin/env python3
"""
Comprehensive URL Testing Script for Profile App
This script tests all profile app URLs and verifies their functionality
"""

import os
import sys

# Add the project path to sys.path so we can import Django modules
sys.path.append('/Users/harshalsmac/WORK/ardur/ardurPeopleSoft')

# Set up Django environment BEFORE importing Django modules
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')

import django
django.setup()

from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth.models import User, Group
from django.contrib.auth import authenticate, login
import json

from trueAlign.models import UserDetails, UserActionLog


class ProfileURLTestCase:
    """Test case for profile app URLs"""
    
    def __init__(self):
        self.client = Client()
        self.admin_user = None
        self.hr_user = None
        self.employee_user = None
        self.test_results = []
        
    def setup_test_data(self):
        """Create test users and groups"""
        print("Setting up test data...")
        
        # Create groups
        admin_group, _ = Group.objects.get_or_create(name='admin')
        hr_group, _ = Group.objects.get_or_create(name='HR')
        employee_group, _ = Group.objects.get_or_create(name='employee')
        
        # Create admin user
        self.admin_user, created = User.objects.get_or_create(
            username='testadmin',
            defaults={
                'email': 'admin@test.com',
                'first_name': 'Test',
                'last_name': 'Admin',
                'is_staff': True,
                'is_superuser': True
            }
        )
        if created:
            self.admin_user.set_password('testpass123')
            self.admin_user.save()
        self.admin_user.groups.add(admin_group)
        
        # Create HR user
        self.hr_user, created = User.objects.get_or_create(
            username='testhr',
            defaults={
                'email': 'hr@test.com',
                'first_name': 'Test',
                'last_name': 'HR',
                'is_staff': False,
                'is_superuser': False
            }
        )
        if created:
            self.hr_user.set_password('testpass123')
            self.hr_user.save()
        self.hr_user.groups.add(hr_group)
        
        # Create employee user
        self.employee_user, created = User.objects.get_or_create(
            username='testemployee',
            defaults={
                'email': 'employee@test.com',
                'first_name': 'Test',
                'last_name': 'Employee',
                'is_staff': False,
                'is_superuser': False
            }
        )
        if created:
            self.employee_user.set_password('testpass123')
            self.employee_user.save()
        self.employee_user.groups.add(employee_group)
        
        # Create UserDetails for test users
        for user in [self.admin_user, self.hr_user, self.employee_user]:
            UserDetails.objects.get_or_create(
                user=user,
                defaults={
                    'contact_number_primary': '+1234567890',
                    'dob': '1990-01-01',
                    'current_address_line1': '123 Test Street',
                    'current_city': 'Test City',
                    'current_state': 'Test State',
                    'current_postal_code': '12345',
                    'current_country': 'Test Country',
                    'employment_status': 'active',
                    'hire_date': '2023-01-01',
                    'start_date': '2023-01-01',
                    'role': 'developer',
                    'employee_type': 'full_time',
                    'personal_email': f'{user.username}@personal.com',
                    'company_email': f'{user.username}@company.com'
                }
            )
        
        print("Test data setup complete")
    
    def test_url(self, name, user=None, method='GET', data=None, expected_status=200, 
                 url_kwargs=None, description=""):
        """Test a single URL"""
        try:
            # Login user if provided
            if user:
                login_success = self.client.login(username=user.username, password='testpass123')
                if not login_success:
                    self.test_results.append({
                        'url_name': name,
                        'status': 'FAILED',
                        'message': f'Login failed for user {user.username}',
                        'description': description
                    })
                    return
            
            # Get URL
            try:
                if url_kwargs:
                    url = reverse(name, kwargs=url_kwargs)
                else:
                    url = reverse(name)
            except Exception as e:
                self.test_results.append({
                    'url_name': name,
                    'status': 'FAILED',
                    'message': f'URL reverse failed: {str(e)}',
                    'description': description
                })
                return
            
            # Make request
            if method == 'GET':
                response = self.client.get(url)
            elif method == 'POST':
                response = self.client.post(url, data or {})
            else:
                response = getattr(self.client, method.lower())(url, data or {})
            
            # Check status
            if response.status_code == expected_status:
                status = 'PASSED'
                message = f'Status: {response.status_code}'
            else:
                status = 'FAILED' if response.status_code in [404, 500] else 'WARNING'
                message = f'Expected: {expected_status}, Got: {response.status_code}'
            
            self.test_results.append({
                'url_name': name,
                'url': url,
                'status': status,
                'message': message,
                'description': description,
                'response_status': response.status_code
            })
            
        except Exception as e:
            self.test_results.append({
                'url_name': name,
                'status': 'ERROR',
                'message': f'Exception: {str(e)}',
                'description': description
            })
        finally:
            # Logout
            self.client.logout()
    
    def run_all_tests(self):
        """Run all URL tests"""
        print("Starting URL tests...")
        
        # Test dashboard (requires HR permission)
        self.test_url('profile:dashboard', self.hr_user, description="HR Dashboard")
        self.test_url('profile:dashboard', self.employee_user, expected_status=403, 
                     description="HR Dashboard - Employee should be forbidden")
        
        # Test user list view (requires HR permission)
        self.test_url('profile:user-list', self.hr_user, description="User List")
        self.test_url('profile:user-list', self.employee_user, expected_status=403,
                     description="User List - Employee should be forbidden")
        
        # Test user detail view
        user_detail_kwargs = {'pk': self.employee_user.id}
        self.test_url('profile:user-detail', self.hr_user, url_kwargs=user_detail_kwargs,
                     description="User Detail View")
        
        # Test user create view (requires HR permission)
        self.test_url('profile:user-create', self.hr_user, description="User Create View")
        self.test_url('profile:user-create', self.employee_user, expected_status=403,
                     description="User Create - Employee should be forbidden")
        
        # Test user update view
        user_update_kwargs = {'pk': self.employee_user.id}
        self.test_url('profile:user-update', self.hr_user, url_kwargs=user_update_kwargs,
                     description="User Update View")
        
        # Test change status view (POST request)
        change_status_kwargs = {'pk': self.employee_user.id}
        self.test_url('profile:change-status', self.hr_user, method='POST',
                     url_kwargs=change_status_kwargs, data={'new_status': 'inactive'},
                     expected_status=302, description="Change User Status")
        
        # Test reset password view (POST request)
        reset_password_kwargs = {'pk': self.employee_user.id}
        self.test_url('profile:reset-password', self.hr_user, method='POST',
                     url_kwargs=reset_password_kwargs, expected_status=302,
                     description="Reset User Password")
        
        # Test bulk upload view
        self.test_url('profile:bulk-upload', self.hr_user, description="Bulk Upload View")
        
        # Test bulk upload errors view
        self.test_url('profile:bulk-upload-errors', self.hr_user,
                     description="Bulk Upload Errors View")
        
        # Test CSV export
        self.test_url('profile:export-csv', self.hr_user, description="Export CSV")
        
        # Test audit logs
        self.test_url('profile:audit-logs', self.hr_user, description="Audit Logs")
        
        # Test user profile views
        self.test_url('profile:my-profile', self.employee_user, 
                     description="My Profile View")
        self.test_url('profile:edit-my-profile', self.employee_user,
                     description="Edit My Profile View")
        
        # Test anonymous access (should redirect to login)
        self.test_url('profile:dashboard', expected_status=302,
                     description="Dashboard - Anonymous should redirect")
        self.test_url('profile:my-profile', expected_status=302,
                     description="My Profile - Anonymous should redirect")
        
        print("URL testing completed")
    
    def print_results(self):
        """Print test results"""
        print("\n" + "="*80)
        print("PROFILE APP URL TEST RESULTS")
        print("="*80)
        
        passed = failed = warnings = errors = 0
        
        for result in self.test_results:
            status_symbol = {
                'PASSED': '✓',
                'FAILED': '✗',
                'WARNING': '⚠',
                'ERROR': '⚠'
            }.get(result['status'], '?')
            
            print(f"{status_symbol} {result['status']:<8} {result['url_name']:<30} {result['message']}")
            if result['description']:
                print(f"   Description: {result['description']}")
            if 'url' in result:
                print(f"   URL: {result['url']}")
            print()
            
            if result['status'] == 'PASSED':
                passed += 1
            elif result['status'] == 'FAILED':
                failed += 1
            elif result['status'] == 'WARNING':
                warnings += 1
            else:
                errors += 1
        
        print("="*80)
        print(f"SUMMARY: {passed} passed, {failed} failed, {warnings} warnings, {errors} errors")
        print("="*80)
        
        return {
            'passed': passed,
            'failed': failed,
            'warnings': warnings,
            'errors': errors,
            'total': len(self.test_results)
        }


def main():
    """Main function"""
    print("Profile App URL Testing Suite")
    print("============================")
    
    tester = ProfileURLTestCase()
    
    try:
        tester.setup_test_data()
        tester.run_all_tests()
        summary = tester.print_results()
        
        # Exit with appropriate code
        if summary['failed'] > 0 or summary['errors'] > 0:
            sys.exit(1)
        else:
            print("\nAll tests completed successfully!")
            sys.exit(0)
            
    except Exception as e:
        print(f"Test suite failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
