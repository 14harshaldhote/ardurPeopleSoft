#!/usr/bin/env python
"""
Test script to verify profile functionality in trueAlign
"""

import os
import sys
import django
from datetime import datetime, timedelta

# Set environment variable for ALLOWED_HOSTS before Django setup
os.environ['ALLOWED_HOSTS'] = 'localhost,127.0.0.1,0.0.0.0,testserver'

# Add the project path
sys.path.append('/Users/harshalsmac/WORK/ardur/ardurHome')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User, Group
from django.test import Client, TestCase
from django.urls import reverse
from trueAlign.models import UserDetails, UserActionLog, OfficeLocation
import json

def create_test_data():
    """Create test data for profile functionality testing"""
    print("Creating test data...")

    # Create HR group
    hr_group, created = Group.objects.get_or_create(name='HR')
    if created:
        print("✓ Created HR group")

    # Create admin user
    admin_user, created = User.objects.get_or_create(
        username='admin_test',
        defaults={
            'email': 'admin@test.com',
            'first_name': 'Admin',
            'last_name': 'User',
            'is_staff': True,
            'is_superuser': True
        }
    )
    if created:
        admin_user.set_password('admin123')
        admin_user.save()
        # Add user to HR group
        admin_user.groups.add(hr_group)
        print(f"✓ Created admin user: {admin_user.username}")

    # Ensure admin user has UserDetails with HR role
    admin_details, created = UserDetails.objects.get_or_create(
        user=admin_user,
        defaults={
            'employment_status': 'active',
            'employee_type': 'hr',
            'role': 'admin',
            'office_location': None,  # Will be set after office is created
            'hire_date': datetime.now().date(),
            'contact_number_primary': '123-456-7890',
            'dob': datetime(1985, 1, 15).date(),
            'base_salary': 100000,
            'job_description': 'HR Administrator - Managing employee records and policies'
        }
    )

    # Create office location
    office, created = OfficeLocation.objects.get_or_create(
        name='Test Office',
        defaults={
            'code': 'TO',
            'address_line1': '123 Test Street',
            'city': 'Test City',
            'state': 'Test State',
            'country': 'Test Country',
            'postal_code': '12345'
        }
    )
    if created:
        print(f"✓ Created office location: {office.name}")

    # Update admin user's office location after office is created
    if admin_details.office_location != office:
        admin_details.office_location = office
        admin_details.save()
        if created:
            print(f"✓ Created admin user details with HR role")

    # Create test employees
    for i in range(5):
        user, created = User.objects.get_or_create(
            username=f'employee_{i}',
            defaults={
                'email': f'employee{i}@test.com',
                'first_name': f'Employee',
                'last_name': f'{i}',
            }
        )
        if created:
            user.set_password('emp123')
            user.save()

        user_details, created = UserDetails.objects.get_or_create(
            user=user,
            defaults={
                'employment_status': 'active' if i % 2 == 0 else 'inactive',
                'employee_type': 'full_time',
                'role': 'employee',
                'office_location': office,
                'hire_date': datetime.now().date() - timedelta(days=30*i),
                'contact_number_primary': f'123-456-78{i:02d}',
                'dob': datetime(1990+i, 1, 15).date(),
                'base_salary': 50000 + (i * 5000),
            }
        )
        if created:
            print(f"✓ Created employee: {user.username}")

    return admin_user

def test_dashboard_functionality():
    """Test dashboard view and analytics"""
    print("\n=== Testing Dashboard Functionality ===")

    client = Client()
    admin_user = User.objects.get(username='admin_test')
    client.force_login(admin_user)

    # Test dashboard view
    try:
        response = client.get('/profile/dashboard/')
        if response.status_code == 200:
            print("✓ Dashboard view loads successfully")
            # Check if context variables are present
            if 'total_users' in response.context:
                print(f"✓ Total users: {response.context['total_users']}")
            if 'active_users' in response.context:
                print(f"✓ Active users: {response.context['active_users']}")
        else:
            print(f"✗ Dashboard view failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Dashboard view error: {str(e)}")

    # Test analytics API
    try:
        response = client.get('/profile/api/dashboard-analytics/')
        if response.status_code == 200:
            data = json.loads(response.content)
            print("✓ Analytics API works successfully")
            print(f"  - Status distribution: {len(data.get('status_distribution', []))}")
            print(f"  - Location distribution: {len(data.get('location_distribution', []))}")
        else:
            print(f"✗ Analytics API failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Analytics API error: {str(e)}")

    # Test stats API
    try:
        response = client.get('/profile/api/dashboard-stats/')
        if response.status_code == 200:
            data = json.loads(response.content)
            print("✓ Stats API works successfully")
            print(f"  - Total users: {data.get('total_users', 0)}")
            print(f"  - Active users: {data.get('active_users', 0)}")
        else:
            print(f"✗ Stats API failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Stats API error: {str(e)}")

def test_user_management():
    """Test user list, detail, and CRUD operations"""
    print("\n=== Testing User Management ===")

    client = Client()
    admin_user = User.objects.get(username='admin_test')
    client.force_login(admin_user)

    # Test user list view
    try:
        response = client.get('/profile/users/')
        if response.status_code == 200:
            print("✓ User list view loads successfully")
            if 'users' in response.context:
                user_count = len(response.context['users'])
                print(f"  - Showing {user_count} users")
        else:
            print(f"✗ User list view failed: {response.status_code}")
    except Exception as e:
        print(f"✗ User list view error: {str(e)}")

    # Test user detail view
    try:
        test_user = User.objects.filter(username__startswith='employee_').first()
        if test_user:
            response = client.get(f'/profile/users/{test_user.id}/')
            if response.status_code == 200:
                print("✓ User detail view loads successfully")
                if 'user_profile' in response.context:
                    profile = response.context['user_profile']
                    print(f"  - User: {profile.full_name}")
                    print(f"  - Status: {profile.employment_status}")
                elif 'user' in response.context and hasattr(response.context['user'], 'profile'):
                    profile = response.context['user'].profile
                    print(f"  - User: {profile.full_name}")
                    print(f"  - Status: {profile.employment_status}")
            else:
                print(f"✗ User detail view failed: {response.status_code}")
    except Exception as e:
        print(f"✗ User detail view error: {str(e)}")

    # Test user creation view
    try:
        response = client.get('/profile/users/new/')
        if response.status_code == 200:
            print("✓ User creation form loads successfully")
        else:
            print(f"✗ User creation form failed: {response.status_code}")
    except Exception as e:
        print(f"✗ User creation form error: {str(e)}")

def test_data_integrity():
    """Test data relationships and integrity"""
    print("\n=== Testing Data Integrity ===")

    # Check UserDetails relationships
    try:
        user_details = UserDetails.objects.select_related('user', 'office_location').all()
        print(f"✓ Found {user_details.count()} user profiles")

        for profile in user_details[:3]:  # Check first 3
            print(f"  - {profile.full_name}: {profile.employment_status}")
            if profile.office_location:
                print(f"    Office: {profile.office_location.name}")
            print(f"    Role: {profile.role}")
    except Exception as e:
        print(f"✗ Data integrity error: {str(e)}")

    # Check action logs
    try:
        logs = UserActionLog.objects.select_related('user', 'action_by').all()
        print(f"✓ Found {logs.count()} action logs")

        for log in logs[:3]:  # Check first 3
            print(f"  - {log.get_action_type_display()} for {log.user.username} by {log.action_by.username}")
    except Exception as e:
        print(f"✗ Action logs error: {str(e)}")

def test_template_rendering():
    """Test template rendering without errors"""
    print("\n=== Testing Template Rendering ===")

    client = Client()
    admin_user = User.objects.get(username='admin_test')
    client.force_login(admin_user)

    templates_to_test = [
        ('/profile/dashboard/', 'Dashboard'),
        ('/profile/users/', 'User List'),
        ('/profile/my-profile/', 'My Profile'),
    ]

    for url, name in templates_to_test:
        try:
            response = client.get(url)
            if response.status_code == 200:
                content = response.content.decode('utf-8')
                # Check for common template errors
                if 'error' not in content.lower() and 'exception' not in content.lower():
                    print(f"✓ {name} template renders correctly")
                else:
                    print(f"⚠ {name} template may have errors")
            else:
                print(f"✗ {name} template failed: {response.status_code}")
        except Exception as e:
            print(f"✗ {name} template error: {str(e)}")

def test_filters_and_search():
    """Test filtering and search functionality"""
    print("\n=== Testing Filters and Search ===")

    client = Client()
    admin_user = User.objects.get(username='admin_test')
    client.force_login(admin_user)

    # Test search functionality
    try:
        response = client.get('/profile/users/?search=employee')
        if response.status_code == 200:
            print("✓ Search functionality works")
            if 'users' in response.context:
                user_count = len(response.context['users'])
                print(f"  - Found {user_count} users matching 'employee'")
        else:
            print(f"✗ Search failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Search error: {str(e)}")

    # Test status filter
    try:
        response = client.get('/profile/users/?status=active')
        if response.status_code == 200:
            print("✓ Status filter works")
            if 'users' in response.context:
                user_count = len(response.context['users'])
                print(f"  - Found {user_count} active users")
        else:
            print(f"✗ Status filter failed: {response.status_code}")
    except Exception as e:
        print(f"✗ Status filter error: {str(e)}")

def run_all_tests():
    """Run all profile functionality tests"""
    print("=== trueAlign Profile Functionality Test ===")
    print(f"Test started at: {datetime.now()}")

    try:
        # Create test data
        admin_user = create_test_data()

        # Run tests
        test_dashboard_functionality()
        test_user_management()
        test_data_integrity()
        test_template_rendering()
        test_filters_and_search()

        print("\n=== Test Summary ===")
        print("✓ All tests completed")
        print("Check the output above for any issues marked with ✗ or ⚠")

    except Exception as e:
        print(f"\n✗ Test suite error: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    run_all_tests()
