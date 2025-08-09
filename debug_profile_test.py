#!/usr/bin/env python
"""
Debug script to catch specific NoneType errors in profile functionality
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
from django.test import Client
from trueAlign.models import UserDetails, OfficeLocation
import json
import traceback

def setup_test_data():
    """Setup minimal test data"""
    print("Setting up test data...")

    # Create HR group
    hr_group, _ = Group.objects.get_or_create(name='HR')

    # Create admin user
    admin_user, created = User.objects.get_or_create(
        username='debug_admin',
        defaults={
            'email': 'debug@test.com',
            'first_name': 'Debug',
            'last_name': 'Admin',
            'is_staff': True,
            'is_superuser': True
        }
    )
    if created:
        admin_user.set_password('debug123')
        admin_user.save()
        admin_user.groups.add(hr_group)
        print("✓ Created debug admin user")

    # Create office location
    office, _ = OfficeLocation.objects.get_or_create(
        name='Debug Office',
        defaults={
            'code': 'DO',
            'address_line1': '123 Debug Street',
            'city': 'Debug City',
            'state': 'Debug State',
            'country': 'Debug Country',
            'postal_code': '12345'
        }
    )

    # Create admin user details
    admin_details, _ = UserDetails.objects.get_or_create(
        user=admin_user,
        defaults={
            'employment_status': 'active',
            'employee_type': 'hr',
            'role': 'admin',
            'office_location': office,
            'hire_date': datetime.now().date(),
            'contact_number_primary': '123-456-7890',
            'dob': datetime(1985, 1, 15).date(),
            'base_salary': 100000,
            'job_description': 'HR Administrator'
        }
    )

    print("✓ Test data setup complete")
    return admin_user

def debug_user_list_view():
    """Debug the user list view specifically"""
    print("\n=== Debugging User List View ===")

    client = Client()
    admin_user = User.objects.get(username='debug_admin')
    client.force_login(admin_user)

    try:
        response = client.get('/profile/users/')
        print(f"Response status: {response.status_code}")

        if response.status_code == 200:
            print("✓ User list view loaded successfully")

            # Check context variables
            context = response.context
            print(f"Context keys: {list(context.keys())}")

            # Check specific variables that might be None
            users = context.get('users')
            print(f"Users type: {type(users)}")
            print(f"Users count: {users.count() if users else 'None'}")

            status_choices = context.get('status_choices')
            print(f"Status choices type: {type(status_choices)}")
            print(f"Status choices: {status_choices}")

            employee_types = context.get('employee_types')
            print(f"Employee types type: {type(employee_types)}")
            print(f"Employee types: {employee_types}")

            locations = context.get('locations')
            print(f"Locations type: {type(locations)}")
            print(f"Locations count: {locations.count() if locations else 'None'}")

            # Try to render the response to catch template errors
            try:
                content = response.content.decode('utf-8')
                print("✓ Template rendered successfully")

                # Check for common error strings
                if 'error' in content.lower():
                    print("⚠ Found 'error' in template content")
                if 'exception' in content.lower():
                    print("⚠ Found 'exception' in template content")

            except Exception as template_error:
                print(f"✗ Template rendering error: {template_error}")
                traceback.print_exc()

        else:
            print(f"✗ User list view failed with status: {response.status_code}")
            if hasattr(response, 'content'):
                print(f"Response content: {response.content.decode('utf-8')[:500]}")

    except Exception as e:
        print(f"✗ Error in user list view: {e}")
        traceback.print_exc()

def debug_dashboard_view():
    """Debug the dashboard view"""
    print("\n=== Debugging Dashboard View ===")

    client = Client()
    admin_user = User.objects.get(username='debug_admin')
    client.force_login(admin_user)

    try:
        response = client.get('/profile/dashboard/')
        print(f"Response status: {response.status_code}")

        if response.status_code == 200:
            print("✓ Dashboard view loaded successfully")

            # Check context variables
            context = response.context
            print(f"Context keys: {list(context.keys())}")

            # Try to render template
            try:
                content = response.content.decode('utf-8')
                print("✓ Dashboard template rendered successfully")

                # Check for error indicators
                if 'error' in content.lower() or 'exception' in content.lower():
                    print("⚠ Found error indicators in dashboard content")

            except Exception as template_error:
                print(f"✗ Dashboard template error: {template_error}")
                traceback.print_exc()

        else:
            print(f"✗ Dashboard view failed: {response.status_code}")

    except Exception as e:
        print(f"✗ Dashboard error: {e}")
        traceback.print_exc()

def debug_search_functionality():
    """Debug search with specific parameters"""
    print("\n=== Debugging Search Functionality ===")

    client = Client()
    admin_user = User.objects.get(username='debug_admin')
    client.force_login(admin_user)

    # Test different search parameters
    search_tests = [
        {'search': 'debug'},
        {'status': 'active'},
        {'location': '1'},
        {'employee_type': 'hr'}
    ]

    for test_params in search_tests:
        try:
            print(f"Testing with params: {test_params}")
            response = client.get('/profile/users/', test_params)
            print(f"  Status: {response.status_code}")

            if response.status_code == 200:
                # Try to access the template rendering
                content = response.content.decode('utf-8')
                print(f"  ✓ Template rendered (length: {len(content)})")
            else:
                print(f"  ✗ Failed with status: {response.status_code}")

        except Exception as e:
            print(f"  ✗ Search test failed: {e}")
            print(f"  Error type: {type(e)}")
            traceback.print_exc()

def run_debug_tests():
    """Run all debug tests"""
    print("=== Profile Debug Test Suite ===")
    print(f"Started at: {datetime.now()}")

    try:
        # Setup test data
        admin_user = setup_test_data()

        # Run debug tests
        debug_dashboard_view()
        debug_user_list_view()
        debug_search_functionality()

        print("\n=== Debug Test Complete ===")
        print("Check output above for specific error details")

    except Exception as e:
        print(f"✗ Debug test suite error: {e}")
        traceback.print_exc()

if __name__ == '__main__':
    run_debug_tests()
