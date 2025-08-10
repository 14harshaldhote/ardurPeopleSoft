#!/usr/bin/env python3
"""
ShiftMaster and ShiftAssignment Testing Runner
============================================

This script sets up the environment and runs comprehensive tests for the
ShiftMaster and ShiftAssignment modules.

Usage:
    python run_shift_tests.py

Requirements:
    - Django project properly configured
    - Database accessible
    - Asia/Kolkata timezone set
"""

import os
import sys
import subprocess
import time
import django
from datetime import datetime
import json

def setup_django_environment():
    """Set up Django environment"""
    print("Setting up Django environment...")

    try:
        # Add the project directory to Python path
        project_dir = os.path.dirname(os.path.abspath(__file__))
        sys.path.insert(0, project_dir)

        # Set Django settings module
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')

        # Setup Django
        django.setup()

        print("✓ Django environment setup completed")
        return True

    except Exception as e:
        print(f"✗ Django environment setup failed: {str(e)}")
        return False

def check_database_connection():
    """Check if database is accessible"""
    print("Checking database connection...")

    try:
        from django.db import connection
        from django.core.management import execute_from_command_line

        # Test database connection
        cursor = connection.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()

        print("✓ Database connection successful")
        return True

    except Exception as e:
        print(f"✗ Database connection failed: {str(e)}")
        print("Attempting to run migrations...")

        try:
            # Try to run migrations
            execute_from_command_line(['manage.py', 'migrate'])
            print("✓ Migrations completed")
            return True
        except Exception as migrate_error:
            print(f"✗ Migration failed: {str(migrate_error)}")
            return False

def check_timezone_setting():
    """Check if timezone is set to Asia/Kolkata"""
    print("Checking timezone configuration...")

    try:
        from django.conf import settings
        import pytz

        # Check Django timezone setting
        django_tz = getattr(settings, 'TIME_ZONE', 'UTC')
        print(f"Django TIME_ZONE: {django_tz}")

        # Set to Asia/Kolkata for testing
        if django_tz != 'Asia/Kolkata':
            print("⚠ Django timezone is not set to Asia/Kolkata")
            print("Setting timezone for this test session...")

        # Activate Asia/Kolkata timezone
        from django.utils import timezone
        ist = pytz.timezone('Asia/Kolkata')
        timezone.activate(ist)

        current_time = timezone.now()
        print(f"✓ Current time in IST: {current_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")

        return True

    except Exception as e:
        print(f"✗ Timezone setup failed: {str(e)}")
        return False

def check_models_available():
    """Check if required models are available"""
    print("Checking required models...")

    try:
        from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
        from django.contrib.auth.models import User

        # Test model access
        shift_count = ShiftMaster.objects.count()
        assignment_count = ShiftAssignment.objects.count()
        user_count = User.objects.count()

        print(f"✓ Models accessible - Shifts: {shift_count}, Assignments: {assignment_count}, Users: {user_count}")
        return True

    except Exception as e:
        print(f"✗ Model access failed: {str(e)}")
        return False

def check_urls_available():
    """Check if required URL patterns are available"""
    print("Checking URL patterns...")

    try:
        from django.urls import reverse
        from django.test import Client

        # Test key URL patterns
        test_urls = [
            'shift:dashboard',
            'shift:list',
            'shift:assignments',
            'shift:create',
            'shift:holidays'
        ]

        client = Client()
        available_urls = []

        for url_name in test_urls:
            try:
                url = reverse(url_name)
                available_urls.append(url_name)
            except Exception:
                print(f"⚠ URL pattern '{url_name}' not available")

        print(f"✓ Available URL patterns: {len(available_urls)}/{len(test_urls)}")
        return len(available_urls) > 0

    except Exception as e:
        print(f"✗ URL pattern check failed: {str(e)}")
        return False

def run_basic_smoke_tests():
    """Run basic smoke tests before comprehensive testing"""
    print("\nRunning basic smoke tests...")

    try:
        from trueAlign.models import ShiftMaster, ShiftAssignment
        from django.contrib.auth.models import User
        from decimal import Decimal
        from datetime import time, date

        # Test 1: Create a basic shift
        test_shift = ShiftMaster.objects.create(
            name='Smoke Test Shift',
            start_time=time(9, 0),
            end_time=time(17, 0),
            shift_duration=Decimal('8.0'),
            work_days='Weekdays'
        )
        print("✓ Basic shift creation works")

        # Test 2: Create a test user
        test_user = User.objects.create_user(
            username='smoke_test_user',
            email='test@example.com',
            password='testpass123'
        )
        print("✓ Basic user creation works")

        # Test 3: Create a basic assignment
        test_assignment = ShiftAssignment.objects.create(
            user=test_user,
            shift=test_shift,
            effective_from=date.today(),
            is_current=True
        )
        print("✓ Basic assignment creation works")

        # Cleanup smoke test data
        test_assignment.delete()
        test_shift.delete()
        test_user.delete()
        print("✓ Smoke test cleanup completed")

        return True

    except Exception as e:
        print(f"✗ Smoke tests failed: {str(e)}")
        return False

def run_comprehensive_tests():
    """Run the comprehensive test suite"""
    print("\n" + "="*60)
    print("STARTING COMPREHENSIVE SHIFT SYSTEM TESTS")
    print("="*60)

    try:
        # Import and run the comprehensive test suite
        from shift_system_comprehensive_test import ShiftSystemTester

        tester = ShiftSystemTester()
        tester.run_all_tests()

        return True

    except ImportError:
        print("✗ Comprehensive test module not found")
        print("Please ensure 'shift_system_comprehensive_test.py' is in the same directory")
        return False
    except Exception as e:
        print(f"✗ Comprehensive tests failed: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def check_frontend_accessibility():
    """Check if frontend pages are accessible"""
    print("\nChecking frontend page accessibility...")

    try:
        from django.test import Client
        from django.contrib.auth.models import User
        from django.urls import reverse

        client = Client()

        # Create a test admin user for frontend testing
        admin_user = User.objects.create_user(
            username='frontend_test_admin',
            email='admin@test.com',
            password='testpass123',
            is_staff=True,
            is_superuser=True
        )

        # Login
        login_success = client.login(username='frontend_test_admin', password='testpass123')
        if not login_success:
            print("⚠ Could not login for frontend testing")
            return False

        # Test key frontend pages
        frontend_pages = {
            'Dashboard': 'shift:dashboard',
            'Shift List': 'shift:list',
            'Create Shift': 'shift:create',
            'Assignments': 'shift:assignments',
            'Assign Shift': 'shift:assign',
            'Holidays': 'shift:holidays',
            'Calendar': 'shift:user_calendar',
            'Schedule': 'shift:schedule',
            'Statistics': 'shift:statistics'
        }

        accessible_pages = 0
        total_pages = len(frontend_pages)

        for page_name, url_name in frontend_pages.items():
            try:
                response = client.get(reverse(url_name))
                if response.status_code == 200:
                    print(f"✓ {page_name} - Accessible")
                    accessible_pages += 1
                else:
                    print(f"⚠ {page_name} - Status {response.status_code}")
            except Exception as e:
                print(f"✗ {page_name} - Error: {str(e)}")

        # Cleanup
        admin_user.delete()

        print(f"\nFrontend Accessibility: {accessible_pages}/{total_pages} pages accessible")
        return accessible_pages > 0

    except Exception as e:
        print(f"✗ Frontend accessibility check failed: {str(e)}")
        return False

def generate_system_info():
    """Generate system information for debugging"""
    print("\nSystem Information:")
    print("-" * 30)

    try:
        import platform
        import sys
        from django import get_version

        print(f"OS: {platform.system()} {platform.release()}")
        print(f"Python: {sys.version.split()[0]}")
        print(f"Django: {get_version()}")

        # Check Django apps
        from django.conf import settings
        if hasattr(settings, 'INSTALLED_APPS'):
            shift_app = 'trueAlign.shift' in settings.INSTALLED_APPS or 'shift' in [app.split('.')[-1] for app in settings.INSTALLED_APPS]
            print(f"Shift app installed: {shift_app}")

        # Check database
        from django.db import connection
        print(f"Database: {connection.vendor}")

        # Current working directory
        print(f"Working directory: {os.getcwd()}")

    except Exception as e:
        print(f"Could not gather system info: {str(e)}")

def main():
    """Main function to run all checks and tests"""
    start_time = time.time()

    print("ShiftMaster & ShiftAssignment Comprehensive Testing Suite")
    print("=" * 60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Timezone: Asia/Kolkata (IST)")

    # Generate system info
    generate_system_info()

    print("\n" + "="*60)
    print("RUNNING PRELIMINARY CHECKS")
    print("="*60)

    # Run preliminary checks
    checks = [
        ("Django Environment", setup_django_environment),
        ("Database Connection", check_database_connection),
        ("Timezone Configuration", check_timezone_setting),
        ("Model Availability", check_models_available),
        ("URL Patterns", check_urls_available),
        ("Basic Smoke Tests", run_basic_smoke_tests),
        ("Frontend Accessibility", check_frontend_accessibility),
    ]

    passed_checks = 0
    total_checks = len(checks)

    for check_name, check_function in checks:
        print(f"\n{check_name}:")
        print("-" * 20)

        try:
            if check_function():
                passed_checks += 1
            else:
                print(f"⚠ {check_name} check failed")
        except Exception as e:
            print(f"✗ {check_name} check error: {str(e)}")

    print(f"\nPreliminary Checks: {passed_checks}/{total_checks} passed")

    # Decide whether to run comprehensive tests
    if passed_checks >= total_checks * 0.7:  # At least 70% checks passed
        print("\n✓ Sufficient checks passed. Running comprehensive tests...")
        run_comprehensive_tests()
    else:
        print("\n✗ Too many preliminary checks failed. Skipping comprehensive tests.")
        print("Please fix the issues above and try again.")

    # Final summary
    end_time = time.time()
    duration = end_time - start_time

    print("\n" + "="*60)
    print("TESTING COMPLETE")
    print("="*60)
    print(f"Total duration: {duration:.2f} seconds")
    print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    # Check if report was generated
    if os.path.exists('shift_system_test_report.json'):
        print("✓ Detailed test report available: shift_system_test_report.json")

        try:
            with open('shift_system_test_report.json', 'r') as f:
                report = json.load(f)
                summary = report.get('summary', {})
                print(f"Test Summary: {summary.get('passed', 0)}/{summary.get('total_tests', 0)} tests passed")
        except:
            pass

    print("\nFor detailed results, check the console output above and the JSON report file.")


if __name__ == "__main__":
    main()
