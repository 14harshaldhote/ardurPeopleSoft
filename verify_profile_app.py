#!/usr/bin/env python3
"""
TrueAlign Profile App Verification Script
========================================

This script performs comprehensive testing of the profile app functionality
including models, views, APIs, templates, and data integrity.

Usage: python verify_profile_app.py
"""

import os
import sys
import django
from datetime import datetime, timedelta
import json

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')

try:
    django.setup()
except Exception as e:
    print(f"❌ Django setup failed: {e}")
    sys.exit(1)

from django.contrib.auth.models import User, Group
from django.test import Client
from django.urls import reverse
from django.db.models import Count
from trueAlign.models import UserDetails, OfficeLocation, UserActionLog


class ProfileAppVerifier:
    """Comprehensive verification of the Profile App functionality"""

    def __init__(self):
        self.client = Client()
        self.errors = []
        self.warnings = []
        self.success_count = 0
        self.total_tests = 0

    def log_success(self, message):
        """Log a successful test"""
        print(f"✅ {message}")
        self.success_count += 1

    def log_error(self, message):
        """Log a failed test"""
        print(f"❌ {message}")
        self.errors.append(message)

    def log_warning(self, message):
        """Log a warning"""
        print(f"⚠️ {message}")
        self.warnings.append(message)

    def test_models(self):
        """Test database models and relationships"""
        print("\n🧪 Testing Database Models...")
        self.total_tests += 6

        try:
            # Test User model
            user_count = User.objects.count()
            if user_count > 0:
                self.log_success(f"User model working - {user_count} users found")
            else:
                self.log_warning("No users found in database")

            # Test UserDetails model
            profile_count = UserDetails.objects.count()
            if profile_count > 0:
                self.log_success(f"UserDetails model working - {profile_count} profiles found")
            else:
                self.log_warning("No user profiles found")

            # Test OfficeLocation model
            office_count = OfficeLocation.objects.count()
            if office_count > 0:
                self.log_success(f"OfficeLocation model working - {office_count} offices found")
            else:
                self.log_warning("No office locations found")

            # Test relationships
            profiles_with_offices = UserDetails.objects.filter(office_location__isnull=False).count()
            if profiles_with_offices > 0:
                self.log_success(f"User-Office relationships working - {profiles_with_offices} linked")
            else:
                self.log_warning("No users linked to office locations")

            # Test model methods
            test_profile = UserDetails.objects.first()
            if test_profile:
                full_name = test_profile.full_name
                status_display = test_profile.status_display
                self.log_success("Model methods (full_name, status_display) working")
            else:
                self.log_warning("Cannot test model methods - no profiles available")

            # Test aggregations
            status_stats = UserDetails.objects.values('employment_status').annotate(
                count=Count('id')
            ).order_by('-count')

            if status_stats.exists():
                self.log_success(f"Database aggregations working - {len(status_stats)} status groups")
            else:
                self.log_warning("No status aggregation data available")

        except Exception as e:
            self.log_error(f"Model testing failed: {str(e)}")

    def test_url_patterns(self):
        """Test URL pattern reversing"""
        print("\n🌐 Testing URL Patterns...")
        self.total_tests += 5

        url_tests = [
            ('profile:dashboard', 'Dashboard URL'),
            ('profile:user-list', 'User List URL'),
            ('profile:user-create', 'User Create URL'),
            ('profile:dashboard-analytics-api', 'Analytics API URL'),
            ('profile:dashboard-stats-api', 'Stats API URL'),
        ]

        for url_name, description in url_tests:
            try:
                url = reverse(url_name)
                self.log_success(f"{description}: {url}")
            except Exception as e:
                self.log_error(f"{description} failed: {str(e)}")

    def test_views_basic(self):
        """Test basic view responses (without authentication)"""
        print("\n🎯 Testing View Responses...")
        self.total_tests += 4

        # Test views that should redirect to login
        test_views = [
            ('/profile/dashboard/', 'Dashboard View'),
            ('/profile/users/', 'User List View'),
            ('/profile/users/new/', 'User Create View'),
            ('/profile/my-profile/', 'My Profile View'),
        ]

        for url, description in test_views:
            try:
                response = self.client.get(url)
                if response.status_code == 302:  # Redirect to login
                    self.log_success(f"{description} properly redirects to login")
                elif response.status_code == 200:
                    self.log_warning(f"{description} allows anonymous access")
                else:
                    self.log_error(f"{description} returned status {response.status_code}")
            except Exception as e:
                self.log_error(f"{description} error: {str(e)}")

    def test_with_authentication(self):
        """Test functionality with authenticated admin user"""
        print("\n🔐 Testing Authenticated Functionality...")
        self.total_tests += 6

        # Get or create admin user
        try:
            admin_user = User.objects.filter(is_superuser=True).first()
            if not admin_user:
                admin_user, created = User.objects.get_or_create(
                    username='test_admin',
                    defaults={
                        'is_superuser': True,
                        'is_staff': True,
                        'email': 'admin@test.com'
                    }
                )
                if created:
                    admin_user.set_password('admin123')
                    admin_user.save()

            # Add to HR group
            hr_group, _ = Group.objects.get_or_create(name='HR')
            admin_user.groups.add(hr_group)

            # Force login
            self.client.force_login(admin_user)
            self.log_success(f"Authenticated as admin user: {admin_user.username}")

        except Exception as e:
            self.log_error(f"Authentication setup failed: {str(e)}")
            return

        # Test authenticated views
        auth_tests = [
            ('/profile/dashboard/', 'Dashboard with auth'),
            ('/profile/users/', 'User list with auth'),
            ('/profile/my-profile/', 'My profile with auth'),
        ]

        for url, description in auth_tests:
            try:
                response = self.client.get(url)
                if response.status_code == 200:
                    self.log_success(f"{description} loads successfully")
                    # Check for basic template elements
                    content = response.content.decode('utf-8')
                    if 'DOCTYPE html' in content:
                        self.log_success(f"{description} returns valid HTML")
                    else:
                        self.log_warning(f"{description} may not return valid HTML")
                else:
                    self.log_error(f"{description} returned status {response.status_code}")
            except Exception as e:
                self.log_error(f"{description} error: {str(e)}")

    def test_api_endpoints(self):
        """Test API endpoints"""
        print("\n🔌 Testing API Endpoints...")
        self.total_tests += 3

        # Ensure we're authenticated
        admin_user = User.objects.filter(is_superuser=True).first()
        if admin_user:
            self.client.force_login(admin_user)

        api_tests = [
            ('/profile/api/dashboard-analytics/', 'Analytics API'),
            ('/profile/api/dashboard-stats/', 'Stats API'),
        ]

        for url, description in api_tests:
            try:
                response = self.client.get(url)
                if response.status_code == 200:
                    try:
                        data = json.loads(response.content)
                        self.log_success(f"{description} returns valid JSON")
                        if isinstance(data, dict):
                            self.log_success(f"{description} has proper data structure")
                        else:
                            self.log_warning(f"{description} returns non-dict data")
                    except json.JSONDecodeError:
                        self.log_error(f"{description} returns invalid JSON")
                elif response.status_code == 403:
                    self.log_warning(f"{description} returns 403 - check permissions")
                else:
                    self.log_error(f"{description} returned status {response.status_code}")
            except Exception as e:
                self.log_error(f"{description} error: {str(e)}")

        # Test POST endpoint (layout save)
        try:
            layout_data = {"test-card": {"width": "300px", "height": "200px"}}
            response = self.client.post(
                '/profile/api/save-dashboard-layout/',
                data=json.dumps({"layout": layout_data}),
                content_type='application/json'
            )
            if response.status_code == 200:
                self.log_success("Layout save API working")
            else:
                self.log_warning(f"Layout save API returned {response.status_code}")
        except Exception as e:
            self.log_error(f"Layout save API error: {str(e)}")

    def test_data_integrity(self):
        """Test data relationships and integrity"""
        print("\n📊 Testing Data Integrity...")
        self.total_tests += 4

        try:
            # Test user-profile relationships
            users_with_profiles = User.objects.filter(userdetails__isnull=False).count()
            total_users = User.objects.count()

            if users_with_profiles > 0:
                self.log_success(f"User-Profile relationships: {users_with_profiles}/{total_users}")
            else:
                self.log_warning("No user-profile relationships found")

            # Test employment status distribution
            statuses = UserDetails.objects.values('employment_status').annotate(
                count=Count('id')
            ).order_by('-count')

            if statuses.exists():
                status_list = list(statuses)
                self.log_success(f"Employment status distribution: {len(status_list)} categories")
                for status in status_list[:3]:  # Show top 3
                    print(f"    • {status['employment_status']}: {status['count']}")
            else:
                self.log_warning("No employment status data found")

            # Test office location assignments
            users_with_offices = UserDetails.objects.filter(
                office_location__isnull=False
            ).count()

            if users_with_offices > 0:
                self.log_success(f"Office assignments: {users_with_offices} users assigned")
            else:
                self.log_warning("No users assigned to office locations")

            # Test recent activity (if any action logs exist)
            recent_logs = UserActionLog.objects.filter(
                timestamp__gte=datetime.now() - timedelta(days=30)
            ).count()

            if recent_logs > 0:
                self.log_success(f"Recent activity logs: {recent_logs} actions recorded")
            else:
                self.log_warning("No recent activity logs found")

        except Exception as e:
            self.log_error(f"Data integrity test failed: {str(e)}")

    def test_template_context(self):
        """Test that templates receive proper context data"""
        print("\n🎨 Testing Template Context...")
        self.total_tests += 2

        # Ensure authentication
        admin_user = User.objects.filter(is_superuser=True).first()
        if admin_user:
            self.client.force_login(admin_user)

        try:
            # Test dashboard context
            response = self.client.get('/profile/dashboard/')
            if response.status_code == 200:
                context_keys = [
                    'total_users', 'active_users', 'inactive_users',
                    'location_stats', 'status_stats', 'recent_logins'
                ]

                missing_keys = [key for key in context_keys if key not in response.context]

                if not missing_keys:
                    self.log_success("Dashboard context has all required variables")
                else:
                    self.log_warning(f"Dashboard missing context keys: {missing_keys}")
            else:
                self.log_error(f"Cannot test dashboard context - status {response.status_code}")

            # Test user list context
            response = self.client.get('/profile/users/')
            if response.status_code == 200:
                if 'users' in response.context:
                    user_count = len(response.context['users'])
                    self.log_success(f"User list context working - {user_count} users")
                else:
                    self.log_error("User list missing 'users' context variable")
            else:
                self.log_error(f"Cannot test user list context - status {response.status_code}")

        except Exception as e:
            self.log_error(f"Template context test failed: {str(e)}")

    def generate_summary(self):
        """Generate verification summary"""
        print("\n" + "="*60)
        print("📋 TRUEALIGN PROFILE APP VERIFICATION SUMMARY")
        print("="*60)

        print(f"\n📊 Test Results:")
        print(f"   ✅ Successful: {self.success_count}/{self.total_tests}")
        print(f"   ❌ Errors: {len(self.errors)}")
        print(f"   ⚠️ Warnings: {len(self.warnings)}")

        success_rate = (self.success_count / self.total_tests * 100) if self.total_tests > 0 else 0
        print(f"   📈 Success Rate: {success_rate:.1f}%")

        # Overall status
        if len(self.errors) == 0 and success_rate >= 80:
            print(f"\n🎉 OVERALL STATUS: ✅ FULLY FUNCTIONAL")
            print("   The profile app is working correctly and ready for use!")
        elif len(self.errors) == 0 and success_rate >= 60:
            print(f"\n⚠️ OVERALL STATUS: 🟡 MOSTLY FUNCTIONAL")
            print("   The profile app works but has some warnings to address.")
        else:
            print(f"\n❌ OVERALL STATUS: 🔴 NEEDS ATTENTION")
            print("   The profile app has issues that should be resolved.")

        # Show errors if any
        if self.errors:
            print(f"\n❌ Errors to Fix:")
            for i, error in enumerate(self.errors, 1):
                print(f"   {i}. {error}")

        # Show warnings if any
        if self.warnings:
            print(f"\n⚠️ Warnings:")
            for i, warning in enumerate(self.warnings, 1):
                print(f"   {i}. {warning}")

        # Usage instructions
        print(f"\n🚀 Quick Start:")
        print(f"   • Dashboard: http://localhost:8000/profile/dashboard/")
        print(f"   • User Management: http://localhost:8000/profile/users/")
        print(f"   • Admin Login: admin / admin123")

        print(f"\n📚 Documentation:")
        print(f"   • Full report: PROFILE_APP_STATUS_REPORT.md")
        print(f"   • API endpoints documented in views.py")

        print("\n" + "="*60)

    def run_all_tests(self):
        """Run comprehensive verification"""
        print("🧪 TRUEALIGN PROFILE APP VERIFICATION")
        print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        try:
            self.test_models()
            self.test_url_patterns()
            self.test_views_basic()
            self.test_with_authentication()
            self.test_api_endpoints()
            self.test_data_integrity()
            self.test_template_context()

        except KeyboardInterrupt:
            print("\n\n⚠️ Verification interrupted by user")
        except Exception as e:
            print(f"\n\n❌ Unexpected error during verification: {str(e)}")
            import traceback
            traceback.print_exc()

        finally:
            self.generate_summary()


if __name__ == "__main__":
    print("Starting TrueAlign Profile App Verification...")
    print("This will test all functionality including models, views, APIs, and data integrity.")
    print()

    verifier = ProfileAppVerifier()
    verifier.run_all_tests()
