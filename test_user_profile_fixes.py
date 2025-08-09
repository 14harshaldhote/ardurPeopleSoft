#!/usr/bin/env python
"""
Comprehensive test script for user profile fixes
Tests group assignment, office location display, and user creation/editing functionality
"""

import os
import sys
import django
from django.conf import settings

# Setup Django environment
sys.path.append('/Users/harshalsmac/WORK/ardur/ardurHome')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User, Group
from django.test import Client, TestCase
from django.urls import reverse
from trueAlign.models import UserDetails, OfficeLocation
from trueAlign.profile.utilities import generate_employee_id
import json

class UserProfileFixesTest:
    def __init__(self):
        self.client = Client()
        self.test_data = {}

    def setup_test_data(self):
        """Setup test data for comprehensive testing"""
        print("🔧 Setting up test data...")

        # Clear existing test data
        self.cleanup_test_data()

        # Create test groups
        self.create_test_groups()

        # Create test office locations
        self.create_test_office_locations()

        # Create test users
        self.create_test_users()

        print("✅ Test data setup completed\n")

    def cleanup_test_data(self):
        """Clean up any existing test data"""
        print("🧹 Cleaning up existing test data...")

        # Delete test users
        test_users = User.objects.filter(username__startswith='test_')
        if test_users.exists():
            print(f"   Deleted {test_users.count()} test users")
            test_users.delete()

        # Delete test groups if they exist
        test_groups = ['Test_Admin', 'Test_HR', 'Test_Employee']
        deleted_groups = Group.objects.filter(name__in=test_groups).delete()
        if deleted_groups[0] > 0:
            print(f"   Deleted {deleted_groups[0]} test groups")

        print("   Cleanup completed")

    def create_test_groups(self):
        """Create test groups"""
        print("👥 Creating test groups...")

        groups = [
            ('Admin', 'System administrators'),
            ('HR', 'Human Resources'),
            ('Manager', 'Team managers'),
            ('Employee', 'Regular employees'),
            ('Finance', 'Finance department'),
            ('Developer', 'Software developers'),
            ('QA', 'Quality assurance'),
            ('Intern', 'Interns and trainees')
        ]

        for group_name, description in groups:
            group, created = Group.objects.get_or_create(name=group_name)
            if created:
                print(f"   ✓ Created group: {group_name}")
            else:
                print(f"   • Group exists: {group_name}")

        self.test_data['groups'] = Group.objects.all()

    def create_test_office_locations(self):
        """Create test office locations"""
        print("🏢 Creating test office locations...")

        locations = [
            {
                'name': 'Ardur Technology - Betul',
                'code': 'ATS',
                'address_line1': 'Ardur Technology Solutions',
                'city': 'Betul',
                'state': 'Madhya Pradesh',
                'postal_code': '460001',
                'country': 'India',
                'is_active': True
            },
            {
                'name': 'Ardur Technology - Pune',
                'code': 'ATP',
                'address_line1': 'Ardur Technology Pvt Ltd',
                'city': 'Pune',
                'state': 'Maharashtra',
                'postal_code': '411057',
                'country': 'India',
                'is_active': True
            },
            {
                'name': 'Work From Home',
                'code': 'WFH',
                'address_line1': 'Remote Location',
                'city': 'Remote',
                'state': 'Remote',
                'postal_code': '000000',
                'country': 'India',
                'is_active': True
            }
        ]

        for location_data in locations:
            location, created = OfficeLocation.objects.get_or_create(
                code=location_data['code'],
                defaults=location_data
            )
            if created:
                print(f"   ✓ Created office: {location.name}")
            else:
                print(f"   • Office exists: {location.name}")

        self.test_data['office_locations'] = OfficeLocation.objects.all()

    def create_test_users(self):
        """Create test users with different roles"""
        print("👤 Creating test users...")

        # Admin user
        admin_user, created = User.objects.get_or_create(
            username='test_admin',
            defaults={
                'first_name': 'Admin',
                'last_name': 'User',
                'email': 'admin@test.com',
                'is_staff': True,
                'is_superuser': True
            }
        )
        if created:
            admin_user.set_password('testpass123')
            admin_user.save()

        admin_group = Group.objects.get(name='Admin')
        admin_user.groups.add(admin_group)

        # Create UserDetails for admin
        admin_profile, created = UserDetails.objects.get_or_create(
            user=admin_user,
            defaults={
                'role': 'admin',
                'employee_type': 'full_time',
                'employment_status': 'active',
                'office_location': OfficeLocation.objects.get(code='ATS')
            }
        )

        if created:
            print("   ✓ Created admin user with profile")
        else:
            print("   • Admin user exists")

        # HR user
        hr_user, created = User.objects.get_or_create(
            username='test_hr',
            defaults={
                'first_name': 'HR',
                'last_name': 'Manager',
                'email': 'hr@test.com'
            }
        )
        if created:
            hr_user.set_password('testpass123')
            hr_user.save()

        hr_group = Group.objects.get(name='HR')
        hr_user.groups.add(hr_group)

        # Create UserDetails for HR
        hr_profile, created = UserDetails.objects.get_or_create(
            user=hr_user,
            defaults={
                'role': 'hr',
                'employee_type': 'full_time',
                'employment_status': 'active',
                'office_location': OfficeLocation.objects.get(code='ATP')
            }
        )

        if created:
            print("   ✓ Created HR user with profile")
        else:
            print("   • HR user exists")

        self.test_data['admin_user'] = admin_user
        self.test_data['hr_user'] = hr_user

    def test_group_assignment(self):
        """Test group assignment functionality"""
        print("🧪 Testing group assignment...")

        # Test that users have correct groups
        admin_user = self.test_data['admin_user']
        hr_user = self.test_data['hr_user']

        admin_groups = list(admin_user.groups.values_list('name', flat=True))
        hr_groups = list(hr_user.groups.values_list('name', flat=True))

        print(f"   Admin user groups: {admin_groups}")
        print(f"   HR user groups: {hr_groups}")

        assert 'Admin' in admin_groups, "Admin user should be in Admin group"
        assert 'HR' in hr_groups, "HR user should be in HR group"

        print("   ✅ Group assignment test passed")

    def test_office_location_display(self):
        """Test office location display and assignment"""
        print("🏢 Testing office location functionality...")

        admin_user = self.test_data['admin_user']
        hr_user = self.test_data['hr_user']

        admin_profile = admin_user.profile
        hr_profile = hr_user.profile

        print(f"   Admin office: {admin_profile.office_location}")
        print(f"   HR office: {hr_profile.office_location}")

        # Test office location properties
        if admin_profile.office_location:
            print(f"   Admin full address: {admin_profile.office_location.full_address}")
            print(f"   Admin working hours: {admin_profile.office_location.working_hours_display}")

        assert admin_profile.office_location is not None, "Admin should have office location"
        assert hr_profile.office_location is not None, "HR should have office location"

        print("   ✅ Office location test passed")

    def test_user_detail_view(self):
        """Test user detail view displays correct information"""
        print("👁️ Testing user detail view...")

        # Login as admin
        self.client.login(username='test_admin', password='testpass123')

        admin_user = self.test_data['admin_user']
        hr_user = self.test_data['hr_user']

        # Test admin user detail view
        response = self.client.get(f'/profile/user/{admin_user.id}/')
        assert response.status_code == 200, f"User detail view failed with status {response.status_code}"

        content = response.content.decode()

        # Check if group information is displayed
        assert 'Admin' in content, "Admin group should be displayed in user detail"

        # Check if office location is displayed
        assert 'Betul' in content, "Office location should be displayed"

        print("   ✅ User detail view test passed")

    def test_user_creation_form(self):
        """Test user creation form functionality"""
        print("📝 Testing user creation form...")

        # Login as admin
        self.client.login(username='test_admin', password='testpass123')

        # Get the create user form
        response = self.client.get('/profile/user/create/')
        assert response.status_code == 200, f"Create user form failed with status {response.status_code}"

        content = response.content.decode()

        # Check if group field is present
        assert 'name="group"' in content, "Group field should be present in create form"

        # Check if office location field is present with options
        assert 'name="office_location"' in content, "Office location field should be present"
        assert 'Betul' in content, "Betul office should be an option"
        assert 'Pune' in content, "Pune office should be an option"

        print("   ✅ User creation form test passed")

    def test_employee_id_generation(self):
        """Test employee ID generation logic"""
        print("🆔 Testing employee ID generation...")

        # Test different combinations
        test_cases = [
            ('Betul', '7', 'Finance/Management group with Betul location'),
            ('Pune', '1', 'Admin group with Pune location'),
            ('Mumbai', '4', 'Employee group with Mumbai location'),
        ]

        for location, group_id, description in test_cases:
            employee_id = generate_employee_id(work_location=location, group_id=group_id)
            print(f"   {description}: {employee_id}")

            assert employee_id is not None, "Employee ID should be generated"
            assert len(employee_id) > 5, "Employee ID should have reasonable length"

        print("   ✅ Employee ID generation test passed")

    def test_user_update_form(self):
        """Test user update form functionality"""
        print("✏️ Testing user update form...")

        # Login as admin
        self.client.login(username='test_admin', password='testpass123')

        hr_user = self.test_data['hr_user']

        # Get the update user form
        response = self.client.get(f'/profile/user/{hr_user.id}/update/')
        assert response.status_code == 200, f"Update user form failed with status {response.status_code}"

        content = response.content.decode()

        # Check if current group is selected
        assert 'HR' in content, "Current group should be displayed in update form"

        # Check if current office location is displayed
        assert 'Pune' in content, "Current office location should be displayed"

        print("   ✅ User update form test passed")

    def test_context_processors(self):
        """Test context processors for group checks"""
        print("🔄 Testing context processors...")

        # Login as admin
        self.client.login(username='test_admin', password='testpass123')

        # Get any page that uses context processors
        response = self.client.get('/profile/user/list/')
        assert response.status_code == 200, "Page with context processors should load"

        # Check context variables (this would need to be tested in template)
        print("   ✅ Context processors test passed (basic check)")

    def run_all_tests(self):
        """Run all tests"""
        print("🚀 Starting comprehensive user profile fixes testing...\n")

        try:
            self.setup_test_data()

            self.test_group_assignment()
            self.test_office_location_display()
            self.test_employee_id_generation()
            self.test_user_detail_view()
            self.test_user_creation_form()
            self.test_user_update_form()
            self.test_context_processors()

            print("\n🎉 All tests passed successfully!")
            print("\n📋 Summary of fixes implemented:")
            print("   ✓ Added Group field to user forms")
            print("   ✓ Improved office location display with full details")
            print("   ✓ Fixed user details modal to show groups and enhanced location info")
            print("   ✓ Updated employee ID generation with proper group handling")
            print("   ✓ Enhanced form templates with better UI and validation")
            print("   ✓ Added comprehensive error handling and user feedback")

        except AssertionError as e:
            print(f"\n❌ Test failed: {e}")
            return False
        except Exception as e:
            print(f"\n💥 Unexpected error: {e}")
            import traceback
            traceback.print_exc()
            return False

        return True

    def generate_test_report(self):
        """Generate detailed test report"""
        print("\n📊 Generating test report...")

        # Count current data
        total_users = User.objects.count()
        total_groups = Group.objects.count()
        total_offices = OfficeLocation.objects.count()
        total_profiles = UserDetails.objects.count()

        print(f"""
📈 Current System Status:
   • Total Users: {total_users}
   • Total Groups: {total_groups}
   • Total Office Locations: {total_offices}
   • Total User Profiles: {total_profiles}
        """)

        # Group breakdown
        print("👥 Groups in system:")
        for group in Group.objects.all():
            user_count = group.user_set.count()
            print(f"   • {group.name}: {user_count} users")

        # Office location breakdown
        print("\n🏢 Office Locations:")
        for office in OfficeLocation.objects.all():
            employee_count = office.employees.count()
            status = "Active" if office.is_active else "Inactive"
            print(f"   • {office.name} ({office.code}): {employee_count} employees - {status}")

        print("\n✨ System is ready for testing!")

def main():
    """Main function to run tests"""
    tester = UserProfileFixesTest()

    # Run tests
    success = tester.run_all_tests()

    # Generate report
    tester.generate_test_report()

    if success:
        print("\n🎯 Next steps:")
        print("1. Login to the admin panel or HR dashboard")
        print("2. Try creating a new user and verify group assignment works")
        print("3. Check user detail pages show correct group and office info")
        print("4. Test the improved office location display")
        print("5. Verify employee ID generation works correctly")

        return 0
    else:
        print("\n🔧 Please fix the identified issues and run the test again")
        return 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
