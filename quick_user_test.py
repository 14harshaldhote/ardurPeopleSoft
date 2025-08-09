#!/usr/bin/env python
"""
Quick diagnostic script to check existing groups and test user creation/editing
"""

import os
import sys
import django

# Setup Django environment
sys.path.append('/Users/harshalsmac/WORK/ardur/ardurHome')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User, Group
from django.test import Client
from trueAlign.models import UserDetails, OfficeLocation
from trueAlign.profile.utilities import generate_employee_id
import json

def check_existing_groups():
    """Check your existing groups"""
    print("🔍 Checking existing groups in auth_group table...")
    print("-" * 50)

    groups = Group.objects.all().order_by('id')
    for group in groups:
        user_count = group.user_set.count()
        print(f"ID: {group.id:2d} | Name: {group.name:12s} | Users: {user_count}")

    print(f"\nTotal groups: {groups.count()}")
    return groups

def check_office_locations():
    """Check existing office locations"""
    print("\n🏢 Checking existing office locations...")
    print("-" * 50)

    locations = OfficeLocation.objects.all().order_by('id')
    for location in locations:
        employee_count = location.employees.count() if hasattr(location, 'employees') else 0
        status = "Active" if location.is_active else "Inactive"
        print(f"ID: {location.id:2d} | Code: {location.code:4s} | Name: {location.name:30s} | Employees: {employee_count} | Status: {status}")

    print(f"\nTotal office locations: {locations.count()}")
    return locations

def test_employee_id_generation():
    """Test employee ID generation with your groups"""
    print("\n🆔 Testing employee ID generation with your groups...")
    print("-" * 50)

    # Test with different group IDs from your data
    test_cases = [
        ('Betul', '7', 'Finance'),
        ('Pune', '1', 'HR'),
        ('Mumbai', '2', 'Admin'),
        ('Delhi', '3', 'Management'),
        ('Bangalore', '4', 'Manager'),
        ('Remote', '5', 'Employee'),
        ('Betul', '6', 'Client'),
    ]

    for location, group_id, group_name in test_cases:
        try:
            employee_id = generate_employee_id(work_location=location, group_id=group_id)
            print(f"Location: {location:10s} | Group: {group_name:10s} (ID:{group_id}) | Generated ID: {employee_id}")
        except Exception as e:
            print(f"Location: {location:10s} | Group: {group_name:10s} (ID:{group_id}) | ERROR: {str(e)}")

def create_test_admin_user():
    """Create a test admin user for testing"""
    print("\n👤 Creating test admin user...")
    print("-" * 50)

    try:
        # Check if HR group exists (ID 1 from your data)
        hr_group = Group.objects.get(id=1)  # HR group
        admin_group = Group.objects.get(id=2)  # Admin group

        # Create or get test admin user
        test_user, created = User.objects.get_or_create(
            username='test_admin_user',
            defaults={
                'first_name': 'Test',
                'last_name': 'Admin',
                'email': 'testadmin@example.com',
                'is_staff': True,
                'is_superuser': True
            }
        )

        if created:
            test_user.set_password('admin123')
            test_user.save()
            print(f"✓ Created new test admin user: {test_user.username}")
        else:
            print(f"• Test admin user already exists: {test_user.username}")

        # Add to admin group
        if admin_group not in test_user.groups.all():
            test_user.groups.add(admin_group)
            print(f"✓ Added user to Admin group")

        # Create or update user profile
        office_location = None
        if OfficeLocation.objects.exists():
            office_location = OfficeLocation.objects.first()

        user_profile, created = UserDetails.objects.get_or_create(
            user=test_user,
            defaults={
                'role': 'admin',
                'employee_type': 'full_time',
                'employment_status': 'active',
                'office_location': office_location,
                'contact_number_primary': '+91-9876543210',
                'company_email': 'testadmin@ardur.com'
            }
        )

        if created:
            print(f"✓ Created user profile")
        else:
            print(f"• User profile already exists")

        return test_user

    except Group.DoesNotExist as e:
        print(f"❌ Group not found: {e}")
        return None
    except Exception as e:
        print(f"❌ Error creating test user: {e}")
        return None

def test_user_form_data():
    """Test form data structure"""
    print("\n📝 Testing form data structure...")
    print("-" * 50)

    client = Client()

    # Try to access the create user form
    try:
        response = client.get('/profile/user/create/')
        print(f"Create user form status: {response.status_code}")

        if response.status_code == 200:
            print("✓ Create user form accessible")

            # Check if the response contains group options
            content = response.content.decode()
            if 'name="group"' in content:
                print("✓ Group field found in form")
            else:
                print("❌ Group field NOT found in form")

            if 'name="office_location"' in content:
                print("✓ Office location field found in form")
            else:
                print("❌ Office location field NOT found in form")
        else:
            print(f"❌ Cannot access create user form (status: {response.status_code})")

    except Exception as e:
        print(f"❌ Error accessing form: {e}")

def test_form_submission():
    """Test actual form submission"""
    print("\n🧪 Testing form submission...")
    print("-" * 50)

    # Create a test admin user first
    admin_user = create_test_admin_user()
    if not admin_user:
        print("❌ Cannot test form submission without admin user")
        return

    client = Client()

    # Login as admin
    login_success = client.login(username='test_admin_user', password='admin123')
    if not login_success:
        print("❌ Cannot login as test admin user")
        return

    print("✓ Logged in as test admin user")

    # Get available groups and office locations
    groups = Group.objects.all()
    locations = OfficeLocation.objects.filter(is_active=True)

    if not groups.exists():
        print("❌ No groups available for testing")
        return

    if not locations.exists():
        print("❌ No office locations available for testing")
        return

    # Prepare form data
    form_data = {
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'john.doe@test.com',
        'password': 'Welcome@123',
        'group': groups.first().id,  # Use first available group
        'office_location': locations.first().id,  # Use first available location
        'role': 'developer',
        'employee_type': 'full_time',
        'employment_status': 'active',
        'contact_number_primary': '+91-9876543210',
    }

    print(f"Testing with group: {groups.first().name} (ID: {groups.first().id})")
    print(f"Testing with office: {locations.first().name} (ID: {locations.first().id})")

    try:
        response = client.post('/profile/user/create/', form_data, follow=True)
        print(f"Form submission status: {response.status_code}")

        if response.status_code == 200:
            # Check if user was created
            if User.objects.filter(email='john.doe@test.com').exists():
                new_user = User.objects.get(email='john.doe@test.com')
                print(f"✓ User created successfully: {new_user.username}")

                # Check group assignment
                user_groups = list(new_user.groups.values_list('name', flat=True))
                print(f"✓ User groups: {user_groups}")

                # Check profile creation
                if hasattr(new_user, 'profile'):
                    profile = new_user.profile
                    print(f"✓ User profile created")
                    print(f"  - Role: {profile.role}")
                    print(f"  - Office: {profile.office_location}")
                    print(f"  - Status: {profile.employment_status}")
                else:
                    print("❌ User profile not created")

                # Clean up test user
                new_user.delete()
                print("✓ Cleaned up test user")

            else:
                print("❌ User was not created")
                print("Response content preview:")
                content = response.content.decode()[:500]
                print(content)
        else:
            print(f"❌ Form submission failed with status {response.status_code}")

    except Exception as e:
        print(f"❌ Error during form submission: {e}")
        import traceback
        traceback.print_exc()

def check_current_issues():
    """Check for common issues"""
    print("\n🔧 Checking for common issues...")
    print("-" * 50)

    issues_found = []

    # Check if groups exist
    if not Group.objects.exists():
        issues_found.append("No groups found in database")

    # Check if office locations exist
    if not OfficeLocation.objects.exists():
        issues_found.append("No office locations found in database")

    # Check if there are any users with profiles
    users_with_profiles = User.objects.filter(profile__isnull=False).count()
    total_users = User.objects.count()

    print(f"Users with profiles: {users_with_profiles}/{total_users}")

    if users_with_profiles == 0 and total_users > 0:
        issues_found.append("Users exist but no user profiles found")

    # Check form template existence
    import os
    template_path = '/Users/harshalsmac/WORK/ardur/ardurHome/trueAlign/templates/profile/user_form.html'
    if not os.path.exists(template_path):
        issues_found.append("User form template not found")

    if issues_found:
        print("❌ Issues found:")
        for issue in issues_found:
            print(f"   • {issue}")
    else:
        print("✓ No obvious issues detected")

    return issues_found

def main():
    """Main function"""
    print("🚀 Quick User Profile Diagnostic Script")
    print("=" * 60)

    # Check existing data
    groups = check_existing_groups()
    locations = check_office_locations()

    # Test employee ID generation
    test_employee_id_generation()

    # Check for issues
    issues = check_current_issues()

    # Test form access
    test_user_form_data()

    # Test actual form submission
    if not issues:
        test_form_submission()

    print("\n" + "=" * 60)
    print("🎯 SUMMARY")
    print("=" * 60)

    if issues:
        print("❌ Issues need to be resolved before testing user creation:")
        for issue in issues:
            print(f"   • {issue}")
    else:
        print("✅ Basic setup looks good!")
        print("\n🔧 Next steps:")
        print("1. Run: python manage.py runserver")
        print("2. Login to: http://localhost:8000/profile/user/create/")
        print("3. Test creating a new user with your existing groups")
        print("4. Verify group assignment and office location display")

    print(f"\nYour Groups Available:")
    for group in groups:
        print(f"   • {group.name} (ID: {group.id})")

if __name__ == "__main__":
    main()
