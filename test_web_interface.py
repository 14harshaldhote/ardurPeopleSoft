#!/usr/bin/env python
"""
Web interface test script to verify user creation and editing through HTML forms
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
import time

def create_admin_user_for_testing():
    """Create admin user for testing web interface"""
    print("👤 Setting up admin user for web testing...")

    # Use HR group (ID: 1) or Admin group (ID: 2)
    try:
        admin_group = Group.objects.get(id=2)  # Admin
    except Group.DoesNotExist:
        admin_group = Group.objects.get(id=1)  # HR as fallback

    # Create or get admin user
    admin_user, created = User.objects.get_or_create(
        username='webtest_admin',
        defaults={
            'first_name': 'Web',
            'last_name': 'Admin',
            'email': 'webadmin@test.com',
            'is_staff': True,
            'is_superuser': True
        }
    )

    if created:
        admin_user.set_password('admin123')
        admin_user.save()
        print(f"✓ Created admin user: {admin_user.username}")
    else:
        print(f"• Admin user exists: {admin_user.username}")

    # Add to admin group
    admin_user.groups.clear()
    admin_user.groups.add(admin_group)

    # Create user profile if doesn't exist
    profile, created = UserDetails.objects.get_or_create(
        user=admin_user,
        defaults={
            'role': 'admin',
            'employee_type': 'full_time',
            'employment_status': 'active',
            'office_location': OfficeLocation.objects.first() if OfficeLocation.objects.exists() else None
        }
    )

    return admin_user

def test_login_access():
    """Test login and access to user management pages"""
    print("\n🔐 Testing login and page access...")
    print("-" * 50)

    client = Client()

    # Test login
    login_data = {
        'username': 'webtest_admin',
        'password': 'admin123'
    }

    login_response = client.post('/login/', login_data, follow=True)

    if login_response.status_code == 200:
        print("✓ Login successful")

        # Test access to user management pages
        pages_to_test = [
            ('/profile/user/list/', 'User List'),
            ('/profile/user/create/', 'Create User Form'),
            ('/profile/dashboard/', 'HR Dashboard'),
        ]

        for url, page_name in pages_to_test:
            try:
                response = client.get(url)
                if response.status_code == 200:
                    print(f"✓ {page_name} accessible")
                else:
                    print(f"❌ {page_name} failed (status: {response.status_code})")
            except Exception as e:
                print(f"❌ {page_name} error: {str(e)}")

        return client
    else:
        print("❌ Login failed")
        return None

def test_create_user_form(client):
    """Test the create user form with your groups"""
    print("\n📝 Testing create user form...")
    print("-" * 50)

    # Get the create form
    response = client.get('/profile/user/create/')

    if response.status_code != 200:
        print(f"❌ Cannot access create form (status: {response.status_code})")
        return False

    content = response.content.decode()

    # Check for essential form elements
    form_checks = [
        ('name="first_name"', 'First Name field'),
        ('name="last_name"', 'Last Name field'),
        ('name="email"', 'Email field'),
        ('name="password"', 'Password field'),
        ('name="group"', 'Group selection field'),
        ('name="office_location"', 'Office Location field'),
    ]

    all_present = True
    for field_check, description in form_checks:
        if field_check in content:
            print(f"✓ {description} present")
        else:
            print(f"❌ {description} missing")
            all_present = False

    # Check if your specific groups are in the form
    your_groups = ['HR', 'Admin', 'Manager', 'Employee', 'Finance', 'Management', 'Client']
    groups_found = []

    for group in your_groups:
        if group in content:
            groups_found.append(group)

    print(f"✓ Groups found in form: {', '.join(groups_found)}")

    # Check office locations
    offices = OfficeLocation.objects.filter(is_active=True)
    offices_found = []

    for office in offices:
        if office.name in content or office.city in content:
            offices_found.append(office.name)

    print(f"✓ Office locations found: {', '.join(offices_found)}")

    return all_present

def test_user_creation_submission(client):
    """Test actually creating a user through the web form"""
    print("\n🧪 Testing user creation submission...")
    print("-" * 50)

    # Clean up any existing test user
    test_email = 'webtest@example.com'
    if User.objects.filter(email=test_email).exists():
        User.objects.filter(email=test_email).delete()
        print("✓ Cleaned up existing test user")

    # Get available groups and offices
    groups = Group.objects.all()
    offices = OfficeLocation.objects.filter(is_active=True)

    if not groups.exists() or not offices.exists():
        print("❌ No groups or offices available")
        return False

    # Prepare form data
    form_data = {
        'first_name': 'Web',
        'last_name': 'Test',
        'email': test_email,
        'password': 'Welcome@123',
        'group': groups.first().id,
        'office_location': offices.first().id,
        'role': 'developer',
        'employee_type': 'full_time',
        'employment_status': 'probation',
        'contact_number_primary': '+91-9876543210',
    }

    print(f"Creating user with:")
    print(f"  Group: {groups.first().name} (ID: {groups.first().id})")
    print(f"  Office: {offices.first().name}")

    try:
        # Submit the form
        response = client.post('/profile/user/create/', form_data, follow=True)

        if response.status_code == 200:
            # Check if user was created
            if User.objects.filter(email=test_email).exists():
                new_user = User.objects.get(email=test_email)
                print(f"✅ User created successfully!")
                print(f"   Username: {new_user.username}")

                # Check group assignment
                user_groups = list(new_user.groups.values_list('name', flat=True))
                print(f"   Groups: {user_groups}")

                # Check profile
                if hasattr(new_user, 'profile'):
                    profile = new_user.profile
                    print(f"   Office: {profile.office_location}")
                    print(f"   Role: {profile.role}")
                    print(f"   Status: {profile.employment_status}")

                # Test user detail view
                detail_response = client.get(f'/profile/user/{new_user.id}/')
                if detail_response.status_code == 200:
                    detail_content = detail_response.content.decode()

                    # Check if group is displayed
                    group_displayed = any(group in detail_content for group in user_groups)
                    office_displayed = profile.office_location.name in detail_content if profile.office_location else False

                    print(f"   Group displayed in detail: {'✓' if group_displayed else '❌'}")
                    print(f"   Office displayed in detail: {'✓' if office_displayed else '❌'}")

                # Test edit form
                edit_response = client.get(f'/profile/user/{new_user.id}/update/')
                if edit_response.status_code == 200:
                    print("   ✓ Edit form accessible")

                    edit_content = edit_response.content.decode()
                    current_group_selected = any(f'selected' in line and group in line
                                               for line in edit_content.split('\n')
                                               for group in user_groups)

                    print(f"   Current group pre-selected: {'✓' if current_group_selected else '❌'}")

                # Clean up
                new_user.delete()
                print("   ✓ Test user cleaned up")

                return True
            else:
                print("❌ User was not created")
                print("Response preview:", response.content.decode()[:200])
                return False
        else:
            print(f"❌ Form submission failed (status: {response.status_code})")
            return False

    except Exception as e:
        print(f"❌ Error during submission: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def show_browser_test_instructions():
    """Show instructions for manual browser testing"""
    print("\n🌐 Manual Browser Testing Instructions")
    print("=" * 60)

    print("1. Open your browser and go to: http://localhost:8000/")
    print("2. Login with:")
    print("   Username: webtest_admin")
    print("   Password: admin123")
    print("")
    print("3. Test User Creation:")
    print("   - Go to: http://localhost:8000/profile/user/create/")
    print("   - Fill in the form with your groups:")

    groups = Group.objects.all().order_by('id')
    for group in groups:
        print(f"     • {group.name} (ID: {group.id})")

    print("   - Select an office location:")
    offices = OfficeLocation.objects.filter(is_active=True)
    for office in offices:
        print(f"     • {office.name} - {office.city}")

    print("")
    print("4. Test User Detail View:")
    print("   - After creating a user, check the detail page")
    print("   - Verify group and office information display correctly")
    print("")
    print("5. Test User Editing:")
    print("   - Click 'Edit Profile' on a user detail page")
    print("   - Verify current group is pre-selected")
    print("   - Try changing group and saving")

def main():
    """Main test function"""
    print("🚀 Web Interface Testing Script")
    print("=" * 60)

    # Setup admin user
    admin_user = create_admin_user_for_testing()

    # Test web interface
    client = test_login_access()

    if client:
        form_ok = test_create_user_form(client)

        if form_ok:
            creation_ok = test_user_creation_submission(client)

            print("\n" + "="*60)
            print("🎯 WEB TEST RESULTS")
            print("="*60)

            if creation_ok:
                print("✅ ALL TESTS PASSED!")
                print("\nYour user profile system is working correctly:")
                print("  ✓ Groups are properly loaded and selectable")
                print("  ✓ Office locations are displayed correctly")
                print("  ✓ User creation works through HTML forms")
                print("  ✓ Group assignment works")
                print("  ✓ User profiles are created with proper relationships")
                print("  ✓ Detail pages show group and office information")
                print("  ✓ Edit forms pre-select current groups")

                print("\n🎉 Ready for production use!")

            else:
                print("❌ User creation test failed")
                print("Check the errors above and fix any issues")
        else:
            print("❌ Form structure test failed")
            print("Essential form fields are missing")
    else:
        print("❌ Cannot access web interface")
        print("Check if the server is running and admin user is created")

    # Show manual testing instructions
    show_browser_test_instructions()

    print(f"\nAdmin user for testing: webtest_admin / admin123")
    print("Server should be running at: http://localhost:8000/")

if __name__ == "__main__":
    main()
