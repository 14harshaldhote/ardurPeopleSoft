#!/usr/bin/env python
"""
Direct form testing script to check user creation and editing forms
"""

import os
import sys
import django

# Setup Django environment
sys.path.append('/Users/harshalsmac/WORK/ardur/ardurHome')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User, Group
from trueAlign.models import UserDetails, OfficeLocation
from trueAlign.profile.forms import UserDetailsCreateForm, UserDetailsUpdateForm

def test_create_form():
    """Test the UserDetailsCreateForm directly"""
    print("🔍 Testing UserDetailsCreateForm...")
    print("-" * 50)

    # Test form initialization
    try:
        form = UserDetailsCreateForm()
        print("✓ Form initialized successfully")

        # Check if group field has choices
        group_choices = list(form.fields['group'].queryset)
        print(f"✓ Group choices available: {len(group_choices)}")
        for group in group_choices:
            print(f"   • {group.name} (ID: {group.id})")

        # Check if office_location field has choices
        office_choices = list(form.fields['office_location'].queryset)
        print(f"✓ Office location choices available: {len(office_choices)}")
        for office in office_choices:
            print(f"   • {office.name} - {office.city}")

        return True

    except Exception as e:
        print(f"❌ Error initializing form: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_form_validation():
    """Test form validation with valid data"""
    print("\n🧪 Testing form validation...")
    print("-" * 50)

    # Get available choices
    groups = Group.objects.all()
    offices = OfficeLocation.objects.filter(is_active=True)

    if not groups.exists():
        print("❌ No groups available for testing")
        return False

    if not offices.exists():
        print("❌ No office locations available for testing")
        return False

    # Test data
    form_data = {
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'john.doe@test.com',
        'password': 'Welcome@123',
        'group': groups.first().id,
        'office_location': offices.first().id,
        'role': 'developer',
        'employee_type': 'full_time',
        'employment_status': 'active',
        'contact_number_primary': '+91-9876543210',
    }

    print(f"Testing with:")
    print(f"  Group: {groups.first().name} (ID: {groups.first().id})")
    print(f"  Office: {offices.first().name} (ID: {offices.first().id})")

    try:
        form = UserDetailsCreateForm(data=form_data)

        if form.is_valid():
            print("✅ Form validation passed!")
            print("✓ All required fields are valid")
            return True
        else:
            print("❌ Form validation failed!")
            print("Errors found:")
            for field, errors in form.errors.items():
                print(f"  • {field}: {errors}")
            return False

    except Exception as e:
        print(f"❌ Error during validation: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_update_form():
    """Test the UserDetailsUpdateForm with existing user"""
    print("\n✏️ Testing UserDetailsUpdateForm...")
    print("-" * 50)

    # Find an existing user with profile
    users_with_profiles = User.objects.filter(profile__isnull=False)

    if not users_with_profiles.exists():
        print("❌ No users with profiles found for testing")
        return False

    test_user = users_with_profiles.first()
    test_profile = test_user.profile

    print(f"Testing with user: {test_user.username}")
    print(f"Current groups: {list(test_user.groups.values_list('name', flat=True))}")

    try:
        # Initialize form with existing user
        form = UserDetailsUpdateForm(instance=test_profile, user=test_user)
        print("✓ Update form initialized successfully")

        # Check if current group is properly set
        if hasattr(form.fields['group'], 'initial') and form.fields['group'].initial:
            print(f"✓ Current group properly set: {form.fields['group'].initial}")
        else:
            print("⚠️ No current group set in form")

        # Check office location choices
        office_choices = list(form.fields['office_location'].queryset)
        print(f"✓ Office location choices: {len(office_choices)}")

        return True

    except Exception as e:
        print(f"❌ Error initializing update form: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_actual_user_creation():
    """Test actual user creation process"""
    print("\n👤 Testing actual user creation...")
    print("-" * 50)

    # Clean up any existing test user
    test_email = 'formtest@example.com'
    if User.objects.filter(email=test_email).exists():
        User.objects.filter(email=test_email).delete()
        print("✓ Cleaned up existing test user")

    groups = Group.objects.all()
    offices = OfficeLocation.objects.filter(is_active=True)

    if not groups.exists() or not offices.exists():
        print("❌ Missing groups or offices for testing")
        return False

    # Form data
    form_data = {
        'first_name': 'Form',
        'last_name': 'Test',
        'email': test_email,
        'password': 'Welcome@123',
        'group': groups.first().id,
        'office_location': offices.first().id,
        'role': 'developer',
        'employee_type': 'full_time',
        'employment_status': 'active',
        'contact_number_primary': '+91-9876543210',
        'company_email': 'formtest@company.com'
    }

    try:
        # Validate form
        form = UserDetailsCreateForm(data=form_data)

        if not form.is_valid():
            print("❌ Form validation failed:")
            for field, errors in form.errors.items():
                print(f"  • {field}: {errors}")
            return False

        print("✓ Form validation passed")

        # Simulate the view's form_valid process
        from trueAlign.profile.utilities import generate_employee_id

        # Get form data
        email = form.cleaned_data.get('email')
        password = form.cleaned_data.get('password')
        first_name = form.cleaned_data.get('first_name')
        last_name = form.cleaned_data.get('last_name')
        work_location = form.cleaned_data.get('office_location')
        group = form.cleaned_data.get('group')

        print(f"Form data extracted:")
        print(f"  • Email: {email}")
        print(f"  • Name: {first_name} {last_name}")
        print(f"  • Group: {group.name} (ID: {group.id})")
        print(f"  • Office: {work_location.name}")

        # Generate employee ID
        username = generate_employee_id(
            work_location=str(work_location) if work_location else None,
            group_id=str(group.id) if group else None
        )
        print(f"  • Generated username: {username}")

        # Create user
        user = User.objects.create_user(
            username=username,
            email=email,
            password=password,
            first_name=first_name,
            last_name=last_name
        )
        print("✓ Django User created")

        # Add user to group
        if group:
            user.groups.add(group)
            print(f"✓ User added to group: {group.name}")

        # Create user profile
        user_profile = form.save(commit=False)
        user_profile.user = user
        user_profile.save()
        print("✓ UserDetails profile created")

        # Verify creation
        created_user = User.objects.get(email=test_email)
        created_profile = created_user.profile
        user_groups = list(created_user.groups.values_list('name', flat=True))

        print("\n✅ User creation successful!")
        print(f"   Username: {created_user.username}")
        print(f"   Groups: {user_groups}")
        print(f"   Office: {created_profile.office_location}")
        print(f"   Role: {created_profile.role}")

        # Clean up
        created_user.delete()
        print("✓ Test user cleaned up")

        return True

    except Exception as e:
        print(f"❌ Error during user creation: {e}")
        import traceback
        traceback.print_exc()

        # Clean up on error
        if User.objects.filter(email=test_email).exists():
            User.objects.filter(email=test_email).delete()

        return False

def show_current_state():
    """Show current database state"""
    print("\n📊 Current Database State")
    print("=" * 50)

    # Groups
    groups = Group.objects.all().order_by('id')
    print(f"Groups ({groups.count()}):")
    for group in groups:
        user_count = group.user_set.count()
        print(f"  {group.id:2d}. {group.name:12s} ({user_count} users)")

    # Office Locations
    offices = OfficeLocation.objects.all().order_by('id')
    print(f"\nOffice Locations ({offices.count()}):")
    for office in offices:
        emp_count = office.employees.count() if hasattr(office, 'employees') else 0
        status = "Active" if office.is_active else "Inactive"
        print(f"  {office.id:2d}. {office.name:25s} - {office.city:10s} ({emp_count} employees) [{status}]")

    # Users with profiles
    total_users = User.objects.count()
    users_with_profiles = User.objects.filter(profile__isnull=False).count()
    print(f"\nUsers: {total_users} total, {users_with_profiles} with profiles")

def main():
    """Main test function"""
    print("🚀 Direct Form Testing Script")
    print("=" * 60)

    # Show current state
    show_current_state()

    # Run tests
    tests = [
        ("Form Initialization", test_create_form),
        ("Form Validation", test_form_validation),
        ("Update Form", test_update_form),
        ("Actual User Creation", test_actual_user_creation),
    ]

    results = {}

    for test_name, test_func in tests:
        try:
            print(f"\n{'='*20} {test_name} {'='*20}")
            results[test_name] = test_func()
        except Exception as e:
            print(f"❌ {test_name} crashed: {e}")
            results[test_name] = False

    # Summary
    print("\n" + "="*60)
    print("🎯 TEST RESULTS SUMMARY")
    print("="*60)

    passed = 0
    failed = 0

    for test_name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")
        if result:
            passed += 1
        else:
            failed += 1

    print(f"\nTotal: {passed} passed, {failed} failed")

    if failed == 0:
        print("\n🎉 All tests passed! Your user forms should work correctly.")
        print("\n🔧 To test in browser:")
        print("1. Run: python manage.py runserver")
        print("2. Visit: http://localhost:8000/profile/user/create/")
        print("3. Try creating a user with your existing groups")
    else:
        print(f"\n⚠️  {failed} test(s) failed. Check the errors above.")

    return 0 if failed == 0 else 1

if __name__ == "__main__":
    sys.exit(main())
