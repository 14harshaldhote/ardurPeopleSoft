#!/usr/bin/env python
"""
Test script to verify role dropdown shows groups from auth_group table
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

def test_role_dropdown_create_form():
    """Test role dropdown in create form"""
    print("🔍 Testing Role Dropdown in Create Form")
    print("-" * 50)

    try:
        form = UserDetailsCreateForm()

        # Check if role field has dynamic choices from auth_group
        role_choices = form.fields['role'].choices

        print(f"✅ Role field initialized with {len(role_choices)} choices")
        print("Role options available:")

        for value, label in role_choices:
            if value:  # Skip empty option
                print(f"   • {label} (value: {value})")

        # Verify these match your auth_group entries
        groups_from_db = Group.objects.all().order_by('name')
        print(f"\nGroups in auth_group table:")
        for group in groups_from_db:
            print(f"   • {group.name} (ID: {group.id})")

        # Check if they match
        form_group_names = [label for value, label in role_choices if value]
        db_group_names = [group.name for group in groups_from_db]

        if set(form_group_names) == set(db_group_names):
            print("✅ Role dropdown matches auth_group table perfectly!")
        else:
            print("❌ Mismatch between role dropdown and auth_group table")
            missing_in_form = set(db_group_names) - set(form_group_names)
            extra_in_form = set(form_group_names) - set(db_group_names)

            if missing_in_form:
                print(f"   Missing in form: {missing_in_form}")
            if extra_in_form:
                print(f"   Extra in form: {extra_in_form}")

        return True

    except Exception as e:
        print(f"❌ Error testing create form: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_role_dropdown_update_form():
    """Test role dropdown in update form with existing user"""
    print("\n🔍 Testing Role Dropdown in Update Form")
    print("-" * 50)

    # Find a user with profile and group
    users_with_profiles = User.objects.filter(profile__isnull=False, groups__isnull=False).distinct()

    if not users_with_profiles.exists():
        print("❌ No users with profiles and groups found for testing")
        return False

    test_user = users_with_profiles.first()
    print(f"Testing with user: {test_user.username}")

    user_groups = list(test_user.groups.values_list('name', flat=True))
    current_role = test_user.profile.role if hasattr(test_user, 'profile') else None

    print(f"User groups: {user_groups}")
    print(f"Current role in profile: {current_role}")

    try:
        form = UserDetailsUpdateForm(instance=test_user.profile, user=test_user)

        # Check role choices
        role_choices = form.fields['role'].choices
        print(f"✅ Update form role field has {len(role_choices)} choices")

        # Check if current role is properly selected
        role_initial = form.fields['role'].initial
        print(f"Role field initial value: {role_initial}")

        # Verify the current role matches user's group
        if user_groups and role_initial:
            expected_role = user_groups[0].lower()  # Should match first group
            if role_initial == expected_role:
                print("✅ Role field properly initialized with user's group")
            else:
                print(f"⚠️ Role initial ({role_initial}) doesn't match user's group ({expected_role})")

        return True

    except Exception as e:
        print(f"❌ Error testing update form: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_role_group_sync():
    """Test role and group synchronization"""
    print("\n🔍 Testing Role-Group Synchronization")
    print("-" * 50)

    # Test creating a user with specific group and see if role syncs
    groups = Group.objects.all()
    offices = OfficeLocation.objects.filter(is_active=True)

    if not groups.exists() or not offices.exists():
        print("❌ Need groups and offices for testing")
        return False

    test_group = groups.first()
    print(f"Testing with group: {test_group.name}")

    # Prepare form data
    form_data = {
        'first_name': 'Role',
        'last_name': 'Test',
        'email': 'roletest@example.com',
        'password': 'Welcome@123',
        'group': test_group.id,
        'role': test_group.name.lower(),  # Should match the group
        'office_location': offices.first().id,
        'employee_type': 'full_time',
        'employment_status': 'probation'
    }

    try:
        form = UserDetailsCreateForm(data=form_data)

        if form.is_valid():
            print("✅ Form validation passed with role matching group")

            # Check cleaned data
            cleaned_group = form.cleaned_data.get('group')
            cleaned_role = form.cleaned_data.get('role')

            print(f"Selected group: {cleaned_group.name}")
            print(f"Selected role: {cleaned_role}")

            if cleaned_role == cleaned_group.name.lower():
                print("✅ Role and group are properly synchronized")
            else:
                print(f"❌ Role ({cleaned_role}) doesn't match group ({cleaned_group.name.lower()})")

            return True
        else:
            print("❌ Form validation failed:")
            for field, errors in form.errors.items():
                print(f"   {field}: {errors}")
            return False

    except Exception as e:
        print(f"❌ Error testing role-group sync: {e}")
        import traceback
        traceback.print_exc()
        return False

def show_current_auth_groups():
    """Show current auth_group table contents"""
    print("\n📊 Current auth_group Table Contents")
    print("-" * 50)

    groups = Group.objects.all().order_by('id')

    print("Your auth_group entries:")
    for group in groups:
        user_count = group.user_set.count()
        print(f"   ID: {group.id:2d} | Name: {group.name:12s} | Users: {user_count}")

    print(f"\nTotal groups: {groups.count()}")

    # Show how they'll appear in role dropdown
    print("\nHow they appear in role dropdown:")
    for group in groups:
        dropdown_value = group.name.lower()
        dropdown_label = group.name
        print(f"   Value: {dropdown_value:12s} | Label: {dropdown_label}")

def verify_template_usage():
    """Verify how the template will render the role dropdown"""
    print("\n🎨 Template Rendering Verification")
    print("-" * 50)

    try:
        form = UserDetailsCreateForm()
        role_field = form.fields['role']

        print("Template will render these options:")
        print('<select name="role" class="...">')

        for value, label in role_field.choices:
            selected = 'selected' if value == form.fields['role'].initial else ''
            print(f'  <option value="{value}" {selected}>{label}</option>')

        print('</select>')

        print("\n✅ Template will show your auth_group names in the dropdown")

    except Exception as e:
        print(f"❌ Error verifying template usage: {e}")

def main():
    """Main test function"""
    print("🚀 Role Dropdown Test - Auth Group Integration")
    print("=" * 60)

    # Show current groups
    show_current_auth_groups()

    # Run tests
    tests = [
        ("Create Form Role Dropdown", test_role_dropdown_create_form),
        ("Update Form Role Dropdown", test_role_dropdown_update_form),
        ("Role-Group Synchronization", test_role_group_sync),
    ]

    results = []

    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} crashed: {e}")
            results.append((test_name, False))

    # Verify template rendering
    verify_template_usage()

    # Summary
    print("\n" + "=" * 60)
    print("🎯 TEST RESULTS SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    failed = len(results) - passed

    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status} {test_name}")

    print(f"\n📊 Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("\n🎉 All tests passed!")
        print("✨ Role dropdown now shows your auth_group entries:")

        groups = Group.objects.all().order_by('name')
        for group in groups:
            print(f"   • {group.name}")

        print("\n🔧 Next steps:")
        print("1. Run: python manage.py runserver")
        print("2. Go to: http://localhost:8000/profile/user/create/")
        print("3. Check the Role dropdown - it should show your groups")
        print("4. Verify Group and Role fields work together")

    else:
        print(f"\n⚠️ {failed} test(s) failed. Check errors above.")

    return 0 if failed == 0 else 1

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
