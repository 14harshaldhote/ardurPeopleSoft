#!/usr/bin/env python3
"""
Test script to verify the profile fix functionality
"""

import os
import sys
import django
from django.conf import settings

# Add the project directory to the path
sys.path.append('/Users/harshalsmac/WORK/ardur/ardurHome')

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User, Group
from trueAlign.models import UserDetails
from django.test import Client
from django.urls import reverse
import json

def test_profile_functionality():
    """Test the complete profile functionality"""
    print("🧪 Testing Profile Fix Functionality")
    print("=" * 50)

    try:
        # Test 1: Check if all users have profiles
        print("\n📋 Test 1: Checking user profiles...")
        users = User.objects.all()
        users_without_profiles = []

        for user in users:
            try:
                profile = UserDetails.objects.get(user=user)
                print(f"  ✅ {user.username} has profile with role: {profile.get_role_display()}")
            except UserDetails.DoesNotExist:
                users_without_profiles.append(user)
                print(f"  ❌ {user.username} missing profile")

        if users_without_profiles:
            print(f"\n⚠️  Found {len(users_without_profiles)} users without profiles!")
            return False
        else:
            print(f"\n✅ All {users.count()} users have profiles!")

        # Test 2: Test profile page access
        print("\n📋 Test 2: Testing profile page access...")
        client = Client()

        # Get a test user
        test_user = User.objects.filter(username='adminTest').first()
        if not test_user:
            test_user = User.objects.first()

        # Login the user
        client.force_login(test_user)

        # Test profile page
        try:
            response = client.get('/profile/my-profile/')
            if response.status_code == 200:
                print(f"  ✅ Profile page accessible for {test_user.username}")

                # Check if page contains profile information
                content = response.content.decode()
                if "Profile Not Found" in content:
                    print("  ❌ Profile page still shows 'Profile Not Found'")
                    return False
                elif test_user.username in content:
                    print("  ✅ Profile page displays user information correctly")
                else:
                    print("  ⚠️  Profile page loaded but content unclear")

            else:
                print(f"  ❌ Profile page returned status code: {response.status_code}")
                return False

        except Exception as e:
            print(f"  ❌ Error accessing profile page: {str(e)}")
            return False

        # Test 3: Test profile creation for new user
        print("\n📋 Test 3: Testing automatic profile creation...")

        # Create a test user
        test_username = 'profile_test_user'

        # Clean up any existing test user
        User.objects.filter(username=test_username).delete()

        # Create new user
        new_user = User.objects.create_user(
            username=test_username,
            email='test@example.com',
            first_name='Test',
            last_name='User'
        )

        # Check if profile was created automatically
        try:
            profile = UserDetails.objects.get(user=new_user)
            print(f"  ✅ Profile automatically created for new user with role: {profile.get_role_display()}")
        except UserDetails.DoesNotExist:
            print("  ❌ Profile was not automatically created for new user")
            # Clean up
            new_user.delete()
            return False

        # Test profile page for new user
        client.force_login(new_user)
        response = client.get('/profile/my-profile/')

        if response.status_code == 200:
            content = response.content.decode()
            if "Profile Not Found" not in content:
                print("  ✅ New user can access profile page without issues")
            else:
                print("  ❌ New user still sees 'Profile Not Found'")
                new_user.delete()
                return False
        else:
            print(f"  ❌ New user profile page returned status: {response.status_code}")
            new_user.delete()
            return False

        # Clean up test user
        new_user.delete()

        # Test 4: Check profile data completeness
        print("\n📋 Test 4: Checking profile data completeness...")
        sample_profiles = UserDetails.objects.all()[:5]

        for profile in sample_profiles:
            user = profile.user
            completeness_score = 0
            total_fields = 10

            # Check key fields
            if profile.role: completeness_score += 1
            if profile.employee_type: completeness_score += 1
            if profile.employment_status: completeness_score += 1
            if profile.personal_email or user.email: completeness_score += 1
            if user.first_name: completeness_score += 1
            if user.last_name: completeness_score += 1
            if profile.contact_number_primary: completeness_score += 1
            if profile.dob: completeness_score += 1
            if profile.current_address_line1: completeness_score += 1
            if profile.emergency_contact_name: completeness_score += 1

            percentage = (completeness_score / total_fields) * 100
            print(f"  📊 {user.username}: {completeness_score}/{total_fields} fields ({percentage:.0f}% complete)")

        print("\n🎉 All tests passed successfully!")
        print("\n📝 Summary:")
        print(f"  • Total users: {User.objects.count()}")
        print(f"  • Users with profiles: {UserDetails.objects.count()}")
        print(f"  • Profile page accessibility: ✅")
        print(f"  • Automatic profile creation: ✅")
        print(f"  • Template functionality: ✅")

        return True

    except Exception as e:
        print(f"\n❌ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

def show_user_roles():
    """Display all users and their roles"""
    print("\n👥 Current User Roles:")
    print("-" * 30)

    users = User.objects.all().order_by('username')
    for user in users:
        try:
            profile = UserDetails.objects.get(user=user)
            role = profile.get_role_display()
            status = profile.employment_status
            print(f"  {user.username:15} | {role:15} | {status}")
        except UserDetails.DoesNotExist:
            print(f"  {user.username:15} | {'NO PROFILE':15} | {'UNKNOWN'}")

if __name__ == "__main__":
    print("🚀 Profile Fix Verification Script")
    print("=" * 50)

    # Show current state
    show_user_roles()

    # Run tests
    success = test_profile_functionality()

    if success:
        print("\n✅ Profile fix verification completed successfully!")
        print("💡 Users should now be able to access their profiles without issues.")
    else:
        print("\n❌ Profile fix verification failed!")
        print("💡 Please check the errors above and fix them.")

    print("\n🔗 Next steps:")
    print("  1. Test by logging in as different users")
    print("  2. Navigate to /profile/my-profile/")
    print("  3. Verify profile information displays correctly")
    print("  4. Test password reset functionality")
