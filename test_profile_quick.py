#!/usr/bin/env python
"""
Quick test script to verify profile module fixes
"""
import os
import sys
import django

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.test import TestCase
from django.contrib.auth.models import User, Group
from trueAlign.models import UserDetails, OfficeLocation
from trueAlign.profile.forms import UserDetailsCreateForm

def test_form_validation():
    """Test form validation with required fields"""
    print("Testing form validation...")
    
    # Create test data
    office_location = OfficeLocation.objects.create(
        name="Test Office",
        city="Test City",
        state="Test State",
        is_active=True
    )
    group = Group.objects.create(name="TestEmployee")
    
    # Test form with all required fields
    form_data = {
        'first_name': 'John',
        'last_name': 'Doe',
        'email': 'john.doe.test@example.com',
        'password': 'Welcome@123',
        'group': group.id,
        'role': 'employee',
        'dob': '1990-01-01',
        'gender': 'Male',
        'contact_number_primary': '1234567890',
        'employee_type': 'full_time',
        'employment_status': 'active',
        'office_location': office_location.id,
        'hire_date': '2023-01-01'
    }
    
    form = UserDetailsCreateForm(data=form_data)
    
    if form.is_valid():
        print("✅ Form validation PASSED")
        return True
    else:
        print("❌ Form validation FAILED")
        print(f"Form errors: {form.errors}")
        return False

def test_user_creation():
    """Test UserDetails creation without duplicates"""
    print("Testing UserDetails creation...")
    
    try:
        # Create user
        user = User.objects.create_user(
            username="testuser123",
            email="testuser123@example.com",
            password="testpass123"
        )
        
        # Create UserDetails with get_or_create
        office_location = OfficeLocation.objects.first()
        user_details, created = UserDetails.objects.get_or_create(
            user=user,
            defaults={
                'office_location': office_location,
                'employment_status': 'active'
            }
        )
        
        print("✅ UserDetails creation PASSED")
        return True
        
    except Exception as e:
        print(f"❌ UserDetails creation FAILED: {e}")
        return False

if __name__ == "__main__":
    print("Running Profile Module Quick Tests...")
    print("=" * 50)
    
    results = []
    results.append(test_form_validation())
    results.append(test_user_creation())
    
    print("=" * 50)
    passed = sum(results)
    total = len(results)
    
    print(f"Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests PASSED!")
        sys.exit(0)
    else:
        print("⚠️  Some tests FAILED!")
        sys.exit(1)
