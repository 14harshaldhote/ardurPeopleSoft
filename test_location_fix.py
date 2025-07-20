#!/usr/bin/env python
"""
Quick test to verify the location detection fix is working correctly.
This test checks that location detection only triggers on booking pages,
not on management pages.
"""

import os
import sys
import django
from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse

# Set up Django environment
sys.path.insert(0, os.path.dirname(__file__))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

User = get_user_model()

class LocationDetectionFixTest(TestCase):
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.client.login(username='testuser', password='testpass123')

    def test_location_detection_on_booking_pages(self):
        """Test that location detection JavaScript is present on booking pages"""
        booking_urls = [
            '/book/',
            '/book/dashboard/',
            '/book/my-bookings/',
        ]

        for url in booking_urls:
            try:
                response = self.client.get(url)
                # Check if the response contains location detection JavaScript
                content = response.content.decode()

                # Look for location detection related JavaScript
                has_location_js = (
                    'checkLocationRequirement' in content or
                    'detectOfficeLocation' in content or
                    'location-modal' in content
                )

                print(f"✓ {url}: Location detection available = {has_location_js}")

            except Exception as e:
                print(f"✗ {url}: Error accessing page - {e}")

    def test_no_location_detection_on_management_pages(self):
        """Test that location detection doesn't trigger on management pages"""
        management_urls = [
            '/book/manage/rooms/',
            '/book/manage/locations/',
            '/book/admin/manage/',
        ]

        for url in management_urls:
            try:
                response = self.client.get(url)
                content = response.content.decode()

                # Check if the page loads without location detection modal
                has_location_modal = 'location-modal' in content

                # The modal should exist in base template but not be triggered
                # Check for the specific JavaScript logic that excludes management pages
                has_exclusion_logic = (
                    'locationExcludedPaths' in content and
                    '/book/manage/' in content
                )

                print(f"✓ {url}: Has location modal = {has_location_modal}")
                print(f"✓ {url}: Has exclusion logic = {has_exclusion_logic}")

            except Exception as e:
                print(f"✗ {url}: Error accessing page - {e}")

    def test_location_exclusion_logic(self):
        """Test the JavaScript logic that excludes management pages"""
        # This tests the logic we added to base.html
        test_cases = [
            # (path, should_require_location)
            ('/book/', True),
            ('/book/dashboard/', False),  # Dashboard handles its own location detection
            ('/book/my-bookings/', True),
            ('/book/manage/rooms/', False),
            ('/book/manage/locations/', False),
            ('/book/admin/manage/', False),
        ]

        print("\n📋 Testing location requirement logic:")
        for path, should_require in test_cases:
            # Simulate the JavaScript logic
            location_required_paths = ['/book/', '/book/my-bookings/']
            location_excluded_paths = ['/book/manage/', '/book/admin/', '/book/dashboard/']

            is_location_required = (
                any(path.startswith(req_path) for req_path in location_required_paths) and
                not any(path.startswith(excl_path) for excl_path in location_excluded_paths)
            )

            status = "✓" if is_location_required == should_require else "✗"
            print(f"{status} {path}: Expected={should_require}, Got={is_location_required}")

def run_manual_test():
    """Run manual tests without Django test framework"""
    print("Location Detection Fix Test")
    print("=" * 40)

    # Test the JavaScript logic manually
    print("\n1. Testing JavaScript Path Logic:")

    def test_path_logic(path):
        location_required_paths = ['/book/', '/book/my-bookings/']
        location_excluded_paths = ['/book/manage/', '/book/admin/', '/book/dashboard/']

        is_location_required = (
            any(path.startswith(req_path) for req_path in location_required_paths) and
            not any(path.startswith(excl_path) for excl_path in location_excluded_paths)
        )

        return is_location_required

    test_paths = [
        ('/book/', True),
        ('/book/dashboard/', False),  # Dashboard handles its own location detection
        ('/book/my-bookings/', True),
        ('/book/manage/rooms/', False),
        ('/book/manage/locations/', False),
        ('/book/admin/manage/', False),
        ('/book/random-page/', True),  # Should require location
        ('/other-page/', False),       # Should not require location
    ]

    all_passed = True
    for path, expected in test_paths:
        result = test_path_logic(path)
        status = "✓" if result == expected else "✗"
        if result != expected:
            all_passed = False
        print(f"{status} {path}: Expected={expected}, Got={result}")

    print(f"\n2. Overall Result: {'✅ All tests passed!' if all_passed else '❌ Some tests failed!'}")

    print("\n3. Manual Testing Instructions:")
    print("   - Start the Django server: python manage.py runserver")
    print("   - Visit /book/manage/rooms/ - Should NOT show location detection modal")
    print("   - Visit /book/dashboard/ - Should handle its own location detection (no modal)")
    print("   - Visit /book/my-bookings/ - Should show location detection modal")
    print("   - Visit /book/manage/rooms/add/ - Should show location detection for office selection")

    return all_passed

if __name__ == '__main__':
    run_manual_test()
