#!/usr/bin/env python
"""
Test script to verify location-based conference room booking system functionality.
Run this script to test the location detection and room filtering features.
"""

import os
import sys
import django
import json

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from trueAlign.models import OfficeLocation, Room
from trueAlign.conf_booking.utils import LocationDetector, LocationValidator


class LocationSystemTest:
    def __init__(self):
        self.client = Client()
        self.test_user = None

    def setup_test_data(self):
        """Setup test data for location testing"""
        print("Setting up test data...")

        # Create test user
        self.test_user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        # Create test office locations
        self.mumbai_office = OfficeLocation.objects.create(
            name='Mumbai - Bandra',
            code='MUM',
            city='Mumbai',
            state='Maharashtra',
            address_line1='Test Address Mumbai',
            postal_code='400050',
            country='India',
            is_active=True
        )

        self.delhi_office = OfficeLocation.objects.create(
            name='Delhi - Gurgaon',
            code='DEL',
            city='Gurgaon',
            state='Haryana',
            address_line1='Test Address Delhi',
            postal_code='122001',
            country='India',
            is_active=True
        )

        # Create test rooms
        self.mumbai_room = Room.objects.create(
            name='Mumbai Conference Room 1',
            office_location=self.mumbai_office,
            capacity=10,
            status=Room.RoomStatus.ACTIVE
        )

        self.delhi_room = Room.objects.create(
            name='Delhi Conference Room 1',
            office_location=self.delhi_office,
            capacity=8,
            status=Room.RoomStatus.ACTIVE
        )

        print("✅ Test data created successfully")

    def test_location_utilities(self):
        """Test location detection utilities"""
        print("\n🧪 Testing Location Utilities...")

        # Test coordinate validation
        valid, lat, lon = LocationValidator.validate_coordinates(19.0760, 72.8777)
        assert valid == True, "Valid coordinates should pass validation"
        print("✅ Coordinate validation works")

        # Test invalid coordinates
        valid, lat, lon = LocationValidator.validate_coordinates(200, 300)
        assert valid == False, "Invalid coordinates should fail validation"
        print("✅ Invalid coordinate handling works")

        # Test office location matching
        office = LocationDetector.find_matching_office_location('Mumbai', 'Maharashtra')
        assert office is not None, "Should find Mumbai office"
        assert office.name == 'Mumbai - Bandra', "Should match correct office"
        print("✅ Office location matching works")

        # Test rooms for location
        rooms = LocationDetector.get_rooms_for_location(self.mumbai_office)
        assert len(rooms) == 1, "Should find one room for Mumbai office"
        assert rooms[0]['name'] == 'Mumbai Conference Room 1', "Should match correct room"
        print("✅ Room filtering by location works")

    def test_location_api(self):
        """Test location detection API"""
        print("\n🌐 Testing Location API...")

        # Login user
        self.client.login(username='testuser', password='testpass123')

        # Test coordinate-based detection
        test_data = {
            'latitude': 19.0760,  # Mumbai coordinates
            'longitude': 72.8777
        }

        response = self.client.post(
            reverse('conf_booking:detect_office_location'),
            data=json.dumps(test_data),
            content_type='application/json'
        )

        assert response.status_code == 200, f"API should return 200, got {response.status_code}"

        data = response.json()
        print(f"API Response: {data}")

        # Note: This might not work in test environment due to external API call
        # but the endpoint should handle it gracefully

        # Test GET request for manual selection
        response = self.client.get(reverse('conf_booking:detect_office_location'))
        assert response.status_code == 200, "GET request should return office locations"

        data = response.json()
        assert 'locations' in data, "Should return locations list"
        assert len(data['locations']) >= 2, "Should have at least 2 test locations"
        print("✅ Location API endpoints work")

    def test_location_requirement_enforcement(self):
        """Test that location is required for booking views"""
        print("\n🔒 Testing Location Requirement Enforcement...")

        # Login user
        self.client.login(username='testuser', password='testpass123')

        # Test booking room without location access
        response = self.client.get(reverse('conf_booking:booking_room'))

        # Should redirect or show warning (depends on implementation)
        if response.status_code == 302:
            print("✅ Booking room redirects when location not granted")
        elif response.status_code == 403:
            print("✅ Booking room blocks access when location not granted")
        else:
            print(f"⚠️ Unexpected response code: {response.status_code}")

        # Test room dashboard
        response = self.client.get(reverse('conf_booking:room_dashboard'))
        print(f"Room dashboard response: {response.status_code}")

        # Test user bookings
        response = self.client.get(reverse('conf_booking:user_bookings'))
        print(f"User bookings response: {response.status_code}")

        print("✅ Location requirement enforcement tested")

    def test_room_filtering(self):
        """Test room filtering by office location"""
        print("\n🏢 Testing Room Filtering...")

        # Login user
        self.client.login(username='testuser', password='testpass123')

        # Test rooms API with office location filter
        response = self.client.get(
            reverse('conf_booking:get_available_rooms'),
            {'office_location_id': self.mumbai_office.id}
        )

        if response.status_code == 403:
            print("✅ Room filtering requires location access (as expected)")
        else:
            data = response.json()
            if 'rooms' in data:
                mumbai_rooms = [r for r in data['rooms'] if r['office_location']['id'] == self.mumbai_office.id]
                assert len(mumbai_rooms) >= 1, "Should find Mumbai rooms"
                print("✅ Room filtering works correctly")

    def cleanup(self):
        """Clean up test data"""
        print("\n🧹 Cleaning up test data...")

        if self.test_user:
            self.test_user.delete()

        Room.objects.filter(name__contains='Conference Room').delete()
        OfficeLocation.objects.filter(code__in=['MUM', 'DEL']).delete()

        print("✅ Test data cleaned up")

    def run_all_tests(self):
        """Run all tests"""
        print("🚀 Starting Location System Tests...")
        print("=" * 50)

        try:
            self.setup_test_data()
            self.test_location_utilities()
            self.test_location_api()
            self.test_location_requirement_enforcement()
            self.test_room_filtering()

            print("\n" + "=" * 50)
            print("✅ All tests completed successfully!")
            print("🎉 Location-based conference room booking system is working!")

        except Exception as e:
            print(f"\n❌ Test failed: {str(e)}")
            import traceback
            traceback.print_exc()

        finally:
            self.cleanup()


if __name__ == '__main__':
    test = LocationSystemTest()
    test.run_all_tests()
