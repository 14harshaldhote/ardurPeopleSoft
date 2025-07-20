#!/usr/bin/env python
"""
Simple test script for location detection functionality
Run this script to test the location detection system manually
"""

import os
import sys
import json
import django
import requests
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(__file__))

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from trueAlign.models import OfficeLocation, Room
from trueAlign.conf_booking.utils import LocationDetector, LocationValidator

def test_coordinate_validation():
    """Test coordinate validation"""
    print("Testing coordinate validation...")

    # Valid coordinates (Mumbai)
    valid, lat, lon = LocationValidator.validate_coordinates(19.0760, 72.8777)
    print(f"✓ Valid coordinates: {valid}, lat: {lat}, lon: {lon}")

    # Invalid coordinates
    valid, lat, lon = LocationValidator.validate_coordinates(100, 200)
    print(f"✓ Invalid coordinates: {valid}, should be False")

    # Invalid format
    valid, lat, lon = LocationValidator.validate_coordinates('invalid', 'invalid')
    print(f"✓ Invalid format: {valid}, should be False")

    print()

def test_city_detection_mock():
    """Test city detection with mock data"""
    print("Testing city detection with mock data...")

    # Mock successful response
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'address': {
                'city': 'Mumbai',
                'state': 'Maharashtra',
                'country': 'India'
            },
            'display_name': 'Mumbai, Maharashtra, India'
        }
        mock_get.return_value = mock_response

        result = LocationDetector.get_city_from_coordinates(19.0760, 72.8777)
        if result:
            print(f"✓ Successfully detected: {result['city']}, {result['state']}")
        else:
            print("✗ Failed to detect city and state")

    # Mock incomplete data (missing state)
    with patch('requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'address': {
                'city': 'Mumbai',
                'country': 'India'
                # Missing state
            },
            'display_name': 'Mumbai, India'
        }
        mock_get.return_value = mock_response

        result = LocationDetector.get_city_from_coordinates(19.0760, 72.8777)
        if result is None:
            print("✓ Correctly rejected incomplete data (missing state)")
        else:
            print("✗ Should have rejected incomplete data")

    print()

def test_office_location_matching():
    """Test office location matching"""
    print("Testing office location matching...")

    # Check if we have any office locations
    office_count = OfficeLocation.objects.filter(is_active=True).count()
    print(f"Found {office_count} active office locations")

    if office_count == 0:
        print("Creating test office locations...")

        # Create test office locations
        mumbai_office = OfficeLocation.objects.create(
            name='Mumbai Office',
            code='MUM',
            city='Mumbai',
            state='Maharashtra',
            address_line1='Test Address Mumbai',
            postal_code='400001',
            country='India',
            is_active=True
        )

        delhi_office = OfficeLocation.objects.create(
            name='Delhi Office',
            code='DEL',
            city='Delhi',
            state='Delhi',
            address_line1='Test Address Delhi',
            postal_code='110001',
            country='India',
            is_active=True
        )

        print(f"✓ Created test offices: {mumbai_office.name}, {delhi_office.name}")

    # Test exact match
    office = LocationDetector.find_matching_office_location('Mumbai', 'Maharashtra')
    if office:
        print(f"✓ Found office for Mumbai, Maharashtra: {office.name}")
    else:
        print("✗ No office found for Mumbai, Maharashtra")

    # Test case insensitive match
    office = LocationDetector.find_matching_office_location('mumbai', 'maharashtra')
    if office:
        print(f"✓ Case insensitive match works: {office.name}")
    else:
        print("✗ Case insensitive match failed")

    # Test requirement for both city and state
    office = LocationDetector.find_matching_office_location('Mumbai', None)
    if office is None:
        print("✓ Correctly rejected city-only match")
    else:
        print("✗ Should have rejected city-only match")

    office = LocationDetector.find_matching_office_location(None, 'Maharashtra')
    if office is None:
        print("✓ Correctly rejected state-only match")
    else:
        print("✗ Should have rejected state-only match")

    print()

def test_room_retrieval():
    """Test room retrieval for locations"""
    print("Testing room retrieval...")

    # Get first active office location
    office = OfficeLocation.objects.filter(is_active=True).first()
    if not office:
        print("No office locations available for testing")
        return

    # Check if office has rooms
    room_count = Room.objects.filter(office_location=office, status=Room.RoomStatus.ACTIVE).count()
    print(f"Office {office.name} has {room_count} active rooms")

    if room_count == 0:
        print("Creating test room...")
        test_room = Room.objects.create(
            name=f'{office.city} Conference Room 1',
            office_location=office,
            capacity=10,
            location='Floor 5',
            status=Room.RoomStatus.ACTIVE,
            room_type=Room.RoomType.CONFERENCE
        )
        print(f"✓ Created test room: {test_room.name}")

    # Test room retrieval
    rooms_data = LocationDetector.get_rooms_for_location(office)
    print(f"✓ Retrieved {len(rooms_data)} rooms for {office.name}")

    if rooms_data:
        room = rooms_data[0]
        print(f"  - Room: {room['name']}, Capacity: {room['capacity']}")

    print()

def test_real_api_call():
    """Test real API call to Nominatim (optional)"""
    print("Testing real API call (optional)...")

    try:
        # Test with Mumbai coordinates
        result = LocationDetector.get_city_from_coordinates(19.0760, 72.8777)
        if result:
            print(f"✓ Real API call successful: {result['city']}, {result['state']}")
        else:
            print("✗ Real API call failed or returned incomplete data")
    except Exception as e:
        print(f"⚠ Real API call failed (this is optional): {e}")

    print()

def run_all_tests():
    """Run all tests"""
    print("Location Detection System Tests")
    print("=" * 50)

    test_coordinate_validation()
    test_city_detection_mock()
    test_office_location_matching()
    test_room_retrieval()
    test_real_api_call()

    print("=" * 50)
    print("Test completed!")
    print()
    print("To test the full system:")
    print("1. Start the Django server: python manage.py runserver")
    print("2. Open conference booking page")
    print("3. Allow location access when prompted")
    print("4. Check if rooms are displayed based on detected location")

if __name__ == '__main__':
    run_all_tests()
