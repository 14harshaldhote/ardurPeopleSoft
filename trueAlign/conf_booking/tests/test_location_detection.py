import os
import sys
import json
import requests
from unittest.mock import patch, MagicMock

# Add the project root to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))

# Set up Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')

import django
django.setup()

from django.test import TestCase, RequestFactory
from django.contrib.auth import get_user_model
from django.contrib.sessions.middleware import SessionMiddleware
from trueAlign.models import OfficeLocation, Room
from trueAlign.conf_booking.utils import LocationDetector, LocationValidator
from trueAlign.conf_booking.views import detect_office_location

User = get_user_model()

class LocationDetectionTestCase(TestCase):
    def setUp(self):
        """Set up test data"""
        self.factory = RequestFactory()
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        # Create test office locations
        self.office_mumbai = OfficeLocation.objects.create(
            name='Mumbai Office',
            code='MUM',
            city='Mumbai',
            state='Maharashtra',
            address_line1='Test Address Mumbai',
            postal_code='400001',
            country='India',
            is_active=True
        )

        self.office_delhi = OfficeLocation.objects.create(
            name='Delhi Office',
            code='DEL',
            city='Delhi',
            state='Delhi',
            address_line1='Test Address Delhi',
            postal_code='110001',
            country='India',
            is_active=True
        )

        # Create test rooms
        self.room_mumbai = Room.objects.create(
            name='Mumbai Conference Room 1',
            office_location=self.office_mumbai,
            capacity=10,
            location='Floor 5',
            status=Room.RoomStatus.ACTIVE,
            room_type=Room.RoomType.CONFERENCE
        )

        self.room_delhi = Room.objects.create(
            name='Delhi Conference Room 1',
            office_location=self.office_delhi,
            capacity=8,
            location='Floor 3',
            status=Room.RoomStatus.ACTIVE,
            room_type=Room.RoomType.CONFERENCE
        )

    def get_request_with_session(self, method='GET', data=None):
        """Create a request with session"""
        if method == 'POST':
            request = self.factory.post('/test/', data=data, content_type='application/json')
        else:
            request = self.factory.get('/test/')

        request.user = self.user

        # Add session middleware
        middleware = SessionMiddleware()
        middleware.process_request(request)
        request.session.save()

        return request

    def test_coordinate_validation(self):
        """Test coordinate validation"""
        # Valid coordinates
        valid, lat, lon = LocationValidator.validate_coordinates(19.0760, 72.8777)
        self.assertTrue(valid)
        self.assertEqual(lat, 19.0760)
        self.assertEqual(lon, 72.8777)

        # Invalid coordinates
        valid, lat, lon = LocationValidator.validate_coordinates(100, 200)
        self.assertFalse(valid)
        self.assertIsNone(lat)
        self.assertIsNone(lon)

        # Invalid format
        valid, lat, lon = LocationValidator.validate_coordinates('invalid', 'invalid')
        self.assertFalse(valid)
        self.assertIsNone(lat)
        self.assertIsNone(lon)

    @patch('trueAlign.conf_booking.utils.requests.get')
    def test_get_city_from_coordinates_success(self, mock_get):
        """Test successful city detection from coordinates"""
        # Mock successful response
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

        self.assertIsNotNone(result)
        self.assertEqual(result['city'], 'Mumbai')
        self.assertEqual(result['state'], 'Maharashtra')
        self.assertEqual(result['country'], 'India')

    @patch('trueAlign.conf_booking.utils.requests.get')
    def test_get_city_from_coordinates_incomplete_data(self, mock_get):
        """Test city detection with incomplete data (missing state)"""
        # Mock response with only city, no state
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

        # Should return None because state is missing
        self.assertIsNone(result)

    @patch('trueAlign.conf_booking.utils.requests.get')
    def test_get_city_from_coordinates_api_error(self, mock_get):
        """Test city detection with API error"""
        # Mock API error
        mock_get.side_effect = requests.exceptions.RequestException("API Error")

        result = LocationDetector.get_city_from_coordinates(19.0760, 72.8777)

        self.assertIsNone(result)

    def test_find_matching_office_location_success(self):
        """Test successful office location matching"""
        # Test exact match
        office = LocationDetector.find_matching_office_location('Mumbai', 'Maharashtra')
        self.assertIsNotNone(office)
        self.assertEqual(office.id, self.office_mumbai.id)

        # Test case insensitive match
        office = LocationDetector.find_matching_office_location('mumbai', 'maharashtra')
        self.assertIsNotNone(office)
        self.assertEqual(office.id, self.office_mumbai.id)

        # Test partial match
        office = LocationDetector.find_matching_office_location('Mum', 'Maha')
        self.assertIsNotNone(office)
        self.assertEqual(office.id, self.office_mumbai.id)

    def test_find_matching_office_location_requires_both_city_and_state(self):
        """Test that office location matching requires both city and state"""
        # Test with only city
        office = LocationDetector.find_matching_office_location('Mumbai', None)
        self.assertIsNone(office)

        # Test with only state
        office = LocationDetector.find_matching_office_location(None, 'Maharashtra')
        self.assertIsNone(office)

        # Test with neither
        office = LocationDetector.find_matching_office_location(None, None)
        self.assertIsNone(office)

    def test_find_matching_office_location_no_match(self):
        """Test office location matching with no match"""
        office = LocationDetector.find_matching_office_location('NonExistent', 'NonExistent')
        self.assertIsNone(office)

    def test_get_rooms_for_location(self):
        """Test getting rooms for a location"""
        rooms_data = LocationDetector.get_rooms_for_location(self.office_mumbai)

        self.assertEqual(len(rooms_data), 1)
        self.assertEqual(rooms_data[0]['name'], 'Mumbai Conference Room 1')
        self.assertEqual(rooms_data[0]['capacity'], 10)
        self.assertEqual(rooms_data[0]['office_location']['id'], self.office_mumbai.id)

    def test_session_location_validation(self):
        """Test session-based location validation"""
        request = self.get_request_with_session('GET')

        # GET requests should be allowed
        self.assertTrue(LocationValidator.check_location_access_in_session(request))

        # POST requests should require verification
        request = self.get_request_with_session('POST')
        self.assertFalse(LocationValidator.is_location_verified_in_session(request))

        # Set location access
        LocationValidator.set_location_access_in_session(request, True)
        self.assertTrue(LocationValidator.is_location_verified_in_session(request))

    @patch('trueAlign.conf_booking.utils.LocationDetector.get_city_from_coordinates')
    def test_detect_office_location_view_success(self, mock_get_city):
        """Test the detect_office_location view with successful detection"""
        # Mock successful city detection
        mock_get_city.return_value = {
            'city': 'Mumbai',
            'state': 'Maharashtra',
            'country': 'India'
        }

        request_data = {
            'latitude': 19.0760,
            'longitude': 72.8777
        }

        request = self.get_request_with_session('POST', json.dumps(request_data))
        response = detect_office_location(request)

        self.assertEqual(response.status_code, 200)

        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['office_location']['city'], 'Mumbai')
        self.assertEqual(response_data['office_location']['state'], 'Maharashtra')
        self.assertGreater(len(response_data['rooms']), 0)

    @patch('trueAlign.conf_booking.utils.LocationDetector.get_city_from_coordinates')
    def test_detect_office_location_view_incomplete_data(self, mock_get_city):
        """Test the detect_office_location view with incomplete location data"""
        # Mock incomplete city detection (missing state)
        mock_get_city.return_value = None

        request_data = {
            'latitude': 19.0760,
            'longitude': 72.8777
        }

        request = self.get_request_with_session('POST', json.dumps(request_data))
        response = detect_office_location(request)

        self.assertEqual(response.status_code, 200)

        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Could not determine both city and state', response_data['message'])
        self.assertTrue(response_data['manual_selection'])

    @patch('trueAlign.conf_booking.utils.LocationDetector.get_city_from_coordinates')
    def test_detect_office_location_view_no_office_match(self, mock_get_city):
        """Test the detect_office_location view with no office location match"""
        # Mock successful city detection but no office match
        mock_get_city.return_value = {
            'city': 'NonExistent',
            'state': 'NonExistent',
            'country': 'India'
        }

        request_data = {
            'latitude': 19.0760,
            'longitude': 72.8777
        }

        request = self.get_request_with_session('POST', json.dumps(request_data))
        response = detect_office_location(request)

        self.assertEqual(response.status_code, 200)

        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('No office location found', response_data['message'])
        self.assertTrue(response_data['manual_selection'])

    def test_detect_office_location_view_invalid_coordinates(self):
        """Test the detect_office_location view with invalid coordinates"""
        request_data = {
            'latitude': 'invalid',
            'longitude': 'invalid'
        }

        request = self.get_request_with_session('POST', json.dumps(request_data))
        response = detect_office_location(request)

        self.assertEqual(response.status_code, 400)

        response_data = json.loads(response.content)
        self.assertFalse(response_data['success'])
        self.assertIn('Invalid coordinates', response_data['error'])

    def test_detect_office_location_view_get_request(self):
        """Test the detect_office_location view with GET request (manual selection)"""
        request = self.get_request_with_session('GET')
        response = detect_office_location(request)

        self.assertEqual(response.status_code, 200)

        response_data = json.loads(response.content)
        self.assertTrue(response_data['success'])
        self.assertIn('locations', response_data)
        self.assertEqual(len(response_data['locations']), 2)  # Mumbai and Delhi


def run_tests():
    """Run the location detection tests"""
    print("Running Location Detection Tests...")
    print("=" * 50)

    # Create test suite
    from django.test.utils import get_runner
    from django.conf import settings

    TestRunner = get_runner(settings)
    test_runner = TestRunner()

    # Run tests
    result = test_runner.run_tests(['trueAlign.conf_booking.tests.test_location_detection'])

    if result == 0:
        print("\n✅ All tests passed!")
    else:
        print(f"\n❌ {result} test(s) failed!")

    return result


if __name__ == '__main__':
    run_tests()
