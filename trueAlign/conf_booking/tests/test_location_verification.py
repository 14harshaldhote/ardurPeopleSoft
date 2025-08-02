"""
Tests for location verification and conference booking functionality.
"""
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from django.test import TestCase, Client
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from django.contrib.sessions.models import Session

from trueAlign.models import Room, OfficeLocation, ConferenceBooking, UserDetails
from trueAlign.conf_booking.utils import LocationValidator, LocationDetector

User = get_user_model()


class LocationVerificationTestCase(TestCase):
    """Test location verification functionality."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            first_name='Test',
            last_name='User'
        )
        
        # Create office location
        self.office_location = OfficeLocation.objects.create(
            name='Test Office',
            code='TST',
            address_line1='123 Test St',
            city='Mumbai',
            state='Maharashtra',
            postal_code='400001',
            country='India',
            is_active=True
        )
        
        # Create room
        self.room = Room.objects.create(
            name='Test Room',
            office_location=self.office_location,
            room_type='CONFERENCE',
            capacity=10,
            location='First Floor',
            facilities='Projector, Whiteboard',
            hourly_rate=100.0,
            status=Room.RoomStatus.ACTIVE
        )
        
        # Create user profile with office location
        self.user_profile = UserDetails.objects.create(
            user=self.user,
            office_location=self.office_location,
            role='developer',
            employee_type='full_time',
            employment_status='active'
        )
        
        # Login user
        self.client.login(username='testuser', password='testpass123')
    
    def test_location_validator_session_check(self):
        """Test LocationValidator session checking functionality."""
        # Test with no session variable set
        session = self.client.session
        session['location_access_granted'] = False
        session.save()
        
        request = MagicMock()
        request.session = session
        request.method = 'POST'
        
        # Should return False for POST requests without verification
        self.assertFalse(LocationValidator.is_location_verified_in_session(request))
        
        # Set location access granted
        session['location_access_granted'] = True
        session.save()
        
        request.session = session
        
        # Should return True when location is verified
        self.assertTrue(LocationValidator.is_location_verified_in_session(request))
    
    def test_location_validator_set_access(self):
        """Test setting location access in session."""
        request = MagicMock()
        request.session = {}
        
        # Set location access
        LocationValidator.set_location_access_in_session(request, True)
        
        self.assertTrue(request.session['location_access_granted'])
        
        # Set location access to False
        LocationValidator.set_location_access_in_session(request, False)
        
        self.assertFalse(request.session['location_access_granted'])
    
    def test_coordinate_validation(self):
        """Test coordinate validation."""
        # Valid coordinates
        valid, lat, lon = LocationValidator.validate_coordinates(19.0760, 72.8777)
        self.assertTrue(valid)
        self.assertEqual(lat, 19.0760)
        self.assertEqual(lon, 72.8777)
        
        # Invalid coordinates (out of range)
        valid, lat, lon = LocationValidator.validate_coordinates(95.0, 185.0)
        self.assertFalse(valid)
        self.assertIsNone(lat)
        self.assertIsNone(lon)
        
        # Invalid coordinates (non-numeric)
        valid, lat, lon = LocationValidator.validate_coordinates('invalid', 'invalid')
        self.assertFalse(valid)
        self.assertIsNone(lat)
        self.assertIsNone(lon)
    
    @patch('requests.get')
    def test_location_detection_success(self, mock_get):
        """Test successful location detection from coordinates."""
        # Mock successful API response
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
        
        # Test location detection
        location_data = LocationDetector.get_city_from_coordinates(19.0760, 72.8777)
        
        self.assertIsNotNone(location_data)
        self.assertEqual(location_data['city'], 'Mumbai')
        self.assertEqual(location_data['state'], 'Maharashtra')
        self.assertEqual(location_data['country'], 'India')
    
    @patch('requests.get')
    def test_location_detection_incomplete_data(self, mock_get):
        """Test location detection with incomplete data."""
        # Mock API response with missing state
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'address': {
                'city': 'Mumbai',
                # Missing state
                'country': 'India'
            },
            'display_name': 'Mumbai, India'
        }
        mock_get.return_value = mock_response
        
        # Should return None when city or state is missing
        location_data = LocationDetector.get_city_from_coordinates(19.0760, 72.8777)
        self.assertIsNone(location_data)
    
    def test_find_matching_office_location(self):
        """Test finding matching office location."""
        # Test exact match
        office = LocationDetector.find_matching_office_location('Mumbai', 'Maharashtra')
        self.assertEqual(office, self.office_location)
        
        # Test case insensitive match
        office = LocationDetector.find_matching_office_location('mumbai', 'maharashtra')
        self.assertEqual(office, self.office_location)
        
        # Test no match
        office = LocationDetector.find_matching_office_location('Delhi', 'Delhi')
        self.assertIsNone(office)
        
        # Test with missing parameters
        office = LocationDetector.find_matching_office_location('Mumbai', None)
        self.assertIsNone(office)
        
        office = LocationDetector.find_matching_office_location(None, 'Maharashtra')
        self.assertIsNone(office)
    
    def test_get_rooms_for_location(self):
        """Test getting rooms for a specific location."""
        rooms_data = LocationDetector.get_rooms_for_location(self.office_location)
        
        self.assertEqual(len(rooms_data), 1)
        room_data = rooms_data[0]
        
        self.assertEqual(room_data['id'], self.room.id)
        self.assertEqual(room_data['name'], self.room.name)
        self.assertEqual(room_data['capacity'], self.room.capacity)
        self.assertEqual(room_data['office_location']['id'], self.office_location.id)
    
    @patch('trueAlign.conf_booking.utils.LocationDetector.get_city_from_coordinates')
    def test_detect_office_location_api_success(self, mock_get_city):
        """Test the detect office location API endpoint with successful detection."""
        # Mock location detection
        mock_get_city.return_value = {
            'city': 'Mumbai',
            'state': 'Maharashtra',
            'country': 'India'
        }
        
        url = reverse('conf_booking:detect_office_location')
        data = {
            'latitude': 19.0760,
            'longitude': 72.8777
        }
        
        response = self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        
        self.assertTrue(response_data['success'])
        # Validate using retrieved office location
        detected_office_id = response_data['office_location']['id']
        detected_office = OfficeLocation.objects.get(id=detected_office_id)
        self.assertEqual(detected_office, self.office_location)
        self.assertEqual(response_data['office_location']['name'], self.office_location.name)
        self.assertEqual(len(response_data['rooms']), 1)
        
        # Check that session is set
        session = self.client.session
        self.assertTrue(session.get('location_access_granted', False))
    
    @patch('trueAlign.conf_booking.utils.LocationDetector.get_city_from_coordinates')
    def test_detect_office_location_api_no_match(self, mock_get_city):
        """Test the detect office location API endpoint with no matching office."""
        # Mock location detection for a city with no office
        mock_get_city.return_value = {
            'city': 'Delhi',
            'state': 'Delhi',
            'country': 'India'
        }
        
        url = reverse('conf_booking:detect_office_location')
        data = {
            'latitude': 28.6139,
            'longitude': 77.2090
        }
        
        response = self.client.post(
            url,
            data=json.dumps(data),
            content_type='application/json'
        )
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        
        self.assertFalse(response_data['success'])
        self.assertIn('No office location found', response_data['message'])
        self.assertTrue(response_data['manual_selection'])
    
    def test_detect_office_location_get_request(self):
        """Test GET request to detect office location endpoint returns all locations."""
        url = reverse('conf_booking:detect_office_location')
        
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        
        self.assertTrue(response_data['success'])
        self.assertEqual(len(response_data['locations']), 1)
        self.assertEqual(response_data['locations'][0]['id'], self.office_location.id)
    
    def test_booking_without_location_verification(self):
        """Test that booking fails without location verification."""
        url = reverse('conf_booking:booking_room')
        
        # Ensure no location verification in session
        session = self.client.session
        session['location_access_granted'] = False
        session.save()
        
        booking_data = {
            'room': self.room.id,
            'purpose': 'Test Meeting',
            'description': 'Test Description',
            'start_time': (timezone.now() + timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M'),
            'end_time': (timezone.now() + timedelta(hours=2)).strftime('%Y-%m-%dT%H:%M'),
            'attendees_count': 5,
            'external_attendees': 0,
            'meeting_type': 'INTERNAL',
            'priority': 'MEDIUM'
        }
        
        response = self.client.post(url, booking_data)
        
        # Should redirect back to dashboard with warning message
        self.assertEqual(response.status_code, 302)
        
        # No booking should be created
        self.assertEqual(ConferenceBooking.objects.count(), 0)
    
    def test_booking_with_location_verification(self):
        """Test that booking succeeds with location verification."""
        url = reverse('conf_booking:booking_room')
        
        # Set location verification in session
        session = self.client.session
        session['location_access_granted'] = True
        session.save()
        
        # Use timezone-aware future time
        now = timezone.now()
        start_time = now + timedelta(hours=2)  # 2 hours from now
        end_time = now + timedelta(hours=3)    # 3 hours from now
        
        booking_data = {
            'room': self.room.id,
            'purpose': 'Test Meeting',
            'description': 'Test Description',
            'start_time': start_time.strftime('%Y-%m-%dT%H:%M'),
            'end_time': end_time.strftime('%Y-%m-%dT%H:%M'),
            'attendees_count': 5,
            'external_attendees': 0,
            'meeting_type': 'INTERNAL',
            'priority': 'MEDIUM'
        }
        
        response = self.client.post(url, booking_data)
        
        # Should redirect back to dashboard
        self.assertEqual(response.status_code, 302)
        
        # Booking should be created
        self.assertEqual(ConferenceBooking.objects.count(), 1)
        
        booking = ConferenceBooking.objects.first()
        self.assertEqual(booking.room, self.room)
        self.assertEqual(booking.booked_by, self.user)
        self.assertEqual(booking.purpose, 'Test Meeting')
        self.assertEqual(booking.attendees_count, 5)
    
    def test_booking_working_hours_removed(self):
        """Test that working hours restriction has been removed."""
        url = reverse('conf_booking:booking_room')
        
        # Set location verification in session
        session = self.client.session
        session['location_access_granted'] = True
        session.save()
        
        # Test booking at night (outside traditional working hours)
        tomorrow = timezone.now().replace(hour=22, minute=0, second=0, microsecond=0) + timedelta(days=1)
        start_time = tomorrow
        end_time = tomorrow + timedelta(hours=2)  # Until midnight
        
        booking_data = {
            'room': self.room.id,
            'purpose': 'Night Shift Meeting',
            'description': 'Night shift coordination meeting',
            'start_time': start_time.strftime('%Y-%m-%dT%H:%M'),
            'end_time': end_time.strftime('%Y-%m-%dT%H:%M'),
            'attendees_count': 3,
            'external_attendees': 0,
            'meeting_type': 'INTERNAL',
            'priority': 'MEDIUM'
        }
        
        response = self.client.post(url, booking_data)
        
        # Should succeed (redirect back to dashboard)
        self.assertEqual(response.status_code, 302)
        
        # Booking should be created successfully
        self.assertEqual(ConferenceBooking.objects.count(), 1)
        
        booking = ConferenceBooking.objects.first()
        self.assertEqual(booking.purpose, 'Night Shift Meeting')
        self.assertEqual(booking.start_time.hour, 22)  # Should be 10 PM
    
    def test_booking_weekend_restriction_still_active(self):
        """Test that weekend restriction is still in place."""
        url = reverse('conf_booking:booking_room')
        
        # Set location verification in session
        session = self.client.session
        session['location_access_granted'] = True
        session.save()
        
        # Find next Saturday
        now = timezone.now()
        days_ahead = 5 - now.weekday()  # Saturday is 5
        if days_ahead <= 0:  # Target day already happened this week
            days_ahead += 7
        
        saturday = now + timedelta(days=days_ahead)
        start_time = saturday.replace(hour=10, minute=0, second=0, microsecond=0)
        end_time = start_time + timedelta(hours=1)
        
        booking_data = {
            'room': self.room.id,
            'purpose': 'Weekend Meeting',
            'description': 'Weekend meeting',
            'start_time': start_time.strftime('%Y-%m-%dT%H:%M'),
            'end_time': end_time.strftime('%Y-%m-%dT%H:%M'),
            'attendees_count': 3,
            'external_attendees': 0,
            'meeting_type': 'INTERNAL',
            'priority': 'MEDIUM'
        }
        
        response = self.client.post(url, booking_data)
        
        # Should still redirect (form validation happens on frontend)
        self.assertEqual(response.status_code, 302)
        
        # No booking should be created due to weekend restriction
        self.assertEqual(ConferenceBooking.objects.count(), 0)
    
    def test_get_rooms_by_location_api(self):
        """Test the get rooms by location API endpoint."""
        url = reverse('conf_booking:get_rooms_by_location')
        
        response = self.client.get(url, {'location': self.office_location.id})
        
        self.assertEqual(response.status_code, 200)
        response_data = response.json()
        
        self.assertTrue(response_data['success'])
        self.assertEqual(response_data['office_location']['id'], self.office_location.id)
        self.assertEqual(len(response_data['rooms']), 1)
        
        # Check that session is set
        session = self.client.session
        self.assertTrue(session.get('location_access_granted', False))
    
    def test_get_rooms_by_location_api_invalid_location(self):
        """Test the get rooms by location API with invalid location ID."""
        url = reverse('conf_booking:get_rooms_by_location')
        
        response = self.client.get(url, {'location': 99999})
        
        self.assertEqual(response.status_code, 404)
        response_data = response.json()
        
        self.assertFalse(response_data['success'])
        self.assertIn('not found', response_data['error'])


class ConferenceBookingFormTestCase(TestCase):
    """Test conference booking form validation."""
    
    def setUp(self):
        """Set up test data."""
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.office_location = OfficeLocation.objects.create(
            name='Test Office',
            code='TST',
            city='Mumbai',
            state='Maharashtra',
            is_active=True
        )
        
        self.room = Room.objects.create(
            name='Test Room',
            office_location=self.office_location,
            room_type='CONFERENCE',
            capacity=10,
            status=Room.RoomStatus.ACTIVE
        )
    
    def test_form_validation_working_hours_removed(self):
        """Test that form validation no longer restricts working hours."""
        from trueAlign.conf_booking.views import ConferenceBookingForm
        
        # Test late night booking (10 PM to 11 PM on a weekday)
        tomorrow = timezone.now().replace(hour=22, minute=0, second=0, microsecond=0) + timedelta(days=1)
        # Ensure it's a weekday
        while tomorrow.weekday() >= 5:  # If it's weekend, move to next day
            tomorrow += timedelta(days=1)
        
        start_time = tomorrow
        end_time = tomorrow + timedelta(hours=1)
        
        form_data = {
            'room': self.room.id,
            'purpose': 'Night Meeting',
            'description': 'Night shift meeting',
            'start_time': start_time,
            'end_time': end_time,
            'attendees_count': 5,
            'external_attendees': 0,
            'meeting_type': 'INTERNAL',
            'priority': 'MEDIUM'
        }
        
        form = ConferenceBookingForm(data=form_data, user=self.user)
        
        # Form should be valid now that working hours restriction is removed
        self.assertTrue(form.is_valid(), f"Form errors: {form.errors}")
    
    def test_form_validation_weekend_restriction_remains(self):
        """Test that form validation still restricts weekends."""
        from trueAlign.conf_booking.views import ConferenceBookingForm
        
        # Find next Saturday
        now = timezone.now()
        days_ahead = 5 - now.weekday()  # Saturday is 5
        if days_ahead <= 0:
            days_ahead += 7
        
        saturday = now + timedelta(days=days_ahead)
        start_time = saturday.replace(hour=10, minute=0, second=0, microsecond=0)
        end_time = start_time + timedelta(hours=1)
        
        form_data = {
            'room': self.room.id,
            'purpose': 'Weekend Meeting',
            'description': 'Weekend meeting',
            'start_time': start_time,
            'end_time': end_time,
            'attendees_count': 5,
            'external_attendees': 0,
            'meeting_type': 'INTERNAL',
            'priority': 'MEDIUM'
        }
        
        form = ConferenceBookingForm(data=form_data, user=self.user)
        
        # Form should be invalid due to weekend restriction
        self.assertFalse(form.is_valid())
        self.assertIn('weekdays', str(form.errors))


class LocationIntegrationTestCase(TestCase):
    """Integration tests for the complete location verification flow."""
    
    def setUp(self):
        """Set up test data."""
        self.client = Client()
        
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        
        self.office_location = OfficeLocation.objects.create(
            name='Mumbai Office',
            code='MUM',
            city='Mumbai',
            state='Maharashtra',
            is_active=True
        )
        
        self.room = Room.objects.create(
            name='Conference Room A',
            office_location=self.office_location,
            room_type='CONFERENCE',
            capacity=10,
            status=Room.RoomStatus.ACTIVE
        )
        
        self.client.login(username='testuser', password='testpass123')
    
    @patch('trueAlign.conf_booking.utils.LocationDetector.get_city_from_coordinates')
    def test_complete_location_booking_flow(self, mock_get_city):
        """Test the complete flow from location detection to successful booking."""
        # Step 1: Detect location
        mock_get_city.return_value = {
            'city': 'Mumbai',
            'state': 'Maharashtra',
            'country': 'India'
        }
        
        detect_url = reverse('conf_booking:detect_office_location')
        location_data = {
            'latitude': 19.0760,
            'longitude': 72.8777
        }
        
        detect_response = self.client.post(
            detect_url,
            data=json.dumps(location_data),
            content_type='application/json'
        )
        
        self.assertEqual(detect_response.status_code, 200)
        detect_result = detect_response.json()
        self.assertTrue(detect_result['success'])
        
        # Step 2: Verify session is set
        session = self.client.session
        self.assertTrue(session.get('location_access_granted', False))
        
        # Step 3: Make booking
        booking_url = reverse('conf_booking:booking_room')
        start_time = timezone.now() + timedelta(hours=1)
        end_time = start_time + timedelta(hours=1)
        
        booking_data = {
            'room': self.room.id,
            'purpose': 'Integration Test Meeting',
            'description': 'Testing complete flow',
            'start_time': start_time.strftime('%Y-%m-%dT%H:%M'),
            'end_time': end_time.strftime('%Y-%m-%dT%H:%M'),
            'attendees_count': 5,
            'external_attendees': 0,
            'meeting_type': 'INTERNAL',
            'priority': 'MEDIUM'
        }
        
        booking_response = self.client.post(booking_url, booking_data)
        
        # Should redirect successfully
        self.assertEqual(booking_response.status_code, 302)
        
        # Booking should be created
        self.assertEqual(ConferenceBooking.objects.count(), 1)
        
        booking = ConferenceBooking.objects.first()
        self.assertEqual(booking.purpose, 'Integration Test Meeting')
        self.assertEqual(booking.booked_by, self.user)
        self.assertEqual(booking.room, self.room)
