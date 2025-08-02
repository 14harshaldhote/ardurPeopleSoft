"""
Tests for Conference Booking functionality, especially handling missing office location
"""
import pytest
from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from django.contrib.messages import get_messages
from unittest.mock import patch, MagicMock
from trueAlign.models import Room, OfficeLocation, ConferenceBooking, UserDetails
from trueAlign.conf_booking.views import ConferenceBookingForm
from datetime import datetime, timedelta
from django.utils import timezone


class ConferenceBookingTestCase(TestCase):
    def setUp(self):
        """Set up test data"""
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
            code='TEST',
            city='Mumbai',
            state='Maharashtra',
            country='India',
            is_active=True
        )
        
        # Create room
        self.room = Room.objects.create(
            name='Meeting Room 1',
            office_location=self.office_location,
            capacity=10,
            room_type='CONFERENCE',
            status='ACTIVE'
        )
        
        # Create client
        self.client = Client()
        self.client.login(username='testuser', password='testpass123')

    def test_booking_form_without_user_profile(self):
        """Test that booking form works when user has no profile"""
        # Ensure user has no profile
        self.assertFalse(hasattr(self.user, 'profile'))
        
        # Initialize form
        form = ConferenceBookingForm(user=self.user)
        
        # Check that form is created successfully
        self.assertIsNotNone(form)
        self.assertIn('room', form.fields)
        
        # Check that room choices include all active rooms (not filtered by office location)
        room_choices = form.fields['room'].choices
        self.assertTrue(len(room_choices) > 1)  # Should have "Select a room" + actual rooms
        
    def test_booking_form_with_user_profile_no_office_location(self):
        """Test that booking form works when user has profile but no office location"""
        # Create profile without office location
        profile = UserDetails.objects.create(user=self.user)
        
        # Initialize form
        form = ConferenceBookingForm(user=self.user)
        
        # Check that form is created successfully
        self.assertIsNotNone(form)
        self.assertIn('room', form.fields)
        
        # Check that room choices include all active rooms
        room_choices = form.fields['room'].choices
        self.assertTrue(len(room_choices) > 1)
        
    def test_booking_form_with_user_profile_and_office_location(self):
        """Test that booking form filters rooms by office location when available"""
        # Create profile with office location
        profile = UserDetails.objects.create(
            user=self.user,
            office_location=self.office_location
        )
        
        # Create another office and room to test filtering
        other_office = OfficeLocation.objects.create(
            name='Other Office',
            code='OTHER',
            city='Delhi',
            state='Delhi',
            country='India',
            is_active=True
        )
        
        other_room = Room.objects.create(
            name='Other Room',
            office_location=other_office,
            capacity=5,
            room_type='CONFERENCE',
            status='ACTIVE'
        )
        
        # Initialize form
        form = ConferenceBookingForm(user=self.user)
        
        # Check that form only includes rooms from user's office location
        room_choices = form.fields['room'].choices
        room_ids = [choice[0] for choice in room_choices if choice[0]]  # Exclude empty choice
        
        self.assertIn(self.room.id, room_ids)
        self.assertNotIn(other_room.id, room_ids)

    def test_template_renders_without_office_location(self):
        """Test template renders correctly when user has no office location"""
        # Ensure user has no profile
        self.assertFalse(hasattr(self.user, 'profile'))
        
        # Access the booking modal template through room dashboard
        response = self.client.get(reverse('conf_booking:room_dashboard'))
        
        # Check response is successful
        self.assertEqual(response.status_code, 200)
        
        # Check that no AttributeError occurs (template should handle missing office location)
        self.assertContains(response, 'Book Conference Room')

    def test_template_renders_with_profile_no_office_location(self):
        """Test template renders correctly when user has profile but no office location"""
        # Create profile without office location
        UserDetails.objects.create(user=self.user)
        
        # Access the booking modal template through room dashboard
        response = self.client.get(reverse('conf_booking:room_dashboard'))
        
        # Check response is successful
        self.assertEqual(response.status_code, 200)
        
        # Check that no AttributeError occurs
        self.assertContains(response, 'Book Conference Room')

    def test_template_renders_with_office_location(self):
        """Test template renders correctly when user has office location"""
        # Create profile with office location
        UserDetails.objects.create(
            user=self.user,
            office_location=self.office_location
        )
        
        # Access the booking modal template through room dashboard
        response = self.client.get(reverse('conf_booking:room_dashboard'))
        
        # Check response is successful
        self.assertEqual(response.status_code, 200)
        
        # Check that office location is displayed
        self.assertContains(response, 'Test Office')

    @patch('trueAlign.conf_booking.utils.LocationValidator.is_location_verified_in_session')
    def test_booking_creation_without_location_verification(self, mock_location_verified):
        """Test that booking is blocked when location is not verified"""
        mock_location_verified.return_value = False
        
        # Prepare booking data
        start_time = timezone.now() + timedelta(hours=1)
        end_time = start_time + timedelta(hours=1)
        
        booking_data = {
            'room': self.room.id,
            'purpose': 'Test Meeting',
            'start_time': start_time.strftime('%Y-%m-%dT%H:%M'),
            'end_time': end_time.strftime('%Y-%m-%dT%H:%M'),
            'attendees_count': 5,
            'external_attendees': 0,
            'meeting_type': 'INTERNAL',
            'priority': 'NORMAL'
        }
        
        # Attempt to create booking
        response = self.client.post(reverse('conf_booking:booking_room'), booking_data)
        
        # Check that user is redirected (due to location verification failure)
        self.assertEqual(response.status_code, 302)
        
        # Check that no booking was created
        self.assertEqual(ConferenceBooking.objects.count(), 0)

    @patch('trueAlign.conf_booking.utils.LocationValidator.is_location_verified_in_session')
    @patch('trueAlign.models.BookingNotification.send_booking_confirmation')
    def test_booking_creation_with_location_verification(self, mock_send_confirmation, mock_location_verified):
        """Test that booking works when location is verified"""
        mock_location_verified.return_value = True
        mock_send_confirmation.return_value = None  # Mock email sending
        
        # Prepare booking data
        start_time = timezone.now() + timedelta(hours=1)
        end_time = start_time + timedelta(hours=1)
        
        booking_data = {
            'room': self.room.id,
            'purpose': 'Test Meeting',
            'start_time': start_time.strftime('%Y-%m-%dT%H:%M'),
            'end_time': end_time.strftime('%Y-%m-%dT%H:%M'),
            'attendees_count': 5,
            'external_attendees': 0,
            'meeting_type': 'INTERNAL',
            'priority': 'NORMAL'
        }
        
        # Create booking
        response = self.client.post(reverse('conf_booking:booking_room'), booking_data)
        
        # Check that user is redirected to dashboard (successful booking)
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse('core:dashboard'))
        
        # Check that booking was created
        self.assertEqual(ConferenceBooking.objects.count(), 1)
        booking = ConferenceBooking.objects.first()
        self.assertEqual(booking.purpose, 'Test Meeting')
        self.assertEqual(booking.booked_by, self.user)

    def test_get_available_rooms_without_office_location(self):
        """Test API endpoint returns rooms when user has no office location"""
        # Mock location validation to pass
        with patch('trueAlign.conf_booking.utils.LocationValidator.check_location_access_in_session', return_value=True):
            response = self.client.get(reverse('conf_booking:get_available_rooms'))
            
            # Should return empty result when no office location is detected
            self.assertEqual(response.status_code, 200)
            data = response.json()
            
            # Check that the response indicates location is required
            self.assertIn('location_required', data)

    def test_form_handles_attribute_error_gracefully(self):
        """Test that form creation handles AttributeError gracefully"""
        # Create a mock user object that will cause AttributeError
        mock_user = MagicMock()
        mock_user.profile = None
        
        # This should not raise an exception
        form = ConferenceBookingForm(user=mock_user)
        
        # Form should be created successfully
        self.assertIsNotNone(form)
        self.assertIn('room', form.fields)


class LocationHandlingIntegrationTestCase(TestCase):
    """Integration tests for location handling in booking system"""
    
    def setUp(self):
        """Set up test data"""
        self.user = User.objects.create_user(
            username='integrationuser',
            email='integration@example.com',
            password='testpass123'
        )
        
        self.office_location = OfficeLocation.objects.create(
            name='Integration Office',
            code='INT',
            city='Pune',
            state='Maharashtra',
            country='India',
            is_active=True
        )
        
        self.room = Room.objects.create(
            name='Integration Room',
            office_location=self.office_location,
            capacity=8,
            room_type='MEETING',
            status='ACTIVE'
        )
        
        self.client = Client()
        self.client.login(username='integrationuser', password='testpass123')
    
    def test_end_to_end_booking_flow_without_profile(self):
        """Test complete booking flow when user has no profile"""
        # Access dashboard first
        response = self.client.get(reverse('conf_booking:room_dashboard'))
        self.assertEqual(response.status_code, 200)
        
        # Check that rooms are displayed
        self.assertContains(response, 'Integration Room')
        
        # Mock location verification for booking
        with patch('trueAlign.conf_booking.utils.LocationValidator.is_location_verified_in_session', return_value=True), \
             patch('trueAlign.models.BookingNotification.send_booking_confirmation', return_value=None):
            
            start_time = timezone.now() + timedelta(hours=2)
            end_time = start_time + timedelta(hours=1)
            
            booking_data = {
                'room': self.room.id,
                'purpose': 'Integration Test Meeting',
                'start_time': start_time.strftime('%Y-%m-%dT%H:%M'),
                'end_time': end_time.strftime('%Y-%m-%dT%H:%M'),
                'attendees_count': 3,
                'external_attendees': 1,
                'meeting_type': 'INTERNAL',
                'priority': 'NORMAL'
            }
            
            response = self.client.post(reverse('conf_booking:booking_room'), booking_data)
            
            # Check successful booking
            self.assertEqual(response.status_code, 302)
            self.assertEqual(ConferenceBooking.objects.count(), 1)
            
            booking = ConferenceBooking.objects.first()
            self.assertEqual(booking.purpose, 'Integration Test Meeting')
            self.assertEqual(booking.attendees_count, 3)


if __name__ == '__main__':
    # Run the tests
    import django
    import os
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trueAlign.settings')
    django.setup()
    
    import unittest
    unittest.main()
