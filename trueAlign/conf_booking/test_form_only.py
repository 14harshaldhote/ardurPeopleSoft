"""
Simple tests focused only on form functionality for conference booking
"""
from django.test import TestCase
from django.contrib.auth.models import User
from trueAlign.models import Room, OfficeLocation, UserDetails
from trueAlign.conf_booking.views import ConferenceBookingForm
from unittest.mock import MagicMock


class SimpleConferenceBookingFormTestCase(TestCase):
    def setUp(self):
        """Set up test data"""
        # Create test user
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
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

    def test_form_creation_without_user_profile(self):
        """Test that form can be created when user has no profile"""
        # Ensure user has no profile
        self.assertFalse(hasattr(self.user, 'profile'))
        
        # Initialize form - this should not raise an exception
        form = ConferenceBookingForm(user=self.user)
        
        # Check that form is created successfully
        self.assertIsNotNone(form)
        self.assertIn('room', form.fields)
        
        # Check that room choices include rooms (not filtered by office location)
        room_choices = form.fields['room'].choices
        self.assertTrue(len(room_choices) > 1)  # Should have "Select a room" + actual rooms
        
        # Check that our test room is in the choices
        room_ids = [choice[0] for choice in room_choices if choice[0]]
        self.assertIn(self.room.id, room_ids)

    def test_form_creation_with_profile_no_office_location(self):
        """Test that form works when user has profile but no office location"""
        # Create profile without office location
        UserDetails.objects.create(user=self.user)
        
        # Initialize form - this should not raise an exception
        form = ConferenceBookingForm(user=self.user)
        
        # Check that form is created successfully
        self.assertIsNotNone(form)
        self.assertIn('room', form.fields)
        
        # Check that room choices include all active rooms
        room_choices = form.fields['room'].choices
        room_ids = [choice[0] for choice in room_choices if choice[0]]
        self.assertIn(self.room.id, room_ids)

    def test_form_creation_with_profile_and_office_location(self):
        """Test that form filters rooms by office location when available"""
        # Create profile with office location
        UserDetails.objects.create(
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
        room_ids = [choice[0] for choice in room_choices if choice[0]]
        
        # Should include room from user's office location
        self.assertIn(self.room.id, room_ids)
        # Should NOT include room from other office location
        self.assertNotIn(other_room.id, room_ids)

    def test_form_handles_attribute_error_gracefully(self):
        """Test that form creation handles AttributeError gracefully"""
        # Create a mock user object that will cause AttributeError
        mock_user = MagicMock()
        mock_user.profile = None
        
        # This should not raise an exception due to our try/except in the form
        try:
            form = ConferenceBookingForm(user=mock_user)
            form_created = True
        except AttributeError:
            form_created = False
        
        # Form should be created successfully without raising AttributeError
        self.assertTrue(form_created)

    def test_form_creation_with_none_user(self):
        """Test that form works when user is None"""
        # Initialize form with None user - should not raise an exception
        form = ConferenceBookingForm(user=None)
        
        # Check that form is created successfully
        self.assertIsNotNone(form)
        self.assertIn('room', form.fields)
        
        # Should show all active rooms when no user is provided
        room_choices = form.fields['room'].choices
        room_ids = [choice[0] for choice in room_choices if choice[0]]
        self.assertIn(self.room.id, room_ids)

    def test_form_basic_validation(self):
        """Test that the basic form validation still works"""
        # Create profile with office location
        UserDetails.objects.create(
            user=self.user,
            office_location=self.office_location
        )
        
        # Initialize form with valid data
        from datetime import datetime, timedelta
        from django.utils import timezone
        
        # Find the next weekday (Monday = 0, Sunday = 6)
        start_time = timezone.now().replace(hour=10, minute=0, second=0, microsecond=0)  # 10 AM
        while start_time.weekday() >= 5:  # Skip weekends
            start_time += timedelta(days=1)
        if start_time <= timezone.now():  # If time has passed today, go to next weekday
            start_time += timedelta(days=1)
            while start_time.weekday() >= 5:
                start_time += timedelta(days=1)
        end_time = start_time + timedelta(hours=1)
        
        form_data = {
            'room': self.room.id,
            'purpose': 'Test Meeting',
            'start_time': start_time.strftime('%Y-%m-%dT%H:%M'),
            'end_time': end_time.strftime('%Y-%m-%dT%H:%M'),
            'attendees_count': 5,
            'external_attendees': 0,
            'meeting_type': 'INTERNAL',
            'priority': 'MEDIUM',  # Use MEDIUM instead of NORMAL
            'description': 'This is a test meeting'
        }
        
        form = ConferenceBookingForm(data=form_data, user=self.user)
        
        # Form should be valid
        self.assertTrue(form.is_valid(), f"Form errors: {form.errors}")


if __name__ == '__main__':
    import django
    import os
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'test_settings')
    django.setup()
    
    import unittest
    unittest.main()
