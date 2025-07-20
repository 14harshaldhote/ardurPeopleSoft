from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.utils import timezone
from datetime import time, datetime, timedelta
from trueAlign.models import OfficeLocation, Room, ConferenceBooking, UserDetails
from trueAlign.conf_booking.views import ConferenceBookingForm, conference_booking_context
import json


class OfficeLocationModelTest(TestCase):
    """Test cases for OfficeLocation model."""

    def setUp(self):
        self.office_location = OfficeLocation.objects.create(
            name='Mumbai - Bandra',
            code='MUM',
            address_line1='Bandra Kurla Complex',
            city='Mumbai',
            state='Maharashtra',
            postal_code='400051',
            country='India',
            phone='+91-22-12345678',
            email='mumbai@company.com',
            timezone='Asia/Kolkata',
            working_hours_start=time(9, 0),
            working_hours_end=time(18, 0),
            is_active=True,
        )

    def test_office_location_creation(self):
        """Test that office location is created correctly."""
        self.assertEqual(self.office_location.name, 'Mumbai - Bandra')
        self.assertEqual(self.office_location.code, 'MUM')
        self.assertTrue(self.office_location.is_active)
        self.assertEqual(str(self.office_location), 'Mumbai - Bandra (MUM)')

    def test_full_address_property(self):
        """Test the full_address property."""
        expected_address = 'Bandra Kurla Complex, Mumbai, Maharashtra, 400051, India'
        self.assertEqual(self.office_location.full_address, expected_address)

    def test_working_hours_display_property(self):
        """Test the working_hours_display property."""
        expected_hours = '09:00 AM - 06:00 PM'
        self.assertEqual(self.office_location.working_hours_display, expected_hours)


class RoomModelTest(TestCase):
    """Test cases for Room model with office location."""

    def setUp(self):
        self.office_location = OfficeLocation.objects.create(
            name='Mumbai - Bandra',
            code='MUM',
            address_line1='Bandra Kurla Complex',
            city='Mumbai',
            state='Maharashtra',
            postal_code='400051',
            country='India',
            is_active=True,
        )

        self.room = Room.objects.create(
            name='Conference Room A',
            office_location=self.office_location,
            room_type=Room.RoomType.CONFERENCE,
            capacity=12,
            location='First Floor',
            facilities='Projector, Whiteboard, Video Conferencing',
            status=Room.RoomStatus.ACTIVE,
        )

    def test_room_creation_with_office_location(self):
        """Test that room is created with office location."""
        self.assertEqual(self.room.office_location, self.office_location)
        self.assertEqual(self.room.name, 'Conference Room A')
        self.assertTrue(self.room.is_available)

    def test_room_string_representation(self):
        """Test room string representation includes office location."""
        expected_str = 'Conference Room A - Mumbai - Bandra (Conference Room) - Active'
        self.assertEqual(str(self.room), expected_str)

    def test_get_available_rooms_by_location(self):
        """Test filtering rooms by office location."""
        # Create another office location and room
        other_office = OfficeLocation.objects.create(
            name='Delhi - Gurgaon',
            code='DEL',
            address_line1='Cyber City',
            city='Gurgaon',
            state='Haryana',
            postal_code='122002',
            country='India',
            is_active=True,
        )

        other_room = Room.objects.create(
            name='Conference Room B',
            office_location=other_office,
            room_type=Room.RoomType.CONFERENCE,
            capacity=8,
            status=Room.RoomStatus.ACTIVE,
        )

        # Test filtering by office location
        mumbai_rooms = Room.get_available_rooms(office_location=self.office_location)
        delhi_rooms = Room.get_available_rooms(office_location=other_office)

        self.assertEqual(mumbai_rooms.count(), 1)
        self.assertEqual(delhi_rooms.count(), 1)
        self.assertEqual(mumbai_rooms.first(), self.room)
        self.assertEqual(delhi_rooms.first(), other_room)

    def test_get_available_rooms_for_user(self):
        """Test getting available rooms for a user based on their office location."""
        # Create a user with office location
        user = User.objects.create_user(username='testuser', password='testpass')
        user_details = UserDetails.objects.create(
            user=user,
            office_location=self.office_location
        )

        # Test getting rooms for user
        user_rooms = Room.get_available_rooms_for_user(user)
        self.assertEqual(user_rooms.count(), 1)
        self.assertEqual(user_rooms.first(), self.room)

    def test_unique_room_name_per_location(self):
        """Test that room names must be unique per office location."""
        # This should work - same name, different location
        other_office = OfficeLocation.objects.create(
            name='Delhi - Gurgaon',
            code='DEL',
            address_line1='Cyber City',
            city='Gurgaon',
            state='Haryana',
            postal_code='122002',
            country='India',
            is_active=True,
        )

        # Creating room with same name in different location should work
        room2 = Room.objects.create(
            name='Conference Room A',
            office_location=other_office,
            room_type=Room.RoomType.CONFERENCE,
            capacity=8,
            status=Room.RoomStatus.ACTIVE,
        )

        self.assertEqual(room2.name, 'Conference Room A')
        self.assertEqual(room2.office_location, other_office)


class ConferenceBookingFormTest(TestCase):
    """Test cases for ConferenceBookingForm with office location filtering."""

    def setUp(self):
        self.office_location = OfficeLocation.objects.create(
            name='Mumbai - Bandra',
            code='MUM',
            address_line1='Bandra Kurla Complex',
            city='Mumbai',
            state='Maharashtra',
            postal_code='400051',
            country='India',
            is_active=True,
        )

        self.room = Room.objects.create(
            name='Conference Room A',
            office_location=self.office_location,
            room_type=Room.RoomType.CONFERENCE,
            capacity=12,
            status=Room.RoomStatus.ACTIVE,
        )

        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.user_details = UserDetails.objects.create(
            user=self.user,
            office_location=self.office_location
        )

    def test_form_filters_rooms_by_user_location(self):
        """Test that form filters rooms by user's office location."""
        # Create another office location and room
        other_office = OfficeLocation.objects.create(
            name='Delhi - Gurgaon',
            code='DEL',
            address_line1='Cyber City',
            city='Gurgaon',
            state='Haryana',
            postal_code='122002',
            country='India',
            is_active=True,
        )

        other_room = Room.objects.create(
            name='Conference Room B',
            office_location=other_office,
            room_type=Room.RoomType.CONFERENCE,
            capacity=8,
            status=Room.RoomStatus.ACTIVE,
        )

        # Test form with user from Mumbai
        form = ConferenceBookingForm(user=self.user)
        room_choices = [choice[0] for choice in form.fields['room'].choices if choice[0]]

        # Should only include rooms from Mumbai office
        self.assertEqual(len(room_choices), 1)
        self.assertEqual(int(room_choices[0]), self.room.id)

    def test_form_shows_all_rooms_when_no_office_location(self):
        """Test that form shows all rooms when user has no office location."""
        # Create user without office location
        user_no_location = User.objects.create_user(username='testuser2', password='testpass')
        UserDetails.objects.create(user=user_no_location, office_location=None)

        form = ConferenceBookingForm(user=user_no_location)
        room_choices = [choice[0] for choice in form.fields['room'].choices if choice[0]]

        # Should include all active rooms
        self.assertEqual(len(room_choices), 1)  # Only our test room exists


class ConferenceBookingViewTest(TestCase):
    """Test cases for conference booking views with office location filtering."""

    def setUp(self):
        self.client = Client()
        self.office_location = OfficeLocation.objects.create(
            name='Mumbai - Bandra',
            code='MUM',
            address_line1='Bandra Kurla Complex',
            city='Mumbai',
            state='Maharashtra',
            postal_code='400051',
            country='India',
            is_active=True,
        )

        self.room = Room.objects.create(
            name='Conference Room A',
            office_location=self.office_location,
            room_type=Room.RoomType.CONFERENCE,
            capacity=12,
            status=Room.RoomStatus.ACTIVE,
        )

        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.user_details = UserDetails.objects.create(
            user=self.user,
            office_location=self.office_location
        )

    def test_conference_booking_context_filters_by_location(self):
        """Test that conference_booking_context filters rooms by user's office location."""
        # Create another office location and room
        other_office = OfficeLocation.objects.create(
            name='Delhi - Gurgaon',
            code='DEL',
            address_line1='Cyber City',
            city='Gurgaon',
            state='Haryana',
            postal_code='122002',
            country='India',
            is_active=True,
        )

        other_room = Room.objects.create(
            name='Conference Room B',
            office_location=other_office,
            room_type=Room.RoomType.CONFERENCE,
            capacity=8,
            status=Room.RoomStatus.ACTIVE,
        )

        # Test context for user with office location
        context = conference_booking_context(user=self.user)

        # Should only include rooms from user's office location
        self.assertEqual(len(context['available_rooms']), 1)
        self.assertEqual(context['available_rooms'][0].name, 'Conference Room A')

    def test_get_available_rooms_api_filters_by_location(self):
        """Test that get_available_rooms API endpoint filters by user's office location."""
        self.client.login(username='testuser', password='testpass')

        # Create another office location and room
        other_office = OfficeLocation.objects.create(
            name='Delhi - Gurgaon',
            code='DEL',
            address_line1='Cyber City',
            city='Gurgaon',
            state='Haryana',
            postal_code='122002',
            country='India',
            is_active=True,
        )

        other_room = Room.objects.create(
            name='Conference Room B',
            office_location=other_office,
            room_type=Room.RoomType.CONFERENCE,
            capacity=8,
            status=Room.RoomStatus.ACTIVE,
        )

        # Test API endpoint
        response = self.client.get(reverse('conf_booking:get_available_rooms'))
        self.assertEqual(response.status_code, 200)

        data = json.loads(response.content)
        self.assertTrue(data['success'])
        self.assertEqual(data['count'], 1)  # Should only return rooms from user's office
        self.assertEqual(data['rooms'][0]['name'], 'Conference Room A')


class AdminPermissionTest(TestCase):
    """Test cases for admin permissions on room management."""

    def setUp(self):
        self.client = Client()
        self.office_location = OfficeLocation.objects.create(
            name='Mumbai - Bandra',
            code='MUM',
            address_line1='Bandra Kurla Complex',
            city='Mumbai',
            state='Maharashtra',
            postal_code='400051',
            country='India',
            is_active=True,
        )

        # Create regular user
        self.regular_user = User.objects.create_user(username='regular', password='testpass')
        UserDetails.objects.create(user=self.regular_user, office_location=self.office_location)

        # Create admin user
        self.admin_user = User.objects.create_user(username='admin', password='testpass', is_staff=True)
        UserDetails.objects.create(user=self.admin_user, office_location=self.office_location)

        # Create superuser
        self.superuser = User.objects.create_superuser(username='super', password='testpass', email='test@test.com')
        UserDetails.objects.create(user=self.superuser, office_location=self.office_location)

    def test_regular_user_cannot_access_admin(self):
        """Test that regular users cannot access admin interface."""
        self.client.login(username='regular', password='testpass')

        # Try to access admin interface
        response = self.client.get('/admin/')
        self.assertEqual(response.status_code, 302)  # Redirect to login

    def test_admin_user_can_access_admin(self):
        """Test that admin users can access admin interface."""
        self.client.login(username='admin', password='testpass')

        # Try to access admin interface
        response = self.client.get('/admin/')
        self.assertEqual(response.status_code, 200)

    def test_superuser_can_access_admin(self):
        """Test that superusers can access admin interface."""
        self.client.login(username='super', password='testpass')

        # Try to access admin interface
        response = self.client.get('/admin/')
        self.assertEqual(response.status_code, 200)


class DashboardIntegrationTest(TestCase):
    """Test cases for dashboard integration with office location filtering."""

    def setUp(self):
        self.client = Client()
        self.office_location = OfficeLocation.objects.create(
            name='Mumbai - Bandra',
            code='MUM',
            address_line1='Bandra Kurla Complex',
            city='Mumbai',
            state='Maharashtra',
            postal_code='400051',
            country='India',
            is_active=True,
        )

        self.room = Room.objects.create(
            name='Conference Room A',
            office_location=self.office_location,
            room_type=Room.RoomType.CONFERENCE,
            capacity=12,
            status=Room.RoomStatus.ACTIVE,
        )

        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.user_details = UserDetails.objects.create(
            user=self.user,
            office_location=self.office_location
        )

    def test_dashboard_shows_location_specific_rooms(self):
        """Test that dashboard shows only rooms from user's office location."""
        self.client.login(username='testuser', password='testpass')

        # Create another office location and room
        other_office = OfficeLocation.objects.create(
            name='Delhi - Gurgaon',
            code='DEL',
            address_line1='Cyber City',
            city='Gurgaon',
            state='Haryana',
            postal_code='122002',
            country='India',
            is_active=True,
        )

        other_room = Room.objects.create(
            name='Conference Room B',
            office_location=other_office,
            room_type=Room.RoomType.CONFERENCE,
            capacity=8,
            status=Room.RoomStatus.ACTIVE,
        )

        # Test room dashboard
        response = self.client.get(reverse('conf_booking:room_dashboard'))
        self.assertEqual(response.status_code, 200)

        # Check that only rooms from user's office location are shown
        content = response.content.decode('utf-8')
        self.assertIn('Conference Room A', content)
        self.assertNotIn('Conference Room B', content)

    def test_booking_creation_with_office_location(self):
        """Test that bookings can be created with office location filtering."""
        self.client.login(username='testuser', password='testpass')

        # Create a booking
        start_time = timezone.now() + timedelta(hours=1)
        end_time = start_time + timedelta(hours=1)

        booking_data = {
            'room': self.room.id,
            'purpose': 'Test Meeting',
            'description': 'Test Description',
            'start_time': start_time.strftime('%Y-%m-%dT%H:%M'),
            'end_time': end_time.strftime('%Y-%m-%dT%H:%M'),
            'attendees_count': 5,
            'external_attendees': 0,
            'meeting_type': 'INTERNAL',
            'priority': 'MEDIUM',
        }

        response = self.client.post(reverse('conf_booking:booking_room'), booking_data)

        # Check that booking was created
        self.assertTrue(ConferenceBooking.objects.filter(
            room=self.room,
            booked_by=self.user,
            purpose='Test Meeting'
        ).exists())


class UserBookingTest(TestCase):
    """Test cases for user booking functionality with office location."""

    def setUp(self):
        self.client = Client()
        self.office_location = OfficeLocation.objects.create(
            name='Mumbai - Bandra',
            code='MUM',
            address_line1='Bandra Kurla Complex',
            city='Mumbai',
            state='Maharashtra',
            postal_code='400051',
            country='India',
            is_active=True,
        )

        self.room = Room.objects.create(
            name='Conference Room A',
            office_location=self.office_location,
            room_type=Room.RoomType.CONFERENCE,
            capacity=12,
            status=Room.RoomStatus.ACTIVE,
        )

        self.user = User.objects.create_user(username='testuser', password='testpass')
        self.user_details = UserDetails.objects.create(
            user=self.user,
            office_location=self.office_location
        )

        # Create a booking
        self.booking = ConferenceBooking.objects.create(
            room=self.room,
            booked_by=self.user,
            purpose='Test Meeting',
            start_time=timezone.now() + timedelta(hours=1),
            end_time=timezone.now() + timedelta(hours=2),
            attendees_count=5,
            status=ConferenceBooking.BookingStatus.CONFIRMED,
        )

    def test_user_can_view_own_bookings(self):
        """Test that users can view their own bookings."""
        self.client.login(username='testuser', password='testpass')

        response = self.client.get(reverse('conf_booking:user_bookings'))
        self.assertEqual(response.status_code, 200)

        content = response.content.decode('utf-8')
        self.assertIn('Test Meeting', content)
        self.assertIn('Conference Room A', content)

    def test_user_can_cancel_own_booking(self):
        """Test that users can cancel their own bookings."""
        self.client.login(username='testuser', password='testpass')

        response = self.client.post(reverse('conf_booking:cancel_booking', args=[self.booking.id]))

        # Check that booking was cancelled
        self.booking.refresh_from_db()
        self.assertEqual(self.booking.status, ConferenceBooking.BookingStatus.CANCELLED)

    def test_user_cannot_cancel_others_booking(self):
        """Test that users cannot cancel other users' bookings."""
        # Create another user
        other_user = User.objects.create_user(username='otheruser', password='testpass')
        UserDetails.objects.create(user=other_user, office_location=self.office_location)

        # Create booking for other user
        other_booking = ConferenceBooking.objects.create(
            room=self.room,
            booked_by=other_user,
            purpose='Other Meeting',
            start_time=timezone.now() + timedelta(hours=3),
            end_time=timezone.now() + timedelta(hours=4),
            attendees_count=3,
            status=ConferenceBooking.BookingStatus.CONFIRMED,
        )

        self.client.login(username='testuser', password='testpass')

        response = self.client.post(reverse('conf_booking:cancel_booking', args=[other_booking.id]))
        self.assertEqual(response.status_code, 403)  # Forbidden

        # Check that booking was not cancelled
        other_booking.refresh_from_db()
        self.assertEqual(other_booking.status, ConferenceBooking.BookingStatus.CONFIRMED)
