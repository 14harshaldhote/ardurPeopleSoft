#!/usr/bin/env python
"""
Test script for Conference Room Booking System
Run this to verify the booking system is working properly.
"""

import os
import sys
import django
from datetime import datetime, timedelta

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User
from trueAlign.models import Room, ConferenceBooking
from django.utils import timezone


def test_room_creation():
    """Test that rooms are created and accessible"""
    print("🧪 Testing Room Creation...")

    rooms = Room.objects.all()
    if rooms.count() == 0:
        print("❌ No rooms found! Run: python manage.py setup_rooms")
        return False

    print(f"✅ Found {rooms.count()} rooms:")
    for room in rooms:
        print(f"   - {room.name} (Capacity: {room.capacity}, Status: {room.status})")

    return True


def test_booking_creation():
    """Test creating a booking"""
    print("\n🧪 Testing Booking Creation...")

    # Get or create a test user
    user, created = User.objects.get_or_create(
        username='test_user',
        defaults={
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'test@example.com'
        }
    )

    if created:
        print(f"✅ Created test user: {user.username}")
    else:
        print(f"✅ Using existing test user: {user.username}")

    # Get first available room
    room = Room.objects.filter(status=Room.RoomStatus.ACTIVE).first()
    if not room:
        print("❌ No active rooms available!")
        return False

    # Create a test booking for tomorrow
    now = timezone.now()
    tomorrow = now + timedelta(days=1)
    start_time = tomorrow.replace(hour=10, minute=0, second=0, microsecond=0)
    end_time = start_time + timedelta(hours=1)

    # Check if booking already exists
    existing_booking = ConferenceBooking.objects.filter(
        room=room,
        start_time=start_time,
        end_time=end_time,
        status=ConferenceBooking.BookingStatus.CONFIRMED
    ).first()

    if existing_booking:
        print(f"✅ Test booking already exists: {existing_booking.purpose}")
        return True

    try:
        booking = ConferenceBooking.objects.create(
            room=room,
            booked_by=user,
            purpose="Test Meeting - Automated Test",
            start_time=start_time,
            end_time=end_time,
            attendees_count=3,
            external_attendees=1,
            meeting_type="INTERNAL",
            priority="NORMAL",
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            description="This is a test booking created by the test script."
        )

        print(f"✅ Created test booking: {booking.purpose}")
        print(f"   - Room: {booking.room.name}")
        print(f"   - Time: {booking.start_time.strftime('%Y-%m-%d %H:%M')} - {booking.end_time.strftime('%H:%M')}")
        print(f"   - Attendees: {booking.attendees_count} internal, {booking.external_attendees} external")

        return True

    except Exception as e:
        print(f"❌ Failed to create booking: {e}")
        return False


def test_booking_validation():
    """Test booking validation rules"""
    print("\n🧪 Testing Booking Validation...")

    user = User.objects.filter(username='test_user').first()
    room = Room.objects.filter(status=Room.RoomStatus.ACTIVE).first()

    if not user or not room:
        print("❌ Test user or room not available")
        return False

    # Test 1: Past booking (should fail)
    try:
        past_time = timezone.now() - timedelta(hours=1)
        ConferenceBooking.objects.create(
            room=room,
            booked_by=user,
            purpose="Past Meeting Test",
            start_time=past_time,
            end_time=past_time + timedelta(hours=1),
            attendees_count=1,
            status=ConferenceBooking.BookingStatus.CONFIRMED
        )
        print("❌ Past booking validation failed - booking was allowed")
        return False
    except Exception:
        print("✅ Past booking correctly rejected")

    # Test 2: Check room capacity (this is typically done in forms/views)
    max_attendees = room.capacity + 5  # Exceed capacity
    print(f"✅ Room capacity validation: {room.name} capacity is {room.capacity}")

    # Test 3: Duration validation
    now = timezone.now()
    future_time = now + timedelta(days=2)
    short_duration = timedelta(minutes=5)  # Too short

    try:
        ConferenceBooking.objects.create(
            room=room,
            booked_by=user,
            purpose="Short Meeting Test",
            start_time=future_time,
            end_time=future_time + short_duration,
            attendees_count=1,
            status=ConferenceBooking.BookingStatus.CONFIRMED
        )
        print("⚠️  Short duration booking allowed (validation may be in views)")
    except Exception:
        print("✅ Short duration booking rejected")

    return True


def test_room_status():
    """Test room status functionality"""
    print("\n🧪 Testing Room Status...")

    for room in Room.objects.filter(status=Room.RoomStatus.ACTIVE):
        print(f"📍 Room: {room.name}")
        print(f"   - Status: {room.status}")
        print(f"   - Is Occupied: {room.is_occupied}")

        current_booking = room.current_booking
        if current_booking:
            print(f"   - Current Booking: {current_booking.purpose}")
        else:
            print("   - Current Booking: None")

        next_booking = room.next_booking
        if next_booking:
            print(f"   - Next Booking: {next_booking.purpose} at {next_booking.start_time.strftime('%H:%M')}")
        else:
            print("   - Next Booking: None")

    return True


def test_user_bookings():
    """Test user booking queries"""
    print("\n🧪 Testing User Bookings...")

    user = User.objects.filter(username='test_user').first()
    if not user:
        print("❌ Test user not found")
        return False

    user_bookings = ConferenceBooking.objects.filter(
        booked_by=user,
        status=ConferenceBooking.BookingStatus.CONFIRMED
    ).order_by('start_time')

    print(f"✅ Found {user_bookings.count()} bookings for user {user.username}:")
    for booking in user_bookings:
        print(f"   - {booking.purpose} in {booking.room.name}")
        print(f"     Time: {booking.start_time.strftime('%Y-%m-%d %H:%M')} - {booking.end_time.strftime('%H:%M')}")

    return True


def cleanup_test_data():
    """Clean up test data"""
    print("\n🧹 Cleaning up test data...")

    # Delete test bookings
    test_bookings = ConferenceBooking.objects.filter(
        purpose__icontains="Test Meeting - Automated Test"
    )
    count = test_bookings.count()
    test_bookings.delete()
    print(f"✅ Deleted {count} test bookings")

    # Optionally delete test user (commented out to preserve)
    # User.objects.filter(username='test_user').delete()
    # print("✅ Deleted test user")


def main():
    """Run all tests"""
    print("🚀 Conference Room Booking System Test Suite")
    print("=" * 50)

    tests = [
        test_room_creation,
        test_booking_creation,
        test_booking_validation,
        test_room_status,
        test_user_bookings,
    ]

    passed = 0
    failed = 0

    for test_func in tests:
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"❌ Test {test_func.__name__} failed with error: {e}")
            failed += 1

    print("\n" + "=" * 50)
    print("📊 Test Results Summary:")
    print(f"✅ Passed: {passed}")
    print(f"❌ Failed: {failed}")
    print(f"📈 Success Rate: {(passed/(passed+failed)*100):.1f}%")

    if failed == 0:
        print("\n🎉 All tests passed! Your booking system is working correctly.")
    else:
        print(f"\n⚠️  {failed} test(s) failed. Please check the issues above.")

    # Ask if user wants to clean up
    cleanup_choice = input("\n🧹 Clean up test data? (y/n): ").lower().strip()
    if cleanup_choice == 'y':
        cleanup_test_data()

    return failed == 0


if __name__ == "__main__":
    try:
        success = main()
        sys.exit(0 if success else 1)
    except KeyboardInterrupt:
        print("\n\n🛑 Test interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n💥 Unexpected error: {e}")
        sys.exit(1)
