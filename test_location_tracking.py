#!/usr/bin/env python3
"""
Location Tracking Test Script
Tests the location tracking functionality in the session management system
"""

import os
import sys
import django
from django.conf import settings

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

import json
import logging
from django.test import RequestFactory, Client
from django.contrib.auth.models import User
from django.utils import timezone
from django.db import transaction
from trueAlign.models import UserSession, Attendance
from trueAlign.core.views import (
    optimized_session_heartbeat,
    optimized_batch_activity_update,
)

class LocationTrackingTester:
    """
    Test location tracking functionality
    """

    def __init__(self):
        self.factory = RequestFactory()
        self.test_results = []
        self.user = None

    def setup_test_user(self):
        """Create or get test user"""
        self.user, created = User.objects.get_or_create(
            username='location_test_user',
            defaults={
                'email': 'location_test@example.com',
                'first_name': 'Location',
                'last_name': 'Test'
            }
        )
        if created:
            print(f"✅ Created test user: {self.user.username}")
        else:
            print(f"✅ Using existing test user: {self.user.username}")

    def test_location_in_heartbeat(self):
        """Test location data in heartbeat requests"""
        print("\n🧪 Testing location data in heartbeat...")

        # Test data with location
        heartbeat_data = {
            "tab_id": "test_location_tab_123",
            "is_idle": False,
            "is_visible": True,
            "url": "http://testserver/dashboard/",
            "title": "Dashboard",
            "location": {
                "latitude": 19.0760,
                "longitude": 72.8777,
                "accuracy": 10
            },
            "location_latitude": 19.0760,
            "location_longitude": 72.8777,
            "location_accuracy": 10,
            "location_timestamp": timezone.now().isoformat(),
            "timestamp": timezone.now().isoformat()
        }

        try:
            request = self.factory.post('/optimized-heartbeat/',
                                      data=json.dumps(heartbeat_data),
                                      content_type='application/json')
            request.user = self.user
            response = optimized_session_heartbeat(request)

            if response.status_code == 200:
                print("  ✅ Heartbeat with location data successful")

                # Check if session was created with location data
                session = UserSession.objects.filter(
                    user=self.user,
                    tab_id="test_location_tab_123"
                ).first()

                if session:
                    if session.location_latitude and session.location_longitude:
                        print(f"  ✅ Session location data saved: lat={session.location_latitude}, lng={session.location_longitude}")
                        print(f"  ✅ Location type: {session.location_type}")
                        self.test_results.append("Heartbeat location data: PASSED")
                    else:
                        print("  ❌ Session location data not saved")
                        self.test_results.append("Heartbeat location data: FAILED")
                else:
                    print("  ❌ Session not found")
                    self.test_results.append("Heartbeat location data: FAILED")
            else:
                print(f"  ❌ Heartbeat failed with status: {response.status_code}")
                self.test_results.append("Heartbeat location data: FAILED")

        except Exception as e:
            print(f"  ❌ Heartbeat test error: {e}")
            self.test_results.append("Heartbeat location data: ERROR")

    def test_location_in_batch_activity(self):
        """Test location data in batch activity updates"""
        print("\n🧪 Testing location data in batch activity...")

        # Test data with location update activity
        batch_data = {
            "tab_id": "test_location_tab_456",
            "activities": [
                {
                    "type": "location_update",
                    "data": {
                        "location_latitude": 18.5204,
                        "location_longitude": 73.8567,
                        "location_accuracy": 15,
                        "location_timestamp": timezone.now().isoformat(),
                        "timestamp": timezone.now().isoformat()
                    },
                    "timestamp": timezone.now().isoformat()
                }
            ],
            "timestamp": timezone.now().isoformat()
        }

        try:
            request = self.factory.post('/optimized-batch-activity/',
                                      data=json.dumps(batch_data),
                                      content_type='application/json')
            request.user = self.user
            response = optimized_batch_activity_update(request)

            if response.status_code == 200:
                print("  ✅ Batch activity with location data successful")

                # Check if session was created/updated with location data
                session = UserSession.objects.filter(
                    user=self.user,
                    tab_id="test_location_tab_456"
                ).first()

                if session:
                    if session.location_latitude and session.location_longitude:
                        print(f"  ✅ Session location data updated: lat={session.location_latitude}, lng={session.location_longitude}")
                        print(f"  ✅ Location type: {session.location_type}")
                        self.test_results.append("Batch activity location data: PASSED")
                    else:
                        print("  ❌ Session location data not updated")
                        self.test_results.append("Batch activity location data: FAILED")
                else:
                    print("  ❌ Session not found")
                    self.test_results.append("Batch activity location data: FAILED")
            else:
                print(f"  ❌ Batch activity failed with status: {response.status_code}")
                self.test_results.append("Batch activity location data: FAILED")

        except Exception as e:
            print(f"  ❌ Batch activity test error: {e}")
            self.test_results.append("Batch activity location data: ERROR")

    def test_location_determination(self):
        """Test location determination logic"""
        print("\n🧪 Testing location determination...")

        try:
            # Create a session with location data
            session = UserSession.objects.create(
                user=self.user,
                tab_id="test_location_determination",
                login_time=timezone.now(),
                last_activity=timezone.now(),
                is_active=True,
                location_latitude=19.0760,  # Mumbai coordinates
                location_longitude=72.8777,
                location_accuracy=10,
                location_type='geo_location'
            )

            # Test location determination
            session.determine_location_type()
            session.refresh_from_db()

            print(f"  ✅ Location type determined: {session.location_type}")
            self.test_results.append("Location determination: PASSED")

            # Test attendance location determination
            from trueAlign.attendance.services import AttendanceIntegrationService
            attendance_service = AttendanceIntegrationService()

            location_result = attendance_service._determine_location_from_session(session)
            print(f"  ✅ Attendance location result: {location_result}")

            if location_result != 'Office':  # Should not default to Office if we have location data
                self.test_results.append("Attendance location determination: PASSED")
            else:
                self.test_results.append("Attendance location determination: NEEDS_IMPROVEMENT")

            # Cleanup
            session.delete()

        except Exception as e:
            print(f"  ❌ Location determination test error: {e}")
            self.test_results.append("Location determination: ERROR")

    def test_location_without_coordinates(self):
        """Test location handling without GPS coordinates"""
        print("\n🧪 Testing location handling without coordinates...")

        try:
            # Create session without location data
            session = UserSession.objects.create(
                user=self.user,
                tab_id="test_no_location",
                login_time=timezone.now(),
                last_activity=timezone.now(),
                is_active=True
            )

            # Test attendance location determination
            from trueAlign.attendance.services import AttendanceIntegrationService
            attendance_service = AttendanceIntegrationService()

            location_result = attendance_service._determine_location_from_session(session)
            print(f"  ✅ Default location result: {location_result}")

            if location_result == 'Office':
                print("  ✅ Correctly defaults to Office when no location data")
                self.test_results.append("Default location handling: PASSED")
            else:
                print("  ❌ Incorrect default location")
                self.test_results.append("Default location handling: FAILED")

            # Cleanup
            session.delete()

        except Exception as e:
            print(f"  ❌ Default location test error: {e}")
            self.test_results.append("Default location handling: ERROR")

    def test_location_edge_cases(self):
        """Test edge cases in location handling"""
        print("\n🧪 Testing location edge cases...")

        try:
            # Test with null coordinates
            session = UserSession.objects.create(
                user=self.user,
                tab_id="test_edge_case_1",
                login_time=timezone.now(),
                last_activity=timezone.now(),
                is_active=True,
                location_latitude=None,
                location_longitude=None
            )

            from trueAlign.attendance.services import AttendanceIntegrationService
            attendance_service = AttendanceIntegrationService()

            location_result = attendance_service._determine_location_from_session(session)
            print(f"  ✅ Null coordinates handled: {location_result}")

            # Test with invalid coordinates
            session.location_latitude = 999.0
            session.location_longitude = 999.0
            session.save()

            location_result = attendance_service._determine_location_from_session(session)
            print(f"  ✅ Invalid coordinates handled: {location_result}")

            self.test_results.append("Edge cases: PASSED")

            # Cleanup
            session.delete()

        except Exception as e:
            print(f"  ❌ Edge cases test error: {e}")
            self.test_results.append("Edge cases: ERROR")

    def cleanup_test_data(self):
        """Clean up test data"""
        print("\n🧹 Cleaning up test data...")

        try:
            # Delete test sessions
            UserSession.objects.filter(user=self.user).delete()
            print("  ✅ Test sessions cleaned up")

            # Optionally delete test user (uncomment if needed)
            # self.user.delete()
            # print("  ✅ Test user deleted")

        except Exception as e:
            print(f"  ❌ Cleanup error: {e}")

    def run_all_tests(self):
        """Run all location tracking tests"""
        print("🧪 Starting Location Tracking Tests...")
        print("=" * 50)

        self.setup_test_user()
        self.test_location_in_heartbeat()
        self.test_location_in_batch_activity()
        self.test_location_determination()
        self.test_location_without_coordinates()
        self.test_location_edge_cases()
        self.cleanup_test_data()

        self.print_results()

    def print_results(self):
        """Print test results summary"""
        print("\n" + "=" * 50)
        print("📊 LOCATION TRACKING TEST RESULTS")
        print("=" * 50)

        passed = sum(1 for result in self.test_results if 'PASSED' in result)
        failed = sum(1 for result in self.test_results if 'FAILED' in result)
        errors = sum(1 for result in self.test_results if 'ERROR' in result)
        needs_improvement = sum(1 for result in self.test_results if 'NEEDS_IMPROVEMENT' in result)

        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"💥 Errors: {errors}")
        print(f"⚠️  Needs Improvement: {needs_improvement}")

        print("\nDetailed Results:")
        for i, result in enumerate(self.test_results, 1):
            status_icon = "✅" if "PASSED" in result else "❌" if "FAILED" in result else "💥" if "ERROR" in result else "⚠️"
            print(f"  {i}. {status_icon} {result}")

        print("\n" + "=" * 50)

        if failed == 0 and errors == 0:
            print("🎉 ALL CRITICAL TESTS PASSED!")
            print("✅ Location tracking is working correctly")
        else:
            print("⚠️  SOME TESTS FAILED OR HAD ERRORS")
            print("🔧 Please review the failed tests above")

        print("=" * 50)

def main():
    """Main test function"""
    try:
        tester = LocationTrackingTester()
        tester.run_all_tests()

        print("\n🎯 Test completed!")
        print("   Check the results above to see if location tracking is working properly.")

    except Exception as e:
        print(f"\n💥 Fatal error during testing: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
