#!/usr/bin/env python
"""
Automated Attendance System Test Runner
Runs comprehensive tests and generates detailed reports
"""

import os
import sys
import django
from datetime import datetime
import json

# Setup Django environment
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.test.utils import get_runner
from django.conf import settings
from trueAlign.tests.factories import TestDataGenerator
from trueAlign.models import Attendance, UserSession, ShiftAssignment


class AttendanceTestRunner:
    """Main test runner with reporting"""
    
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.results = {}
    
    def run_tests(self, verbosity=2):
        """Run all tests"""
        print("\n" + "=" * 100)
        print("🧪 ATTENDANCE SYSTEM - AUTOMATED TEST SUITE")
        print("=" * 100)
        print(f"📅 Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 100)
        
        self.start_time = datetime.now()
        
        # Get test runner
        TestRunner = get_runner(settings)
        test_runner = TestRunner(verbosity=verbosity, interactive=False, keepdb=False)
        
        # Run tests
        print("\n🚀 Starting test execution...\n")
        failures = test_runner.run_tests(['trueAlign.tests'])
        
        self.end_time = datetime.now()
        
        # Generate report
        self.generate_report(failures)
        
        return failures
    
    def generate_report(self, failures):
        """Generate detailed test report"""
        duration = (self.end_time - self.start_time).total_seconds()
        
        print("\n" + "=" * 100)
        print("📊 TEST EXECUTION SUMMARY")
        print("=" * 100)
        
        # Get database stats
        attendance_count = Attendance.objects.count()
        session_count = UserSession.objects.count()
        assignment_count = ShiftAssignment.objects.count()
        
        print(f"\n⏱️  Execution Time: {duration:.2f} seconds")
        print(f"{'✅' if failures == 0 else '❌'} Test Result: {'PASSED' if failures == 0 else 'FAILED'}")
        print(f"\n📈 Database Statistics:")
        print(f"   - Attendance Records: {attendance_count}")
        print(f"   - User Sessions: {session_count}")
        print(f"   - Shift Assignments: {assignment_count}")
        
        # Check data quality
        print(f"\n🔍 Data Quality Checks:")
        
        populated_ip = Attendance.objects.filter(
            clock_in_time__isnull=False,
            ip_address__isnull=False
        ).count()
        
        populated_device = Attendance.objects.filter(
            clock_in_time__isnull=False,
            device_info__isnull=False
        ).count()
        
        populated_location = Attendance.objects.exclude(
            location='Office'
        ).count()
        
        with_overtime = Attendance.objects.filter(
            overtime_hours__gt=0
        ).count()
        
        with_late = Attendance.objects.filter(
            late_minutes__gt=0
        ).count()
        
        print(f"   ✅ IP Addresses Populated: {populated_ip}")
        print(f"   ✅ Device Info Populated: {populated_device}")
        print(f"   ✅ Non-Office Locations: {populated_location}")
        print(f"   ✅ Overtime Records: {with_overtime}")
        print(f"   ✅ Late Arrivals: {with_late}")
        
        # Location distribution
        print(f"\n📍 Location Distribution:")
        from django.db.models import Count
        location_stats = Attendance.objects.values('location').annotate(
            count=Count('id')
        ).order_by('-count')
        
        for stat in location_stats:
            print(f"   - {stat['location']}: {stat['count']}")
        
        # Status distribution
        print(f"\n📊 Status Distribution:")
        status_stats = Attendance.objects.values('status').annotate(
            count=Count('id')
        ).order_by('-count')
        
        for stat in status_stats:
            print(f"   - {stat['status']}: {stat['count']}")
        
        print("\n" + "=" * 100)
        
        if failures == 0:
            print("🎉 ALL TESTS PASSED! Attendance system is working correctly.")
        else:
            print("⚠️  SOME TESTS FAILED! Please review the output above.")
        
        print("=" * 100 + "\n")
        
        # Save report to file
        self.save_report_to_file(failures, duration)
    
    def save_report_to_file(self, failures, duration):
        """Save test report to JSON file"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'duration_seconds': duration,
            'test_result': 'PASSED' if failures == 0 else 'FAILED',
            'failures_count': failures,
            'database_stats': {
                'attendance_records': Attendance.objects.count(),
                'user_sessions': UserSession.objects.count(),
                'shift_assignments': ShiftAssignment.objects.count()
            },
            'data_quality': {
                'ip_populated': Attendance.objects.filter(
                    clock_in_time__isnull=False,
                    ip_address__isnull=False
                ).count(),
                'device_populated': Attendance.objects.filter(
                    clock_in_time__isnull=False,
                    device_info__isnull=False
                ).count(),
                'non_office_locations': Attendance.objects.exclude(
                    location='Office'
                ).count()
            }
        }
        
        report_file = f'test_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"📄 Detailed report saved to: {report_file}")


def run_quick_smoke_test():
    """Run quick smoke test"""
    print("\n" + "=" * 100)
    print("⚡ QUICK SMOKE TEST")
    print("=" * 100)
    
    from trueAlign.tests.factories import TestUserFactory, TestShiftFactory, TestSessionFactory, TestShiftAssignmentFactory
    from trueAlign.attendance.services import AttendanceAutoMarkingService
    from django.utils import timezone
    
    # Create test user
    user = TestUserFactory.create_user("smoke_test_user")
    shift = TestShiftFactory.create_day_shift("Smoke Test Shift")
    TestShiftAssignmentFactory.assign_shift_to_user(user, shift)
    
    # Create session
    today = timezone.now().date()
    session = TestSessionFactory.create_session(
        user=user,
        date=today,
        login_hour=9,
        logout_hour=17,
        location_type="Home"
    )
    
    # Create attendance
    attendance, _ = Attendance.objects.get_or_create(
        user=user,
        date=today,
        defaults={'shift': shift}
    )
    
    # Update from session
    service = AttendanceAutoMarkingService()
    service._update_attendance_with_sessions(attendance, [session])
    attendance.refresh_from_db()
    
    # Verify
    checks = {
        'Status Present': attendance.status == 'Present',
        'IP Populated': attendance.ip_address is not None,
        'Device Info Populated': attendance.device_info is not None,
        'Location is Home': attendance.location == 'Home',
        'Clock In Set': attendance.clock_in_time is not None,
        'Clock Out Set': attendance.clock_out_time is not None,
    }
    
    print("\n✅ Smoke Test Results:")
    all_passed = True
    for check, result in checks.items():
        status = "✅" if result else "❌"
        print(f"   {status} {check}: {result}")
        if not result:
            all_passed = False
    
    # Cleanup
    attendance.delete()
    session.delete()
    user.delete()
    shift.delete()
    
    print("\n" + ("🎉 SMOKE TEST PASSED!" if all_passed else "⚠️  SMOKE TEST FAILED!"))
    print("=" * 100 + "\n")
    
    return all_passed


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Run Attendance System Tests')
    parser.add_argument(
        '--full',
        action='store_true',
        help='Run full comprehensive test suite'
    )
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Run quick smoke test only'
    )
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Clean up test data'
    )
    parser.add_argument(
        '--verbosity',
        type=int,
        default=2,
        help='Test verbosity level (0-3)'
    )
    
    args = parser.parse_args()
    
    try:
        if args.cleanup:
            print("🧹 Cleaning up test data...")
            TestDataGenerator.cleanup_test_data()
            print("✅ Cleanup complete!")
            return 0
        
        if args.quick:
            success = run_quick_smoke_test()
            return 0 if success else 1
        
        if args.full:
            runner = AttendanceTestRunner()
            failures = runner.run_tests(verbosity=args.verbosity)
            return failures
        
        # Default: run both
        print("Running quick smoke test first...\n")
        smoke_passed = run_quick_smoke_test()
        
        if smoke_passed:
            print("\n✅ Smoke test passed! Running full test suite...\n")
            runner = AttendanceTestRunner()
            failures = runner.run_tests(verbosity=args.verbosity)
            return failures
        else:
            print("\n❌ Smoke test failed! Skipping full test suite.")
            return 1
    
    except KeyboardInterrupt:
        print("\n\n⚠️  Tests interrupted by user")
        return 1
    except Exception as e:
        print(f"\n\n❌ Error running tests: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(main())
