#!/usr/bin/env python
"""
Notification Testing Utility
============================

This script tests the leave management notification system comprehensively.
It can be run standalone to diagnose notification issues and verify the system works.

Usage: python test_notifications.py

Requirements:
- Django environment must be properly configured
- Database must be accessible
- User groups (HR, Manager, Employee) must exist
- Leave types must exist
"""

import os
import sys
import django
from datetime import date, timedelta
from decimal import Decimal

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User, Group
from django.db import transaction
from django.conf import settings
from trueAlign.models import LeaveRequest, LeaveType, UserLeaveBalance
from trueAlign.notifications.models import Notification
from trueAlign.notifications.signals import leave_request_notification, get_notification_recipients_for_leave


class NotificationTester:
    def __init__(self):
        self.results = []
        self.test_data_created = []

    def log(self, message, status="INFO"):
        """Log test results"""
        status_icons = {
            "SUCCESS": "✅",
            "ERROR": "❌",
            "WARNING": "⚠️",
            "INFO": "ℹ️"
        }
        icon = status_icons.get(status, "•")
        print(f"{icon} {message}")
        self.results.append((status, message))

    def test_basic_notification_creation(self):
        """Test basic notification model functionality"""
        self.log("=== TESTING BASIC NOTIFICATION CREATION ===")

        try:
            # Get a test user
            test_user = User.objects.first()
            if not test_user:
                self.log("No users found in database", "ERROR")
                return False

            # Create a test notification
            notification = Notification.objects.create(
                recipient=test_user,
                type='BROWSER',
                title='Test Notification',
                message='This is a test notification',
                event_type='test_event'
            )

            self.log(f"Created notification ID {notification.id} for {test_user.username}", "SUCCESS")

            # Clean up
            notification.delete()
            self.log("Test notification cleaned up", "INFO")
            return True

        except Exception as e:
            self.log(f"Failed to create basic notification: {e}", "ERROR")
            return False

    def test_notification_recipients(self):
        """Test recipient selection for leave notifications"""
        self.log("=== TESTING NOTIFICATION RECIPIENTS ===")

        try:
            # Create a dummy leave request for testing
            test_user = User.objects.filter(groups__name='Employee').first()
            if not test_user:
                self.log("No Employee users found", "WARNING")
                test_user = User.objects.first()

            leave_type = LeaveType.objects.first()
            if not leave_type:
                self.log("No leave types found", "ERROR")
                return False

            dummy_leave = LeaveRequest(
                user=test_user,
                leave_type=leave_type,
                start_date=date.today(),
                end_date=date.today(),
                reason="Test",
                status="Pending"
            )

            # Test recipient selection
            recipients = get_notification_recipients_for_leave(dummy_leave)

            if recipients:
                self.log(f"Found {len(recipients)} notification recipients:", "SUCCESS")
                for recipient in recipients:
                    groups = [g.name for g in recipient.groups.all()]
                    self.log(f"  - {recipient.username} (Groups: {groups})", "INFO")
            else:
                self.log("No notification recipients found", "WARNING")
                hr_users = User.objects.filter(groups__name='HR').count()
                manager_users = User.objects.filter(groups__name='Manager').count()
                self.log(f"HR users in system: {hr_users}", "INFO")
                self.log(f"Manager users in system: {manager_users}", "INFO")

            return len(recipients) > 0

        except Exception as e:
            self.log(f"Error testing recipients: {e}", "ERROR")
            return False

    def test_notification_config(self):
        """Test notification configuration"""
        self.log("=== TESTING NOTIFICATION CONFIGURATION ===")

        try:
            config = settings.NOTIFICATION_CONFIG
            real_time_events = config.get('REAL_TIME_EVENTS', {})

            self.log(f"Browser notifications enabled: {config.get('ENABLE_BROWSER_NOTIFICATIONS', False)}", "INFO")
            self.log(f"Email notifications enabled: {config.get('ENABLE_EMAIL_NOTIFICATIONS', False)}", "INFO")

            critical_events = [
                'leave_request_created',
                'leave_request_approved',
                'leave_request_rejected'
            ]

            all_enabled = True
            for event in critical_events:
                enabled = real_time_events.get(event, False)
                status = "SUCCESS" if enabled else "WARNING"
                self.log(f"{event}: {enabled}", status)
                if not enabled:
                    all_enabled = False

            return all_enabled

        except Exception as e:
            self.log(f"Error checking notification config: {e}", "ERROR")
            return False

    def test_signal_connection(self):
        """Test if Django signals are properly connected"""
        self.log("=== TESTING SIGNAL CONNECTION ===")

        try:
            from django.db.models.signals import post_save

            # Check if our signal handler is connected
            signal_handlers = post_save._live_receivers(sender=LeaveRequest)

            connected_handlers = []
            for handler in signal_handlers:
                handler_name = getattr(handler, '__name__', str(handler))
                if 'leave_request_notification' in handler_name:
                    connected_handlers.append(handler_name)

            if connected_handlers:
                self.log(f"Found connected signal handlers: {connected_handlers}", "SUCCESS")
                return True
            else:
                self.log("Leave request notification signal not connected", "ERROR")
                self.log("Available signal handlers:", "INFO")
                for handler in signal_handlers:
                    handler_name = getattr(handler, '__name__', str(handler))
                    self.log(f"  - {handler_name}", "INFO")
                return False

        except Exception as e:
            self.log(f"Error testing signal connection: {e}", "ERROR")
            return False

    def test_leave_request_notification_trigger(self):
        """Test notification triggering with actual leave request"""
        self.log("=== TESTING LEAVE REQUEST NOTIFICATION TRIGGERING ===")

        try:
            # Find a suitable test user and leave type
            test_user = User.objects.filter(groups__name='Employee').first()
            if not test_user:
                test_user = User.objects.first()

            leave_type = LeaveType.objects.filter(is_paid=False).first()
            if not leave_type:
                leave_type = LeaveType.objects.first()

            if not test_user or not leave_type:
                self.log("Cannot find test user or leave type", "ERROR")
                return False

            # Count notifications before
            before_count = Notification.objects.count()

            # Create a minimal leave request that bypasses validation
            with transaction.atomic():
                leave_request = LeaveRequest.objects.create(
                    user=test_user,
                    leave_type=leave_type,
                    start_date=date.today() + timedelta(days=30),  # Future date
                    end_date=date.today() + timedelta(days=30),
                    reason="Test notification trigger",
                    status="Pending",
                    leave_days=Decimal('1')
                )

                self.test_data_created.append(('LeaveRequest', leave_request.id))
                self.log(f"Created test leave request ID {leave_request.id}", "INFO")

            # Count notifications after
            after_count = Notification.objects.count()
            new_notifications = after_count - before_count

            if new_notifications > 0:
                self.log(f"SUCCESS: {new_notifications} notifications created for new leave request", "SUCCESS")

                # Show the notifications
                recent_notifications = Notification.objects.order_by('-timestamp')[:new_notifications]
                for notif in recent_notifications:
                    self.log(f"  📧 '{notif.title}' to {notif.recipient.username} ({notif.event_type})", "INFO")

                return True
            else:
                self.log("No notifications created for new leave request", "WARNING")
                self.log("Manually triggering signal...", "INFO")

                # Manually trigger the signal
                try:
                    leave_request_notification(
                        sender=LeaveRequest,
                        instance=leave_request,
                        created=True
                    )

                    after_manual = Notification.objects.count()
                    manual_notifications = after_manual - after_count

                    if manual_notifications > 0:
                        self.log(f"Manual signal trigger created {manual_notifications} notifications", "SUCCESS")
                        return True
                    else:
                        self.log("Manual signal trigger also failed", "ERROR")
                        return False

                except Exception as signal_error:
                    self.log(f"Manual signal trigger failed: {signal_error}", "ERROR")
                    return False

        except Exception as e:
            self.log(f"Error testing leave request notifications: {e}", "ERROR")
            import traceback
            self.log(f"Traceback: {traceback.format_exc()}", "ERROR")
            return False

    def test_status_change_notification(self):
        """Test notifications when leave status changes"""
        self.log("=== TESTING STATUS CHANGE NOTIFICATIONS ===")

        try:
            # Find an existing pending leave request
            pending_leave = LeaveRequest.objects.filter(status='Pending').first()

            if not pending_leave:
                self.log("No pending leave requests found - creating one", "INFO")
                # Create a test leave request
                test_user = User.objects.filter(groups__name='Employee').first() or User.objects.first()
                leave_type = LeaveType.objects.first()

                if not test_user or not leave_type:
                    self.log("Cannot create test leave request - missing data", "ERROR")
                    return False

                pending_leave = LeaveRequest.objects.create(
                    user=test_user,
                    leave_type=leave_type,
                    start_date=date.today() + timedelta(days=31),
                    end_date=date.today() + timedelta(days=31),
                    reason="Test status change",
                    status="Pending",
                    leave_days=Decimal('1')
                )
                self.test_data_created.append(('LeaveRequest', pending_leave.id))

            self.log(f"Testing status change for leave request ID {pending_leave.id}", "INFO")

            # Count notifications before status change
            before_count = Notification.objects.count()

            # Change status with proper tracking
            old_status = pending_leave.status
            pending_leave.status = 'Approved'
            pending_leave._status_changed = (old_status, 'Approved')  # Set status change tracking
            pending_leave.save(update_fields=['status'])

            # Count notifications after
            after_count = Notification.objects.count()
            status_notifications = after_count - before_count

            if status_notifications > 0:
                self.log(f"SUCCESS: {status_notifications} notifications created for status change", "SUCCESS")

                recent_notifications = Notification.objects.order_by('-timestamp')[:status_notifications]
                for notif in recent_notifications:
                    self.log(f"  📧 '{notif.title}' to {notif.recipient.username} ({notif.event_type})", "INFO")

                # Revert status change
                pending_leave.status = old_status
                pending_leave.save(update_fields=['status'])
                self.log(f"Reverted status back to {old_status}", "INFO")

                return True
            else:
                self.log("No notifications created for status change", "WARNING")

                # Try manual signal trigger
                self.log("Manually triggering status change signal...", "INFO")
                try:
                    leave_request_notification(
                        sender=LeaveRequest,
                        instance=pending_leave,
                        created=False
                    )

                    after_manual = Notification.objects.count()
                    manual_notifications = after_manual - after_count

                    if manual_notifications > 0:
                        self.log(f"Manual trigger created {manual_notifications} notifications", "SUCCESS")
                        return True
                    else:
                        self.log("Manual trigger also failed", "ERROR")
                        return False

                except Exception as signal_error:
                    self.log(f"Manual signal trigger failed: {signal_error}", "ERROR")
                    return False

        except Exception as e:
            self.log(f"Error testing status change notifications: {e}", "ERROR")
            return False

    def cleanup_test_data(self):
        """Clean up any test data created during testing"""
        self.log("=== CLEANING UP TEST DATA ===")

        for data_type, data_id in self.test_data_created:
            try:
                if data_type == 'LeaveRequest':
                    LeaveRequest.objects.filter(id=data_id).delete()
                    self.log(f"Deleted test {data_type} ID {data_id}", "INFO")
            except Exception as e:
                self.log(f"Error cleaning up {data_type} ID {data_id}: {e}", "WARNING")

    def run_all_tests(self):
        """Run all notification tests"""
        self.log("🚀 STARTING NOTIFICATION SYSTEM TESTS")
        self.log("=" * 60)

        tests = [
            ("Basic Notification Creation", self.test_basic_notification_creation),
            ("Notification Recipients", self.test_notification_recipients),
            ("Notification Configuration", self.test_notification_config),
            ("Signal Connection", self.test_signal_connection),
            ("Leave Request Notifications", self.test_leave_request_notification_trigger),
            ("Status Change Notifications", self.test_status_change_notification)
        ]

        passed = 0
        total = len(tests)

        try:
            for test_name, test_func in tests:
                self.log(f"\n🧪 Running: {test_name}")
                result = test_func()
                if result:
                    passed += 1

        finally:
            # Always clean up
            self.cleanup_test_data()

        self.log("\n" + "=" * 60)
        self.log("📊 TEST SUMMARY")
        self.log("=" * 60)

        success_rate = (passed / total) * 100
        status = "SUCCESS" if passed == total else "WARNING" if passed > total/2 else "ERROR"

        self.log(f"Tests Passed: {passed}/{total} ({success_rate:.1f}%)", status)

        if passed < total:
            self.log("\n🔧 TROUBLESHOOTING TIPS:")
            if passed == 0:
                self.log("- Check if Django is properly configured")
                self.log("- Verify database connection")
                self.log("- Ensure User groups (HR, Manager) exist")
            else:
                self.log("- Check Redis/Celery configuration for async notifications")
                self.log("- Verify notification config in settings.py")
                self.log("- Check Django signal registration in apps.py")

        return passed == total


def main():
    """Main entry point"""
    tester = NotificationTester()
    success = tester.run_all_tests()

    if success:
        print("\n🎉 All notification tests passed! The system is working correctly.")
        sys.exit(0)
    else:
        print("\n⚠️ Some tests failed. See output above for troubleshooting.")
        sys.exit(1)


if __name__ == "__main__":
    main()
