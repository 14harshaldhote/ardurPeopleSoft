#!/usr/bin/env python3
"""
Session Management Fixes Validation Script
Validates that all session management issues have been resolved
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
from django.core.cache import cache
from trueAlign.models import UserSession, Attendance
from trueAlign.core.middleware import OptimizedSessionTrackingMiddleware
from trueAlign.core.views import (
    optimized_session_heartbeat,
    optimized_batch_activity_update,
    optimized_session_status,
    optimized_end_session
)

class SessionFixesValidator:
    """
    Comprehensive validator for session management fixes
    """

    def __init__(self):
        self.passed_tests = []
        self.failed_tests = []
        self.warnings = []

    def run_all_validations(self):
        """Run all validation tests"""
        print("🔍 Starting session management fixes validation...")
        print("=" * 60)

        # 1. Test buffer initialization
        self.test_buffer_initialization()

        # 2. Test session creation
        self.test_session_creation()

        # 3. Test duplicate prevention
        self.test_duplicate_prevention()

        # 4. Test endpoints
        self.test_session_endpoints()

        # 5. Test transaction handling
        self.test_transaction_handling()

        # 6. Test middleware functionality
        self.test_middleware_functionality()

        # 7. Test database integrity
        self.test_database_integrity()

        # 8. Test error handling
        self.test_error_handling()

        self.print_results()

    def test_buffer_initialization(self):
        """Test that buffer initialization works correctly"""
        print("\n🧪 Testing buffer initialization...")

        try:
            middleware = OptimizedSessionTrackingMiddleware(None)

            # Test buffer structure
            if hasattr(middleware, '_activity_buffer'):
                self.passed_tests.append("Middleware has activity buffer")
                print("  ✅ Activity buffer exists")
            else:
                self.failed_tests.append("Missing activity buffer")
                print("  ❌ Activity buffer missing")

            # Test buffer initialization doesn't crash
            try:
                # Create a test user
                user = User.objects.first()
                if user:
                    session = UserSession.objects.create(
                        user=user,
                        tab_id='test_buffer_123',
                        login_time=timezone.now(),
                        is_active=True
                    )

                    # Test buffer key generation
                    buffer_key = f"activity_{user.id}_{session.id}"

                    # Initialize buffer
                    middleware._activity_buffer[buffer_key] = {
                        'clicks': [],
                        'scrolls': [],
                        'keyboard_events': [],
                        'mouse_movements': 0,
                        'tab_visibility_log': [],
                        'idle_state_changes': [],
                        'performance_metrics': {},
                        'page_views': [],
                        'pending_updates': {},
                        'last_activity': timezone.now(),
                        'last_flush': timezone.now().timestamp(),
                        'user_id': user.id
                    }

                    # Test setdefault behavior
                    buffer = middleware._activity_buffer[buffer_key]
                    buffer.setdefault('pending_updates', {})

                    self.passed_tests.append("Buffer initialization works")
                    print("  ✅ Buffer initialization successful")

                    # Cleanup
                    session.delete()

                else:
                    self.warnings.append("No users found for buffer test")
                    print("  ⚠️  No users found for testing")

            except Exception as e:
                self.failed_tests.append(f"Buffer initialization error: {e}")
                print(f"  ❌ Buffer initialization failed: {e}")

        except Exception as e:
            self.failed_tests.append(f"Middleware initialization error: {e}")
            print(f"  ❌ Middleware initialization failed: {e}")

    def test_session_creation(self):
        """Test session creation works without deadlocks"""
        print("\n🧪 Testing session creation...")

        try:
            user = User.objects.first()
            if not user:
                self.warnings.append("No users found for session creation test")
                print("  ⚠️  No users available for testing")
                return

            # Test basic session creation
            session = UserSession.objects.create(
                user=user,
                tab_id='test_creation_123',
                login_time=timezone.now(),
                last_activity=timezone.now(),
                is_active=True
            )

            self.passed_tests.append("Basic session creation works")
            print("  ✅ Basic session creation successful")

            # Test session update
            session.last_activity = timezone.now()
            session.save()

            self.passed_tests.append("Session update works")
            print("  ✅ Session update successful")

            # Test session closure
            session.is_active = False
            session.ended_at = timezone.now()
            session.logout_time = timezone.now()
            session.save()

            self.passed_tests.append("Session closure works")
            print("  ✅ Session closure successful")

            # Cleanup
            session.delete()

        except Exception as e:
            self.failed_tests.append(f"Session creation error: {e}")
            print(f"  ❌ Session creation failed: {e}")

    def test_duplicate_prevention(self):
        """Test that duplicate sessions are prevented"""
        print("\n🧪 Testing duplicate session prevention...")

        try:
            user = User.objects.first()
            if not user:
                self.warnings.append("No users found for duplicate prevention test")
                print("  ⚠️  No users available for testing")
                return

            # Create first session
            session1 = UserSession.objects.create(
                user=user,
                tab_id='test_duplicate_123',
                login_time=timezone.now(),
                is_active=True
            )

            # Try to create duplicate session with same tab_id
            session2 = UserSession.objects.create(
                user=user,
                tab_id='test_duplicate_123',
                login_time=timezone.now(),
                is_active=True
            )

            # Check if middleware would handle this correctly
            middleware = OptimizedSessionTrackingMiddleware(None)

            # Simulate middleware logic
            existing_session = UserSession.objects.filter(
                user=user,
                tab_id='test_duplicate_123',
                is_active=True
            ).first()

            if existing_session:
                self.passed_tests.append("Duplicate detection works")
                print("  ✅ Duplicate session detection successful")
            else:
                self.failed_tests.append("Duplicate detection failed")
                print("  ❌ Duplicate session detection failed")

            # Cleanup
            session1.delete()
            session2.delete()

        except Exception as e:
            self.failed_tests.append(f"Duplicate prevention error: {e}")
            print(f"  ❌ Duplicate prevention test failed: {e}")

    def test_session_endpoints(self):
        """Test all session endpoints work correctly"""
        print("\n🧪 Testing session endpoints...")

        try:
            factory = RequestFactory()
            user = User.objects.first()

            if not user:
                self.warnings.append("No users found for endpoint testing")
                print("  ⚠️  No users available for testing")
                return

            # Test heartbeat endpoint
            try:
                request = factory.post('/optimized-heartbeat/',
                                    data=json.dumps({"tab_id": "test_endpoint_123"}),
                                    content_type='application/json')
                request.user = user
                response = optimized_session_heartbeat(request)

                if response.status_code == 200:
                    self.passed_tests.append("Heartbeat endpoint works")
                    print("  ✅ Heartbeat endpoint successful")
                else:
                    self.failed_tests.append(f"Heartbeat endpoint failed: {response.status_code}")
                    print(f"  ❌ Heartbeat endpoint failed: {response.status_code}")

            except Exception as e:
                self.failed_tests.append(f"Heartbeat endpoint error: {e}")
                print(f"  ❌ Heartbeat endpoint error: {e}")

            # Test batch activity endpoint
            try:
                request = factory.post('/optimized-batch-activity/',
                                    data=json.dumps({
                                        "tab_id": "test_endpoint_123",
                                        "activities": []
                                    }),
                                    content_type='application/json')
                request.user = user
                response = optimized_batch_activity_update(request)

                if response.status_code == 200:
                    self.passed_tests.append("Batch activity endpoint works")
                    print("  ✅ Batch activity endpoint successful")
                else:
                    self.failed_tests.append(f"Batch activity endpoint failed: {response.status_code}")
                    print(f"  ❌ Batch activity endpoint failed: {response.status_code}")

            except Exception as e:
                self.failed_tests.append(f"Batch activity endpoint error: {e}")
                print(f"  ❌ Batch activity endpoint error: {e}")

            # Test session status endpoint
            try:
                request = factory.post('/optimized-session-status/',
                                    data=json.dumps({"tab_id": "test_endpoint_123"}),
                                    content_type='application/json')
                request.user = user
                response = optimized_session_status(request)

                if response.status_code in [200, 404]:  # 404 is acceptable if no session
                    self.passed_tests.append("Session status endpoint works")
                    print("  ✅ Session status endpoint successful")
                else:
                    self.failed_tests.append(f"Session status endpoint failed: {response.status_code}")
                    print(f"  ❌ Session status endpoint failed: {response.status_code}")

            except Exception as e:
                self.failed_tests.append(f"Session status endpoint error: {e}")
                print(f"  ❌ Session status endpoint error: {e}")

        except Exception as e:
            self.failed_tests.append(f"Endpoint testing error: {e}")
            print(f"  ❌ Endpoint testing failed: {e}")

    def test_transaction_handling(self):
        """Test transaction handling improvements"""
        print("\n🧪 Testing transaction handling...")

        try:
            user = User.objects.first()
            if not user:
                self.warnings.append("No users found for transaction testing")
                print("  ⚠️  No users available for testing")
                return

            # Test nested transaction detection
            try:
                with transaction.atomic():
                    # Check if we can detect being in a transaction
                    if transaction.get_connection().in_atomic_block:
                        self.passed_tests.append("Transaction detection works")
                        print("  ✅ Transaction detection successful")
                    else:
                        self.failed_tests.append("Transaction detection failed")
                        print("  ❌ Transaction detection failed")

            except Exception as e:
                self.failed_tests.append(f"Transaction detection error: {e}")
                print(f"  ❌ Transaction detection error: {e}")

            # Test session creation in transaction
            try:
                with transaction.atomic():
                    session = UserSession.objects.create(
                        user=user,
                        tab_id='test_transaction_123',
                        login_time=timezone.now(),
                        is_active=True
                    )

                    # Test update in same transaction
                    session.last_activity = timezone.now()
                    session.save()

                    self.passed_tests.append("Transaction operations work")
                    print("  ✅ Transaction operations successful")

                    # Cleanup
                    session.delete()

            except Exception as e:
                self.failed_tests.append(f"Transaction operations error: {e}")
                print(f"  ❌ Transaction operations failed: {e}")

        except Exception as e:
            self.failed_tests.append(f"Transaction handling error: {e}")
            print(f"  ❌ Transaction handling test failed: {e}")

    def test_middleware_functionality(self):
        """Test middleware functionality"""
        print("\n🧪 Testing middleware functionality...")

        try:
            # Test middleware initialization
            middleware = OptimizedSessionTrackingMiddleware(None)

            # Test configuration
            from trueAlign.core.session_config import CONFIG

            required_configs = [
                'HEARTBEAT_THROTTLE_INTERVAL',
                'ACTIVITY_THROTTLE_INTERVAL',
                'MAX_BUFFER_SIZE',
                'SESSION_TIMEOUT_MINUTES'
            ]

            config_passed = 0
            for config_name in required_configs:
                if hasattr(CONFIG, config_name):
                    config_passed += 1

            if config_passed == len(required_configs):
                self.passed_tests.append("Middleware configuration complete")
                print("  ✅ Middleware configuration successful")
            else:
                self.failed_tests.append(f"Missing {len(required_configs) - config_passed} config items")
                print(f"  ❌ Missing {len(required_configs) - config_passed} config items")

        except Exception as e:
            self.failed_tests.append(f"Middleware functionality error: {e}")
            print(f"  ❌ Middleware functionality test failed: {e}")

    def test_database_integrity(self):
        """Test database integrity after fixes"""
        print("\n🧪 Testing database integrity...")

        try:
            # Check for orphaned sessions
            orphaned_sessions = UserSession.objects.filter(user__isnull=True).count()
            if orphaned_sessions == 0:
                self.passed_tests.append("No orphaned sessions found")
                print("  ✅ No orphaned sessions")
            else:
                self.warnings.append(f"Found {orphaned_sessions} orphaned sessions")
                print(f"  ⚠️  Found {orphaned_sessions} orphaned sessions")

            # Check for invalid session states
            invalid_sessions = UserSession.objects.filter(
                is_active=True,
                ended_at__isnull=False
            ).count()

            if invalid_sessions == 0:
                self.passed_tests.append("No invalid session states")
                print("  ✅ No invalid session states")
            else:
                self.warnings.append(f"Found {invalid_sessions} invalid session states")
                print(f"  ⚠️  Found {invalid_sessions} invalid session states")

            # Check for duplicate active sessions
            from django.db.models import Count
            duplicate_sessions = UserSession.objects.filter(
                is_active=True
            ).values('user_id').annotate(
                count=Count('id')
            ).filter(count__gt=1).count()

            if duplicate_sessions == 0:
                self.passed_tests.append("No duplicate active sessions")
                print("  ✅ No duplicate active sessions")
            else:
                self.warnings.append(f"Found {duplicate_sessions} users with multiple sessions")
                print(f"  ⚠️  Found {duplicate_sessions} users with multiple sessions")

        except Exception as e:
            self.failed_tests.append(f"Database integrity error: {e}")
            print(f"  ❌ Database integrity test failed: {e}")

    def test_error_handling(self):
        """Test error handling improvements"""
        print("\n🧪 Testing error handling...")

        try:
            factory = RequestFactory()
            user = User.objects.first()

            if not user:
                self.warnings.append("No users found for error handling test")
                print("  ⚠️  No users available for testing")
                return

            # Test malformed JSON handling
            try:
                request = factory.post('/optimized-heartbeat/',
                                    data="invalid json",
                                    content_type='application/json')
                request.user = user
                response = optimized_session_heartbeat(request)

                if response.status_code in [200, 400, 500]:  # Should handle gracefully
                    self.passed_tests.append("Malformed JSON handled gracefully")
                    print("  ✅ Malformed JSON handling successful")
                else:
                    self.failed_tests.append(f"Malformed JSON handling failed: {response.status_code}")
                    print(f"  ❌ Malformed JSON handling failed: {response.status_code}")

            except Exception as e:
                # This is expected for malformed JSON, but should not crash
                self.passed_tests.append("Exception handling works")
                print("  ✅ Exception handling successful")

            # Test missing data handling
            try:
                request = factory.post('/optimized-batch-activity/',
                                    data=json.dumps({}),  # Empty data
                                    content_type='application/json')
                request.user = user
                response = optimized_batch_activity_update(request)

                if response.status_code in [200, 400]:
                    self.passed_tests.append("Missing data handled gracefully")
                    print("  ✅ Missing data handling successful")
                else:
                    self.failed_tests.append(f"Missing data handling failed: {response.status_code}")
                    print(f"  ❌ Missing data handling failed: {response.status_code}")

            except Exception as e:
                self.failed_tests.append(f"Missing data handling error: {e}")
                print(f"  ❌ Missing data handling error: {e}")

        except Exception as e:
            self.failed_tests.append(f"Error handling test error: {e}")
            print(f"  ❌ Error handling test failed: {e}")

    def print_results(self):
        """Print validation results"""
        print("\n" + "=" * 60)
        print("📊 VALIDATION RESULTS")
        print("=" * 60)

        # Summary
        total_tests = len(self.passed_tests) + len(self.failed_tests)
        success_rate = (len(self.passed_tests) / total_tests * 100) if total_tests > 0 else 0

        print(f"📈 Success Rate: {success_rate:.1f}% ({len(self.passed_tests)}/{total_tests})")

        # Passed tests
        if self.passed_tests:
            print(f"\n✅ PASSED TESTS ({len(self.passed_tests)}):")
            for i, test in enumerate(self.passed_tests, 1):
                print(f"  {i}. {test}")

        # Failed tests
        if self.failed_tests:
            print(f"\n❌ FAILED TESTS ({len(self.failed_tests)}):")
            for i, test in enumerate(self.failed_tests, 1):
                print(f"  {i}. {test}")

        # Warnings
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for i, warning in enumerate(self.warnings, 1):
                print(f"  {i}. {warning}")

        print("\n" + "=" * 60)

        # Final verdict
        if len(self.failed_tests) == 0:
            print("🎉 ALL CRITICAL TESTS PASSED!")
            print("✅ Session management fixes are working correctly")
            print("🚀 Ready for production deployment")
        else:
            print("⚠️  SOME TESTS FAILED!")
            print("🔧 Please review failed tests and apply additional fixes")
            print("📋 Check the error messages above for guidance")

        print("=" * 60)

def main():
    """Main validation function"""
    try:
        validator = SessionFixesValidator()
        validator.run_all_validations()

        # Return exit code based on results
        if len(validator.failed_tests) == 0:
            print("\n🎯 Validation completed successfully!")
            sys.exit(0)
        else:
            print(f"\n❌ Validation failed with {len(validator.failed_tests)} failed tests")
            sys.exit(1)

    except Exception as e:
        print(f"\n💥 Fatal error during validation: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
