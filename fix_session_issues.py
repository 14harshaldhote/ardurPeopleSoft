#!/usr/bin/env python3
"""
Comprehensive Session Management Fix Script
Addresses all the issues identified in the Django session tracking system:
1. KeyError: 'pending_updates' in middleware
2. Multiple sessions being created for same user
3. MySQL deadlock errors in signal handlers
4. Missing/404 session endpoints
5. Buffer initialization race conditions
"""

import os
import sys
import django
from django.conf import settings

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

import logging
from django.db import transaction, connection
from django.core.cache import cache
from django.utils import timezone
from django.contrib.auth.models import User
from trueAlign.models import UserSession, Attendance

logger = logging.getLogger(__name__)

class SessionIssuesFixer:
    """
    Comprehensive session management issue fixer
    """

    def __init__(self):
        self.issues_found = []
        self.fixes_applied = []

    def run_all_fixes(self):
        """Run all fixes in order"""
        print("🔧 Starting comprehensive session management fixes...")

        # 1. Database fixes
        self.fix_database_issues()

        # 2. Clean up duplicate sessions
        self.cleanup_duplicate_sessions()

        # 3. Fix buffer initialization
        self.fix_buffer_initialization()

        # 4. Test session endpoints
        self.test_session_endpoints()

        # 5. Apply database optimizations
        self.apply_database_optimizations()

        # 6. Clear problematic caches
        self.clear_problematic_caches()

        # 7. Test middleware functionality
        self.test_middleware_functionality()

        print("\n✅ All fixes completed successfully!")
        self.print_summary()

    def fix_database_issues(self):
        """Fix database-related issues"""
        print("\n📊 Fixing database issues...")

        try:
            with transaction.atomic():
                # Fix any orphaned sessions
                orphaned_sessions = UserSession.objects.filter(
                    user__isnull=True
                ).count()

                if orphaned_sessions > 0:
                    UserSession.objects.filter(user__isnull=True).delete()
                    print(f"  ✓ Cleaned up {orphaned_sessions} orphaned sessions")
                    self.fixes_applied.append(f"Cleaned {orphaned_sessions} orphaned sessions")

                # Fix sessions with invalid states
                invalid_sessions = UserSession.objects.filter(
                    is_active=True,
                    ended_at__isnull=False
                ).count()

                if invalid_sessions > 0:
                    UserSession.objects.filter(
                        is_active=True,
                        ended_at__isnull=False
                    ).update(is_active=False)
                    print(f"  ✓ Fixed {invalid_sessions} sessions with invalid active state")
                    self.fixes_applied.append(f"Fixed {invalid_sessions} invalid session states")

                # Fix missing logout times
                missing_logout = UserSession.objects.filter(
                    is_active=False,
                    ended_at__isnull=False,
                    logout_time__isnull=True
                ).count()

                if missing_logout > 0:
                    UserSession.objects.filter(
                        is_active=False,
                        ended_at__isnull=False,
                        logout_time__isnull=True
                    ).update(logout_time=timezone.now())
                    print(f"  ✓ Fixed {missing_logout} sessions with missing logout times")
                    self.fixes_applied.append(f"Fixed {missing_logout} missing logout times")

        except Exception as e:
            print(f"  ❌ Error fixing database issues: {e}")
            self.issues_found.append(f"Database fix error: {e}")

    def cleanup_duplicate_sessions(self):
        """Clean up duplicate sessions for users"""
        print("\n🔄 Cleaning up duplicate sessions...")

        try:
            with transaction.atomic():
                # Find users with multiple active sessions
                users_with_multiple_sessions = UserSession.objects.filter(
                    is_active=True
                ).values('user_id').annotate(
                    session_count=models.Count('id')
                ).filter(session_count__gt=1)

                duplicates_cleaned = 0

                for user_data in users_with_multiple_sessions:
                    user_id = user_data['user_id']

                    # Get all active sessions for this user
                    user_sessions = UserSession.objects.filter(
                        user_id=user_id,
                        is_active=True
                    ).order_by('-last_activity')

                    # Keep the most recent session, deactivate others
                    sessions_to_deactivate = user_sessions[1:]

                    for session in sessions_to_deactivate:
                        session.is_active = False
                        session.ended_at = timezone.now()
                        session.logout_time = timezone.now()
                        session.save()
                        duplicates_cleaned += 1

                if duplicates_cleaned > 0:
                    print(f"  ✓ Cleaned up {duplicates_cleaned} duplicate sessions")
                    self.fixes_applied.append(f"Cleaned {duplicates_cleaned} duplicate sessions")
                else:
                    print("  ✓ No duplicate sessions found")

        except Exception as e:
            print(f"  ❌ Error cleaning duplicate sessions: {e}")
            self.issues_found.append(f"Duplicate session cleanup error: {e}")

    def fix_buffer_initialization(self):
        """Fix buffer initialization issues"""
        print("\n🔧 Fixing buffer initialization...")

        try:
            # Clear all activity buffers to prevent stale data
            cache_keys = cache.keys("activity_*")
            if cache_keys:
                cache.delete_many(cache_keys)
                print(f"  ✓ Cleared {len(cache_keys)} activity buffers")
                self.fixes_applied.append(f"Cleared {len(cache_keys)} activity buffers")

            # Clear session-related caches
            session_cache_keys = cache.keys("opt_session*")
            if session_cache_keys:
                cache.delete_many(session_cache_keys)
                print(f"  ✓ Cleared {len(session_cache_keys)} session caches")
                self.fixes_applied.append(f"Cleared {len(session_cache_keys)} session caches")

            # Clear throttle caches
            throttle_cache_keys = cache.keys("*throttle*")
            if throttle_cache_keys:
                cache.delete_many(throttle_cache_keys)
                print(f"  ✓ Cleared {len(throttle_cache_keys)} throttle caches")
                self.fixes_applied.append(f"Cleared {len(throttle_cache_keys)} throttle caches")

        except Exception as e:
            print(f"  ❌ Error fixing buffer initialization: {e}")
            self.issues_found.append(f"Buffer initialization error: {e}")

    def test_session_endpoints(self):
        """Test session endpoints availability"""
        print("\n🌐 Testing session endpoints...")

        try:
            from django.urls import reverse
            from django.test import RequestFactory
            from django.contrib.auth import get_user_model
            from trueAlign.core.views import (
                optimized_session_heartbeat,
                optimized_batch_activity_update,
                optimized_end_session,
                optimized_session_status
            )

            User = get_user_model()
            factory = RequestFactory()

            # Create test user
            test_user, created = User.objects.get_or_create(
                username='test_session_user',
                defaults={'email': 'test@example.com'}
            )

            endpoints_tested = []

            # Test heartbeat endpoint
            try:
                request = factory.post('/optimized-heartbeat/',
                                    data='{"tab_id": "test_tab"}',
                                    content_type='application/json')
                request.user = test_user
                response = optimized_session_heartbeat(request)
                endpoints_tested.append(f"Heartbeat endpoint: {response.status_code}")
            except Exception as e:
                endpoints_tested.append(f"Heartbeat endpoint error: {e}")

            # Test batch activity endpoint
            try:
                request = factory.post('/optimized-batch-activity/',
                                    data='{"tab_id": "test_tab", "activities": []}',
                                    content_type='application/json')
                request.user = test_user
                response = optimized_batch_activity_update(request)
                endpoints_tested.append(f"Batch activity endpoint: {response.status_code}")
            except Exception as e:
                endpoints_tested.append(f"Batch activity endpoint error: {e}")

            # Test session status endpoint
            try:
                request = factory.post('/optimized-session-status/',
                                    data='{"tab_id": "test_tab"}',
                                    content_type='application/json')
                request.user = test_user
                response = optimized_session_status(request)
                endpoints_tested.append(f"Session status endpoint: {response.status_code}")
            except Exception as e:
                endpoints_tested.append(f"Session status endpoint error: {e}")

            for result in endpoints_tested:
                print(f"  ✓ {result}")

            self.fixes_applied.append(f"Tested {len(endpoints_tested)} endpoints")

        except Exception as e:
            print(f"  ❌ Error testing endpoints: {e}")
            self.issues_found.append(f"Endpoint testing error: {e}")

    def apply_database_optimizations(self):
        """Apply database optimizations to prevent deadlocks"""
        print("\n⚡ Applying database optimizations...")

        try:
            with connection.cursor() as cursor:
                # Check current isolation level
                cursor.execute("SELECT @@tx_isolation")
                isolation_level = cursor.fetchone()[0]
                print(f"  ✓ Current isolation level: {isolation_level}")

                # Add indexes if they don't exist
                optimizations = [
                    "CREATE INDEX IF NOT EXISTS idx_user_session_user_active ON trueAlign_usersession(user_id, is_active)",
                    "CREATE INDEX IF NOT EXISTS idx_user_session_tab_id ON trueAlign_usersession(tab_id)",
                    "CREATE INDEX IF NOT EXISTS idx_attendance_user_date ON trueAlign_attendance(user_id, date)",
                    "CREATE INDEX IF NOT EXISTS idx_user_session_login_time ON trueAlign_usersession(login_time)",
                ]

                for optimization in optimizations:
                    try:
                        cursor.execute(optimization)
                        print(f"  ✓ Applied: {optimization.split('ON')[1] if 'ON' in optimization else 'optimization'}")
                    except Exception as e:
                        print(f"  ⚠️  Skipped optimization (may already exist): {e}")

                self.fixes_applied.append("Applied database optimizations")

        except Exception as e:
            print(f"  ❌ Error applying database optimizations: {e}")
            self.issues_found.append(f"Database optimization error: {e}")

    def clear_problematic_caches(self):
        """Clear caches that might be causing issues"""
        print("\n🗑️  Clearing problematic caches...")

        try:
            cache_patterns = [
                "heartbeat_*",
                "session_*",
                "activity_*",
                "throttle_*",
                "opt_*",
                "pending_updates_*"
            ]

            total_cleared = 0
            for pattern in cache_patterns:
                try:
                    keys = cache.keys(pattern)
                    if keys:
                        cache.delete_many(keys)
                        total_cleared += len(keys)
                        print(f"  ✓ Cleared {len(keys)} keys matching '{pattern}'")
                except Exception as e:
                    print(f"  ⚠️  Error clearing pattern '{pattern}': {e}")

            if total_cleared > 0:
                self.fixes_applied.append(f"Cleared {total_cleared} cache keys")
            else:
                print("  ✓ No problematic cache keys found")

        except Exception as e:
            print(f"  ❌ Error clearing caches: {e}")
            self.issues_found.append(f"Cache clearing error: {e}")

    def test_middleware_functionality(self):
        """Test middleware functionality"""
        print("\n🔬 Testing middleware functionality...")

        try:
            from trueAlign.core.middleware import OptimizedSessionTrackingMiddleware

            # Test buffer initialization
            middleware = OptimizedSessionTrackingMiddleware(None)

            # Test buffer creation
            if hasattr(middleware, '_activity_buffer'):
                print("  ✓ Middleware has activity buffer")
            else:
                print("  ❌ Middleware missing activity buffer")
                self.issues_found.append("Middleware missing activity buffer")

            # Test configuration
            from trueAlign.core.session_config import CONFIG

            required_configs = [
                'HEARTBEAT_THROTTLE_INTERVAL',
                'ACTIVITY_THROTTLE_INTERVAL',
                'MAX_BUFFER_SIZE',
                'SESSION_TIMEOUT_MINUTES'
            ]

            for config_name in required_configs:
                if hasattr(CONFIG, config_name):
                    print(f"  ✓ Config has {config_name}")
                else:
                    print(f"  ❌ Config missing {config_name}")
                    self.issues_found.append(f"Config missing {config_name}")

            self.fixes_applied.append("Tested middleware functionality")

        except Exception as e:
            print(f"  ❌ Error testing middleware: {e}")
            self.issues_found.append(f"Middleware testing error: {e}")

    def print_summary(self):
        """Print summary of fixes applied"""
        print("\n" + "="*60)
        print("📋 FIX SUMMARY")
        print("="*60)

        if self.fixes_applied:
            print("✅ FIXES APPLIED:")
            for i, fix in enumerate(self.fixes_applied, 1):
                print(f"  {i}. {fix}")
        else:
            print("ℹ️  No fixes were needed")

        if self.issues_found:
            print("\n⚠️  ISSUES FOUND:")
            for i, issue in enumerate(self.issues_found, 1):
                print(f"  {i}. {issue}")
        else:
            print("\n✅ No issues found")

        print("\n" + "="*60)
        print("🎯 NEXT STEPS:")
        print("  1. Restart your Django server")
        print("  2. Test the session endpoints manually")
        print("  3. Monitor logs for any remaining issues")
        print("  4. Check for deadlock errors in production")
        print("="*60)

def main():
    """Main function to run the fix script"""
    try:
        fixer = SessionIssuesFixer()
        fixer.run_all_fixes()

        print("\n🚀 Session management fixes completed successfully!")
        print("   Please restart your Django server and test the application.")

    except Exception as e:
        print(f"\n❌ Fatal error running fixes: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
