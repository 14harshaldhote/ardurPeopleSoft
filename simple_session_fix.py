#!/usr/bin/env python3
"""
Simple Session Cleanup Script
Fixes the most critical session management issues
"""

import os
import sys
import django
from django.conf import settings

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

import logging
from django.db import transaction
from django.core.cache import cache
from django.utils import timezone
from django.contrib.auth.models import User
from trueAlign.models import UserSession, Attendance

def cleanup_duplicate_sessions():
    """Clean up duplicate active sessions"""
    print("🔄 Cleaning up duplicate sessions...")

    try:
        with transaction.atomic():
            # Get users with multiple active sessions
            from django.db.models import Count

            users_with_duplicates = UserSession.objects.filter(
                is_active=True
            ).values('user_id').annotate(
                count=Count('id')
            ).filter(count__gt=1)

            fixed_count = 0
            for user_data in users_with_duplicates:
                user_id = user_data['user_id']

                # Get all active sessions for this user, ordered by last activity
                sessions = UserSession.objects.filter(
                    user_id=user_id,
                    is_active=True
                ).order_by('-last_activity')

                # Keep the most recent, deactivate the rest
                for session in sessions[1:]:  # Skip the first (most recent)
                    session.is_active = False
                    session.ended_at = timezone.now()
                    session.logout_time = timezone.now()
                    session.save()
                    fixed_count += 1

            print(f"  ✓ Fixed {fixed_count} duplicate sessions")

    except Exception as e:
        print(f"  ❌ Error: {e}")

def fix_invalid_sessions():
    """Fix sessions with invalid states"""
    print("🔧 Fixing invalid session states...")

    try:
        with transaction.atomic():
            # Fix sessions that are marked active but have end times
            invalid_active = UserSession.objects.filter(
                is_active=True,
                ended_at__isnull=False
            ).update(is_active=False)

            # Fix sessions missing logout times
            missing_logout = UserSession.objects.filter(
                is_active=False,
                ended_at__isnull=False,
                logout_time__isnull=True
            ).update(logout_time=timezone.now())

            print(f"  ✓ Fixed {invalid_active} invalid active sessions")
            print(f"  ✓ Fixed {missing_logout} missing logout times")

    except Exception as e:
        print(f"  ❌ Error: {e}")

def clear_cache():
    """Clear all caches safely"""
    print("🗑️  Clearing caches...")

    try:
        cache.clear()
        print("  ✓ All caches cleared")
    except Exception as e:
        print(f"  ❌ Error clearing cache: {e}")

def main():
    """Main function"""
    print("🚀 Starting simple session cleanup...")

    cleanup_duplicate_sessions()
    fix_invalid_sessions()
    clear_cache()

    print("\n✅ Session cleanup completed!")
    print("   Please restart your Django server now.")

if __name__ == "__main__":
    main()
