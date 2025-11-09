#!/usr/bin/env python
"""
Clear dashboard cache to force reload with fresh data
"""

import os
import sys
import django

# Setup Django
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.core.cache import cache
from django.contrib.auth import get_user_model

User = get_user_model()

def clear_caches():
    print(f"\n{'='*60}")
    print(f"🗑️  CLEARING DASHBOARD CACHES")
    print(f"{'='*60}\n")
    
    users = User.objects.all()
    
    cleared_count = 0
    for user in users:
        # Clear dashboard cache
        cache_key = f'dashboard_context_{user.id}'
        cache.delete(cache_key)
        
        # Clear user-specific attendance caches
        cache.delete(f'attendance:{user.id}:*')
        cache.delete(f'user_attendance_today:{user.id}')
        cache.delete(f'user_attendance_{user.id}')
        
        print(f"✅ Cleared cache for: {user.username}")
        cleared_count += 1
    
    # Clear global cache (if supported)
    try:
        cache.clear()
        print(f"\n✅ Cleared entire cache!")
    except AttributeError:
        print(f"\n✅ Cleared {cleared_count} user-specific caches")
    
    print(f"\n✅ All caches cleared! Refresh your dashboard.\n")

if __name__ == '__main__':
    clear_caches()
