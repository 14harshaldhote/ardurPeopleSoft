#!/usr/bin/env python
"""
Test script to verify session data capture is working properly
"""
import os
import sys
import django
from datetime import datetime

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from django.contrib.auth.models import User
from trueAlign.models import UserSession, SessionActivity
from django.utils import timezone

def test_session_capture():
    """Test session data capture functionality"""
    print("🔍 Testing Session Data Capture...")
    
    # Get or create a test user
    user, created = User.objects.get_or_create(
        username='test_user',
        defaults={'email': 'test@example.com'}
    )
    
    print(f"✅ Using user: {user.username}")
    
    # Test data that would be sent from JavaScript
    test_client_data = {
        'ip_address': '127.0.0.1',
        'user_agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'session_fingerprint': 'test_fingerprint_123',
        'browser_fingerprint': 'test_fingerprint_123',
        'browser': 'Chrome',
        'os': 'MacOS',
        'device_type': 'desktop',
        'screen_resolution': '1920x1080',
        'timezone_offset': -330,
        'language': 'en-US',
        'battery_level': 85.5,
        'connection_type': 'wifi',
        'csrf_token': 'test_csrf_token',
        'url': 'http://127.0.0.1:8000/dashboard/',
        'title': 'Dashboard - ArdurTrueAlign',
        'referrer': 'http://127.0.0.1:8000/login/',
        'location_data': {
            'latitude': 19.0760,
            'longitude': 72.8777,
            'accuracy': 100.0
        }
    }
    
    # Test session creation
    print("\n📝 Testing session creation...")
    session, created = UserSession.get_or_create_session(
        user=user,
        tab_id='test_tab_123',
        parent_session_id=None,
        client_data=test_client_data,
        session_key=UserSession.generate_session_key()
    )
    
    print(f"✅ Session {'created' if created else 'found'}: {session.id}")
    print(f"   Browser: {session.browser}")
    print(f"   OS: {session.os}")
    print(f"   Device: {session.device_type}")
    print(f"   Screen: {session.screen_resolution}")
    print(f"   Location: {session.location_latitude}, {session.location_longitude}")
    
    # Test activity recording
    print("\n📊 Testing activity recording...")
    activity_data = {
        'is_idle': False,
        'is_visible': True,
        'productivity_score': 75.5,
        'engagement_score': 80.2,
        'browser': 'Chrome',
        'os': 'MacOS',
        'fingerprint': 'test_fingerprint_123',
        'device_type': 'desktop',
        'screen_resolution': '1920x1080',
        'timezone_offset': -330,
        'language': 'en-US',
        'battery_level': 85.5,
        'connection_type': 'wifi',
        'total_clicks': 15,
        'total_scrolls': 8,
        'total_keystrokes': 45,
        'total_mouse_moves': 120,
        'page_views': 3,
        'tab_switches': 2,
        'session_duration': 1800000,  # 30 minutes
        'idle_time': 300000,  # 5 minutes
        'working_time': 1500000,  # 25 minutes
        'performance_metrics': {
            'load_time': 1200,
            'dom_content_loaded': 800,
            'first_paint': 600
        },
        'viewport_width': 1920,
        'viewport_height': 1080,
        'color_depth': 24,
        'pixel_depth': 24,
        'available_memory': 8,
        'hardware_concurrency': 8,
        'cookie_enabled': True,
        'do_not_track': None,
        'platform': 'MacIntel',
        'vendor': 'Google Inc.',
        'java_enabled': False,
        'on_line': True,
        'timestamp': timezone.now().isoformat()
    }
    
    activity = SessionActivity.record_activity(
        session=session,
        activity_type='heartbeat',
        activity_data=activity_data,
        url='http://127.0.0.1:8000/dashboard/',
        title='Dashboard - ArdurTrueAlign',
        location_data=test_client_data.get('location_data')
    )
    
    if activity:
        print(f"✅ Activity recorded: {activity.id}")
        print(f"   Type: {activity.activity_type}")
        print(f"   URL: {activity.url}")
        print(f"   Productivity Score: {activity.productivity_score}")
        print(f"   Engagement Score: {activity.engagement_score}")
    else:
        print("❌ Failed to record activity")
    
    # Test session update
    print("\n🔄 Testing session update...")
    session.browser = 'Firefox'
    session.os = 'Windows'
    session.device_type = 'laptop'
    session.screen_resolution = '1366x768'
    session.save()
    
    print(f"✅ Session updated")
    print(f"   Browser: {session.browser}")
    print(f"   OS: {session.os}")
    print(f"   Device: {session.device_type}")
    print(f"   Screen: {session.screen_resolution}")
    
    # Test activity summary
    print("\n📈 Testing activity summary...")
    summary = SessionActivity.get_activity_summary(session)
    print(f"✅ Activity summary: {summary}")
    
    # Test recent activities
    print("\n⏰ Testing recent activities...")
    recent = SessionActivity.get_recent_activities(session, hours=1)
    print(f"✅ Recent activities: {recent.count()}")
    
    print("\n🎉 Session data capture test completed successfully!")
    return True

if __name__ == '__main__':
    try:
        test_session_capture()
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)