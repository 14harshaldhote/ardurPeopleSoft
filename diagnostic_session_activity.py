#!/usr/bin/env python
"""
Diagnostic script to check session activity recording
"""
import os
import django
import sys

# Setup Django
sys.path.append('/Users/harshalsmac/WORK/ardur/ardurHome')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from trueAlign.models import UserSession, SessionActivity
from trueAlign.core import get_batch_writer
from django.contrib.auth import get_user_model

User = get_user_model()

print("="*60)
print("SESSION ACTIVITY DIAGNOSTIC")
print("="*60)

# Check SessionActivity table
print("\n1. Checking SessionActivity table...")
total_activities = SessionActivity.objects.count()
print(f"   Total activities in database: {total_activities}")

if total_activities > 0:
    recent = SessionActivity.objects.order_by('-created_at')[:5]
    print("\n   Recent activities:")
    for act in recent:
        print(f"   - {act.created_at} | {act.activity_type} | Session: {act.session_id}")
else:
    print("   ⚠️  NO ACTIVITIES FOUND IN DATABASE")

# Check UserSession table
print("\n2. Checking UserSession table...")
total_sessions = UserSession.objects.count()
active_sessions = UserSession.objects.filter(is_active=True).count()
print(f"   Total sessions: {total_sessions}")
print(f"   Active sessions: {active_sessions}")

# Check batch writer
print("\n3. Checking Batch Writer...")
try:
    batch_writer = get_batch_writer()
    if batch_writer:
        metrics = batch_writer.get_metrics()
        print(f"   ✓ Batch writer initialized")
        print(f"   - Total buffered activities: {metrics.get('total_buffered_activities', 0)}")
        print(f"   - Active users in buffer: {metrics.get('active_users', 0)}")
        print(f"   - Successful writes: {metrics.get('successful_writes', 0)}")
        print(f"   - Failed writes: {metrics.get('failed_writes', 0)}")
        print(f"   - Retry queue size: {metrics.get('retry_queue_size', 0)}")
        
        # Check if background threads are alive
        if batch_writer._flush_thread and batch_writer._flush_thread.is_alive():
            print(f"   ✓ Flush thread is RUNNING")
        else:
            print(f"   ✗ Flush thread is NOT running")
            
        if batch_writer._retry_thread and batch_writer._retry_thread.is_alive():
            print(f"   ✓ Retry thread is RUNNING")
        else:
            print(f"   ✗ Retry thread is NOT running")
    else:
        print("   ✗ Batch writer is None!")
except Exception as e:
    print(f"   ✗ Error checking batch writer: {e}")

# Test activity recording
print("\n4. Testing activity recording...")
try:
    from django.utils import timezone
    
    # Get a real user
    user = User.objects.first()
    if user:
        print(f"   Using user: {user.username}")
        
        # Get or create a session
        session = UserSession.objects.filter(user=user, is_active=True).first()
        
        if not session:
            session = UserSession.objects.create(
                user=user,
                session_key='test_diagnostic_session',
                ip_address='127.0.0.1',
                login_time=timezone.now()
            )
            print(f"   Created test session: {session.id}")
        else:
            print(f"   Using existing session: {session.id}")
        
        # Try to record an activity
        print(f"   Recording test activity...")
        SessionActivity.record_activity(
            session=session,
            activity_type='heartbeat',
            activity_data={'test': True, 'source': 'diagnostic_script'},
            url='/diagnostic/test',
            title='Diagnostic Test'
        )
        
        print(f"   ✓ Activity recorded (queued in batch writer)")
        
        # Check buffer
        if batch_writer:
            metrics = batch_writer.get_metrics()
            print(f"   - Activities now in buffer: {metrics.get('total_buffered_activities', 0)}")
            
            # Force flush to test if it works
            print(f"\n   Forcing buffer flush...")
            batch_writer.force_flush_all()
            
            # Check database again
            import time
            time.sleep(1)  # Wait for flush to complete
            
            new_count = SessionActivity.objects.count()
            print(f"   - Activities in DB after flush: {new_count}")
            
            if new_count > total_activities:
                print(f"   ✓ SUCCESS! {new_count - total_activities} new activities written")
            else:
                print(f"   ✗ FAILED! No new activities in database")
    else:
        print("   ✗ No users found in database")
        
except Exception as e:
    print(f"   ✗ Error during test: {e}")
    import traceback
    traceback.print_exc()

print("\n" + "="*60)
print("DIAGNOSTIC COMPLETE")
print("="*60)
