#!/usr/bin/env python
"""
DEEP DIAGNOSTIC: Check every step of the attendance flow
"""

import os
import sys
import django

project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from trueAlign.models import UserSession, Attendance
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.db.models.signals import post_save
import pytz
from datetime import datetime

User = get_user_model()
IST = pytz.timezone('Asia/Kolkata')

def deep_diagnostic():
    now_ist = timezone.now().astimezone(IST)
    today = now_ist.date()
    
    print(f"\n{'='*70}")
    print(f"🔍 DEEP DIAGNOSTIC - ATTENDANCE SYSTEM")
    print(f"Time: {now_ist.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"{'='*70}\n")
    
    # Step 1: Check if signals are registered
    print("1️⃣  CHECKING SIGNAL REGISTRATION")
    print("-" * 70)
    
    from trueAlign.attendance import signals as att_signals
    receivers = post_save._live_receivers(UserSession)
    
    print(f"   Post-save receivers for UserSession: {len(receivers)}")
    for receiver in receivers:
        print(f"   ✓ {receiver}")
    
    if not receivers:
        print("   ❌ NO SIGNALS REGISTERED! This is the problem!")
    print()
    
    # Step 2: Check active sessions
    print("2️⃣  CHECKING ACTIVE SESSIONS")
    print("-" * 70)
    
    start_of_day = IST.localize(datetime.combine(today, datetime.min.time()))
    end_of_day = IST.localize(datetime.combine(today, datetime.max.time()))
    
    active_sessions = UserSession.objects.filter(is_active=True)
    print(f"   Total active sessions: {active_sessions.count()}")
    
    sessions_today = UserSession.objects.filter(
        login_time__gte=start_of_day,
        login_time__lte=end_of_day
    )
    print(f"   Sessions today: {sessions_today.count()}")
    
    for session in sessions_today:
        login_ist = session.login_time.astimezone(IST)
        print(f"   → {session.user.username}: {login_ist.strftime('%H:%M:%S')} (Active: {session.is_active})")
    print()
    
    # Step 3: Check attendance records
    print("3️⃣  CHECKING ATTENDANCE RECORDS")
    print("-" * 70)
    
    today_attendance = Attendance.objects.filter(date=today)
    print(f"   Attendance records today: {today_attendance.count()}")
    
    for att in today_attendance:
        clock_in_str = att.clock_in_time.astimezone(IST).strftime('%H:%M:%S') if att.clock_in_time else 'NULL'
        first_session_str = str(att.first_session.id)[:8] if att.first_session else 'NULL'
        print(f"   → {att.user.username}:")
        print(f"      Status: {att.status}")
        print(f"      Clock In: {clock_in_str}")
        print(f"      First Session: {first_session_str}")
        print(f"      Is Weekend: {att.is_weekend}")
    print()
    
    # Step 4: Try manual signal processing
    print("4️⃣  TESTING SIGNAL PROCESSING")
    print("-" * 70)
    
    if sessions_today.exists():
        test_session = sessions_today.first()
        user = test_session.user
        
        print(f"   Testing with session: {test_session.id}")
        print(f"   User: {user.username}")
        
        # Try to manually process
        try:
            from trueAlign.attendance.services import AttendanceIntegrationService
            
            service = AttendanceIntegrationService()
            result = service.process_session_login(user, test_session)
            
            print(f"   Manual processing result: {result.success}")
            print(f"   Message: {result.message}")
            
            if result.success:
                # Check if attendance was updated
                att = Attendance.objects.get(user=user, date=today)
                clock_in_str = att.clock_in_time.astimezone(IST).strftime('%H:%M:%S') if att.clock_in_time else 'NULL'
                print(f"   ✅ Attendance after manual processing:")
                print(f"      Status: {att.status}")
                print(f"      Clock In: {clock_in_str}")
            else:
                print(f"   ❌ Manual processing failed!")
                
        except Exception as e:
            print(f"   ❌ Error during manual processing: {e}")
            import traceback
            traceback.print_exc()
    else:
        print(f"   ⚠️  No sessions today to test")
    print()
    
    # Step 5: Check cron job status
    print("5️⃣  CHECKING CRON JOB STATUS")
    print("-" * 70)
    
    from django.core.cache import cache
    
    last_auto_marking = cache.get('last_auto_marking_completion')
    if last_auto_marking:
        print(f"   Last auto-marking: {last_auto_marking}")
    else:
        print(f"   ⚠️  No recent auto-marking run")
    
    last_creation = cache.get('last_daily_creation_completion')
    if last_creation:
        print(f"   Last daily creation: {last_creation}")
    else:
        print(f"   ⚠️  No recent daily creation run")
    print()
    
    # Step 6: Summary and recommendations
    print("=" * 70)
    print("📊 SUMMARY")
    print("=" * 70)
    
    issues = []
    
    if not receivers:
        issues.append("❌ Signals NOT registered")
    
    if active_sessions.count() > 0 and today_attendance.filter(status='Weekend').count() > 0:
        issues.append("❌ Active sessions but attendance still 'Weekend'")
    
    if sessions_today.count() > 0:
        for session in sessions_today:
            try:
                att = Attendance.objects.get(user=session.user, date=today)
                if not att.clock_in_time:
                    issues.append(f"❌ {session.user.username}: Has session but no clock_in_time")
                if att.status in ['Weekend', 'Not Marked']:
                    issues.append(f"❌ {session.user.username}: Has session but status is '{att.status}'")
            except Attendance.DoesNotExist:
                issues.append(f"❌ {session.user.username}: Has session but no attendance record")
    
    if issues:
        print("\n⚠️  ISSUES FOUND:")
        for issue in issues:
            print(f"   {issue}")
        
        print("\n🔧 FIXING NOW...")
        fix_issues()
    else:
        print("\n✅ Everything looks good!")
    
    print()

def fix_issues():
    """Fix all identified issues"""
    now_ist = timezone.now().astimezone(IST)
    today = now_ist.date()
    
    start_of_day = IST.localize(datetime.combine(today, datetime.min.time()))
    end_of_day = IST.localize(datetime.combine(today, datetime.max.time()))
    
    sessions_today = UserSession.objects.filter(
        login_time__gte=start_of_day,
        login_time__lte=end_of_day
    )
    
    from trueAlign.attendance.services import AttendanceIntegrationService
    service = AttendanceIntegrationService()
    
    fixed = 0
    for session in sessions_today:
        user = session.user
        
        # Get or create attendance
        att, created = Attendance.objects.get_or_create(
            user=user,
            date=today,
            defaults={
                'status': 'Present',
                'clock_in_time': session.login_time.astimezone(IST),
                'first_session': session,
                'location': 'Office',
                'is_weekend': False,
                'is_holiday': False,
            }
        )
        
        if created:
            print(f"   ✅ Created attendance for {user.username}")
            fixed += 1
        elif att.status in ['Weekend', 'Holiday', 'Not Marked'] or not att.clock_in_time:
            old_status = att.status
            att.status = 'Present'
            att.clock_in_time = att.clock_in_time or session.login_time.astimezone(IST)
            att.first_session = att.first_session or session
            att.is_weekend = False
            att.is_holiday = False
            att.save()
            print(f"   ✅ Fixed {user.username}: {old_status} → Present")
            fixed += 1
    
    print(f"\n   Fixed {fixed} attendance records")
    print(f"   ✅ Done! Refresh your dashboard.")

if __name__ == '__main__':
    deep_diagnostic()
