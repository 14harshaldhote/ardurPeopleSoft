#!/usr/bin/env python
"""
FORCE MARK PRESENT: Manually mark all users with active sessions as Present
This bypasses the signal system
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

from trueAlign.models import UserSession, Attendance
from django.contrib.auth import get_user_model
from django.utils import timezone
import pytz
from datetime import datetime

User = get_user_model()
IST = pytz.timezone('Asia/Kolkata')

def force_mark_present():
    now_ist = timezone.now().astimezone(IST)
    today = now_ist.date()
    
    print(f"\n{'='*60}")
    print(f"🔥 FORCE MARKING PRESENT")
    print(f"Time: {now_ist.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"{'='*60}\n")
    
    # Get ALL active sessions (not just today, to catch any timezone issues)
    active_sessions = UserSession.objects.filter(
        is_active=True
    ).select_related('user').order_by('user', '-login_time')
    
    print(f"📊 Found {active_sessions.count()} active sessions\n")
    
    # Group by user (get latest session per user)
    user_sessions = {}
    for session in active_sessions:
        if session.user.id not in user_sessions:
            user_sessions[session.user.id] = session
    
    print(f"📊 Processing {len(user_sessions)} unique users\n")
    
    fixed_count = 0
    already_correct = 0
    
    for user_id, session in user_sessions.items():
        user = session.user
        login_time_ist = session.login_time.astimezone(IST)
        session_date = login_time_ist.date()
        
        print(f"👤 {user.username}:")
        print(f"   Session: {session.id[:8]}...")
        print(f"   Login: {login_time_ist.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"   Is Active: {session.is_active}")
        
        # Get or create attendance for the session's date
        attendance, created = Attendance.objects.get_or_create(
            user=user,
            date=session_date,
            defaults={
                'status': 'Present',
                'clock_in_time': login_time_ist,
                'first_session': session,
                'location': 'Office',
                'is_weekend': False,
                'is_holiday': False,
            }
        )
        
        if created:
            print(f"   ✅ CREATED attendance: Present")
            fixed_count += 1
        elif attendance.status not in ['Present', 'Present & Late']:
            old_status = attendance.status
            attendance.status = 'Present'
            attendance.clock_in_time = attendance.clock_in_time or login_time_ist
            attendance.first_session = attendance.first_session or session
            
            # Override weekend/holiday flags
            if old_status in ['Weekend', 'Holiday']:
                attendance.is_weekend = False
                attendance.is_holiday = False
            
            attendance.save()
            print(f"   ✅ FIXED: {old_status} → Present")
            fixed_count += 1
        else:
            print(f"   ℹ️  Already {attendance.status}")
            already_correct += 1
        
        print()
    
    print(f"{'='*60}")
    print(f"📈 SUMMARY:")
    print(f"   - Fixed/Created: {fixed_count}")
    print(f"   - Already Correct: {already_correct}")
    print(f"   - Total Users: {len(user_sessions)}")
    print(f"{'='*60}\n")
    
    # Show today's attendance
    print(f"📊 TODAY'S ATTENDANCE ({today}):")
    today_attendance = Attendance.objects.filter(date=today).select_related('user')
    
    if today_attendance.exists():
        for att in today_attendance:
            status_icon = "✅" if att.status in ['Present', 'Present & Late'] else "⚠️"
            clock_in_str = att.clock_in_time.astimezone(IST).strftime('%H:%M') if att.clock_in_time else '—'
            print(f"   {status_icon} {att.user.username}: {att.status} (In: {clock_in_str})")
    else:
        print(f"   (No attendance records for today)")
    
    print(f"\n✅ DONE! Refresh your dashboard now!\n")

if __name__ == '__main__':
    force_mark_present()
