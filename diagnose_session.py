#!/usr/bin/env python
"""
DIAGNOSTIC: Check current session and attendance state
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

User = get_user_model()
IST = pytz.timezone('Asia/Kolkata')

def diagnose():
    now_ist = timezone.now().astimezone(IST)
    today = now_ist.date()
    
    # Create timezone-aware date range for today in IST
    from datetime import datetime
    start_of_day = IST.localize(datetime.combine(today, datetime.min.time()))
    end_of_day = IST.localize(datetime.combine(today, datetime.max.time()))
    
    print(f"\n{'='*60}")
    print(f"🔍 DIAGNOSTIC REPORT")
    print(f"Time: {now_ist.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"Date Range: {start_of_day.strftime('%Y-%m-%d %H:%M')} to {end_of_day.strftime('%Y-%m-%d %H:%M')}")
    print(f"{'='*60}\n")
    
    # Get ALL sessions (for debugging)
    all_sessions = UserSession.objects.all().order_by('-login_time')[:10]
    print(f"📊 Last 10 Sessions in Database:")
    for s in all_sessions:
        login_ist = s.login_time.astimezone(IST)
        print(f"   {s.user.username}: {login_ist.strftime('%Y-%m-%d %H:%M:%S %Z')} (Active: {s.is_active})")
    print()
    
    # Get sessions today using timezone-aware range
    sessions_today = UserSession.objects.filter(
        login_time__gte=start_of_day,
        login_time__lte=end_of_day
    ).select_related('user').order_by('-login_time')
    
    print(f"📊 Sessions Today: {sessions_today.count()}\n")
    
    for session in sessions_today:
        user = session.user
        print(f"{'='*60}")
        print(f"👤 USER: {user.username} (ID: {user.id})")
        print(f"{'='*60}")
        
        # Session details
        login_time_ist = session.login_time.astimezone(IST)
        print(f"\n🔐 SESSION:")
        print(f"   ID:         {session.id}")
        print(f"   Login:      {login_time_ist.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        print(f"   Is Active:  {session.is_active}")
        print(f"   Logout:     {session.logout_time.astimezone(IST).strftime('%Y-%m-%d %H:%M:%S %Z') if session.logout_time else 'Still Active'}")
        
        # Attendance details
        try:
            attendance = Attendance.objects.get(user=user, date=today)
            print(f"\n✓ ATTENDANCE FOUND:")
            print(f"   Status:        {attendance.status}")
            print(f"   Clock In:      {attendance.clock_in_time.astimezone(IST).strftime('%H:%M:%S') if attendance.clock_in_time else 'NOT SET'}")
            print(f"   Clock Out:     {attendance.clock_out_time.astimezone(IST).strftime('%H:%M:%S') if attendance.clock_out_time else 'NOT SET'}")
            print(f"   Total Hours:   {attendance.total_hours or 'NOT SET'}")
            print(f"   First Session: {attendance.first_session.id if attendance.first_session else 'NOT SET'}")
            print(f"   Is Weekend:    {attendance.is_weekend}")
            print(f"   Is Holiday:    {attendance.is_holiday}")
            
            # Check if status needs fixing
            if attendance.status in ['Weekend', 'Holiday', 'Not Marked'] and session.is_active:
                print(f"\n⚠️  ISSUE DETECTED!")
                print(f"   → User has ACTIVE session but status is '{attendance.status}'")
                print(f"   → This should be 'Present'!")
                
                print(f"\n🔧 FIXING NOW...")
                old_status = attendance.status
                attendance.status = 'Present'
                attendance.clock_in_time = login_time_ist
                attendance.first_session = session
                
                if old_status in ['Weekend', 'Holiday']:
                    attendance.is_weekend = False
                    attendance.is_holiday = False
                
                attendance.save()
                print(f"✅ FIXED: {user.username} changed from '{old_status}' to 'Present'")
            else:
                print(f"\n✓ Status looks correct")
                
        except Attendance.DoesNotExist:
            print(f"\n❌ NO ATTENDANCE RECORD FOUND!")
            print(f"   Creating now...")
            
            attendance = Attendance.objects.create(
                user=user,
                date=today,
                status='Present',
                clock_in_time=login_time_ist,
                first_session=session,
                location='Office'
            )
            print(f"✅ CREATED attendance for {user.username}")
        
        print()
    
    print(f"\n{'='*60}")
    print(f"📊 FINAL ATTENDANCE SUMMARY")
    print(f"{'='*60}\n")
    
    today_attendance = Attendance.objects.filter(date=today)
    for att in today_attendance:
        status_icon = "✅" if att.status == 'Present' else "⚠️"
        print(f"{status_icon} {att.user.username}: {att.status} (Clock In: {att.clock_in_time.astimezone(IST).strftime('%H:%M') if att.clock_in_time else '—'})")
    
    print(f"\n✅ Diagnosis Complete! Refresh your dashboard.\n")

if __name__ == '__main__':
    diagnose()
