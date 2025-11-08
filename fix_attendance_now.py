#!/usr/bin/env python
"""
CRITICAL FIX: Mark all users with active sessions as Present
This fixes the bug where users are logged in but attendance shows 'Weekend' or 'Not Marked'
"""

import os
import sys
import django

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Setup Django (ardurTrueAlign is the main Django project)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from trueAlign.models import UserSession, Attendance
from datetime import date, datetime, timedelta
from django.utils import timezone
import pytz

def fix_attendance():
    # Use IST timezone to match your location
    IST = pytz.timezone('Asia/Kolkata')
    now_ist = timezone.now().astimezone(IST)
    today = now_ist.date()
    
    print(f"\n{'='*60}")
    print(f"🔧 FIXING ATTENDANCE FOR: {today} (IST)")
    print(f"Current time: {now_ist.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"{'='*60}\n")
    
    # Debug: Check total sessions in database
    total_sessions = UserSession.objects.count()
    print(f"📊 Total sessions in database: {total_sessions}")
    
    # Get all sessions from today - use date range to handle timezone correctly
    start_of_day = datetime.combine(today, datetime.min.time())
    end_of_day = datetime.combine(today, datetime.max.time())
    
    # Make timezone-aware
    start_of_day = IST.localize(start_of_day)
    end_of_day = IST.localize(end_of_day)
    
    print(f"Searching for sessions between {start_of_day} and {end_of_day}\n")
    
    # Get all sessions from today (don't filter by is_active!)
    sessions_today = UserSession.objects.filter(
        login_time__gte=start_of_day,
        login_time__lte=end_of_day
    ).select_related('user').order_by('user', '-login_time')
    
    print(f"📊 Found {sessions_today.count()} total sessions today")
    
    # Get unique users
    seen_users = set()
    unique_sessions = []
    for session in sessions_today:
        if session.user.id not in seen_users:
            seen_users.add(session.user.id)
            unique_sessions.append(session)
    
    print(f"📊 Found {len(unique_sessions)} unique users with sessions today\n")
    
    # Debug: Show the sessions we found
    if unique_sessions:
        print("Sessions found:")
        for s in unique_sessions:
            print(f"  - User: {s.user.username}, Login: {s.login_time}, Active: {s.is_active}")
        print()
    
    fixed_count = 0
    already_present = 0
    
    for session in unique_sessions:
        user = session.user
        print(f"\nProcessing {user.username}...")
        
        # Get or create attendance
        attendance, created = Attendance.objects.get_or_create(
            user=user,
            date=today,
            defaults={
                'status': 'Present',
                'clock_in_time': session.login_time,
                'first_session': session,
                'location': 'Office'
            }
        )
        
        if created:
            print(f"✅ CREATED: {user.username} - marked as Present")
            fixed_count += 1
        elif attendance.status in ['Not Marked', None, '', 'Weekend', 'Holiday', 'Yet to Clock In']:
            # Update to Present - including Weekend/Holiday if they logged in!
            old_status = attendance.status
            attendance.status = 'Present'
            
            # If was weekend/holiday, override flags since they're working
            if old_status in ['Weekend', 'Holiday']:
                attendance.is_weekend = False
                attendance.is_holiday = False
            
            if not attendance.clock_in_time:
                attendance.clock_in_time = session.login_time
            if not attendance.first_session:
                attendance.first_session = session
            attendance.save()
            print(f"✅ FIXED: {user.username} - changed from '{old_status or 'Not Marked'}' to Present")
            fixed_count += 1
        else:
            print(f"ℹ️  SKIP: {user.username} - already marked as '{attendance.status}'")
            already_present += 1
    
    print(f"\n{'='*60}")
    print(f"📈 SUMMARY:")
    print(f"   - Fixed/Created: {fixed_count}")
    print(f"   - Already Present: {already_present}")
    print(f"   - Total Users: {len(unique_sessions)}")
    print(f"{'='*60}\n")
    
    # Show current stats
    print("📊 CURRENT ATTENDANCE STATS:")
    from django.db.models import Count
    stats = Attendance.objects.filter(date=today).values('status').annotate(count=Count('id'))
    for stat in stats:
        print(f"   - {stat['status']}: {stat['count']}")
    
    print(f"\n✅ DONE! Check HR Dashboard now!\n")

if __name__ == '__main__':
    fix_attendance()
