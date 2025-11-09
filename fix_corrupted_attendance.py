#!/usr/bin/env python
"""
FIX CORRUPTED ATTENDANCE: Clear clock_out_time when clock_in_time is NULL
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
import pytz
from datetime import datetime

User = get_user_model()
IST = pytz.timezone('Asia/Kolkata')

def fix_corrupted_attendance():
    now_ist = timezone.now().astimezone(IST)
    today = now_ist.date()
    
    print(f"\n{'='*70}")
    print(f"🔧 FIXING CORRUPTED ATTENDANCE RECORDS")
    print(f"{'='*70}\n")
    
    # Find all attendance with clock_out but no clock_in
    corrupted = Attendance.objects.filter(
        clock_in_time__isnull=True,
        clock_out_time__isnull=False
    )
    
    print(f"Found {corrupted.count()} corrupted records (clock_out but no clock_in)\n")
    
    for att in corrupted:
        print(f"Fixing {att.user.username} on {att.date}:")
        print(f"   Before: clock_in=NULL, clock_out={att.clock_out_time}")
        
        # Clear the corrupted clock_out_time
        att.clock_out_time = None
        att.last_session = None
        att.total_hours = None
        att.save(update_fields=['clock_out_time', 'last_session', 'total_hours'])
        
        print(f"   After: Cleared clock_out_time")
        print()
    
    # Now process today's sessions properly
    print(f"{'='*70}")
    print(f"📊 PROCESSING TODAY'S SESSIONS")
    print(f"{'='*70}\n")
    
    start_of_day = IST.localize(datetime.combine(today, datetime.min.time()))
    end_of_day = IST.localize(datetime.combine(today, datetime.max.time()))
    
    sessions_today = UserSession.objects.filter(
        login_time__gte=start_of_day,
        login_time__lte=end_of_day
    ).select_related('user').order_by('user', 'login_time')
    
    # Group by user to get first and last session
    user_sessions = {}
    for session in sessions_today:
        if session.user.id not in user_sessions:
            user_sessions[session.user.id] = {
                'user': session.user,
                'first_session': session,
                'last_session': session
            }
        else:
            user_sessions[session.user.id]['last_session'] = session
    
    print(f"Processing {len(user_sessions)} users\n")
    
    from trueAlign.attendance.services import AttendanceIntegrationService
    
    fixed_count = 0
    for user_id, data in user_sessions.items():
        user = data['user']
        first_session = data['first_session']
        last_session = data['last_session']
        
        print(f"👤 {user.username}:")
        
        # Get or create attendance
        att, created = Attendance.objects.get_or_create(
            user=user,
            date=today,
            defaults={
                'status': 'Present',
                'location': 'Office',
                'is_weekend': False,
                'is_holiday': False,
            }
        )
        
        # Set clock_in from first session
        login_time_ist = first_session.login_time.astimezone(IST)
        att.clock_in_time = login_time_ist
        att.first_session = first_session
        
        # Set status to Present (override Weekend)
        if att.status in ['Weekend', 'Holiday', 'Not Marked']:
            att.status = 'Present'
            att.is_weekend = False
            att.is_holiday = False
        
        # Set clock_out if last session has logout_time
        if last_session.logout_time:
            logout_time_ist = last_session.logout_time.astimezone(IST)
            att.clock_out_time = logout_time_ist
            att.last_session = last_session
            
            # Calculate total hours
            time_diff = logout_time_ist - login_time_ist
            total_seconds = time_diff.total_seconds()
            if total_seconds > 0:
                from decimal import Decimal
                att.total_hours = Decimal(str(round(total_seconds / 3600, 2)))
        
        # Skip validation to avoid errors
        att.save(update_fields=[
            'status', 'clock_in_time', 'clock_out_time', 'first_session',
            'last_session', 'total_hours', 'is_weekend', 'is_holiday', 'location'
        ])
        
        clock_in_str = login_time_ist.strftime('%H:%M:%S')
        clock_out_str = logout_time_ist.strftime('%H:%M:%S') if last_session.logout_time else '—'
        
        print(f"   ✅ {att.status}")
        print(f"   Clock In:  {clock_in_str}")
        print(f"   Clock Out: {clock_out_str}")
        print(f"   Total:     {att.total_hours or '—'}h")
        print()
        
        fixed_count += 1
    
    print(f"{'='*70}")
    print(f"✅ Fixed {fixed_count} attendance records")
    print(f"{'='*70}\n")
    
    print(f"🔄 Clearing cache...")
    from django.core.cache import cache
    cache.clear()
    
    print(f"✅ All done! Refresh your dashboard now!\n")

if __name__ == '__main__':
    fix_corrupted_attendance()
