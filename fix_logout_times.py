#!/usr/bin/env python
"""
FIX: Process all sessions with logout_time to update attendance clock_out_time and total_hours
This fixes the bug where sessions were logged out but attendance wasn't updated
"""

import os
import sys
import django

# Add project root to Python path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurTrueAlign.settings')
django.setup()

from trueAlign.models import UserSession, Attendance
from datetime import date, datetime, timedelta
from django.utils import timezone
from decimal import Decimal
import pytz

def fix_logout_times():
    IST = pytz.timezone('Asia/Kolkata')
    now_ist = timezone.now().astimezone(IST)
    
    print(f"\n{'='*60}")
    print(f"🔧 FIXING LOGOUT TIMES AND TOTAL HOURS")
    print(f"Current time: {now_ist.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"{'='*60}\n")
    
    # Get all sessions with logout_time (logged out sessions)
    logged_out_sessions = UserSession.objects.filter(
        logout_time__isnull=False
    ).select_related('user').order_by('user', 'logout_time')
    
    print(f"📊 Found {logged_out_sessions.count()} logged out sessions\n")
    
    fixed_count = 0
    skipped_count = 0
    
    for session in logged_out_sessions:
        user = session.user
        
        # Normalize logout time to IST
        logout_time_ist = session.logout_time.astimezone(IST)
        logout_date = logout_time_ist.date()
        
        try:
            # Get attendance record for that date
            attendance = Attendance.objects.get(user=user, date=logout_date)
            
            # Check if it needs fixing
            needs_update = False
            
            # Normalize existing times to IST for comparison
            clock_in_ist = attendance.clock_in_time.astimezone(IST) if attendance.clock_in_time else None
            clock_out_ist = attendance.clock_out_time.astimezone(IST) if attendance.clock_out_time else None
            
            # Fix clock_out_time if missing or this logout is later
            if not clock_out_ist or logout_time_ist > clock_out_ist:
                attendance.clock_out_time = logout_time_ist  # Store in IST
                attendance.last_session = session
                needs_update = True
                print(f"  → Setting clock_out: {logout_time_ist.strftime('%H:%M:%S %Z')}")
            
            # Calculate total_hours if we have both times (in IST)
            if clock_in_ist and attendance.clock_out_time:
                clock_out_normalized = attendance.clock_out_time.astimezone(IST)
                time_diff = clock_out_normalized - clock_in_ist
                total_seconds = time_diff.total_seconds()
                
                # Only calculate if positive
                if total_seconds > 0:
                    new_total_hours = Decimal(str(round(total_seconds / 3600, 2)))
                    
                    if attendance.total_hours != new_total_hours:
                        attendance.total_hours = new_total_hours
                        needs_update = True
                        print(f"  → Calculating total_hours: {new_total_hours}h")
                else:
                    print(f"  ⚠️ Skipping negative time: {total_seconds}s")
                    skipped_count += 1
                    continue
            
            if needs_update:
                attendance.save()
                print(f"✅ FIXED: {user.username} on {logout_date}")
                print(f"   Clock In:  {attendance.clock_in_time.strftime('%H:%M:%S') if attendance.clock_in_time else 'N/A'}")
                print(f"   Clock Out: {attendance.clock_out_time.strftime('%H:%M:%S') if attendance.clock_out_time else 'N/A'}")
                print(f"   Total:     {attendance.total_hours}h\n")
                fixed_count += 1
            else:
                skipped_count += 1
                
        except Attendance.DoesNotExist:
            print(f"⚠️  No attendance record for {user.username} on {logout_date}")
            continue
    
    print(f"\n{'='*60}")
    print(f"📈 SUMMARY:")
    print(f"   - Fixed: {fixed_count}")
    print(f"   - Skipped (already correct): {skipped_count}")
    print(f"   - Total Processed: {logged_out_sessions.count()}")
    print(f"{'='*60}\n")
    
    # Show current stats for today
    print("📊 TODAY'S ATTENDANCE WITH TIMES:")
    today = now_ist.date()
    today_attendance = Attendance.objects.filter(
        date=today,
        clock_out_time__isnull=False
    ).select_related('user')
    
    for att in today_attendance:
        print(f"  {att.user.username}: {att.clock_in_time.strftime('%H:%M') if att.clock_in_time else '—'} → {att.clock_out_time.strftime('%H:%M') if att.clock_out_time else '—'} ({att.total_hours}h)")
    
    if not today_attendance:
        print("  (No records with clock_out_time today)")
    
    print(f"\n✅ DONE! Refresh your dashboard!\n")

if __name__ == '__main__':
    fix_logout_times()
