from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from .models import UserSession, Attendance

@receiver(user_logged_in)
def track_login_time(sender, request, user, **kwargs):
    try:
        # Get current time with timezone awareness
        local_now = timezone.localtime(timezone.now())
        print(f"DEBUG: Current localized time: {local_now}")

        # Create user session
        session = UserSession.objects.create(
            user=user,
            session_key=request.session.session_key,
            login_time=local_now,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            location=request.session.get('location', 'Home')
        )
        print(f"DEBUG: Session created: {session}")

        # Check for weekend or holiday
        today_date = local_now.date()
        is_weekend = today_date.weekday() >= 5  # 5 is Saturday, 6 is Sunday
        is_holiday = False  # You might have logic to determine holidays
        print(f"Checking if {today_date} is a holiday.")

        # Default status based on weekend/holiday
        default_status = 'Weekend' if is_weekend else 'Holiday' if is_holiday else 'Present'
        
        print(f"Saving attendance for user {user.username} on {today_date}. Weekend: {is_weekend}, Holiday: {is_holiday}")

        # IMPORTANT: Query first to see if there's an existing record
        existing_attendance = Attendance.objects.filter(
            user=user,
            date=today_date
        ).first()
        
        if existing_attendance:
            # Update the existing attendance
            print(f"DEBUG: Found existing attendance: {existing_attendance}")
            if not existing_attendance.clock_in_time and existing_attendance.status in ['Absent', 'Late']:
                existing_attendance.status = default_status
                existing_attendance.clock_in_time = local_now
                existing_attendance.location = session.location
                existing_attendance.save(update_fields=['status', 'clock_in_time', 'location'])
                print(f"DEBUG: Existing attendance updated: {existing_attendance}")
            attendance = existing_attendance
        else:
            # Create new attendance record
            attendance = Attendance.objects.create(
                user=user,
                date=today_date,
                status=default_status,
                clock_in_time=local_now,
                location=session.location,
                is_weekend=is_weekend,
                is_holiday=is_holiday
            )
            print(f"DEBUG: New attendance created: {attendance}")

        print(f"DEBUG: Login processed - User: {user.username}, Status: {attendance.status}, Clock in: {attendance.clock_in_time}")
    
    except Exception as e:
        import traceback
        print(f"DEBUG: Login tracking error: {str(e)}")
        print(f"DEBUG: Error traceback: {traceback.format_exc()}")

@receiver(user_logged_out)
def track_logout_time(sender, request, user, **kwargs):
    try:
        # Get current time with timezone awareness
        local_now = timezone.localtime(timezone.now())
        print(f"DEBUG: Current localized time at logout: {local_now}")

        # Find and end active session
        active_session = UserSession.objects.filter(
            user=user,
            session_key=request.session.session_key,
            logout_time__isnull=True
        ).first()

        if active_session:
            active_session.logout_time = local_now
            active_session.save(update_fields=['logout_time'])
            print(f"DEBUG: Session updated with logout time: {active_session}")

        # Update attendance record
        attendance = Attendance.objects.filter(
            user=user,
            date=local_now.date()
        ).first()

        if attendance:
            print(f"DEBUG: Found attendance to update at logout: {attendance}")
            # Check if this is a new clock out or an update
            if not attendance.clock_out_time and attendance.clock_in_time:
                # Ensure clock_in_time is timezone-aware
                if timezone.is_naive(attendance.clock_in_time):
                    clock_in_time = timezone.make_aware(attendance.clock_in_time)
                    print(f"DEBUG: Made clock_in_time timezone-aware: {clock_in_time}")
                else:
                    clock_in_time = attendance.clock_in_time
                    print(f"DEBUG: clock_in_time already timezone-aware: {clock_in_time}")
                
                # Update clock_out_time
                attendance.clock_out_time = local_now
                
                # Calculate total hours
                duration = local_now - clock_in_time
                total_hours = duration.total_seconds() / 3600  # Convert to hours
                attendance.total_hours = round(total_hours, 2)
                print(f"DEBUG: Calculated total hours: {attendance.total_hours}")
                
                # Save changes
                attendance.save(update_fields=['clock_out_time', 'total_hours'])
                print(f"DEBUG: Attendance updated with clock out time: {attendance}")
            else:
                print(f"DEBUG: No clock out update needed: clock_in={attendance.clock_in_time}, clock_out={attendance.clock_out_time}")
        else:
            print(f"DEBUG: No attendance record found for today: {local_now.date()}")

        print(f"DEBUG: Logout tracked - User: {user.username}, Clock out: {local_now}")
    
    except Exception as e:
        import traceback
        print(f"DEBUG: Logout tracking error: {str(e)}")
        print(f"DEBUG: Error traceback: {traceback.format_exc()}")