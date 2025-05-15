from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta
import pytz

# Get IST timezone
IST = pytz.timezone('Asia/Kolkata')

@receiver(user_logged_in)
def track_login_time(sender, request, user, **kwargs):
    """
    Track user login time and create/update attendance record
    with improved error handling and shift detection
    """
    try:
        # Import models here to avoid circular imports
        from .models import UserSession, Attendance
        
        # Get current time in UTC and convert to IST
        utc_now = timezone.now()
        ist_now = utc_now.astimezone(IST)
        today_date = ist_now.date()

        print(f"DEBUG: Current UTC time: {utc_now}")
        print(f"DEBUG: Current IST time: {ist_now}")

        # Device/location info
        ip_address = request.META.get('REMOTE_ADDR', '')
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        
        # Create basic device info
        device_info = {
            'user_agent': user_agent,
            'browser': _detect_browser(user_agent),
            'device_type': _detect_device_type(user_agent)
        }

        # Create user session using get_or_create_session (uses UTC internally)
        session = UserSession.get_or_create_session(
            user=user,
            session_key=request.session.session_key,
            ip_address=ip_address,
            user_agent=user_agent
        )
        print(f"DEBUG: Session created: {session}")
        print(f"DEBUG: Session login time (UTC): {session.login_time}")
        print(f"DEBUG: Session login time (IST): {session.login_time.astimezone(IST)}")

        # Get location from session
        location = session.location

        # Create attendance record using the proper method - ensure we're using IST time
        attendance = Attendance.create_attendance(
            user=user,
            clock_in_time=ist_now,  # Pass IST time for consistency
            location=location,
            ip_address=ip_address,
            device_info=device_info
        )
        
        print(f"DEBUG: Login processed - User: {user.username}, Status: {attendance.status}, Clock in: {attendance.clock_in_time}")
    
    except Exception as e:
        import traceback
        print(f"DEBUG: Login tracking error: {str(e)}")
        print(f"DEBUG: Error traceback: {traceback.format_exc()}")


@receiver(user_logged_out)
def track_logout_time(sender, request, user, **kwargs):
    """
    Track user logout time and update attendance record
    with improved handling of breaks and night shifts
    """
    try:
        # Import models here to avoid circular imports
        from .models import UserSession, Attendance
        
        # Get current time in UTC and convert to IST
        utc_now = timezone.now()
        ist_now = utc_now.astimezone(IST)
        print(f"DEBUG: Current UTC time at logout: {utc_now}")
        print(f"DEBUG: Current IST time at logout: {ist_now}")

        # Find and end active session - end_session handles UTC conversion internally
        active_session = UserSession.objects.filter(
            user=user,
            is_active=True
        ).first()

        if active_session:
            active_session.end_session(logout_time=utc_now)  # Pass UTC time for consistency
            print(f"DEBUG: Session ended: {active_session}")
            print(f"DEBUG: Session logout time (UTC): {active_session.logout_time}")
            print(f"DEBUG: Session logout time (IST): {active_session.logout_time.astimezone(IST)}")
            print(f"DEBUG: Working hours: {active_session.get_total_working_hours_display()}")
            print(f"DEBUG: Session duration: {active_session.get_session_duration_display()}")

        # Use the Attendance.clock_out class method to handle the clock out with IST time
        attendance = Attendance.clock_out(user, ist_now)  # Pass IST time for consistency
        if attendance:
            print(f"DEBUG: Attendance updated with clock out time: {attendance}")
            print(f"DEBUG: Attendance clock out time: {attendance.clock_out_time}")
        else:
            print(f"DEBUG: No active attendance record found to clock out")

        print(f"DEBUG: Logout tracked - User: {user.username}, Clock out: {ist_now}")
    
    except Exception as e:
        import traceback
        print(f"DEBUG: Logout tracking error: {str(e)}")
        print(f"DEBUG: Error traceback: {traceback.format_exc()}")


def _detect_browser(user_agent):
    """Simple browser detection from user agent string"""
    browsers = [
        ('Chrome', 'Chrome'),
        ('Firefox', 'Firefox'),
        ('Safari', 'Safari'),
        ('Edge', 'Edge'),
        ('MSIE', 'Internet Explorer'),
        ('Opera', 'Opera'),
    ]
    
    for browser_key, browser_name in browsers:
        if browser_key in user_agent:
            return browser_name
    return "Unknown"


def _detect_device_type(user_agent):
    """Simple device type detection from user agent string"""
    if any(mobile_os in user_agent for mobile_os in ['Android', 'iPhone', 'iPad', 'Mobile']):
        return 'Mobile'
    return 'Desktop'