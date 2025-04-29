from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from datetime import timedelta

@receiver(user_logged_in)
def track_login_time(sender, request, user, **kwargs):
    """
    Track user login time and create/update attendance record
    with improved error handling and shift detection
    """
    try:
        # Import models here to avoid circular imports
        from .models import UserSession, Attendance, ShiftAssignment, Holiday
        
        # Get current time with timezone awareness
        local_now = timezone.localtime(timezone.now())
        print(f"DEBUG: Current localized time: {local_now}")
        today_date = local_now.date()

        # Device/location info
        ip_address = request.META.get('REMOTE_ADDR', '')
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        location = request.session.get('location', 'Office')  # Default to Office if not specified
        
        # Create basic device info
        device_info = {
            'user_agent': user_agent,
            'browser': _detect_browser(user_agent),
            'device_type': _detect_device_type(user_agent)
        }

        # Create user session - FIXED to use get_or_create_session
        session = UserSession.get_or_create_session(
            user=user,
            session_key=request.session.session_key,
            ip_address=ip_address,
            user_agent=user_agent
        )
        print(f"DEBUG: Session created: {session}")

        # Create attendance record using the proper method
        attendance = Attendance.create_attendance(
            user=user,
            clock_in_time=local_now,
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
        
        # Get current time with timezone awareness
        local_now = timezone.localtime(timezone.now())
        print(f"DEBUG: Current localized time at logout: {local_now}")

        # Find and end active session
        active_session = UserSession.objects.filter(
            user=user,
            session_key=request.session.session_key,
            is_active=True
        ).first()

        if active_session:
            active_session.end_session(logout_time=local_now)
            print(f"DEBUG: Session updated with logout time: {active_session}")

        # Use the Attendance.clock_out class method to handle the clock out
        attendance = Attendance.clock_out(user, local_now)
        if attendance:
            print(f"DEBUG: Attendance updated with clock out time: {attendance}")
        else:
            print(f"DEBUG: No active attendance record found to clock out")

        print(f"DEBUG: Logout tracked - User: {user.username}, Clock out: {local_now}")
    
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