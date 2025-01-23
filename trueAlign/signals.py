from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver
from django.utils import timezone
from .models import UserSession, Attendance


@receiver(user_logged_in)
def track_login_time(sender, request, user, **kwargs):
    try:
        local_now = timezone.localtime(timezone.now())  # Get the current localized datetime

        # Create session record
        session = UserSession.objects.create(
            user=user,
            session_key=request.session.session_key,
            login_time=local_now,
            ip_address=request.META.get('REMOTE_ADDR', ''),
            location=request.session.get('location', 'Home')
        )

        # Create or update attendance with immediate status change
        attendance, created = Attendance.objects.get_or_create(
            user=user,
            date=local_now.date(),
            defaults={
                'status': 'Present',
                'clock_in_time': local_now,  # Use the full datetime object
                'location': session.location
            }
        )

        # If not created and no clock_in_time, update explicitly
        if not created and not attendance.clock_in_time:
            attendance.status = 'Present'
            attendance.clock_in_time = local_now  # Use the full datetime object
            attendance.location = session.location
            attendance.save(update_fields=['status', 'clock_in_time', 'location'])

        print(f"Login processed - User: {user.username}, Status: {attendance.status}, Clock in: {attendance.clock_in_time}")
    except Exception as e:
        print(f"Login tracking error: {str(e)}")


@receiver(user_logged_out)
def track_logout_time(sender, request, user, **kwargs):
    try:
        local_now = timezone.localtime(timezone.now())  # Get the current localized datetime

        # Find and end active session
        active_session = UserSession.objects.filter(
            user=user,
            session_key=request.session.session_key,
            logout_time__isnull=True
        ).first()

        if active_session:
            active_session.logout_time = local_now  # Use datetime
            active_session.save()

        # Update attendance
        attendance = Attendance.objects.filter(
            user=user,
            date=local_now.date()
        ).first()

        if attendance:
            attendance.clock_out_time = local_now  # Use datetime
            attendance.save(update_fields=['clock_out_time'])
            attendance.save(recalculate=True)

        print(f"Logout tracked - User: {user.username}, Clock out: {local_now}")
    except Exception as e:
        print(f"Logout tracking error: {str(e)}")
