# services/date_service.py
from datetime import datetime, date, timedelta
from django.utils import timezone
from django.conf import settings
import pytz

class DateService:
    """Centralized date handling service"""

    # Asia/Kolkata timezone
    IST_TIMEZONE = pytz.timezone('Asia/Kolkata')

    def __init__(self):
        self.IST = pytz.timezone(getattr(settings, 'TIME_ZONE', 'Asia/Kolkata'))
        print(f"[DEBUG] DateService initialized with timezone: {self.IST}")

    def get_current_time_ist(self):
        """Return current time in Asia/Kolkata timezone (aware)."""
        current_time = timezone.now().astimezone(self.IST_TIMEZONE)
        print(f"Current IST time: {current_time}")
        return current_time

    def to_ist(self, dt):
        """Convert a datetime to Asia/Kolkata timezone (aware)."""
        if dt is None:
            print("Converting None to IST: None returned")
            return None
        if timezone.is_naive(dt):
            ist_time = self.IST_TIMEZONE.localize(dt)
        else:
            ist_time = dt.astimezone(self.IST_TIMEZONE)
        print(f"Converting {dt} to IST: {ist_time}")
        return ist_time

    def get_current_date_time(self):
        """Get current date and time in IST"""
        local_now = self.get_current_time_ist()
        print(f"[DEBUG] get_current_date_time called. Local now: {local_now}")
        return local_now

    def get_current_date_time_formatted(self):
        """Get current date and time in IST in AM/PM format"""
        local_now = self.get_current_time_ist()
        formatted_time = local_now.strftime("%Y-%m-%d %I:%M:%S %p")
        print(f"[DEBUG] Current IST time in AM/PM format: {formatted_time}")
        return formatted_time

    def get_current_date(self):
        """Get current date in IST"""
        current_date = self.get_current_date_time().date()
        print(f"[DEBUG] get_current_date called. Current date: {current_date}")
        return current_date

    def get_date_range(self, time_period, custom_start=None, custom_end=None):
        """Get date range based on time period"""
        print(f"[DEBUG] get_date_range called with time_period={time_period}, custom_start={custom_start}, custom_end={custom_end}")
        if custom_start and custom_end:
            print(f"[DEBUG] Returning custom date range: start_date={custom_start}, end_date={custom_end}")
            return {'start_date': custom_start, 'end_date': custom_end}

        today = self.get_current_date()
        print(f"[DEBUG] Calculating date range for today: {today}")

        ranges = {
            'today': {'start_date': today, 'end_date': today},
            'yesterday': {
                'start_date': today - timedelta(days=1),
                'end_date': today - timedelta(days=1)
            },
            'this_week': {
                'start_date': today - timedelta(days=today.weekday()),
                'end_date': today
            },
            'last_week': {
                'start_date': today - timedelta(days=today.weekday() + 7),
                'end_date': today - timedelta(days=today.weekday() + 1)
            },
            'this_month': {
                'start_date': today.replace(day=1),
                'end_date': today
            },
            'last_month': {
                'start_date': (today.replace(day=1) - timedelta(days=1)).replace(day=1),
                'end_date': today.replace(day=1) - timedelta(days=1)
            },
            'this_year': {
                'start_date': today.replace(month=1, day=1),
                'end_date': today
            },
            'last_year': {
                'start_date': today.replace(year=today.year-1, month=1, day=1),
                'end_date': today.replace(year=today.year-1, month=12, day=31)
            }
        }

        result = ranges.get(time_period, ranges['today'])
        print(f"[DEBUG] Date range for '{time_period}': start_date={result['start_date']}, end_date={result['end_date']}")
        return result
