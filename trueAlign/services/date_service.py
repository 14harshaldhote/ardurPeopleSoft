# services/date_service.py
from datetime import datetime, date, timedelta
from django.utils import timezone
from django.conf import settings
import pytz

class DateService:
    """Centralized date handling service"""
    
    def __init__(self):
        self.IST = pytz.timezone(getattr(settings, 'TIME_ZONE', 'Asia/Kolkata'))
    
    def get_current_date_time(self):
        """Get current date and time in IST"""
        return timezone.localtime(timezone.now(), self.IST)
    
    def get_current_date(self):
        """Get current date in IST"""
        return self.get_current_date_time().date()
    
    def get_date_range(self, time_period, custom_start=None, custom_end=None):
        """Get date range based on time period"""
        if custom_start and custom_end:
            return {'start_date': custom_start, 'end_date': custom_end}
        
        today = self.get_current_date()
        
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
        
        return ranges.get(time_period, ranges['today'])