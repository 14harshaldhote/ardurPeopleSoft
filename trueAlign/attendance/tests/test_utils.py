# attendance/tests/test_utils.py
"""
Utility Functions Unit Tests

Tests for attendance utility functions.
"""

from django.test import TestCase
from datetime import date, timedelta
from decimal import Decimal

from ..utils import (
    get_date_range,
    format_attendance_status,
    calculate_attendance_percentage,
    calculate_work_hours,
    is_business_day,
    get_ist_today,
)
from ..exceptions import InvalidDateRangeError


class DateRangeUtilsTest(TestCase):
    """Tests for date range utilities"""

    def test_get_date_range_today(self):
        """Test getting today's date range"""
        start, end = get_date_range("today")
        self.assertEqual(start, end)
        self.assertEqual(start, get_ist_today())

    def test_get_date_range_week(self):
        """Test getting current week range"""
        start, end = get_date_range("week")
        self.assertEqual((end - start).days, 6)
        self.assertEqual(start.weekday(), 0)  # Monday

    def test_get_date_range_month(self):
        """Test getting month range"""
        start, end = get_date_range("month", year=2025, month=12)
        self.assertEqual(start.day, 1)
        self.assertEqual(end.day, 31)

    def test_get_date_range_last_30_days(self):
        """Test getting last 30 days"""
        start, end = get_date_range("last_30_days")
        self.assertEqual((end - start).days, 29)
        self.assertEqual(end, get_ist_today())

    def test_get_date_range_custom(self):
        """Test custom date range"""
        custom_start = date(2025, 1, 1)
        custom_end = date(2025, 12, 31)
        start, end = get_date_range("custom", start_date=custom_start, end_date=custom_end)
        self.assertEqual(start, custom_start)
        self.assertEqual(end, custom_end)

    def test_get_date_range_invalid_type(self):
        """Test invalid period type raises error"""
        with self.assertRaises(ValueError):
            get_date_range("invalid_type")


class FormatUtilsTest(TestCase):
    """Tests for formatting utilities"""

    def test_format_attendance_status(self):
        """Test attendance status formatting"""
        self.assertEqual(format_attendance_status("Present"), "✓ Present")
        self.assertEqual(format_attendance_status("Present & Late"), "⏰ Late")
        self.assertEqual(format_attendance_status("Absent"), "✗ Absent")
        self.assertEqual(format_attendance_status("On Leave"), "🏖️ On Leave")

    def test_calculate_attendance_percentage(self):
        """Test attendance percentage calculation"""
        self.assertEqual(calculate_attendance_percentage(20, 25), Decimal("80.0"))
        self.assertEqual(calculate_attendance_percentage(30, 30), Decimal("100.0"))
        self.assertEqual(calculate_attendance_percentage(0, 10), Decimal("0.0"))
        self.assertEqual(calculate_attendance_percentage(0, 0), Decimal("0.0"))


class WorkHoursTest(TestCase):
    """Tests for work hours calculation"""

    def test_calculate_work_hours(self):
        """Test work hours calculation"""
        from datetime import datetime
        import pytz

        IST = pytz.timezone("Asia/Kolkata")
        clock_in = IST.localize(datetime(2025, 12, 18, 9, 0))
        clock_out = IST.localize(datetime(2025, 12, 18, 18, 0))

        hours = calculate_work_hours(clock_in, clock_out)
        self.assertEqual(hours, Decimal("9.00"))

    def test_calculate_work_hours_none(self):
        """Test work hours with None values"""
        hours = calculate_work_hours(None, None)
        self.assertEqual(hours, Decimal("0.0"))


class BusinessDayTest(TestCase):
    """Tests for business day check"""

    def test_is_business_day_weekday(self):
        """Test weekday is business day"""
        # Monday
        monday = date(2025, 12, 15)
        self.assertTrue(is_business_day(monday))

    def test_is_business_day_weekend(self):
        """Test weekend is not business day"""
        # Saturday
        saturday = date(2025, 12, 20)
        self.assertFalse(is_business_day(saturday))

        # Sunday
        sunday = date(2025, 12, 21)
        self.assertFalse(is_business_day(sunday))

    def test_is_business_day_holiday(self):
        """Test holiday is not business day"""
        holiday = date(2025, 12, 25)  # Christmas
        holidays = [holiday]
        self.assertFalse(is_business_day(holiday, holidays))
