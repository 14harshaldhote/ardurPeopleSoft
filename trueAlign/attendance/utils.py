# attendance/utils.py
"""
Attendance Utilities

Common utility functions for date handling, calculations, and formatting.
"""

from datetime import date, datetime, timedelta
from typing import Optional, Tuple
from decimal import Decimal

import pytz

IST = pytz.timezone("Asia/Kolkata")


def get_date_range(
    period_type: str, start_date: Optional[date] = None, end_date: Optional[date] = None, **kwargs
) -> Tuple[date, date]:
    """
    Unified date range calculation

    Args:
        period_type: 'today', 'week', 'month', 'custom', 'last_7_days', 'last_30_days', 'last_90_days'
        start_date: Custom start date
        end_date: Custom end date
        **kwargs: year, month for specific period selection

    Returns:
        Tuple of (start_date, end_date)
    """
    today = datetime.now(IST).date()

    if period_type == "today":
        return today, today

    elif period_type == "week":
        # Current week (Monday to Sunday)
        start = today - timedelta(days=today.weekday())
        end = start + timedelta(days=6)
        return start, end

    elif period_type == "month":
        year = kwargs.get("year", today.year)
        month = kwargs.get("month", today.month)
        from calendar import monthrange

        start = date(year, month, 1)
        end = date(year, month, monthrange(year, month)[1])
        return start, end

    elif period_type == "last_7_days":
        return today - timedelta(days=6), today

    elif period_type == "last_30_days":
        return today - timedelta(days=29), today

    elif period_type == "last_90_days":
        return today - timedelta(days=89), today

    elif period_type == "custom":
        if not start_date or not end_date:
            raise ValueError("Custom period requires start_date and end_date")
        return start_date, end_date

    else:
        raise ValueError(f"Unknown period type: {period_type}")


def format_attendance_status(status: str) -> str:
    """Standardize status formatting for display"""
    status_map = {
        "Present": "✓ Present",
        "Present & Late": "⏰ Late",
        "Absent": "✗ Absent",
        "On Leave": "🏖️ On Leave",
        "Work From Home": "🏠 WFH",
        "Holiday": "🎉 Holiday",
        "Weekend": "📅 Weekend",
        "Not Marked": "❓ Not Marked",
    }
    return status_map.get(status, status)


def calculate_attendance_percentage(present: int, total: int) -> Decimal:
    """Consistent percentage calculation with rounding"""
    if total == 0:
        return Decimal("0.0")
    return Decimal(str(round((present / total * 100), 1)))


def calculate_work_hours(clock_in: datetime, clock_out: datetime) -> Decimal:
    """Calculate work hours between clock in and clock out"""
    if not clock_in or not clock_out:
        return Decimal("0.0")

    # Normalize to IST
    clock_in_ist = clock_in.astimezone(IST)
    clock_out_ist = clock_out.astimezone(IST)

    duration = clock_out_ist - clock_in_ist
    hours = duration.total_seconds() / 3600

    # Cap at 24 hours
    if hours > 24.0:
        hours = 24.0

    return Decimal(str(round(hours, 2)))


def is_business_day(target_date: date, holidays: list = None) -> bool:
    """Check if date is a business day (not weekend or holiday)"""
    # Check weekend
    if target_date.weekday() in [5, 6]:  # Saturday, Sunday
        return False

    # Check holidays
    if holidays and target_date in holidays:
        return False

    return True


def get_ist_now() -> datetime:
    """Get current datetime in IST timezone"""
    return datetime.now(IST)


def get_ist_today() -> date:
    """Get current date in IST timezone"""
    return get_ist_now().date()
