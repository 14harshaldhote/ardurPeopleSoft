"""
Financial Year Utilities for Indian FY (April-March)
Handles FY calculations, quarters, and date validations
"""

from datetime import date, datetime, timedelta
from dateutil.relativedelta import relativedelta
from typing import Tuple, List, Dict, Optional


def get_current_fy() -> Tuple[date, date, str]:
    """
    Get current financial year details
    
    Indian FY runs from April 1 to March 31
    
    Returns:
        tuple: (fy_start_date, fy_end_date, fy_string)
        
    Example:
        For date in Dec 2024:
        Returns: (date(2024, 4, 1), date(2025, 3, 31), "FY 2024-25")
        
        For date in Feb 2025:
        Returns: (date(2024, 4, 1), date(2025, 3, 31), "FY 2024-25")
    """
    today = date.today()
    
    if today.month >= 4:  # Apr-Dec: Current year starts FY
        fy_start = date(today.year, 4, 1)
        fy_end = date(today.year + 1, 3, 31)
        fy_string = f"FY {today.year}-{str(today.year + 1)[2:]}"
    else:  # Jan-Mar: Previous year starts FY
        fy_start = date(today.year - 1, 4, 1)
        fy_end = date(today.year, 3, 31)
        fy_string = f"FY {today.year - 1}-{str(today.year)[2:]}"
    
    return (fy_start, fy_end, fy_string)


def get_fy_for_date(target_date: date) -> Tuple[date, date, str]:
    """
    Get financial year for a specific date
    
    Args:
        target_date: Date to get FY for
        
    Returns:
        tuple: (fy_start_date, fy_end_date, fy_string)
        
    Example:
        >>> get_fy_for_date(date(2024, 5, 15))
        (date(2024, 4, 1), date(2025, 3, 31), 'FY 2024-25')
        
        >>> get_fy_for_date(date(2024, 2, 15))
        (date(2023, 4, 1), date(2024, 3, 31), 'FY 2023-24')
    """
    if isinstance(target_date, datetime):
        target_date = target_date.date()
    
    if target_date.month >= 4:
        fy_start = date(target_date.year, 4, 1)
        fy_end = date(target_date.year + 1, 3, 31)
        fy_string = f"FY {target_date.year}-{str(target_date.year + 1)[2:]}"
    else:
        fy_start = date(target_date.year - 1, 4, 1)
        fy_end = date(target_date.year, 3, 31)
        fy_string = f"FY {target_date.year - 1}-{str(target_date.year)[2:]}"
    
    return (fy_start, fy_end, fy_string)


def get_fy_by_year(fy_year: int) -> Tuple[date, date, str]:
    """
    Get FY dates by starting year
    
    Args:
        fy_year: Starting year of FY (e.g., 2024 for FY 2024-25)
        
    Returns:
        tuple: (fy_start_date, fy_end_date, fy_string)
        
    Example:
        >>> get_fy_by_year(2024)
        (date(2024, 4, 1), date(2025, 3, 31), 'FY 2024-25')
    """
    fy_start = date(fy_year, 4, 1)
    fy_end = date(fy_year + 1, 3, 31)
    fy_string = f"FY {fy_year}-{str(fy_year + 1)[2:]}"
    
    return (fy_start, fy_end, fy_string)


def get_fy_quarters(fy_year: int) -> List[Tuple[date, date, str]]:
    """
    Get all quarters for a financial year
    
    Args:
        fy_year: Starting year of FY (e.g., 2024 for FY 2024-25)
        
    Returns:
        list: List of tuples (quarter_start, quarter_end, quarter_name)
        
    Example:
        >>> get_fy_quarters(2024)
        [
            (date(2024, 4, 1), date(2024, 6, 30), 'Q1 FY 2024-25'),
            (date(2024, 7, 1), date(2024, 9, 30), 'Q2 FY 2024-25'),
            (date(2024, 10, 1), date(2024, 12, 31), 'Q3 FY 2024-25'),
            (date(2025, 1, 1), date(2025, 3, 31), 'Q4 FY 2024-25')
        ]
    """
    fy_start = date(fy_year, 4, 1)
    fy_string_short = f"FY {fy_year}-{str(fy_year + 1)[2:]}"
    
    quarters = [
        # Q1: Apr-Jun
        (
            fy_start,
            date(fy_year, 6, 30),
            f"Q1 {fy_string_short}"
        ),
        # Q2: Jul-Sep
        (
            date(fy_year, 7, 1),
            date(fy_year, 9, 30),
            f"Q2 {fy_string_short}"
        ),
        # Q3: Oct-Dec
        (
            date(fy_year, 10, 1),
            date(fy_year, 12, 31),
            f"Q3 {fy_string_short}"
        ),
        # Q4: Jan-Mar (next calendar year)
        (
            date(fy_year + 1, 1, 1),
            date(fy_year + 1, 3, 31),
            f"Q4 {fy_string_short}"
        ),
    ]
    
    return quarters


def get_current_quarter() -> Tuple[date, date, str, int]:
    """
    Get current quarter details
    
    Returns:
        tuple: (quarter_start, quarter_end, quarter_name, quarter_number)
        
    Example:
        For date in May 2024:
        Returns: (date(2024, 4, 1), date(2024, 6, 30), 'Q1 FY 2024-25', 1)
    """
    today = date.today()
    fy_start, fy_end, fy_string = get_fy_for_date(today)
    fy_year = fy_start.year
    
    quarters = get_fy_quarters(fy_year)
    
    for idx, (q_start, q_end, q_name) in enumerate(quarters, 1):
        if q_start <= today <= q_end:
            return (q_start, q_end, q_name, idx)
    
    # Fallback (should not reach here)
    return quarters[0] + (1,)


def get_fy_months(fy_year: int) -> List[Tuple[date, date, str]]:
    """
    Get all months for a financial year
    
    Args:
        fy_year: Starting year of FY
        
    Returns:
        list: List of tuples (month_start, month_end, month_name)
        
    Example:
        >>> get_fy_months(2024)
        [
            (date(2024, 4, 1), date(2024, 4, 30), 'Apr 2024'),
            (date(2024, 5, 1), date(2024, 5, 31), 'May 2024'),
            ...
            (date(2025, 3, 1), date(2025, 3, 31), 'Mar 2025')
        ]
    """
    months = []
    current = date(fy_year, 4, 1)
    fy_end = date(fy_year + 1, 3, 31)
    
    while current <= fy_end:
        # Get last day of current month
        if current.month == 12:
            month_end = date(current.year, 12, 31)
        else:
            next_month = date(current.year, current.month + 1, 1)
            month_end = next_month - timedelta(days=1)
        
        # If month_end exceeds FY end, cap it
        if month_end > fy_end:
            month_end = fy_end
        
        month_name = current.strftime('%b %Y')
        
        months.append((current, month_end, month_name))
        
        # Move to next month
        if current.month == 12:
            current = date(current.year + 1, 1, 1)
        else:
            current = date(current.year, current.month + 1, 1)
    
    return months


def is_date_in_fy(target_date: date, fy_year: int) -> bool:
    """
    Check if a date falls in a specific FY
    
    Args:
        target_date: Date to check
        fy_year: FY starting year
        
    Returns:
        bool: True if date is in FY
        
    Example:
        >>> is_date_in_fy(date(2024, 5, 15), 2024)
        True
        >>> is_date_in_fy(date(2024, 2, 15), 2024)
        False  # This is in FY 2023-24
    """
    if isinstance(target_date, datetime):
        target_date = target_date.date()
    
    fy_start, fy_end, _ = get_fy_by_year(fy_year)
    
    return fy_start <= target_date <= fy_end


def get_fy_progress() -> Dict[str, any]:
    """
    Get current FY progress as percentage
    
    Returns:
        dict: {
            'fy_string': str,
            'days_elapsed': int,
            'days_total': int,
            'days_remaining': int,
            'progress_pct': float
        }
        
    Example:
        >>> get_fy_progress()
        {
            'fy_string': 'FY 2024-25',
            'days_elapsed': 120,
            'days_total': 365,
            'days_remaining': 245,
            'progress_pct': 32.88
        }
    """
    today = date.today()
    fy_start, fy_end, fy_string = get_current_fy()
    
    days_total = (fy_end - fy_start).days + 1
    days_elapsed = (today - fy_start).days + 1
    days_remaining = (fy_end - today).days
    
    progress_pct = (days_elapsed / days_total * 100) if days_total > 0 else 0
    
    return {
        'fy_string': fy_string,
        'days_elapsed': days_elapsed,
        'days_total': days_total,
        'days_remaining': days_remaining,
        'progress_pct': round(progress_pct, 2)
    }


def get_previous_fy(fy_year: Optional[int] = None) -> Tuple[date, date, str]:
    """
    Get previous financial year
    
    Args:
        fy_year: FY year to get previous of (if None, uses current FY)
        
    Returns:
        tuple: (fy_start, fy_end, fy_string) for previous FY
        
    Example:
        >>> get_previous_fy(2024)  # Get FY 2023-24
        (date(2023, 4, 1), date(2024, 3, 31), 'FY 2023-24')
    """
    if fy_year is None:
        fy_start, _, _ = get_current_fy()
        fy_year = fy_start.year
    
    return get_fy_by_year(fy_year - 1)


def get_next_fy(fy_year: Optional[int] = None) -> Tuple[date, date, str]:
    """
    Get next financial year
    
    Args:
        fy_year: FY year to get next of (if None, uses current FY)
        
    Returns:
        tuple: (fy_start, fy_end, fy_string) for next FY
        
    Example:
        >>> get_next_fy(2024)  # Get FY 2025-26
        (date(2025, 4, 1), date(2026, 3, 31), 'FY 2025-26')
    """
    if fy_year is None:
        fy_start, _, _ = get_current_fy()
        fy_year = fy_start.year
    
    return get_fy_by_year(fy_year + 1)


def format_fy_string(fy_year: int, full: bool = False) -> str:
    """
    Format FY string
    
    Args:
        fy_year: FY starting year
        full: If True, return full format (e.g., "FY 2024-2025")
              If False, return short format (e.g., "FY 2024-25")
        
    Returns:
        str: Formatted FY string
        
    Example:
        >>> format_fy_string(2024, full=False)
        'FY 2024-25'
        >>> format_fy_string(2024, full=True)
        'FY 2024-2025'
    """
    if full:
        return f"FY {fy_year}-{fy_year + 1}"
    else:
        return f"FY {fy_year}-{str(fy_year + 1)[2:]}"


# ============================================
# USAGE EXAMPLES
# ============================================

if __name__ == '__main__':
    print("Financial Year Utilities - Examples\n")
    
    # Current FY
    start, end, fy = get_current_fy()
    print(f"Current FY: {fy}")
    print(f"  Period: {start} to {end}\n")
    
    # FY for specific date
    target = date(2024, 1, 15)
    start, end, fy = get_fy_for_date(target)
    print(f"FY for {target}: {fy}")
    print(f"  Period: {start} to {end}\n")
    
    # Quarters
    quarters = get_fy_quarters(2024)
    print("Quarters for FY 2024-25:")
    for q_start, q_end, q_name in quarters:
        print(f"  {q_name}: {q_start} to {q_end}")
    print()
    
    # Current quarter
    q_start, q_end, q_name, q_num = get_current_quarter()
    print(f"Current Quarter: {q_name} (Q{q_num})")
    print(f"  Period: {q_start} to {q_end}\n")
    
    # FY Progress
    progress = get_fy_progress()
    print(f"FY Progress for {progress['fy_string']}:")
    print(f"  Days elapsed: {progress['days_elapsed']}/{progress['days_total']}")
    print(f"  Days remaining: {progress['days_remaining']}")
    print(f"  Progress: {progress['progress_pct']}%\n")
    
    # Check if date in FY
    test_date = date(2024, 5, 15)
    in_fy = is_date_in_fy(test_date, 2024)
    print(f"Is {test_date} in FY 2024-25? {in_fy}")
    
    test_date2 = date(2024, 2, 15)
    in_fy2 = is_date_in_fy(test_date2, 2024)
    print(f"Is {test_date2} in FY 2024-25? {in_fy2}")
