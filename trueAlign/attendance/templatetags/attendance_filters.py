# attendance/templatetags/attendance_filters.py
from django import template
from django.utils.safestring import mark_safe
from datetime import datetime, date
import calendar

register = template.Library()


@register.filter
def attendance_status_class(status):
    """
    Convert attendance status to Bootstrap CSS class
    """
    status_classes = {
        'Present': 'success',
        'Present & Late': 'warning',
        'Absent': 'danger',
        'On Leave': 'info',
        'Work From Home': 'primary',
        'Holiday': 'secondary',
        'Weekend': 'light',
        'Not Marked': 'secondary',
        'Yet to Clock In': 'warning',
        'Comp Off': 'info'
    }
    return status_classes.get(status, 'secondary')


@register.filter
def get_item(dictionary, key):
    """
    Get item from dictionary by key
    Usage: {{ mydict|get_item:key }}
    """
    if dictionary and key is not None:
        return dictionary.get(key)
    return None


@register.filter
def attendance_count(attendance_list, status):
    """
    Count attendance records by status
    Usage: {{ attendance_data|attendance_count:"Present" }}
    """
    if not attendance_list:
        return 0

    count = 0
    for attendance in attendance_list:
        if isinstance(attendance, dict):
            if attendance.get('status') == status:
                count += 1
        elif hasattr(attendance, 'status'):
            if attendance.status == status:
                count += 1
    return count


@register.filter
def status_icon(status):
    """
    Get Font Awesome icon for attendance status
    """
    icons = {
        'Present': 'fas fa-check-circle text-success',
        'Present & Late': 'fas fa-clock text-warning',
        'Absent': 'fas fa-times-circle text-danger',
        'On Leave': 'fas fa-calendar-alt text-info',
        'Work From Home': 'fas fa-home text-primary',
        'Holiday': 'fas fa-gift text-secondary',
        'Weekend': 'fas fa-calendar-day text-muted',
        'Not Marked': 'fas fa-question-circle text-secondary',
        'Yet to Clock In': 'fas fa-hourglass-half text-warning',
        'Comp Off': 'fas fa-calendar-check text-info'
    }
    icon_class = icons.get(status, 'fas fa-circle text-muted')
    return mark_safe(f'<i class="{icon_class}"></i>')


@register.filter
def format_duration(minutes):
    """
    Format minutes into human readable duration
    Usage: {{ minutes|format_duration }}
    """
    if not minutes:
        return "0 minutes"

    hours = minutes // 60
    mins = minutes % 60

    if hours > 0:
        if mins > 0:
            return f"{hours}h {mins}m"
        else:
            return f"{hours}h"
    else:
        return f"{mins}m"


@register.filter
def percentage(value, total):
    """
    Calculate percentage
    Usage: {{ value|percentage:total }}
    """
    if not total or total == 0:
        return 0
    return round((value / total) * 100, 1)


@register.filter
def month_name(month_number):
    """
    Convert month number to month name
    Usage: {{ 1|month_name }} -> January
    """
    try:
        return calendar.month_name[int(month_number)]
    except (ValueError, IndexError):
        return ""


@register.filter
def day_name(day_number):
    """
    Convert day number to day name (0=Monday, 6=Sunday)
    """
    try:
        return calendar.day_name[int(day_number)]
    except (ValueError, IndexError):
        return ""


@register.filter
def total_hours(attendance_list):
    """
    Calculate total hours from attendance list
    """
    if not attendance_list:
        return 0

    total = 0
    for attendance in attendance_list:
        if isinstance(attendance, dict):
            hours = attendance.get('total_hours', 0)
        else:
            hours = getattr(attendance, 'total_hours', 0)

        if hours:
            total += float(hours)

    return round(total, 2)


@register.filter
def working_days(attendance_list):
    """
    Count working days (excluding weekends, holidays, leaves)
    """
    if not attendance_list:
        return 0

    count = 0
    excluded_statuses = ['Weekend', 'Holiday', 'On Leave']

    for attendance in attendance_list:
        if isinstance(attendance, dict):
            status = attendance.get('status')
        else:
            status = getattr(attendance, 'status', None)

        if status and status not in excluded_statuses:
            count += 1

    return count


@register.filter
def attendance_percentage(present_days, total_working_days):
    """
    Calculate attendance percentage
    """
    if not total_working_days or total_working_days == 0:
        return 0
    return round((present_days / total_working_days) * 100, 1)


@register.filter
def time_difference(start_time, end_time):
    """
    Calculate time difference in hours
    """
    if not start_time or not end_time:
        return 0

    try:
        if isinstance(start_time, str):
            start_time = datetime.strptime(start_time, '%H:%M').time()
        if isinstance(end_time, str):
            end_time = datetime.strptime(end_time, '%H:%M').time()

        # Convert to minutes for calculation
        start_minutes = start_time.hour * 60 + start_time.minute
        end_minutes = end_time.hour * 60 + end_time.minute

        # Handle overnight shifts
        if end_minutes < start_minutes:
            end_minutes += 24 * 60

        diff_minutes = end_minutes - start_minutes
        return round(diff_minutes / 60, 2)

    except (ValueError, AttributeError):
        return 0


@register.filter
def is_late(clock_in_time, shift_start_time, grace_period=10):
    """
    Check if clock in time is late
    """
    if not clock_in_time or not shift_start_time:
        return False

    try:
        if isinstance(clock_in_time, str):
            clock_in_time = datetime.strptime(clock_in_time, '%H:%M').time()
        if isinstance(shift_start_time, str):
            shift_start_time = datetime.strptime(shift_start_time, '%H:%M').time()

        clock_in_minutes = clock_in_time.hour * 60 + clock_in_time.minute
        shift_start_minutes = shift_start_time.hour * 60 + shift_start_time.minute
        grace_end_minutes = shift_start_minutes + grace_period

        return clock_in_minutes > grace_end_minutes

    except (ValueError, AttributeError):
        return False


@register.filter
def format_time_12h(time_value):
    """
    Format time in 12-hour format with AM/PM
    """
    if not time_value:
        return ""

    try:
        if isinstance(time_value, str):
            time_obj = datetime.strptime(time_value, '%H:%M').time()
        else:
            time_obj = time_value

        return time_obj.strftime('%I:%M %p')

    except (ValueError, AttributeError):
        return str(time_value)


@register.filter
def attendance_trend(current_value, previous_value):
    """
    Get trend indicator (up/down/same)
    """
    if not current_value or not previous_value:
        return "same"

    current = float(current_value)
    previous = float(previous_value)

    if current > previous:
        return "up"
    elif current < previous:
        return "down"
    else:
        return "same"


@register.filter
def trend_icon(trend):
    """
    Get trend icon based on trend value
    """
    icons = {
        'up': '<i class="fas fa-arrow-up text-success"></i>',
        'down': '<i class="fas fa-arrow-down text-danger"></i>',
        'same': '<i class="fas fa-minus text-muted"></i>'
    }
    return mark_safe(icons.get(trend, ''))


@register.filter
def regularization_badge(status):
    """
    Get regularization status badge
    """
    badges = {
        'Pending': '<span class="badge badge-warning">Pending</span>',
        'Approved': '<span class="badge badge-success">Approved</span>',
        'Rejected': '<span class="badge badge-danger">Rejected</span>'
    }
    return mark_safe(badges.get(status, ''))


@register.filter
def can_regularize(attendance, max_days=30, max_attempts=3):
    """
    Check if attendance can be regularized
    """
    if not attendance:
        return False

    # Get attendance data
    if isinstance(attendance, dict):
        status = attendance.get('status')
        reg_status = attendance.get('regularization_status')
        attempts = attendance.get('regularization_attempts', 0)
        date_val = attendance.get('date')
    else:
        status = getattr(attendance, 'status', None)
        reg_status = getattr(attendance, 'regularization_status', None)
        attempts = getattr(attendance, 'regularization_attempts', 0)
        date_val = getattr(attendance, 'date', None)

    # Check if already approved
    if reg_status == 'Approved':
        return False

    # Check if too many attempts
    if attempts >= max_attempts:
        return False

    # Check if too old
    if date_val:
        try:
            if isinstance(date_val, str):
                att_date = datetime.strptime(date_val, '%Y-%m-%d').date()
            else:
                att_date = date_val

            days_old = (date.today() - att_date).days
            if days_old > max_days:
                return False
        except (ValueError, AttributeError):
            pass

    # Check if status allows regularization
    regularizable_statuses = ['Absent', 'Present & Late', 'Not Marked', 'Yet to Clock In']
    return status in regularizable_statuses


@register.filter
def overtime_class(overtime_hours):
    """
    Get CSS class for overtime hours
    """
    if not overtime_hours:
        return ""

    hours = float(overtime_hours)
    if hours >= 4:
        return "text-success font-weight-bold"
    elif hours >= 2:
        return "text-info"
    elif hours > 0:
        return "text-warning"
    else:
        return ""


@register.filter
def attendance_color(status):
    """
    Get color code for attendance status
    """
    colors = {
        'Present': '#28a745',
        'Present & Late': '#ffc107',
        'Absent': '#dc3545',
        'On Leave': '#17a2b8',
        'Work From Home': '#6f42c1',
        'Holiday': '#6c757d',
        'Weekend': '#e9ecef',
        'Not Marked': '#ffffff',
        'Yet to Clock In': '#fd7e14',
        'Comp Off': '#20c997'
    }
    return colors.get(status, '#6c757d')


@register.simple_tag
def attendance_summary_card(title, value, icon, color_class="primary"):
    """
    Generate attendance summary card HTML
    Usage: {% attendance_summary_card "Present Days" 25 "check-circle" "success" %}
    """
    html = f'''
    <div class="card border-left-{color_class} shadow h-100 py-2">
        <div class="card-body">
            <div class="row no-gutters align-items-center">
                <div class="col mr-2">
                    <div class="text-xs font-weight-bold text-{color_class} text-uppercase mb-1">
                        {title}
                    </div>
                    <div class="h5 mb-0 font-weight-bold text-gray-800">{value}</div>
                </div>
                <div class="col-auto">
                    <i class="fas fa-{icon} fa-2x text-gray-300"></i>
                </div>
            </div>
        </div>
    </div>
    '''
    return mark_safe(html)


@register.filter
def split_time(time_str, part):
    """
    Split time string and return specific part
    Usage: {{ "14:30"|split_time:"hour" }} -> 14
    """
    if not time_str:
        return ""

    try:
        if ':' in str(time_str):
            hour, minute = str(time_str).split(':')
            if part == 'hour':
                return hour
            elif part == 'minute':
                return minute
        return time_str
    except (ValueError, AttributeError):
        return time_str


@register.filter
def days_since(date_value):
    """
    Calculate days since given date
    """
    if not date_value:
        return 0

    try:
        if isinstance(date_value, str):
            date_obj = datetime.strptime(date_value, '%Y-%m-%d').date()
        else:
            date_obj = date_value

        return (date.today() - date_obj).days

    except (ValueError, AttributeError):
        return 0


@register.filter
def highlight_today(date_value):
    """
    Add CSS class if date is today
    """
    if not date_value:
        return ""

    try:
        if isinstance(date_value, str):
            date_obj = datetime.strptime(date_value, '%Y-%m-%d').date()
        else:
            date_obj = date_value

        if date_obj == date.today():
            return "table-info"
        return ""

    except (ValueError, AttributeError):
        return ""

from django import template

register = template.Library()

@register.filter
def dict_get(dictionary, key):
    """Get value from dictionary by key"""
    return dictionary.get(key)

@register.filter 
def dict_has_key(dictionary, key):
    """Check if dictionary has key"""
    return key in dictionary

@register.simple_tag
def attendance_count(attendance_data, status):
    """Count attendance records by status"""
    count = 0
    for day, data in attendance_data.items():
        if data.get('status') == status:
            count += 1
    return count

from django import template

register = template.Library()

@register.filter
def dict_get(dictionary, key):
    """Get value from dictionary by key"""
    return dictionary.get(key)

@register.filter 
def dict_has_key(dictionary, key):
    """Check if dictionary has key"""
    return key in dictionary

@register.simple_tag
def attendance_count(attendance_data, status):
    """Count attendance records by status"""
    if not attendance_data:
        return 0
    count = 0
    for day, data in attendance_data.items():
        if data.get('status') == status:
            count += 1
    return count

@register.filter
def get_item(dictionary, key):
    """Alternative way to get dictionary item"""
    return dictionary.get(key)
