# attendance/views/employee_views.py
"""
Employee Views

Views for employee-facing attendance functionality.
"""

# TODO: Functions to be moved here from original views.py:
# - attendance_dashboard
# - attendance_calendar
# - request_regularization
# - Helper functions: _build_dashboard_context, _get_or_create_today_attendance, 
#   _get_recent_attendance, _calculate_monthly_stats, _ensure_attendance_integration

# TEMPORARY: Import from original module for backwards compatibility
# These will be moved here in future refactoring iterations
import sys
from trueAlign.attendance import views_original as original_views

attendance_dashboard = original_views.attendance_dashboard
attendance_calendar = original_views.attendance_calendar
request_regularization = original_views.request_regularization

__all__ = [
    'attendance_dashboard',
    'attendance_calendar',
    'request_regularization',
]
