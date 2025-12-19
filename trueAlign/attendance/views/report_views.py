# attendance/views/report_views.py
"""
Report Views

Views for reporting, searching, and analytics.
"""

# TODO: Move from original views.py:
# - attendance_report
# - export_attendance_csv
# - search_attendance
# - attendance_analytics

# TEMPORARY: Import from original module
from trueAlign.attendance import views_original as original_views

attendance_report = original_views.attendance_report
export_attendance_csv = original_views.export_attendance_csv
search_attendance = original_views.search_attendance
attendance_analytics = original_views.attendance_analytics

__all__ = [
    'attendance_report',
    'export_attendance_csv',
    'search_attendance',
    'attendance_analytics',
]
