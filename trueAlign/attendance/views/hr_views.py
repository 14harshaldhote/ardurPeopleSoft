# attendance/views/hr_views.py
"""
HR Views

Views for HR administration and oversight.
"""

# TODO: Move from original views.py:
# - hr_attendance_dashboard
# - hr_regularization_requests
# - process_regularization
# - hr_add_attendance
# - bulk_attendance_operations
# - attendance_cleanup

# TEMPORARY: Import from original module
from trueAlign.attendance import views_original as original_views

hr_attendance_dashboard = original_views.hr_attendance_dashboard
hr_regularization_requests = original_views.hr_regularization_requests
process_regularization = original_views.process_regularization
hr_add_attendance = original_views.hr_add_attendance
bulk_attendance_operations = original_views.bulk_attendance_operations
attendance_cleanup = original_views.attendance_cleanup

__all__ = [
    'hr_attendance_dashboard',
    'hr_regularization_requests',
    'process_regularization',
    'hr_add_attendance',
    'bulk_attendance_operations',
    'attendance_cleanup',
]
