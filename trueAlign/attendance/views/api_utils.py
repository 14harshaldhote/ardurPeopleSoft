# attendance/views/api_utils.py
"""
API Utilities

API endpoints and utility views for attendance data.
"""

# TODO: Move from original views.py:
# - get_attendance_data
# - get_monthly_attendance_data
# - run_auto_marking
# - attendance_summary_api
# - verify_session_status
# - update_activity
# - get_attendance_context_for_user
# - Helper functions: _get_user_current_shift, _calculate_attendance_status

# TEMPORARY: Import from original module
from trueAlign.attendance import views_original as original_views

get_attendance_data = original_views.get_attendance_data
get_monthly_attendance_data = original_views.get_monthly_attendance_data
run_auto_marking = original_views.run_auto_marking
attendance_summary_api = original_views.attendance_summary_api
verify_session_status = original_views.verify_session_status
update_activity = original_views.update_activity
get_attendance_context_for_user = original_views.get_attendance_context_for_user

__all__ = [
    'get_attendance_data',
    'get_monthly_attendance_data',
    'run_auto_marking',
    'attendance_summary_api',
    'verify_session_status',
    'update_activity',
    'get_attendance_context_for_user',
]
