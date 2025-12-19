# attendance/views/manager_views.py
"""
Manager Views

Views for manager team oversight functionality.
"""

# TODO: Move from original views.py:
# - manager_attendance_overview

# TEMPORARY: Import from original module
from trueAlign.attendance import views_original as original_views

manager_attendance_overview = original_views.manager_attendance_overview

__all__ = ['manager_attendance_overview']
