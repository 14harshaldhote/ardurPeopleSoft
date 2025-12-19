# attendance/views/__init__.py
"""
Attendance Views Package

Modular view layer split by user role and functionality.

IMPORTANT: This package structure currently acts as a COMPATIBILITY LAYER.
The actual views are still in the original views_original.py module file.
The submodules (employee_views, manager_views, etc.) re-export them.

Future refactoring will move the actual function implementations to the submodules.
"""

from django.contrib.auth.decorators import login_required, user_passes_test
from functools import wraps

# Permission check functions
def is_hr_check(user):
    """Check if user is HR"""
    return user.is_authenticated and user.groups.filter(name='HR').exists()


def is_manager_check(user):
    """Check if user is manager"""
    return user.is_authenticated and (
        user.groups.filter(name__in=['Manager', 'HR', 'Admin']).exists()
    )


def is_employee_check(user):
    """Check if user is employee (any authenticated user)"""
    return user.is_authenticated


# Decorators  
def hr_required():
    """Decorator to restrict access to HR users"""
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        @user_passes_test(is_hr_check)
        def wrapper(request, *args, **kwargs):
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


def manager_required():
    """Decorator to restrict access to managers"""
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        @user_passes_test(is_manager_check)
        def wrapper(request, *args, **kwargs):
            return view_func(request, *args, **kwargs)
        return wrapper
    return decorator


# Re-export all views for backwards compatibility with URLs
# Import from submodules which import from views_original
from .employee_views import attendance_dashboard, attendance_calendar, request_regularization
from .manager_views import manager_attendance_overview
from .hr_views import (
    hr_attendance_dashboard, hr_regularization_requests, process_regularization,
    hr_add_attendance, bulk_attendance_operations, attendance_cleanup
)
from .report_views import attendance_report, export_attendance_csv, search_attendance, attendance_analytics
from .api_utils import (
    get_attendance_data, get_monthly_attendance_data, run_auto_marking,
    attendance_summary_api, verify_session_status, update_activity, get_attendance_context_for_user
)

__all__ = [
    # Permission helpers
    'is_hr_check',
    'is_manager_check',
    'is_employee_check',
    'hr_required',
    'manager_required',
    # Employee views
    'attendance_dashboard',
    'attendance_calendar',
    'request_regularization',
    # Manager views
    'manager_attendance_overview',
    # HR views
    'hr_attendance_dashboard',
    'hr_regularization_requests',
    'process_regularization',
    'hr_add_attendance',
    'bulk_attendance_operations',
    'attendance_cleanup',
    # Report views
    'attendance_report',
    'export_attendance_csv',
    'search_attendance',
    'attendance_analytics',
    # API
    'get_attendance_data',
    'get_monthly_attendance_data',
    'run_auto_marking',
    'attendance_summary_api',
    'verify_session_status',
    'update_activity',
    'get_attendance_context_for_user',
]
