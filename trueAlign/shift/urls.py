"""
TrueAlign Shift Management URLs - Optimized
Essential URL configuration for shift management system
Simplified and maintainable URL structure
"""

from django.urls import path, include
from . import views

app_name = 'shift'

urlpatterns = [
    # ============================
    # DASHBOARD AND OVERVIEW
    # ============================
    path('', views.shift_dashboard, name='dashboard'),
    path('statistics/', views.shift_statistics, name='statistics'),

    # ============================
    # SHIFT MANAGEMENT
    # ============================
    path('shifts/', views.shift_list, name='list'),
    path('shifts/create/', views.create_shift, name='create'),
    path('shifts/<int:shift_id>/', views.shift_detail, name='detail'),
    path('shifts/<int:shift_id>/edit/', views.update_shift, name='update'),
    path('shifts/<int:shift_id>/delete/', views.delete_shift, name='delete'),

    # ============================
    # ASSIGNMENT MANAGEMENT
    # ============================
    path('assignments/', views.assignment_list, name='assignments'),
    path('assignments/assign/', views.assign_shift, name='assign'),
    path('assignments/bulk/', views.bulk_assign_shift, name='bulk_assign'),
    path('assignments/<int:assignment_id>/end/', views.end_assignment, name='end_assignment'),

    # CSV Operations
    path('assignments/upload/', views.csv_upload_assignments, name='csv_upload'),
    path('assignments/export/', views.export_assignments_csv, name='csv_export'),

    # ============================
    # CALENDAR AND SCHEDULE
    # ============================
    path('calendar/', views.user_shift_calendar, name='calendar'),
    path('calendar/<int:user_id>/', views.user_shift_calendar, name='user_calendar_specific'),
    path('schedule/', views.shift_schedule_view, name='schedule'),

    # ============================
    # HOLIDAY MANAGEMENT
    # ============================
    path('holidays/', views.holiday_list, name='holidays'),
    path('holidays/create/', views.create_holiday, name='create_holiday'),
    path('holidays/<int:holiday_id>/delete/', views.delete_holiday, name='delete_holiday'),

    # ============================
    # ESSENTIAL API ENDPOINTS
    # ============================
    path('api/', include([
        # Core Data APIs
        path('shifts/<int:shift_id>/', views.api_shift_details, name='api_shift_details'),
        path('users/<int:user_id>/assignments/', views.api_user_assignments, name='api_user_assignments'),
        path('schedule/', views.api_schedule_for_date, name='api_schedule'),

        # Essential Validation APIs
        path('validate/assignment/', views.api_validate_assignment, name='api_validate_assignment'),
        path('validate-bulk-conflicts/', views.api_validate_bulk_conflicts, name='api_validate_bulk_conflicts'),
        
        # CSV Template
        path('csv-template/', views.api_download_csv_template, name='api_csv_template'),
        
        # Search APIs
        path('search-users/', views.api_search_users, name='api_search_users'),

        # Basic Conflict Detection
        path('conflicts/check/', views.api_check_conflicts, name='api_check_conflicts'),

        # Holiday APIs
        path('holidays/check/', views.api_is_holiday, name='api_is_holiday'),
        path('holidays/list/', views.api_holidays_list, name='api_holidays_list'),
    ])),

    # ============================
    # REPORTS
    # ============================
    path('reports/assignments/', views.report_assignments, name='report_assignments'),
]

# Simplified URL Patterns for different access levels
manager_patterns = [
    'dashboard', 'statistics', 'list', 'create', 'detail', 'update', 'delete',
    'assignments', 'assign', 'bulk_assign', 'end_assignment', 'csv_upload', 'csv_export',
    'calendar', 'user_calendar_specific', 'schedule', 'holidays', 'create_holiday', 'delete_holiday',
    'report_assignments'
]

hr_patterns = [
    'dashboard', 'statistics', 'list', 'detail', 'assignments', 'assign', 'bulk_assign',
    'end_assignment', 'csv_upload', 'csv_export', 'calendar', 'user_calendar_specific', 'schedule',
    'holidays', 'create_holiday', 'delete_holiday', 'report_assignments'
]

employee_patterns = [
    'dashboard', 'list', 'detail', 'assignments', 'calendar', 'schedule', 'holidays'
]

# Export patterns for permission checking
URL_PERMISSION_MAP = {
    'Manager': manager_patterns,
    'HR': hr_patterns,
    'Employee': employee_patterns,
}
