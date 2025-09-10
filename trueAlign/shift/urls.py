"""
TrueAlign Shift Management URLs
Comprehensive URL configuration for shift management system
Manager-friendly interface with clear navigation patterns
"""

from django.urls import path, include
from django.views.generic import RedirectView
from . import views

app_name = 'shift'

urlpatterns = [
    # ============================
    # DASHBOARD AND OVERVIEW
    # ============================
    path('', views.shift_dashboard, name='dashboard'),
    path('dashboard/', views.shift_dashboard, name='dashboard_alt'),
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
    path('calendar/user/', views.user_shift_calendar, name='user_calendar'),
    path('calendar/<int:user_id>/', views.user_shift_calendar, name='user_calendar_specific'),
    path('schedule/', views.shift_schedule_view, name='schedule'),

    # ============================
    # HOLIDAY MANAGEMENT
    # ============================
    path('holidays/', views.holiday_list, name='holidays'),
    path('holidays/create/', views.create_holiday, name='create_holiday'),
    path('holidays/<int:holiday_id>/delete/', views.delete_holiday, name='delete_holiday'),

    # ============================
    # API ENDPOINTS
    # ============================
    path('api/', include([
        # Core Data APIs
        path('shifts/<int:shift_id>/', views.api_shift_details, name='api_shift_details'),
        path('users/<int:user_id>/', views.api_user_info, name='api_user_info'),
        path('users/<int:user_id>/assignments/', views.api_user_assignments, name='api_user_assignments'),
        path('users/<int:user_id>/status/', views.api_user_shift_status, name='api_user_status'),
        path('schedule/', views.api_schedule_for_date, name='api_schedule'),

        # Validation APIs
        path('validate/shift-name/', views.api_validate_shift_name, name='api_validate_shift_name'),
        path('validate/assignment/', views.api_validate_assignment, name='api_validate_assignment'),
        path('validate/bulk-assignment/', views.api_bulk_assignment_validation, name='api_bulk_validation'),

        # Conflict Detection APIs
        path('conflicts/check/', views.api_check_conflicts, name='api_check_conflicts'),
        path('conflicts/resolve/', views.api_resolve_conflicts, name='api_resolve_conflicts'),

        # Smart Suggestions APIs
        path('suggestions/', views.api_get_suggestions, name='api_suggestions'),
        path('suggestions/<str:suggestion_id>/dismiss/', views.api_dismiss_suggestion, name='api_dismiss_suggestion'),

        # Analytics and Statistics
        path('analytics/dashboard/', views.api_dashboard_stats, name='api_dashboard_stats'),
        path('analytics/shifts/<int:shift_id>/', views.api_shift_analytics, name='api_shift_analytics'),
        path('analytics/users/<int:user_id>/', views.api_user_analytics, name='api_user_analytics'),

        # Quick Actions APIs
        path('quick/available-users/', views.api_available_users, name='api_available_users'),
        path('quick/shift-recommendations/', views.api_shift_recommendations, name='api_shift_recommendations'),
        path('quick/upcoming-changes/', views.api_upcoming_changes, name='api_upcoming_changes'),

        # Utility APIs
        path('holidays/check/', views.api_is_holiday, name='api_is_holiday'),
        path('holidays/list/', views.api_holidays_list, name='api_holidays_list'),
        path('system/status/', views.api_system_status, name='api_system_status'),
    ])),

    # ============================
    # MANAGER QUICK ACTIONS
    # ============================
    path('quick/', include([
        path('assign-user/', views.quick_assign_user, name='quick_assign'),
        path('end-assignment/', views.quick_end_assignment, name='quick_end'),
        path('create-shift/', views.quick_create_shift, name='quick_create_shift'),
        path('user-status/<int:user_id>/', views.quick_user_status, name='quick_user_status'),
    ])),

    # ============================
    # REPORTS AND EXPORTS
    # ============================
    path('reports/', include([
        path('assignments/', views.report_assignments, name='report_assignments'),
        path('attendance/', views.report_attendance, name='report_attendance'),
        path('conflicts/', views.report_conflicts, name='report_conflicts'),
        path('utilization/', views.report_utilization, name='report_utilization'),
    ])),

    # ============================
    # BATCH OPERATIONS
    # ============================
    path('batch/', include([
        path('activate-shifts/', views.batch_activate_shifts, name='batch_activate'),
        path('deactivate-shifts/', views.batch_deactivate_shifts, name='batch_deactivate'),
        path('end-assignments/', views.batch_end_assignments, name='batch_end_assignments'),
        path('extend-assignments/', views.batch_extend_assignments, name='batch_extend'),
    ])),

    # ============================
    # SETTINGS AND CONFIGURATION
    # ============================
    path('settings/', include([
        path('', views.shift_settings, name='settings'),
        path('groups/', views.manage_groups, name='manage_groups'),
        path('permissions/', views.manage_permissions, name='manage_permissions'),
        path('templates/', views.shift_templates, name='templates'),
    ])),

    # ============================
    # CONFLICT MANAGEMENT
    # ============================
    path('conflicts/', include([
        path('', views.conflict_dashboard, name='conflict_dashboard'),
        path('detect/', views.detect_conflicts, name='detect_conflicts'),
        path('resolve/', views.resolve_conflicts, name='resolve_conflicts'),
        path('<int:conflict_id>/auto-resolve/', views.auto_resolve_conflict, name='auto_resolve'),
    ])),

    # ============================
    # HELP AND DOCUMENTATION
    # ============================
    path('help/', include([
        path('', views.help_index, name='help'),
        path('getting-started/', views.help_getting_started, name='help_getting_started'),
        path('conflict-resolution/', views.help_conflicts, name='help_conflicts'),
        path('csv-import/', views.help_csv_import, name='help_csv'),
        path('api-docs/', views.help_api_docs, name='help_api'),
    ])),

    # ============================
    # DEVELOPMENT AND TESTING
    # ============================
    path('dev/', include([
        path('test-conflicts/', views.test_conflict_detection, name='test_conflicts'),
        path('test-assignments/', views.test_assignments, name='test_assignments'),
        path('generate-test-data/', views.generate_test_data, name='generate_test_data'),
        path('system-diagnostic/', views.system_diagnostic, name='system_diagnostic'),
    ])),

    # ============================
    # LEGACY REDIRECTS
    # ============================
    path('shift-list/', RedirectView.as_view(pattern_name='shift:list', permanent=True)),
    path('assignment-list/', RedirectView.as_view(pattern_name='shift:assignments', permanent=True)),
    path('shift-calendar/', RedirectView.as_view(pattern_name='shift:calendar', permanent=True)),

    # ============================
    # MOBILE API ENDPOINTS
    # ============================
    # path('mobile/', include([
    #     path('my-shifts/', views.mobile_my_shifts, name='mobile_my_shifts'),
    #     path('my-schedule/', views.mobile_my_schedule, name='mobile_my_schedule'),
    #     path('clock-in/', views.mobile_clock_in, name='mobile_clock_in'),
    #     path('clock-out/', views.mobile_clock_out, name='mobile_clock_out'),
    #     path('request-change/', views.mobile_request_change, name='mobile_request_change'),
    # ])),
]

# URL Patterns for different access levels
manager_patterns = [
    'dashboard', 'statistics', 'list', 'create', 'detail', 'update', 'delete',
    'assignments', 'assign', 'bulk_assign', 'end_assignment', 'csv_upload', 'csv_export',
    'calendar', 'user_calendar', 'schedule', 'holidays', 'create_holiday', 'delete_holiday',
    'conflict_dashboard', 'detect_conflicts', 'resolve_conflicts', 'settings',
    'reports', 'batch_operations'
]

hr_patterns = [
    'dashboard', 'statistics', 'list', 'detail', 'assignments', 'assign', 'bulk_assign',
    'end_assignment', 'csv_upload', 'csv_export', 'calendar', 'user_calendar', 'schedule',
    'holidays', 'create_holiday', 'delete_holiday', 'reports'
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
