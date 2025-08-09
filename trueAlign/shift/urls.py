from django.urls import path, include
from trueAlign.shift import views

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
    path('shifts/<int:shift_id>/update/', views.update_shift, name='update'),
    path('shifts/<int:shift_id>/delete/', views.delete_shift, name='delete'),

    # AJAX API endpoints for shifts
    path('shifts/<int:shift_id>/api/', views.shift_api, name='shift_api'),
    path('shifts/<int:shift_id>/assignments/', views.shift_assignments_api, name='shift_assignments_api'),
    path('shifts/<int:shift_id>/statistics/', views.shift_statistics_api, name='shift_statistics_api'),

    # ============================
    # ASSIGNMENT MANAGEMENT
    # ============================
    path('assignments/', views.assignment_list, name='assignments'),
    path('assignments/assign/', views.assign_shift, name='assign'),
    path('assignments/bulk/', views.bulk_assign_shift, name='bulk_assign'),
    path('assignments/<int:assignment_id>/end/', views.end_assignment, name='end_assignment'),

    # CSV Upload for bulk assignments
    path('assignments/csv-upload/', views.csv_upload_assignments, name='csv_upload'),
    path('assignments/csv-results/', views.csv_import_results, name='csv_results'),

    # ============================
    # CALENDAR AND SCHEDULE
    # ============================
    path('calendar/', views.user_shift_calendar, name='user_calendar'),
    path('calendar/user/<int:user_id>/', views.user_shift_calendar, name='user_calendar_detail'),
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
        # Shift related APIs
        path('shift-details/<int:shift_id>/', views.api_shift_details, name='api_shift_details'),

        # User related APIs
        path('user-assignments/<int:user_id>/', views.api_user_assignments, name='api_user_assignments'),
        path('user-shift-status/', views.api_user_shift_status, name='api_user_shift_status'),
        path('user-shift-status/<int:user_id>/', views.api_user_shift_status, name='api_user_shift_status_detail'),

        # Schedule and planning APIs
        path('upcoming-changes/', views.api_upcoming_changes, name='api_upcoming_changes'),
        path('schedule-for-date/', views.api_schedule_for_date, name='api_schedule_for_date'),

        # Utility APIs
        path('is-holiday/', views.api_is_holiday, name='api_is_holiday'),

        # Suggestions and Validation APIs
        path('suggestions/', views.api_suggestions, name='api_suggestions'),
        path('suggestions/<str:suggestion_id>/dismiss/', views.api_dismiss_suggestion, name='api_dismiss_suggestion'),
        path('validate-shift-name/', views.api_validate_shift_name, name='api_validate_shift_name'),
        path('validate-user-assignment/', views.api_validate_user_assignment, name='api_validate_user_assignment'),
        path('shift-recommendations/<int:shift_id>/', views.api_shift_recommendations, name='api_shift_recommendations'),
        path('dashboard-stats/', views.api_dashboard_stats, name='api_dashboard_stats'),
        path('bulk-assignment-validation/', views.api_bulk_assignment_validation, name='api_bulk_assignment_validation'),
    ])),

    # ============================
    # LOGGING TEST ENDPOINTS
    # ============================
    # Test endpoints commented out - test_views module not available
    # path('test-dashboard/', test_views.test_logging_dashboard, name='test_dashboard'),
    # path('test-create-shift/', test_views.test_create_shift, name='test_create_shift'),
    # path('test-security/', test_views.test_security_logging, name='test_security'),
    # path('test-api/', test_views.test_api_logging, name='test_api'),
    # path('test-error/', test_views.test_error_logging, name='test_error'),
    # path('test-performance/', test_views.test_performance_logging, name='test_performance'),
    # path('test-workflow/', test_views.test_user_workflow, name='test_workflow'),
    # path('test-status/', test_views.test_logging_status, name='test_status'),
]
