# attendance/api_urls.py
from django.urls import path
from . import api_views

app_name = 'attendance_api'

urlpatterns = [
    # Dashboard API endpoints
    path('dashboard/', api_views.DashboardDataAPI.as_view(), name='dashboard_api'),
    path('dashboard/charts/', api_views.dashboard_charts_api, name='dashboard_charts_api'),
    path('dashboard/summary/', api_views.dashboard_summary_api, name='dashboard_summary_api'),

    # Role-based data endpoints
    path('employee/personal/', api_views.employee_personal_data, name='employee_personal_data'),
    path('employee/monthly-summary/', api_views.employee_monthly_summary, name='employee_monthly_summary'),
    path('employee/attendance-history/', api_views.employee_attendance_history, name='employee_attendance_history'),

    # Manager endpoints
    path('manager/team-overview/', api_views.manager_team_overview, name='manager_team_overview'),
    path('manager/team-summary/', api_views.manager_team_summary, name='manager_team_summary'),

    # HR endpoints
    path('hr/all-users/', api_views.hr_all_users_data, name='hr_all_users_data'),
    path('hr/analytics/', api_views.hr_analytics_data, name='hr_analytics_data'),
    path('hr/department-summary/', api_views.hr_department_summary, name='hr_department_summary'),

    # Export endpoints
    path('export/excel/', api_views.export_excel, name='export_excel'),
    path('export/csv/', api_views.export_csv, name='export_csv'),
    path('export/pdf/', api_views.export_pdf, name='export_pdf'),

    # Regularization endpoints
    path('regularization/request/', api_views.regularization_request, name='regularization_request'),
    path('regularization/status/<int:attendance_id>/', api_views.regularization_status, name='regularization_status'),
    path('regularization/approve/', api_views.approve_regularization, name='approve_regularization'),
    path('regularization/reject/', api_views.reject_regularization, name='reject_regularization'),

    # Analytics endpoints
    path('analytics/monthly/', api_views.monthly_analytics, name='monthly_analytics'),
    path('analytics/weekly/', api_views.weekly_analytics, name='weekly_analytics'),
    path('analytics/yearly/', api_views.yearly_analytics, name='yearly_analytics'),

    # Real-time data endpoints
    path('live/attendance-count/', api_views.live_attendance_count, name='live_attendance_count'),
    path('live/current-status/', api_views.live_current_status, name='live_current_status'),

    # Utility endpoints
    path('attendance-data/', api_views.get_attendance_data, name='api_attendance_data'),
    path('monthly-data/', api_views.get_monthly_attendance_data, name='api_monthly_data'),
    path('run-auto-marking/', api_views.run_auto_marking, name='api_run_auto_marking'),
    path('summary/', api_views.attendance_summary_api, name='api_summary'),
    path('health-check/', api_views.attendance_health_check, name='health_check'),

    # Session verification endpoints
    path('verify-session-status/', api_views.verify_session_status, name='verify_session_status'),
    path('update-activity/', api_views.update_activity, name='update_activity'),
]
