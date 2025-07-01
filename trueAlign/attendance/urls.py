# attendance/urls.py
from django.urls import path
from . import views

app_name = 'attendance'

urlpatterns = [
    # Employee Views
    path('', views.attendance_dashboard, name='dashboard'),
    path('calendar/', views.attendance_calendar, name='calendar'),
    path('calendar/<int:year>/<int:month>/', views.attendance_calendar, name='calendar_month'),
    path('request-regularization/', views.request_regularization, name='request_regularization'),
    path('request-regularization/<int:attendance_id>/', views.request_regularization, name='request_regularization_specific'),

    # Manager Views
    path('manager/overview/', views.manager_attendance_overview, name='manager_overview'),

    # HR Views
    path('hr/dashboard/', views.hr_attendance_dashboard, name='hr_dashboard'),
    path('hr/regularization-requests/', views.hr_regularization_requests, name='hr_regularization_requests'),
    path('hr/process-regularization/<int:attendance_id>/', views.process_regularization, name='process_regularization'),
    path('hr/add-attendance/', views.hr_add_attendance, name='hr_add_attendance'),
    path('hr/bulk-operations/', views.bulk_attendance_operations, name='bulk_attendance_operations'),
    path('hr/analytics/', views.attendance_analytics, name='analytics'),
    path('hr/cleanup/', views.attendance_cleanup, name='cleanup'),

    # Report Views
    path('report/', views.attendance_report, name='report'),
    path('export/csv/', views.export_attendance_csv, name='export_csv'),

    # Search and Utility Views
    path('search/', views.search_attendance, name='search'),

    # API Endpoints
    path('api/attendance-data/', views.get_attendance_data, name='api_attendance_data'),
    path('api/monthly-data/', views.get_monthly_attendance_data, name='api_monthly_data'),
    path('api/run-auto-marking/', views.run_auto_marking, name='api_run_auto_marking'),
    path('api/summary/', views.attendance_summary_api, name='api_summary'),
]
