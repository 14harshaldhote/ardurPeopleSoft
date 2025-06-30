# attendance/urls.py
from django.urls import path
from . import views

app_name = 'attendance'

urlpatterns = [
    # Employee Views
    path('', views.attendance_dashboard, name='dashboard'),
    path('calendar/', views.attendance_calendar, name='calendar'),
    path('request-regularization/', views.request_regularization, name='request_regularization'),

    # Manager Views
    path('manager/overview/', views.manager_attendance_overview, name='manager_overview'),

    # HR Views
    path('hr/dashboard/', views.hr_attendance_dashboard, name='hr_dashboard'),
    path('hr/regularization-requests/', views.hr_regularization_requests, name='hr_regularization_requests'),
    path('hr/process-regularization/<int:attendance_id>/', views.process_regularization, name='process_regularization'),
    path('hr/add-attendance/', views.hr_add_attendance, name='hr_add_attendance'),
    path('hr/analytics/', views.attendance_analytics, name='analytics'),

    # Reports
    path('report/', views.attendance_report, name='report'),

    # API Endpoints
    path('api/attendance-data/', views.get_attendance_data, name='api_attendance_data'),

    # Calendar Navigation (AJAX endpoints)
    path('calendar/<int:year>/<int:month>/', views.attendance_calendar, name='calendar_month'),
]
