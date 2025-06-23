# urls.py for shift management
from django.urls import path
from . import views

app_name = 'shift'

urlpatterns = [
    # Dashboard and overview
    path('', views.shift_dashboard, name='dashboard'),
    path('statistics/', views.shift_statistics, name='statistics'),

    # Shift management
    path('list/', views.shift_list, name='list'),
    path('create/', views.create_shift, name='create'),
    path('update/<int:shift_id>/', views.update_shift, name='update'),
    path('delete/<int:shift_id>/', views.delete_shift, name='delete'),
    path('detail/<int:shift_id>/', views.shift_detail, name='detail'),

    # Shift assignments
    path('assignments/', views.assignment_list, name='assignments'),
    path('assign/', views.assign_shift, name='assign'),
    path('end-assignment/<int:assignment_id>/', views.end_shift_assignment, name='end_assignment'),
    path('user-shifts/<int:user_id>/', views.user_shift_history, name='user_shifts'),
    path('unassigned-users/', views.unassigned_users, name='unassigned_users'),

    # Holidays
    path('holidays/', views.holiday_list, name='holidays'),
    path('holidays/create/', views.create_holiday, name='create_holiday'),
    path('holidays/update/<int:holiday_id>/', views.update_holiday, name='update_holiday'),
    path('holidays/delete/<int:holiday_id>/', views.delete_holiday, name='delete_holiday'),

    # API endpoints for AJAX requests
    path('api/shift-details/<int:shift_id>/', views.api_shift_details, name='api_shift_details'),
    path('api/user-assignments/<int:user_id>/', views.api_user_assignments, name='api_user_assignments'),
    path('api/upcoming-changes/', views.api_upcoming_changes, name='api_upcoming_changes'),
    path('api/holidays/<int:year>/', views.api_holidays_by_year, name='api_holidays_by_year'),
]
