"""
URL Configuration for Leave Management System
Simplified and working URL patterns
"""
from django.urls import path
from . import views

app_name = 'leave_management'

urlpatterns = [
    # ================================
    # DASHBOARD URLS
    # ================================
    path('', views.dashboard, name='dashboard'),
    path('dashboard/', views.dashboard, name='dashboard_alias'),
    path('employee/', views.employee_dashboard, name='employee_dashboard'),
    path('manager/', views.manager_dashboard, name='manager_dashboard'),
    path('hr/', views.hr_dashboard, name='hr_dashboard'),
    path('admin/', views.admin_dashboard, name='admin_dashboard'),

    # ================================
    # LEAVE REQUEST URLS
    # ================================
    path('apply/', views.apply_leave, name='apply_leave'),
    path('my-leaves/', views.my_leaves, name='my_leaves'),
    path('leave/<int:leave_id>/', views.leave_detail, name='leave_detail'),
    path('leave/<int:leave_id>/approve/', views.approve_leave, name='approve_leave'),
    path('leave/<int:leave_id>/reject/', views.reject_leave, name='reject_leave'),
    path('leave/<int:leave_id>/cancel/', views.cancel_leave, name='cancel_leave'),

    # ================================
    # TEAM MANAGEMENT URLS
    # ================================
    path('team/leaves/', views.team_leaves, name='team_leaves'),

    # ================================
    # BALANCE URLS
    # ================================
    path('balance/', views.leave_balance, name='leave_balance'),

    # ================================
    # COMP-OFF URLS
    # ================================
    path('comp-off/apply/', views.apply_comp_off, name='apply_comp_off'),
    path('comp-off/my-requests/', views.my_comp_off, name='my_comp_off'),

    # ================================
    # URL ALIASES FOR TEST COMPATIBILITY
    # ================================
    path('my_leaves/', views.my_leaves, name='my_leaves_alias'),
    path('comp_off/', views.apply_comp_off, name='comp_off_alias'),

    # ================================
    # API ENDPOINTS (for backward compatibility and testing)
    # ================================
    path('api/balance/', views.api_leave_balance, name='api_balance'),
    path('api/types/', views.api_leave_types, name='api_types'),
    path('api/balance/<int:user_id>/', views.api_leave_balance, name='api_user_balance'),

    # API endpoints are also handled in api_urls.py
]
