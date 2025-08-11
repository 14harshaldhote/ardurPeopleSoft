"""
API URL Configuration for Leave Management System
Dedicated API endpoints for leave management functionality
"""
from django.urls import path
from . import views

app_name = 'leave_management_api'

urlpatterns = [
    # ================================
    # LEAVE BALANCE API ENDPOINTS
    # ================================
    path('leave_balance/', views.api_leave_balance, name='leave_balance'),
    path('leave_balance/<int:user_id>/', views.api_leave_balance, name='user_leave_balance'),

    # ================================
    # LEAVE TYPES API ENDPOINTS
    # ================================
    path('leave_types/', views.api_leave_types, name='leave_types'),
]
