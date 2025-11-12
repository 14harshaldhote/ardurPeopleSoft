"""
API URL Configuration for Leave Management System
Dedicated API endpoints for leave management functionality
"""
from django.urls import path
from . import views
from . import api_views

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
    
    # ================================
    # POLICY ALLOCATION & TRACKING API ENDPOINTS
    # ================================
    path('policy_allocation_status/', api_views.api_policy_allocation_status, name='policy_allocation_status'),
    path('policy_expiration_alerts/', api_views.api_policy_expiration_alerts, name='policy_expiration_alerts'),
    path('bulk_allocate_leaves/', api_views.api_bulk_allocate_leaves, name='bulk_allocate_leaves'),
    path('leave_usage_analytics/', api_views.api_leave_usage_analytics, name='leave_usage_analytics'),
]
