"""
Support URL Configuration
URL patterns for the support ticket system with multiple file upload support
"""

from django.urls import path
from . import views

app_name = 'support'

urlpatterns = [
    # Dashboard
    path('dashboard/', views.support_dashboard, name='dashboard'),

    # Ticket List and API
    path('tickets/', views.ticket_list, name='ticket_list'),
    path('tickets/api/', views.ticket_list_api, name='ticket_list_api'),

    # Ticket Management
    path('tickets/create/', views.create_ticket, name='create_ticket'),
    path('tickets/<int:pk>/', views.ticket_detail, name='ticket_detail'),

    # Ticket Actions
    path('tickets/<int:pk>/reopen/', views.reopen_ticket, name='reopen_ticket'),
    path('tickets/<int:pk>/escalate/', views.escalate_ticket, name='escalate_ticket'),

    # Attachment Management
    path('tickets/<int:pk>/attachments/<int:attachment_id>/download/',
         views.download_attachment, name='download_attachment'),
    path('tickets/<int:pk>/attachments/<int:attachment_id>/delete/',
         views.delete_attachment, name='delete_attachment'),
    path('attachments/serve/<path:file_path>/',
         views.serve_ticket_attachment, name='serve_attachment'),

    # Bulk Operations
    path('tickets/bulk-actions/', views.bulk_ticket_actions, name='bulk_ticket_actions'),

    # Export
    path('tickets/export/', views.ticket_export, name='ticket_export'),

    # API Endpoints
    path('api/tickets/stats/', views.get_ticket_stats, name='get_ticket_stats'),
    path('api/tickets/search/', views.search_tickets, name='search_tickets'),
    path('api/users/by-group/<int:group_id>/', views.get_users_by_group, name='get_users_by_group'),

    # Additional API endpoints for AJAX calls
    path('api/tickets/<int:pk>/comments/', views.get_ticket_comments_api, name='get_ticket_comments_api'),
    path('api/tickets/<int:pk>/activities/', views.get_ticket_activities_api, name='get_ticket_activities_api'),
]
