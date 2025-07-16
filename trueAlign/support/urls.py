"""
URL Configuration for Smart Ticketing System
Provides comprehensive URL patterns for all ticket operations
"""

from django.urls import path, include
from . import views

app_name = 'support'

urlpatterns = [
    # Dashboard and main views
    path('', views.dashboard, name='dashboard'),
    path('tickets/', views.ticket_list, name='ticket_list'),
    path('my-tickets/', views.my_tickets, name='my_tickets'),
    path('agent-dashboard/', views.agent_dashboard, name='agent_dashboard'),

    # Ticket operations
    path('tickets/create/', views.create_ticket, name='create_ticket'),
    path('tickets/<str:ticket_id>/', views.ticket_detail, name='ticket_detail'),
    path('tickets/<str:ticket_id>/update/', views.update_ticket, name='update_ticket'),
    path('tickets/<str:ticket_id>/comment/', views.add_comment, name='add_comment'),
    path('tickets/<str:ticket_id>/assign/', views.assign_ticket, name='assign_ticket'),
    path('tickets/<str:ticket_id>/escalate/', views.escalate_ticket, name='escalate_ticket'),
    path('tickets/<str:ticket_id>/reopen/', views.reopen_ticket, name='reopen_ticket'),
    path('tickets/<str:ticket_id>/close/', views.close_ticket, name='close_ticket'),
    path('tickets/<str:ticket_id>/feedback/', views.submit_feedback, name='submit_feedback'),

    # Bulk operations
    path('tickets/bulk-actions/', views.bulk_actions, name='bulk_actions'),

    # File operations
    path('attachments/<int:attachment_id>/download/', views.download_attachment, name='download_attachment'),
    path('attachments/<int:attachment_id>/delete/', views.delete_attachment, name='delete_attachment'),

    # Analytics and reporting
    path('analytics/', views.analytics, name='analytics'),
    path('sla-monitoring/', views.sla_monitoring, name='sla_monitoring'),
    path('sla-check/', views.run_sla_check, name='run_sla_check'),

    # Export functionality
    path('export/', views.export_tickets, name='export_tickets'),

    # Search functionality
    path('search/', views.search_tickets, name='search_tickets'),

    # API endpoints
    path('api/stats/', views.api_ticket_stats, name='api_ticket_stats'),
    path('api/tickets/<str:ticket_id>/assignable-users/', views.api_assignable_users, name='api_assignable_users'),
    path('api/tickets/<str:ticket_id>/activities/', views.api_ticket_activities, name='api_ticket_activities'),

    # Help and documentation
    path('help/', views.user_guide, name='user_guide'),
]
