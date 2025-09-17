from django.urls import path
from . import views

app_name = 'support'

urlpatterns = [
    # Main support dashboard
    path('', views.SupportDashboardView.as_view(), name='dashboard'),

    # Ticket management
    path('create/', views.TicketCreateView.as_view(), name='create_ticket'),
    path('ticket/<int:ticket_id>/', views.TicketDetailView.as_view(), name='ticket_detail'),
    path('my-tickets/', views.my_tickets, name='my_tickets'),

    # Ticket actions
    path('ticket/<int:ticket_id>/update-status/', views.update_ticket_status, name='update_status'),
    path('ticket/<int:ticket_id>/reassign/', views.reassign_ticket, name='reassign_ticket'),
    path('ticket/<int:ticket_id>/comment/', views.add_comment, name='add_comment'),
    path('ticket/<int:ticket_id>/attachment/', views.add_attachment, name='add_attachment'),
    path('ticket/<int:ticket_id>/escalate/', views.escalate_ticket, name='escalate_ticket'),

    # AJAX endpoints
    path('ajax/stats/', views.ajax_ticket_stats, name='ajax_stats'),
    path('ajax/search/', views.ajax_search_tickets, name='ajax_search'),
]
