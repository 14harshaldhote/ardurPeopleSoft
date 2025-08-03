"""
Notification URLs
URL patterns for notification API endpoints
"""

from django.urls import path
from . import views

app_name = 'notifications'

urlpatterns = [
    # User notification endpoints
    path('api/notifications/', views.get_notifications, name='get_notifications'),
    path('api/notifications/<int:notification_id>/read/', views.mark_notification_read, name='mark_notification_read'),
    path('api/notifications/mark-all-read/', views.mark_all_notifications_read, name='mark_all_notifications_read'),
    path('api/notifications/<int:notification_id>/delete/', views.delete_notification, name='delete_notification'),
    path('api/notifications/settings/', views.notification_settings, name='notification_settings'),
    
    # Admin notification endpoints
    path('api/admin/notifications/send-announcement/', views.send_announcement, name='send_announcement'),
    path('api/admin/notifications/stats/', views.notification_stats, name='notification_stats'),
]
