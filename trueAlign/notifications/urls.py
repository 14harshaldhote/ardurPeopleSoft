from django.urls import path
from . import views

app_name = 'truealign_notifications'

urlpatterns = [
    path('api/notifications/', views.get_notifications, name='get_notifications'),
    path('api/notifications/mark-read/<int:notification_id>/', views.mark_notification_read, name='mark_notification_read'),
    path('api/notifications/mark-all-read/', views.mark_all_read, name='mark_all_read'),
    path('api/notifications/delete/<int:notification_id>/', views.delete_notification, name='delete_notification'),
]
