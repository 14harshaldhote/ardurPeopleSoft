from django.urls import path
from . import views

app_name = 'notifications'

urlpatterns = [
    path('', views.get_unread_notifications, name='unread'),
    path('mark-read/<int:notification_id>/', views.mark_notification_read, name='mark_read'),
    path('mark-all-read/', views.mark_all_read, name='mark_all_read'),
]
