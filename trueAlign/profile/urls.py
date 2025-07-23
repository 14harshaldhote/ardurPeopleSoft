from django.urls import path
from . import views

app_name = 'profile'

urlpatterns = [
    # Dashboard
    path('dashboard/', views.hr_dashboard, name='dashboard'),

    # User management
    path('users/', views.UserListView.as_view(), name='user-list'),
    path('users/<int:pk>/', views.UserDetailView.as_view(), name='user-detail'),
    path('users/new/', views.UserCreateView.as_view(), name='user-create'),
    path('users/<int:pk>/edit/', views.UserUpdateView.as_view(), name='user-update'),
    path('users/<int:pk>/change-status/', views.change_user_status, name='change-status'),
    path('users/<int:pk>/reset-password/', views.reset_user_password, name='reset-password'),
    path('users/bulk-upload/', views.bulk_upload_users, name='bulk-upload'),
    path('users/bulk-upload/errors/', views.bulk_upload_errors, name='bulk-upload-errors'),

    # Data export
    path('users/export-csv/', views.export_users_csv, name='export-csv'),

    # Audit logs
    path('audit-logs/', views.AuditLogListView.as_view(), name='audit-logs'),
]
