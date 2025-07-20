from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    # Authentication URLs
    path('', views.home_view, name='home'),

    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Password Reset URLs
    path('password-reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', views.CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('password-reset/confirm/<uidb64>/<token>/', views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password-reset/complete/', views.CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),

    # Session management URLs (legacy compatibility)
    path('session/status/', views.optimized_session_status, name='session_status'),
    path('session/update-activity/', views.optimized_batch_activity_update, name='update_activity'),
    path('session/analytics/', views.optimized_session_analytics, name='session_analytics'),
    path('session/detail/', views.optimized_session_status, name='session_detail'),
    path('session/end/', views.optimized_end_session, name='end_session'),
    path('session/log-activity/', views.log_activity, name='log_activity'),
    path('session/heartbeat/', views.optimized_session_heartbeat, name='session_heartbeat'),

    # Optimized session management URLs
    path('optimized-heartbeat/', views.optimized_session_heartbeat, name='optimized_heartbeat'),
    path('optimized-batch-activity/', views.optimized_batch_activity_update, name='optimized_batch_activity'),
    path('optimized-session-status/', views.optimized_session_status, name='optimized_session_status'),
    path('optimized-end-session/', views.optimized_end_session, name='optimized_end_session'),
    path('optimized-force-sync/', views.optimized_force_sync, name='optimized_force_sync'),
    path('optimized-session-analytics/', views.optimized_session_analytics, name='optimized_session_analytics'),
    path('optimized-bulk-update/', views.optimized_bulk_session_update, name='optimized_bulk_update'),

    # API endpoints for session management
    path('api/session/create/', views.create_session, name='create_session'),
    path('api/session/update/', views.update_session, name='update_session'),

    path('dashboard/', views.dashboard_view, name='dashboard'),
    path('configurations/', views.configurations_view, name='configurations'),

]
