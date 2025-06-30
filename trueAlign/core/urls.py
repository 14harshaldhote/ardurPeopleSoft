from django.urls import path
from . import views
from django.views.generic.base import RedirectView

app_name = 'core'

urlpatterns = [
    # Authentication URLs
    #
    path('', RedirectView.as_view(url='login/', permanent=False)),  # Redirect from '' to 'login/'

    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # Password Reset URLs
    path('password-reset/', views.CustomPasswordResetView.as_view(), name='password_reset'),
    path('password-reset/done/', views.CustomPasswordResetDoneView.as_view(), name='password_reset_done'),
    path('password-reset/confirm/<uidb64>/<token>/', views.CustomPasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('password-reset/complete/', views.CustomPasswordResetCompleteView.as_view(), name='password_reset_complete'),

    # Session management URLs
    path('session/status/', views.get_session_status, name='session_status'),
    path('session/update-activity/', views.update_last_activity, name='update_activity'),
    path('session/analytics/', views.session_analytics, name='session_analytics'),
    path('session/detail/', views.session_status, name='session_detail'),
    path('session/end/', views.end_session, name='end_session'),
    path('session/log-activity/', views.log_activity, name='log_activity'),
    path('session/heartbeat/', views.session_heartbeat, name='session_heartbeat'),

    # API endpoints for session management
    path('api/session/create/', views.create_session, name='create_session'),
    path('api/session/update/', views.update_session, name='update_session'),

    path('dashboard/', views.dashboard_view, name='dashboard'),

]
