from django.urls import path
from . import views

app_name = 'sessions'

urlpatterns = [
    # Dashboard - Main entry point
    path('', views.session_dashboard, name='dashboard'),
    path('dashboard/filter/', views.dashboard_filter, name='dashboard_filter'),
    path('dashboard/ajax/', views.dashboard_ajax_update, name='dashboard_ajax_update'),

    # Session management URLs
    path('sessions/', views.session_list, name='session_list'),
    path('sessions/<uuid:session_id>/', views.session_detail, name='session_detail'),
    path('sessions/<uuid:session_id>/end/', views.end_session, name='end_session'),
    path('sessions/daily/<int:user_id>/<str:date>/', views.session_daily_detail, name='session_daily_detail'),

    # Office location URLs
    path('locations/', views.office_locations, name='office_locations'),
    path('locations/<int:location_id>/', views.location_detail, name='location_detail'),

    # Analytics and reporting
    path('analytics/', views.session_analytics, name='analytics'),
    path('export/', views.session_export, name='export'),
]
