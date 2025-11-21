from django.urls import path
from . import views
from . import api_views
from . import export_views

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
    path('export/', export_views.export_selection_page, name='export'),
    path('export/excel/', export_views.export_to_excel, name='export_excel'),
    
    # ============================================================================
    # NEW API ENDPOINTS
    # ============================================================================
    
    # Dashboard Stats API
    path('api/stats/', api_views.api_dashboard_stats, name='api_stats'),
    
    # Chart Data APIs
    path('api/hourly/', api_views.api_hourly_activity, name='api_hourly'),
    path('api/office-distribution/', api_views.api_office_distribution, name='api_office_dist'),
    path('api/device-stats/', api_views.api_device_statistics, name='api_device_stats'),
    path('api/activity-timeline/', api_views.api_activity_timeline, name='api_timeline'),
    
    # Drill-Down APIs
    path('api/drill/active/', api_views.api_drill_active_sessions, name='api_drill_active'),
    path('api/drill/idle/', api_views.api_drill_idle_sessions, name='api_drill_idle'),
    path('api/drill/office/<int:office_id>/', api_views.api_drill_office, name='api_drill_office'),
    
    # Live Activity Feed
    path('api/live-feed/', api_views.api_live_activity_feed, name='api_live_feed'),
    
    # User Search
    path('api/user-search/', api_views.api_user_search, name='api_user_search'),
]

