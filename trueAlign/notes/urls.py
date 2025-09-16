from django.urls import path
from . import views

app_name = 'notes'

urlpatterns = [
    # Global Updates - Main CRUD operations
    path('', views.global_update_list, name='global_update_list'),
    path('global-updates/', views.global_update_list, name='global_update_list'),
    path('global-updates/create/', views.global_update_create, name='global_update_create'),
    path('global-updates/<int:pk>/', views.global_update_detail, name='global_update_detail'),
    path('global-updates/<int:pk>/edit/', views.global_update_edit, name='global_update_edit'),
    path('global-updates/<int:pk>/delete/', views.global_update_delete, name='global_update_delete'),
    path('global-updates/<int:pk>/toggle-status/', views.global_update_toggle_status, name='global_update_toggle_status'),

    # AJAX endpoints
    path('ajax/status/', views.global_update_ajax_status, name='global_update_ajax_status'),
    path('ajax/search/', views.global_update_search, name='global_update_search'),
    path('global-updates/<int:pk>/mark-read/', views.global_update_mark_read, name='global_update_mark_read'),
]
