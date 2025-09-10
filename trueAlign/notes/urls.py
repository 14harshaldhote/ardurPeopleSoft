from django.urls import path
from . import views

app_name = 'notes'

urlpatterns = [
    # Main CRUD operations
    path('', views.global_update_list, name='global_update_list'),
    path('create/', views.global_update_create, name='global_update_create'),
    path('<int:pk>/', views.global_update_detail, name='global_update_detail'),
    path('<int:pk>/edit/', views.global_update_edit, name='global_update_edit'),
    path('<int:pk>/delete/', views.global_update_delete, name='global_update_delete'),

    # AJAX endpoints
    path('ajax/status/', views.global_update_ajax_status, name='global_update_ajax_status'),
    path('<int:pk>/mark-read/', views.global_update_mark_read, name='global_update_mark_read'),
]
