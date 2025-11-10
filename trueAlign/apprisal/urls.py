"""
URL Configuration for Appraisal module
"""
from django.urls import path
from . import views

app_name = 'appraisal'

urlpatterns = [
    # List and dashboard
    path('', views.appraisal_list, name='appraisal_list'),
    path('dashboard/', views.appraisal_dashboard, name='appraisal_dashboard'),
    path('export/', views.appraisal_export, name='appraisal_export'),
    
    # CRUD operations
    path('create/', views.appraisal_create, name='appraisal_create'),
    path('<int:pk>/', views.appraisal_detail, name='appraisal_detail'),
    path('<int:pk>/update/', views.appraisal_update, name='appraisal_update'),
    
    # Workflow operations
    path('<int:pk>/submit/', views.appraisal_submit, name='appraisal_submit'),
    path('<int:pk>/review/', views.appraisal_review, name='appraisal_review'),
]
