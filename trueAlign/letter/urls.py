from django.urls import path
from . import views

app_name = 'letter'

urlpatterns = [
    path('dashboard/', views.LetterDashboardView.as_view(), name='dashboard'),
    path('template/<int:pk>/', views.LetterDetailView.as_view(), name='detail'),
    path('template/<int:pk>/generate/', views.GenerateLetterView.as_view(), name='generate'),
    path('template/<int:pk>/preview/', views.PreviewLetterView.as_view(), name='preview'),
    path('download/<int:pk>/', views.DownloadLetterPDFView.as_view(), name='download_pdf'),
]
