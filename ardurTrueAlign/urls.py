"""
URL configuration for ardurTrueAlign project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import path, include, re_path
from django.http import HttpResponse
from django.conf import settings
from django.conf.urls.static import static
from trueAlign.attendance import api_views as attendance_api_views
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView

urlpatterns = [
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),

    # Optimized session tracker endpoints (root level for JavaScript)
    path('optimized-heartbeat/', attendance_api_views.optimized_heartbeat, name='root_optimized_heartbeat'),
    path('optimized-batch-activity/', attendance_api_views.optimized_batch_activity, name='root_optimized_batch_activity'),
    path('optimized-end-session/', attendance_api_views.optimized_end_session, name='root_optimized_end_session'),


    path('admin/', admin.site.urls),
    
    # API v1 (Phase 3.2)
    path('api/v1/attendance/', include('trueAlign.attendance.api.v1_urls')),
    
    path('', include('trueAlign.urls')),  # Include URLs for the 'aps' app
    path('', include('trueAlign.notifications.urls')),  # Include URLs for the notifications app
    path('.well-known/appspecific/com.chrome.devtools.json', lambda request: HttpResponse(status=204)),
    
    # API Documentation (Phase 3)
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]+ static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
