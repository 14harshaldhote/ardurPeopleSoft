# attendance/api/v1_urls.py
"""
API Version 1 URLs

All v1 API endpoints for the attendance module.
"""

from django.urls import path, include

# Import the existing api_urls
from ..api_urls import urlpatterns as base_urlpatterns

app_name = 'attendance_api_v1'

# Version 1 uses the existing API structure
# Future versions can customize or override these patterns
urlpatterns = base_urlpatterns
