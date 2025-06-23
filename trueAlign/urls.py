# trueAlign/urls.py
from django.urls import path, include
from django.urls import path, register_converter
from uuid import UUID
# Create a UUID converter
class UUIDConverter:
    regex = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'

    def to_python(self, value):
        return UUID(value)

    def to_url(self, value):
        return str(value)

# Register the converter
register_converter(UUIDConverter, 'uuid')

# Appraisal URL patterns


# Enhanced Session Management URLs


# Admin-specific URLs under 'admin/'


# Main URL configuration for the project
urlpatterns = [
    # Include core app URLs without the 'core/' prefix
    path('', include('trueAlign.core.urls')),
    path('shifts/', include('trueAlign.shift.urls')),



    # Include chat URLs with namespace


]
