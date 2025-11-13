# trueAlign/urls.py
from django.urls import path, include, re_path
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

# Main URL configuration for the project
urlpatterns = [
    # Include core app URLs without the 'core/' prefix
    path('', include('trueAlign.core.urls')),

    # Include other app URLs with appropriate prefixes
    path('sessions/', include('trueAlign.sessions.urls')),
    path('profile/', include('trueAlign.profile.urls')),
    path('shift/', include('trueAlign.shift.urls')),
    path('leave_management/', include('trueAlign.leave_management.urls')),
    path('attendance/', include('trueAlign.attendance.urls')),
    path('notes/', include('trueAlign.notes.urls')),
    path('support/', include('trueAlign.support.urls')),
    path('conference/', include('trueAlign.confrence.urls')),  # Conference Room Booking
    path('appraisal/', include('trueAlign.apprisal.urls')),  # Appraisal System

    # API endpoints
    path('api/', include('trueAlign.leave_management.api_urls')),
    path('api/attendance/', include('trueAlign.attendance.api_urls')),

    # The session endpoints will be handled by core.urls directly
    # They're defined in trueAlign.core.urls.py with paths like:
    # path('session/heartbeat/', views.session_heartbeat, name='session_heartbeat'),
]
