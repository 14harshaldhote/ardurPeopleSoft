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
    path('shift/', include('trueAlign.shift.urls')),
    path('book/', include('trueAlign.conf_booking.urls')),
    path('attendance/', include('trueAlign.attendance.urls')),
    path('support/', include('trueAlign.support.urls')),
    path('sessions/', include('trueAlign.sessions.urls')),
    path('leave/', include('trueAlign.leave_management.urls')),
    path('profile/', include('trueAlign.profile.urls')),

    # The session endpoints will be handled by core.urls directly
    # They're defined in trueAlign.core.urls.py with paths like:
    # path('session/heartbeat/', views.session_heartbeat, name='session_heartbeat'),
]
