from django.urls import path
from . import views

app_name = 'conf_booking'

urlpatterns = [
    # Main booking functionality
    path('book/', views.booking_room, name='booking_room'),
    path('cancel/<int:booking_id>/', views.cancel_booking, name='cancel_booking'),

    # User booking management
    path('my-bookings/', views.user_bookings, name='user_bookings'),
    path('details/<int:booking_id>/', views.booking_details, name='booking_details'),
    path('check-in/<int:booking_id>/', views.check_in_booking, name='check_in_booking'),

    # Room management and dashboard
    path('dashboard/', views.room_dashboard, name='room_dashboard'),
    path('analytics/', views.booking_analytics, name='booking_analytics'),

    # Admin functionality
    path('admin/manage/', views.admin_booking_management, name='admin_management'),
    path('admin/no-show/<int:booking_id>/', views.mark_no_show, name='mark_no_show'),

    # API endpoints
    path('api/available-slots/', views.get_available_slots, name='get_available_slots'),
    path('api/room/<int:room_id>/', views.get_room_details, name='get_room_details'),
    path('api/rooms/', views.get_available_rooms, name='get_available_rooms'),

    # Legacy URL for backward compatibility
    path('ut/', views.booking_room, name='booking_room_legacy'),
    
    path('api/available-slots/', views.get_available_slots, name='get_available_slots'),
    path('api/room/<int:room_id>/', views.get_room_details, name='get_room_details'),
    path('api/rooms/', views.get_available_rooms, name='get_available_rooms'),
    path('api/calendar-data/', views.get_calendar_data, name='get_calendar_data'),
    path('api/quick-booking/', views.create_quick_booking, name='create_quick_booking'),
]
