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
    path('api/calendar-data/', views.get_calendar_data, name='get_calendar_data'),
    path('api/quick-booking/', views.create_quick_booking, name='create_quick_booking'),

    # Management URLs (Admin only)
    path('manage/locations/', views.manage_locations, name='manage_locations'),
    path('manage/locations/add/', views.add_location, name='add_location'),
    path('manage/locations/edit/<int:location_id>/', views.edit_location, name='edit_location'),
    path('manage/locations/delete/<int:location_id>/', views.delete_location, name='delete_location'),
    path('manage/rooms/', views.manage_rooms, name='manage_rooms'),
    path('manage/rooms/add/', views.add_room, name='add_room'),
    path('manage/rooms/edit/<int:room_id>/', views.edit_room, name='edit_room'),
    path('manage/rooms/delete/<int:room_id>/', views.delete_room, name='delete_room'),

    # API for location detection
    path('api/office-location/', views.detect_office_location, name='detect_office_location'),
    path('api/rooms/', views.get_rooms_by_location, name='get_rooms_by_location'),

    # Legacy URL for backward compatibility
    path('ut/', views.booking_room, name='booking_room_legacy'),
]
