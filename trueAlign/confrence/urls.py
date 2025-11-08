"""
Conference Room Module URL Configuration
Defines all routes for room management and booking.
"""

from django.urls import path
from . import views

app_name = 'conference'

urlpatterns = [
    # ============= Admin Room Management URLs =============
    path('admin/rooms/', views.room_list_admin, name='admin_room_list'),
    path('admin/rooms/create/', views.room_create, name='room_create'),
    path('admin/rooms/<int:room_id>/edit/', views.room_edit, name='room_edit'),
    path('admin/rooms/<int:room_id>/delete/', views.room_delete, name='room_delete'),
    path('admin/rooms/<int:room_id>/toggle/', views.room_toggle_active, name='room_toggle_active'),
    
    # ============= Public Room Browsing URLs =============
    path('rooms/', views.room_list, name='room_list'),
    path('rooms/<int:room_id>/', views.room_detail, name='room_detail'),
    
    # ============= Booking Management URLs =============
    path('bookings/create/', views.booking_create, name='booking_create'),
    path('bookings/create/<int:room_id>/', views.booking_create, name='booking_create_room'),
    path('bookings/my/', views.my_bookings, name='my_bookings'),
    path('bookings/<int:booking_id>/', views.booking_detail, name='booking_detail'),
    path('bookings/<int:booking_id>/cancel/', views.booking_cancel, name='booking_cancel'),
    
    # ============= Calendar & Schedule URLs =============
    path('calendar/', views.booking_calendar, name='calendar'),
    
    # ============= API/AJAX URLs =============
    path('api/check-availability/', views.check_availability, name='check_availability'),
]
