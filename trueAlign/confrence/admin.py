"""
Django Admin configuration for Conference Room module.
"""

from django.contrib import admin
from trueAlign.models import ConferenceRoom, RoomBooking


@admin.register(ConferenceRoom)
class ConferenceRoomAdmin(admin.ModelAdmin):
    """Admin interface for Conference Rooms."""
    
    list_display = [
        'name', 
        'office_location', 
        'floor', 
        'capacity', 
        'is_active',
        'max_booking_duration_hours',
        'created_at'
    ]
    
    list_filter = [
        'is_active',
        'office_location',
        'floor',
        'created_at'
    ]
    
    search_fields = [
        'name',
        'description',
        'office_location__name'
    ]
    
    readonly_fields = [
        'created_at',
        'updated_at',
        'created_by'
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'office_location', 'floor', 'capacity', 'description', 'image')
        }),
        ('Amenities', {
            'fields': ('amenities',),
            'description': 'Add amenities as a JSON array. Example: ["Projector", "Whiteboard", "AC"]'
        }),
        ('Booking Rules', {
            'fields': (
                'buffer_time_minutes',
                'min_lead_time_minutes',
                'max_booking_duration_hours'
            )
        }),
        ('Status', {
            'fields': ('is_active',)
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def save_model(self, request, obj, form, change):
        """Set created_by to current user if creating new room."""
        if not change:  # Creating new object
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(RoomBooking)
class RoomBookingAdmin(admin.ModelAdmin):
    """Admin interface for Room Bookings."""
    
    list_display = [
        'title',
        'room',
        'booked_by',
        'start_time',
        'end_time',
        'attendee_count',
        'status',
        'created_at'
    ]
    
    list_filter = [
        'status',
        'room',
        'room__office_location',
        'start_time',
        'created_at'
    ]
    
    search_fields = [
        'title',
        'purpose',
        'booked_by__username',
        'booked_by__email',
        'booked_by__first_name',
        'booked_by__last_name',
        'room__name'
    ]
    
    readonly_fields = [
        'created_at',
        'updated_at',
        'cancelled_at',
        'duration_display'
    ]
    
    date_hierarchy = 'start_time'
    
    fieldsets = (
        ('Booking Information', {
            'fields': ('room', 'booked_by', 'title', 'purpose', 'status')
        }),
        ('Time Information', {
            'fields': ('start_time', 'end_time', 'duration_display')
        }),
        ('Attendees', {
            'fields': ('attendee_count', 'attendees')
        }),
        ('Additional Information', {
            'fields': ('special_requirements',)
        }),
        ('Cancellation', {
            'fields': ('cancelled_at', 'cancellation_reason'),
            'classes': ('collapse',)
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    
    def duration_display(self, obj):
        """Display booking duration."""
        return f"{obj.duration_hours:.1f} hours"
    duration_display.short_description = 'Duration'
    
    actions = ['cancel_bookings', 'confirm_bookings']
    
    def cancel_bookings(self, request, queryset):
        """Bulk cancel selected bookings."""
        count = 0
        for booking in queryset:
            if booking.is_upcoming and booking.status != RoomBooking.STATUS_CANCELLED:
                booking.cancel(reason="Cancelled by admin")
                count += 1
        
        self.message_user(request, f'{count} booking(s) cancelled successfully.')
    cancel_bookings.short_description = 'Cancel selected bookings'
    
    def confirm_bookings(self, request, queryset):
        """Bulk confirm selected bookings."""
        count = queryset.filter(status=RoomBooking.STATUS_PENDING).update(
            status=RoomBooking.STATUS_CONFIRMED
        )
        self.message_user(request, f'{count} booking(s) confirmed successfully.')
    confirm_bookings.short_description = 'Confirm selected bookings'
