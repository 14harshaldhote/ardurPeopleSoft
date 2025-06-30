from django.contrib import admin
from django.utils.html import format_html
from django.utils import timezone
from django.db.models import Count, Sum, F
from django.urls import reverse
from django.utils.safestring import mark_safe
from trueAlign.models import Room, ConferenceBooking
from datetime import timedelta


@admin.register(Room)
class RoomAdmin(admin.ModelAdmin):
    list_display = [
        'name', 'room_type', 'capacity', 'status', 'location',
        'total_bookings', 'total_hours_booked', 'current_status',
        'created_at'
    ]
    list_filter = [
        'status', 'room_type', 'capacity', 'created_at'
    ]
    search_fields = ['name', 'location', 'facilities']
    ordering = ['name']
    readonly_fields = [
        'total_bookings', 'total_hours_booked', 'created_at', 'updated_at',
        'current_booking_info', 'next_booking_info', 'today_utilization'
    ]

    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'room_type', 'capacity', 'location', 'status')
        }),
        ('Details', {
            'fields': ('description', 'facilities', 'hourly_rate', 'image')
        }),
        ('Analytics', {
            'fields': ('total_bookings', 'total_hours_booked', 'today_utilization'),
            'classes': ('collapse',)
        }),
        ('Current Status', {
            'fields': ('current_booking_info', 'next_booking_info'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    actions = ['mark_active', 'mark_maintenance', 'mark_inactive', 'update_analytics']

    def current_status(self, obj):
        """Display current room status with color coding."""
        current_booking = obj.current_booking
        if current_booking:
            return format_html(
                '<span style="color: red; font-weight: bold;">🔴 OCCUPIED</span><br>'
                '<small>Until {}</small>',
                current_booking.end_time.strftime('%I:%M %p')
            )

        next_booking = obj.next_booking
        if next_booking and next_booking.start_time <= timezone.now() + timedelta(minutes=30):
            return format_html(
                '<span style="color: orange; font-weight: bold;">🟡 SOON OCCUPIED</span><br>'
                '<small>At {}</small>',
                next_booking.start_time.strftime('%I:%M %p')
            )

        return format_html('<span style="color: green; font-weight: bold;">🟢 AVAILABLE</span>')

    current_status.short_description = 'Current Status'

    def current_booking_info(self, obj):
        """Display current booking information."""
        current_booking = obj.current_booking
        if current_booking:
            booking_url = reverse('admin:trueAlign_conferencebooking_change', args=[current_booking.id])
            return format_html(
                '<a href="{}" target="_blank">{}</a><br>'
                'By: {}<br>'
                'Until: {}',
                booking_url,
                current_booking.purpose,
                current_booking.booked_by.get_full_name(),
                current_booking.end_time.strftime('%I:%M %p')
            )
        return "No current booking"

    current_booking_info.short_description = 'Current Booking'

    def next_booking_info(self, obj):
        """Display next booking information."""
        next_booking = obj.next_booking
        if next_booking:
            booking_url = reverse('admin:trueAlign_conferencebooking_change', args=[next_booking.id])
            return format_html(
                '<a href="{}" target="_blank">{}</a><br>'
                'By: {}<br>'
                'At: {}',
                booking_url,
                next_booking.purpose,
                next_booking.booked_by.get_full_name(),
                next_booking.start_time.strftime('%I:%M %p')
            )
        return "No upcoming booking today"

    next_booking_info.short_description = 'Next Booking'

    def today_utilization(self, obj):
        """Display today's utilization percentage."""
        today = timezone.now().date()
        utilization = ConferenceBooking.get_room_utilization(obj, today, today)

        if utilization >= 80:
            color = 'red'
        elif utilization >= 50:
            color = 'orange'
        else:
            color = 'green'

        return format_html(
            '<span style="color: {}; font-weight: bold;">{:.1f}%</span>',
            color, utilization
        )

    today_utilization.short_description = 'Today\'s Utilization'

    def mark_active(self, request, queryset):
        """Mark selected rooms as active."""
        updated = queryset.update(status=Room.RoomStatus.ACTIVE)
        self.message_user(request, f'{updated} rooms marked as active.')

    mark_active.short_description = "Mark selected rooms as active"

    def mark_maintenance(self, request, queryset):
        """Mark selected rooms as under maintenance."""
        updated = queryset.update(status=Room.RoomStatus.MAINTENANCE)
        self.message_user(request, f'{updated} rooms marked as under maintenance.')

    mark_maintenance.short_description = "Mark selected rooms as under maintenance"

    def mark_inactive(self, request, queryset):
        """Mark selected rooms as inactive."""
        updated = queryset.update(status=Room.RoomStatus.INACTIVE)
        self.message_user(request, f'{updated} rooms marked as inactive.')

    mark_inactive.short_description = "Mark selected rooms as inactive"

    def update_analytics(self, request, queryset):
        """Update analytics for selected rooms."""
        for room in queryset:
            room.update_analytics()
        self.message_user(request, f'Analytics updated for {queryset.count()} rooms.')

    update_analytics.short_description = "Update analytics for selected rooms"

    def get_queryset(self, request):
        """Optimize queryset with prefetch_related."""
        return super().get_queryset(request).prefetch_related('bookings')


class ConferenceBookingInline(admin.TabularInline):
    """Inline for showing bookings in Room admin."""
    model = ConferenceBooking
    extra = 0
    fields = ['purpose', 'booked_by', 'start_time', 'end_time', 'status', 'attendees_count']
    readonly_fields = ['booked_by']
    can_delete = False

    def get_queryset(self, request):
        return super().get_queryset(request).filter(
            start_time__date__gte=timezone.now().date()
        ).select_related('booked_by')


@admin.register(ConferenceBooking)
class ConferenceBookingAdmin(admin.ModelAdmin):
    list_display = [
        'room', 'purpose', 'booked_by', 'start_time', 'end_time',
        'status', 'priority', 'attendees_count', 'duration_display',
        'booking_status_display', 'created_at'
    ]
    list_filter = [
        'status', 'priority', 'meeting_type', 'room', 'start_time',
        'created_at', 'checked_in', 'no_show'
    ]
    search_fields = [
        'purpose', 'description', 'booked_by__username', 'booked_by__first_name',
        'booked_by__last_name', 'room__name'
    ]
    date_hierarchy = 'start_time'
    ordering = ['-created_at']

    readonly_fields = [
        'created_at', 'updated_at', 'total_cost', 'duration_display',
        'booking_status_display', 'cancelled_info', 'check_in_info'
    ]

    fieldsets = (
        ('Booking Details', {
            'fields': ('room', 'purpose', 'description', 'booked_by')
        }),
        ('Schedule', {
            'fields': ('start_time', 'end_time', 'duration_display')
        }),
        ('Meeting Information', {
            'fields': ('meeting_type', 'priority', 'attendees_count', 'external_attendees')
        }),
        ('Status & Tracking', {
            'fields': ('status', 'booking_status_display', 'check_in_info')
        }),
        ('Recurring Settings', {
            'fields': ('recurring_pattern', 'parent_booking'),
            'classes': ('collapse',)
        }),
        ('Cost Information', {
            'fields': ('hourly_rate', 'total_cost'),
            'classes': ('collapse',)
        }),
        ('Cancellation Details', {
            'fields': ('cancelled_info',),
            'classes': ('collapse',)
        }),
        ('Approval Workflow', {
            'fields': ('approved_by', 'approved_at'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )

    actions = [
        'confirm_bookings', 'cancel_bookings', 'mark_no_show',
        'send_reminders', 'export_bookings'
    ]

    def duration_display(self, obj):
        """Display booking duration in a readable format."""
        duration = obj.duration
        hours = duration.total_seconds() // 3600
        minutes = (duration.total_seconds() % 3600) // 60

        if hours > 0:
            return f"{int(hours)}h {int(minutes)}m"
        else:
            return f"{int(minutes)}m"

    duration_display.short_description = 'Duration'

    def booking_status_display(self, obj):
        """Display booking status with visual indicators."""
        now = timezone.now()

        if obj.status == ConferenceBooking.BookingStatus.CANCELLED:
            return format_html('<span style="color: red;">❌ CANCELLED</span>')

        if obj.no_show:
            return format_html('<span style="color: purple;">👻 NO SHOW</span>')

        if obj.checked_in:
            return format_html('<span style="color: green;">✅ CHECKED IN</span>')

        if obj.is_current:
            if obj.can_check_in:
                return format_html('<span style="color: orange;">⏰ CAN CHECK IN</span>')
            else:
                return format_html('<span style="color: blue;">🔵 ONGOING</span>')

        if obj.is_past:
            return format_html('<span style="color: gray;">⏹️ COMPLETED</span>')

        if obj.start_time <= now + timedelta(minutes=15):
            return format_html('<span style="color: orange;">⚡ STARTING SOON</span>')

        return format_html('<span style="color: green;">📅 CONFIRMED</span>')

    booking_status_display.short_description = 'Booking Status'

    def cancelled_info(self, obj):
        """Display cancellation information."""
        if obj.status == ConferenceBooking.BookingStatus.CANCELLED:
            info = f"Cancelled at: {obj.cancelled_at.strftime('%B %d, %Y at %I:%M %p')}<br>"
            if obj.cancelled_by:
                info += f"Cancelled by: {obj.cancelled_by.get_full_name()}<br>"
            if obj.cancellation_reason:
                info += f"Reason: {obj.cancellation_reason}"
            return mark_safe(info)
        return "Not cancelled"

    cancelled_info.short_description = 'Cancellation Info'

    def check_in_info(self, obj):
        """Display check-in information."""
        if obj.checked_in:
            return f"Checked in at: {obj.checked_in_at.strftime('%B %d, %Y at %I:%M %p')}"
        elif obj.no_show:
            return "Marked as no-show"
        elif obj.can_check_in:
            return "Can check in now"
        else:
            return "Check-in not available"

    check_in_info.short_description = 'Check-in Status'

    def confirm_bookings(self, request, queryset):
        """Confirm selected bookings."""
        updated = queryset.filter(
            status__in=[ConferenceBooking.BookingStatus.PENDING]
        ).update(
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            approved_by=request.user,
            approved_at=timezone.now()
        )
        self.message_user(request, f'{updated} bookings confirmed.')

    confirm_bookings.short_description = "Confirm selected bookings"

    def cancel_bookings(self, request, queryset):
        """Cancel selected bookings."""
        count = 0
        for booking in queryset.filter(status=ConferenceBooking.BookingStatus.CONFIRMED):
            if booking.can_be_cancelled:
                booking.cancel(cancelled_by=request.user, reason="Cancelled by admin")
                count += 1

        self.message_user(request, f'{count} bookings cancelled.')

    cancel_bookings.short_description = "Cancel selected bookings"

    def mark_no_show(self, request, queryset):
        """Mark selected bookings as no-show."""
        count = 0
        for booking in queryset:
            if booking.is_past and not booking.checked_in:
                booking.mark_no_show()
                count += 1

        self.message_user(request, f'{count} bookings marked as no-show.')

    mark_no_show.short_description = "Mark selected bookings as no-show"

    def send_reminders(self, request, queryset):
        """Send reminders for selected bookings."""
        # This would integrate with your notification system
        upcoming_bookings = queryset.filter(
            status=ConferenceBooking.BookingStatus.CONFIRMED,
            start_time__lte=timezone.now() + timedelta(minutes=30),
            start_time__gt=timezone.now(),
            checked_in=False
        )

        # Here you would implement the actual reminder sending logic
        count = upcoming_bookings.count()
        self.message_user(request, f'Reminders would be sent for {count} bookings.')

    send_reminders.short_description = "Send reminders for selected bookings"

    def export_bookings(self, request, queryset):
        """Export selected bookings to CSV."""
        # This would implement CSV export functionality
        self.message_user(request, f'Export functionality would export {queryset.count()} bookings.')

    export_bookings.short_description = "Export selected bookings to CSV"

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related(
            'room', 'booked_by', 'cancelled_by', 'approved_by'
        )

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """Customize foreign key fields."""
        if db_field.name == "room":
            kwargs["queryset"] = Room.objects.filter(status=Room.RoomStatus.ACTIVE)
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    def save_model(self, request, obj, form, change):
        """Custom save logic."""
        if not change:  # New booking
            obj.hourly_rate = obj.room.hourly_rate

        super().save_model(request, obj, form, change)

        # Update room analytics
        obj.room.update_analytics()


# Add the inline to RoomAdmin
RoomAdmin.inlines = [ConferenceBookingInline]


# Custom admin site configuration
admin.site.site_header = "Conference Room Management"
admin.site.site_title = "Room Booking Admin"
admin.site.index_title = "Welcome to Room Booking Administration"
