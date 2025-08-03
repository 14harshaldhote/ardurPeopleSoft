"""
Notification Admin
Django admin configuration for notifications
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import Notification
from .tasks import send_system_announcement


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = [
        'id', 'recipient_display', 'type', 'title_truncated', 
        'event_type', 'read_status', 'timestamp'
    ]
    list_filter = [
        'type', 'event_type', 'read', 'timestamp'
    ]
    search_fields = [
        'recipient__username', 'recipient__email', 
        'title', 'message', 'event_type'
    ]
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']
    
    fieldsets = (
        ('Notification Details', {
            'fields': ('recipient', 'type', 'title', 'message')
        }),
        ('Event Information', {
            'fields': ('event_type', 'event_reference_id')
        }),
        ('Status', {
            'fields': ('read', 'timestamp')
        }),
    )
    
    def recipient_display(self, obj):
        """Display recipient with link to user admin"""
        user_admin_url = reverse('admin:auth_user_change', args=[obj.recipient.id])
        return format_html(
            '<a href="{}">{}</a>',
            user_admin_url,
            obj.recipient.get_full_name() or obj.recipient.username
        )
    recipient_display.short_description = 'Recipient'
    recipient_display.admin_order_field = 'recipient__username'
    
    def title_truncated(self, obj):
        """Show truncated title"""
        if len(obj.title) > 50:
            return obj.title[:50] + '...'
        return obj.title
    title_truncated.short_description = 'Title'
    title_truncated.admin_order_field = 'title'
    
    def read_status(self, obj):
        """Display read status with icon"""
        if obj.read:
            return format_html(
                '<span style="color: green;">✓ Read</span>'
            )
        else:
            return format_html(
                '<span style="color: red;">✗ Unread</span>'
            )
    read_status.short_description = 'Status'
    read_status.admin_order_field = 'read'
    
    actions = ['mark_as_read', 'mark_as_unread', 'delete_selected']
    
    def mark_as_read(self, request, queryset):
        """Mark selected notifications as read"""
        updated = queryset.update(read=True)
        self.message_user(
            request, 
            f'{updated} notification(s) marked as read.'
        )
    mark_as_read.short_description = 'Mark selected notifications as read'
    
    def mark_as_unread(self, request, queryset):
        """Mark selected notifications as unread"""
        updated = queryset.update(read=False)
        self.message_user(
            request, 
            f'{updated} notification(s) marked as unread.'
        )
    mark_as_unread.short_description = 'Mark selected notifications as unread'
    
    def get_queryset(self, request):
        """Optimize queries"""
        return super().get_queryset(request).select_related('recipient')


# Custom admin views for sending announcements
class NotificationAdminMixin:
    """Mixin for sending notifications from admin"""
    
    def send_announcement_view(self, request):
        """Custom view for sending announcements"""
        if request.method == 'POST':
            title = request.POST.get('title')
            message = request.POST.get('message')
            user_groups = request.POST.getlist('user_groups')
            all_users = request.POST.get('all_users') == 'on'
            
            if title and message:
                # Send announcement via Celery task
                send_system_announcement.delay(title, message, user_groups, all_users)
                self.message_user(
                    request, 
                    'Announcement sent successfully!'
                )
            else:
                self.message_user(
                    request, 
                    'Title and message are required.', 
                    level='ERROR'
                )
        
        # Render announcement form
        from django.contrib.auth.models import Group
        groups = Group.objects.all()
        
        context = {
            'title': 'Send System Announcement',
            'groups': groups,
            'opts': self.model._meta,
            'has_change_permission': self.has_change_permission(request),
        }
        
        return self.render_change_form(
            request, 
            context, 
            template_name='admin/notifications/send_announcement.html'
        )


# Enhanced admin site customization
admin.site.site_header = 'ArdurTrueAlign Administration'
admin.site.site_title = 'ArdurTrueAlign Admin'
admin.site.index_title = 'Welcome to ArdurTrueAlign Administration'
