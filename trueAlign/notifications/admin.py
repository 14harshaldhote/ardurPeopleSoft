"""
Notification Admin
Django admin configuration for notifications
"""

from django.contrib import admin
from django.utils.html import format_html
from trueAlign.models import Notification


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = [
        'get_recipient', 'title_truncated', 'module',
        'read_status', 'timestamp'
    ]
    list_filter = ['module', 'read', 'timestamp']
    search_fields = [
        'recipient__username', 'recipient__email',
        'title', 'message'
    ]
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']
    
    def get_recipient(self, obj):
        return format_html(
            '<a href="/admin/auth/user/{}/change/">{}</a>',
            obj.recipient.id,
            obj.recipient.get_full_name() or obj.recipient.username
        )
    get_recipient.short_description = 'Recipient'
    get_recipient.admin_order_field = 'recipient__username'

    def title_truncated(self, obj):
        if len(obj.title) > 50:
            return f"{obj.title[:50]}..."
        return obj.title
    title_truncated.short_description = 'Title'
    title_truncated.admin_order_field = 'title'
    
    def read_status(self, obj):
        icon = '✓' if obj.read else '✗'
        color = 'green' if obj.read else 'red'
        return format_html(
            '<span style="color: {};">{} {}</span>',
            color,
            icon,
            'Read' if obj.read else 'Unread'
        )
    read_status.short_description = 'Status'
    read_status.admin_order_field = 'read'
    
    actions = ['mark_as_read', 'mark_as_unread']

    def mark_as_read(self, request, queryset):
        updated = queryset.update(read=True)
        self.message_user(request, f"{updated} notifications marked as read.")
    mark_as_read.short_description = "Mark selected notifications as read"

    def mark_as_unread(self, request, queryset):
        updated = queryset.update(read=False)
        self.message_user(request, f"{updated} notifications marked as unread.")
    mark_as_unread.short_description = "Mark selected notifications as unread"
