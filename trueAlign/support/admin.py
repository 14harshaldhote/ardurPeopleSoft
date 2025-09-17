from django.contrib import admin
from trueAlign.models import (
    Support, TicketComment, TicketAttachment, TicketActivity,
    StatusLog, CommentAttachment
)


class TicketCommentInline(admin.TabularInline):
    """Inline admin for ticket comments"""
    model = TicketComment
    extra = 0
    fields = ('user', 'content', 'is_internal', 'created_at')
    readonly_fields = ('created_at',)
    ordering = ('created_at',)


class TicketAttachmentInline(admin.TabularInline):
    """Inline admin for ticket attachments"""
    model = TicketAttachment
    extra = 0
    fields = ('file', 'original_filename', 'description', 'uploaded_by', 'uploaded_at')
    readonly_fields = ('uploaded_at', 'original_filename')
    ordering = ('-uploaded_at',)


class TicketActivityInline(admin.TabularInline):
    """Inline admin for ticket activities"""
    model = TicketActivity
    extra = 0
    fields = ('action', 'user', 'details', 'timestamp')
    readonly_fields = ('timestamp',)
    ordering = ('-timestamp',)


class StatusLogInline(admin.TabularInline):
    """Inline admin for status logs"""
    model = StatusLog
    extra = 0
    fields = ('old_status', 'new_status', 'changed_by', 'changed_at')
    readonly_fields = ('changed_at',)
    ordering = ('-changed_at',)


@admin.register(Support)
class SupportAdmin(admin.ModelAdmin):
    """Admin configuration for Support tickets"""

    list_display = (
        'ticket_id', 'subject', 'user', 'status', 'priority',
        'issue_type', 'assigned_to_user', 'created_at', 'is_overdue'
    )

    list_filter = (
        'status', 'priority', 'issue_type', 'assigned_group',
        'created_at', 'resolved_at', 'sla_breach'
    )

    search_fields = (
        'ticket_id', 'subject', 'description', 'user__username',
        'user__first_name', 'user__last_name', 'assigned_to_user__username'
    )

    readonly_fields = (
        'ticket_id', 'created_at', 'updated_at', 'resolved_at',
        'resolution_time', 'response_time', 'time_to_close',
        'sla_breach', 'sla_status'
    )

    fieldsets = (
        ('Basic Information', {
            'fields': (
                'ticket_id', 'user', 'subject', 'description', 'issue_type'
            )
        }),
        ('Status & Priority', {
            'fields': (
                'status', 'priority', 'assigned_group', 'assigned_to_user'
            )
        }),
        ('Additional Details', {
            'fields': (
                'location', 'asset_id', 'parent_ticket'
            ),
            'classes': ('collapse',)
        }),
        ('SLA & Timing', {
            'fields': (
                'due_date', 'sla_target_date', 'sla_breach', 'sla_status',
                'resolution_time', 'response_time', 'time_to_close'
            ),
            'classes': ('collapse',)
        }),
        ('Escalation & Resolution', {
            'fields': (
                'escalation_level', 'reopen_count', 'resolution_summary',
                'satisfaction_rating', 'feedback'
            ),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': (
                'created_at', 'updated_at', 'resolved_at'
            ),
            'classes': ('collapse',)
        }),
        ('System', {
            'fields': (
                'is_deleted',
            ),
            'classes': ('collapse',)
        })
    )

    inlines = [StatusLogInline, TicketCommentInline, TicketAttachmentInline, TicketActivityInline]

    ordering = ('-created_at',)
    date_hierarchy = 'created_at'

    actions = ['mark_resolved', 'mark_closed', 'assign_to_admin', 'assign_to_hr']

    def mark_resolved(self, request, queryset):
        """Mark selected tickets as resolved"""
        count = queryset.update(status='Resolved')
        self.message_user(request, f'{count} tickets marked as resolved.')
    mark_resolved.short_description = "Mark selected tickets as resolved"

    def mark_closed(self, request, queryset):
        """Mark selected tickets as closed"""
        count = queryset.update(status='Closed')
        self.message_user(request, f'{count} tickets marked as closed.')
    mark_closed.short_description = "Mark selected tickets as closed"

    def assign_to_admin(self, request, queryset):
        """Assign selected tickets to Admin group"""
        count = queryset.update(assigned_group='Admin')
        self.message_user(request, f'{count} tickets assigned to Admin group.')
    assign_to_admin.short_description = "Assign to Admin group"

    def assign_to_hr(self, request, queryset):
        """Assign selected tickets to HR group"""
        count = queryset.update(assigned_group='HR')
        self.message_user(request, f'{count} tickets assigned to HR group.')
    assign_to_hr.short_description = "Assign to HR group"


@admin.register(TicketComment)
class TicketCommentAdmin(admin.ModelAdmin):
    """Admin configuration for Ticket Comments"""

    list_display = ('ticket', 'user', 'content_preview', 'is_internal', 'created_at')
    list_filter = ('is_internal', 'created_at', 'user')
    search_fields = ('ticket__ticket_id', 'ticket__subject', 'content', 'user__username')
    readonly_fields = ('created_at',)
    ordering = ('-created_at',)
    date_hierarchy = 'created_at'

    def content_preview(self, obj):
        """Show preview of comment content"""
        return obj.content[:50] + '...' if len(obj.content) > 50 else obj.content
    content_preview.short_description = 'Content Preview'


@admin.register(TicketAttachment)
class TicketAttachmentAdmin(admin.ModelAdmin):
    """Admin configuration for Ticket Attachments"""

    list_display = (
        'ticket', 'original_filename', 'file_size_human',
        'uploaded_by', 'uploaded_at', 'is_deleted'
    )
    list_filter = ('uploaded_at', 'file_type', 'is_deleted')
    search_fields = (
        'ticket__ticket_id', 'original_filename', 'description',
        'uploaded_by__username'
    )
    readonly_fields = ('uploaded_at', 'file_size', 'file_type')
    ordering = ('-uploaded_at',)
    date_hierarchy = 'uploaded_at'


@admin.register(TicketActivity)
class TicketActivityAdmin(admin.ModelAdmin):
    """Admin configuration for Ticket Activities"""

    list_display = ('ticket', 'action', 'user', 'timestamp', 'details_preview')
    list_filter = ('action', 'timestamp', 'user')
    search_fields = ('ticket__ticket_id', 'details', 'user__username')
    readonly_fields = ('timestamp',)
    ordering = ('-timestamp',)
    date_hierarchy = 'timestamp'

    def details_preview(self, obj):
        """Show preview of activity details"""
        return obj.details[:50] + '...' if obj.details and len(obj.details) > 50 else obj.details or ''
    details_preview.short_description = 'Details Preview'


@admin.register(StatusLog)
class StatusLogAdmin(admin.ModelAdmin):
    """Admin configuration for Status Logs"""

    list_display = ('ticket', 'old_status', 'new_status', 'changed_by', 'changed_at')
    list_filter = ('old_status', 'new_status', 'changed_at')
    search_fields = ('ticket__ticket_id', 'changed_by__username')
    readonly_fields = ('changed_at',)
    ordering = ('-changed_at',)
    date_hierarchy = 'changed_at'


@admin.register(CommentAttachment)
class CommentAttachmentAdmin(admin.ModelAdmin):
    """Admin configuration for Comment Attachments"""

    list_display = (
        'comment', 'original_filename', 'file_size_human',
        'uploaded_by', 'uploaded_at', 'is_active'
    )
    list_filter = ('uploaded_at', 'content_type', 'is_active')
    search_fields = (
        'comment__ticket__ticket_id', 'original_filename',
        'description', 'uploaded_by__username'
    )
    readonly_fields = ('uploaded_at', 'file_size', 'content_type')
    ordering = ('-uploaded_at',)
    date_hierarchy = 'uploaded_at'

    def get_queryset(self, request):
        """Optimize queryset with select_related"""
        return super().get_queryset(request).select_related(
            'comment__ticket', 'uploaded_by'
        )
