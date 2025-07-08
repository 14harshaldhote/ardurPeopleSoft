"""
Django Admin Configuration for Support System
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.db.models import Count
from django.utils import timezone
from trueAlign.models import (
    Support, TicketComment, TicketAttachment,
    TicketActivity, CommentAttachment, StatusLog
)


@admin.register(Support)
class SupportAdmin(admin.ModelAdmin):
    list_display = [
        'ticket_id', 'subject_truncated', 'status_colored', 'priority_colored',
        'user_name', 'assigned_to_name', 'created_at', 'sla_status_colored',
        'comments_count', 'attachments_count'
    ]
    list_filter = [
        'status', 'priority', 'issue_type', 'assigned_group',
        'sla_breach', 'created_at', 'resolved_at'
    ]
    search_fields = [
        'ticket_id', 'subject', 'description', 'user__username',
        'user__first_name', 'user__last_name', 'assigned_to_user__username'
    ]
    readonly_fields = [
        'ticket_id', 'created_at', 'updated_at', 'resolved_at',
        'resolution_time', 'time_to_close', 'sla_breach',
        'sla_target_date', 'reopen_count', 'escalation_level'
    ]
    fieldsets = (
        ('Basic Information', {
            'fields': ('ticket_id', 'user', 'subject', 'description', 'issue_type')
        }),
        ('Status & Priority', {
            'fields': ('status', 'priority', 'assigned_to_user', 'assigned_group')
        }),
        ('Additional Details', {
            'fields': ('department', 'location', 'asset_id', 'due_date'),
            'classes': ('collapse',)
        }),
        ('CC & Related', {
            'fields': ('cc_users', 'parent_ticket'),
            'classes': ('collapse',)
        }),
        ('Resolution', {
            'fields': ('resolution_summary', 'satisfaction_rating', 'feedback'),
            'classes': ('collapse',)
        }),
        ('System Information', {
            'fields': (
                'created_at', 'updated_at', 'resolved_at', 'resolution_time',
                'time_to_close', 'sla_target_date', 'sla_breach',
                'reopen_count', 'escalation_level'
            ),
            'classes': ('collapse',)
        }),
    )
    filter_horizontal = ['cc_users']
    date_hierarchy = 'created_at'
    ordering = ['-created_at']
    actions = ['mark_resolved', 'mark_closed', 'assign_to_hr', 'escalate_priority']

    def get_queryset(self, request):
        queryset = super().get_queryset(request)
        return queryset.select_related(
            'user', 'assigned_to_user', 'parent_ticket'
        ).prefetch_related(
            'cc_users'
        ).annotate(
            comments_count=Count('comments'),
            attachments_count=Count('attachments')
        )

    def subject_truncated(self, obj):
        return obj.subject[:50] + '...' if len(obj.subject) > 50 else obj.subject
    subject_truncated.admin_order_field = 'subject'
    subject_truncated.short_description = 'Subject'

    def status_colored(self, obj):
        colors = {
            'New': '#17a2b8',
            'Open': '#007bff',
            'In Progress': '#ffc107',
            'Pending User Response': '#e83e8c',
            'Pending Third Party': '#6610f2',
            'On Hold': '#6c757d',
            'Resolved': '#28a745',
            'Closed': '#495057',
        }
        color = colors.get(obj.status, '#6c757d')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_status_display()
        )
    status_colored.admin_order_field = 'status'
    status_colored.short_description = 'Status'

    def priority_colored(self, obj):
        colors = {
            'Critical': '#6f42c1',
            'High': '#dc3545',
            'Medium': '#fd7e14',
            'Low': '#28a745',
        }
        color = colors.get(obj.priority, '#6c757d')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.get_priority_display()
        )
    priority_colored.admin_order_field = 'priority'
    priority_colored.short_description = 'Priority'

    def user_name(self, obj):
        return obj.user.get_full_name() or obj.user.username
    user_name.admin_order_field = 'user__username'
    user_name.short_description = 'Created By'

    def assigned_to_name(self, obj):
        if obj.assigned_to_user:
            return obj.assigned_to_user.get_full_name() or obj.assigned_to_user.username
        return 'Unassigned'
    assigned_to_name.admin_order_field = 'assigned_to_user__username'
    assigned_to_name.short_description = 'Assigned To'

    def sla_status_colored(self, obj):
        if obj.sla_breach:
            return format_html('<span style="color: #dc3545; font-weight: bold;">Breached</span>')
        elif obj.resolved_at:
            return format_html('<span style="color: #28a745; font-weight: bold;">Met</span>')
        else:
            # Check if close to breach
            if obj.sla_target_date and timezone.now() > obj.sla_target_date * 0.8:
                return format_html('<span style="color: #ffc107; font-weight: bold;">At Risk</span>')
            return format_html('<span style="color: #17a2b8;">On Track</span>')
    sla_status_colored.admin_order_field = 'sla_breach'
    sla_status_colored.short_description = 'SLA Status'

    def comments_count(self, obj):
        return obj.comments_count
    comments_count.admin_order_field = 'comments_count'
    comments_count.short_description = 'Comments'

    def attachments_count(self, obj):
        return obj.attachments_count
    attachments_count.admin_order_field = 'attachments_count'
    attachments_count.short_description = 'Attachments'

    def mark_resolved(self, request, queryset):
        updated = queryset.update(status='Resolved', resolved_at=timezone.now())
        self.message_user(request, f'{updated} tickets marked as resolved.')
    mark_resolved.short_description = 'Mark selected tickets as resolved'

    def mark_closed(self, request, queryset):
        updated = queryset.update(status='Closed')
        self.message_user(request, f'{updated} tickets marked as closed.')
    mark_closed.short_description = 'Mark selected tickets as closed'

    def assign_to_hr(self, request, queryset):
        updated = queryset.update(assigned_group='HR')
        self.message_user(request, f'{updated} tickets assigned to HR group.')
    assign_to_hr.short_description = 'Assign selected tickets to HR'

    def escalate_priority(self, request, queryset):
        for ticket in queryset:
            if ticket.priority == 'Low':
                ticket.priority = 'Medium'
            elif ticket.priority == 'Medium':
                ticket.priority = 'High'
            elif ticket.priority == 'High':
                ticket.priority = 'Critical'
            ticket.escalation_level += 1
            ticket.save()
        self.message_user(request, f'{queryset.count()} tickets escalated.')
    escalate_priority.short_description = 'Escalate priority of selected tickets'


class CommentAttachmentInline(admin.TabularInline):
    model = CommentAttachment
    extra = 0
    readonly_fields = ['uploaded_at', 'file_size', 'content_type']
    fields = ['file', 'original_filename', 'description', 'uploaded_by', 'uploaded_at', 'file_size']


@admin.register(TicketComment)
class TicketCommentAdmin(admin.ModelAdmin):
    list_display = ['ticket_link', 'user_name', 'content_preview', 'is_internal', 'created_at']
    list_filter = ['is_internal', 'created_at', 'ticket__status']
    search_fields = ['content', 'ticket__ticket_id', 'user__username']
    readonly_fields = ['created_at']
    inlines = [CommentAttachmentInline]
    date_hierarchy = 'created_at'
    ordering = ['-created_at']

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('ticket', 'user')

    def ticket_link(self, obj):
        url = reverse('admin:trueAlign_support_change', args=[obj.ticket.pk])
        return format_html('<a href="{}">{}</a>', url, obj.ticket.ticket_id)
    ticket_link.short_description = 'Ticket'

    def user_name(self, obj):
        return obj.user.get_full_name() or obj.user.username
    user_name.short_description = 'User'

    def content_preview(self, obj):
        return obj.content[:100] + '...' if len(obj.content) > 100 else obj.content
    content_preview.short_description = 'Content'


class TicketAttachmentInline(admin.TabularInline):
    model = TicketAttachment
    extra = 0
    readonly_fields = ['uploaded_at', 'file_size', 'file_type']
    fields = ['file', 'original_filename', 'description', 'uploaded_by', 'uploaded_at', 'file_size']


@admin.register(TicketAttachment)
class TicketAttachmentAdmin(admin.ModelAdmin):
    list_display = ['ticket_link', 'original_filename', 'file_size_human', 'uploaded_by_name', 'uploaded_at']
    list_filter = ['uploaded_at', 'file_type', 'is_deleted']
    search_fields = ['original_filename', 'ticket__ticket_id', 'uploaded_by__username']
    readonly_fields = ['uploaded_at', 'file_size', 'file_type', 'formatted_filename']
    date_hierarchy = 'uploaded_at'
    ordering = ['-uploaded_at']

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('ticket', 'uploaded_by')

    def ticket_link(self, obj):
        url = reverse('admin:trueAlign_support_change', args=[obj.ticket.pk])
        return format_html('<a href="{}">{}</a>', url, obj.ticket.ticket_id)
    ticket_link.short_description = 'Ticket'

    def uploaded_by_name(self, obj):
        return obj.uploaded_by.get_full_name() or obj.uploaded_by.username
    uploaded_by_name.short_description = 'Uploaded By'


@admin.register(TicketActivity)
class TicketActivityAdmin(admin.ModelAdmin):
    list_display = ['ticket_link', 'action', 'user_name', 'details_preview', 'timestamp']
    list_filter = ['action', 'timestamp']
    search_fields = ['ticket__ticket_id', 'user__username', 'details']
    readonly_fields = ['timestamp']
    date_hierarchy = 'timestamp'
    ordering = ['-timestamp']

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('ticket', 'user')

    def ticket_link(self, obj):
        url = reverse('admin:trueAlign_support_change', args=[obj.ticket.pk])
        return format_html('<a href="{}">{}</a>', url, obj.ticket.ticket_id)
    ticket_link.short_description = 'Ticket'

    def user_name(self, obj):
        if obj.user:
            return obj.user.get_full_name() or obj.user.username
        return 'System'
    user_name.short_description = 'User'

    def details_preview(self, obj):
        return obj.details[:100] + '...' if len(obj.details) > 100 else obj.details
    details_preview.short_description = 'Details'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


@admin.register(CommentAttachment)
class CommentAttachmentAdmin(admin.ModelAdmin):
    list_display = ['comment_link', 'original_filename', 'file_size_human', 'uploaded_by_name', 'uploaded_at']
    list_filter = ['uploaded_at', 'content_type', 'is_active']
    search_fields = ['original_filename', 'comment__ticket__ticket_id', 'uploaded_by__username']
    readonly_fields = ['uploaded_at', 'file_size', 'content_type', 'formatted_filename']
    date_hierarchy = 'uploaded_at'
    ordering = ['-uploaded_at']

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('comment', 'uploaded_by')

    def comment_link(self, obj):
        url = reverse('admin:trueAlign_ticketcomment_change', args=[obj.comment.pk])
        return format_html('<a href="{}">Comment #{}</a>', url, obj.comment.pk)
    comment_link.short_description = 'Comment'

    def uploaded_by_name(self, obj):
        return obj.uploaded_by.get_full_name() or obj.uploaded_by.username
    uploaded_by_name.short_description = 'Uploaded By'


@admin.register(StatusLog)
class StatusLogAdmin(admin.ModelAdmin):
    list_display = ['ticket_link', 'old_status', 'new_status', 'changed_by_name', 'changed_at']
    list_filter = ['old_status', 'new_status', 'changed_at']
    search_fields = ['ticket__ticket_id', 'changed_by__username']
    readonly_fields = ['changed_at']
    date_hierarchy = 'changed_at'
    ordering = ['-changed_at']

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('ticket', 'changed_by')

    def ticket_link(self, obj):
        url = reverse('admin:trueAlign_support_change', args=[obj.ticket.pk])
        return format_html('<a href="{}">{}</a>', url, obj.ticket.ticket_id)
    ticket_link.short_description = 'Ticket'

    def changed_by_name(self, obj):
        if obj.changed_by:
            return obj.changed_by.get_full_name() or obj.changed_by.username
        return 'System'
    changed_by_name.short_description = 'Changed By'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False


# Inline configurations for Support admin
class TicketCommentInline(admin.TabularInline):
    model = TicketComment
    extra = 0
    readonly_fields = ['created_at']
    fields = ['user', 'content', 'is_internal', 'created_at']
    ordering = ['-created_at']

class TicketActivityInline(admin.TabularInline):
    model = TicketActivity
    extra = 0
    readonly_fields = ['action', 'user', 'timestamp', 'details']
    fields = ['action', 'user', 'timestamp', 'details']
    ordering = ['-timestamp']

    def has_add_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

# Add inlines to Support admin
SupportAdmin.inlines = [TicketCommentInline, TicketAttachmentInline, TicketActivityInline]


# Custom admin site configuration
admin.site.site_header = "Support System Administration"
admin.site.site_title = "Support Admin"
admin.site.index_title = "Support System Management"
