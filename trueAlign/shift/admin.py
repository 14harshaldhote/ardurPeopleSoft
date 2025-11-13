"""
Django Admin Configuration for Shift Management
Provides comprehensive admin interface with advanced features
"""

from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.db.models import Count, Q
from django.utils import timezone
from trueAlign.models import ShiftMaster, ShiftAssignment, ShiftConflict, ShiftValidationRule


@admin.register(ShiftValidationRule)
class ShiftValidationRuleAdmin(admin.ModelAdmin):
    """Admin for shift validation rules"""
    list_display = ['name', 'rule_type', 'value', 'group', 'is_active', 'created_at']
    list_filter = ['rule_type', 'is_active', 'group']
    search_fields = ['name', 'rule_type']
    ordering = ['-created_at']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'rule_type', 'value')
        }),
        ('Scope', {
            'fields': ('group', 'is_active')
        }),
    )


@admin.register(ShiftMaster)
class ShiftMasterAdmin(admin.ModelAdmin):
    """Enhanced admin for shift master"""
    list_display = [
        'name', 'timing_display', 'duration_display',
        'active_assignments_count', 'status_badge', 'created_at'
    ]
    list_filter = [
        'is_active', 'work_days', 'requires_approval', 'created_at'
    ]
    search_fields = ['name', 'description']
    ordering = ['-created_at']
    readonly_fields = ['created_at', 'updated_at', 'crosses_midnight']
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'description', 'color_code')
        }),
        ('Timing', {
            'fields': ('start_time', 'end_time', 'shift_duration', 'crosses_midnight')
        }),
        ('Breaks & Grace Periods', {
            'fields': ('break_duration', 'grace_period')
        }),
        ('Work Days', {
            'fields': ('work_days', 'custom_work_days')
        }),
        ('Business Rules', {
            'fields': ('min_rest_hours', 'max_consecutive_days', 'overtime_threshold')
        }),
        ('Status & Approval', {
            'fields': ('is_active', 'requires_approval')
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def shift_type_badge(self, obj):
        """Display shift type with color badge"""
        colors = {
            'MORNING': '#10B981',  # Green
            'EVENING': '#F59E0B',  # Yellow
            'NIGHT': '#6366F1',    # Indigo
            'CUSTOM': '#6B7280'    # Gray
        }
        color = colors.get(obj.shift_type, '#6B7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 8px; '
            'border-radius: 12px; font-size: 11px;">{}</span>',
            color, obj.get_shift_type_display()
        )
    shift_type_badge.short_description = 'Type'
    
    def timing_display(self, obj):
        """Display shift timing"""
        return f"{obj.start_time.strftime('%H:%M')} - {obj.end_time.strftime('%H:%M')}"
    timing_display.short_description = 'Timing'
    
    def duration_display(self, obj):
        """Display shift duration with break info"""
        return f"{obj.shift_duration}h (Work: {obj.expected_work_hours}h)"
    duration_display.short_description = 'Duration'
    
    def active_assignments_count(self, obj):
        """Count of active assignments"""
        count = obj.assignments.filter(status__in=['ACTIVE', 'APPROVED']).count()
        if count > 0:
            url = reverse('admin:shift_shiftassignment_changelist')
            return format_html(
                '<a href="{}?shift__id__exact={}">{} assignments</a>',
                url, obj.id, count
            )
        return '0 assignments'
    active_assignments_count.short_description = 'Active Assignments'
    
    def status_badge(self, obj):
        """Display status with color"""
        if obj.is_active:
            return format_html(
                '<span style="color: #10B981; font-weight: bold;">● Active</span>'
            )
        return format_html(
            '<span style="color: #EF4444; font-weight: bold;">● Inactive</span>'
        )
    status_badge.short_description = 'Status'
    
    def get_queryset(self, request):
        """Optimize queryset with annotations"""
        return super().get_queryset(request).annotate(
            assignments_count=Count('assignments')
        )


class ShiftConflictInline(admin.TabularInline):
    """Inline for shift conflicts"""
    model = ShiftConflict
    fk_name = 'assignment'  # Specify which ForeignKey to use
    extra = 0
    readonly_fields = ['conflict_type', 'severity', 'description', 'is_resolved', 'created_at']
    fields = ['conflict_type', 'severity', 'description', 'is_resolved', 'created_at']
    
    def has_add_permission(self, request, obj=None):
        return False


@admin.register(ShiftAssignment)
class ShiftAssignmentAdmin(admin.ModelAdmin):
    """Enhanced admin for shift assignments"""
    list_display = [
        'user_display', 'shift_display', 'date_range_display',
        'status_badge', 'current_badge', 'days_remaining_display', 'created_at'
    ]
    list_filter = [
        'status', 'is_current', 'requires_approval',
        'created_at', 'effective_from'
    ]
    search_fields = [
        'user__username', 'user__first_name', 'user__last_name',
        'shift__name', 'notes'
    ]
    ordering = ['-created_at']
    readonly_fields = [
        'created_at', 'updated_at', 'assignment_hash'
    ]
    inlines = [ShiftConflictInline]
    
    fieldsets = (
        ('Assignment Details', {
            'fields': ('user', 'shift', 'status')
        }),
        ('Date Range', {
            'fields': ('effective_from', 'effective_to', 'is_current')
        }),
        ('Approval', {
            'fields': ('requires_approval', 'approved_by', 'approved_at')
        }),
        ('Notes', {
            'fields': ('notes',)
        }),
        ('Metadata', {
            'fields': ('created_by', 'created_at', 'updated_at', 'assignment_hash'),
            'classes': ('collapse',)
        }),
    )
    
    def user_display(self, obj):
        """Display user with link"""
        return format_html(
            '<a href="{}">{}</a>',
            reverse('admin:auth_user_change', args=[obj.user.id]),
            obj.user.get_full_name() or obj.user.username
        )
    user_display.short_description = 'User'
    
    def shift_display(self, obj):
        """Display shift with color"""
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            obj.shift.color_code, obj.shift.name
        )
    shift_display.short_description = 'Shift'
    
    def date_range_display(self, obj):
        """Display date range"""
        end_date = obj.effective_to.strftime('%Y-%m-%d') if obj.effective_to else 'Ongoing'
        return f"{obj.effective_from.strftime('%Y-%m-%d')} to {end_date}"
    date_range_display.short_description = 'Date Range'
    
    def status_badge(self, obj):
        """Display status with color"""
        colors = {
            'ACTIVE': '#10B981',
            'PENDING': '#F59E0B',
            'APPROVED': '#3B82F6',
            'REJECTED': '#EF4444',
            'EXPIRED': '#6B7280'
        }
        color = colors.get(obj.status, '#6B7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 8px; '
            'border-radius: 12px; font-size: 11px;">{}</span>',
            color, obj.get_status_display()
        )
    status_badge.short_description = 'Status'
    
    def current_badge(self, obj):
        """Display current status"""
        if obj.is_current:
            return format_html(
                '<span style="color: #10B981; font-weight: bold;">● Current</span>'
            )
        return format_html(
            '<span style="color: #6B7280;">○ Not Current</span>'
        )
    current_badge.short_description = 'Current'
    
    def days_remaining_display(self, obj):
        """Display days remaining"""
        days = obj.days_remaining
        if days is None:
            return 'Ongoing'
        elif days <= 0:
            return 'Expired'
        elif days <= 7:
            return format_html(
                '<span style="color: #F59E0B; font-weight: bold;">{} days</span>',
                days
            )
        return f"{days} days"
    days_remaining_display.short_description = 'Days Remaining'
    
    def get_queryset(self, request):
        """Optimize queryset"""
        return super().get_queryset(request).select_related(
            'user', 'shift', 'created_by', 'approved_by'
        )
    
    actions = ['approve_assignments', 'reject_assignments', 'mark_as_current']
    
    def approve_assignments(self, request, queryset):
        """Bulk approve assignments"""
        count = 0
        for assignment in queryset.filter(status='PENDING'):
            assignment.approve(request.user)
            count += 1
        
        self.message_user(
            request,
            f'Successfully approved {count} assignments.'
        )
    approve_assignments.short_description = 'Approve selected assignments'
    
    def reject_assignments(self, request, queryset):
        """Bulk reject assignments"""
        count = 0
        for assignment in queryset.filter(status='PENDING'):
            assignment.reject('Bulk rejection from admin')
            count += 1
        
        self.message_user(
            request,
            f'Successfully rejected {count} assignments.'
        )
    reject_assignments.short_description = 'Reject selected assignments'
    
    def mark_as_current(self, request, queryset):
        """Mark assignments as current"""
        count = queryset.update(is_current=True)
        self.message_user(
            request,
            f'Successfully marked {count} assignments as current.'
        )
    mark_as_current.short_description = 'Mark as current'


@admin.register(ShiftConflict)
class ShiftConflictAdmin(admin.ModelAdmin):
    """Admin for shift conflicts"""
    list_display = [
        'assignment_display', 'conflict_type_badge', 'severity_badge',
        'resolution_status', 'created_at'
    ]
    list_filter = [
        'conflict_type', 'severity', 'is_resolved', 'created_at'
    ]
    search_fields = [
        'assignment__user__username', 'assignment__shift__name',
        'description', 'resolution_notes'
    ]
    ordering = ['-created_at']
    readonly_fields = ['created_at']
    
    fieldsets = (
        ('Conflict Details', {
            'fields': ('assignment', 'conflicting_assignment', 'conflict_type', 'severity')
        }),
        ('Description', {
            'fields': ('description',)
        }),
        ('Resolution', {
            'fields': ('is_resolved', 'resolved_by', 'resolved_at', 'resolution_notes')
        }),
        ('Metadata', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        }),
    )
    
    def assignment_display(self, obj):
        """Display assignment info"""
        return f"{obj.assignment.user.username} - {obj.assignment.shift.name}"
    assignment_display.short_description = 'Assignment'
    
    def conflict_type_badge(self, obj):
        """Display conflict type with color"""
        colors = {
            'OVERLAP': '#EF4444',
            'REST_VIOLATION': '#F59E0B',
            'MAX_HOURS': '#F59E0B',
            'ROLE_RESTRICTION': '#8B5CF6',
            'APPROVAL_REQUIRED': '#3B82F6'
        }
        color = colors.get(obj.conflict_type, '#6B7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 8px; '
            'border-radius: 12px; font-size: 11px;">{}</span>',
            color, obj.get_conflict_type_display()
        )
    conflict_type_badge.short_description = 'Type'
    
    def severity_badge(self, obj):
        """Display severity with color"""
        colors = {
            'LOW': '#10B981',
            'MEDIUM': '#F59E0B',
            'HIGH': '#EF4444',
            'CRITICAL': '#7C2D12'
        }
        color = colors.get(obj.severity, '#6B7280')
        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 8px; '
            'border-radius: 12px; font-size: 11px;">{}</span>',
            color, obj.get_severity_display()
        )
    severity_badge.short_description = 'Severity'
    
    def resolution_status(self, obj):
        """Display resolution status"""
        if obj.is_resolved:
            return format_html(
                '<span style="color: #10B981; font-weight: bold;">✓ Resolved</span>'
            )
        return format_html(
            '<span style="color: #EF4444; font-weight: bold;">⚠ Unresolved</span>'
        )
    resolution_status.short_description = 'Status'
    
    actions = ['resolve_conflicts']
    
    def resolve_conflicts(self, request, queryset):
        """Bulk resolve conflicts"""
        count = 0
        for conflict in queryset.filter(is_resolved=False):
            conflict.resolve(request.user, 'Bulk resolution from admin')
            count += 1
        
        self.message_user(
            request,
            f'Successfully resolved {count} conflicts.'
        )
    resolve_conflicts.short_description = 'Resolve selected conflicts'


# Customize admin site
admin.site.site_header = 'Shift Management System'
admin.site.site_title = 'Shift Admin'
admin.site.index_title = 'Shift Management Administration'
