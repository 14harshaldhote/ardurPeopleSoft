from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from django.utils import timezone
from trueAlign.models import GlobalUpdate


@admin.register(GlobalUpdate)
class GlobalUpdateAdmin(admin.ModelAdmin):
    list_display = [
        'title',
        'status_badge',
        'managed_by',
        'scheduled_date_display',
        'created_at',
        'updated_at',
        'view_link'
    ]
    list_filter = [
        'status',
        'primary_language',
        'created_at',
        'scheduled_date',
        'managed_by'
    ]
    search_fields = [
        'title',
        'description',
        'title_hi',
        'description_hi',
        'title_mr',
        'description_mr',
        'managed_by__username',
        'managed_by__first_name',
        'managed_by__last_name'
    ]
    readonly_fields = [
        'created_at',
        'updated_at'
    ]
    fieldsets = (
        ('Basic Information', {
            'fields': ('title', 'description', 'primary_language', 'status')
        }),
        ('Hindi Translation', {
            'fields': ('title_hi', 'description_hi'),
            'classes': ('collapse',),
            'description': 'Hindi translations (optional)'
        }),
        ('Marathi Translation', {
            'fields': ('title_mr', 'description_mr'),
            'classes': ('collapse',),
            'description': 'Marathi translations (optional)'
        }),
        ('Scheduling', {
            'fields': ('scheduled_date',),
            'description': 'Only required for scheduled updates'
        }),
        ('Management', {
            'fields': ('managed_by',)
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    ordering = ['-created_at']
    date_hierarchy = 'created_at'
    list_per_page = 25

    def status_badge(self, obj):
        """Display status as a colored badge"""
        colors = {
            'upcoming': '#ffc107',
            'released': '#28a745',
            'scheduled': '#17a2b8'
        }
        icons = {
            'upcoming': 'clock',
            'released': 'check-circle',
            'scheduled': 'calendar'
        }

        color = colors.get(obj.status, '#6c757d')
        icon = icons.get(obj.status, 'info')

        return format_html(
            '<span style="background-color: {}; color: white; padding: 2px 8px; '
            'border-radius: 10px; font-size: 11px; font-weight: bold;">'
            '<i class="fas fa-{}" style="margin-right: 4px;"></i>{}</span>',
            color, icon, obj.get_status_display()
        )
    status_badge.short_description = 'Status'
    status_badge.admin_order_field = 'status'

    def scheduled_date_display(self, obj):
        """Display scheduled date with formatting"""
        if obj.scheduled_date:
            now = timezone.now()
            if obj.scheduled_date > now:
                time_diff = obj.scheduled_date - now
                if time_diff.days > 0:
                    time_str = f"in {time_diff.days} days"
                else:
                    hours = time_diff.seconds // 3600
                    time_str = f"in {hours} hours"

                return format_html(
                    '<div>{}</div><small style="color: #6c757d;">{}</small>',
                    obj.scheduled_date.strftime('%b %d, %Y %I:%M %p'),
                    time_str
                )
            else:
                return format_html(
                    '<div style="color: #dc3545;">{}</div>'
                    '<small style="color: #dc3545;">Past due</small>',
                    obj.scheduled_date.strftime('%b %d, %Y %I:%M %p')
                )
        return '-'
    scheduled_date_display.short_description = 'Scheduled Date'
    scheduled_date_display.admin_order_field = 'scheduled_date'

    def view_link(self, obj):
        """Link to view the update on frontend"""
        if obj.pk:
            url = reverse('notes:global_update_detail', args=[obj.pk])
            return format_html(
                '<a href="{}" target="_blank" class="button" '
                'style="padding: 4px 8px; background: #007cba; color: white; '
                'text-decoration: none; border-radius: 3px; font-size: 11px;">'
                '<i class="fas fa-external-link-alt"></i> View</a>',
                url
            )
        return '-'
    view_link.short_description = 'Actions'

    def get_queryset(self, request):
        """Optimize queryset with select_related"""
        return super().get_queryset(request).select_related('managed_by')

    def save_model(self, request, obj, form, change):
        """Set managed_by to current user if not set"""
        if not obj.managed_by and not change:
            obj.managed_by = request.user
        super().save_model(request, obj, form, change)

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        """Filter managed_by to HR users only"""
        if db_field.name == "managed_by":
            kwargs["queryset"] = db_field.related_model.objects.filter(
                groups__name="HR"
            ).distinct()
        return super().formfield_for_foreignkey(db_field, request, **kwargs)

    class Media:
        css = {
            'all': ('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css',)
        }

    def has_view_permission(self, request, obj=None):
        """Allow viewing for all staff users"""
        return request.user.is_staff

    def has_change_permission(self, request, obj=None):
        """Allow editing for HR users only"""
        if request.user.is_superuser:
            return True
        return request.user.groups.filter(name='HR').exists()

    def has_add_permission(self, request):
        """Allow adding for HR users only"""
        if request.user.is_superuser:
            return True
        return request.user.groups.filter(name='HR').exists()

    def has_delete_permission(self, request, obj=None):
        """Allow deletion for HR users only"""
        if request.user.is_superuser:
            return True
        return request.user.groups.filter(name='HR').exists()

    def get_readonly_fields(self, request, obj=None):
        """Make managed_by readonly for non-superusers if already set"""
        readonly = list(self.readonly_fields)
        if obj and obj.managed_by and not request.user.is_superuser:
            readonly.append('managed_by')
        return readonly


# Custom admin site configuration
admin.site.site_header = "TrueAlign Global Updates Admin"
admin.site.site_title = "Global Updates Admin"
admin.site.index_title = "Welcome to Global Updates Administration"
