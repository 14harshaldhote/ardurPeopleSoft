from django.contrib import admin
from django.contrib.auth.models import User
from django.db import models
from django.forms import TextInput, Textarea
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import path, reverse
from django.utils.html import format_html
from django.utils.safestring import mark_safe
from django.contrib import messages
from django.db.models import Count, Q
from django.utils import timezone
from datetime import date, timedelta
from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday


class ShiftAssignmentInline(admin.TabularInline):
    """Inline admin for shift assignments."""
    model = ShiftAssignment
    extra = 0
    fields = ('user', 'effective_from', 'effective_to', 'is_current', 'created_at')
    readonly_fields = ('created_at',)
    raw_id_fields = ('user',)

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user')


@admin.register(ShiftMaster)
class ShiftMasterAdmin(admin.ModelAdmin):
    """Admin interface for ShiftMaster."""

    list_display = (
        'name', 'shift_time_display', 'duration_display', 'work_days_display',
        'active_assignments_count', 'is_active', 'crosses_midnight_display', 'created_at'
    )
    list_filter = (
        'is_active', 'work_days', 'created_at', 'updated_at'
    )
    search_fields = ('name', 'custom_work_days')
    ordering = ('name',)

    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'is_active')
        }),
        ('Shift Timing', {
            'fields': (
                ('start_time', 'end_time'),
                'shift_duration',
                ('break_duration', 'grace_period'),
            ),
            'description': 'Configure shift timing and duration settings.'
        }),
        ('Working Days', {
            'fields': ('work_days', 'custom_work_days'),
            'description': 'Set which days this shift is active.'
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    readonly_fields = ('created_at', 'updated_at')
    inlines = [ShiftAssignmentInline]

    actions = ['activate_shifts', 'deactivate_shifts', 'duplicate_shifts']

    # Custom display methods
    def shift_time_display(self, obj):
        """Display shift time range with midnight crossing indicator."""
        time_range = f"{obj.start_time.strftime('%H:%M')} - {obj.end_time.strftime('%H:%M')}"
        if obj.crosses_midnight:
            return format_html(
                '{} <span style="color: orange; font-weight: bold;">(crosses midnight)</span>',
                time_range
            )
        return time_range
    shift_time_display.short_description = 'Shift Time'
    shift_time_display.admin_order_field = 'start_time'

    def duration_display(self, obj):
        """Display shift duration with expected hours."""
        return f"{obj.shift_duration}h (work: {obj.expected_hours}h)"
    duration_display.short_description = 'Duration'
    duration_display.admin_order_field = 'shift_duration'

    def work_days_display(self, obj):
        """Display work days with custom days if applicable."""
        if obj.work_days == 'Custom' and obj.custom_work_days:
            return f"{obj.work_days}: {obj.custom_work_days}"
        return obj.work_days
    work_days_display.short_description = 'Work Days'
    work_days_display.admin_order_field = 'work_days'

    def crosses_midnight_display(self, obj):
        """Display midnight crossing status with icon."""
        if obj.crosses_midnight:
            return format_html(
                '<span style="color: orange;">🌙 Yes</span>'
            )
        return format_html(
            '<span style="color: green;">☀️ No</span>'
        )
    crosses_midnight_display.short_description = 'Crosses Midnight'
    crosses_midnight_display.admin_order_field = 'end_time'

    def active_assignments_count(self, obj):
        """Display count of active assignments."""
        count = obj.shiftassignment_set.filter(is_current=True).count()
        if count > 0:
            url = reverse('admin:trueAlign_shiftassignment_changelist')
            return format_html(
                '<a href="{}?shift__id__exact={}&is_current__exact=1" style="color: blue;">{} active</a>',
                url, obj.id, count
            )
        return "0 active"
    active_assignments_count.short_description = 'Active Assignments'

    # Custom actions
    def activate_shifts(self, request, queryset):
        """Bulk activate selected shifts."""
        updated = queryset.update(is_active=True)
        self.message_user(
            request,
            f'{updated} shift(s) were successfully activated.',
            messages.SUCCESS
        )
    activate_shifts.short_description = "Activate selected shifts"

    def deactivate_shifts(self, request, queryset):
        """Bulk deactivate selected shifts."""
        updated = queryset.update(is_active=False)
        self.message_user(
            request,
            f'{updated} shift(s) were successfully deactivated.',
            messages.WARNING
        )
    deactivate_shifts.short_description = "Deactivate selected shifts"

    def duplicate_shifts(self, request, queryset):
        """Duplicate selected shifts."""
        duplicated = 0
        for shift in queryset:
            # Create a copy with a new name
            new_shift = ShiftMaster(
                name=f"{shift.name} (Copy)",
                start_time=shift.start_time,
                end_time=shift.end_time,
                shift_duration=shift.shift_duration,
                break_duration=shift.break_duration,
                grace_period=shift.grace_period,
                work_days=shift.work_days,
                custom_work_days=shift.custom_work_days,
                is_active=False  # Start as inactive
            )
            new_shift.save()
            duplicated += 1

        self.message_user(
            request,
            f'{duplicated} shift(s) were successfully duplicated.',
            messages.SUCCESS
        )
    duplicate_shifts.short_description = "Duplicate selected shifts"

    def get_queryset(self, request):
        """Optimize queryset with annotations."""
        return super().get_queryset(request).annotate(
            active_assignments_count=Count(
                'shiftassignment',
                filter=Q(shiftassignment__is_current=True)
            )
        )

    # Custom form widgets
    formfield_overrides = {
        models.CharField: {'widget': TextInput(attrs={'size': '40'})},
        models.TextField: {'widget': Textarea(attrs={'rows': 3, 'cols': 40})},
    }


@admin.register(ShiftAssignment)
class ShiftAssignmentAdmin(admin.ModelAdmin):
    """Admin interface for ShiftAssignment."""

    list_display = (
        'user_display', 'shift_display', 'effective_from', 'effective_to',
        'status_display', 'days_remaining_display', 'created_at'
    )
    list_filter = (
        'is_current', 'shift', 'effective_from', 'effective_to', 'created_at'
    )
    search_fields = (
        'user__username', 'user__first_name', 'user__last_name',
        'shift__name'
    )
    ordering = ('-created_at',)
    date_hierarchy = 'effective_from'

    fieldsets = (
        ('Assignment Details', {
            'fields': (
                ('user', 'shift'),
                ('effective_from', 'effective_to'),
                'is_current'
            )
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )
    readonly_fields = ('created_at', 'updated_at')
    raw_id_fields = ('user',)

    actions = ['end_assignments', 'extend_assignments', 'make_current']

    # Custom display methods
    def user_display(self, obj):
        """Display user with full name and link."""
        full_name = obj.user.get_full_name()
        display_name = f"{obj.user.username}"
        if full_name:
            display_name += f" ({full_name})"

        url = reverse('admin:auth_user_change', args=[obj.user.id])
        return format_html('<a href="{}">{}</a>', url, display_name)
    user_display.short_description = 'User'
    user_display.admin_order_field = 'user__username'

    def shift_display(self, obj):
        """Display shift with time range."""
        shift_info = f"{obj.shift.name} ({obj.shift.start_time.strftime('%H:%M')}-{obj.shift.end_time.strftime('%H:%M')})"
        url = reverse('admin:trueAlign_shiftmaster_change', args=[obj.shift.id])
        return format_html('<a href="{}">{}</a>', url, shift_info)
    shift_display.short_description = 'Shift'
    shift_display.admin_order_field = 'shift__name'

    def status_display(self, obj):
        """Display assignment status with color coding."""
        if obj.has_ended():
            return format_html(
                '<span style="color: red; font-weight: bold;">Ended</span>'
            )
        elif obj.is_current:
            return format_html(
                '<span style="color: green; font-weight: bold;">Active</span>'
            )
        else:
            return format_html(
                '<span style="color: orange; font-weight: bold;">Inactive</span>'
            )
    status_display.short_description = 'Status'

    def days_remaining_display(self, obj):
        """Display days remaining in assignment."""
        days = obj.days_remaining()
        if days is None:
            return "Open-ended"
        elif days <= 0:
            return format_html('<span style="color: red;">Ended</span>')
        elif days <= 7:
            return format_html('<span style="color: orange;">{} days</span>', days)
        else:
            return f"{days} days"
    days_remaining_display.short_description = 'Days Remaining'

    # Custom actions
    def end_assignments(self, request, queryset):
        """Bulk end selected assignments."""
        today = timezone.now().date()
        updated = 0

        for assignment in queryset.filter(is_current=True):
            if not assignment.effective_to or assignment.effective_to > today:
                assignment.effective_to = today
                assignment.is_current = False
                assignment.save()
                updated += 1

        self.message_user(
            request,
            f'{updated} assignment(s) were ended.',
            messages.SUCCESS
        )
    end_assignments.short_description = "End selected assignments"

    def extend_assignments(self, request, queryset):
        """Extend selected assignments by 30 days."""
        extended = 0

        for assignment in queryset.filter(effective_to__isnull=False):
            assignment.effective_to += timedelta(days=30)
            assignment.save()
            extended += 1

        self.message_user(
            request,
            f'{extended} assignment(s) were extended by 30 days.',
            messages.SUCCESS
        )
    extend_assignments.short_description = "Extend assignments by 30 days"

    def make_current(self, request, queryset):
        """Make selected assignments current."""
        updated = queryset.update(is_current=True)
        self.message_user(
            request,
            f'{updated} assignment(s) were made current.',
            messages.SUCCESS
        )
    make_current.short_description = "Make assignments current"

    def get_queryset(self, request):
        """Optimize queryset with select_related."""
        return super().get_queryset(request).select_related('user', 'shift')


@admin.register(Holiday)
class HolidayAdmin(admin.ModelAdmin):
    """Admin interface for Holiday."""

    list_display = (
        'name', 'date', 'day_of_week', 'recurring_yearly_display',
        'days_until_display', 'created_at'
    )
    list_filter = ('recurring_yearly', 'date', 'created_at')
    search_fields = ('name',)
    ordering = ('date',)
    date_hierarchy = 'date'

    fieldsets = (
        ('Holiday Information', {
            'fields': ('name', 'date', 'recurring_yearly')
        }),
        ('Metadata', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        })
    )
    readonly_fields = ('created_at',)

    actions = ['make_recurring', 'make_non_recurring', 'duplicate_for_next_year']

    # Custom display methods
    def day_of_week(self, obj):
        """Display day of week for the holiday."""
        return obj.date.strftime('%A')
    day_of_week.short_description = 'Day of Week'

    def recurring_yearly_display(self, obj):
        """Display recurring status with icon."""
        if obj.recurring_yearly:
            return format_html(
                '<span style="color: green;">🔄 Yes</span>'
            )
        return format_html(
            '<span style="color: gray;">📅 No</span>'
        )
    recurring_yearly_display.short_description = 'Recurring'
    recurring_yearly_display.admin_order_field = 'recurring_yearly'

    def days_until_display(self, obj):
        """Display days until holiday."""
        today = timezone.now().date()

        if obj.recurring_yearly:
            # Calculate next occurrence
            current_year = today.year
            this_year_date = obj.date.replace(year=current_year)

            if this_year_date >= today:
                target_date = this_year_date
            else:
                target_date = obj.date.replace(year=current_year + 1)
        else:
            target_date = obj.date

        delta = (target_date - today).days

        if delta < 0:
            return format_html('<span style="color: gray;">Past</span>')
        elif delta == 0:
            return format_html('<span style="color: red; font-weight: bold;">Today!</span>')
        elif delta <= 7:
            return format_html('<span style="color: orange; font-weight: bold;">{} days</span>', delta)
        else:
            return f"{delta} days"
    days_until_display.short_description = 'Days Until'

    # Custom actions
    def make_recurring(self, request, queryset):
        """Make selected holidays recurring."""
        updated = queryset.update(recurring_yearly=True)
        self.message_user(
            request,
            f'{updated} holiday(s) were made recurring.',
            messages.SUCCESS
        )
    make_recurring.short_description = "Make holidays recurring"

    def make_non_recurring(self, request, queryset):
        """Make selected holidays non-recurring."""
        updated = queryset.update(recurring_yearly=False)
        self.message_user(
            request,
            f'{updated} holiday(s) were made non-recurring.',
            messages.SUCCESS
        )
    make_non_recurring.short_description = "Make holidays non-recurring"

    def duplicate_for_next_year(self, request, queryset):
        """Create copies of holidays for next year."""
        duplicated = 0
        next_year = timezone.now().year + 1

        for holiday in queryset:
            try:
                new_date = holiday.date.replace(year=next_year)
                Holiday.objects.get_or_create(
                    name=holiday.name,
                    date=new_date,
                    defaults={'recurring_yearly': holiday.recurring_yearly}
                )
                duplicated += 1
            except ValueError:
                # Handle leap year edge case (Feb 29)
                continue

        self.message_user(
            request,
            f'{duplicated} holiday(s) were duplicated for {next_year}.',
            messages.SUCCESS
        )
    duplicate_for_next_year.short_description = f"Duplicate for {timezone.now().year + 1}"


# Custom admin site configuration
class ShiftAdminSite(admin.AdminSite):
    """Custom admin site for shift management."""

    site_header = "Shift Management Administration"
    site_title = "Shift Admin"
    index_title = "Welcome to Shift Management"

    def get_urls(self):
        """Add custom URLs to admin site."""
        urls = super().get_urls()
        custom_urls = [
            path('shift-statistics/', self.admin_view(self.shift_statistics_view), name='shift_statistics'),
            path('bulk-assignment/', self.admin_view(self.bulk_assignment_view), name='bulk_assignment'),
        ]
        return custom_urls + urls

    def shift_statistics_view(self, request):
        """Custom view for shift statistics."""
        from trueAlign.shift.services import ShiftService

        service = ShiftService()
        stats = service.get_shift_statistics()

        context = {
            'title': 'Shift Statistics',
            'statistics': stats,
            'opts': {'app_label': 'trueAlign', 'model_name': 'shift_statistics'},
        }

        return render(request, 'admin/shift_statistics.html', context)

    def bulk_assignment_view(self, request):
        """Custom view for bulk assignments."""
        if request.method == 'POST':
            # Handle bulk assignment logic here
            pass

        context = {
            'title': 'Bulk Assignment',
            'opts': {'app_label': 'trueAlign', 'model_name': 'bulk_assignment'},
        }

        return render(request, 'admin/bulk_assignment.html', context)


# Register custom admin site
shift_admin_site = ShiftAdminSite(name='shift_admin')
shift_admin_site.register(ShiftMaster, ShiftMasterAdmin)
shift_admin_site.register(ShiftAssignment, ShiftAssignmentAdmin)
shift_admin_site.register(Holiday, HolidayAdmin)


# Admin customizations for better UX
admin.site.site_header = "TrueAlign Administration"
admin.site.site_title = "TrueAlign Admin"
admin.site.index_title = "Welcome to TrueAlign Administration"


# Custom filters
class ActiveShiftFilter(admin.SimpleListFilter):
    """Custom filter for active shifts."""
    title = 'shift status'
    parameter_name = 'shift_status'

    def lookups(self, request, model_admin):
        return (
            ('active', 'Active shifts only'),
            ('inactive', 'Inactive shifts only'),
            ('with_assignments', 'Shifts with assignments'),
            ('without_assignments', 'Shifts without assignments'),
        )

    def queryset(self, request, queryset):
        if self.value() == 'active':
            return queryset.filter(is_active=True)
        elif self.value() == 'inactive':
            return queryset.filter(is_active=False)
        elif self.value() == 'with_assignments':
            return queryset.filter(shiftassignment__isnull=False).distinct()
        elif self.value() == 'without_assignments':
            return queryset.filter(shiftassignment__isnull=True)
        return queryset


class AssignmentStatusFilter(admin.SimpleListFilter):
    """Custom filter for assignment status."""
    title = 'assignment status'
    parameter_name = 'assignment_status'

    def lookups(self, request, model_admin):
        return (
            ('current', 'Current assignments'),
            ('ended', 'Ended assignments'),
            ('ending_soon', 'Ending within 7 days'),
            ('long_term', 'Long-term (>90 days)'),
        )

    def queryset(self, request, queryset):
        today = timezone.now().date()

        if self.value() == 'current':
            return queryset.filter(is_current=True)
        elif self.value() == 'ended':
            return queryset.filter(is_current=False, effective_to__lt=today)
        elif self.value() == 'ending_soon':
            return queryset.filter(
                effective_to__gte=today,
                effective_to__lte=today + timedelta(days=7)
            )
        elif self.value() == 'long_term':
            return queryset.filter(
                Q(effective_to__gte=today + timedelta(days=90)) |
                Q(effective_to__isnull=True)
            )
        return queryset


# Add custom filters to admin classes
ShiftMasterAdmin.list_filter = ShiftMasterAdmin.list_filter + (ActiveShiftFilter,)
ShiftAssignmentAdmin.list_filter = ShiftAssignmentAdmin.list_filter + (AssignmentStatusFilter,)
