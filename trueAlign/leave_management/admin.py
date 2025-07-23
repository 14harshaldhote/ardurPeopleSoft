from django.contrib import admin
from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance,
    LeaveRequest, CompOffRequest
)

class LeaveAllocationInline(admin.TabularInline):
    model = LeaveAllocation
    extra = 1

@admin.register(LeaveType)
class LeaveTypeAdmin(admin.ModelAdmin):
    list_display = ('name', 'is_paid', 'requires_approval', 'requires_documentation', 'can_be_half_day', 'is_active')
    list_filter = ('is_paid', 'requires_approval', 'requires_documentation', 'can_be_half_day', 'is_active')
    search_fields = ('name', 'description')
    fieldsets = (
        (None, {
            'fields': ('name', 'description')
        }),
        ('Leave Settings', {
            'fields': ('is_paid', 'requires_approval', 'requires_documentation',
                      'count_weekends', 'can_be_half_day', 'is_active')
        }),
    )

@admin.register(LeavePolicy)
class LeavePolicyAdmin(admin.ModelAdmin):
    list_display = ('name', 'group', 'is_active', 'created_at', 'updated_at')
    list_filter = ('is_active', 'group')
    search_fields = ('name',)
    inlines = [LeaveAllocationInline]

@admin.register(LeaveAllocation)
class LeaveAllocationAdmin(admin.ModelAdmin):
    list_display = ('policy', 'leave_type', 'annual_days', 'carry_forward_limit',
                   'max_consecutive_days', 'advance_notice_days')
    list_filter = ('policy', 'leave_type')
    search_fields = ('policy__name', 'leave_type__name')

@admin.register(UserLeaveBalance)
class UserLeaveBalanceAdmin(admin.ModelAdmin):
    list_display = ('user', 'leave_type', 'year', 'allocated', 'used',
                   'carried_forward', 'additional', 'available')
    list_filter = ('year', 'leave_type')
    search_fields = ('user__username', 'user__first_name', 'user__last_name', 'leave_type__name')
    readonly_fields = ('available',)

    def available(self, obj):
        return obj.available

@admin.register(LeaveRequest)
class LeaveRequestAdmin(admin.ModelAdmin):
    list_display = ('user', 'leave_type', 'start_date', 'end_date', 'leave_days',
                   'status', 'approver', 'created_at')
    list_filter = ('status', 'leave_type', 'start_date', 'approver')
    search_fields = ('user__username', 'user__first_name', 'user__last_name', 'reason')
    readonly_fields = ('leave_days',)
    date_hierarchy = 'start_date'

    fieldsets = (
        (None, {
            'fields': ('user', 'leave_type', 'start_date', 'end_date', 'half_day', 'leave_days')
        }),
        ('Request Details', {
            'fields': ('reason', 'status', 'approver', 'rejection_reason', 'documentation')
        }),
        ('Additional Information', {
            'fields': ('suggested_dates', 'is_retroactive', 'created_at', 'updated_at')
        }),
    )

@admin.register(CompOffRequest)
class CompOffRequestAdmin(admin.ModelAdmin):
    list_display = ('user', 'worked_date', 'hours_worked', 'status', 'approver')
    list_filter = ('status', 'worked_date')
    search_fields = ('user__username', 'user__first_name', 'user__last_name', 'reason')
