from django.contrib import admin
from trueAlign.models import UserDetails, UserActionLog

class UserDetailsAdmin(admin.ModelAdmin):
    list_display = ('user', 'role', 'employment_status', 'office_location')
    search_fields = ('user__username', 'user__first_name', 'user__last_name', 'user__email')
    list_filter = ('employment_status', 'role', 'office_location')
    ordering = ('user__username',)

class UserActionLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'action_type', 'action_by', 'timestamp')
    search_fields = ('user__username', 'action_by__username', 'action_type')
    list_filter = ('action_type', 'timestamp')
    ordering = ('-timestamp',)

admin.site.register(UserDetails, UserDetailsAdmin)
admin.site.register(UserActionLog, UserActionLogAdmin)
