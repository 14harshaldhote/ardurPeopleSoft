from django.contrib import admin
from simple_history.admin import SimpleHistoryAdmin
from trueAlign.models import LetterTemplate, GeneratedLetter

@admin.register(LetterTemplate)
class LetterTemplateAdmin(SimpleHistoryAdmin):
    list_display = ('name', 'type', 'is_active', 'created_at', 'updated_at')
    list_filter = ('type', 'is_active')
    search_fields = ('name', 'content')
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        (None, {
            'fields': ('name', 'type', 'is_active')
        }),
        ('Content', {
            'fields': ('content', 'placeholders')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at')
        }),
    )

@admin.register(GeneratedLetter)
class GeneratedLetterAdmin(SimpleHistoryAdmin):
    list_display = ('template', 'employee', 'generated_by', 'generated_at')
    list_filter = ('template__type', 'generated_at')
    search_fields = ('employee__username', 'employee__first_name', 'employee__last_name', 'template__name')
    readonly_fields = ('generated_at', 'content', 'pdf_file')
    
    def has_add_permission(self, request):
        return False
        
    def has_change_permission(self, request, obj=None):
        return False
