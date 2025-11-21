"""
Enhanced export views with custom field selection
"""

from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.utils import timezone
from datetime import datetime
import openpyxl
from openpyxl.styles import Font, PatternFill, Alignment
from openpyxl.utils import get_column_letter

from trueAlign.models import UserSession
from .views import get_filtered_sessions_queryset


# Available fields for export
EXPORT_FIELDS = {
    'user__username': 'Username',
    'user__first_name': 'First Name',
    'user__last_name': 'Last Name',
    'user__email': 'Email',
    'login_time': 'Login Time',
    'ended_at': 'End Time',
    'duration': 'Duration (minutes)',
    'is_active': 'Is Active',
    'is_idle': 'Is Idle',
    'current_office_location__name': 'Office',
    'device_type': 'Device Type',
    'browser': 'Browser',
    'os': 'Operating System',
    'ip_address': 'IP Address',
    'location_latitude': 'Latitude',
    'location_longitude': 'Longitude',
    'productivity_score': 'Productivity Score',
    'engagement_score': 'Engagement Score',
    'session_key': 'Session Key',
    'created_at': 'Created At',
}


@login_required
def export_selection_page(request):
    """
    Display export configuration page.
    """
    from trueAlign.models import OfficeLocation
    
    context = {
        'available_fields': EXPORT_FIELDS,
        'page_title': 'Export Sessions Data',
        'all_offices': OfficeLocation.objects.filter(is_active=True).order_by('name')
    }
    return render(request, 'sessions/export_selection.html', context)


@login_required
def export_to_excel(request):
    """
    Export sessions data to Excel with custom field selection.
    
    POST Parameters:
    - format: 'xlsx'
    - fields[]: List of field names to include
    - office_id: Filter by office
    - date_from: Start date
    - date_to: End date
    - status: active/idle/ended
    """
    try:
        # Get selected fields
        selected_fields = request.POST.getlist('fields[]') or request.GET.getlist('fields[]')
        if not selected_fields:
            # Default fields if none selected
            selected_fields = [
                'user__username', 'user__first_name', 'user__last_name',
                'login_time', 'ended_at', 'duration', 'current_office_location__name',
                'device_type', 'is_active'
            ]
        
        # Validate fields
        selected_fields = [f for f in selected_fields if f in EXPORT_FIELDS]
        
        # Get filter parameters
        office_id = request.POST.get('office_id') or request.GET.get('office_id')
        date_from = request.POST.get('date_from') or request.GET.get('date_from')
        date_to = request.POST.get('date_to') or request.GET.get('date_to')
        status = request.POST.get('status') or request.GET.get('status')
        
        # Build queryset
        sessions = get_filtered_sessions_queryset(office_id=office_id)
        
        # Apply date filters
        if date_from:
            try:
                date_from_obj = datetime.strptime(date_from, '%Y-%m-%d')
                sessions = sessions.filter(login_time__date__gte=date_from_obj)
            except ValueError:
                pass
        
        if date_to:
            try:
                date_to_obj = datetime.strptime(date_to, '%Y-%m-%d')
                sessions = sessions.filter(login_time__date__lte=date_to_obj)
            except ValueError:
                pass
        
        # Apply status filter
        if status:
            if status == 'active':
                sessions = sessions.filter(is_active=True, is_idle=False)
            elif status == 'idle':
                sessions = sessions.filter(is_active=True, is_idle=True)
            elif status == 'ended':
                sessions = sessions.filter(is_active=False)
        
        # Select related for efficiency
        sessions = sessions.select_related('user', 'current_office_location')
        
        # Create workbook
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Sessions Export"
        
        # Define styles
        header_font = Font(bold=True, color="FFFFFF", size=12)
        header_fill = PatternFill(start_color="4F46E5", end_color="4F46E5", fill_type="solid")
        header_alignment = Alignment(horizontal="center", vertical="center")
        
        # Write headers
        for col_idx, field_key in enumerate(selected_fields, start=1):
            cell = ws.cell(row=1, column=col_idx)
            cell.value = EXPORT_FIELDS[field_key]
            cell.font = header_font
            cell.fill = header_fill
            cell.alignment = header_alignment
        
        # Write data
        for row_idx, session in enumerate(sessions, start=2):
            for col_idx, field_key in enumerate(selected_fields, start=1):
                value = get_field_value(session, field_key)
                ws.cell(row=row_idx, column=col_idx, value=value)
        
        # Auto-size columns
        for col_idx in range(1, len(selected_fields) + 1):
            column_letter = get_column_letter(col_idx)
            ws.column_dimensions[column_letter].width = 20
        
        # Freeze first row
        ws.freeze_panes = "A2"
        
        # Create response
        response = HttpResponse(
            content_type='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )
        filename = f"sessions_export_{timezone.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        wb.save(response)
        return response
        
    except Exception as e:
        return HttpResponse(f"Error generating export: {str(e)}", status=500)


def get_field_value(session, field_key):
    """
    Get field value from session object, handling special cases.
    """
    if field_key == 'duration':
        if session.ended_at:
            duration = (session.ended_at - session.login_time).total_seconds() / 60
            return f"{int(duration)} min"
        else:
            duration = (timezone.now() - session.login_time).total_seconds() / 60
            return f"{int(duration)} min (ongoing)"
    
    # Handle nested fields (e.g., user__username)
    if '__' in field_key:
        parts = field_key.split('__')
        value = session
        for part in parts:
            if value is None:
                return ''
            value = getattr(value, part, None)
        return str(value) if value is not None else ''
    
    # Direct field access
    value = getattr(session, field_key, '')
    
    # Format datetime
    if hasattr(value, 'strftime'):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    
    # Format boolean
    if isinstance(value, bool):
        return 'Yes' if value else 'No'
    
    return str(value) if value is not None else ''
