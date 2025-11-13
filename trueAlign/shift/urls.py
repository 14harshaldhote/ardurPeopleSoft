"""
URL Configuration for Shift Management
Provides Django template-based interface
"""

from django.urls import path
from . import views

app_name = 'shift'

urlpatterns = [
    # Dashboard
    path('', views.dashboard, name='dashboard'),
    
    # Shift Management
    path('shifts/', views.shift_list, name='shift_list'),
    path('shifts/create/', views.shift_create, name='shift_create'),
    path('shifts/<int:pk>/', views.shift_detail, name='shift_detail'),
    path('shifts/<int:pk>/edit/', views.shift_edit, name='shift_edit'),
    path('shifts/<int:pk>/delete/', views.shift_delete, name='shift_delete'),
    
    # Assignment Management
    path('assignments/', views.assignment_list, name='assignment_list'),
    path('assignments/create/', views.assignment_create, name='assignment_create'),
    path('assignments/bulk-create/', views.bulk_assignment_create, name='bulk_assignment_create'),
    path('assignments/<int:pk>/', views.assignment_detail, name='assignment_detail'),
    path('assignments/<int:pk>/approve/', views.assignment_approve, name='assignment_approve'),
    path('assignments/<int:pk>/reject/', views.assignment_reject, name='assignment_reject'),
    path('assignments/<int:pk>/end/', views.assignment_end, name='assignment_end'),
    
    # Conflict Management
    path('conflicts/', views.conflict_list, name='conflict_list'),
    
    # Calendar view
    path('calendar/', views.calendar_view, name='calendar_view'),
    
    # Team assignments view
    path('team-assignments/', views.team_assignments_view, name='team_assignments'),
    
    # Utilization reports view
    path('reports/utilization/', views.utilization_reports_view, name='utilization_reports'),
    
    # Enhanced API endpoints with business logic
    path('api/shifts/', views.api_shifts_list, name='api_shifts_list'),
    path('api/assignments/', views.api_assignments_list, name='api_assignments_list'),
    path('api/dashboard-stats/', views.api_dashboard_stats, name='api_dashboard_stats'),
    
    # New enhanced API endpoints
    path('api/conflicts/<int:conflict_id>/resolve/', views.resolve_conflict, name='resolve_conflict'),
    path('api/assignments/history/<int:user_id>/', views.assignment_history, name='assignment_history'),
    path('api/assignments/current/', views.current_assignments_api, name='current_assignments_api'),
    path('api/shifts/<int:shift_id>/utilization/', views.shift_utilization_report, name='shift_utilization_report'),
    path('api/shifts/<int:shift_id>/duplicate/', views.duplicate_shift, name='duplicate_shift'),
    path('api/assignments/<int:assignment_id>/reassign/', views.reassign_assignment, name='reassign_assignment'),
    path('api/reports/assignments/', views.assignment_report, name='assignment_report'),
    path('api/conflicts/statistics/', views.conflict_statistics, name='conflict_statistics'),
]

# URL patterns for different operations:
"""
Shift Master URLs:
- GET /api/shifts/ - List all shifts
- POST /api/shifts/ - Create new shift
- GET /api/shifts/{id}/ - Get shift details
- PUT /api/shifts/{id}/ - Update shift
- DELETE /api/shifts/{id}/ - Delete shift
- POST /api/shifts/{id}/duplicate/ - Duplicate shift
- GET /api/shifts/{id}/assignments/ - Get shift assignments
- GET /api/shifts/statistics/ - Get shift statistics

Shift Assignment URLs:
- GET /api/assignments/ - List all assignments
- POST /api/assignments/ - Create new assignment
- GET /api/assignments/{id}/ - Get assignment details
- PUT /api/assignments/{id}/ - Update assignment
- DELETE /api/assignments/{id}/ - Delete assignment
- POST /api/assignments/bulk_assign/ - Bulk assign shifts
- POST /api/assignments/{id}/approve/ - Approve assignment
- POST /api/assignments/{id}/reject/ - Reject assignment
- GET /api/assignments/current_assignments/ - Get current assignments
- GET /api/assignments/user_history/ - Get user assignment history
- GET /api/assignments/calendar_view/ - Get calendar view

Shift Conflict URLs:
- GET /api/conflicts/ - List all conflicts
- GET /api/conflicts/{id}/ - Get conflict details
- POST /api/conflicts/{id}/resolve/ - Resolve conflict
- GET /api/conflicts/statistics/ - Get conflict statistics

Reports URLs:
- POST /api/reports/assignment_report/ - Generate assignment report
- GET /api/reports/dashboard_stats/ - Get dashboard statistics

Query Parameters:
- ?is_active=true/false - Filter by active status
- ?shift_type=MORNING/EVENING/NIGHT/CUSTOM - Filter by shift type
- ?status=ACTIVE/PENDING/APPROVED/REJECTED - Filter by status
- ?user_id=123 - Filter by user
- ?shift_id=456 - Filter by shift
- ?start_date=2024-01-01 - Filter by start date
- ?end_date=2024-12-31 - Filter by end date
- ?search=keyword - Search by name/description
- ?page=1&page_size=20 - Pagination
"""
