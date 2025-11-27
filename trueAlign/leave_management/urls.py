from django.urls import path
from . import views

app_name = 'leave_management'

urlpatterns = [
    path('employee/', views.EmployeeDashboardView.as_view(), name='employee_dashboard'),
    path('manager/', views.ManagerDashboardView.as_view(), name='manager_dashboard'),
    path('hr/', views.HRDashboardView.as_view(), name='hr_dashboard'),
    path('admin/', views.AdminDashboardView.as_view(), name='admin_dashboard'),
    
    # Leave Requests
    path('apply/', views.LeaveApplyView.as_view(), name='apply_leave'),
    path('request/<int:pk>/', views.LeaveDetailView.as_view(), name='leave_detail'),
    path('request/<int:pk>/edit/', views.LeaveUpdateView.as_view(), name='leave_update'),
    path('request/<int:pk>/action/', views.LeaveActionView.as_view(), name='leave_action'),
    path('my-leaves/', views.MyLeavesView.as_view(), name='my_leaves'),
    path('team-leaves/', views.TeamLeavesView.as_view(), name='team_leaves'),
    
    # Comp-Off
    path('comp-off/apply/', views.CompOffApplyView.as_view(), name='apply_comp_off'),
    path('comp-off/<int:pk>/action/', views.CompOffActionView.as_view(), name='comp_off_action'),
    
    # Admin/HR Management - Leave Types
    path('types/', views.LeaveTypeListView.as_view(), name='leavetype_list'),
    path('types/create/', views.LeaveTypeCreateView.as_view(), name='leavetype_create'),
    path('types/<int:pk>/edit/', views.LeaveTypeUpdateView.as_view(), name='leavetype_update'),
    
    # Admin/HR Management - Policies
    path('policies/', views.LeavePolicyListView.as_view(), name='policy_list'),
    path('policies/create/', views.LeavePolicyCreateView.as_view(), name='policy_create'),
    path('policies/<int:pk>/edit/', views.LeavePolicyUpdateView.as_view(), name='policy_update'),
    
    # Admin/HR Management - Allocations
    path('allocation/create/', views.LeaveAllocationCreateView.as_view(), name='allocation_create'),
    
    # HR - Balance Adjustment
    path('balance/adjust/', views.ManualBalanceAdjustmentView.as_view(), name='balance_adjust'),
    
    # Analytics
    path('analytics/', views.LeaveAnalyticsView.as_view(), name='leave_analytics'),
    path('api/analytics-data/', views.LeaveAnalyticsDataView.as_view(), name='leave_analytics_data'),
]
