from django.urls import path, include
from . import views

# Admin-specific URLs under 'truealign/admin/'
admin_patterns = [
    path('usersessions/', views.user_sessions_view, name='user_sessions'),
    path('report/', views.report_view, name='report'),
    path('reports/projects_report/', views.projects_report_view, name='projects_report'),
    path('reports/system_errors/', views.system_error_view, name='system_errors'),
    path('reports/system_usage/', views.system_usage_view, name='system_usage'),
    path('leave/requests/', views.view_leave_requests_admin, name='view_leave_requests_admin'),
    path('projects_dashboard/', views.project_dashboard, name='project_dashboard'),
    path('projects/create/', views.project_create, name='project_create'),
    path('projects/update/<int:project_id>/', views.project_update, name='project_update'),
    path('projects/<int:project_id>/delete/', views.project_delete, name='project_delete'),
    path('projects/<int:project_id>/assign/', views.assign_employee, name='assign_employee'),
    path('projects/<int:project_id>/remove/', views.assign_employee, name='remove_member'),
    path('projects/<int:project_id>/reactivate/', views.reactivate_employee, name='reactivate_member'),
    path('projects/<int:project_id>/change-role/', views.change_role, name='change_role'),
    path('projects/<int:project_id>/update_hours/', views.update_hours, name='update_hours'),
    path('reports/breaks/', views.break_report_view, name='break_report_view'),
    path('attendance/', views.admin_attendance_view, name='attendance'),
    path('support/', views.admin_support, name='admin_support'),
    path('support/<uuid:ticket_id>/', views.admin_support, name='admin_support_with_ticket'),
]

# Employee-specific URLs under 'truealign/employee/'
employee_patterns = [
    path('support/', views.employee_support, name='employee_support'),
    path('attendance/', views.employee_attendance_view, name='attendance'),
    path('timesheet/', views.timesheet_view, name='timesheet'),
    path('leave/', views.leave_view, name='leave_view'),
    path('profile/', views.employee_profile, name='employee_profile'),
]

# HR-specific URLs under 'truealign/hr/'
hr_patterns = [
    path('leave/requests/', views.view_leave_requests_hr, name='view_leave_requests_hr'),
    path('leave/<int:leave_id>/<str:action>/', views.manage_leave_request_hr, name='manage_leave_hr'),
    path('attendance/', views.hr_attendance_view, name='attendance'),
    path('userdetails/', views.hr_dashboard, name='hr_dashboard'),
    path('user/<int:user_id>/', views.hr_user_detail, name='hr_user_detail'),
    path('hr/support/', views.hr_support, name='hr_support'),
    path('hr/support/<uuid:ticket_id>/', views.hr_support, name='hr_support_with_ticket'),
    path('hr/get-update/<int:update_id>/', views.get_update_data, name='get_update_data'),
    path('hr/create-update/', views.hr_create_update, name='hr_create_update'),
    path('hr/edit-update/<int:update_id>/', views.hr_edit_update, name='hr_edit_update'),
    path('hr/delete-update/<int:update_id>/', views.hr_delete_update, name='hr_delete_update'),
    path('employees/', views.employee_directory, name='employee_directory'),
]

# Manager-specific URLs under 'truealign/manager/'
manager_patterns = [
    path('projects/', views.manager_project_view, {'action': 'list'}, name='project_list'),
    path('projects/create/', views.manager_project_view, {'action': 'create'}, name='project_create'),
    path('projects/update/<int:project_id>/', views.manager_project_view, {'action': 'update'}, name='project_update'),
    path('projects/detail/<int:project_id>/', views.manager_project_view, {'action': 'detail'}, name='project_detail'),
    path('employee/', views.manager_employee_profile, name='manager_employee_profile'),
    path('user/<int:user_id>/', views.manager_user_detail, name='manager_user_detail'),
    path('create-project-update/', views.manager_create_project_update, name='manager_create_project_update'),
    path('edit-project-update/<int:update_id>/', views.manager_edit_project_update, name='manager_edit_project_update'),
    path('delete-project-update/<int:update_id>/', views.manager_delete_project_update, name='manager_delete_project_update'),
    path('report/', views.manager_report_view, name='report'),
    path('reports/breaks/', views.break_report_view_manager, name='break_report_view_manager'),
    path('reports/attendance/', views.attendance_report_view_manager, name='attendance_report_view_manager'),
    path('leave/requests/', views.view_leave_requests_manager, name='view_leave_requests_manager'),
    path('leave/<int:leave_id>/<str:action>/', views.manage_leave_request_manager, name='manage_leave_manager'),
    path('view_timesheets/', views.manager_view_timesheets, name='view_timesheets'),
    path('bulk-update-timesheet/', views.bulk_update_timesheet, name='bulk_update_timesheet'),
    path('assign_tasks/', views.assign_tasks, name='assign_tasks'),
    path('attendance/', views.manager_attendance_view, name='attendance'),
]

# Main URL configuration for the project
urlpatterns = [
    path('', views.home_view, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('set_password/<str:username>/', views.set_password_view, name='set_password'),
    path('profile/<int:user_id>/', views.user_profile, name='user_profile'),
    path('update-last-activity/', views.update_last_activity, name='update_last_activity'),
    path('end-session/', views.end_session, name='end_session'),
    path('break/check/', views.check_active_break, name='check_active_break'),
    path('break/take/', views.take_break, name='take_break'),
    path('break/end/<int:break_id>/', views.end_break, name='end_break'),
    path('chats/', views.chat_view, name='chat_view'),
    path('dashboard/', views.dashboard_view, name='dashboard'),

    # Admin-specific URLs under 'truealign/admin/'
    path('truealign/admin/', include((admin_patterns, 'aps'), namespace='aps_admin')),

    # Employee-specific URLs under 'truealign/employee/'
    path('truealign/employee/', include((employee_patterns, 'aps'), namespace='aps_employee')),

    # HR-specific URLs under 'truealign/hr/'
    path('truealign/hr/', include((hr_patterns, 'aps'), namespace='aps_hr')),

    # Manager-specific URLs under 'truealign/manager/'
    path('truealign/manager/', include((manager_patterns, 'aps'), namespace='aps_manager')),
]