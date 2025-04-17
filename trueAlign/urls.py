# trueAlign/urls.py
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
    path('leave/requests/<int:leave_id>/<str:action>/', views.manage_leave_request_admin, name='manage_leave_request_admin'),
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
    path('user/<int:user_id>/sessions/<str:date_str>/', views.user_session_detail_view, name='user_session_detail'),
]

# Employee-specific URLs under 'truealign/employee/'
employee_patterns = [
    path('support/', views.employee_support, name='employee_support'),
    path('attendance/', views.employee_attendance_view, name='attendance'),
    path('timesheet/', views.timesheet_view, name='timesheet'),
    path('leave/', views.leave_view, name='leave_view'),
    path('profile/', views.employee_profile, name='employee_profile'),
    path('timesheet/details/<str:week_start_date>/', views.get_timesheet_details, name='timesheet_details'),
    path('applications/', views.application_for_user, name='application_for_user'),

]

# HR-specific URLs under 'truealign/hr/'
hr_patterns = [
    path('leave/requests/', views.view_leave_requests_hr, name='view_leave_requests_hr'),
    path('leave/<int:leave_id>/<str:action>/', views.manage_leave_request_hr, name='manage_leave_request_hr'),
    path('attendance/', views.hr_attendance_view, name='attendance'),
    path('dashboard/', views.hr_dashboard, name='hr_dashboard'),
    path('user/<int:user_id>/', views.hr_user_detail, name='hr_user_detail'),
    path('support/', views.hr_support, name='hr_support'),
    path('support/<uuid:ticket_id>/', views.hr_support, name='hr_support_with_ticket'),
    path('get-update/<int:update_id>/', views.get_update_data, name='get_update_data'),
    path('create-update/', views.hr_create_update, name='hr_create_update'),
    path('edit-update/<int:update_id>/', views.hr_edit_update, name='hr_edit_update'),
    path('delete-update/<int:update_id>/', views.hr_delete_update, name='hr_delete_update'),
    path('employees/', views.employee_directory, name='employee_directory'),
    path('mark_attendance/', views.manual_attendance, name='manual_attendance'),
    path('user/add/', views.add_user, name='add_user'),
    path('user/bulk-add/', views.bulk_add_users, name='bulk_add_users'),
    path('user/import-errors/', views.import_errors, name='import_errors'),
    
    # User Actions
    path('user/<int:user_id>/reset-password/', views.reset_user_password, name='reset_user_password'),
    path('user/<int:user_id>/change-status/', views.change_user_status, name='change_user_status'),
    path('user/<int:user_id>/change-role/', views.change_user_role, name='change_user_role'),
    
    # Logs and Reports
    path('logs/', views.user_action_logs, name='user_action_logs'),
    path('logs/user/<int:user_id>/', views.user_action_logs, name='user_specific_logs'),
    path('sessions/', views.session_logs, name='session_logs'),
    path('sessions/user/<int:user_id>/', views.session_logs, name='user_session_logs'),
    path('reports/', views.user_reports, name='user_reports'),
    path('leave/', views.leave_view, name='leave_view'),
]

# Manager-specific URLs under 'truealign/manager/'
manager_patterns = [
    # Timesheet management
    path('timesheets/<int:timesheet_id>/', views.timesheet_detail, name='timesheet_detail'),
    # Project management URLs
    path('projects/', views.manager_project_view, {'action': 'list'}, name='project_list'),
    path('projects/create/', views.manager_project_view, {'action': 'create'}, name='project_create'),
    path('projects/update/<int:project_id>/', views.manager_project_view, {'action': 'update'}, name='project_update'),
    path('projects/detail/<int:project_id>/', views.manager_project_view, {'action': 'detail'}, name='project_detail'),
    path('projects/<int:project_id>/manage-employees/', views.manager_project_view, {'action': 'manage_employees'}, name='manage_employees'),

    # Project updates
    path('project-updates/create/', views.manager_create_project_update, name='manager_create_project_update'),
    path('project-updates/<int:update_id>/edit/', views.manager_edit_project_update, name='manager_edit_project_update'),
    path('project-updates/<int:update_id>/delete/', views.manager_delete_project_update, name='manager_delete_project_update'),

    # Employee management
    path('employee/', views.manager_employee_profile, name='manager_employee_profile'),
    path('user/<int:user_id>/', views.manager_user_detail, name='manager_user_detail'),
    path('assign-tasks/', views.assign_tasks, name='assign_tasks'),

    # Reports and monitoring
    path('report/', views.manager_report_view, name='report'),
    path('reports/breaks/', views.break_report_view_manager, name='break_report_view_manager'),
    path('reports/attendance/', views.attendance_report_view_manager, name='attendance_report_view_manager'),
    path('attendance/', views.manager_attendance_view, name='attendance'),
    path('timesheets/', views.manager_view_timesheets, name='view_timesheets'),
    path('timesheets/bulk-update/', views.bulk_update_timesheet, name='bulk_update_timesheet'),

    # Leave management
    path('leave/requests/', views.view_leave_requests_manager, name='view_leave_requests_manager'),
    path('leave/<int:leave_id>/<str:action>/', views.manage_leave_request_manager, name='manage_leave_manager'),
]

# Chat URL patterns
chat_patterns = [
    path('', views.chat_home, name='home'),
    path('<str:chat_type>/<int:chat_id>/', views.chat_home, name='detail'),
    path('send_message/<str:chat_type>/<int:chat_id>/', views.chat_home, name='send_message'),
]

# Main URL configuration for the project
urlpatterns = [
    path('', views.home_view, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('set_password/<str:username>/', views.set_password_view, name='set_password'),
    path('profile/<int:user_id>/', views.user_profile, name='user_profile'),
    path('update-last-activity/', views.update_last_activity, name='update_last_activity'),
    path('session-status/', views.get_session_status, name='get_session_status'),
    path('end-session/', views.end_session, name='end_session'),
    path('break/check/', views.check_active_break, name='check_active_break'),
    path('break/take/', views.take_break, name='take_break'),
    path('break/end/<int:break_id>/', views.end_break, name='end_break'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    
    # Include chat URLs with namespace
    path('chat/', include((chat_patterns, 'chat'))),

    # Admin-specific URLs under 'truealign/admin/'
    path('truealign/admin/', include((admin_patterns, 'aps'), namespace='aps_admin')),

    # Employee-specific URLs under 'truealign/employee/'
    path('truealign/employee/', include((employee_patterns, 'aps'), namespace='aps_employee')),

    # HR-specific URLs under 'truealign/hr/'
    path('truealign/hr/', include((hr_patterns, 'aps'), namespace='aps_hr')),

    # Manager-specific URLs under 'truealign/manager/'
    path('truealign/manager/', include((manager_patterns, 'aps'), namespace='aps_manager')),

    path('reset-password/', views.reset_password, name='reset_password'),

]
