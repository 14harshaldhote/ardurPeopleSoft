# trueAlign/urls.py
from django.urls import path, include
from . import views
from django.urls import path, register_converter
from uuid import UUID
from . import views

# Create a UUID converter
class UUIDConverter:
    regex = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
    
    def to_python(self, value):
        return UUID(value)
        
    def to_url(self, value):
        return str(value)

# Register the converter
register_converter(UUIDConverter, 'uuid')

# Appraisal URL patterns
appraisal_patterns = [
    # Basic CRUD operations
    path('list/', views.appraisal_list, name='appraisal_list'),
    path('create/', views.appraisal_create, name='appraisal_create'),
    path('<int:pk>/', views.appraisal_detail, name='appraisal_detail'),
    path('<int:pk>/update/', views.appraisal_update, name='appraisal_update'),
    path('<int:pk>/submit/', views.appraisal_submit, name='appraisal_submit'),
    path('<int:pk>/review/', views.appraisal_review, name='appraisal_review'),
    path('dashboard/', views.appraisal_dashboard, name='appraisal_dashboard'),
]

# Admin-specific URLs under 'admin/'
admin_patterns = [
    path('usersessions/', views.user_sessions_view, name='user_sessions'),
    path('report/', views.report_view, name='report'),
    path('reports/projects/', views.projects_report_view, name='projects_report'),
    path('reports/errors/', views.system_error_view, name='system_errors'),
    path('reports/usage/', views.system_usage_view, name='system_usage'),
    path('leave-requests/', views.view_leave_requests_admin, name='view_leave_requests_admin'),
    path('leave-requests/<int:leave_id>/<str:action>/', views.manage_leave_request_admin, name='manage_leave_request_admin'),
    path('projects/', views.project_dashboard, name='project_dashboard'),
    path('projects/create/', views.project_create, name='project_create'),
    path('projects/<int:project_id>/update/', views.project_update, name='project_update'),
    path('projects/<int:project_id>/delete/', views.project_delete, name='project_delete'),
    path('projects/<int:project_id>/assign/', views.assign_employee, name='assign_employee'),
    path('projects/<int:project_id>/remove/', views.assign_employee, name='remove_member'),
    path('projects/<int:project_id>/reactivate/', views.reactivate_employee, name='reactivate_member'),
    path('projects/<int:project_id>/change-role/', views.change_role, name='change_role'),
    path('projects/<int:project_id>/update-hours/', views.update_hours, name='update_hours'),
    path('reports/breaks/', views.break_report_view, name='break_report_view'),
    path('support/', views.admin_support, name='admin_support'),
    path('support/<uuid:ticket_id>/', views.admin_support, name='admin_support_with_ticket'),
    path('user/<int:user_id>/sessions/<str:date_str>/', views.user_session_detail_view, name='user_session_detail'),
]

# Employee-specific URLs under 'employee/'
employee_patterns = [
    path('support/', views.employee_support, name='employee_support'),
    path('attendance/', views.attendance_dashboard, name='attendance_dashboard'),
    path('attendance/calendar/', views.attendance_calendar, name='attendance_calendar'),
    path('attendance/check-in-out/', views.session_activity, name='session_activity'),
    path('attendance/regularization/', views.attendance_regularization, name='attendance_regularization'),
    path('timesheet/', views.timesheet_view, name='timesheet'),
    path('leave/', views.leave_view, name='leave_view'),
    path('profile/', views.employee_profile, name='employee_profile'),
    path('timesheet/details/<str:week_start_date>/', views.get_timesheet_details, name='timesheet_details'),
    path('applications/', views.application_for_user, name='application_for_user'),
]

# HR-specific URLs under 'hr/'
hr_patterns = [
    path('leave-requests/', views.view_leave_requests_hr, name='view_leave_requests_hr'),
    path('leave/<int:leave_id>/<str:action>/', views.manage_leave_request_hr, name='manage_leave_request_hr'),
    path('dashboard/', views.hr_dashboard, name='hr_dashboard'),
    path('user/<int:user_id>/', views.hr_user_detail, name='hr_user_detail'),
    path('support/', views.hr_support, name='hr_support'),
    path('support/<uuid:ticket_id>/', views.hr_support, name='hr_support_with_ticket'),
    path('updates/<int:update_id>/', views.get_update_data, name='get_update_data'),
    path('updates/create/', views.hr_create_update, name='hr_create_update'),
    path('updates/<int:update_id>/edit/', views.hr_edit_update, name='hr_edit_update'),
    path('updates/<int:update_id>/delete/', views.hr_delete_update, name='hr_delete_update'),
    path('employees/', views.employee_directory, name='employee_directory'),
    path('user/add/', views.add_user, name='add_user'),
    path('user/import-errors/', views.import_errors, name='import_errors'),
    path('users/bulk-add/', views.bulk_add_users, name='bulk_add_users'),
    
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

# Manager-specific URLs under 'manager/'
manager_patterns = [
    # Timesheet management
    path('timesheets/<int:timesheet_id>/', views.timesheet_detail, name='timesheet_detail'),
    # Project management URLs
    path('projects/', views.manager_project_view, {'action': 'list'}, name='project_list'),
    path('projects/create/', views.manager_project_view, {'action': 'create'}, name='project_create'),
    path('projects/<int:project_id>/update/', views.manager_project_view, {'action': 'update'}, name='project_update'),
    path('projects/<int:project_id>/', views.manager_project_view, {'action': 'detail'}, name='project_detail'),
    path('projects/<int:project_id>/employees/', views.manager_project_view, {'action': 'manage_employees'}, name='manage_employees'),

    # Project updates
    path('updates/create/', views.manager_create_project_update, name='manager_create_project_update'),
    path('updates/<int:update_id>/edit/', views.manager_edit_project_update, name='manager_edit_project_update'),
    path('updates/<int:update_id>/delete/', views.manager_delete_project_update, name='manager_delete_project_update'),

    # Employee management
    path('employee/', views.manager_employee_profile, name='manager_employee_profile'),
    path('user/<int:user_id>/', views.manager_user_detail, name='manager_user_detail'),
    path('tasks/assign/', views.assign_tasks, name='assign_tasks'),
    # Reports and monitoring
    path('report/', views.manager_report_view, name='report'),
    path('reports/attendance/', views.attendance_report_view_manager, name='attendance_report_view_manager'),
    path('reports/breaks/', views.break_report_view_manager, name='break_report_view_manager'),
    path('timesheets/', views.manager_view_timesheets, name='view_timesheets'),
    path('timesheets/bulk-update/', views.bulk_update_timesheet, name='bulk_update_timesheet'),

    # Leave management
    path('leave-requests/', views.view_leave_requests_manager, name='view_leave_requests_manager'),
    path('leave/<int:leave_id>/<str:action>/', views.manage_leave_request_manager, name='manage_leave_manager'),

    # Shift Management URLs (improved, explicit, RESTful)
    # Dashboard
    path('shifts/', views.shift_dashboard, name='shift_dashboard'),
    # Shift CRUD
    path('shifts/list/', views.shift_list, name='shift_list'),
    path('shifts/new/', views.shift_create, name='shift_create'),
    path('shifts/<int:pk>/', views.shift_detail, name='shift_detail'),
    path('shifts/<int:pk>/update/', views.shift_update, name='shift_update'),
    path('shifts/<int:pk>/delete/', views.shift_delete, name='shift_delete'),
    path('shifts/<int:pk>/toggle/', views.api_toggle_shift_active, name='toggle_shift_active'),

    # Holiday CRUD
    path('holidays/', views.holiday_list, name='holiday_list'),
    path('holidays/create/', views.holiday_create, name='holiday_create'),
    path('holidays/<int:pk>/update/', views.holiday_update, name='holiday_update'),
    path('holidays/<int:pk>/delete/', views.holiday_delete, name='holiday_delete'),

    # Shift Assignment CRUD
    path('assignments/', views.assignment_list, name='assignment_list'),
    path('assignments/create/', views.assignment_create, name='assignment_create'),
    path('assignments/bulk-add/', views.bulk_assignment, name='bulk_assignment'),
    path('assignments/<int:pk>/update/', views.assignment_update, name='assignment_update'),
    path('assignments/<int:pk>/delete/', views.assignment_delete, name='assignment_delete'),

    # User shift info
    path('user-shifts/', views.user_shift_info, name='user_shift_info'),
    path('user-shifts/<int:user_id>/', views.user_shift_info, name='user_shift_info_specific'),

    # Shift calendar
    path('shift-calendar/', views.shift_calendar, name='shift_calendar'),

    # API endpoints
    path('api/shifts/<int:shift_id>/users/', views.api_get_shift_users, name='api_get_shift_users'),
    path('api/users/<int:user_id>/shift/', views.api_get_user_shift, name='api_get_user_shift'),
]

# Chat URL patterns
chat_patterns = [
    path('', views.chat_home, name='home'),
    path('<str:chat_type>/<int:chat_id>/', views.chat_home, name='detail'),
    path('send/<str:chat_type>/<int:chat_id>/', views.chat_home, name='send_message'),
]

finance_patterns = [
    # Dashboard
    path('', views.finance_dashboard, name='dashboard'),
    # Expense Management
    path('expenses/', views.expense_entry, name='expense_entry'),
    
    # Voucher Management  
    path('vouchers/', views.voucher_entry, name='voucher_entry'),
    
    # Bank Payment Management
    # Bank Payment URLs
    path('bank-payments/', views.bank_payment_list, name='bank_payment_list'),
    path('bank-payments/create/', views.bank_payment_create, name='bank_payment_create'),
    path('bank-payments/<str:payment_id>/', views.bank_payment_detail, name='bank_payment_detail'),
    path('bank-payments/<str:payment_id>/update/', views.bank_payment_update, name='bank_payment_update'),
    path('bank-payments/<str:payment_id>/delete/', views.bank_payment_delete, name='bank_payment_delete'),
    path('bank-payments/<str:payment_id>/verify/', views.bank_payment_verify, name='bank_payment_verify'),
    path('bank-payments/<str:payment_id>/approve/', views.bank_payment_approve, name='bank_payment_approve'),
    path('bank-payments/<str:payment_id>/execute/', views.bank_payment_execute, name='bank_payment_execute'),
    path('bank-payments/<str:payment_id>/mark-failed/', views.bank_payment_mark_failed, name='bank_payment_mark_failed'),
    
    # Bank Account URLs
    path('bank-accounts/', views.bank_account_list, name='bank_account_list'),
    path('bank-accounts/create/', views.bank_account_create, name='bank_account_create'),
    path('bank-accounts/<int:account_id>/update/', views.bank_account_update, name='bank_account_update'),
    
    # Dashboard and Reports
    path('bank-payments/dashboard/', views.bank_payment_dashboard, name='bank_payment_dashboard'),
    path('bank-payments/reports/', views.bank_payment_report, name='bank_payment_report'),
  
    # Subscription Management
    path('subscriptions/', views.subscription_payment_entry, name='subscription_payment_entry'),
    
    # Invoice Management
    path('invoices/', views.invoice_generation, name='invoice_generation'),
    path('invoices/<int:invoice_id>/', views.invoice_detail, name='invoice_detail'),
    path('invoices/<int:invoice_id>/print/', views.invoice_print, name='invoice_print'),
    path('invoices/<int:invoice_id>/edit/', views.invoice_edit, name='invoice_edit'),
    path('invoices/<int:invoice_id>/status/', views.invoice_update_status, name='invoice_update_status'),

    path('parameters/', views.financial_parameter_list, name='financial_parameter_list'),
    path('parameters/create/', views.financial_parameter_create, name='financial_parameter_create'),
    path('parameters/<int:pk>/', views.financial_parameter_detail, name='financial_parameter_detail'),
    path('parameters/<int:pk>/update/', views.financial_parameter_update, name='financial_parameter_update'),
    path('parameters/<int:pk>/delete/', views.financial_parameter_delete, name='financial_parameter_delete'),
    path('parameters/<int:pk>/duplicate/', views.financial_parameter_duplicate, name='financial_parameter_duplicate'),
    path('parameters/entity/<int:content_type_id>/<int:object_id>/', views.entity_parameter_list, name='entity_parameter_list'),
    path('parameters/history/<str:key>/', views.parameter_history, name='parameter_history'),
    path('parameters/<int:pk>/approve/', views.approve_parameter, name='approve_parameter'),
]

leave_patterns = [
    # Dashboard
    path('dashboard/', views.leave_dashboard, name='leave_dashboard'),

    path('hr/', views.hr_leave_view, name='hr_leave_view'),
    path('finance/', views.finance_leave_view, name='finance_leave_view'),
    path('management/', views.management_leave_view, name='management_leave_view'),
    path('employee/', views.employee_leave_view, name='employee_leave_view'),
    path('manager/', views.manager_leave_view, name='manager_leave_view'),

    # Leave Request
    path('requests/create/', views.leave_request_create, name='leave_request_create'),
    path('requests/', views.leave_request_list, name='leave_request_list'),
    path('requests/<int:pk>/', views.leave_request_detail, name='leave_request_detail'),
    path('requests/<int:pk>/update/', views.leave_request_update, name='leave_request_update'),
    path('requests/<int:pk>/cancel/', views.leave_request_cancel, name='leave_request_cancel'),
    path('requests/<int:pk>/approve/', views.leave_request_approve, name='leave_request_approve'),
    path('requests/<int:pk>/reject/', views.leave_request_reject, name='leave_request_reject'),
    path('approvals/', views.leave_approval_list, name='leave_approval_list'),
    path('balance/bulk/', views.bulk_leave_balance_create, name='bulk_leave_balance_create'),


    # Leave Types
    path('types/', views.leave_type_list, name='leave_type_list'),
    path('types/create/', views.leave_type_create, name='leave_type_create'),
    path('types/<int:pk>/update/', views.leave_type_update, name='leave_type_update'),
    path('types/<int:pk>/delete/', views.leave_type_delete, name='leave_type_delete'),

    # Leave Policies
    path('policies/', views.leave_policy_list, name='leave_policy_list'),
    path('policies/create/', views.leave_policy_create, name='leave_policy_create'),
    path('policies/<int:pk>/update/', views.leave_policy_update, name='leave_policy_update'),
    path('policies/<int:pk>/delete/', views.leave_policy_delete, name='leave_policy_delete'),
    path('policies/<int:policy_id>/allocation/', views.leave_allocation_manage, name='leave_allocation_manage'),

    # Comp-off Requests
    path('compoff/create/', views.comp_off_request_create, name='comp_off_request_create'),
    path('compoff/', views.comp_off_request_list, name='comp_off_request_list'),
    path('compoff/<int:pk>/approve/', views.comp_off_request_approve, name='comp_off_request_approve'),
    path('compoff/<int:pk>/reject/', views.comp_off_request_reject, name='comp_off_request_reject'),

    # Reports
    path('reports/leaves/', views.leave_report, name='leave_report'),
    path('reports/balance/', views.leave_balance_report, name='leave_balance_report'),
]

attendance_patterns = [
    # Dashboard view
    path('dashboard/', views.hr_attendance_dashboard, name='hr_attendance_dashboard'),
    
    # Attendance list view
    path('list/', views.hr_attendance_list, name='hr_attendance_list'),
    
    # Edit specific attendance record
    path('records/<int:attendance_id>/edit/', views.hr_edit_attendance, name='hr_edit_attendance'),
    
    # Regularization requests
    path('regularization/<int:attendance_id>/process/', views.hr_process_regularization, name='hr_process_regularization'),    
    # Process specific regularization request
    path('regularization/requests/', views.hr_attendance_regularization_requests, name='hr_attendance_regularization_requests'),    
    # Generate attendance reports
    path('reports/', views.hr_generate_report, name='hr_generate_report'),

    path('calendar/', views.hr_attendance_view, name='hr_attendance_view'),

    path('add/', views.add_attendance, name='add_attendance'),
    
    # Bulk update attendance
    path('bulk-update/', views.bulk_update_attendance, name='hr_bulk_update_attendance'),
    
    # Attendance statistics
    path('statistics/', views.attendance_statistics, name='hr_attendance_statistics'),

    path('regularization/analytics/', views.regularization_analytics_dashboard, name='regularization_analytics_dashboard'),

    path('attendance-details/', views.get_attendance_details, name='get_attendance_details'),


    #new attendance analytics
    path('analytics/', views.attendance_analytics, name='attendance_analytics'),
    path('analytics/export/', views.attendance_export, name='attendance_export'),
    path('analytics/detail/', views.attendance_detail_analysis, name='attendance_detail_analysis'),
    path('analytics/detail/<int:user_id>/', views.attendance_detail_analysis, name='attendance_detail_analysis_user'),
    path('analytics/status-users/', views.get_status_users, name='get_status_users'),

]

support_patterns = [
    path('', views.support_dashboard, name='support_dashboard'),
    path('create/', views.create_ticket, name='create_ticket'),
    path('<int:pk>/', views.ticket_detail, name='ticket_detail'),
    path('<int:pk>/update/', views.update_ticket, name='update_ticket'),
    path('assign/', views.assign_ticket, name='assign_ticket'),
    path('list/', views.ticket_list, name='ticket_list'),
]

holiday_pattern=[
    path('',views.holiday_dashboard,name='holiday_dashboard'),
    path('create/',views.holidays_create,name='holiday_create'),
    path('<int:pk>/update/',views.holidays_update,name='holiday_update'),
    path('<int:pk>/delete/',views.holidays_delete,name='holiday_delete'),
    path('list/',views.holiday_lists,name='holiday_lists'),
]

entertainment_patterns=[
    path('',views.entertainment_dashboard,name='entertainment'),
    path('games/', views.games, name='games_hub'),
    
    # Tic-Tac-Toe game routes
    path('tictactoe/', views.TicTacToeGameView.as_view(), name='game_list'),
    path('tictactoe/<uuid:game_id>/', views.TicTacToeGameView.as_view(), name='game_detail'), 
    # Other game view routes
    path('notifications/', views.NotificationView.as_view(), name='notifications'),
    path('leaderboard/', views.LeaderboardView.as_view(), name='leaderboard'),
    path('icons/', views.GameIconView.as_view(), name='game_icons'),
    path('history/', views.GameHistoryView.as_view(), name='game_history'),
    path('history/<int:user_id>/', views.GameHistoryView.as_view(), name='user_game_history'),

]

# Main URL configuration for the project
urlpatterns = [
    path('', views.home_view, name='home'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    path('set-password/<str:username>/', views.set_password_view, name='set_password'),
    path('profile/<int:user_id>/', views.user_profile, name='user_profile'),
    path('update-activity/', views.update_last_activity, name='update_last_activity'),
    path('session-status/', views.get_session_status, name='get_session_status'),
    path('end-session/', views.end_session, name='end_session'),
    path('break/check/', views.check_active_break, name='check_active_break'),
    path('break/take/', views.take_break, name='take_break'),
    path('break/end/<int:break_id>/', views.end_break, name='end_break'),
    path('dashboard/', views.dashboard_view, name='dashboard'),
    
    # Include chat URLs with namespace
    path('chat/', include((chat_patterns, 'chat'))),

    # Admin-specific URLs under 'admin/'
    path('administration/', include((admin_patterns, 'aps'), namespace='aps_admin')),

    # Employee-specific URLs under 'employee/'
    path('employee/', include((employee_patterns, 'aps'), namespace='aps_employee')),
    
    # Finance related URLS
    path('finance/', include((finance_patterns, 'aps'), namespace='aps_finance')),

    # HR-specific URLs under 'hr/'
    path('hr/', include((hr_patterns, 'aps'), namespace='aps_hr')),

    # Manager-specific URLs under 'manager/'
    path('manager/', include((manager_patterns, 'aps'), namespace='aps_manager')),

    # Leave-specific URLs under 'leave/'
    path('leave/', include((leave_patterns, 'aps'), namespace='aps_leave')),

    # Attendance URLs
    path('attendance/', include((attendance_patterns, 'aps'), namespace='aps_attendance')),

    #support URLs
    path('support/', include((support_patterns, 'aps'), namespace='aps_support')),

    path('holiday/',include((holiday_pattern, 'aps'), namespace='aps_holiday')),
    # Appraisal URLs
    path('appraisal/', include((appraisal_patterns, 'appraisal'))),

    path('reset-password/', views.reset_password, name='reset_password'),

    # Entertainment URLs
    path('entertainment/', include((entertainment_patterns, 'aps'), namespace='aps_entertainment')),
]