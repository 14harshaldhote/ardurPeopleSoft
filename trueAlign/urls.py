# trueAlign/urls.py
from django.urls import path, include
from . import views

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

# finance_patterns = [
#     path('projects/', views.project_list, name='project_list'),
#     path('transactions/', views.transaction_list, name='transaction_list'), 
#     path('accounts/', views.chart_of_accounts, name='chart_of_accounts'),
#     path('vendors/', views.vendor_list, name='vendor_list'),
#     path('payments/', views.payment_list, name='payment_list'),
#     path('client-payments/', views.client_payment_list, name='client_payment_list'),
# ]

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
    path('user/import-errors/', views.import_errors, name='import_errors'),
    path('bulk-add-users/', views.bulk_add_users, name='bulk_add_users'),
    
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

    # Shift Management URLs (improved, explicit, RESTful)
    # Dashboard
    path('shifts/dashboard/', views.shift_dashboard, name='shift_dashboard'),
    # Shift CRUD
    path('shifts/', views.shift_list, name='shift_list'),
    path('shifts/new/', views.shift_create, name='shift_create'),
    path('shifts/<int:pk>/', views.shift_detail, name='shift_detail'),
    path('shifts/<int:pk>/update/', views.shift_update, name='shift_update'),
    path('shifts/<int:pk>/delete/', views.shift_delete, name='shift_delete'),
    path('shifts/<int:pk>/toggle-active/', views.api_toggle_shift_active, name='toggle_shift_active'),

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
    path('user-shift/', views.user_shift_info, name='user_shift_info'),
    path('user-shift/<int:user_id>/', views.user_shift_info, name='user_shift_info_specific'),

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
    path('send_message/<str:chat_type>/<int:chat_id>/', views.chat_home, name='send_message'),
]

finance_patterns = [
    # # Dashboard
    path('', views.finance_dashboard, name='dashboard'),
    # Expense Management
    path('expenses/', views.expense_entry, name='expense_entry'),
    
    # Voucher Management  
    path('vouchers/', views.voucher_entry, name='voucher_entry'),
    
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
    
    # # Transactions
    # path('transactions/', views.transaction_list, name='transaction_list'),
    # path('transactions/create/', views.transaction_create, name='transaction_create'),
    # path('transactions/<int:transaction_id>/', views.transaction_detail, name='transaction_detail'),
    
    # # Invoices
    # path('invoices/', views.invoice_list, name='invoice_list'),
    # path('invoices/<int:invoice_id>/', views.invoice_detail, name='invoice_detail'),
    # path('invoices/<int:invoice_id>/pdf/', views.generate_invoice_pdf, name='generate_invoice_pdf'),
    
    # # Payments
    # path('payments/', views.payment_list, name='payment_list'),
    
    # # # Reports
    # # path('reports/', views.report_dashboard, name='report_dashboard'),
    # # path('reports/<str:report_type>/', views.generate_report, name='generate_report'),
    # # path('reports/<str:report_type>/export/<str:format>/', views.export_report, name='export_report'),
    
    # # Parameters
    # path('parameters/', views.parameter_list, name='parameter_list'),
    # path('parameters/create/', views.parameter_create, name='parameter_create'),
    # path('parameters/<int:parameter_id>/edit/', views.parameter_edit, name='parameter_edit'),
    
    # # Calculation Rules
    # path('rules/', views.calculation_rule_list, name='calculation_rule_list'),
    # path('rules/create/', views.calculation_rule_create, name='calculation_rule_create'),
    # path('rules/<int:rule_id>/edit/', views.calculation_rule_edit, name='calculation_rule_edit'),
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
    
    #finance related URLS
path('finance/', include((finance_patterns, 'aps'), namespace='aps_finance')),

    # HR-specific URLs under 'truealign/hr/'
    path('truealign/hr/', include((hr_patterns, 'aps'), namespace='aps_hr')),

    # Manager-specific URLs under 'truealign/manager/'
    path('truealign/manager/', include((manager_patterns, 'aps'), namespace='aps_manager')),

    # Appraisal URLs
    path('appraisal/', include((appraisal_patterns, 'appraisal'))),

    path('reset-password/', views.reset_password, name='reset_password'),
]
