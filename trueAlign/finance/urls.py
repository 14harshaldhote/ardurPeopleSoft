"""
URL Configuration for Finance Module
"""

from django.urls import path
from . import views

app_name = 'finance'

urlpatterns = [
    # Dashboard
    path('', views.finance_dashboard, name='dashboard'),
    
    # Financial Parameters
    path('parameters/', views.financial_parameter_list, name='parameter_list'),
    path('parameters/create/', views.financial_parameter_create, name='parameter_create'),
    path('parameters/<int:pk>/edit/', views.financial_parameter_edit, name='parameter_edit'),
    path('parameters/<int:pk>/approve/', views.financial_parameter_approve, name='parameter_approve'),
    
    # Daily Expenses
    path('expenses/', views.expense_list, name='expense_list'),
    path('expenses/create/', views.expense_create, name='expense_create'),
    path('expenses/<int:pk>/', views.expense_detail, name='expense_detail'),
    path('expenses/<int:pk>/submit/', views.expense_submit, name='expense_submit'),
    path('expenses/<int:pk>/approve/', views.expense_approve, name='expense_approve'),
    path('expenses/<int:pk>/mark-paid/', views.expense_mark_paid, name='expense_mark_paid'),
    path('expenses/export/excel/', views.expense_export_excel, name='expense_export_excel'),
    path('expenses/<int:pk>/print/', views.expense_print_pdf, name='expense_print_pdf'),
    
    # Vouchers
    path('vouchers/', views.voucher_list, name='voucher_list'),
    path('vouchers/create/', views.voucher_create, name='voucher_create'),
    path('vouchers/<int:pk>/', views.voucher_detail, name='voucher_detail'),
    path('vouchers/<int:pk>/department-approve/', views.voucher_department_approve, name='voucher_department_approve'),
    path('vouchers/<int:pk>/finance-approve/', views.voucher_finance_approve, name='voucher_finance_approve'),
    path('vouchers/<int:pk>/post/', views.voucher_post, name='voucher_post'),
    path('vouchers/<int:pk>/print/', views.voucher_print_pdf, name='voucher_print_pdf'),
    path('vouchers/export/excel/', views.voucher_export_excel, name='voucher_export_excel'),
    
    # Bank Accounts
    path('bank-accounts/', views.bank_account_list, name='bank_account_list'),
    path('bank-accounts/create/', views.bank_account_create, name='bank_account_create'),
    path('bank-accounts/<int:pk>/edit/', views.bank_account_edit, name='bank_account_edit'),
    
    # Bank Payments
    path('bank-payments/', views.bank_payment_list, name='bank_payment_list'),
    path('bank-payments/create/', views.bank_payment_create, name='bank_payment_create'),
    path('bank-payments/<int:pk>/', views.bank_payment_detail, name='bank_payment_detail'),
    path('bank-payments/<int:pk>/verify/', views.bank_payment_verify, name='bank_payment_verify'),
    path('bank-payments/<int:pk>/approve/', views.bank_payment_approve, name='bank_payment_approve'),
    path('bank-payments/<int:pk>/execute/', views.bank_payment_execute, name='bank_payment_execute'),
    path('bank-payments/export/excel/', views.bank_payment_export_excel, name='bank_payment_export_excel'),
    
    # Subscriptions
    path('subscriptions/', views.subscription_list, name='subscription_list'),
    path('subscriptions/create/', views.subscription_create, name='subscription_create'),
    path('subscriptions/<int:pk>/edit/', views.subscription_edit, name='subscription_edit'),
    path('subscriptions/<int:pk>/renew/', views.subscription_renew, name='subscription_renew'),
    path('subscriptions/<int:pk>/cancel/', views.subscription_cancel, name='subscription_cancel'),
    path('subscriptions/export/excel/', views.subscription_export_excel, name='subscription_export_excel'),
    
    # Client Invoices
    path('invoices/', views.invoice_list, name='invoice_list'),
    path('invoices/create/', views.invoice_create, name='invoice_create'),
    path('invoices/<int:pk>/', views.invoice_detail, name='invoice_detail'),
    path('invoices/<int:pk>/approve/', views.invoice_approve, name='invoice_approve'),
    path('invoices/<int:pk>/send/', views.invoice_send, name='invoice_send'),
    path('invoices/<int:pk>/mark-paid/', views.invoice_mark_paid, name='invoice_mark_paid'),
    path('invoices/<int:pk>/print/', views.invoice_print_pdf, name='invoice_print_pdf'),
    path('invoices/export/excel/', views.invoice_export_excel, name='invoice_export_excel'),
    
    # Chart of Accounts
    path('chart-of-accounts/', views.chart_of_account_list, name='chart_of_account_list'),
    path('chart-of-accounts/create/', views.chart_of_account_create, name='chart_of_account_create'),
    path('chart-of-accounts/<int:pk>/edit/', views.chart_of_account_edit, name='chart_of_account_edit'),
    
    # ==================== CASH MANAGEMENT ====================
    path('cash/', views.cash_box_dashboard, name='cash_box_dashboard'),
    path('cash/boxes/create/', views.cash_box_create, name='cash_box_create'),
    path('cash/boxes/<int:pk>/edit/', views.cash_box_edit, name='cash_box_edit'),
    path('cash/boxes/<int:pk>/', views.cash_box_detail, name='cash_box_detail'),
    path('cash/transactions/', views.cash_transaction_list, name='cash_transaction_list'),
    path('cash/transactions/create/', views.cash_transaction_create, name='cash_transaction_create'),
    
    # ==================== PAYMENT ALLOCATION ====================
    path('allocations/', views.payment_allocation_list, name='payment_allocation_list'),
    path('allocations/create/', views.payment_allocation_create, name='payment_allocation_create'),
    path('allocations/expense/<str:expense_id>/', views.expense_allocations_view, name='expense_allocations_view'),
    path('allocations/quick-allocate/<str:expense_id>/', views.quick_allocate_expense, name='quick_allocate_expense'),
    
    # ==================== BANK RECONCILIATION ====================
    path('reconciliation/', views.bank_reconciliation_dashboard, name='bank_reconciliation_dashboard'),
    path('reconciliation/upload/', views.bank_statement_upload, name='bank_statement_upload'),
    path('reconciliation/statement/<int:pk>/', views.statement_detail, name='statement_detail'),
    path('reconciliation/statement/<int:pk>/auto-reconcile/', views.auto_reconcile_statement, name='auto_reconcile_statement'),
    
    # ==================== INTELLIGENCE ====================
    path('intelligence/', views.intelligence_dashboard, name='intelligence_dashboard'),
]