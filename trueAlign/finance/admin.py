from django.contrib import admin
from trueAlign.models import (
    FinancialParameter, DailyExpense, Voucher, VoucherDetail,
    BankAccount, BankPayment, Subscription, ClientInvoice, ChartOfAccount
)


class VoucherDetailInline(admin.TabularInline):
    model = VoucherDetail
    extra = 1
    fields = ('account', 'debit_amount', 'credit_amount', 'description')


@admin.register(FinancialParameter)
class FinancialParameterAdmin(admin.ModelAdmin):
    list_display = ('key', 'name', 'category', 'value', 'value_type', 'is_global', 'valid_from', 'valid_to', 'is_approved')
    list_filter = ('category', 'value_type', 'is_global', 'is_approved', 'fiscal_year')
    search_fields = ('key', 'name', 'description')
    readonly_fields = ('created_at', 'updated_at', 'created_by', 'updated_by', 'approved_at', 'approved_by')
    fieldsets = (
        ('Parameter Information', {
            'fields': ('key', 'name', 'category', 'description')
        }),
        ('Value', {
            'fields': ('value_type', 'value')
        }),
        ('Scope', {
            'fields': ('is_global', 'content_type', 'object_id')
        }),
        ('Validity Period', {
            'fields': ('valid_from', 'valid_to', 'fiscal_year', 'fiscal_quarter')
        }),
        ('Approval', {
            'fields': ('is_approved', 'approved_at', 'approved_by')
        }),
        ('Audit', {
            'fields': ('created_at', 'created_by', 'updated_at', 'updated_by'),
            'classes': ('collapse',)
        })
    )

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(DailyExpense)
class DailyExpenseAdmin(admin.ModelAdmin):
    list_display = ('expense_id', 'category', 'amount', 'date', 'status', 'paid_by')
    list_filter = ('status', 'category', 'date')
    search_fields = ('expense_id', 'description', 'paid_by__username')
    readonly_fields = ('created_at', 'updated_at', 'approved_at')
    fieldsets = (
        ('Expense Information', {
            'fields': ('expense_id', 'date', 'category', 'description', 'amount')
        }),
        ('Approval', {
            'fields': ('status', 'paid_by', 'approved_by', 'approved_at', 'rejection_reason')
        }),
        ('Attachments', {
            'fields': ('attachments',)
        }),
        ('Audit', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )



@admin.register(Voucher)
class VoucherAdmin(admin.ModelAdmin):
    list_display = ('voucher_number', 'type', 'date', 'party_name', 'amount', 'status')
    list_filter = ('type', 'status', 'date')
    search_fields = ('voucher_number', 'party_name', 'reference_no')
    inlines = [VoucherDetailInline]
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        ('Voucher Information', {
            'fields': ('voucher_number', 'type', 'date', 'reference_no', 'party_name', 'purpose', 'amount')
        }),
        ('Approval', {
            'fields': ('status', 'department_approved_by', 'finance_approved_by')
        }),
        ('Attachments', {
            'fields': ('attachments',)
        }),
        ('Audit', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(VoucherDetail)
class VoucherDetailAdmin(admin.ModelAdmin):
    list_display = ('voucher', 'account', 'debit_amount', 'credit_amount')
    list_filter = ('account__account_type',)
    search_fields = ('voucher__voucher_number', 'account__name')


@admin.register(BankAccount)
class BankAccountAdmin(admin.ModelAdmin):
    list_display = ('account_number', 'bank_name', 'branch', 'current_balance', 'is_active')
    list_filter = ('is_active', 'bank_name')
    search_fields = ('account_number', 'bank_name', 'branch', 'ifsc_code')


@admin.register(BankPayment)
class BankPaymentAdmin(admin.ModelAdmin):
    list_display = ('payment_id', 'bank_account', 'party_name', 'amount', 'payment_date', 'status')
    list_filter = ('status', 'payment_date', 'bank_account')
    search_fields = ('payment_id', 'party_name', 'reference_number')
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        ('Payment Information', {
            'fields': ('payment_id', 'bank_account', 'party_name', 'payment_reason', 'amount', 'payment_date', 'reference_number')
        }),
        ('Approval', {
            'fields': ('status', 'verified_by', 'approved_by')
        }),
        ('Attachments', {
            'fields': ('attachments',)
        }),
        ('Audit', {
            'fields': ('created_by', 'created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )

    def save_model(self, request, obj, form, change):
        if not change:
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(Subscription)
class SubscriptionAdmin(admin.ModelAdmin):
    list_display = ('name', 'vendor', 'amount', 'frequency', 'next_payment_date', 'status')
    list_filter = ('status', 'frequency')
    search_fields = ('name', 'vendor', 'subscription_type')


@admin.register(ClientInvoice)
class ClientInvoiceAdmin(admin.ModelAdmin):
    list_display = ('invoice_number', 'client', 'billing_model', 'total_amount', 'due_date', 'status')
    list_filter = ('status', 'billing_model', 'billing_cycle_start')
    search_fields = ('invoice_number', 'client__username', 'client__email')
    readonly_fields = ('created_at', 'updated_at')
    fieldsets = (
        ('Invoice Information', {
            'fields': ('invoice_number', 'client', 'billing_model', 'billing_cycle_start', 'billing_cycle_end')
        }),
        ('Billing Details', {
            'fields': ('order_count', 'fte_count', 'rate', 'subtotal', 'tax_amount', 'discount', 'total_amount')
        }),
        ('Status & Approval', {
            'fields': ('status', 'due_date', 'approved_by')
        }),
        ('Audit', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )


@admin.register(ChartOfAccount)
class ChartOfAccountAdmin(admin.ModelAdmin):
    list_display = ('code', 'name', 'account_type', 'parent', 'is_active')
    list_filter = ('account_type', 'is_active')
    search_fields = ('code', 'name')
    fieldsets = (
        ('Account Information', {
            'fields': ('code', 'name', 'account_type', 'parent', 'description')
        }),
        ('Status', {
            'fields': ('is_active',)
        }),
        ('Audit', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        })
    )