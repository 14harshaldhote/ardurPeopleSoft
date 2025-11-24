from django import forms
from django.contrib.contenttypes.models import ContentType
from trueAlign.models import (
    FinancialParameter, DailyExpense, Voucher, VoucherDetail,
    BankAccount, BankPayment, Subscription, ClientInvoice, ChartOfAccount
)


class FinancialParameterForm(forms.ModelForm):
    class Meta:
        model = FinancialParameter
        fields = [
            'key', 'name', 'category', 'description', 'value_type', 'value',
            'is_global', 'content_type', 'object_id',
            'valid_from', 'valid_to', 'fiscal_year', 'fiscal_quarter'
        ]
        widgets = {
            'key': forms.TextInput(attrs={'class': 'form-control'}),
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'value_type': forms.Select(attrs={'class': 'form-select'}),
            'value': forms.TextInput(attrs={'class': 'form-control'}),
            'is_global': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'content_type': forms.Select(attrs={'class': 'form-select'}),
            'object_id': forms.NumberInput(attrs={'class': 'form-control'}),
            'valid_from': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'valid_to': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'fiscal_year': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'YYYY-YYYY'}),
            'fiscal_quarter': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'YYYY-Q#'}),
        }





class DailyExpenseForm(forms.ModelForm):
    class Meta:
        model = DailyExpense
        fields = ['date', 'category', 'description', 'amount', 'attachments']
        widgets = {
            'date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'category': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'amount': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'attachments': forms.FileInput(attrs={'class': 'form-control'}),
        }


class ExpenseApprovalForm(forms.ModelForm):
    class Meta:
        model = DailyExpense
        fields = ['status', 'rejection_reason']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-select'}),
            'rejection_reason': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Limit status choices to approval-related ones
        self.fields['status'].choices = [
            ('approved', 'Approved'),
            ('rejected', 'Rejected'),
        ]


class VoucherForm(forms.ModelForm):
    class Meta:
        model = Voucher
        fields = ['type', 'date', 'reference_no', 'party_name', 'purpose', 'amount', 'attachments']
        widgets = {
            'type': forms.Select(attrs={'class': 'form-select'}),
            'date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'reference_no': forms.TextInput(attrs={'class': 'form-control'}),
            'party_name': forms.TextInput(attrs={'class': 'form-control'}),
            'purpose': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'amount': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'attachments': forms.FileInput(attrs={'class': 'form-control'}),
        }


class VoucherDetailForm(forms.ModelForm):
    class Meta:
        model = VoucherDetail
        fields = ['account', 'debit_amount', 'credit_amount', 'description']
        widgets = {
            'account': forms.Select(attrs={'class': 'form-select'}),
            'debit_amount': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'credit_amount': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
        }


# Formset for voucher details
from django.forms import inlineformset_factory

VoucherDetailFormSet = inlineformset_factory(
    Voucher,
    VoucherDetail,
    form=VoucherDetailForm,
    extra=3,
    can_delete=True
)


class BankAccountForm(forms.ModelForm):
    class Meta:
        model = BankAccount
        fields = ['name', 'account_number', 'bank_name', 'branch', 'ifsc_code', 'current_balance', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'account_number': forms.TextInput(attrs={'class': 'form-control'}),
            'bank_name': forms.TextInput(attrs={'class': 'form-control'}),
            'branch': forms.TextInput(attrs={'class': 'form-control'}),
            'ifsc_code': forms.TextInput(attrs={'class': 'form-control'}),
            'current_balance': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }


class BankPaymentForm(forms.ModelForm):
    class Meta:
        model = BankPayment
        fields = ['bank_account', 'party_name', 'payment_reason', 'amount', 'payment_date', 'reference_number', 'attachments']
        widgets = {
            'bank_account': forms.Select(attrs={'class': 'form-select'}),
            'party_name': forms.TextInput(attrs={'class': 'form-control'}),
            'payment_reason': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'amount': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'payment_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'reference_number': forms.TextInput(attrs={'class': 'form-control'}),
            'attachments': forms.FileInput(attrs={'class': 'form-control'}),
        }


class BankPaymentApprovalForm(forms.ModelForm):
    class Meta:
        model = BankPayment
        fields = ['status']
        widgets = {
            'status': forms.Select(attrs={'class': 'form-select'}),
        }

    def __init__(self, *args, **kwargs):
        current_status = kwargs.pop('current_status', None)
        super().__init__(*args, **kwargs)
        
        # Define next possible statuses based on current status
        if current_status == 'pending':
            self.fields['status'].choices = [
                ('verified', 'Verified'),
            ]
        elif current_status == 'verified':
            self.fields['status'].choices = [
                ('approved', 'Approved'),
            ]
        elif current_status == 'approved':
            self.fields['status'].choices = [
                ('executed', 'Payment Executed'),
                ('failed', 'Failed'),
            ]


class SubscriptionForm(forms.ModelForm):
    class Meta:
        model = Subscription
        fields = ['name', 'vendor', 'subscription_type', 'amount', 'frequency', 'start_date', 'next_payment_date', 'auto_renew', 'alert_days', 'status']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'vendor': forms.TextInput(attrs={'class': 'form-control'}),
            'subscription_type': forms.TextInput(attrs={'class': 'form-control'}),
            'amount': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'frequency': forms.Select(attrs={'class': 'form-select'}),
            'start_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'next_payment_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'auto_renew': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'alert_days': forms.NumberInput(attrs={'class': 'form-control'}),
            'status': forms.Select(attrs={'class': 'form-select'}),
        }


class ClientInvoiceForm(forms.ModelForm):
    class Meta:
        model = ClientInvoice
        fields = [
            'client', 'billing_model', 'billing_cycle_start', 'billing_cycle_end',
            'order_count', 'fte_count', 'rate', 'subtotal', 'tax_amount', 'discount', 'total_amount', 'due_date'
        ]
        widgets = {
            'client': forms.Select(attrs={'class': 'form-select'}),
            'billing_model': forms.Select(attrs={'class': 'form-select'}),
            'billing_cycle_start': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'billing_cycle_end': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'order_count': forms.NumberInput(attrs={'class': 'form-control'}),
            'fte_count': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'rate': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'subtotal': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'readonly': True}),
            'tax_amount': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'discount': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01'}),
            'total_amount': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.01', 'readonly': True}),
            'due_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
        }


class ChartOfAccountForm(forms.ModelForm):
    class Meta:
        model = ChartOfAccount
        fields = ['code', 'name', 'account_type', 'parent', 'description', 'is_active']
        widgets = {
            'code': forms.TextInput(attrs={'class': 'form-control'}),
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'account_type': forms.Select(attrs={'class': 'form-select'}),
            'parent': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }


# Filter Forms for List Views
class ExpenseFilterForm(forms.Form):
    status = forms.ChoiceField(
        choices=[('', 'All Statuses')] + list(DailyExpense.EXPENSE_STATUS),
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    category = forms.ChoiceField(
        choices=[('', 'All Categories')] + list(DailyExpense.EXPENSE_CATEGORIES),
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
    )
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
    )


class VoucherFilterForm(forms.Form):
    type = forms.ChoiceField(
        choices=[('', 'All Types')] + list(Voucher.VOUCHER_TYPES),
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    status = forms.ChoiceField(
        choices=[('', 'All Statuses')] + list(Voucher.VOUCHER_STATUS),
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
    )
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
    )


class BankPaymentFilterForm(forms.Form):
    bank_account = forms.ModelChoiceField(
        queryset=BankAccount.objects.filter(is_active=True),
        required=False,
        empty_label="All Bank Accounts",
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    status = forms.ChoiceField(
        choices=[('', 'All Statuses')] + list(BankPayment.PAYMENT_STATUS),
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
    )
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
    )


class InvoiceFilterForm(forms.Form):
    status = forms.ChoiceField(
        choices=[('', 'All Statuses')] + list(ClientInvoice.INVOICE_STATUS),
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    billing_model = forms.ChoiceField(
        choices=[('', 'All Billing Models')] + list(ClientInvoice.BILLING_MODELS),
        required=False,
        widget=forms.Select(attrs={'class': 'form-select'})
    )
    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
    )
    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'class': 'form-control', 'type': 'date'})
    )