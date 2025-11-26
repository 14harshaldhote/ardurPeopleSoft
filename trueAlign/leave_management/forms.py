from django import forms
from trueAlign.models import LeaveRequest, CompOffRequest

class LeaveRequestForm(forms.ModelForm):
    class Meta:
        model = LeaveRequest
        fields = ['leave_type', 'start_date', 'end_date', 'reason', 'half_day', 'approver', 'documentation']
        widgets = {
            'start_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'end_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'reason': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'leave_type': forms.Select(attrs={'class': 'form-select'}),
            'approver': forms.Select(attrs={'class': 'form-select'}),
            'documentation': forms.FileInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user:
            from .selectors import get_potential_approvers, get_active_policy
            self.fields['approver'].queryset = get_potential_approvers(user)
            
            policy = get_active_policy(user)
            if policy:
                allocated_types = policy.allocations.values_list('leave_type', flat=True)
                self.fields['leave_type'].queryset = self.fields['leave_type'].queryset.filter(id__in=allocated_types)

class CompOffRequestForm(forms.ModelForm):
    class Meta:
        model = CompOffRequest
        fields = ['worked_date', 'hours_worked', 'reason', 'approver']
        widgets = {
            'worked_date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'reason': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'hours_worked': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.5'}),
            'approver': forms.Select(attrs={'class': 'form-select'}),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)
        if user:
            from .selectors import get_potential_approvers
            self.fields['approver'].queryset = get_potential_approvers(user)

from trueAlign.models import LeaveType, LeavePolicy, LeaveAllocation

class LeaveTypeForm(forms.ModelForm):
    class Meta:
        model = LeaveType
        fields = ['name', 'description', 'is_paid', 'requires_approval', 'requires_documentation', 
                  'count_weekends', 'can_be_half_day', 'max_days_allowed', 'carry_forward_allowed', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
            'max_days_allowed': forms.NumberInput(attrs={'class': 'form-control'}),
        }

class LeavePolicyForm(forms.ModelForm):
    class Meta:
        model = LeavePolicy
        fields = ['name', 'group', 'effective_from', 'effective_to', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'group': forms.Select(attrs={'class': 'form-select'}),
            'effective_from': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'effective_to': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
        }

class LeaveAllocationForm(forms.ModelForm):
    class Meta:
        model = LeaveAllocation
        fields = ['policy', 'leave_type', 'annual_days', 'advance_notice_days', 'max_consecutive_days', 'carryforward_limit']
        widgets = {
            'policy': forms.Select(attrs={'class': 'form-select'}),
            'leave_type': forms.Select(attrs={'class': 'form-select'}),
            'annual_days': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.5'}),
            'advance_notice_days': forms.NumberInput(attrs={'class': 'form-control'}),
            'max_consecutive_days': forms.NumberInput(attrs={'class': 'form-control'}),
            'carryforward_limit': forms.NumberInput(attrs={'class': 'form-control', 'step': '0.5'}),
        }
    
    def __init__(self, *args, **kwargs):
        policy = kwargs.pop('policy', None)
        super().__init__(*args, **kwargs)
        if policy:
            self.fields['policy'].initial = policy
            self.fields['policy'].widget = forms.HiddenInput()


from django.contrib.auth import get_user_model
User = get_user_model()

class ManualBalanceAdjustmentForm(forms.Form):
    employee = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Employee"
    )
    leave_type = forms.ModelChoiceField(
        queryset=LeaveType.objects.filter(is_active=True),
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Leave Type"
    )
    ADJUSTMENT_CHOICES = [
        ('credit', 'Credit (Add Days)'),
        ('debit', 'Debit (Remove Days)'),
    ]
    adjustment_type = forms.ChoiceField(
        choices=ADJUSTMENT_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        label="Adjustment Type"
    )
    days = forms.DecimalField(
        max_digits=5,
        decimal_places=1,
        min_value=0.5,
        widget=forms.NumberInput(attrs={'class': 'form-control', 'step': '0.5'}),
        help_text="Number of days to add or remove"
    )
    reason = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 3, 'class': 'form-control'}),
        help_text="Reason for this manual adjustment (required for audit)"
    )

