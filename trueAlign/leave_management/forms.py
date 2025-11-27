from django import forms
from trueAlign.models import LeaveRequest, CompOffRequest

class LeaveRequestForm(forms.ModelForm):
    class Meta:
        model = LeaveRequest
        fields = ['leave_type', 'start_date', 'end_date', 'reason', 'half_day', 'approver', 'documentation']
        widgets = {
            'start_date': forms.DateInput(attrs={
                'type': 'date', 
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-transparent text-sm transition-all'
            }),
            'end_date': forms.DateInput(attrs={
                'type': 'date', 
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-transparent text-sm transition-all'
            }),
            'reason': forms.Textarea(attrs={
                'rows': 3, 
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-transparent text-sm transition-all min-h-[100px]'
            }),
            'leave_type': forms.Select(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-transparent text-sm transition-all'
            }),
            'approver': forms.Select(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-emerald-500/50 focus:border-transparent text-sm transition-all'
            }),
            'documentation': forms.FileInput(attrs={
                'class': 'block w-full text-sm text-zinc-700 file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-sm file:font-medium file:bg-white/20 file:text-zinc-700 hover:file:bg-white/30 file:cursor-pointer cursor-pointer backdrop-blur-sm'
            }),
            'half_day': forms.CheckboxInput(attrs={
                'class': 'rounded border-white/20 text-emerald-600 bg-white/20 focus:ring-emerald-500/50 h-5 w-5'
            }),
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
            'worked_date': forms.DateInput(attrs={
                'type': 'date', 
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-transparent text-sm transition-all'
            }),
            'reason': forms.Textarea(attrs={
                'rows': 3, 
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-transparent text-sm transition-all min-h-[100px]'
            }),
            'hours_worked': forms.NumberInput(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-transparent text-sm transition-all', 
                'step': '0.5'
            }),
            'approver': forms.Select(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-transparent text-sm transition-all'
            }),
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
            'name': forms.TextInput(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-transparent text-sm transition-all'
            }),
            'description': forms.Textarea(attrs={
                'rows': 3, 
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-transparent text-sm transition-all min-h-[100px]'
            }),
            'max_days_allowed': forms.NumberInput(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-red-500/50 focus:border-transparent text-sm transition-all'
            }),
            'is_paid': forms.CheckboxInput(attrs={'class': 'rounded border-white/20 text-red-600 bg-white/20 focus:ring-red-500/50 h-5 w-5'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'rounded border-white/20 text-red-600 bg-white/20 focus:ring-red-500/50 h-5 w-5'}),
            'requires_approval': forms.CheckboxInput(attrs={'class': 'rounded border-white/20 text-red-600 bg-white/20 focus:ring-red-500/50 h-5 w-5'}),
            'requires_documentation': forms.CheckboxInput(attrs={'class': 'rounded border-white/20 text-red-600 bg-white/20 focus:ring-red-500/50 h-5 w-5'}),
            'can_be_half_day': forms.CheckboxInput(attrs={'class': 'rounded border-white/20 text-red-600 bg-white/20 focus:ring-red-500/50 h-5 w-5'}),
            'carry_forward_allowed': forms.CheckboxInput(attrs={'class': 'rounded border-white/20 text-red-600 bg-white/20 focus:ring-red-500/50 h-5 w-5'}),
            'count_weekends': forms.CheckboxInput(attrs={'class': 'rounded border-white/20 text-red-600 bg-white/20 focus:ring-red-500/50 h-5 w-5'}),
        }

class LeavePolicyForm(forms.ModelForm):
    class Meta:
        model = LeavePolicy
        fields = ['name', 'group', 'effective_from', 'effective_to', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-transparent text-sm transition-all'
            }),
            'group': forms.Select(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-transparent text-sm transition-all'
            }),
            'effective_from': forms.DateInput(attrs={
                'type': 'date', 
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-transparent text-sm transition-all'
            }),
            'effective_to': forms.DateInput(attrs={
                'type': 'date', 
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-transparent text-sm transition-all'
            }),
            'is_active': forms.CheckboxInput(attrs={'class': 'rounded border-white/20 text-purple-600 bg-white/20 focus:ring-purple-500/50 h-5 w-5'}),
        }

class LeaveAllocationForm(forms.ModelForm):
    class Meta:
        model = LeaveAllocation
        fields = ['policy', 'leave_type', 'annual_days', 'advance_notice_days', 'max_consecutive_days', 'carryforward_limit']
        widgets = {
            'policy': forms.Select(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-transparent text-sm transition-all'
            }),
            'leave_type': forms.Select(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-transparent text-sm transition-all'
            }),
            'annual_days': forms.NumberInput(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-transparent text-sm transition-all', 
                'step': '0.5', 
                'placeholder': 'e.g., 12'
            }),
            'advance_notice_days': forms.NumberInput(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-transparent text-sm transition-all', 
                'placeholder': 'e.g., 3'
            }),
            'max_consecutive_days': forms.NumberInput(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-transparent text-sm transition-all', 
                'placeholder': 'e.g., 5 (0 for no limit)'
            }),
            'carryforward_limit': forms.NumberInput(attrs={
                'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-green-500/50 focus:border-transparent text-sm transition-all', 
                'step': '0.5', 
                'placeholder': 'e.g., 5'
            }),
        }
        labels = {
            'annual_days': 'Annual Days',
            'advance_notice_days': 'Advance Notice (days)',
            'max_consecutive_days': 'Max Consecutive Days',
            'carryforward_limit': 'Carry Forward Limit',
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
        widget=forms.Select(attrs={
            'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-transparent text-sm transition-all'
        }),
        label="Employee"
    )
    leave_type = forms.ModelChoiceField(
        queryset=LeaveType.objects.filter(is_active=True),
        widget=forms.Select(attrs={
            'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-transparent text-sm transition-all'
        }),
        label="Leave Type"
    )
    ADJUSTMENT_CHOICES = [
        ('credit', 'Credit (Add Days)'),
        ('debit', 'Debit (Remove Days)'),
    ]
    adjustment_type = forms.ChoiceField(
        choices=ADJUSTMENT_CHOICES,
        widget=forms.Select(attrs={
            'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-transparent text-sm transition-all'
        }),
        label="Adjustment Type"
    )
    days = forms.DecimalField(
        max_digits=5,
        decimal_places=1,
        min_value=0.5,
        widget=forms.NumberInput(attrs={
            'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-transparent text-sm transition-all', 
            'step': '0.5'
        }),
        help_text="Number of days to add or remove"
    )
    reason = forms.CharField(
        widget=forms.Textarea(attrs={
            'rows': 3, 
            'class': 'w-full px-4 py-3 bg-white/20 border border-white/20 rounded-lg backdrop-blur-sm text-zinc-900 placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-transparent text-sm transition-all min-h-[100px]'
        }),
        help_text="Reason for this manual adjustment (required for audit)"
    )

