
# forms.py
from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import time

from .models import ShiftMaster, Holiday, ShiftAssignment

class ShiftMasterForm(forms.ModelForm):
    class Meta:
        model = ShiftMaster
        fields = ['name', 'start_time', 'end_time', 'shift_duration', 
                  'break_duration', 'grace_period', 'work_days', 'custom_work_days', 
                  'is_active']
        widgets = {
            'start_time': forms.TimeInput(attrs={'type': 'time'}),
            'end_time': forms.TimeInput(attrs={'type': 'time'}),
            'break_duration': forms.TextInput(attrs={'placeholder': 'HH:MM:SS format (e.g. 00:30:00 for 30 minutes)'}),
            'grace_period': forms.TextInput(attrs={'placeholder': 'HH:MM:SS format (e.g. 00:15:00 for 15 minutes)'}),
            'custom_work_days': forms.TextInput(attrs={'placeholder': 'E.g., 0,2,4 for Mon,Wed,Fri (0=Mon, 6=Sun)'}),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        start_time = cleaned_data.get('start_time')
        end_time = cleaned_data.get('end_time')
        work_days = cleaned_data.get('work_days')
        custom_work_days = cleaned_data.get('custom_work_days')
        
        # Validate work_days and custom_work_days
        if work_days == 'Custom' and not custom_work_days:
            self.add_error('custom_work_days', 'Custom work days are required when "Custom" is selected.')
        
        if custom_work_days:
            try:
                days = [int(day) for day in custom_work_days.split(',')]
                for day in days:
                    if day < 0 or day > 6:
                        self.add_error('custom_work_days', 'Day values must be between 0 (Monday) and 6 (Sunday).')
            except ValueError:
                self.add_error('custom_work_days', 'Invalid format. Use comma-separated numbers from 0-6.')
        
        return cleaned_data

class HolidayForm(forms.ModelForm):
    class Meta:
        model = Holiday
        fields = ['name', 'date', 'recurring_yearly']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date'}),
        }
    
    def clean_date(self):
        date = self.cleaned_data.get('date')
        if date and date < timezone.now().date():
            raise ValidationError('Holiday date cannot be in the past.')
        return date

class ShiftAssignmentForm(forms.ModelForm):
    class Meta:
        model = ShiftAssignment
        fields = ['user', 'shift', 'effective_from', 'effective_to', 'is_current']
        widgets = {
            'effective_from': forms.DateInput(attrs={'type': 'date'}),
            'effective_to': forms.DateInput(attrs={'type': 'date', 'required': False}),
        }
    
    def clean(self):
        cleaned_data = super().clean()
        effective_from = cleaned_data.get('effective_from')
        effective_to = cleaned_data.get('effective_to')
        
        if effective_to and effective_from and effective_to < effective_from:
            self.add_error('effective_to', 'End date cannot be before start date.')
        
        return cleaned_data



from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import datetime, timedelta

from .models import (
    LeavePolicy, LeaveType, LeaveAllocation, UserLeaveBalance,
    LeaveRequest, CompOffRequest
)
from django.contrib.auth.models import Group, User

class LeavePolicyForm(forms.ModelForm):
    """Form for creating and updating leave policies"""
    class Meta:
        model = LeavePolicy
        fields = ['name', 'group', 'is_active']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'group': forms.Select(attrs={'class': 'form-select'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }

class LeaveTypeForm(forms.ModelForm):
    """Form for creating and updating leave types"""
    class Meta:
        model = LeaveType
        fields = [
            'name', 'description', 'is_paid', 'requires_approval',
            'requires_documentation', 'count_weekends', 'can_be_half_day', 'is_active'
        ]
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'is_paid': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'requires_approval': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'requires_documentation': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'count_weekends': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'can_be_half_day': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'is_active': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }
    
    def clean_name(self):
        name = self.cleaned_data['name']
        # Check if name already exists (case insensitive) when creating a new leave type
        if not self.instance.pk:
            if LeaveType.objects.filter(name__iexact=name).exists():
                raise ValidationError('A leave type with this name already exists.')
        return name

class LeaveAllocationForm(forms.ModelForm):
    """Form for creating and updating leave allocations"""
    class Meta:
        model = LeaveAllocation
        fields = ['policy', 'leave_type', 'annual_days', 'carry_forward_limit', 
                 'max_consecutive_days', 'advance_notice_days']
        widgets = {
            'policy': forms.Select(attrs={'class': 'form-select'}),
            'leave_type': forms.Select(attrs={'class': 'form-select'}),
            'annual_days': forms.NumberInput(attrs={'class': 'form-control', 'min': 0, 'step': 0.5}),
            'carry_forward_limit': forms.NumberInput(attrs={'class': 'form-control', 'min': 0, 'step': 0.5}),
            'max_consecutive_days': forms.NumberInput(attrs={'class': 'form-control', 'min': 0}),
            'advance_notice_days': forms.NumberInput(attrs={'class': 'form-control', 'min': 0})
        }

    def clean(self):
        cleaned_data = super().clean()
        policy = cleaned_data.get('policy')
        leave_type = cleaned_data.get('leave_type')
        
        # Check for uniqueness of policy and leave_type combination
        if policy and leave_type:
            if LeaveAllocation.objects.filter(policy=policy, leave_type=leave_type).exclude(id=self.instance.id if self.instance else None).exists():
                raise ValidationError('This leave type is already allocated to this policy.')
        
        return cleaned_data

class LeaveRequestForm(forms.ModelForm):
    """Form for creating and updating leave requests"""
    
    def __init__(self, *args, **kwargs):
        # Allow passing available_leave_types to limit choices
        available_leave_types = kwargs.pop('available_leave_types', None)
        super().__init__(*args, **kwargs)
        
        if available_leave_types is not None:
            self.fields['leave_type'].queryset = available_leave_types
            
        # Add required field indicators
        self.fields['leave_type'].required = True
        self.fields['start_date'].required = True 
        self.fields['end_date'].required = True
        self.fields['reason'].required = True
        self.fields['user'].required = True
    
    class Meta:
        model = LeaveRequest
        fields = ['user', 'leave_type', 'start_date', 'end_date', 'half_day', 'reason', 'documentation', 'is_retroactive']
        widgets = {
            'user': forms.HiddenInput(),
            'leave_type': forms.Select(attrs={
                'class': 'form-select',
                'placeholder': 'Select leave type'
            }),
            'start_date': forms.DateInput(attrs={
                'class': 'form-control', 
                'type': 'date'
            }),
            'end_date': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }),
            'half_day': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            }),
            'reason': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Enter reason for leave'
            }),
            'documentation': forms.FileInput(attrs={
                'class': 'form-control'
            }),
            'is_retroactive': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }
    
    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        leave_type = cleaned_data.get('leave_type')
        half_day = cleaned_data.get('half_day')
        documentation = cleaned_data.get('documentation')
        is_retroactive = cleaned_data.get('is_retroactive')
        user = cleaned_data.get('user')
        
        if not user:
            raise ValidationError('User is required')
            
        if start_date and end_date:
            # Check if end date is after start date
            if start_date > end_date:
                raise ValidationError('End date must be after start date')
            
            # Check if leave is being applied for past dates without retroactive flag
            today = timezone.now().date()
            if start_date < today and not is_retroactive:
                raise ValidationError('You cannot apply for leaves in the past without marking as retroactive')
            
            # For half-day leave, start and end date must be the same
            if half_day and start_date != end_date:
                raise ValidationError('For half-day leave, start and end date must be the same')
        
        # Check if leave type allows half day
        if leave_type and half_day and not leave_type.can_be_half_day:
            raise ValidationError(f"{leave_type.name} cannot be taken as half day")
        
        # Check for documentation if required
        if leave_type and leave_type.requires_documentation and not documentation:
            if not self.instance or not self.instance.documentation:
                raise ValidationError(f"{leave_type.name} requires supporting documentation")
        
        return cleaned_data

class LeaveRejectForm(forms.Form):
    """Form for rejecting a leave request with reason"""
    rejection_reason = forms.CharField(
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        required=True,
        help_text='Provide a reason for rejecting this leave request'
    )
    suggested_dates = forms.CharField(
        widget=forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g., 2023-06-15 to 2023-06-20'}),
        required=False,
        help_text='Optionally suggest alternative dates (if applicable)'
    )

class CompOffRequestForm(forms.ModelForm):
    """Form for requesting comp-off time"""
    class Meta:
        model = CompOffRequest
        fields = ['worked_date', 'hours_worked', 'reason']
        widgets = {
            'worked_date': forms.DateInput(attrs={'class': 'form-control', 'type': 'date'}),
            'hours_worked': forms.NumberInput(attrs={'class': 'form-control', 'min': 0.5, 'step': 0.5}),
            'reason': forms.Textarea(attrs={'class': 'form-control', 'rows': 3})
        }
    
    def clean_worked_date(self):
        worked_date = self.cleaned_data['worked_date']
        today = timezone.now().date()
        
        # Cannot claim comp-off for future dates
        if worked_date > today:
            raise ValidationError('You cannot claim comp-off for future dates')
        
        # Limit how far back comp-off can be claimed (e.g., 30 days)
        thirty_days_ago = today - timedelta(days=30)
        if worked_date < thirty_days_ago:
            raise ValidationError('Comp-off claims must be made within 30 days of the worked date')
        
        return worked_date
    
    def clean_hours_worked(self):
        hours_worked = self.cleaned_data['hours_worked']
        
        if hours_worked <= 0:
            raise ValidationError('Hours worked must be greater than zero')
        
        if hours_worked > 12:
            raise ValidationError('Hours worked cannot exceed 12 hours per day')
        
        return hours_worked

class UserLeaveBalanceForm(forms.ModelForm):
    """Form for manually updating user leave balances (HR use)"""
    class Meta:
        model = UserLeaveBalance
        fields = ['user', 'leave_type', 'year', 'allocated', 'carried_forward', 'additional']
        widgets = {
            'user': forms.Select(attrs={'class': 'form-select'}),
            'leave_type': forms.Select(attrs={'class': 'form-select'}),
            'year': forms.NumberInput(attrs={'class': 'form-control', 'min': 2000, 'max': 2100}),
            'allocated': forms.NumberInput(attrs={'class': 'form-control', 'min': 0, 'step': 0.5}),
            'carried_forward': forms.NumberInput(attrs={'class': 'form-control', 'min': 0, 'step': 0.5}),
            'additional': forms.NumberInput(attrs={'class': 'form-control', 'min': 0, 'step': 0.5})
        }
    
    def clean(self):
        cleaned_data = super().clean()
        user = cleaned_data.get('user')
        leave_type = cleaned_data.get('leave_type')
        year = cleaned_data.get('year')
        
        # Check uniqueness of user, leave_type, and year combination
        if user and leave_type and year:
            exists = UserLeaveBalance.objects.filter(
                user=user, leave_type=leave_type, year=year
            ).exclude(id=self.instance.id if self.instance else None).exists()
            
            if exists:
                raise ValidationError('A balance record already exists for this user, leave type, and year')
        
        return cleaned_data

class LeaveReportFilterForm(forms.Form):
    """Form for filtering leave reports"""
    year = forms.ChoiceField(
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=True
    )
    month = forms.ChoiceField(
        choices=[('', 'All Months')] + [(str(i), datetime(2000, i, 1).strftime('%B')) for i in range(1, 13)],
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=False
    )
    leave_type = forms.ModelChoiceField(
        queryset=LeaveType.objects.all(),
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=False,
        empty_label='All Leave Types'
    )
    department = forms.ChoiceField(
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=False
    )
    status = forms.ChoiceField(
        choices=[('', 'All Statuses')] + LeaveRequest.STATUS_CHOICES,
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=False
    )
    
    def __init__(self, *args, **kwargs):
        departments = kwargs.pop('departments', [])
        years = kwargs.pop('years', [])
        super().__init__(*args, **kwargs)
        
        # Dynamically set department choices
        dept_choices = [('', 'All Departments')]
        for dept in departments:
            dept_choices.append((dept, dept))
        self.fields['department'].choices = dept_choices
        
        # Dynamically set year choices
        current_year = timezone.now().year
        year_choices = [(str(y), str(y)) for y in range(current_year - 2, current_year + 2)]
        self.fields['year'].choices = year_choices
        self.fields['year'].initial = str(current_year)

class BulkLeaveAllocationForm(forms.Form):
    """Form for bulk leave allocation to a group"""
    policy = forms.ModelChoiceField(
        queryset=LeavePolicy.objects.filter(is_active=True),
        widget=forms.Select(attrs={'class': 'form-select'}),
        required=True,
        help_text='Select the leave policy to apply'
    )
    year = forms.IntegerField(
        widget=forms.NumberInput(attrs={'class': 'form-control', 'min': 2000, 'max': 2100}),
        initial=timezone.now().year,
        required=True,
        help_text='Year to allocate leaves for'
    )
    include_existing = forms.BooleanField(
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        required=False,
        initial=False,
        help_text='Update existing balances (if unchecked, only creates new balances)'
    )


class LeaveApprovalForm(forms.Form):
    """Form for approving leave requests"""
    comments = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 3}),
        required=False,
        help_text='Optional comments for the approval'
    )



class LeaveRejectionForm(forms.Form):
    """Form for rejecting leave requests"""
    rejection_reason = forms.CharField(
        widget=forms.Textarea(attrs={'rows': 3}),
        required=True,
        help_text='Provide a reason for rejecting this leave request'
    )
    suggest_dates = forms.BooleanField(
        required=False,
        label='Suggest alternative dates'
    )
    suggested_start_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'type': 'date'})
    )
    suggested_end_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'type': 'date'})
    )
    
    def clean(self):
        cleaned_data = super().clean()
        suggest_dates = cleaned_data.get('suggest_dates')
        
        if suggest_dates:
            start_date = cleaned_data.get('suggested_start_date')
            end_date = cleaned_data.get('suggested_end_date')
            
            if not start_date:
                self.add_error('suggested_start_date', 'Please provide a suggested start date')
            
            if not end_date:
                self.add_error('suggested_end_date', 'Please provide a suggested end date')
            
            if start_date and end_date and start_date > end_date:
                self.add_error('suggested_end_date', 'End date must be after start date')
        
        return cleaned_data