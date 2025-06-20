# forms.py for shift management
from django import forms
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import timedelta

class ShiftForm(forms.ModelForm):
    """Form for creating and updating shifts"""
    class Meta:
        from ..models import ShiftMaster
        model = ShiftMaster
        fields = ['name', 'start_time', 'end_time', 'shift_duration', 
                 'break_duration', 'grace_period', 'work_days', 
                 'custom_work_days', 'is_active']
        widgets = {
            'start_time': forms.TimeInput(attrs={'type': 'time'}),
            'end_time': forms.TimeInput(attrs={'type': 'time'}),
            'break_duration': forms.TextInput(attrs={'placeholder': 'Duration in minutes'}),
            'grace_period': forms.TextInput(attrs={'placeholder': 'Duration in minutes'}),
            'custom_work_days': forms.TextInput(attrs={'placeholder': 'Monday,Tuesday,Wednesday,...'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['custom_work_days'].required = False
        self.fields['shift_duration'].help_text = 'Duration in hours (e.g., 8.5 for 8 hours 30 minutes)'
        self.fields['break_duration'].help_text = 'Break duration in minutes'
        self.fields['grace_period'].help_text = 'Grace period in minutes'
        
        # Convert timedelta to minutes for form display
        if self.instance.pk:
            if self.instance.break_duration:
                self.initial['break_duration'] = self.instance.break_duration.total_seconds() / 60
            if self.instance.grace_period:
                self.initial['grace_period'] = self.instance.grace_period.total_seconds() / 60
    
    def clean(self):
        cleaned_data = super().clean()
        work_days = cleaned_data.get('work_days')
        custom_work_days = cleaned_data.get('custom_work_days')
        
        # Validate custom work days if selected
        if work_days == 'Custom' and not custom_work_days:
            self.add_error('custom_work_days', 'Custom work days must be specified when Custom option is selected')
        
        # Convert minutes to timedelta for break_duration and grace_period
        break_duration = cleaned_data.get('break_duration')
        if break_duration is not None:
            cleaned_data['break_duration'] = timedelta(minutes=int(break_duration))
        
        grace_period = cleaned_data.get('grace_period')
        if grace_period is not None:
            cleaned_data['grace_period'] = timedelta(minutes=int(grace_period))
        
        return cleaned_data

class ShiftAssignmentForm(forms.Form):
    """Form for assigning shifts to users"""
    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True).order_by('first_name', 'last_name'),
        label='User'
    )
    shift = forms.ModelChoiceField(
        queryset=None,  # Will be set in __init__
        label='Shift'
    )
    effective_from = forms.DateField(
        widget=forms.DateInput(attrs={'type': 'date'}),
        initial=timezone.now().date,
        label='Effective From'
    )
    effective_to = forms.DateField(
        widget=forms.DateInput(attrs={'type': 'date'}),
        required=False,
        label='Effective To (Optional)'
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Import here to avoid circular imports
        from ..models import ShiftMaster
        self.fields['shift'].queryset = ShiftMaster.objects.filter(is_active=True).order_by('name')
        
        # Add help text
        self.fields['effective_from'].help_text = 'Date from which this shift assignment is effective'
        self.fields['effective_to'].help_text = 'Optional end date for this shift assignment'
    
    def clean(self):
        cleaned_data = super().clean()
        effective_from = cleaned_data.get('effective_from')
        effective_to = cleaned_data.get('effective_to')
        
        # Validate effective_to is after effective_from
        if effective_from and effective_to and effective_to < effective_from:
            self.add_error('effective_to', 'Effective To date must be after Effective From date')
        
        return cleaned_data

class HolidayForm(forms.ModelForm):
    """Form for creating and updating holidays"""
    class Meta:
        from ..models import Holiday
        model = Holiday
        fields = ['name', 'date', 'recurring_yearly']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date'}),
        }
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['recurring_yearly'].help_text = 'If checked, this holiday will recur on the same date every year'