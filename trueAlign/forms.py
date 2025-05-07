
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