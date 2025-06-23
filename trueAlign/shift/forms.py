# forms.py for shift management

# --- Cleaned up and consolidated imports ---
from django import forms
from django.contrib.auth.models import User
from django.utils import timezone
from django.core.exceptions import ValidationError
from datetime import timedelta

# --- CORRECTED IMPORT ---
# Use a single dot '.' to import from the models.py file in the same app directory.
from ..models import ShiftMaster, ShiftAssignment, Holiday


class ShiftForm(forms.ModelForm):
    """
    Form for creating and updating shifts, aligned with the ShiftMaster model.
    """
    class Meta:
        model = ShiftMaster
        fields = [
            'name', 'start_time', 'end_time', 'shift_duration', 'break_duration',
            'grace_period', 'work_days', 'custom_work_days', 'is_active'
        ]
        widgets = {
            'name': forms.TextInput(attrs={'placeholder': 'e.g., Morning Shift, General Shift'}),
            'start_time': forms.TimeInput(attrs={'type': 'time'}),
            'end_time': forms.TimeInput(attrs={'type': 'time'}),
            'shift_duration': forms.NumberInput(attrs={'placeholder': 'e.g., 8.5 for 8h 30m', 'step': '0.01'}),
            'break_duration': forms.NumberInput(attrs={'placeholder': 'e.g., 30 for 30 minutes', 'step': '1'}),
            'grace_period': forms.NumberInput(attrs={'placeholder': 'e.g., 15 for 15 minutes', 'step': '1'}),
            'custom_work_days': forms.TextInput(attrs={'placeholder': 'e.g., Monday,Wednesday,Friday'}),
        }
        labels = {
            'is_active': 'Set this shift as active'
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['custom_work_days'].required = False
        self.fields['shift_duration'].help_text = 'Duration in hours (e.g., 8.5 for 8 hours 30 minutes).'
        self.fields['break_duration'].help_text = 'Duration of the break in minutes.'
        self.fields['grace_period'].help_text = 'Grace period for late clock-ins in minutes.'
        self.fields['custom_work_days'].help_text = 'Required only if "Work Days" is set to "Custom".'

        if self.instance and self.instance.pk:
            # For existing instances, display the correct values
            if hasattr(self.instance, 'break_duration') and self.instance.break_duration:
                self.initial['break_duration'] = self.instance.break_duration.total_seconds() / 60
            if hasattr(self.instance, 'grace_period') and self.instance.grace_period:
                self.initial['grace_period'] = self.instance.grace_period.total_seconds() / 60

    def clean_break_duration(self):
        break_duration_minutes = self.cleaned_data.get('break_duration')
        if break_duration_minutes is not None:
            try:
                minutes = float(break_duration_minutes)
                return timedelta(minutes=minutes)
            except (ValueError, TypeError):
                raise ValidationError('Please enter a valid number of minutes.')
        return timedelta(minutes=30)  # Default value

    def clean_grace_period(self):
        grace_period_minutes = self.cleaned_data.get('grace_period')
        if grace_period_minutes is not None:
            try:
                minutes = float(grace_period_minutes)
                return timedelta(minutes=minutes)
            except (ValueError, TypeError):
                raise ValidationError('Please enter a valid number of minutes.')
        return timedelta(minutes=15)  # Default value

    def clean(self):
        cleaned_data = super().clean()
        work_days = cleaned_data.get('work_days')
        custom_work_days = cleaned_data.get('custom_work_days')
        if work_days == 'Custom' and not custom_work_days:
            self.add_error('custom_work_days', 'This field is required when "Work Days" is set to "Custom".')
        return cleaned_data


class ShiftAssignmentForm(forms.Form):
    """Form for assigning shifts to users"""
    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True).order_by('first_name', 'last_name'),
        label='User'
    )
    shift = forms.ModelChoiceField(
        queryset=ShiftMaster.objects.filter(is_active=True).order_by('name'),
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
        # The local import `from .models import ShiftMaster` is no longer needed
        # because we moved it to the top of the file.
        # The queryset for 'shift' is now set directly at the field definition.
        self.fields['effective_from'].help_text = 'Date from which this shift assignment is effective'
        self.fields['effective_to'].help_text = 'Optional end date for this shift assignment'

    def clean(self):
        cleaned_data = super().clean()
        effective_from = cleaned_data.get('effective_from')
        effective_to = cleaned_data.get('effective_to')
        if effective_from and effective_to and effective_to < effective_from:
            self.add_error('effective_to', 'Effective To date must be after Effective From date')
        return cleaned_data


class HolidayForm(forms.ModelForm):
    """Form for creating and updating holidays"""
    class Meta:
        model = Holiday
        fields = ['name', 'date', 'recurring_yearly']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['recurring_yearly'].help_text = 'If checked, this holiday will recur on the same date every year'
