import csv
import io
from datetime import datetime, date, time, timedelta
from decimal import Decimal
from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.utils import timezone
from trueAlign.models import ShiftMaster, ShiftAssignment, Holiday
from django.contrib.auth.models import Group


class ShiftForm(forms.ModelForm):
    """
    Enhanced form for creating and updating shift master records with comprehensive validations.
    """

    # Custom field for break duration in minutes with enhanced validation
    break_duration_minutes = forms.IntegerField(
        min_value=0,
        max_value=480,  # 8 hours max
        initial=30,
        help_text="Break duration in minutes (0-480). Must be less than total shift duration.",
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': '0',
            'max': '480',
            'step': '5',
            'placeholder': '30',
            'data-validation': 'break-duration'
        })
    )

    # Custom field for grace period in minutes with enhanced validation
    grace_period_minutes = forms.IntegerField(
        min_value=0,
        max_value=120,  # 2 hours max
        initial=15,
        help_text="Grace period in minutes (0-120). Time buffer for late arrivals.",
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'min': '0',
            'max': '120',
            'step': '5',
            'placeholder': '15',
            'data-validation': 'grace-period'
        })
    )

    # Field to indicate if this is an overnight shift
    is_overnight = forms.BooleanField(
        required=False,
        initial=False,
        help_text="Check if this shift crosses midnight (e.g., 10:00 PM to 6:00 AM)",
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input',
            'data-validation': 'overnight-shift'
        })
    )

    class Meta:
        model = ShiftMaster
        fields = [
            'name', 'start_time', 'end_time', 'shift_duration',
            'work_days', 'custom_work_days', 'is_active'
        ]
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter unique shift name (e.g., Morning Shift)',
                'maxlength': 50,
                'data-validation': 'shift-name',
                'data-original-name': '',  # Will be set in __init__
            }),
            'start_time': forms.TimeInput(attrs={
                'class': 'form-control',
                'type': 'time',
                'data-validation': 'start-time',
                'data-toggle': 'tooltip',
                'title': 'Select shift start time (24-hour format)'
            }),
            'end_time': forms.TimeInput(attrs={
                'class': 'form-control',
                'type': 'time',
                'data-validation': 'end-time',
                'data-toggle': 'tooltip',
                'title': 'Select shift end time (can be next day for overnight shifts)'
            }),
            'shift_duration': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.5',
                'min': '0.5',
                'max': '24',
                'placeholder': '8.0',
                'data-validation': 'shift-duration',
                'data-toggle': 'tooltip',
                'title': 'Total shift hours including breaks'
            }),
            'work_days': forms.Select(attrs={
                'class': 'form-control',
                'data-validation': 'work-days',
                'onchange': 'toggleCustomWorkDays(this.value)'
            }),
            'custom_work_days': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Monday,Tuesday,Wednesday,Thursday,Friday',
                'data-validation': 'custom-work-days',
                'style': 'display:none;',  # Initially hidden
                'data-toggle': 'tooltip',
                'title': 'Comma-separated day names (case-sensitive)'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input',
                'data-toggle': 'tooltip',
                'title': 'Uncheck to deactivate this shift'
            })
        }
        help_texts = {
            'name': 'Unique name for the shift (max 50 characters)',
            'start_time': 'Shift start time (24-hour format)',
            'end_time': 'Shift end time (can be next day for night shifts)',
            'shift_duration': 'Total shift duration in hours (including breaks)',
            'work_days': 'Select working days pattern',
            'custom_work_days': 'Comma-separated day names (only if Custom is selected)',
            'is_active': 'Uncheck to deactivate this shift'
        }

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        super().__init__(*args, **kwargs)

        # Set initial values for duration fields if editing existing shift
        if self.instance and self.instance.pk:
            if self.instance.break_duration:
                self.fields['break_duration_minutes'].initial = int(
                    self.instance.break_duration.total_seconds() // 60
                )
            if self.instance.grace_period:
                self.fields['grace_period_minutes'].initial = int(
                    self.instance.grace_period.total_seconds() // 60
                )

            # Set overnight flag
            self.fields['is_overnight'].initial = self.instance.crosses_midnight

            # Store original name for duplicate checking
            self.fields['name'].widget.attrs['data-original-name'] = self.instance.name

        # Add CSS classes for validation feedback
        for field_name, field in self.fields.items():
            if hasattr(field.widget, 'attrs'):
                existing_class = field.widget.attrs.get('class', '')
                field.widget.attrs['class'] = f'{existing_class} validation-field'.strip()

        # Make custom_work_days initially hidden if not Custom
        if self.instance and self.instance.work_days != 'Custom':
            self.fields['custom_work_days'].widget.attrs['style'] = 'display:none;'

        # Add AJAX validation attributes
        self.fields['name'].widget.attrs.update({
            'data-ajax-validate': 'true',
            'data-validate-url': '/shift/api/validate-name/',
        })

        # Add real-time calculation attributes
        for time_field in ['start_time', 'end_time']:
            self.fields[time_field].widget.attrs.update({
                'onchange': 'calculateShiftDuration()',
                'data-calculate': 'true'
            })

    def clean_name(self):
        """Enhanced shift name validation with better error messages."""
        name = self.cleaned_data.get('name')

        if not name:
            raise ValidationError("Shift name is required.")

        # Clean the name
        name = name.strip()

        if len(name) < 2:
            raise ValidationError("Shift name must be at least 2 characters long.")

        if len(name) > 50:
            raise ValidationError("Shift name cannot exceed 50 characters.")

        # Check for invalid characters
        import re
        if not re.match(r'^[a-zA-Z0-9\s\-_()]+$', name):
            raise ValidationError("Shift name can only contain letters, numbers, spaces, hyphens, underscores, and parentheses.")

        # Check for duplicate names (case-insensitive, excluding current instance if editing)
        existing_query = ShiftMaster.objects.filter(name__iexact=name)
        if self.instance and self.instance.pk:
            existing_query = existing_query.exclude(pk=self.instance.pk)

        if existing_query.exists():
            existing_shift = existing_query.first()
            raise ValidationError(
                f"A shift with the name '{name}' already exists. "
                f"Existing shift: {existing_shift.start_time.strftime('%H:%M')} - "
                f"{existing_shift.end_time.strftime('%H:%M')}"
            )

        return name

    def clean_shift_duration(self):
        """Validate shift duration."""
        duration = self.cleaned_data.get('shift_duration')
        if not duration:
            raise ValidationError("Shift duration is required.")

        if duration <= 0:
            raise ValidationError("Shift duration must be greater than 0.")

        if duration > 24:
            raise ValidationError("Shift duration cannot exceed 24 hours.")

        return duration

    def clean_break_duration_minutes(self):
        """Validate break duration."""
        minutes = self.cleaned_data.get('break_duration_minutes')
        if minutes is None:
            raise ValidationError("Break duration is required.")

        if minutes < 0:
            raise ValidationError("Break duration cannot be negative.")

        if minutes > 480:  # 8 hours
            raise ValidationError("Break duration cannot exceed 8 hours.")

        return minutes

    def clean_grace_period_minutes(self):
        """Validate grace period."""
        minutes = self.cleaned_data.get('grace_period_minutes')
        if minutes is None:
            raise ValidationError("Grace period is required.")

        if minutes < 0:
            raise ValidationError("Grace period cannot be negative.")

        if minutes > 120:  # 2 hours
            raise ValidationError("Grace period cannot exceed 2 hours.")

        return minutes

    def clean_custom_work_days(self):
        """Validate custom work days format."""
        work_days = self.cleaned_data.get('work_days')
        custom_work_days = self.cleaned_data.get('custom_work_days')

        if work_days == 'Custom':
            if not custom_work_days:
                raise ValidationError("Custom work days are required when 'Custom' is selected.")

            # Validate day names
            valid_days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
            day_names = [day.strip() for day in custom_work_days.split(',')]

            invalid_days = [day for day in day_names if day not in valid_days]
            if invalid_days:
                raise ValidationError(f"Invalid day names: {', '.join(invalid_days)}. "
                                    f"Valid days are: {', '.join(valid_days)}")

            if len(day_names) != len(set(day_names)):
                raise ValidationError("Duplicate day names found in custom work days.")

        return custom_work_days

    def clean(self):
        """Enhanced cross-field validation with comprehensive checks."""
        cleaned_data = super().clean()
        start_time = cleaned_data.get('start_time')
        end_time = cleaned_data.get('end_time')
        duration = cleaned_data.get('shift_duration')
        break_minutes = cleaned_data.get('break_duration_minutes', 0)
        grace_minutes = cleaned_data.get('grace_period_minutes', 0)
        work_days = cleaned_data.get('work_days')
        custom_work_days = cleaned_data.get('custom_work_days')
        is_overnight = cleaned_data.get('is_overnight', False)

        errors = {}

        # Validate time consistency
        if start_time and end_time:
            # Check if overnight flag matches actual times
            actual_overnight = end_time < start_time
            if is_overnight != actual_overnight:
                if actual_overnight:
                    errors['is_overnight'] = 'This appears to be an overnight shift. Please check the overnight option.'
                else:
                    errors['is_overnight'] = 'End time is after start time. This is not an overnight shift.'

            # Calculate actual duration
            if actual_overnight:
                calculated_hours = (24 - start_time.hour - start_time.minute/60) + (end_time.hour + end_time.minute/60)
            else:
                calculated_hours = (end_time.hour + end_time.minute/60) - (start_time.hour + start_time.minute/60)

            # Validate minimum shift duration
            if calculated_hours < 0.5:
                errors['__all__'] = 'Shift duration must be at least 30 minutes.'
            elif calculated_hours > 24:
                errors['__all__'] = 'Shift duration cannot exceed 24 hours.'

            # Auto-calculate duration if not provided or significantly different
            calculated_decimal = Decimal(str(round(calculated_hours, 2)))
            if not duration or abs(duration - calculated_decimal) > Decimal('0.5'):
                cleaned_data['shift_duration'] = calculated_decimal
                duration = cleaned_data['shift_duration']

        # Validate break duration vs shift duration
        if duration and break_minutes:
            break_hours = Decimal(str(break_minutes)) / Decimal('60')
            duration_decimal = Decimal(str(duration))
            if break_hours >= duration_decimal:
                errors['break_duration_minutes'] = f'Break duration ({break_minutes} min) must be less than shift duration ({duration} hours).'
            elif break_hours > duration_decimal * Decimal('0.5'):  # More than 50% of shift
                self.add_error('break_duration_minutes', f'Warning: Break duration ({break_minutes} min) is more than 50% of shift duration.')

        # Validate grace period reasonableness
        if grace_minutes and duration:
            grace_hours = Decimal(str(grace_minutes)) / Decimal('60')
            duration_decimal = Decimal(str(duration))
            if grace_hours > duration_decimal * Decimal('0.25'):  # More than 25% of shift
                self.add_error('grace_period_minutes', f'Warning: Grace period ({grace_minutes} min) seems excessive for a {duration}-hour shift.')

        # Validate custom work days
        if work_days == 'Custom':
            if not custom_work_days:
                errors['custom_work_days'] = 'Custom work days are required when "Custom" is selected.'
            else:
                valid_days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
                day_names = [day.strip() for day in custom_work_days.split(',') if day.strip()]

                invalid_days = [day for day in day_names if day not in valid_days]
                if invalid_days:
                    errors['custom_work_days'] = f'Invalid day names: {", ".join(invalid_days)}. Valid: {", ".join(valid_days)}'

                if len(day_names) != len(set(day_names)):
                    errors['custom_work_days'] = 'Duplicate day names found.'

                if len(day_names) == 0:
                    errors['custom_work_days'] = 'At least one working day must be specified.'

        # Check for shift conflicts with existing shifts
        if start_time and end_time and work_days:
            conflicts = self._check_shift_conflicts(cleaned_data)
            if conflicts:
                conflict_names = [f"{c.name} ({c.start_time.strftime('%H:%M')}-{c.end_time.strftime('%H:%M')})" for c in conflicts]
                errors['__all__'] = f'This shift has time conflicts with existing shifts: {", ".join(conflict_names)}. Please adjust the timing or working days.'

        if errors:
            raise ValidationError(errors)

        return cleaned_data

    def _check_shift_conflicts(self, cleaned_data):
        """Check for conflicts with existing shifts."""
        from trueAlign.models import ShiftMaster

        start_time = cleaned_data.get('start_time')
        end_time = cleaned_data.get('end_time')
        work_days = cleaned_data.get('work_days')
        custom_work_days = cleaned_data.get('custom_work_days')

        if not start_time or not end_time:
            return []

        # Get work days list
        if work_days == 'Weekdays':
            my_work_days = set([0, 1, 2, 3, 4])  # Mon-Fri
        elif work_days == 'All Days':
            my_work_days = set([0, 1, 2, 3, 4, 5])  # Mon-Sat
        elif work_days == 'Custom' and custom_work_days:
            day_map = {'Monday': 0, 'Tuesday': 1, 'Wednesday': 2, 'Thursday': 3,
                      'Friday': 4, 'Saturday': 5, 'Sunday': 6}
            day_names = [day.strip() for day in custom_work_days.split(',') if day.strip()]
            my_work_days = set(day_map.get(day) for day in day_names if day in day_map if day_map.get(day) is not None)
        else:
            return []

        if not my_work_days:
            return []

        # Check existing shifts
        existing_shifts = ShiftMaster.objects.filter(is_active=True)
        if self.instance and self.instance.pk:
            existing_shifts = existing_shifts.exclude(pk=self.instance.pk)

        conflicts = []
        for shift in existing_shifts:
            # Check work days overlap
            shift_work_days = set(shift.working_days_list)
            common_days = my_work_days.intersection(shift_work_days)
            if common_days:
                # Only check time overlap if there are common working days
                if self._times_overlap(start_time, end_time, shift.start_time, shift.end_time):
                    conflicts.append(shift)

        return conflicts

    def _times_overlap(self, start1, end1, start2, end2):
        """Check if two time ranges overlap with improved logic."""
        if not all([start1, end1, start2, end2]):
            return False

        # Convert to minutes for easier comparison
        start1_min = start1.hour * 60 + start1.minute
        end1_min = end1.hour * 60 + end1.minute
        start2_min = start2.hour * 60 + start2.minute
        end2_min = end2.hour * 60 + end2.minute

        # Handle overnight shifts
        if end1 < start1:  # First shift crosses midnight
            end1_min += 24 * 60
        if end2 < start2:  # Second shift crosses midnight
            end2_min += 24 * 60

        # Check for actual overlap (not just touching)
        # Two ranges overlap if start of one is before end of other and vice versa
        overlap = (start1_min < end2_min) and (start2_min < end1_min)

        return overlap

    def save(self, commit=True):
        """Save the form with custom duration fields."""
        instance = super().save(commit=False)

        # Convert minutes to timedelta
        break_minutes = self.cleaned_data.get('break_duration_minutes', 30)
        grace_minutes = self.cleaned_data.get('grace_period_minutes', 15)

        instance.break_duration = timedelta(minutes=break_minutes)
        instance.grace_period = timedelta(minutes=grace_minutes)

        if commit:
            # Skip model validation since form validation already passed
            # Temporarily disable the model's clean method to avoid duplicate validation
            original_clean = instance.clean
            instance.clean = lambda: None
            try:
                instance.save()
            finally:
                # Always restore the original clean method
                instance.clean = original_clean

        return instance


class ShiftAssignmentForm(forms.ModelForm):
    """
    Enhanced form for creating shift assignments with comprehensive validations.
    """

    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True).select_related('profile').order_by('first_name', 'last_name', 'username'),
        widget=forms.Select(attrs={
            'class': 'form-control select2',
            'data-validation': 'user-select',
            'data-placeholder': 'Select user to assign shift to',
            'data-ajax-validate': 'true',
            'data-validate-url': '/shift/api/validate-user/'
        }),
        help_text="Select an active user to assign shift to",
        empty_label="-- Select User --"
    )

    shift = forms.ModelChoiceField(
        queryset=ShiftMaster.objects.filter(is_active=True).order_by('name'),
        widget=forms.Select(attrs={
            'class': 'form-control select2',
            'data-validation': 'shift-select',
            'data-placeholder': 'Select shift to assign',
            'onchange': 'updateShiftDetails(this.value)',
            'data-ajax-validate': 'true'
        }),
        help_text="Select an active shift to assign",
        empty_label="-- Select Shift --"
    )

    # Enhanced date fields with better validation
    effective_from = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-control datepicker',
            'type': 'date',
            'data-validation': 'effective-from',
            'data-min-date': 'today',
            'onchange': 'validateDateRange()',
            'data-toggle': 'tooltip',
            'title': 'Assignment start date (cannot be in the past)'
        }),
        help_text="Date when this shift assignment becomes effective (cannot be in the past)"
    )

    effective_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control datepicker',
            'type': 'date',
            'data-validation': 'effective-to',
            'onchange': 'validateDateRange()',
            'data-toggle': 'tooltip',
            'title': 'Assignment end date (optional, leave blank for ongoing assignment)'
        }),
        help_text="Date when this shift assignment ends (leave blank for ongoing assignment)"
    )

    # Additional field for assignment reason/notes
    reason = forms.CharField(
        max_length=500,
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Optional: Reason for this assignment or any special notes...',
            'maxlength': 500,
            'data-validation': 'reason'
        }),
        help_text="Optional reason or notes for this assignment"
    )

    # Field to override conflict warnings
    override_conflicts = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input',
            'data-validation': 'override-conflicts',
            'onchange': 'toggleConflictOverride()'
        }),
        help_text="Check to override conflict warnings (admin only)"
    )

    class Meta:
        model = ShiftAssignment
        fields = ['user', 'shift', 'effective_from', 'effective_to', 'notes']
        widgets = {
            'notes': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 2,
                'placeholder': 'Additional notes about this assignment...',
                'maxlength': 1000
            })
        }

    def __init__(self, *args, **kwargs):
        self.request = kwargs.pop('request', None)
        self.user_filter = kwargs.pop('user_filter', None)
        self.shift_filter = kwargs.pop('shift_filter', None)
        super().__init__(*args, **kwargs)

        # Filter users based on provided criteria
        if self.user_filter:
            self.fields['user'].queryset = self.fields['user'].queryset.filter(**self.user_filter)

        # Filter shifts based on provided criteria
        if self.shift_filter:
            self.fields['shift'].queryset = self.fields['shift'].queryset.filter(**self.shift_filter)

        # Set minimum date for effective_from
        today = timezone.now().date()
        self.fields['effective_from'].widget.attrs['min'] = today.isoformat()

        # Hide override_conflicts for non-admin users
        if self.request and not self.request.user.is_staff:
            self.fields['override_conflicts'].widget.attrs['style'] = 'display:none;'
            self.fields['override_conflicts'].help_text = ''

        # Pre-populate fields if editing existing assignment
        if self.instance and self.instance.pk:
            self.fields['reason'].initial = self.instance.notes

            # Allow past dates for existing assignments (admin edit)
            if self.request and self.request.user.is_staff:
                self.fields['effective_from'].widget.attrs['data-min-date'] = ''
                del self.fields['effective_from'].widget.attrs['min']

        # Add CSS classes for validation feedback
        for field_name, field in self.fields.items():
            if hasattr(field.widget, 'attrs'):
                existing_class = field.widget.attrs.get('class', '')
                field.widget.attrs['class'] = f'{existing_class} validation-field'.strip()

    def clean_user(self):
        """Enhanced user validation."""
        user = self.cleaned_data.get('user')

        if not user:
            raise ValidationError("User selection is required.")

        if not user.is_active:
            raise ValidationError("Cannot assign shift to inactive user.")

        return user

    def clean_shift(self):
        """Enhanced shift validation."""
        shift = self.cleaned_data.get('shift')

        if not shift:
            raise ValidationError("Shift selection is required.")

        if not shift.is_active:
            raise ValidationError("Cannot assign inactive shift.")

        return shift

    def clean_effective_from(self):
        """Enhanced effective from date validation."""
        effective_from = self.cleaned_data.get('effective_from')

        if not effective_from:
            raise ValidationError("Effective from date is required.")

        today = timezone.now().date()

        # Allow past dates only for existing assignments and admin users
        if effective_from < today:
            if not self.instance or not self.instance.pk:
                raise ValidationError("Cannot create new assignments with past effective dates.")
            elif self.request and not self.request.user.is_staff:
                raise ValidationError("Only administrators can modify assignments with past dates.")

        # Check if date is too far in future (optional business rule)
        max_future_date = today + timedelta(days=365)  # 1 year max
        if effective_from > max_future_date:
            raise ValidationError("Assignment date cannot be more than 1 year in the future.")

        return effective_from

    def clean_effective_to(self):
        """Enhanced effective to date validation."""
        effective_to = self.cleaned_data.get('effective_to')
        effective_from = self.cleaned_data.get('effective_from')

        if effective_to:
            if effective_from and effective_to <= effective_from:
                raise ValidationError("End date must be after start date.")

            # Check maximum assignment duration (optional business rule)
            if effective_from:
                duration = (effective_to - effective_from).days
                if duration > 365:  # 1 year max
                    raise ValidationError("Assignment duration cannot exceed 1 year.")
                elif duration < 1:
                    raise ValidationError("Assignment must be at least 1 day long.")

        return effective_to

    def clean_reason(self):
        """Validate reason field."""
        reason = self.cleaned_data.get('reason', '')

        if reason and len(reason.strip()) < 10:
            raise ValidationError("If providing a reason, please give at least 10 characters of detail.")

        return reason.strip() if reason else ''

    def clean(self):
        """Enhanced cross-field validation for assignment conflicts."""
        cleaned_data = super().clean()
        user = cleaned_data.get('user')
        shift = cleaned_data.get('shift')
        effective_from = cleaned_data.get('effective_from')
        effective_to = cleaned_data.get('effective_to')
        override_conflicts = cleaned_data.get('override_conflicts', False)
        reason = cleaned_data.get('reason', '')

        errors = {}

        if user and shift and effective_from:
            # Check for overlapping assignments (but allow same-day transitions)
            conflicts = self._check_assignment_conflicts(user, effective_from, effective_to)

            if conflicts and not override_conflicts:
                # Filter out conflicts that are just boundary touches (same day end/start)
                real_conflicts = []
                for conflict in conflicts:
                    conflict_end = conflict.effective_to or date.max
                    # Allow same-day transitions
                    if not (conflict_end == effective_from or conflict.effective_from == effective_to):
                        real_conflicts.append(conflict)

                if real_conflicts:
                    conflict_descriptions = []
                    for conflict in real_conflicts:
                        desc = f"{conflict.shift.name} ({conflict.effective_from}"
                        if conflict.effective_to:
                            desc += f" to {conflict.effective_to}"
                        else:
                            desc += " - ongoing"
                        desc += ")"
                        conflict_descriptions.append(desc)

                    errors['__all__'] = (
                        f"This assignment conflicts with existing assignments: {', '.join(conflict_descriptions)}. "
                        f"Check 'Override conflicts' to proceed anyway (admin only)."
                    )

            # Check if user is already assigned to this exact shift in overlapping period
            exact_conflicts = self._check_exact_shift_conflicts(user, shift, effective_from, effective_to)
            if exact_conflicts:
                errors['__all__'] = f"User is already assigned to this shift during the specified period."

            # Validate shift working days against assignment period
            working_days_warning = self._validate_working_days(shift, effective_from, effective_to)
            if working_days_warning:
                self.add_error(None, f"Note: {working_days_warning}")

        # Require reason for conflict overrides
        if override_conflicts and not reason:
            errors['reason'] = "Reason is required when overriding conflicts."

        # Validate user permissions for override
        if override_conflicts and self.request and not self.request.user.is_staff:
            errors['override_conflicts'] = "Only administrators can override assignment conflicts."

        if errors:
            raise ValidationError(errors)

        # Store reason in notes field for saving
        if reason:
            cleaned_data['notes'] = reason

        return cleaned_data

    def _check_assignment_conflicts(self, user, effective_from, effective_to):
        """Check for overlapping assignments for the user."""
        assignments = ShiftAssignment.objects.filter(user=user)

        # Exclude current instance if editing
        if self.instance and self.instance.pk:
            assignments = assignments.exclude(pk=self.instance.pk)

        conflicts = []
        for assignment in assignments:
            if self._date_ranges_overlap(effective_from, effective_to,
                                       assignment.effective_from, assignment.effective_to):
                conflicts.append(assignment)

        return conflicts

    def _check_exact_shift_conflicts(self, user, shift, effective_from, effective_to):
        """Check for exact same shift assignments in overlapping period."""
        assignments = ShiftAssignment.objects.filter(user=user, shift=shift)

        if self.instance and self.instance.pk:
            assignments = assignments.exclude(pk=self.instance.pk)

        conflicts = []
        for assignment in assignments:
            if self._date_ranges_overlap(effective_from, effective_to,
                                       assignment.effective_from, assignment.effective_to):
                conflicts.append(assignment)

        return conflicts

    def _date_ranges_overlap(self, start1, end1, start2, end2):
        """Check if two date ranges overlap, allowing same-day transitions."""
        # Handle None end dates (ongoing assignments)
        if end1 is None and end2 is None:
            return start1 == start2

        if end1 is None:
            return start1 < (end2 or start2)

        if end2 is None:
            return start2 < end1

        # Both have end dates - allow same day transitions (end1 == start2 or end2 == start1)
        return not (end1 <= start2 or end2 <= start1)

    def _validate_working_days(self, shift, effective_from, effective_to):
        """Validate if assignment period includes shift working days."""
        if not shift or not effective_from:
            return None

        working_days = set(shift.working_days_list)

        # Check a sample of dates to see if any fall on working days
        check_date = effective_from
        end_date = effective_to or (effective_from + timedelta(days=7))  # Check first week if ongoing

        found_working_day = False
        days_checked = 0

        while check_date <= end_date and days_checked < 14:  # Check max 2 weeks
            if check_date.weekday() in working_days:
                found_working_day = True
                break
            check_date += timedelta(days=1)
            days_checked += 1

        if not found_working_day:
            working_day_names = [
                ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'][day]
                for day in working_days
            ]
            return f"This shift only works on {', '.join(working_day_names)}, but the assignment period may not include these days."

        return None

    def save(self, commit=True):
        """Enhanced save with proper field handling."""
        instance = super().save(commit=False)

        # Set created_by if available
        if self.request and self.request.user:
            if not instance.created_by:
                instance.created_by = self.request.user

        # Handle notes field
        reason = self.cleaned_data.get('reason', '')
        if reason:
            existing_notes = instance.notes or ''
            if existing_notes:
                instance.notes = f"{existing_notes}\n\n[Assignment Reason: {reason}]"
            else:
                instance.notes = f"[Assignment Reason: {reason}]"

        if commit:
            instance.save()

        return instance




class BulkAssignmentForm(forms.Form):
    """
    A fully updated and scalable form for bulk assigning shifts to a large number
    of employees, designed to work with a modern JavaScript UI.
    """

    # Add group filter to help with large user lists
    group_filter = forms.ModelChoiceField(
        queryset=Group.objects.all().order_by('name'),
        required=False,
        widget=forms.Select(attrs={
            'class': 'w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500',
            'id': 'groupFilter'
        }),
        label="Filter by Group",
        help_text="Filter employees by their group/role."
    )

    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.none(),  # Will be set dynamically
        widget=forms.SelectMultiple(
            attrs={'class': 'hidden'}
        ),
        label="Employees",
        help_text="Employees will be selected in the interactive list."
    )

    shift = forms.ModelChoiceField(
        queryset=ShiftMaster.objects.filter(is_active=True).order_by('name'),
        widget=forms.Select(attrs={
            'class': 'w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500'
        }),
        label="Shift to Assign",
        help_text="Select the shift to assign to all selected employees."
    )

    effective_from = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500',
            'type': 'date'
        }),
        label="Effective From",
        help_text="Date when these assignments become effective."
    )

    effective_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500',
            'type': 'date'
        }),
        label="Effective To (Optional)",
        help_text="Date when these assignments end. Leave blank for an indefinite assignment."
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        try:
            # Get users with current active assignments
            active_assignment_user_ids = ShiftAssignment.objects.filter(
                is_current=True,
                effective_from__lte=timezone.now().date()
            ).filter(
                models.Q(effective_to__isnull=True) |
                models.Q(effective_to__gte=timezone.now().date())
            ).values_list('user_id', flat=True)

            # Set queryset to exclude users with active assignments
            self.fields['users'].queryset = User.objects.filter(
                is_active=True
            ).exclude(
                id__in=active_assignment_user_ids
            ).select_related().prefetch_related('groups').order_by(
                'first_name', 'last_name', 'username'
            )
        except Exception as e:
            # Fallback to all active users if there's an error
            self.fields['users'].queryset = User.objects.filter(
                is_active=True
            ).order_by('first_name', 'last_name', 'username')

    def clean_users(self):
        users = self.cleaned_data.get('users')
        if not users:
            raise ValidationError("You must select at least one employee to assign a shift.")

        if len(users) > 500:
            raise ValidationError("Cannot assign a shift to more than 500 users at once. Please perform the action in smaller batches.")

        return users

    def clean_effective_from(self):
        effective_from = self.cleaned_data.get('effective_from')
        if effective_from and effective_from < timezone.now().date():
            raise ValidationError("The 'Effective From' date cannot be in the past.")
        return effective_from

    def clean(self):
        cleaned_data = super().clean()
        effective_from = cleaned_data.get('effective_from')
        effective_to = cleaned_data.get('effective_to')

        if effective_from and effective_to:
            if effective_to <= effective_from:
                raise ValidationError({
                    'effective_to': "The 'Effective To' date must be after the 'Effective From' date."
                })

        return cleaned_data




class HolidayForm(forms.ModelForm):
    """
    Form for creating and updating holidays.
    """

    class Meta:
        model = Holiday
        fields = ['name', 'date', 'recurring_yearly']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-input',
                'placeholder': 'Holiday name (e.g., Christmas)',
                'maxlength': 100
            }),
            'date': forms.DateInput(attrs={
                'class': 'form-input',
                'type': 'date'
            }),
            'recurring_yearly': forms.CheckboxInput(attrs={
                'class': 'w-4 h-4 text-blue-600 bg-gray-100 border-gray-300 rounded focus:ring-blue-500 dark:focus:ring-blue-600 dark:ring-offset-gray-800 focus:ring-2 dark:bg-gray-700 dark:border-gray-600'
            })
        }
        help_texts = {
            'name': 'Name of the holiday',
            'date': 'Date of the holiday',
            'recurring_yearly': 'Check if this holiday occurs every year on the same date'
        }

    def clean_name(self):
        """Validate holiday name."""
        name = self.cleaned_data.get('name')
        if not name:
            raise ValidationError("Holiday name is required.")

        return name.strip()

    def clean_date(self):
        """Validate holiday date."""
        holiday_date = self.cleaned_data.get('date')
        if not holiday_date:
            raise ValidationError("Holiday date is required.")

        return holiday_date

    def clean(self):
        """Check for duplicate holidays."""
        cleaned_data = super().clean()
        name = cleaned_data.get('name')
        holiday_date = cleaned_data.get('date')

        if name and holiday_date:
            # Check for exact duplicate
            existing_query = Holiday.objects.filter(name__iexact=name, date=holiday_date)
            if self.instance and self.instance.pk:
                existing_query = existing_query.exclude(pk=self.instance.pk)

            if existing_query.exists():
                raise ValidationError(f"Holiday '{name}' on {holiday_date} already exists.")

        return cleaned_data


class CSVUploadForm(forms.Form):
    """
    Form for uploading CSV files for bulk shift assignments.
    """

    csv_file = forms.FileField(
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.csv'
        }),
        help_text="Upload CSV file with shift assignments (max 5MB)"
    )

    def clean_csv_file(self):
        """Validate uploaded CSV file."""
        csv_file = self.cleaned_data.get('csv_file')

        if not csv_file:
            raise ValidationError("CSV file is required.")

        # Check file size (5MB limit)
        if csv_file.size > 5 * 1024 * 1024:
            raise ValidationError("File size cannot exceed 5MB.")

        # Check file extension
        if not csv_file.name.lower().endswith('.csv'):
            raise ValidationError("File must be a CSV file (.csv extension).")

        # Validate CSV content
        try:
            csv_content = csv_file.read().decode('utf-8')
            csv_file.seek(0)  # Reset file pointer

            # Check if file is empty
            if not csv_content.strip():
                raise ValidationError("CSV file is empty.")

            # Validate CSV structure
            csv_lines = csv_content.strip().split('\n')
            if len(csv_lines) < 2:
                raise ValidationError("CSV file must contain at least a header row and one data row.")

            # Check headers
            csv_reader = csv.DictReader(io.StringIO(csv_content))
            required_headers = ['username', 'shift_name', 'effective_from']
            missing_headers = [h for h in required_headers if h not in csv_reader.fieldnames]

            if missing_headers:
                raise ValidationError(f"Missing required headers: {', '.join(missing_headers)}. "
                                    f"Required headers are: {', '.join(required_headers)}")

            # Validate data rows (sample first few rows)
            row_count = 0
            for row in csv_reader:
                row_count += 1
                if row_count > 5:  # Only validate first 5 rows for performance
                    break

                # Check required fields
                for field in required_headers:
                    if not row.get(field, '').strip():
                        raise ValidationError(f"Row {row_count + 1}: {field} cannot be empty.")

                # Validate date format
                try:
                    datetime.strptime(row['effective_from'], '%Y-%m-%d')
                except ValueError:
                    raise ValidationError(f"Row {row_count + 1}: Invalid effective_from date format. Use YYYY-MM-DD.")

                # Validate effective_to if provided
                if row.get('effective_to', '').strip():
                    try:
                        datetime.strptime(row['effective_to'], '%Y-%m-%d')
                    except ValueError:
                        raise ValidationError(f"Row {row_count + 1}: Invalid effective_to date format. Use YYYY-MM-DD.")

            if row_count > 1000:
                raise ValidationError("CSV file cannot contain more than 1000 rows.")

        except UnicodeDecodeError:
            raise ValidationError("File must be a valid UTF-8 encoded CSV file.")
        except Exception as e:
            if isinstance(e, ValidationError):
                raise
            raise ValidationError(f"Error reading CSV file: {str(e)}")

        return csv_file


class ShiftFilterForm(forms.Form):
    """
    Form for filtering shift lists and reports.
    """

    ACTIVE_CHOICES = [
        ('', 'All'),
        ('true', 'Active Only'),
        ('false', 'Inactive Only')
    ]

    name = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search by shift name'
        })
    )

    is_active = forms.ChoiceField(
        required=False,
        choices=ACTIVE_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    work_days = forms.ChoiceField(
        required=False,
        choices=[('', 'All')] + ShiftMaster.WORK_DAYS_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control'})
    )


class AssignmentFilterForm(forms.Form):
    """
    Form for filtering shift assignments.
    """

    STATUS_CHOICES = [
        ('', 'All'),
        ('current', 'Current'),
        ('ended', 'Ended'),
        ('upcoming', 'Upcoming')
    ]

    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True).order_by('username'),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'}),
        empty_label="All Users"
    )

    shift = forms.ModelChoiceField(
        queryset=ShiftMaster.objects.filter(is_active=True).order_by('name'),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'}),
        empty_label="All Shifts"
    )

    status = forms.ChoiceField(
        required=False,
        choices=STATUS_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )

    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )

    def clean(self):
        """Validate date range."""
        cleaned_data = super().clean()
        date_from = cleaned_data.get('date_from')
        date_to = cleaned_data.get('date_to')

        if date_from and date_to:
            if date_to < date_from:
                raise ValidationError("End date must be after start date.")

        return cleaned_data


class ReportGenerationForm(forms.Form):
    """
    Form for generating shift reports.
    """

    REPORT_TYPES = [
        ('daily', 'Daily Schedule'),
        ('weekly', 'Weekly Summary'),
        ('monthly', 'Monthly Report'),
        ('assignment_history', 'Assignment History'),
        ('statistics', 'Statistics Report')
    ]

    EXPORT_FORMATS = [
        ('html', 'HTML (Web View)'),
        ('csv', 'CSV (Excel Compatible)'),
        ('pdf', 'PDF (Printable)')
    ]

    report_type = forms.ChoiceField(
        choices=REPORT_TYPES,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    start_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )

    end_date = forms.DateField(
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )

    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True).order_by('username'),
        required=False,
        widget=forms.CheckboxSelectMultiple(),
        help_text="Leave empty to include all users"
    )

    shifts = forms.ModelMultipleChoiceField(
        queryset=ShiftMaster.objects.filter(is_active=True).order_by('name'),
        required=False,
        widget=forms.CheckboxSelectMultiple(),
        help_text="Leave empty to include all shifts"
    )

    export_format = forms.ChoiceField(
        choices=EXPORT_FORMATS,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    def clean(self):
        """Validate date range and combinations."""
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')

        if start_date and end_date:
            if end_date < start_date:
                raise ValidationError("End date must be after start date.")

            # Limit report range
            date_diff = (end_date - start_date).days
            if date_diff > 365:
                raise ValidationError("Report date range cannot exceed 1 year.")

        return cleaned_data
