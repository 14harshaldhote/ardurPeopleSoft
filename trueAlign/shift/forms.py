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
    Form for creating and updating shift master records.
    """

    # Custom field for break duration in minutes
    break_duration_minutes = forms.IntegerField(
        min_value=0,
        max_value=480,  # 8 hours max
        initial=30,
        help_text="Break duration in minutes (0-480)"
    )

    # Custom field for grace period in minutes
    grace_period_minutes = forms.IntegerField(
        min_value=0,
        max_value=120,  # 2 hours max
        initial=15,
        help_text="Grace period in minutes (0-120)"
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
                'placeholder': 'Enter shift name (e.g., Morning Shift)',
                'maxlength': 50
            }),
            'start_time': forms.TimeInput(attrs={
                'class': 'form-control',
                'type': 'time'
            }),
            'end_time': forms.TimeInput(attrs={
                'class': 'form-control',
                'type': 'time'
            }),
            'shift_duration': forms.NumberInput(attrs={
                'class': 'form-control',
                'step': '0.5',
                'min': '0.5',
                'max': '24',
                'placeholder': '8.0'
            }),
            'work_days': forms.Select(attrs={
                'class': 'form-control'
            }),
            'custom_work_days': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Monday,Tuesday,Wednesday,Thursday,Friday',
                'help_text': 'Required only if "Custom" is selected for work days'
            }),
            'is_active': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
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

    def clean_name(self):
        """Validate shift name uniqueness."""
        name = self.cleaned_data.get('name')
        if not name:
            raise ValidationError("Shift name is required.")

        # Check for duplicate names (excluding current instance if editing)
        existing_query = ShiftMaster.objects.filter(name__iexact=name)
        if self.instance and self.instance.pk:
            existing_query = existing_query.exclude(pk=self.instance.pk)

        if existing_query.exists():
            raise ValidationError(f"A shift with the name '{name}' already exists.")

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
        """Cross-field validation."""
        cleaned_data = super().clean()
        start_time = cleaned_data.get('start_time')
        end_time = cleaned_data.get('end_time')
        duration = cleaned_data.get('shift_duration')
        break_minutes = cleaned_data.get('break_duration_minutes', 0)

        # Validate break duration vs shift duration
        if duration and break_minutes:
            break_hours = break_minutes / 60
            if break_hours >= duration:
                raise ValidationError("Break duration must be less than shift duration.")

        # Auto-calculate duration if not provided
        if start_time and end_time and not duration:
            if end_time < start_time:  # Crosses midnight
                hours = (24 - start_time.hour - start_time.minute/60) + (end_time.hour + end_time.minute/60)
            else:
                hours = (end_time.hour + end_time.minute/60) - (start_time.hour + start_time.minute/60)

            cleaned_data['shift_duration'] = round(hours, 2)

        return cleaned_data

    def save(self, commit=True):
        """Save the form with custom duration fields."""
        instance = super().save(commit=False)

        # Convert minutes to timedelta
        break_minutes = self.cleaned_data.get('break_duration_minutes', 30)
        grace_minutes = self.cleaned_data.get('grace_period_minutes', 15)

        instance.break_duration = timedelta(minutes=break_minutes)
        instance.grace_period = timedelta(minutes=grace_minutes)

        if commit:
            instance.save()

        return instance


class ShiftAssignmentForm(forms.ModelForm):
    """
    Form for creating shift assignments.
    """

    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True).order_by('username'),
        widget=forms.Select(attrs={'class': 'form-control'}),
        help_text="Select user to assign shift to"
    )

    shift = forms.ModelChoiceField(
        queryset=ShiftMaster.objects.filter(is_active=True).order_by('name'),
        widget=forms.Select(attrs={'class': 'form-control'}),
        help_text="Select shift to assign"
    )

    class Meta:
        model = ShiftAssignment
        fields = ['user', 'shift', 'effective_from', 'effective_to']
        widgets = {
            'effective_from': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            }),
            'effective_to': forms.DateInput(attrs={
                'class': 'form-control',
                'type': 'date'
            })
        }
        help_texts = {
            'effective_from': 'Date when this shift assignment becomes effective',
            'effective_to': 'Date when this shift assignment ends (leave blank for open-ended)'
        }

    def clean_effective_from(self):
        """Validate effective from date."""
        effective_from = self.cleaned_data.get('effective_from')

        if not effective_from:
            raise ValidationError("Effective from date is required.")

        # Allow assignments to start from today or future
        if effective_from < timezone.now().date():
            raise ValidationError("Effective from date cannot be in the past.")

        return effective_from

    def clean_effective_to(self):
        """Validate effective to date."""
        effective_to = self.cleaned_data.get('effective_to')
        effective_from = self.cleaned_data.get('effective_from')

        if effective_to and effective_from:
            if effective_to <= effective_from:
                raise ValidationError("Effective to date must be after effective from date.")

        return effective_to

    def clean(self):
        """Cross-field validation for assignment conflicts."""
        cleaned_data = super().clean()
        user = cleaned_data.get('user')
        shift = cleaned_data.get('shift')
        effective_from = cleaned_data.get('effective_from')
        effective_to = cleaned_data.get('effective_to')

        if user and shift and effective_from:
            # Check for overlapping assignments
            from trueAlign.shift.services import ShiftService
            service = ShiftService()

            is_valid, error_message = service.validate_shift_assignment(
                user.id, shift.id, effective_from, effective_to
            )

            if not is_valid:
                raise ValidationError(error_message)

        return cleaned_data




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
