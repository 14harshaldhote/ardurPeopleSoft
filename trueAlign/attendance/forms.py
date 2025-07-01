# attendance/forms.py
from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from datetime import datetime, date, timedelta
from django.utils import timezone

from trueAlign.models import Attendance, ShiftAssignment


class AttendanceForm(forms.ModelForm):
    """
    Form for manually adding/editing attendance records
    """
    clock_in_time = forms.TimeField(
        required=False,
        widget=forms.TimeInput(attrs={
            'type': 'time',
            'class': 'form-control'
        }),
        help_text="Clock in time (24-hour format)"
    )

    clock_out_time = forms.TimeField(
        required=False,
        widget=forms.TimeInput(attrs={
            'type': 'time',
            'class': 'form-control'
        }),
        help_text="Clock out time (24-hour format)"
    )

    date = forms.DateField(
        widget=forms.DateInput(attrs={
            'type': 'date',
            'class': 'form-control'
        })
    )

    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        widget=forms.Select(attrs={'class': 'form-control'}),
        empty_label="Select Employee"
    )

    remarks = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Additional remarks or notes...'
        })
    )

    class Meta:
        model = Attendance
        fields = [
            'user', 'date', 'status', 'clock_in_time', 'clock_out_time',
            'location', 'remarks', 'is_half_day'
        ]
        widgets = {
            'status': forms.Select(attrs={'class': 'form-control'}),
            'location': forms.Select(attrs={'class': 'form-control'}),
            'is_half_day': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Filter users based on permissions
        if self.user and not (self.user.groups.filter(name='HR').exists() or self.user.is_superuser):
            self.fields['user'].queryset = User.objects.filter(id=self.user.id)
            self.fields['user'].initial = self.user

        # Filter location choices if needed
        if hasattr(self.instance, 'location'):
            # Keep existing location choices
            pass

    def clean(self):
        cleaned_data = super().clean()
        user = cleaned_data.get('user')
        date = cleaned_data.get('date')
        clock_in_time = cleaned_data.get('clock_in_time')
        clock_out_time = cleaned_data.get('clock_out_time')

        # Check if attendance already exists for this user and date
        if user and date:
            existing = Attendance.objects.filter(user=user, date=date)
            if self.instance and self.instance.pk:
                existing = existing.exclude(pk=self.instance.pk)

            if existing.exists():
                raise ValidationError(f"Attendance record already exists for {user.get_full_name()} on {date}")

        # Validate clock times
        if clock_in_time and clock_out_time:
            if clock_out_time <= clock_in_time:
                raise ValidationError("Clock out time must be after clock in time")

        # Validate date is not in future
        if date and date > timezone.now().date():
            raise ValidationError("Cannot create attendance for future dates")

        return cleaned_data


class RegularizationForm(forms.Form):
    """
    Form for requesting attendance regularization
    """
    REGULARIZATION_CHOICES = [
        ('Present', 'Present'),
        ('Present & Late', 'Present & Late'),
        ('Absent', 'Absent'),
        ('On Leave', 'On Leave'),
        ('Work From Home', 'Work From Home'),
        ('Half Day', 'Half Day'),
    ]

    attendance_id = forms.IntegerField(widget=forms.HiddenInput())

    requested_status = forms.ChoiceField(
        choices=REGULARIZATION_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control'}),
        label="Requested Status"
    )

    reason = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 4,
            'placeholder': 'Please provide a detailed reason for this regularization request...'
        }),
        label="Reason for Regularization",
        help_text="Provide a clear explanation for why this attendance needs to be regularized"
    )

    clock_in_time = forms.TimeField(
        required=False,
        widget=forms.TimeInput(attrs={
            'type': 'time',
            'class': 'form-control'
        }),
        label="Requested Clock In Time",
        help_text="If applicable, specify the correct clock in time"
    )

    clock_out_time = forms.TimeField(
        required=False,
        widget=forms.TimeInput(attrs={
            'type': 'time',
            'class': 'form-control'
        }),
        label="Requested Clock Out Time",
        help_text="If applicable, specify the correct clock out time"
    )

    def clean(self):
        cleaned_data = super().clean()
        reason = cleaned_data.get('reason')

        if reason and len(reason.strip()) < 10:
            raise ValidationError("Please provide a more detailed reason (at least 10 characters)")

        return cleaned_data


class AttendanceFilterForm(forms.Form):
    """
    Form for filtering attendance data
    """
    TIME_PERIOD_CHOICES = [
        ('today', 'Today'),
        ('yesterday', 'Yesterday'),
        ('this_week', 'This Week'),
        ('last_week', 'Last Week'),
        ('this_month', 'This Month'),
        ('last_month', 'Last Month'),
        ('this_year', 'This Year'),
        ('custom', 'Custom Range'),
    ]

    time_period = forms.ChoiceField(
        choices=TIME_PERIOD_CHOICES,
        initial='this_month',
        widget=forms.Select(attrs={'class': 'form-control'}),
        required=False
    )

    start_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'type': 'date',
            'class': 'form-control'
        }),
        label="From Date"
    )

    end_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'type': 'date',
            'class': 'form-control'
        }),
        label="To Date"
    )

    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'}),
        empty_label="All Employees"
    )

    status = forms.ChoiceField(
        choices=[('', 'All Status')] + Attendance.STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    location = forms.ChoiceField(
        choices=[('', 'All Locations')] + Attendance.LOCATION_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Limit user selection based on permissions
        if user and not (user.groups.filter(name__in=['HR', 'Manager']).exists() or user.is_superuser):
            self.fields['user'].queryset = User.objects.filter(id=user.id)
            self.fields['user'].initial = user

    def clean(self):
        cleaned_data = super().clean()
        time_period = cleaned_data.get('time_period')
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')

        if time_period == 'custom':
            if not start_date or not end_date:
                raise ValidationError("Start date and end date are required for custom range")

            if start_date > end_date:
                raise ValidationError("Start date cannot be after end date")

            if (end_date - start_date).days > 365:
                raise ValidationError("Date range cannot exceed 365 days")

        return cleaned_data


class HRRegularizationProcessForm(forms.Form):
    """
    Form for HR to process regularization requests
    """
    ACTION_CHOICES = [
        ('approve', 'Approve'),
        ('reject', 'Reject'),
    ]

    action = forms.ChoiceField(
        choices=ACTION_CHOICES,
        widget=forms.RadioSelect(attrs={'class': 'form-check-input'})
    )

    comments = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Add comments for the employee (optional)...'
        }),
        label="HR Comments"
    )


class BulkAttendanceForm(forms.Form):
    """
    Form for bulk attendance operations
    """
    BULK_ACTION_CHOICES = [
        ('mark_present', 'Mark as Present'),
        ('mark_absent', 'Mark as Absent'),
        ('mark_holiday', 'Mark as Holiday'),
        ('mark_weekend', 'Mark as Weekend'),
    ]

    date = forms.DateField(
        widget=forms.DateInput(attrs={
            'type': 'date',
            'class': 'form-control'
        })
    )

    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True),
        widget=forms.CheckboxSelectMultiple(),
        label="Select Employees"
    )

    action = forms.ChoiceField(
        choices=BULK_ACTION_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    reason = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 2,
            'placeholder': 'Reason for bulk action...'
        }),
        label="Reason"
    )

    def clean(self):
        cleaned_data = super().clean()
        date = cleaned_data.get('date')
        users = cleaned_data.get('users')

        if date and date > timezone.now().date():
            raise ValidationError("Cannot perform bulk operations on future dates")

        if users and len(users) > 100:
            raise ValidationError("Cannot process more than 100 users at once")

        return cleaned_data


class AttendanceSearchForm(forms.Form):
    """
    Form for searching attendance records
    """
    employee_search = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search by employee name or username...'
        }),
        label="Employee Search"
    )

    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'type': 'date',
            'class': 'form-control'
        }),
        label="From Date"
    )

    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'type': 'date',
            'class': 'form-control'
        }),
        label="To Date"
    )

    status = forms.ChoiceField(
        choices=[('', 'All Status')] + Attendance.STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    regularization_status = forms.ChoiceField(
        choices=[('', 'All')] + [
            ('Pending', 'Pending'),
            ('Approved', 'Approved'),
            ('Rejected', 'Rejected'),
        ],
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'}),
        label="Regularization Status"
    )


class QuickAttendanceForm(forms.Form):
    """
    Quick form for marking today's attendance
    """
    status = forms.ChoiceField(
        choices=[
            ('Present', 'Present'),
            ('Present & Late', 'Present & Late'),
            ('Work From Home', 'Work From Home'),
            ('On Leave', 'On Leave'),
            ('Absent', 'Absent'),
        ],
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    location = forms.ChoiceField(
        choices=Attendance.LOCATION_CHOICES,
        initial='Office',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    remarks = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Optional remarks...'
        })
    )


class AttendanceImportForm(forms.Form):
    """
    Form for importing attendance data from CSV/Excel
    """
    file = forms.FileField(
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.csv,.xlsx,.xls'
        }),
        help_text="Upload CSV or Excel file with attendance data"
    )

    overwrite_existing = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Overwrite existing records",
        help_text="Check this to overwrite existing attendance records for the same date and user"
    )

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            # Check file size (max 5MB)
            if file.size > 5 * 1024 * 1024:
                raise ValidationError("File size cannot exceed 5MB")

            # Check file extension
            allowed_extensions = ['.csv', '.xlsx', '.xls']
            file_extension = file.name.lower().split('.')[-1]
            if f'.{file_extension}' not in allowed_extensions:
                raise ValidationError("Only CSV and Excel files are allowed")

        return file


class AttendanceCalendarForm(forms.Form):
    """
    Form for calendar navigation
    """
    year = forms.IntegerField(
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        min_value=2020,
        max_value=2030
    )

    month = forms.IntegerField(
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        min_value=1,
        max_value=12
    )


class AttendanceSettingsForm(forms.Form):
    """
    Form for attendance system settings
    """
    auto_marking_enabled = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        label="Enable automatic attendance marking"
    )

    grace_period_minutes = forms.IntegerField(
        initial=10,
        min_value=0,
        max_value=60,
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        label="Grace period (minutes)"
    )

    regularization_deadline_days = forms.IntegerField(
        initial=7,
        min_value=1,
        max_value=30,
        widget=forms.NumberInput(attrs={'class': 'form-control'}),
        label="Regularization deadline (days)"
    )


class SessionAttendanceForm(forms.Form):
    """
    Form for manual session-based attendance marking
    """
    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        widget=forms.Select(attrs={'class': 'form-control'}),
        label="Employee"
    )

    login_time = forms.DateTimeField(
        widget=forms.DateTimeInput(attrs={
            'type': 'datetime-local',
            'class': 'form-control'
        }),
        label="Login Time"
    )

    logout_time = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'type': 'datetime-local',
            'class': 'form-control'
        }),
        label="Logout Time"
    )

    location = forms.ChoiceField(
        choices=Attendance.LOCATION_CHOICES,
        widget=forms.Select(attrs={'class': 'form-control'}),
        initial='Office'
    )

    ip_address = forms.GenericIPAddressField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'IP Address'
        })
    )

    def clean(self):
        cleaned_data = super().clean()
        login_time = cleaned_data.get('login_time')
        logout_time = cleaned_data.get('logout_time')

        if login_time and logout_time:
            if logout_time <= login_time:
                raise ValidationError("Logout time must be after login time")

        return cleaned_data
