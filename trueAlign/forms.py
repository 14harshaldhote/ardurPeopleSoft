
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

from django import forms
from django.utils import timezone
from django.core.exceptions import ValidationError
import json
from datetime import datetime, date, timedelta

from .models import Attendance, User

class BaseAttendanceForm(forms.Form):
    """Base form with common validation logic"""
    def validate_breaks_format(self, breaks_str):
        """Validate breaks JSON format and time logic"""
        if not breaks_str:
            return True

        try:
            breaks_list = json.loads(breaks_str)
            if not isinstance(breaks_list, list):
                raise ValidationError("Breaks must be a list of break periods")

            for break_item in breaks_list:
                if not isinstance(break_item, dict):
                    raise ValidationError("Each break must be a dictionary")

                start = datetime.strptime(break_item.get('start', ''), '%H:%M').time()
                end = datetime.strptime(break_item.get('end', ''), '%H:%M').time()

                if start >= end:
                    raise ValidationError("Break end time must be after start time")

            return True
        except (json.JSONDecodeError, ValueError):
            raise ValidationError("Invalid break format. Use [{'start':'HH:MM', 'end':'HH:MM'}]")

class AttendanceForm(BaseAttendanceForm):
    """Form for adding/editing a single attendance record"""
    user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-control select2',
            'data-placeholder': 'Select User'
        })
    )

    date = forms.DateField(
        required=True,
        initial=timezone.localdate,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date',
            'max': timezone.localdate().strftime('%Y-%m-%d')
        })
    )

    status = forms.ChoiceField(
        choices=Attendance.STATUS_CHOICES,
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-control',
            'data-toggle': 'status-dependent-fields'
        })
    )

    location = forms.ChoiceField(
        choices=Attendance.LOCATION_CHOICES,
        required=True,
        initial='Office',
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )

    is_half_day = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input',
            'data-toggle': 'half-day-fields'
        })
    )

    clock_in_time = forms.TimeField(
        required=False,
        widget=forms.TimeInput(attrs={
            'class': 'form-control',
            'type': 'time'
        })
    )

    clock_out_time = forms.TimeField(
        required=False,
        widget=forms.TimeInput(attrs={
            'class': 'form-control',
            'type': 'time'
        })
    )

    leave_type = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control leave-type-field hidden'
        })
    )

    holiday_name = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control holiday-field hidden'
        })
    )

    breaks = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 2,
            'placeholder': '[{"start":"09:00", "end":"09:15"}]'
        })
    )

    regularization_reason = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Reason for attendance regularization...'
        })
    )

    remarks = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 2,
            'placeholder': 'Additional remarks...'
        })
    )

    def clean(self):
        cleaned_data = super().clean()
        status = cleaned_data.get('status')
        date_value = cleaned_data.get('date')

        # Status-specific validations
        if status == 'On Leave':
            if not cleaned_data.get('leave_type'):
                self.add_error('leave_type', 'Leave type is required')

        elif status == 'Holiday':
            if not cleaned_data.get('holiday_name'):
                self.add_error('holiday_name', 'Holiday name is required')

        elif status in ['Present', 'Present & Late']:
            clock_in = cleaned_data.get('clock_in_time')
            clock_out = cleaned_data.get('clock_out_time')

            if not clock_in and not cleaned_data.get('regularization_reason'):
                self.add_error('clock_in_time', 'Clock-in time or regularization reason is required')

            if clock_in and clock_out:
                if clock_in >= clock_out:
                    self.add_error('clock_out_time', 'Clock-out must be after clock-in')

                # Validate against current time for today's entry
                if date_value == timezone.localdate():
                    current_time = timezone.localtime().time()
                    if clock_out > current_time:
                        self.add_error('clock_out_time', "Clock-out can't be in the future")

        # Validate breaks if provided
        breaks = cleaned_data.get('breaks')
        if breaks:
            try:
                self.validate_breaks_format(breaks)
            except ValidationError as e:
                self.add_error('breaks', e.message)

        return cleaned_data

class BulkAttendanceForm(BaseAttendanceForm):
    """Form for bulk attendance entry"""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['user'].widget.attrs['disabled'] = True

class AttendanceFilterForm(forms.Form):
    """Enhanced form for filtering users in bulk attendance entry"""
    department = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Filter by department...'
        })
    )

    start_date = forms.DateField(
        required=True,
        initial=timezone.localdate,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )

    end_date = forms.DateField(
        required=True,
        initial=timezone.localdate,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )

    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.none(),
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'form-control select2-multiple',
            'data-placeholder': 'Select users...',
            'size': 8
        })
    )

    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')

        if start_date and end_date:
            if start_date > end_date:
                self.add_error('end_date', 'End date must be after start date')

            date_range = (end_date - start_date).days
            if date_range > 31:  # Limit to one month
                self.add_error('end_date', 'Date range cannot exceed 31 days')

        return cleaned_data


# forms.py
from django import forms
from django.core.exceptions import ValidationError
from .models import Attendance, User
from django.db.models import Q

class ManualAttendanceForm(forms.ModelForm):
    """
    Form for HR to manually add attendance records
    """
    user = forms.ModelChoiceField(
        queryset=User.objects.filter(
            Q(groups__name='Management') | Q(groups__name='Backoffice')
        ).distinct().order_by('username'),
        label='Employee',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    class Meta:
        model = Attendance
        fields = ['user', 'date', 'status']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
            'status': forms.Select(attrs={'class': 'form-control'})
        }

    def clean(self):
        """
        Validate that no additional fields are required for manual entry
        """
        cleaned_data = super().clean()

        # Ensure only basic fields are set
        cleaned_data['clock_in_time'] = None
        cleaned_data['clock_out_time'] = None
        cleaned_data['leave_type'] = None
        cleaned_data['regularization_status'] = None
        cleaned_data['regularization_reason'] = None

        return cleaned_data



from django import forms
from django.contrib.auth.models import User, Group
from django.core.exceptions import ValidationError
from django.utils import timezone
from .models import Support, TicketComment, TicketAttachment

class TicketForm(forms.ModelForm):
            # Use regular FileField without the multiple attribute in the widget
            # We'll handle multiple files in the view instead
    attachments = forms.FileField(
                required=False,
                help_text="You can upload multiple files",
                widget=forms.FileInput()
            )

    cc_users = forms.ModelMultipleChoiceField(
        queryset=User.objects.all(),
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'form-control select2-multiple',
            'data-placeholder': 'Select users to CC...'
        }),
        help_text="Users to be notified about this ticket"
    )

    parent_ticket = forms.ModelChoiceField(
        queryset=Support.objects.filter(status__in=['Open', 'In Progress']),
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-control',
            'data-placeholder': 'Select parent ticket (optional)'
        }),
        help_text="Link this ticket to an existing ticket"
    )

    class Meta:
        model = Support
        fields = [
            'issue_type', 'subject', 'description', 'priority',
            'department', 'location', 'asset_id', 'assigned_group',
            'assigned_to_user', 'due_date', 'cc_users', 'parent_ticket'
        ]
        widgets = {
            'subject': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Brief description of the issue'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5,
                'placeholder': 'Provide detailed information about the issue'
            }),
            'issue_type': forms.Select(attrs={'class': 'form-control'}),
            'priority': forms.Select(attrs={'class': 'form-control'}),
            'department': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Your department'
            }),
            'location': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Your location/office'
            }),
            'asset_id': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Asset/Equipment ID (if applicable)'
            }),
            'assigned_group': forms.Select(attrs={'class': 'form-control'}),
            'assigned_to_user': forms.Select(attrs={'class': 'form-control'}),
            'due_date': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            }),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Make certain fields optional for normal users
        self.fields['department'].required = False
        self.fields['location'].required = False
        self.fields['asset_id'].required = False
        self.fields['due_date'].required = False
        self.fields['parent_ticket'].required = False

        # Set up user assignee choices - only HR and Admin users
        try:
            hr_group = Group.objects.get(name='HR')
            admin_group = Group.objects.get(name='Admin')

            hr_users = hr_group.user_set.all()
            admin_users = admin_group.user_set.all()

            assignable_users = (hr_users | admin_users).distinct()
            self.fields['assigned_to_user'].queryset = assignable_users
        except Group.DoesNotExist:
            self.fields['assigned_to_user'].queryset = User.objects.filter(is_staff=True)

        self.fields['assigned_to_user'].required = False

        # Optional assigned group field (will be auto-populated)
        self.fields['assigned_group'].required = False

        # Set issue type choices that help with routing
        self.fields['issue_type'].help_text = "HR issues and Access Management are routed to HR. All other issues are routed to Admin."

        # Exclude current user from CC list if user is provided
        if user:
            self.fields['cc_users'].queryset = User.objects.exclude(id=user.id)

    def clean_due_date(self):
        due_date = self.cleaned_data.get('due_date')
        if due_date and due_date <= timezone.now():
            raise ValidationError('Due date must be in the future.')
        return due_date

class CommentForm(forms.ModelForm):
    is_internal = forms.BooleanField(
        required=False,
        label="Internal Note (only visible to staff)",
        help_text="Check this box if this comment should only be visible to HR and Admin staff",
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

    class Meta:
        model = TicketComment
        fields = ['content', 'is_internal']
        widgets = {
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Add a comment or update...'
            }),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Hide internal note option for non-staff users
        if user and not user.is_staff:
            self.fields['is_internal'].widget = forms.HiddenInput()
            self.fields['is_internal'].initial = False

class TicketAttachmentForm(forms.ModelForm):
    class Meta:
        model = TicketAttachment
        fields = ['file', 'description']
        widgets = {
            'file': forms.FileInput(attrs={
                'class': 'form-control',
                'accept': '.pdf,.doc,.docx,.txt,.png,.jpg,.jpeg,.gif'
            }),
            'description': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Brief description of the file'
            })
        }

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            # Check file size (limit to 10MB)
            if file.size > 10 * 1024 * 1024:
                raise ValidationError('File size cannot exceed 10MB.')

            # Check file extension
            allowed_extensions = ['.pdf', '.doc', '.docx', '.txt', '.png', '.jpg', '.jpeg', '.gif']
            file_name = file.name.lower()
            if not any(file_name.endswith(ext) for ext in allowed_extensions):
                raise ValidationError('File type not allowed. Allowed types: PDF, DOC, DOCX, TXT, PNG, JPG, JPEG, GIF')

        return file

class TicketFilterForm(forms.Form):
    """Form for filtering tickets in the list view"""
    STATUS_CHOICES = [('', 'All Statuses')] + list(Support.Status.choices)
    PRIORITY_CHOICES = [('', 'All Priorities')] + list(Support.Priority.choices)
    ISSUE_TYPE_CHOICES = [('', 'All Types')] + list(Support.IssueType.choices)
    SLA_STATUS_CHOICES = [('', 'All SLA Status')] + list(Support.SLAStatus.choices)

    search = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search by ticket ID, subject, or description...'
        })
    )

    status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    priority = forms.ChoiceField(
        choices=PRIORITY_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    issue_type = forms.ChoiceField(
        choices=ISSUE_TYPE_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    assigned_group = forms.ChoiceField(
        choices=[('', 'All Groups')] + list(Support.AssignedGroup.choices),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    assigned_to_user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_staff=True),
        required=False,
        empty_label='All Assignees',
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    sla_status = forms.ChoiceField(
        choices=SLA_STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    show_overdue = forms.BooleanField(
        required=False,
        label='Show only overdue tickets',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

    show_breached_sla = forms.BooleanField(
        required=False,
        label='Show only SLA breached tickets',
        widget=forms.CheckboxInput(attrs={'class': 'form-check-input'})
    )

    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        }),
        label='Created From'
    )

    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        }),
        label='Created To'
    )

class TicketUpdateForm(forms.ModelForm):
    """Form for updating ticket details by staff"""
    class Meta:
        model = Support
        fields = [
            'status', 'priority', 'assigned_group', 'assigned_to_user',
            'due_date', 'subject', 'description', 'cc_users'
        ]
        widgets = {
            'status': forms.Select(attrs={'class': 'form-control'}),
            'priority': forms.Select(attrs={'class': 'form-control'}),
            'assigned_group': forms.Select(attrs={'class': 'form-control'}),
            'assigned_to_user': forms.Select(attrs={'class': 'form-control'}),
            'due_date': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local'
            }),
            'subject': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5
            }),
            'cc_users': forms.SelectMultiple(attrs={
                'class': 'form-control select2-multiple'
            })
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set up assignee choices for staff users
        try:
            hr_group = Group.objects.get(name='HR')
            admin_group = Group.objects.get(name='Admin')
            assignable_users = (hr_group.user_set.all() | admin_group.user_set.all()).distinct()
            self.fields['assigned_to_user'].queryset = assignable_users
        except Group.DoesNotExist:
            self.fields['assigned_to_user'].queryset = User.objects.filter(is_staff=True)

class TicketReopenForm(forms.Form):
    """Form for reopening a closed ticket"""
    reason = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Provide a reason for reopening this ticket...'
        }),
        required=True,
        label='Reason for reopening'
    )

class TicketEscalationForm(forms.Form):
    """Form for escalating a ticket"""
    reason = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Provide a reason for escalation...'
        }),
        required=True,
        label='Escalation reason'
    )

    escalate_to_group = forms.ChoiceField(
        choices=Support.AssignedGroup.choices,
        widget=forms.Select(attrs={'class': 'form-control'}),
        required=True,
        label='Escalate to group'
    )

class TicketResolutionForm(forms.Form):
    """Form for resolving a ticket"""
    resolution_summary = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 4,
            'placeholder': 'Describe how the issue was resolved...'
        }),
        required=True,
        label='Resolution summary'
    )

class TicketSatisfactionForm(forms.ModelForm):
    """Form for user satisfaction rating"""
    class Meta:
        model = Support
        fields = ['satisfaction_rating', 'feedback']
        widgets = {
            'satisfaction_rating': forms.RadioSelect(
                choices=[(i, f'{i} Star{"s" if i != 1 else ""}') for i in range(1, 6)]
            ),
            'feedback': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Share your feedback about the support provided...'
            })
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['satisfaction_rating'].required = True
        self.fields['feedback'].required = False

'''----------------------------------------- HOLIDAY FORM -----------------------------------------------'''


# Form for Holiday model
from django import forms

class HolidayForm(forms.ModelForm):
    class Meta:
        model = Holiday
        fields = ['name', 'date', 'recurring_yearly']
        widgets = {
            'date': forms.DateInput(attrs={'type': 'date'}),
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'recurring_yearly': forms.CheckboxInput(attrs={'class': 'form-check-input'})
        }
