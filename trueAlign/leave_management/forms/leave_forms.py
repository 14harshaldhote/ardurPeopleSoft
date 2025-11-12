"""
Main Leave Application and Approval Forms
"""
from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from django.utils import timezone
from datetime import datetime, timedelta
from decimal import Decimal

from trueAlign.models import LeaveType, LeaveRequest, CompOffRequest, UserLeaveBalance
from ..utils import get_potential_approvers, can_approve_leave
from ..services.leave_service import LeaveService


class LeaveApplicationForm(forms.ModelForm):
    """
    Comprehensive leave application form with validation
    """

    class Meta:
        model = LeaveRequest
        fields = [
            'leave_type', 'start_date', 'end_date', 'half_day',
            'reason', 'documentation', 'is_retroactive'
        ]
        widgets = {
            'start_date': forms.DateInput(
                attrs={
                    'type': 'date',
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'min': timezone.now().date().strftime('%Y-%m-%d')
                }
            ),
            'end_date': forms.DateInput(
                attrs={
                    'type': 'date',
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'min': timezone.now().date().strftime('%Y-%m-%d')
                }
            ),
            'leave_type': forms.Select(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'onchange': 'updateLeaveTypeInfo(this.value)'
                }
            ),
            'reason': forms.Textarea(
                attrs={
                    'rows': 4,
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'placeholder': 'Please provide reason for your leave...'
                }
            ),
            'documentation': forms.FileInput(
                attrs={
                    'class': 'block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-emerald-50 file:text-emerald-700 hover:file:bg-emerald-100',
                    'accept': '.pdf,.doc,.docx,.jpg,.jpeg,.png'
                }
            ),
            'half_day': forms.CheckboxInput(
                attrs={
                    'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
                }
            ),
            'is_retroactive': forms.CheckboxInput(
                attrs={
                    'class': 'h-4 w-4 text-amber-600 focus:ring-amber-500 border-gray-300 rounded'
                }
            )
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Filter active leave types
        self.fields['leave_type'].queryset = LeaveType.objects.filter(is_active=True)
        self.fields['leave_type'].empty_label = "Select Leave Type"

        # Make documentation optional by default
        self.fields['documentation'].required = False

        # Set help text
        self.fields['half_day'].help_text = "Check if this is a half-day leave"
        self.fields['is_retroactive'].help_text = "Check if applying for past dates (requires special approval)"

        # Add CSS classes to labels
        for field_name, field in self.fields.items():
            if field_name == 'half_day':
                continue
            field.label_suffix = ""

    def clean(self):
        cleaned_data = super().clean()
        leave_type = cleaned_data.get('leave_type')
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        half_day = cleaned_data.get('half_day', False)
        documentation = cleaned_data.get('documentation')
        is_retroactive = cleaned_data.get('is_retroactive', False)

        if not self.user:
            raise ValidationError("User context is required for validation")

        # Basic date validation
        if start_date and end_date:
            if start_date > end_date:
                raise ValidationError("End date must be on or after start date")

        # Leave type specific validations
        if leave_type:
            # Half-day validation
            if half_day and not leave_type.can_be_half_day:
                raise ValidationError(f"{leave_type.name} cannot be taken as half day")

            # Documentation requirement
            if leave_type.requires_documentation and not documentation:
                raise ValidationError(f"{leave_type.name} requires supporting documentation")

        # Retroactive leave validation
        if not is_retroactive and start_date and start_date < timezone.now().date():
            raise ValidationError("Cannot apply for past dates without marking as retroactive")

        # Create temporary leave request for comprehensive validation
        if all([leave_type, start_date, end_date]):
            temp_leave = LeaveRequest(
                user=self.user,
                leave_type=leave_type,
                start_date=start_date,
                end_date=end_date,
                half_day=half_day,
                is_retroactive=is_retroactive,
                documentation=documentation
            )
            temp_leave.leave_days = temp_leave.calculate_leave_days()

            # Use service for validation
            validation_result = LeaveService.validate_leave_request(temp_leave)

            if not validation_result['is_valid']:
                error_message = '; '.join(validation_result['errors'])
                raise ValidationError(error_message)

        return cleaned_data

    def _post_clean(self):
        """Override to prevent model validation errors when user is not set"""
        # Set the user temporarily for validation
        if self.user and not self.instance.user_id:
            self.instance.user = self.user
        
        # Call parent _post_clean but catch user-related validation errors
        try:
            super()._post_clean()
        except ValidationError as e:
            # If the error is about missing user, ignore it during form validation
            if 'User is required' not in str(e):
                raise

    def get_leave_days_preview(self):
        """Get preview of leave days for the current form data"""
        if self.is_valid():
            temp_leave = LeaveRequest(
                leave_type=self.cleaned_data['leave_type'],
                start_date=self.cleaned_data['start_date'],
                end_date=self.cleaned_data['end_date'],
                half_day=self.cleaned_data.get('half_day', False)
            )
            return temp_leave.calculate_leave_days()
        return 0


class LeaveApprovalForm(forms.Form):
    """
    Form for approving leave requests
    """
    comments = forms.CharField(
        required=False,
        widget=forms.Textarea(
            attrs={
                'rows': 3,
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                'placeholder': 'Optional comments for approval...'
            }
        ),
        help_text="Add any comments or notes for this approval"
    )

    def __init__(self, *args, **kwargs):
        self.leave_request = kwargs.pop('leave_request', None)
        self.approver = kwargs.pop('approver', None)
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()

        if not self.leave_request:
            raise ValidationError("Leave request is required")

        if not self.approver:
            raise ValidationError("Approver is required")

        # Validate approver can approve this leave
        if not can_approve_leave(self.approver, self.leave_request.user):
            raise ValidationError("You are not authorized to approve this leave request")

        # Check if already processed
        if self.leave_request.status != 'Pending':
            raise ValidationError(f"Leave request is already {self.leave_request.status}")

        return cleaned_data


class LeaveRejectionForm(forms.Form):
    """
    Form for rejecting leave requests
    """
    rejection_reason = forms.CharField(
        label="Rejection Reason",
        widget=forms.Textarea(
            attrs={
                'rows': 4,
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-rose-500 focus:ring-rose-500 sm:text-sm',
                'placeholder': 'Please provide reason for rejection...'
            }
        ),
        help_text="Please provide a clear reason for rejecting this leave request"
    )

    suggested_dates = forms.CharField(
        label="Suggested Alternative Dates",
        required=False,
        widget=forms.TextInput(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring-amber-500 sm:text-sm',
                'placeholder': 'e.g., 2024-01-15 to 2024-01-17'
            }
        ),
        help_text="Optionally suggest alternative dates"
    )

    def __init__(self, *args, **kwargs):
        self.leave_request = kwargs.pop('leave_request', None)
        self.approver = kwargs.pop('approver', None)
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()

        if not self.leave_request:
            raise ValidationError("Leave request is required")

        if not self.approver:
            raise ValidationError("Approver is required")

        # Validate approver can reject this leave
        if not can_approve_leave(self.approver, self.leave_request.user):
            raise ValidationError("You are not authorized to reject this leave request")

        # Check if already processed
        if self.leave_request.status != 'Pending':
            raise ValidationError(f"Leave request is already {self.leave_request.status}")

        return cleaned_data


class LeaveCancellationForm(forms.Form):
    """
    Form for cancelling leave requests
    """
    cancellation_reason = forms.CharField(
        label="Cancellation Reason",
        required=False,
        widget=forms.Textarea(
            attrs={
                'rows': 3,
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring-amber-500 sm:text-sm',
                'placeholder': 'Optional reason for cancellation...'
            }
        ),
        help_text="Optionally provide reason for cancelling this leave"
    )

    def __init__(self, *args, **kwargs):
        self.leave_request = kwargs.pop('leave_request', None)
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

    def clean(self):
        cleaned_data = super().clean()

        if not self.leave_request:
            raise ValidationError("Leave request is required")

        if not self.user:
            raise ValidationError("User is required")

        # Check if can be cancelled
        if self.leave_request.status in ['Cancelled', 'Rejected']:
            raise ValidationError("Leave request is already cancelled or rejected")

        # Check if user can cancel (own leave or HR/Admin)
        from ..utils import is_hr, is_admin
        if (self.leave_request.user.id != self.user.id and
            not (is_hr(self.user) or is_admin(self.user))):
            raise ValidationError("You can only cancel your own leave requests")

        return cleaned_data


class CompOffRequestForm(forms.ModelForm):
    """
    Form for comp-off requests
    """

    class Meta:
        model = CompOffRequest
        fields = ['worked_date', 'reason', 'hours_worked']
        widgets = {
            'worked_date': forms.DateInput(
                attrs={
                    'type': 'date',
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-lime-500 focus:ring-lime-500 sm:text-sm',
                    'max': timezone.now().date().strftime('%Y-%m-%d')
                }
            ),
            'reason': forms.Textarea(
                attrs={
                    'rows': 4,
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-lime-500 focus:ring-lime-500 sm:text-sm',
                    'placeholder': 'Describe the work done and reason for comp-off...'
                }
            ),
            'hours_worked': forms.NumberInput(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-lime-500 focus:ring-lime-500 sm:text-sm',
                    'min': '0.5',
                    'max': '16',
                    'step': '0.5'
                }
            )
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Set help text
        self.fields['worked_date'].help_text = "Date when you worked extra hours"
        self.fields['hours_worked'].help_text = "Total extra hours worked (e.g., 8 for full day)"
        self.fields['reason'].help_text = "Describe the work done that requires compensation"

    def clean_worked_date(self):
        worked_date = self.cleaned_data.get('worked_date')

        if worked_date:
            # Cannot be future date
            if worked_date > timezone.now().date():
                raise ValidationError("Worked date cannot be in the future")

            # Cannot be too far in the past (e.g., more than 30 days)
            thirty_days_ago = timezone.now().date() - timedelta(days=30)
            if worked_date < thirty_days_ago:
                raise ValidationError("Cannot claim comp-off for dates more than 30 days ago")

        return worked_date

    def clean_hours_worked(self):
        hours_worked = self.cleaned_data.get('hours_worked')

        if hours_worked:
            if hours_worked < 0.5:
                raise ValidationError("Minimum 0.5 hours required for comp-off")
            if hours_worked > 16:
                raise ValidationError("Maximum 16 hours allowed per day")

        return hours_worked

    def clean(self):
        cleaned_data = super().clean()
        worked_date = cleaned_data.get('worked_date')

        if self.user and worked_date:
            # Check for duplicate comp-off requests for the same date
            existing_request = CompOffRequest.objects.filter(
                user=self.user,
                worked_date=worked_date
            )

            if self.instance and self.instance.pk:
                existing_request = existing_request.exclude(pk=self.instance.pk)

            if existing_request.exists():
                raise ValidationError(f"You already have a comp-off request for {worked_date}")

        return cleaned_data


class QuickLeaveForm(forms.Form):
    """
    Simplified form for quick leave application (emergency use)
    """
    leave_type = forms.ModelChoiceField(
        queryset=LeaveType.objects.filter(is_active=True),
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-rose-500 focus:ring-rose-500 sm:text-sm'
            }
        ),
        empty_label="Select Leave Type"
    )

    date = forms.DateField(
        widget=forms.DateInput(
            attrs={
                'type': 'date',
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-rose-500 focus:ring-rose-500 sm:text-sm'
            }
        )
    )

    half_day = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                'class': 'h-4 w-4 text-rose-600 focus:ring-rose-500 border-gray-300 rounded'
            }
        )
    )

    reason = forms.CharField(
        widget=forms.Textarea(
            attrs={
                'rows': 3,
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-rose-500 focus:ring-rose-500 sm:text-sm',
                'placeholder': 'Emergency reason...'
            }
        )
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Only show leave types that don't require documentation
        self.fields['leave_type'].queryset = LeaveType.objects.filter(
            is_active=True,
            requires_documentation=False
        )

    def clean(self):
        cleaned_data = super().clean()
        leave_type = cleaned_data.get('leave_type')
        date = cleaned_data.get('date')
        half_day = cleaned_data.get('half_day', False)

        if leave_type and half_day and not leave_type.can_be_half_day:
            raise ValidationError(f"{leave_type.name} cannot be taken as half day")

        # Quick leave is essentially same-day application
        if date and date != timezone.now().date():
            raise ValidationError("Quick leave can only be applied for today")

        return cleaned_data

    def save(self, user):
        """Convert quick leave to regular leave request"""
        cleaned_data = self.cleaned_data

        leave_request = LeaveRequest(
            user=user,
            leave_type=cleaned_data['leave_type'],
            start_date=cleaned_data['date'],
            end_date=cleaned_data['date'],
            half_day=cleaned_data.get('half_day', False),
            reason=cleaned_data['reason'],
            is_retroactive=True  # Since it's same day application
        )

        leave_request.save()
        return leave_request


class LeaveBalanceAdjustmentForm(forms.Form):
    """
    Form for HR/Admin to manually adjust leave balances
    """
    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm'
            }
        ),
        empty_label="Select User"
    )

    leave_type = forms.ModelChoiceField(
        queryset=LeaveType.objects.filter(is_active=True),
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm'
            }
        ),
        empty_label="Select Leave Type"
    )

    adjustment_type = forms.ChoiceField(
        choices=[
            ('add', 'Add Days'),
            ('subtract', 'Subtract Days'),
            ('set', 'Set Balance')
        ],
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm'
            }
        )
    )

    days = forms.DecimalField(
        max_digits=5,
        decimal_places=1,
        min_value=0,
        widget=forms.NumberInput(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                'step': '0.5'
            }
        )
    )

    reason = forms.CharField(
        widget=forms.Textarea(
            attrs={
                'rows': 3,
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                'placeholder': 'Reason for adjustment...'
            }
        )
    )

    def clean(self):
        cleaned_data = super().clean()
        user = cleaned_data.get('user')
        leave_type = cleaned_data.get('leave_type')
        adjustment_type = cleaned_data.get('adjustment_type')
        days = cleaned_data.get('days')

        if all([user, leave_type, adjustment_type, days]):
            # Check if balance exists
            try:
                balance = UserLeaveBalance.objects.get(
                    user=user,
                    leave_type=leave_type,
                    year=timezone.now().year
                )

                if adjustment_type == 'subtract' and balance.available < days:
                    raise ValidationError(f"Cannot subtract {days} days. Available balance: {balance.available}")
            except UserLeaveBalance.DoesNotExist:
                if adjustment_type in ['subtract']:
                    raise ValidationError("No balance record found for this user and leave type")

        return cleaned_data
