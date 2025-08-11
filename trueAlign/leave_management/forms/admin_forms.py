"""
Admin Forms for Leave Management
For HR and Admin users to manage leave policies, types, and allocations
"""
from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User, Group
from django.utils import timezone
from decimal import Decimal

from trueAlign.models import (
    LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance
)


class LeaveTypeForm(forms.ModelForm):
    """
    Form for creating and editing leave types
    """

    class Meta:
        model = LeaveType
        fields = [
            'name', 'description', 'is_paid', 'requires_approval',
            'requires_documentation', 'count_weekends', 'can_be_half_day', 'is_active'
        ]
        widgets = {
            'name': forms.TextInput(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'placeholder': 'e.g., Annual Leave, Sick Leave'
                }
            ),
            'description': forms.Textarea(
                attrs={
                    'rows': 3,
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'placeholder': 'Description of this leave type...'
                }
            ),
            'is_paid': forms.CheckboxInput(
                attrs={
                    'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
                }
            ),
            'requires_approval': forms.CheckboxInput(
                attrs={
                    'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
                }
            ),
            'requires_documentation': forms.CheckboxInput(
                attrs={
                    'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
                }
            ),
            'count_weekends': forms.CheckboxInput(
                attrs={
                    'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
                }
            ),
            'can_be_half_day': forms.CheckboxInput(
                attrs={
                    'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
                }
            ),
            'is_active': forms.CheckboxInput(
                attrs={
                    'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
                }
            )
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set help text
        self.fields['is_paid'].help_text = "Whether this leave type is paid or unpaid"
        self.fields['requires_approval'].help_text = "Whether this leave type needs manager approval"
        self.fields['requires_documentation'].help_text = "Whether supporting documents are mandatory"
        self.fields['count_weekends'].help_text = "Whether weekends count as leave days"
        self.fields['can_be_half_day'].help_text = "Whether this leave can be taken as half day"
        self.fields['is_active'].help_text = "Whether this leave type is currently available"

    def clean_name(self):
        name = self.cleaned_data.get('name')

        if name:
            # Check for duplicate names
            existing = LeaveType.objects.filter(name__iexact=name)
            if self.instance and self.instance.pk:
                existing = existing.exclude(pk=self.instance.pk)

            if existing.exists():
                raise ValidationError("A leave type with this name already exists")

            # Validate name format
            if len(name.strip()) < 2:
                raise ValidationError("Leave type name must be at least 2 characters long")

        return name


class LeavePolicyForm(forms.ModelForm):
    """
    Form for creating and editing leave policies
    """

    class Meta:
        model = LeavePolicy
        fields = ['name', 'group', 'is_active']
        widgets = {
            'name': forms.TextInput(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'placeholder': 'e.g., Employee Policy, Manager Policy'
                }
            ),
            'group': forms.Select(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm'
                }
            ),
            'is_active': forms.CheckboxInput(
                attrs={
                    'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
                }
            )
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Filter groups to show only relevant ones
        self.fields['group'].queryset = Group.objects.all().order_by('name')
        self.fields['group'].empty_label = "Select Group/Role"

        self.fields['is_active'].help_text = "Whether this policy is currently active"

    def clean(self):
        cleaned_data = super().clean()
        group = cleaned_data.get('group')

        if group:
            # Check if group already has an active policy
            existing_policy = LeavePolicy.objects.filter(
                group=group,
                is_active=True
            )

            if self.instance and self.instance.pk:
                existing_policy = existing_policy.exclude(pk=self.instance.pk)

            if existing_policy.exists():
                raise ValidationError(f"Group '{group.name}' already has an active leave policy")

        return cleaned_data


class LeaveAllocationForm(forms.ModelForm):
    """
    Form for creating and editing leave allocations within policies
    """

    class Meta:
        model = LeaveAllocation
        fields = [
            'policy', 'leave_type', 'annual_days', 'carryforward_limit',
            'max_consecutive_days', 'advance_notice_days'
        ]
        widgets = {
            'policy': forms.Select(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm'
                }
            ),
            'leave_type': forms.Select(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm'
                }
            ),
            'annual_days': forms.NumberInput(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'step': '0.5',
                    'min': '0'
                }
            ),
            'carry_forward_limit': forms.NumberInput(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'step': '0.5',
                    'min': '0'
                }
            ),
            'max_consecutive_days': forms.NumberInput(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'min': '0'
                }
            ),
            'advance_notice_days': forms.NumberInput(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'min': '0'
                }
            )
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Filter active policies and leave types
        self.fields['policy'].queryset = LeavePolicy.objects.filter(is_active=True).order_by('name')
        self.fields['leave_type'].queryset = LeaveType.objects.filter(is_active=True).order_by('name')

        # Set empty labels
        self.fields['policy'].empty_label = "Select Policy"
        self.fields['leave_type'].empty_label = "Select Leave Type"

        # Set help text
        self.fields['annual_days'].help_text = "Total days allocated per year"
        self.fields['carry_forward_limit'].help_text = "Maximum days that can be carried forward (0 = no limit)"
        self.fields['max_consecutive_days'].help_text = "Maximum consecutive days allowed (0 = no limit)"
        self.fields['advance_notice_days'].help_text = "Days of advance notice required (0 = no requirement)"

    def clean(self):
        cleaned_data = super().clean()
        policy = cleaned_data.get('policy')
        leave_type = cleaned_data.get('leave_type')
        annual_days = cleaned_data.get('annual_days')
        carry_forward_limit = cleaned_data.get('carry_forward_limit')

        if policy and leave_type:
            # Check for duplicate allocation
            existing = LeaveAllocation.objects.filter(
                policy=policy,
                leave_type=leave_type
            )

            if self.instance and self.instance.pk:
                existing = existing.exclude(pk=self.instance.pk)

            if existing.exists():
                raise ValidationError(f"Allocation for {leave_type.name} already exists in {policy.name}")

        if annual_days and carry_forward_limit:
            if carry_forward_limit > annual_days:
                raise ValidationError("Carry forward limit cannot exceed annual allocation")

        return cleaned_data


class BulkAllocationForm(forms.Form):
    """
    Form for bulk allocation of leaves to multiple users
    """
    target_groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.all(),
        widget=forms.CheckboxSelectMultiple(
            attrs={
                'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
            }
        ),
        help_text="Select groups/roles to allocate leaves to"
    )

    specific_users = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        widget=forms.CheckboxSelectMultiple(
            attrs={
                'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
            }
        ),
        help_text="Optionally select specific users (overrides group selection)"
    )

    year = forms.IntegerField(
        initial=timezone.now().year,
        widget=forms.NumberInput(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                'min': timezone.now().year - 1,
                'max': timezone.now().year + 2
            }
        ),
        help_text="Year for leave allocation"
    )

    reset_existing = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(
            attrs={
                'class': 'h-4 w-4 text-amber-600 focus:ring-amber-500 border-gray-300 rounded'
            }
        ),
        help_text="Reset existing allocations for the selected year"
    )

    include_carried_forward = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(
            attrs={
                'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
            }
        ),
        help_text="Include carried forward days from previous year"
    )

    def clean_year(self):
        year = self.cleaned_data.get('year')
        current_year = timezone.now().year

        if year < (current_year - 1) or year > (current_year + 2):
            raise ValidationError("Year must be within reasonable range")

        return year

    def clean(self):
        cleaned_data = super().clean()
        target_groups = cleaned_data.get('target_groups')
        specific_users = cleaned_data.get('specific_users')

        if not target_groups and not specific_users:
            raise ValidationError("Please select either target groups or specific users")

        return cleaned_data

    def get_target_users(self):
        """Get the final list of users for allocation"""
        specific_users = self.cleaned_data.get('specific_users')

        if specific_users:
            return list(specific_users)

        target_groups = self.cleaned_data.get('target_groups')
        if target_groups:
            return list(User.objects.filter(
                groups__in=target_groups,
                is_active=True
            ).distinct())

        return []


class UserLeaveBalanceForm(forms.ModelForm):
    """
    Form for manually editing user leave balances
    """

    class Meta:
        model = UserLeaveBalance
        fields = ['user', 'leave_type', 'year', 'allocated', 'used', 'carried_forward', 'additional']
        widgets = {
            'user': forms.Select(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm'
                }
            ),
            'leave_type': forms.Select(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm'
                }
            ),
            'year': forms.NumberInput(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'min': timezone.now().year - 5,
                    'max': timezone.now().year + 2
                }
            ),
            'allocated': forms.NumberInput(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'step': '0.5',
                    'min': '0'
                }
            ),
            'used': forms.NumberInput(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'step': '0.5',
                    'min': '0'
                }
            ),
            'carried_forward': forms.NumberInput(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'step': '0.5',
                    'min': '0'
                }
            ),
            'additional': forms.NumberInput(
                attrs={
                    'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                    'step': '0.5',
                    'min': '0'
                }
            )
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Filter active users and leave types
        self.fields['user'].queryset = User.objects.filter(is_active=True).order_by('first_name', 'last_name')
        self.fields['leave_type'].queryset = LeaveType.objects.filter(is_active=True).order_by('name')

        # Set empty labels
        self.fields['user'].empty_label = "Select User"
        self.fields['leave_type'].empty_label = "Select Leave Type"

        # Set default year
        if not self.instance.pk:
            self.fields['year'].initial = timezone.now().year

        # Set help text
        self.fields['allocated'].help_text = "Total days allocated for the year"
        self.fields['used'].help_text = "Days already used"
        self.fields['carried_forward'].help_text = "Days carried forward from previous year"
        self.fields['additional'].help_text = "Additional days (comp-off, special allocation, etc.)"

    def clean(self):
        cleaned_data = super().clean()
        user = cleaned_data.get('user')
        leave_type = cleaned_data.get('leave_type')
        year = cleaned_data.get('year')
        used = cleaned_data.get('used', 0)
        allocated = cleaned_data.get('allocated', 0)
        carried_forward = cleaned_data.get('carried_forward', 0)
        additional = cleaned_data.get('additional', 0)

        if user and leave_type and year:
            # Check for duplicate balance record
            existing = UserLeaveBalance.objects.filter(
                user=user,
                leave_type=leave_type,
                year=year
            )

            if self.instance and self.instance.pk:
                existing = existing.exclude(pk=self.instance.pk)

            if existing.exists():
                raise ValidationError(f"Balance record already exists for {user.get_full_name()} - {leave_type.name} - {year}")

        # Validate used days don't exceed total available
        total_available = allocated + carried_forward + additional
        if used > total_available:
            raise ValidationError(f"Used days ({used}) cannot exceed total available days ({total_available})")

        return cleaned_data


class LeaveCarryForwardForm(forms.Form):
    """
    Form for processing year-end carry forward
    """
    from_year = forms.IntegerField(
        initial=timezone.now().year - 1,
        widget=forms.NumberInput(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-lime-500 focus:ring-lime-500 sm:text-sm'
            }
        ),
        help_text="Year to carry forward from"
    )

    to_year = forms.IntegerField(
        initial=timezone.now().year,
        widget=forms.NumberInput(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-lime-500 focus:ring-lime-500 sm:text-sm'
            }
        ),
        help_text="Year to carry forward to"
    )

    target_groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.all(),
        widget=forms.CheckboxSelectMultiple(
            attrs={
                'class': 'h-4 w-4 text-lime-600 focus:ring-lime-500 border-gray-300 rounded'
            }
        ),
        help_text="Select groups for carry forward processing"
    )

    leave_types = forms.ModelMultipleChoiceField(
        queryset=LeaveType.objects.filter(is_active=True),
        widget=forms.CheckboxSelectMultiple(
            attrs={
                'class': 'h-4 w-4 text-lime-600 focus:ring-lime-500 border-gray-300 rounded'
            }
        ),
        help_text="Select leave types to process"
    )

    dry_run = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(
            attrs={
                'class': 'h-4 w-4 text-amber-600 focus:ring-amber-500 border-gray-300 rounded'
            }
        ),
        help_text="Preview changes without applying them"
    )

    def clean(self):
        cleaned_data = super().clean()
        from_year = cleaned_data.get('from_year')
        to_year = cleaned_data.get('to_year')

        if from_year and to_year:
            if to_year <= from_year:
                raise ValidationError("'To year' must be greater than 'From year'")

            if to_year - from_year != 1:
                raise ValidationError("Can only carry forward to the immediate next year")

        return cleaned_data


class LeaveEncashmentForm(forms.Form):
    """
    Form for processing leave encashment
    """
    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring-amber-500 sm:text-sm'
            }
        ),
        empty_label="Select User"
    )

    leave_type = forms.ModelChoiceField(
        queryset=LeaveType.objects.filter(is_active=True, is_paid=True),
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring-amber-500 sm:text-sm'
            }
        ),
        empty_label="Select Leave Type"
    )

    year = forms.IntegerField(
        initial=timezone.now().year,
        widget=forms.NumberInput(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring-amber-500 sm:text-sm'
            }
        )
    )

    days_to_encash = forms.DecimalField(
        max_digits=5,
        decimal_places=1,
        min_value=0.5,
        widget=forms.NumberInput(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring-amber-500 sm:text-sm',
                'step': '0.5'
            }
        ),
        help_text="Number of days to encash"
    )

    reason = forms.CharField(
        widget=forms.Textarea(
            attrs={
                'rows': 3,
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring-amber-500 sm:text-sm',
                'placeholder': 'Reason for encashment...'
            }
        )
    )

    def clean(self):
        cleaned_data = super().clean()
        user = cleaned_data.get('user')
        leave_type = cleaned_data.get('leave_type')
        year = cleaned_data.get('year')
        days_to_encash = cleaned_data.get('days_to_encash')

        if all([user, leave_type, year, days_to_encash]):
            try:
                balance = UserLeaveBalance.objects.get(
                    user=user,
                    leave_type=leave_type,
                    year=year
                )

                if days_to_encash > balance.available:
                    raise ValidationError(f"Cannot encash {days_to_encash} days. Available balance: {balance.available}")

            except UserLeaveBalance.DoesNotExist:
                raise ValidationError("No leave balance found for the selected user, leave type, and year")

        return cleaned_data
