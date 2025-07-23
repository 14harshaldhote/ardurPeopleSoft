"""
Filter and Reporting Forms for Leave Management
"""
from django import forms
from django.contrib.auth.models import User, Group
from django.utils import timezone
from datetime import datetime, timedelta, date
from calendar import monthrange

from trueAlign.models import LeaveType, LeaveRequest


class LeaveFilterForm(forms.Form):
    """
    General purpose leave filtering form for dashboards and lists
    """
    STATUS_CHOICES = [
        ('', 'All Statuses'),
        ('Pending', 'Pending'),
        ('Approved', 'Approved'),
        ('Rejected', 'Rejected'),
        ('Cancelled', 'Cancelled')
    ]

    PERIOD_CHOICES = [
        ('', 'Select Period'),
        ('today', 'Today'),
        ('this_week', 'This Week'),
        ('this_month', 'This Month'),
        ('this_quarter', 'This Quarter'),
        ('this_year', 'This Year'),
        ('last_30_days', 'Last 30 Days'),
        ('last_90_days', 'Last 90 Days'),
        ('custom', 'Custom Date Range')
    ]

    # Status filter
    status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        required=False,
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm'
            }
        )
    )

    # Leave type filter
    leave_type = forms.ModelChoiceField(
        queryset=LeaveType.objects.filter(is_active=True),
        required=False,
        empty_label="All Leave Types",
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm'
            }
        )
    )

    # User filter (for managers/HR viewing team leaves)
    user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        empty_label="All Users",
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm'
            }
        )
    )

    # Quick period selection
    period = forms.ChoiceField(
        choices=PERIOD_CHOICES,
        required=False,
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm',
                'onchange': 'toggleCustomDateRange(this.value)'
            }
        )
    )

    # Custom date range
    start_date = forms.DateField(
        required=False,
        widget=forms.DateInput(
            attrs={
                'type': 'date',
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm'
            }
        )
    )

    end_date = forms.DateField(
        required=False,
        widget=forms.DateInput(
            attrs={
                'type': 'date',
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm'
            }
        )
    )

    # Search by reason/comments
    search = forms.CharField(
        required=False,
        widget=forms.TextInput(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm',
                'placeholder': 'Search by reason or comments...'
            }
        )
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        show_user_filter = kwargs.pop('show_user_filter', True)
        super().__init__(*args, **kwargs)

        # Hide user filter if not needed (e.g., for employee's own view)
        if not show_user_filter:
            del self.fields['user']
        elif user:
            # For managers, show only their team members
            from ..utils import is_manager, is_hr, is_admin
            if is_manager(user) and not (is_hr(user) or is_admin(user)):
                # In a real system, you'd filter by reporting hierarchy
                # For now, show all employees
                employee_group = Group.objects.filter(name='Employee').first()
                if employee_group:
                    self.fields['user'].queryset = User.objects.filter(
                        groups=employee_group,
                        is_active=True
                    ).order_by('first_name', 'last_name')

    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')
        period = cleaned_data.get('period')

        # Validate custom date range
        if period == 'custom':
            if not start_date or not end_date:
                raise forms.ValidationError("Start date and end date are required for custom period")
            if start_date > end_date:
                raise forms.ValidationError("Start date must be before end date")

        return cleaned_data

    def get_date_range(self):
        """Get the actual date range based on period selection"""
        period = self.cleaned_data.get('period')
        today = timezone.now().date()

        if period == 'today':
            return today, today
        elif period == 'this_week':
            start = today - timedelta(days=today.weekday())
            end = start + timedelta(days=6)
            return start, end
        elif period == 'this_month':
            start = today.replace(day=1)
            end = today.replace(day=monthrange(today.year, today.month)[1])
            return start, end
        elif period == 'this_quarter':
            quarter = (today.month - 1) // 3 + 1
            start = today.replace(month=(quarter - 1) * 3 + 1, day=1)
            end_month = quarter * 3
            end = today.replace(month=end_month, day=monthrange(today.year, end_month)[1])
            return start, end
        elif period == 'this_year':
            start = today.replace(month=1, day=1)
            end = today.replace(month=12, day=31)
            return start, end
        elif period == 'last_30_days':
            end = today
            start = today - timedelta(days=30)
            return start, end
        elif period == 'last_90_days':
            end = today
            start = today - timedelta(days=90)
            return start, end
        elif period == 'custom':
            return self.cleaned_data.get('start_date'), self.cleaned_data.get('end_date')

        return None, None


class LeaveReportForm(forms.Form):
    """
    Advanced form for generating leave reports
    """
    REPORT_TYPES = [
        ('summary', 'Leave Summary Report'),
        ('detailed', 'Detailed Leave Report'),
        ('balance', 'Leave Balance Report'),
        ('utilization', 'Leave Utilization Report'),
        ('trends', 'Leave Trends Report'),
        ('comp_off', 'Comp-off Report')
    ]

    FORMAT_CHOICES = [
        ('html', 'View Online'),
        ('pdf', 'Download PDF'),
        ('excel', 'Download Excel'),
        ('csv', 'Download CSV')
    ]

    # Report type
    report_type = forms.ChoiceField(
        choices=REPORT_TYPES,
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm'
            }
        )
    )

    # Date range
    start_date = forms.DateField(
        initial=lambda: (timezone.now().date().replace(day=1)),
        widget=forms.DateInput(
            attrs={
                'type': 'date',
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm'
            }
        ),
        help_text="Report start date"
    )

    end_date = forms.DateField(
        initial=timezone.now().date,
        widget=forms.DateInput(
            attrs={
                'type': 'date',
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm'
            }
        ),
        help_text="Report end date"
    )

    # Filters
    groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.all(),
        required=False,
        widget=forms.CheckboxSelectMultiple(
            attrs={
                'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
            }
        ),
        help_text="Filter by user groups/roles"
    )

    users = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        widget=forms.SelectMultiple(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm',
                'size': '6'
            }
        ),
        help_text="Select specific users (optional)"
    )

    leave_types = forms.ModelMultipleChoiceField(
        queryset=LeaveType.objects.filter(is_active=True),
        required=False,
        widget=forms.CheckboxSelectMultiple(
            attrs={
                'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
            }
        ),
        help_text="Filter by leave types"
    )

    # Report format
    format = forms.ChoiceField(
        choices=FORMAT_CHOICES,
        initial='html',
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-emerald-500 focus:ring-emerald-500 sm:text-sm'
            }
        )
    )

    # Additional options
    include_cancelled = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(
            attrs={
                'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
            }
        ),
        help_text="Include cancelled leave requests"
    )

    include_rejected = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(
            attrs={
                'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
            }
        ),
        help_text="Include rejected leave requests"
    )

    group_by_month = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(
            attrs={
                'class': 'h-4 w-4 text-emerald-600 focus:ring-emerald-500 border-gray-300 rounded'
            }
        ),
        help_text="Group results by month"
    )

    def clean(self):
        cleaned_data = super().clean()
        start_date = cleaned_data.get('start_date')
        end_date = cleaned_data.get('end_date')

        if start_date and end_date:
            if start_date > end_date:
                raise forms.ValidationError("Start date must be before end date")

            # Limit report range to prevent performance issues
            if (end_date - start_date).days > 365:
                raise forms.ValidationError("Report date range cannot exceed 365 days")

        return cleaned_data


class TeamLeaveFilterForm(forms.Form):
    """
    Specialized form for team leave filtering (for managers)
    """
    VIEW_CHOICES = [
        ('calendar', 'Calendar View'),
        ('list', 'List View'),
        ('timeline', 'Timeline View')
    ]

    # View type
    view_type = forms.ChoiceField(
        choices=VIEW_CHOICES,
        initial='calendar',
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring-amber-500 sm:text-sm'
            }
        )
    )

    # Month/Year selection for calendar view
    month = forms.ChoiceField(
        choices=[(i, date(2000, i, 1).strftime('%B')) for i in range(1, 13)],
        initial=timezone.now().month,
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring-amber-500 sm:text-sm'
            }
        )
    )

    year = forms.IntegerField(
        initial=timezone.now().year,
        widget=forms.NumberInput(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring-amber-500 sm:text-sm',
                'min': timezone.now().year - 2,
                'max': timezone.now().year + 2
            }
        )
    )

    # Team member filter
    team_members = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        widget=forms.CheckboxSelectMultiple(
            attrs={
                'class': 'h-4 w-4 text-amber-600 focus:ring-amber-500 border-gray-300 rounded'
            }
        ),
        help_text="Select team members to view"
    )

    # Leave type filter
    leave_types = forms.ModelMultipleChoiceField(
        queryset=LeaveType.objects.filter(is_active=True),
        required=False,
        widget=forms.CheckboxSelectMultiple(
            attrs={
                'class': 'h-4 w-4 text-amber-600 focus:ring-amber-500 border-gray-300 rounded'
            }
        ),
        help_text="Filter by leave types"
    )

    # Show only upcoming leaves
    upcoming_only = forms.BooleanField(
        required=False,
        initial=False,
        widget=forms.CheckboxInput(
            attrs={
                'class': 'h-4 w-4 text-amber-600 focus:ring-amber-500 border-gray-300 rounded'
            }
        ),
        help_text="Show only upcoming leaves"
    )

    def __init__(self, *args, **kwargs):
        manager = kwargs.pop('manager', None)
        super().__init__(*args, **kwargs)

        if manager:
            # Filter team members based on manager
            # In a real system, you'd have proper reporting hierarchy
            # For now, show all employees
            try:
                employee_group = Group.objects.get(name='Employee')
                self.fields['team_members'].queryset = User.objects.filter(
                    groups=employee_group,
                    is_active=True
                ).order_by('first_name', 'last_name')
            except Group.DoesNotExist:
                pass


class AdvancedLeaveFilterForm(forms.Form):
    """
    Advanced filtering form with multiple criteria
    """
    # Basic filters
    status = forms.MultipleChoiceField(
        choices=LeaveRequest.STATUS_CHOICES,
        required=False,
        widget=forms.CheckboxSelectMultiple(
            attrs={
                'class': 'h-4 w-4 text-sky-600 focus:ring-sky-500 border-gray-300 rounded'
            }
        )
    )

    leave_types = forms.ModelMultipleChoiceField(
        queryset=LeaveType.objects.filter(is_active=True),
        required=False,
        widget=forms.CheckboxSelectMultiple(
            attrs={
                'class': 'h-4 w-4 text-sky-600 focus:ring-sky-500 border-gray-300 rounded'
            }
        )
    )

    # Date filters
    applied_after = forms.DateField(
        required=False,
        label="Applied After",
        widget=forms.DateInput(
            attrs={
                'type': 'date',
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm'
            }
        )
    )

    applied_before = forms.DateField(
        required=False,
        label="Applied Before",
        widget=forms.DateInput(
            attrs={
                'type': 'date',
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm'
            }
        )
    )

    leave_start_after = forms.DateField(
        required=False,
        label="Leave Starts After",
        widget=forms.DateInput(
            attrs={
                'type': 'date',
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm'
            }
        )
    )

    leave_start_before = forms.DateField(
        required=False,
        label="Leave Starts Before",
        widget=forms.DateInput(
            attrs={
                'type': 'date',
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm'
            }
        )
    )

    # Duration filters
    min_days = forms.DecimalField(
        required=False,
        min_value=0,
        max_digits=5,
        decimal_places=1,
        widget=forms.NumberInput(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm',
                'step': '0.5'
            }
        ),
        help_text="Minimum leave days"
    )

    max_days = forms.DecimalField(
        required=False,
        min_value=0,
        max_digits=5,
        decimal_places=1,
        widget=forms.NumberInput(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm',
                'step': '0.5'
            }
        ),
        help_text="Maximum leave days"
    )

    # Special filters
    half_day_only = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                'class': 'h-4 w-4 text-sky-600 focus:ring-sky-500 border-gray-300 rounded'
            }
        ),
        help_text="Show only half-day leaves"
    )

    retroactive_only = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                'class': 'h-4 w-4 text-sky-600 focus:ring-sky-500 border-gray-300 rounded'
            }
        ),
        help_text="Show only retroactive applications"
    )

    with_documentation = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(
            attrs={
                'class': 'h-4 w-4 text-sky-600 focus:ring-sky-500 border-gray-300 rounded'
            }
        ),
        help_text="Show only requests with documentation"
    )

    # Approver filter
    approvers = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        widget=forms.SelectMultiple(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-sky-500 focus:ring-sky-500 sm:text-sm',
                'size': '4'
            }
        )
    )

    def clean(self):
        cleaned_data = super().clean()

        # Validate date ranges
        applied_after = cleaned_data.get('applied_after')
        applied_before = cleaned_data.get('applied_before')
        if applied_after and applied_before and applied_after > applied_before:
            raise forms.ValidationError("'Applied after' date must be before 'Applied before' date")

        leave_start_after = cleaned_data.get('leave_start_after')
        leave_start_before = cleaned_data.get('leave_start_before')
        if leave_start_after and leave_start_before and leave_start_after > leave_start_before:
            raise forms.ValidationError("'Leave starts after' date must be before 'Leave starts before' date")

        # Validate day ranges
        min_days = cleaned_data.get('min_days')
        max_days = cleaned_data.get('max_days')
        if min_days and max_days and min_days > max_days:
            raise forms.ValidationError("Minimum days must be less than maximum days")

        return cleaned_data


class QuickStatsForm(forms.Form):
    """
    Quick form for dashboard statistics
    """
    STATS_PERIOD = [
        ('today', 'Today'),
        ('this_week', 'This Week'),
        ('this_month', 'This Month'),
        ('this_year', 'This Year')
    ]

    period = forms.ChoiceField(
        choices=STATS_PERIOD,
        initial='this_month',
        widget=forms.Select(
            attrs={
                'class': 'block w-full rounded-md border-gray-300 shadow-sm focus:border-rose-500 focus:ring-rose-500 sm:text-sm'
            }
        )
    )

    include_team = forms.BooleanField(
        required=False,
        initial=True,
        widget=forms.CheckboxInput(
            attrs={
                'class': 'h-4 w-4 text-rose-600 focus:ring-rose-500 border-gray-300 rounded'
            }
        ),
        help_text="Include team statistics (for managers)"
    )
