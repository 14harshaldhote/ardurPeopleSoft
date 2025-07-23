from django import forms
from django.contrib.auth.models import User, Group
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm
from django.core.exceptions import ValidationError
from django.utils import timezone

from trueAlign.models import UserDetails, OfficeLocation

class UserDetailsCreateForm(forms.ModelForm):
    """Form for creating a new user with UserDetails"""
    email = forms.EmailField(required=True)
    first_name = forms.CharField(max_length=150, required=True)
    last_name = forms.CharField(max_length=150, required=True)
    password = forms.CharField(widget=forms.PasswordInput(), required=True)
    confirm_password = forms.CharField(widget=forms.PasswordInput(), required=True)
    group = forms.ModelChoiceField(
        queryset=Group.objects.all(),
        required=True,
        empty_label="Select a role/group",
        help_text="Select the user's role/group",
        widget=forms.Select(attrs={
            'class': 'w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring focus:ring-amber-200 focus:ring-opacity-50'
        })
    )

    class Meta:
        model = UserDetails
        fields = [
            'dob', 'blood_group', 'gender', 'marital_status', 'contact_number_primary',
            'personal_email', 'company_email', 'current_address_line1', 'current_city',
            'current_state', 'current_postal_code', 'current_country',
            'permanent_address_line1', 'permanent_city', 'permanent_state',
            'permanent_postal_code', 'permanent_country', 'is_current_same_as_permanent',
            'emergency_contact_name', 'emergency_contact_number', 'emergency_contact_relationship',
            'employee_type', 'reporting_manager', 'hire_date', 'start_date',
            'probation_end_date', 'notice_period_days', 'job_description', 'office_location',
            'employment_status', 'role'
        ]
        widgets = {
            'dob': forms.DateInput(attrs={
                'type': 'date',
                'class': 'w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring focus:ring-amber-200 focus:ring-opacity-50'
            }),
            'hire_date': forms.DateInput(attrs={
                'type': 'date',
                'class': 'w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring focus:ring-amber-200 focus:ring-opacity-50'
            }),
            'start_date': forms.DateInput(attrs={
                'type': 'date',
                'class': 'w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring focus:ring-amber-200 focus:ring-opacity-50'
            }),
            'probation_end_date': forms.DateInput(attrs={
                'type': 'date',
                'class': 'w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring focus:ring-amber-200 focus:ring-opacity-50'
            }),
            'job_description': forms.Textarea(attrs={
                'rows': 3,
                'class': 'w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring focus:ring-amber-200 focus:ring-opacity-50'
            }),
            'office_location': forms.Select(attrs={
                'class': 'w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring focus:ring-amber-200 focus:ring-opacity-50'
            }),
            'employment_status': forms.Select(attrs={
                'class': 'w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring focus:ring-amber-200 focus:ring-opacity-50'
            }),
            'employee_type': forms.Select(attrs={
                'class': 'w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring focus:ring-amber-200 focus:ring-opacity-50'
            }),
            'role': forms.Select(attrs={
                'class': 'w-full rounded-xl border-gray-300 shadow-sm focus:ring-sky-500 focus:border-sky-500'
            }),
        }

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        confirm_password = cleaned_data.get('confirm_password')
        email = cleaned_data.get('email')
        company_email = cleaned_data.get('company_email')
        personal_email = cleaned_data.get('personal_email')

        # Check if passwords match
        if password and confirm_password and password != confirm_password:
            self.add_error('confirm_password', 'Passwords do not match')

        # Check if email already exists
        if email and User.objects.filter(email=email).exists():
            self.add_error('email', 'Email already exists')

        # Check company email uniqueness if provided
        if company_email and UserDetails.objects.filter(company_email=company_email).exists():
            self.add_error('company_email', 'Company email already exists')

        # Check personal email uniqueness if provided
        if personal_email and UserDetails.objects.filter(personal_email=personal_email).exists():
            self.add_error('personal_email', 'Personal email already exists')

        # Validate date fields
        current_date = timezone.now().date()
        hire_date = cleaned_data.get('hire_date')
        start_date = cleaned_data.get('start_date')
        probation_end_date = cleaned_data.get('probation_end_date')

        if hire_date and start_date and hire_date > start_date:
            self.add_error('start_date', 'Start date cannot be earlier than hire date')

        if start_date and probation_end_date and start_date > probation_end_date:
            self.add_error('probation_end_date', 'Probation end date cannot be earlier than start date')

        return cleaned_data


class UserDetailsUpdateForm(forms.ModelForm):
    """Form for updating an existing user's details"""
    first_name = forms.CharField(max_length=150, required=True)
    last_name = forms.CharField(max_length=150, required=True)
    email = forms.EmailField(required=True)

    class Meta:
        model = UserDetails
        fields = [
            'dob', 'blood_group', 'gender', 'marital_status', 'contact_number_primary',
            'personal_email', 'company_email', 'current_address_line1', 'current_city',
            'current_state', 'current_postal_code', 'current_country',
            'permanent_address_line1', 'permanent_city', 'permanent_state',
            'permanent_postal_code', 'permanent_country', 'is_current_same_as_permanent',
            'emergency_contact_name', 'emergency_contact_number', 'emergency_contact_relationship',
            'employee_type', 'reporting_manager', 'job_description', 'office_location',
            'employment_status', 'role'
        ]
        widgets = {
            'dob': forms.DateInput(attrs={'type': 'date'}),
            'job_description': forms.Textarea(attrs={'rows': 3}),
            'role': forms.Select(attrs={
                'class': 'w-full rounded-xl border-gray-300 shadow-sm focus:ring-sky-500 focus:border-sky-500'
            }),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        if user:
            self.fields['first_name'].initial = user.first_name
            self.fields['last_name'].initial = user.last_name
            self.fields['email'].initial = user.email

    def clean(self):
        cleaned_data = super().clean()
        company_email = cleaned_data.get('company_email')
        personal_email = cleaned_data.get('personal_email')
        email = cleaned_data.get('email')

        # Check company email uniqueness if provided
        if company_email:
            existing = UserDetails.objects.filter(company_email=company_email).exclude(pk=self.instance.pk)
            if existing.exists():
                self.add_error('company_email', 'Company email already exists')

        # Check personal email uniqueness if provided
        if personal_email:
            existing = UserDetails.objects.filter(personal_email=personal_email).exclude(pk=self.instance.pk)
            if existing.exists():
                self.add_error('personal_email', 'Personal email already exists')

        # Check email uniqueness
        if email:
            existing = User.objects.filter(email=email).exclude(pk=self.instance.user.pk)
            if existing.exists():
                self.add_error('email', 'Email already exists')

        return cleaned_data


class PasswordResetForm(forms.Form):
    """Form for resetting a user's password"""
    new_password = forms.CharField(widget=forms.PasswordInput(), required=True)
    confirm_password = forms.CharField(widget=forms.PasswordInput(), required=True)

    def clean(self):
        cleaned_data = super().clean()
        new_password = cleaned_data.get('new_password')
        confirm_password = cleaned_data.get('confirm_password')

        if new_password and confirm_password and new_password != confirm_password:
            self.add_error('confirm_password', 'Passwords do not match')

        # Add password complexity validation if needed
        if new_password and len(new_password) < 8:
            self.add_error('new_password', 'Password must be at least 8 characters long')

        return cleaned_data


class StatusChangeForm(forms.Form):
    """Form for changing a user's employment status"""
    status = forms.ChoiceField(choices=UserDetails.EMPLOYMENT_STATUS_CHOICES, required=True)
    exit_reason = forms.CharField(widget=forms.Textarea(attrs={'rows': 3}), required=False)
    rehire_eligibility = forms.BooleanField(required=False)

    def __init__(self, *args, **kwargs):
        current_status = kwargs.pop('current_status', None)
        super().__init__(*args, **kwargs)

        if current_status:
            self.fields['status'].initial = current_status


class UserFilterForm(forms.Form):
    """Form for filtering users in the list view"""
    status = forms.ChoiceField(
        choices=[('', 'All')] + list(UserDetails.EMPLOYMENT_STATUS_CHOICES),
        required=False
    )
    location = forms.ModelChoiceField(
        queryset=OfficeLocation.objects.filter(is_active=True),
        required=False,
        empty_label="All Locations"
    )
    employee_type = forms.ChoiceField(
        choices=[('', 'All')] + list(UserDetails.EMPLOYEE_TYPE_CHOICES),
        required=False
    )
    search = forms.CharField(required=False)


class CSVImportForm(forms.Form):
    """Form for importing users from a CSV file"""
    csv_file = forms.FileField(
        label='Select a CSV/XLSX file',
        help_text='File must be in CSV or XLSX format with proper headers',
        widget=forms.FileInput(attrs={
            'accept': '.csv,.xlsx,.xls',
            'class': 'w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring focus:ring-amber-200 focus:ring-opacity-50'
        })
    )
    group = forms.ModelChoiceField(
        queryset=Group.objects.all(),
        required=True,
        empty_label="Select default role/group for all users",
        help_text="This role will be assigned to all users in the uploaded file",
        widget=forms.Select(attrs={
            'class': 'w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring focus:ring-amber-200 focus:ring-opacity-50'
        })
    )
    office_location = forms.ModelChoiceField(
        queryset=OfficeLocation.objects.filter(is_active=True),
        required=True,
        empty_label="Select default office location",
        help_text="This location will be assigned to all users in the uploaded file",
        widget=forms.Select(attrs={
            'class': 'w-full rounded-md border-gray-300 shadow-sm focus:border-amber-500 focus:ring focus:ring-amber-200 focus:ring-opacity-50'
        })
    )
