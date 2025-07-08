"""
Support Forms Module
Django forms for the support ticket system
"""

from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db import models
from trueAlign.models import Support, TicketComment, TicketAttachment
from .widgets import MultipleFileField, MultipleFileInput


class TicketCreateForm(forms.Form):  # Changed from ModelForm to Form
    """Form for creating new support tickets"""

    # Basic ticket fields
    subject = forms.CharField(
        max_length=200,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Brief description of the issue',
            'maxlength': 200
        })
    )

    description = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 6,
            'placeholder': 'Detailed description of the issue, steps to reproduce, etc.'
        })
    )

    priority = forms.ChoiceField(
        choices=Support.Priority.choices,
        initial=Support.Priority.MEDIUM,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    issue_type = forms.ChoiceField(
        choices=Support.IssueType.choices,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    assigned_group = forms.ChoiceField(
        choices=[('', 'Auto-assign based on issue type')] + list(Support.AssignedGroup.choices),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    department = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Your department'
        })
    )

    location = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Office location or building'
        })
    )

    asset_id = forms.CharField(
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Hardware/Software asset ID (if applicable)'
        })
    )

    # Multiple file upload field - FIXED
    attachments = MultipleFileField(
        required=False,
        help_text='You can upload multiple files. Maximum 10MB per file.',
        widget=MultipleFileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.doc,.docx,.txt,.jpg,.jpeg,.png,.gif,.zip,.csv,.xlsx'
        })
    )

    def clean_subject(self):
        subject = self.cleaned_data.get('subject')
        if subject:
            subject = subject.strip()
            if len(subject) < 5:
                raise ValidationError('Subject must be at least 5 characters long.')
        return subject

    def clean_description(self):
        description = self.cleaned_data.get('description')
        if description:
            description = description.strip()
            if len(description) < 10:
                raise ValidationError('Description must be at least 10 characters long.')
        return description

    def clean_attachments(self):
        """Additional validation for attachments"""
        attachments = self.cleaned_data.get('attachments', [])
        if attachments:
            # Limit number of files
            if len(attachments) > 10:
                raise ValidationError('You can upload maximum 10 files at once.')

            # Calculate total size
            total_size = sum(getattr(f, 'size', 0) for f in attachments)
            max_total_size = 50 * 1024 * 1024  # 50MB total
            if total_size > max_total_size:
                raise ValidationError('Total file size cannot exceed 50MB.')

        return attachments


class TicketUpdateForm(forms.ModelForm):
    """Form for updating existing support tickets"""

    class Meta:
        model = Support
        fields = [
            'subject', 'description', 'priority', 'issue_type',
            'assigned_group', 'department', 'location', 'asset_id',
            'resolution_summary'
        ]
        widgets = {
            'subject': forms.TextInput(attrs={'class': 'form-control'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 6}),
            'priority': forms.Select(attrs={'class': 'form-control'}),
            'issue_type': forms.Select(attrs={'class': 'form-control'}),
            'assigned_group': forms.Select(attrs={'class': 'form-control'}),
            'department': forms.TextInput(attrs={'class': 'form-control'}),
            'location': forms.TextInput(attrs={'class': 'form-control'}),
            'asset_id': forms.TextInput(attrs={'class': 'form-control'}),
            'resolution_summary': forms.Textarea(attrs={'class': 'form-control', 'rows': 4}),
        }

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Only allow certain fields to be edited by non-staff users
        if user and not (user.is_staff or user.groups.filter(name__in=['Admin', 'HR']).exists()):
            # Regular users can only edit description and add resolution summary
            allowed_fields = ['description', 'resolution_summary']
            for field_name in list(self.fields.keys()):
                if field_name not in allowed_fields:
                    del self.fields[field_name]

    def _get_user_roles(self, user):
        """Get user roles for permission checking"""
        roles = []
        if user.is_staff:
            roles.append('Staff')
        if user.groups.filter(name='Admin').exists():
            roles.append('Admin')
        if user.groups.filter(name='HR').exists():
            roles.append('HR')
        return roles


class CommentForm(forms.Form):  # Changed from ModelForm to Form
    """Form for adding comments to tickets"""

    content = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 4,
            'placeholder': 'Add your comment here...',
            'id': 'comment_content',
            'name': 'comment_content'
        })
    )

    is_internal = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input',
            'id': 'is_internal',
            'name': 'is_internal'
        })
    )

    # Fixed multiple file upload for comments
    comment_attachments = MultipleFileField(
        required=False,
        help_text='Attach files to your comment (optional)',
        widget=MultipleFileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.doc,.docx,.txt,.jpg,.jpeg,.png,.gif,.zip,.csv,.xlsx',
            'id': 'comment-attachments'
        })
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Only staff can add internal comments
        if self.user and not (self.user.is_staff or self.user.groups.filter(name__in=['Admin', 'HR']).exists()):
            self.fields['is_internal'].widget = forms.HiddenInput()

    def clean_content(self):
        content = self.cleaned_data.get('content')
        if content:
            content = content.strip()
            if len(content) < 3:
                raise ValidationError('Comment must be at least 3 characters long.')
        return content


class StatusUpdateForm(forms.Form):
    """Form for updating ticket status"""

    status = forms.ChoiceField(
        choices=Support.Status.choices,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    comment = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Optional comment about the status change'
        }),
        required=False
    )

    def clean(self):
        cleaned_data = super().clean()
        status = cleaned_data.get('status')

        # Some statuses might require comments
        if status in ['Resolved', 'Closed', 'On Hold']:
            comment = cleaned_data.get('comment')
            if not comment or len(comment.strip()) < 10:
                raise ValidationError(
                    f'A detailed comment is required when changing status to "{status}".'
                )

        return cleaned_data


class AssignmentForm(forms.Form):
    """Form for assigning tickets to users or groups"""

    assigned_to_user = forms.ModelChoiceField(
        queryset=User.objects.none(),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'}),
        empty_label="Select a user..."
    )

    assigned_group = forms.ChoiceField(
        choices=[('', 'No Group')] + list(Support.AssignedGroup.choices),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    assignment_comment = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 2,
            'placeholder': 'Optional comment about the assignment'
        }),
        required=False
    )

    def __init__(self, *args, **kwargs):
        user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Filter users based on role
        if user:
            roles = self._get_user_roles(user)
            if 'Admin' in roles:
                # Admins can assign to any staff member
                self.fields['assigned_to_user'].queryset = User.objects.filter(is_staff=True)
            elif 'HR' in roles:
                # HR can assign to HR group members
                self.fields['assigned_to_user'].queryset = User.objects.filter(
                    groups__name='HR'
                )
            else:
                # Regular users can't assign
                self.fields['assigned_to_user'].queryset = User.objects.none()

    def _get_user_roles(self, user):
        """Get user roles for permission checking"""
        roles = []
        if user.is_staff:
            roles.append('Staff')
        if user.groups.filter(name='Admin').exists():
            roles.append('Admin')
        if user.groups.filter(name='HR').exists():
            roles.append('HR')
        return roles


class TicketSearchForm(forms.Form):
    """Form for searching tickets"""

    search_query = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search tickets...'
        })
    )

    status = forms.MultipleChoiceField(
        choices=Support.Status.choices,
        required=False,
        widget=forms.CheckboxSelectMultiple()
    )

    priority = forms.MultipleChoiceField(
        choices=Support.Priority.choices,
        required=False,
        widget=forms.CheckboxSelectMultiple()
    )

    issue_type = forms.MultipleChoiceField(
        choices=Support.IssueType.choices,
        required=False,
        widget=forms.CheckboxSelectMultiple()
    )

    assigned_group = forms.MultipleChoiceField(
        choices=Support.AssignedGroup.choices,
        required=False,
        widget=forms.CheckboxSelectMultiple()
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
        cleaned_data = super().clean()
        date_from = cleaned_data.get('date_from')
        date_to = cleaned_data.get('date_to')

        if date_from and date_to and date_from > date_to:
            raise ValidationError('Start date must be before end date.')

        return cleaned_data


class BulkActionForm(forms.Form):
    """Form for bulk actions on tickets"""

    action = forms.ChoiceField(
        choices=[
            ('assign', 'Assign to User/Group'),
            ('change_status', 'Change Status'),
            ('change_priority', 'Change Priority'),
            ('delete', 'Delete'),
        ],
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    # Assignment fields
    assigned_to_user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_staff=True),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    assigned_group = forms.ChoiceField(
        choices=[('', 'No Group')] + list(Support.AssignedGroup.choices),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    # Status change field
    new_status = forms.ChoiceField(
        choices=Support.Status.choices,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    # Priority change field
    new_priority = forms.ChoiceField(
        choices=Support.Priority.choices,
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    # Comment field for bulk actions
    comment = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Optional comment for this bulk action'
        }),
        required=False
    )

    def clean(self):
        cleaned_data = super().clean()
        action = cleaned_data.get('action')

        # Validate based on action type
        if action == 'assign':
            if not cleaned_data.get('assigned_to_user') and not cleaned_data.get('assigned_group'):
                raise ValidationError('Please select either a user or group for assignment.')
        elif action == 'change_status':
            if not cleaned_data.get('new_status'):
                raise ValidationError('Please select a new status.')
        elif action == 'change_priority':
            if not cleaned_data.get('new_priority'):
                raise ValidationError('Please select a new priority.')

        return cleaned_data


class CCUsersForm(forms.Form):
    """Form for managing CC users on tickets"""

    cc_users = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        widget=forms.CheckboxSelectMultiple()
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Filter to only show relevant users
        self.fields['cc_users'].queryset = User.objects.filter(
            is_active=True
        ).order_by('first_name', 'last_name', 'username')


class DueDateForm(forms.Form):
    """Form for setting due dates on tickets"""

    due_date = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'class': 'form-control',
            'type': 'datetime-local'
        })
    )

    def clean_due_date(self):
        due_date = self.cleaned_data.get('due_date')
        if due_date and due_date < timezone.now():
            raise ValidationError('Due date cannot be in the past.')
        return due_date


class PriorityUpdateForm(forms.Form):
    """Form for updating ticket priority"""

    priority = forms.ChoiceField(
        choices=Support.Priority.choices,
        widget=forms.Select(attrs={'class': 'form-control'})
    )


class TicketFilterForm(forms.Form):
    """Form for filtering tickets in list view"""

    status = forms.ChoiceField(
        choices=[('', 'All Status')] + list(Support.Status.choices),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    priority = forms.ChoiceField(
        choices=[('', 'All Priorities')] + list(Support.Priority.choices),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    issue_type = forms.ChoiceField(
        choices=[('', 'All Types')] + list(Support.IssueType.choices),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    assigned_group = forms.ChoiceField(
        choices=[('', 'All Groups')] + list(Support.AssignedGroup.choices),
        required=False,
        widget=forms.Select(attrs={'class': 'form-control'})
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Add any additional initialization if needed


class AttachmentForm(forms.Form):
    """Form for uploading attachments - FIXED"""

    files = MultipleFileField(
        required=True,
        help_text='Select files to upload (max 10 files, 10MB each)',
        widget=MultipleFileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.doc,.docx,.txt,.jpg,.jpeg,.png,.gif,.zip,.csv,.xlsx'
        })
    )

    description = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 2,
            'placeholder': 'Optional description for the attachments'
        }),
        required=False
    )

    def clean_files(self):
        """Additional validation for attachment files"""
        files = self.cleaned_data.get('files', [])
        if files:
            # Limit number of files
            if len(files) > 10:
                raise ValidationError('You can upload maximum 10 files at once.')

            # Calculate total size
            total_size = sum(getattr(f, 'size', 0) for f in files)
            max_total_size = 50 * 1024 * 1024  # 50MB total
            if total_size > max_total_size:
                raise ValidationError('Total file size cannot exceed 50MB.')

        return files
