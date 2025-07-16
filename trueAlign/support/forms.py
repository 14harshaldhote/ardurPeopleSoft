"""
Comprehensive Forms Module for Smart Ticketing System
Provides form classes for ticket creation, editing, and management operations
"""

from django import forms
from django.contrib.auth.models import User, Group
from django.core.exceptions import ValidationError
from django.utils import timezone
from django.db.models import Q
from trueAlign.models import Support, UserDetails, TicketComment, TicketAttachment
from .utils import TicketValidator, PermissionManager


class TicketCreationForm(forms.ModelForm):
    """
    Form for creating new tickets with intelligent field handling
    """

    # Additional fields not in the model
    cc_users = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'form-control select2',
            'multiple': True,
            'data-placeholder': 'Select users to CC...'
        }),
        help_text="Select users to be notified about this ticket"
    )

    attachments = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.doc,.docx,.xls,.xlsx,.txt,.png,.jpg,.jpeg,.gif,.zip'
        }),
        help_text="Upload supporting files (Max 10MB each)"
    )

    class Meta:
        model = Support
        fields = ['subject', 'description', 'issue_type', 'priority', 'department', 'location', 'asset_id']
        widgets = {
            'subject': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Brief description of the issue',
                'maxlength': 200
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5,
                'placeholder': 'Detailed description of the issue...',
                'maxlength': 5000
            }),
            'issue_type': forms.Select(attrs={
                'class': 'form-control',
                'onchange': 'updateIssueTypeGuidance(this.value)'
            }),
            'priority': forms.Select(attrs={
                'class': 'form-control',
                'onchange': 'updatePriorityGuidance(this.value)'
            }),
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
                'placeholder': 'Asset ID (if applicable)',
                'pattern': '[A-Z0-9-]+',
                'title': 'Use uppercase letters, numbers, and hyphens only'
            })
        }
        help_texts = {
            'subject': 'Provide a clear, concise summary of the issue',
            'description': 'Include all relevant details, error messages, and steps to reproduce',
            'issue_type': 'Select the category that best describes your issue',
            'priority': 'System will auto-calculate priority based on impact and urgency',
            'asset_id': 'Hardware/software asset identifier (if known)'
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Pre-fill user department if available
        if self.user:
            try:
                user_details = UserDetails.objects.get(user=self.user)
                self.fields['department'].initial = user_details.department
            except UserDetails.DoesNotExist:
                pass

        # Set default priority
        self.fields['priority'].initial = 'Medium'

    def clean_subject(self):
        subject = self.cleaned_data.get('subject')
        if len(subject) < 5:
            raise ValidationError("Subject must be at least 5 characters long")
        return subject

    def clean_description(self):
        description = self.cleaned_data.get('description')
        if len(description) < 10:
            raise ValidationError("Description must be at least 10 characters long")
        return description

    def clean_asset_id(self):
        asset_id = self.cleaned_data.get('asset_id')
        if asset_id and not asset_id.replace('-', '').isalnum():
            raise ValidationError("Asset ID can only contain letters, numbers, and hyphens")
        return asset_id

    def clean(self):
        cleaned_data = super().clean()

        # Use ticket validator for comprehensive validation
        validator = TicketValidator()
        validation_result = validator.validate_ticket_data(cleaned_data)

        if not validation_result['is_valid']:
            for error in validation_result['errors']:
                raise ValidationError(error)

        return cleaned_data


class TicketUpdateForm(forms.ModelForm):
    """
    Form for updating existing tickets with permission-based field access
    """

    class Meta:
        model = Support
        fields = ['subject', 'description', 'status', 'priority', 'assigned_to_user', 'assigned_group', 'resolution_summary']
        widgets = {
            'subject': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Brief description of the issue'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 5,
                'placeholder': 'Detailed description of the issue...'
            }),
            'status': forms.Select(attrs={
                'class': 'form-control',
                'onchange': 'updateStatusGuidance(this.value)'
            }),
            'priority': forms.Select(attrs={
                'class': 'form-control'
            }),
            'assigned_to_user': forms.Select(attrs={
                'class': 'form-control'
            }),
            'assigned_group': forms.Select(attrs={
                'class': 'form-control'
            }),
            'resolution_summary': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Summary of resolution (required when marking as resolved)'
            })
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        self.ticket = kwargs.pop('ticket', None)
        super().__init__(*args, **kwargs)

        # Permission-based field access
        if self.user and self.ticket:
            user_roles = PermissionManager.get_user_roles(self.user)

            # Check if user can generally change ticket status
            # We'll do specific status validation in clean_status method
            can_change_any_status = self._can_change_any_status()
            if not can_change_any_status:
                self.fields['status'].disabled = True

            # Only allow assignment if user has permission
            if not PermissionManager.can_assign_ticket(self.user, self.ticket):
                self.fields['assigned_to_user'].disabled = True
                self.fields['assigned_group'].disabled = True

            # Populate assignable users
            if PermissionManager.can_assign_ticket(self.user, self.ticket):
                self.fields['assigned_to_user'].queryset = PermissionManager.get_assignable_users(self.user, self.ticket)

    def _can_change_any_status(self):
        """
        Check if user can change status to any valid status
        """
        if not self.user or not self.ticket:
            return False

        # Check some common status changes to determine if user can change status
        test_statuses = ['Open', 'In Progress', 'Resolved', 'Closed']

        for status in test_statuses:
            if status != self.ticket.status:
                try:
                    if PermissionManager.can_change_status(self.user, self.ticket, status):
                        return True
                except:
                    continue
        return False

    def clean_status(self):
        status = self.cleaned_data.get('status')
        if self.ticket and status != self.ticket.status:
            # Check permission for the specific status change
            if not PermissionManager.can_change_status(self.user, self.ticket, status):
                raise ValidationError("You don't have permission to change the status to this value")
        return status

    def clean(self):
        cleaned_data = super().clean()

        # Validate status transitions
        if self.ticket:
            validator = TicketValidator()
            old_status = self.ticket.status
            new_status = cleaned_data.get('status')

            if old_status != new_status:
                validation_result = validator.validate_status_transition(old_status, new_status)
                if not validation_result['valid']:
                    raise ValidationError(validation_result['error'])

        return cleaned_data



class CommentForm(forms.ModelForm):
    """
    Form for adding comments to tickets
    """

    attachments = forms.FileField(
        required=False,
        widget=forms.FileInput(attrs={
            'class': 'form-control',
            'accept': '.pdf,.doc,.docx,.xls,.xlsx,.txt,.png,.jpg,.jpeg,.gif,.zip'
        }),
        help_text="Upload supporting files (Max 10MB each)"
    )

    class Meta:
        model = TicketComment
        fields = ['content', 'is_internal']
        widgets = {
            'content': forms.Textarea(attrs={
                'class': 'form-control',
                'rows': 4,
                'placeholder': 'Add your comment...',
                'required': True
            }),
            'is_internal': forms.CheckboxInput(attrs={
                'class': 'form-check-input'
            })
        }

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        self.ticket = kwargs.pop('ticket', None)
        super().__init__(*args, **kwargs)

        # Only show internal comment option to staff
        if not (self.user and self.user.is_staff):
            self.fields['is_internal'].widget = forms.HiddenInput()
            self.fields['is_internal'].initial = False

    def clean_content(self):
        content = self.cleaned_data.get('content')
        if len(content.strip()) < 1:
            raise ValidationError("Comment content cannot be empty")
        return content


class BulkActionForm(forms.Form):
    """
    Form for bulk actions on tickets
    """

    ACTION_CHOICES = [
        ('', 'Select Action'),
        ('assign', 'Assign to User'),
        ('change_status', 'Change Status'),
        ('change_priority', 'Change Priority'),
        ('add_tag', 'Add Tag'),
        ('export', 'Export Selected'),
    ]

    STATUS_CHOICES = [
        ('New', 'New'),
        ('Open', 'Open'),
        ('In Progress', 'In Progress'),
        ('Pending User Response', 'Pending User Response'),
        ('Resolved', 'Resolved'),
        ('Closed', 'Closed'),
    ]

    PRIORITY_CHOICES = [
        ('Low', 'Low'),
        ('Medium', 'Medium'),
        ('High', 'High'),
        ('Critical', 'Critical'),
    ]

    action = forms.ChoiceField(
        choices=ACTION_CHOICES,
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )

    ticket_ids = forms.CharField(
        widget=forms.HiddenInput(),
        required=True
    )

    # Optional fields for specific actions
    assigned_to = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )

    new_status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )

    new_priority = forms.ChoiceField(
        choices=PRIORITY_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )

    tag_name = forms.CharField(
        max_length=50,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Tag name'
        })
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        super().__init__(*args, **kwargs)

        # Populate assignable users
        if self.user:
            assignable_users = PermissionManager.get_assignable_users(self.user)
            self.fields['assigned_to'].queryset = assignable_users

    def clean(self):
        cleaned_data = super().clean()
        action = cleaned_data.get('action')

        # Validate required fields based on action
        if action == 'assign' and not cleaned_data.get('assigned_to'):
            raise ValidationError("Please select a user to assign tickets to")
        elif action == 'change_status' and not cleaned_data.get('new_status'):
            raise ValidationError("Please select a new status")
        elif action == 'change_priority' and not cleaned_data.get('new_priority'):
            raise ValidationError("Please select a new priority")
        elif action == 'add_tag' and not cleaned_data.get('tag_name'):
            raise ValidationError("Please enter a tag name")

        return cleaned_data


class TicketSearchForm(forms.Form):
    """
    Advanced search form for tickets
    """

    search_query = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Search tickets...'
        })
    )

    status = forms.MultipleChoiceField(
        choices=[
            ('New', 'New'),
            ('Open', 'Open'),
            ('In Progress', 'In Progress'),
            ('Pending User Response', 'Pending User Response'),
            ('Resolved', 'Resolved'),
            ('Closed', 'Closed'),
        ],
        required=False,
        widget=forms.CheckboxSelectMultiple()
    )

    priority = forms.MultipleChoiceField(
        choices=[
            ('Low', 'Low'),
            ('Medium', 'Medium'),
            ('High', 'High'),
            ('Critical', 'Critical'),
        ],
        required=False,
        widget=forms.CheckboxSelectMultiple()
    )

    issue_type = forms.MultipleChoiceField(
        choices=[
            ('Bug Report', 'Bug Report'),
            ('Feature Request', 'Feature Request'),
            ('Technical Support', 'Technical Support'),
            ('Account Issue', 'Account Issue'),
            ('General Inquiry', 'General Inquiry'),
        ],
        required=False,
        widget=forms.CheckboxSelectMultiple()
    )

    assigned_to = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )

    assigned_group = forms.CharField(
        max_length=50,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Assigned group'
        })
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

    sla_status = forms.ChoiceField(
        choices=[
            ('', 'All'),
            ('on_track', 'On Track'),
            ('at_risk', 'At Risk'),
            ('breached', 'Breached'),
        ],
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )

    overdue_only = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        })
    )

    def clean(self):
        cleaned_data = super().clean()
        date_from = cleaned_data.get('date_from')
        date_to = cleaned_data.get('date_to')

        if date_from and date_to and date_from > date_to:
            raise ValidationError("Start date cannot be after end date")

        return cleaned_data


class TicketAssignmentForm(forms.Form):
    """
    Form for assigning tickets to users
    """

    assigned_to = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-control'
        }),
        help_text="Select a user to assign this ticket to"
    )

    assignment_note = forms.CharField(
        max_length=500,
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 3,
            'placeholder': 'Optional note about the assignment...'
        })
    )

    def __init__(self, *args, **kwargs):
        self.user = kwargs.pop('user', None)
        self.ticket = kwargs.pop('ticket', None)
        super().__init__(*args, **kwargs)

        # Populate assignable users
        if self.user and self.ticket:
            assignable_users = PermissionManager.get_assignable_users(self.user, self.ticket)
            self.fields['assigned_to'].queryset = assignable_users


class TicketEscalationForm(forms.Form):
    """
    Form for escalating tickets
    """

    escalation_reason = forms.CharField(
        max_length=1000,
        required=True,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 4,
            'placeholder': 'Please provide a reason for escalation...'
        }),
        help_text="Explain why this ticket needs to be escalated"
    )

    escalate_to = forms.ModelChoiceField(
        queryset=User.objects.filter(is_staff=True, is_active=True),
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-control'
        }),
        help_text="Optional: Select a specific person to escalate to"
    )

    def __init__(self, *args, **kwargs):
        self.ticket = kwargs.pop('ticket', None)
        super().__init__(*args, **kwargs)

    def clean_escalation_reason(self):
        reason = self.cleaned_data.get('escalation_reason')
        if len(reason.strip()) < 10:
            raise ValidationError("Please provide a detailed reason for escalation")
        return reason


class TicketFeedbackForm(forms.Form):
    """
    Form for submitting feedback on resolved tickets
    """

    RATING_CHOICES = [
        (1, '1 - Very Poor'),
        (2, '2 - Poor'),
        (3, '3 - Average'),
        (4, '4 - Good'),
        (5, '5 - Excellent'),
    ]

    satisfaction_rating = forms.ChoiceField(
        choices=RATING_CHOICES,
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-control'
        }),
        help_text="Rate your satisfaction with the support provided"
    )

    feedback = forms.CharField(
        max_length=1000,
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 4,
            'placeholder': 'Please share your feedback about the support experience...'
        }),
        help_text="Optional: Share your experience and suggestions"
    )

    def clean_satisfaction_rating(self):
        rating = self.cleaned_data.get('satisfaction_rating')
        if not rating or int(rating) < 1 or int(rating) > 5:
            raise ValidationError("Please select a valid rating")
        return int(rating)


class TicketReopenForm(forms.Form):
    """
    Form for reopening closed/resolved tickets
    """

    reopen_reason = forms.CharField(
        max_length=1000,
        required=True,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 4,
            'placeholder': 'Please explain why this ticket needs to be reopened...'
        }),
        help_text="Provide a detailed reason for reopening this ticket"
    )

    def clean_reopen_reason(self):
        reason = self.cleaned_data.get('reopen_reason')
        if len(reason.strip()) < 10:
            raise ValidationError("Please provide a detailed reason for reopening")
        return reason
