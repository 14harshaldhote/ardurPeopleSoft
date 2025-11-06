from django import forms
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from trueAlign.models import Support, TicketComment
from .forms_mixins import CrispyFormMixin


class TicketCreateForm(CrispyFormMixin, forms.ModelForm):
    """Form for creating new support tickets"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['issue_type'].widget.attrs.update({
            'class': 'block w-full px-4 py-3 rounded-xl bg-white/50 border border-white/40 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500',
            'required': True
        })
        self.fields['subject'].widget.attrs.update({
            'class': 'block w-full px-4 py-3 rounded-xl bg-white/50 border border-white/40 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500',
            'placeholder': 'Brief description of the issue',
            'maxlength': 200,
            'required': True
        })
        self.fields['description'].widget.attrs.update({
            'class': 'block w-full px-4 py-3 rounded-xl bg-white/50 border border-white/40 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500',
            'rows': 5,
            'placeholder': 'Provide detailed information about the issue...',
            'required': True
        })
        self.fields['priority'].widget.attrs.update({
            'class': 'block w-full px-4 py-3 rounded-xl bg-white/50 border border-white/40 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500'
        })
        self.fields['location'].widget.attrs.update({
            'class': 'block w-full px-4 py-3 rounded-xl bg-white/50 border border-white/40 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500',
            'placeholder': 'Office location (optional)',
            'maxlength': 100
        })
        self.fields['asset_id'].widget.attrs.update({
            'class': 'block w-full px-4 py-3 rounded-xl bg-white/50 border border-white/40 focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500',
            'placeholder': 'Asset/Equipment ID (if applicable)',
            'maxlength': 50
        })

    class Meta:
        model = Support
        fields = [
            'issue_type',
            'subject',
            'description',
            'priority',
            'location',
            'asset_id'
        ]

        labels = {
            'issue_type': 'Type of Issue',
            'subject': 'Subject',
            'description': 'Description',
            'priority': 'Priority Level',
            'location': 'Location',
            'asset_id': 'Asset ID'
        }

        help_texts = {
            'issue_type': 'Select the category that best describes your issue',
            'priority': 'Select priority based on business impact',
            'asset_id': 'Enter the ID of any related hardware or software asset'
        }

    def clean_subject(self):
        subject = self.cleaned_data.get('subject', '').strip()
        if not subject:
            raise ValidationError('Subject is required.')
        if len(subject) < 5:
            raise ValidationError('Subject must be at least 5 characters long.')
        return subject

    def clean_description(self):
        description = self.cleaned_data.get('description', '').strip()
        if not description:
            raise ValidationError('Description is required.')
        if len(description) < 20:
            raise ValidationError('Please provide a more detailed description (at least 20 characters).')
        return description


class TicketCommentForm(forms.ModelForm):
    """Form for adding comments to tickets"""

    class Meta:
        model = TicketComment
        fields = ['content', 'is_internal']

        widgets = {
            'content': forms.Textarea(
                attrs={
                    'class': 'form-control',
                    'rows': 4,
                    'placeholder': 'Enter your comment...',
                    'required': True
                }
            ),
            'is_internal': forms.CheckboxInput(
                attrs={
                    'class': 'form-check-input'
                }
            )
        }

        labels = {
            'content': 'Comment',
            'is_internal': 'Internal Note (Staff Only)'
        }

        help_texts = {
            'is_internal': 'Check this box if the comment should only be visible to staff members'
        }

    def clean_content(self):
        content = self.cleaned_data.get('content', '').strip()
        if not content:
            raise ValidationError('Comment content is required.')
        if len(content) < 5:
            raise ValidationError('Comment must be at least 5 characters long.')
        return content


class TicketStatusForm(forms.Form):
    """Form for updating ticket status"""

    status = forms.ChoiceField(
        choices=Support.Status.choices,
        widget=forms.Select(
            attrs={
                'class': 'form-control',
                'required': True
            }
        ),
        label='New Status',
        help_text='Select the new status for this ticket'
    )

    comment = forms.CharField(
        widget=forms.Textarea(
            attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Optional comment about the status change...'
            }
        ),
        required=False,
        label='Comment',
        help_text='Optional comment explaining the status change'
    )

    def clean_status(self):
        status = self.cleaned_data.get('status')
        if not status:
            raise ValidationError('Please select a status.')
        return status


class TicketReassignForm(forms.Form):
    """Form for reassigning tickets"""

    assigned_to_user = forms.ModelChoiceField(
        queryset=User.objects.filter(is_active=True),
        empty_label="-- Select User --",
        required=False,
        widget=forms.Select(
            attrs={
                'class': 'form-control'
            }
        ),
        label='Assign to User',
        help_text='Select a user to assign this ticket to'
    )

    assigned_group = forms.ChoiceField(
        choices=[('', '-- Select Group --')] + list(Support.AssignedGroup.choices),
        required=False,
        widget=forms.Select(
            attrs={
                'class': 'form-control'
            }
        ),
        label='Assign to Group',
        help_text='Select a group to assign this ticket to'
    )

    def __init__(self, *args, available_assignees=None, **kwargs):
        super().__init__(*args, **kwargs)

        if available_assignees:
            # Set the queryset for assigned_to_user based on available assignees
            user_ids = [assignee.get('id') for assignee in available_assignees if assignee.get('id')]
            if user_ids:
                self.fields['assigned_to_user'].queryset = User.objects.filter(
                    id__in=user_ids,
                    is_active=True
                ).order_by('first_name', 'last_name')

    def clean(self):
        cleaned_data = super().clean()
        assigned_to_user = cleaned_data.get('assigned_to_user') if cleaned_data else None
        assigned_group = cleaned_data.get('assigned_group') if cleaned_data else None

        if not assigned_to_user and not assigned_group:
            raise ValidationError('Please select either a user or a group for assignment.')

        return cleaned_data


class TicketSearchForm(forms.Form):
    """Form for searching tickets"""

    search = forms.CharField(
        max_length=200,
        required=False,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'Search by ticket ID, subject, or description...',
            }
        ),
        label='Search'
    )

    status = forms.ChoiceField(
        choices=[('', 'All Statuses')] + list(Support.Status.choices),
        required=False,
        widget=forms.Select(
            attrs={
                'class': 'form-control'
            }
        ),
        label='Status Filter'
    )

    priority = forms.ChoiceField(
        choices=[('', 'All Priorities')] + list(Support.Priority.choices),
        required=False,
        widget=forms.Select(
            attrs={
                'class': 'form-control'
            }
        ),
        label='Priority Filter'
    )

    issue_type = forms.ChoiceField(
        choices=[('', 'All Issue Types')] + list(Support.IssueType.choices),
        required=False,
        widget=forms.Select(
            attrs={
                'class': 'form-control'
            }
        ),
        label='Issue Type Filter'
    )


class TicketAttachmentForm(forms.Form):
    """Form for uploading ticket attachments"""

    file = forms.FileField(
        widget=forms.ClearableFileInput(
            attrs={
                'class': 'form-control-file',
                'accept': '.pdf,.doc,.docx,.txt,.jpg,.jpeg,.png,.gif,.zip,.rar'
            }
        ),
        label='Select File',
        help_text='Maximum file size: 10MB. Supported formats: PDF, DOC, DOCX, TXT, JPG, PNG, GIF, ZIP, RAR'
    )

    description = forms.CharField(
        max_length=255,
        required=False,
        widget=forms.TextInput(
            attrs={
                'class': 'form-control',
                'placeholder': 'Brief description of the file (optional)'
            }
        ),
        label='Description'
    )

    def clean_file(self):
        file = self.cleaned_data.get('file')
        if file:
            # Check file size (10MB limit)
            if file.size > 10 * 1024 * 1024:
                raise ValidationError('File size must be less than 10MB.')

            # Check file extension
            allowed_extensions = [
                '.pdf', '.doc', '.docx', '.txt', '.jpg', '.jpeg',
                '.png', '.gif', '.zip', '.rar'
            ]
            file_extension = file.name.lower().split('.')[-1]
            if f'.{file_extension}' not in allowed_extensions:
                raise ValidationError(
                    'Unsupported file format. Please use: PDF, DOC, DOCX, TXT, JPG, PNG, GIF, ZIP, or RAR.'
                )

        return file


class TicketEscalationForm(forms.Form):
    """Form for escalating tickets"""

    reason = forms.CharField(
        widget=forms.Textarea(
            attrs={
                'class': 'form-control',
                'rows': 3,
                'placeholder': 'Please provide a reason for escalation...',
                'required': True
            }
        ),
        label='Escalation Reason',
        help_text='Explain why this ticket needs to be escalated',
        max_length=500
    )

    def clean_reason(self):
        reason = self.cleaned_data.get('reason', '').strip()
        if not reason:
            raise ValidationError('Please provide a reason for escalation.')
        if len(reason) < 10:
            raise ValidationError('Please provide a more detailed reason (at least 10 characters).')
        return reason


class TicketFilterForm(forms.Form):
    """Advanced filtering form for tickets"""

    status = forms.MultipleChoiceField(
        choices=Support.Status.choices,
        required=False,
        widget=forms.CheckboxSelectMultiple(
            attrs={'class': 'form-check-input'}
        ),
        label='Status'
    )

    priority = forms.MultipleChoiceField(
        choices=Support.Priority.choices,
        required=False,
        widget=forms.CheckboxSelectMultiple(
            attrs={'class': 'form-check-input'}
        ),
        label='Priority'
    )

    issue_type = forms.MultipleChoiceField(
        choices=Support.IssueType.choices,
        required=False,
        widget=forms.CheckboxSelectMultiple(
            attrs={'class': 'form-check-input'}
        ),
        label='Issue Type'
    )

    date_from = forms.DateField(
        required=False,
        widget=forms.DateInput(
            attrs={
                'class': 'form-control',
                'type': 'date'
            }
        ),
        label='From Date'
    )

    date_to = forms.DateField(
        required=False,
        widget=forms.DateInput(
            attrs={
                'class': 'form-control',
                'type': 'date'
            }
        ),
        label='To Date'
    )

    def clean(self):
        cleaned_data = super().clean()
        date_from = cleaned_data.get('date_from') if cleaned_data else None
        date_to = cleaned_data.get('date_to') if cleaned_data else None

        if date_from and date_to and date_from > date_to:
            raise ValidationError('From date cannot be later than To date.')

        return cleaned_data