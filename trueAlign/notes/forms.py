from django import forms
from django.core.exceptions import ValidationError
from django.utils import timezone
from trueAlign.models import GlobalUpdate


class GlobalUpdateForm(forms.ModelForm):
    """Form for creating and editing global updates"""

    class Meta:
        model = GlobalUpdate
        fields = ['title', 'description', 'title_hi', 'description_hi', 'title_mr', 'description_mr', 'primary_language', 'status', 'scheduled_date']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter update title (English)',
                'maxlength': 255
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'Enter detailed description of the update (English)',
                'rows': 6
            }),
            'title_hi': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'अपडेट शीर्षक दर्ज करें (हिंदी)',
                'maxlength': 255
            }),
            'description_hi': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'अपडेट का विस्तृत विवरण दर्ज करें (हिंदी)',
                'rows': 6
            }),
            'title_mr': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'अपडेट शीर्षक प्रविष्ट करा (मराठी)',
                'maxlength': 255
            }),
            'description_mr': forms.Textarea(attrs={
                'class': 'form-control',
                'placeholder': 'अपडेटचे तपशीलवार वर्णन प्रविष्ट करा (मराठी)',
                'rows': 6
            }),
            'primary_language': forms.Select(attrs={
                'class': 'form-control'
            }),
            'status': forms.Select(attrs={
                'class': 'form-control'
            }),
            'scheduled_date': forms.DateTimeInput(attrs={
                'class': 'form-control',
                'type': 'datetime-local',
                'placeholder': 'Select scheduled date and time'
            })
        }
        labels = {
            'title': 'Update Title (English)',
            'description': 'Description (English)',
            'title_hi': 'Update Title (Hindi)',
            'description_hi': 'Description (Hindi)',
            'title_mr': 'Update Title (Marathi)',
            'description_mr': 'Description (Marathi)',
            'primary_language': 'Primary Language',
            'status': 'Status',
            'scheduled_date': 'Scheduled Date & Time'
        }
        help_texts = {
            'title': 'A clear and concise title for the global update in English',
            'description': 'Detailed information about the update in English',
            'title_hi': 'Hindi translation of the update title (optional)',
            'description_hi': 'Hindi translation of the update description (optional)',
            'title_mr': 'Marathi translation of the update title (optional)',
            'description_mr': 'Marathi translation of the update description (optional)',
            'primary_language': 'The primary language for this update',
            'status': 'Choose the appropriate status for this update',
            'scheduled_date': 'Required only for scheduled updates - when this update should become visible'
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make scheduled_date field initially hidden with JavaScript
        self.fields['scheduled_date'].widget.attrs.update({
            'style': 'display: none;'
        })

    def clean_title(self):
        """Validate title field"""
        title = self.cleaned_data.get('title')
        if title:
            title = title.strip()
            if len(title) < 5:
                raise ValidationError("Title must be at least 5 characters long.")
            if len(title) > 255:
                raise ValidationError("Title cannot exceed 255 characters.")
        return title

    def clean_description(self):
        """Validate description field"""
        description = self.cleaned_data.get('description')
        if description:
            description = description.strip()
            if len(description) < 10:
                raise ValidationError("Description must be at least 10 characters long.")
            if len(description) > 5000:
                raise ValidationError("Description cannot exceed 5000 characters.")
        return description

    def clean_scheduled_date(self):
        """Validate scheduled_date field"""
        scheduled_date = self.cleaned_data.get('scheduled_date')
        status = self.cleaned_data.get('status')

        if status == 'scheduled':
            if not scheduled_date:
                raise ValidationError("Scheduled date is required for scheduled updates.")
            if scheduled_date <= timezone.now():
                raise ValidationError("Scheduled date must be in the future.")

        if status != 'scheduled' and scheduled_date:
            raise ValidationError("Scheduled date can only be set for scheduled updates.")

        return scheduled_date

    def clean(self):
        """Additional form validation"""
        cleaned_data = super().clean()
        status = cleaned_data.get('status')
        scheduled_date = cleaned_data.get('scheduled_date')

        # Additional validation for status and scheduled_date consistency
        if status == 'scheduled' and not scheduled_date:
            raise ValidationError("Scheduled updates must have a scheduled date.")

        if status != 'scheduled' and scheduled_date:
            raise ValidationError("Scheduled date can only be set for 'scheduled' status.")

        return cleaned_data


class GlobalUpdateFilterForm(forms.Form):
    """Form for filtering global updates"""

    STATUS_CHOICES = [('', 'All Statuses')] + GlobalUpdate.STATUS_CHOICES

    status = forms.ChoiceField(
        choices=STATUS_CHOICES,
        required=False,
        widget=forms.Select(attrs={
            'class': 'form-control form-control-sm'
        })
    )

    search = forms.CharField(
        max_length=255,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control form-control-sm',
            'placeholder': 'Search by title or description...'
        })
    )


class GlobalUpdateQuickCreateForm(forms.ModelForm):
    """Simplified form for quick update creation"""

    class Meta:
        model = GlobalUpdate
        fields = ['title', 'description', 'status']
        widgets = {
            'title': forms.TextInput(attrs={
                'class': 'form-control form-control-sm',
                'placeholder': 'Quick update title'
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control form-control-sm',
                'placeholder': 'Brief description',
                'rows': 3
            }),
            'status': forms.Select(attrs={
                'class': 'form-control form-control-sm'
            })
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove scheduled option for quick create
        self.fields['status'].choices = [
            ('upcoming', 'Upcoming'),
            ('released', 'Just Released'),
        ]
