"""
Custom Widgets for Support System
"""

from django import forms
from django.forms.widgets import ClearableFileInput
from django.utils.safestring import mark_safe


class MultipleFileInput(ClearableFileInput):
    """
    Custom widget that allows multiple file uploads
    """
    allow_multiple_selected = True

    def __init__(self, attrs=None):
        default_attrs = {
            'multiple': True,
            'class': 'form-control',
        }
        if attrs:
            default_attrs.update(attrs)
        super().__init__(default_attrs)

    def value_from_datadict(self, data, files, name):
        """
        Handle multiple files from the request
        """
        if hasattr(files, 'getlist'):
            return files.getlist(name)
        return files.get(name)


class MultipleFileField(forms.FileField):
    """
    Custom field that handles multiple files
    """
    widget = MultipleFileInput

    def __init__(self, *args, **kwargs):
        kwargs.setdefault('widget', MultipleFileInput)
        super().__init__(*args, **kwargs)

    def clean(self, data, initial=None):
        """
        Validate multiple files
        """
        # Handle single file or multiple files
        if not isinstance(data, list):
            data = [data] if data else []

        # Remove empty values
        data = [f for f in data if f]

        if not data and self.required:
            raise forms.ValidationError(self.error_messages['required'])

        # Validate each file
        cleaned_files = []
        for file_data in data:
            if file_data:
                # Validate individual file
                cleaned_file = super().clean(file_data, initial)
                if cleaned_file:
                    # Additional validations
                    self._validate_file_size(cleaned_file)
                    self._validate_file_type(cleaned_file)
                    cleaned_files.append(cleaned_file)

        return cleaned_files

    def _validate_file_size(self, file_obj):
        """Validate file size (max 10MB)"""
        max_size = 10 * 1024 * 1024  # 10MB in bytes
        if hasattr(file_obj, 'size') and file_obj.size > max_size:
            raise forms.ValidationError(
                f'File "{file_obj.name}" is too large. Maximum size allowed is 10MB.'
            )

    def _validate_file_type(self, file_obj):
        """Validate file type"""
        allowed_extensions = [
            '.pdf', '.doc', '.docx', '.txt', '.jpg', '.jpeg',
            '.png', '.gif', '.zip', '.csv', '.xlsx', '.xls'
        ]

        if hasattr(file_obj, 'name') and file_obj.name:
            extension = '.' + file_obj.name.split('.')[-1].lower()
            if extension not in allowed_extensions:
                raise forms.ValidationError(
                    f'File type "{extension}" is not allowed. '
                    f'Allowed types: {", ".join(allowed_extensions)}'
                )
