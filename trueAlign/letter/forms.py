from django import forms
from django.contrib.auth import get_user_model
from trueAlign.models import LetterTemplate

User = get_user_model()

class LetterGenerationForm(forms.Form):
    employee = forms.ModelChoiceField(
        queryset=User.objects.all(), # Filter appropriately, e.g., active employees
        widget=forms.Select(attrs={'class': 'form-control select2', 'data-placeholder': 'Select Employee'}),
        label="Select Employee"
    )
    date_of_generation = forms.DateField(
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
        label="Date"
    )
    
    # Dynamic fields will be handled in the template/JS or added dynamically here if needed
    # For now, we can have a generic JSON field or specific fields based on common requirements
    
    # Common fields that might be needed
    effective_date = forms.DateField(
        required=False,
        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
        label="Effective Date"
    )
    
    reason = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
        label="Reason / Comments"
    )

    def __init__(self, *args, **kwargs):
        template = kwargs.pop('template', None)
        super().__init__(*args, **kwargs)
        
        if template and template.placeholders:
            for placeholder in template.placeholders:
                # Skip 'date' as it is handled by date_of_generation
                if placeholder == 'date':
                    continue

                # Determine field type based on placeholder name
                if 'date' in placeholder or 'day' in placeholder:
                    self.fields[placeholder] = forms.DateField(
                        label=placeholder.replace('_', ' ').title(),
                        widget=forms.DateInput(attrs={'type': 'date', 'class': 'form-control'}),
                        required=True
                    )
                else:
                    self.fields[placeholder] = forms.CharField(
                        label=placeholder.replace('_', ' ').title(),
                        widget=forms.TextInput(attrs={'class': 'form-control'}),
                        required=True
                    )
