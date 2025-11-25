from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import SetPasswordForm


class DirectPasswordResetForm(forms.Form):
    """Form for direct password reset without email verification."""
    email = forms.CharField(
        max_length=254,
        widget=forms.TextInput(attrs={
            'class': 'w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500',
            'placeholder': 'Email or username'
        }),
        help_text='Enter email address or username'
    )
    new_password1 = forms.CharField(
        label="New password",
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
        }),
        strip=False,
    )
    new_password2 = forms.CharField(
        label="Confirm password",
        widget=forms.PasswordInput(attrs={
            'class': 'w-full px-3 py-2 border border-gray-300 rounded-lg shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500'
        }),
        strip=False,
    )

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('new_password1')
        password2 = cleaned_data.get('new_password2')

        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError("The two password fields didn't match.")
        
        return cleaned_data

    def clean_email(self):
        email_or_username = self.cleaned_data['email']
        # Try to find user by email or username
        try:
            if '@' in email_or_username:
                user = User.objects.get(email=email_or_username)
            else:
                user = User.objects.get(username=email_or_username)
        except User.DoesNotExist:
            raise forms.ValidationError("No user found with this email or username.")
        
        self.user = user
        return email_or_username

    def save(self):
        """Set the new password for the user."""
        password = self.cleaned_data['new_password1']
        self.user.set_password(password)
        self.user.save()
        return self.user
