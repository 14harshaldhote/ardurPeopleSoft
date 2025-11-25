"""
Validators for the profile application.
Provides validation for Indian identity documents, bank details, and contact information.
"""
import re
from django.core.validators import RegexValidator
from django.core.exceptions import ValidationError
from .constants import (
    PAN_PATTERN, 
    AADHAR_PATTERN, 
    IFSC_PATTERN, 
    INDIAN_PHONE_PATTERN,
    ERROR_MESSAGES
)


# PAN Card Validator
pan_validator = RegexValidator(
    regex=PAN_PATTERN,
    message=ERROR_MESSAGES['pan_invalid'],
    code='invalid_pan'
)


def validate_pan_number(value):
    """
    Validate PAN (Permanent Account Number) format.
    Format: ABCDE1234F (5 letters, 4 digits, 1 letter)
    """
    if not value:
        return value
    
    value = value.strip().upper()
    
    if not re.match(PAN_PATTERN, value):
        raise ValidationError(
            ERROR_MESSAGES['pan_invalid'],
            code='invalid_pan'
        )
    
    return value


# Aadhar Card Validator
def validate_aadhar_number(value):
    """
    Validate Aadhar number format and basic checksum.
    Format: 12 digits
    """
    if not value:
        return value
    
    # Remove spaces and non-digits
    cleaned_value = re.sub(r'\D', '', str(value))
    
    if not re.match(AADHAR_PATTERN, cleaned_value):
        raise ValidationError(
            ERROR_MESSAGES['aadhar_invalid'],
            code='invalid_aadhar'
        )
    
    # Basic validation: Aadhar should not start with 0 or 1
    if cleaned_value[0] in ['0', '1']:
        raise ValidationError(
            'Aadhar number cannot start with 0 or 1',
            code='invalid_aadhar_start'
        )
    
    return cleaned_value


# IFSC Code Validator
ifsc_validator = RegexValidator(
    regex=IFSC_PATTERN,
    message=ERROR_MESSAGES['ifsc_invalid'],
    code='invalid_ifsc'
)


def validate_ifsc_code(value):
    """
    Validate IFSC (Indian Financial System Code) format.
    Format: SBIN0001234 (4 letters, 1 zero, 6 alphanumeric)
    """
    if not value:
        return value
    
    value = value.strip().upper()
    
    if not re.match(IFSC_PATTERN, value):
        raise ValidationError(
            ERROR_MESSAGES['ifsc_invalid'],
            code='invalid_ifsc'
        )
    
    # Fifth character must be 0
    if value[4] != '0':
        raise ValidationError(
            'Fifth character of IFSC code must be 0',
            code='invalid_ifsc_format'
        )
    
    return value


# Indian Phone Number Validator
indian_phone_validator = RegexValidator(
    regex=INDIAN_PHONE_PATTERN,
    message=ERROR_MESSAGES['phone_invalid'],
    code='invalid_phone'
)


def validate_indian_phone(value):
    """
    Validate Indian mobile phone number.
    Format: 10 digits starting with 6, 7, 8, or 9
    """
    if not value:
        return value
    
    # Remove spaces, hyphens, and country code
    cleaned_value = re.sub(r'[\s\-\+]', '', str(value))
    
    # Remove +91 or 91 prefix if present
    if cleaned_value.startswith('+91'):
        cleaned_value = cleaned_value[3:]
    elif cleaned_value.startswith('91') and len(cleaned_value) > 10:
        cleaned_value = cleaned_value[2:]
    
    if not re.match(INDIAN_PHONE_PATTERN, cleaned_value):
        raise ValidationError(
            ERROR_MESSAGES['phone_invalid'],
            code='invalid_phone'
        )
    
    return cleaned_value


# Bank Account Number Validator
def validate_bank_account_number(value):
    """
    Validate Indian bank account number.
    Typically 9-18 digits
    """
    if not value:
        return value
    
    cleaned_value = re.sub(r'\D', '', str(value))
    
    if len(cleaned_value) < 9 or len(cleaned_value) > 18:
        raise ValidationError(
            'Bank account number must be between 9 and 18 digits',
            code='invalid_account_number'
        )
    
    return cleaned_value


# Passport Number Validator
def validate_passport_number(value):
    """
    Validate Indian passport number.
    Format: 1 letter followed by 7 digits
    """
    if not value:
        return value
    
    value = value.strip().upper()
    
    # Indian passport format: A1234567
    if not re.match(r'^[A-Z]\d{7}$', value):
        raise ValidationError(
            'Passport number must be 1 letter followed by 7 digits (e.g., A1234567)',
            code='invalid_passport'
        )
    
    return value


# Email domain validator for company emails
def validate_company_email_domain(value, allowed_domains=None):
    """
    Validate that email belongs to allowed company domains.
    
    Args:
        value: Email address to validate
        allowed_domains: List of allowed domains (default: ['ardurtechnology.com'])
    """
    if not value:
        return value
    
    if allowed_domains is None:
        allowed_domains = ['ardurtechnology.com']
    
    domain = value.split('@')[-1].lower()
    
    if domain not in allowed_domains:
        raise ValidationError(
            f'Company email must be from one of these domains: {", ".join(allowed_domains)}',
            code='invalid_company_email_domain'
        )
    
    return value


# Date validators
def validate_future_date(value):
    """Validate that a date is in the future"""
    from django.utils import timezone
    
    if value and value <= timezone.now().date():
        raise ValidationError(
            'This date must be in the future',
            code='date_not_future'
        )
    
    return value


def validate_past_date(value):
    """Validate that a date is in the past"""
    from django.utils import timezone
    
    if value and value >= timezone.now().date():
        raise ValidationError(
            'This date must be in the past',
            code='date_not_past'
        )
    
    return value
