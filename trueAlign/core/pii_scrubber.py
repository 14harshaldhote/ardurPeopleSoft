# Utility functions for PII scrubbing

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse


# Sensitive query parameters that may contain PII
SENSITIVE_PARAMS = [
    'name', 'email', 'phone', 'mobile', 'ssn', 'aadhar', 'pan',
    'password', 'token', 'key', 'secret', 'id', 'user_id',
    'firstname', 'lastname', 'address', 'dob', 'birthdate'
]

# Patterns for PII detection
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
PHONE_PATTERN = re.compile(r'\b\d{10,12}\b')  # 10-12 digit phone numbers
PAN_PATTERN = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b')  # Indian PAN format
AADHAR_PATTERN = re.compile(r'\b\d{12}\b')  # 12 digit Aadhar


def scrub_url(url):
    """
    Remove PII from URLs by redacting sensitive query parameters
    """
    if not url:
        return url
    
    try:
        parsed = urlparse(url)
        
        # Parse query parameters
        params = parse_qs(parsed.query)
        
        # Redact sensitive parameters
        scrubbed_params = {}
        for key, values in params.items():
            if key.lower() in SENSITIVE_PARAMS:
                scrubbed_params[key] = ['[REDACTED]']
            else:
                # Check if value contains PII patterns
                scrubbed_values = []
                for value in values:
                    if isinstance(value, str):
                        # Check for email
                        if EMAIL_PATTERN.search(value):
                            scrubbed_values.append('[EMAIL]')
                        # Check for phone
                        elif PHONE_PATTERN.search(value):
                            scrubbed_values.append('[PHONE]')
                        # Check for PAN
                        elif PAN_PATTERN.search(value):
                            scrubbed_values.append('[PAN]')
                        # Check for Aadhar
                        elif AADHAR_PATTERN.search(value):
                            scrubbed_values.append('[AADHAR]')
                        else:
                            scrubbed_values.append(value)
                    else:
                        scrubbed_values.append(value)
                scrubbed_params[key] = scrubbed_values
        
        # Reconstruct URL
        new_query = urlencode(scrubbed_params, doseq=True)
        scrubbed_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        # Limit length
        if len(scrubbed_url) > 2000:
            scrubbed_url = scrubbed_url[:2000]
        
        return scrubbed_url
        
    except Exception:
        # If parsing fails, return truncated URL
        return url[:2000] if len(url) > 2000 else url


def scrub_title(title):
    """
    Remove PII from page titles
    """
    if not title:
        return title
    
    # Truncate first
    title = title[:500]
    
    # Replace PII patterns
    title = EMAIL_PATTERN.sub('[EMAIL]', title)
    title = PHONE_PATTERN.sub('[PHONE]', title)
    title = PAN_PATTERN.sub('[PAN]', title)
    title = AADHAR_PATTERN.sub('[AADHAR]', title)
    
    return title


def scrub_activity_data(activity_data):
    """
    Scrub PII from activity data dictionary
    """
    if not isinstance(activity_data, dict):
        return activity_data
    
    scrubbed = {}
    for key, value in activity_data.items():
        if key.lower() in SENSITIVE_PARAMS:
            scrubbed[key] = '[REDACTED]'
        elif isinstance(value, str):
            # Scrub string values
            value = EMAIL_PATTERN.sub('[EMAIL]', value)
            value = PHONE_PATTERN.sub('[PHONE]', value)
            value = PAN_PATTERN.sub('[PAN]', value)
            value = AADHAR_PATTERN.sub('[AADHAR]', value)
            scrubbed[key] = value
        elif isinstance(value, dict):
            # Recursive scrub for nested dicts
            scrubbed[key] = scrub_activity_data(value)
        elif isinstance(value, list):
            # Scrub lists
            scrubbed[key] = [
                scrub_activity_data(item) if isinstance(item, dict)
                else EMAIL_PATTERN.sub('[EMAIL]', str(item)) if isinstance(item, str)
                else item
                for item in value
            ]
        else:
            scrubbed[key] = value
    
    return scrubbed
