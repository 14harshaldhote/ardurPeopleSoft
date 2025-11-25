"""
Utility functions for the profile app
"""
import logging
import re
import secrets
import string
from functools import wraps
from django.contrib.auth.models import User
from trueAlign.models import UserDetails
from django.shortcuts import redirect
from django.contrib import messages
from datetime import datetime

logger = logging.getLogger(__name__)


# Security: Secure Password Generation
def generate_secure_password(length=12):
    """
    Generate a cryptographically secure random password.
    
    Args:
        length (int): Length of the password (default: 12)
    
    Returns:
        str: Secure random password
    
    Example:
        >>> pwd = generate_secure_password()
        >>> len(pwd)
        12
    """
    # Define character sets
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    
    # Generate password ensuring it has at least one of each type
    while True:
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        
        # Ensure password has at least:
        # - 1 uppercase letter
        # - 1 lowercase letter
        # - 1 digit
        # - 1 special character
        if (any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in "!@#$%^&*" for c in password)):
            return password


# Decorator for HR/Admin permission checking
def hr_admin_required(view_func):
    """
    Decorator to restrict views to HR and Admin users only.
    
    Usage:
        @login_required
        @hr_admin_required
        def my_view(request):
            # View code
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not is_hr_or_admin(request.user):
            messages.error(request, "You do not have permission to access this page.")
            return redirect('profile:dashboard')
        return view_func(request, *args, **kwargs)
    return wrapper


# Helpers
def is_hr_or_admin(user):
    """Check if user has HR or admin role"""
    try:
        # Check if user is in HR group
        if user.groups.filter(name='HR').exists():
            return True

        profile = user.profile
        job_description = profile.job_description or ''
        return user.is_superuser or profile.employee_type == 'hr' or 'HR' in job_description
    except (AttributeError, UserDetails.DoesNotExist):
        return False


# Helper function to generate employee ID
def generate_employee_id(work_location=None, group_id=None):
    """
    Generate employee ID based on work location with role-based reserved ranges

    Reserved ranges for Management and Finance groups (IDs 7 and 8):
    - 1-15: First priority range
    - 301-400: Second priority range

    Regular employees use 101-300 and 401+ ranges
    """
    from django.db.models import Q

    # Check if user belongs to Finance or Management groups based on group_id
    is_reserved_role = False
    if group_id and group_id in ['7', '8']:  # Finance or Management
        is_reserved_role = True

    # Determine prefix based on location
    current_year = str(datetime.now().year)[2:]
    if work_location and work_location.lower() == 'betul':
        prefix = "ATS"
        separator = "-"
        year_suffix = current_year
    elif work_location and work_location.lower() == 'pune':
        prefix = "AT"
        separator = "-"
        year_suffix = current_year
    else:
        prefix = "EMP"
        year_suffix = current_year
        separator = "-"

    # Function to extract numeric ID from username
    def extract_id(username):
        # Extract numbers at the end of the string
        match = re.search(r'(\d+)$', username)
        if match:
            try:
                return int(match.group(1))
            except ValueError:
                return None
        return None

    # Set ID ranges based on role
    if is_reserved_role:
        # Check if there's a gap in priority range 1-15
        used_ids = []

        # Query all users with the prefix
        all_users = User.objects.filter(username__startswith=prefix)

        # Find all used IDs in the priority range
        for user in all_users:
            user_id = extract_id(user.username)
            if user_id and 1 <= user_id <= 15:
                used_ids.append(user_id)

        # Look for the first available ID in priority range
        for i in range(1, 16):
            if i not in used_ids:
                seq_num = i
                break
        else:
            # Priority range is full, check reserved range 301-400
            used_ids = []
            for user in all_users:
                user_id = extract_id(user.username)
                if user_id and 301 <= user_id <= 400:
                    used_ids.append(user_id)

            # Look for the first available ID in reserved range
            for i in range(301, 401):
                if i not in used_ids:
                    seq_num = i
                    break
            else:
                # Both ranges are full, generate fallback ID
                timestamp = int(datetime.now().timestamp())
                return f"{prefix}{separator}{timestamp}"
    else:
        # Regular employees use 101-300 and 401+
        all_users = User.objects.filter(username__startswith=prefix)
        highest_id = 100  # Start from 101

        # Find the highest used ID outside reserved ranges
        for user in all_users:
            user_id = extract_id(user.username)
            if user_id and user_id > highest_id and user_id not in range(1, 16) and user_id not in range(301, 401):
                highest_id = user_id

        # Start from highest + 1
        seq_num = highest_id + 1

        # Skip reserved ranges
        if 1 <= seq_num <= 15:
            seq_num = 101
        elif 301 <= seq_num <= 400:
            seq_num = 401

    # Format the sequence number and build the ID
    formatted_seq = f"{seq_num:04d}"
    employee_id = f"{prefix}{year_suffix}{separator}{formatted_seq}"

    # Final validation to ensure ID doesn't already exist
    if User.objects.filter(username=employee_id).exists():
        # If this ID is taken, recurse with a timestamp-based ID
        timestamp = int(datetime.now().timestamp())
        return f"{prefix}{year_suffix}{separator}{timestamp}"

    return employee_id

# Helper function to send welcome email
def send_welcome_email(user, password):
    """Send welcome email with login credentials"""
    from django.core.mail import EmailMessage, EmailMultiAlternatives
    from django.template.loader import render_to_string

    subject = "Welcome to Ardur Company Portal"

    # Plain text email body
    email_body = f"""
    Hello {user.first_name} {user.last_name},

    Welcome to Our Company! Your account has been created successfully.

    Here are your login details:
    Username: {user.username}
    Password: {password}

    Please log in at: https://home.ardurtechnology.com/login/

    For security reasons, we recommend changing your password after first login.

    Regards,
    HR Department
    """

    # Try to render HTML template, fall back to plain text if it fails
    try:
        html_message = render_to_string('components/hr/emails/welcome_email.html', {
            'user': user,
            'password': password,
            'login_url': 'https://home.ardurtechnology.com/login/'
        })

        # Send email with both HTML and plain text
        email = EmailMultiAlternatives(
            subject=subject,
            body=email_body,
            to=[user.email]
        )
        email.attach_alternative(html_message, "text/html")
    except Exception as e:
        logger.error(f"Error rendering HTML template: {str(e)}")
        # Fall back to plain text email
        email = EmailMessage(
            subject=subject,
            body=email_body,
            to=[user.email]
        )

    # Add logging before sending (removed password for security)
    logger.info(f"Attempting to send welcome email to {user.email}")

    # Send the email
    email.send()
    logger.info(f"Welcome email sent successfully to {user.email}")

    return True