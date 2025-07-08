# In your app's templatetags directory
from django import template
register = template.Library()

@register.filter
def get_item(dictionary, key):
    return dictionary.get(key)

from django import template
from django.forms.boundfield import BoundField

register = template.Library()

@register.filter(name='addclass')
def addclass(value, arg):
    """
    Add CSS classes to Django form fields

    Usage in template:
    {{ form.field|addclass:"new classes" }}
    """
    # If value is a BoundField (Django form field)
    if isinstance(value, BoundField):
        # Get the current attributes of the field
        attrs = value.field.widget.attrs

        # If classes already exist, append new classes
        if 'class' in attrs:
            attrs['class'] += f" {arg}"
        else:
            attrs['class'] = arg

        # Return the modified field
        return value

    # If not a form field, return original value
    return value

from django import template
from datetime import timedelta

register = template.Library()

@register.filter
def timedelta_humanize(td):
    """
    Convert a timedelta object to a human-readable string.
    Example: 2 hours 30 minutes
    """
    if not isinstance(td, timedelta):
        return str(td)

    days = td.days
    hours, remainder = divmod(td.seconds, 3600)
    minutes, seconds = divmod(remainder, 60)

    parts = []
    if days:
        parts.append(f"{days} {'day' if days == 1 else 'days'}")
    if hours:
        parts.append(f"{hours} {'hour' if hours == 1 else 'hours'}")
    if minutes:
        parts.append(f"{minutes} {'minute' if minutes == 1 else 'minutes'}")
    if seconds and not (days or hours or minutes):
        parts.append(f"{seconds} {'second' if seconds == 1 else 'seconds'}")

    return " ".join(parts) if parts else "0 seconds"

from django import template

register = template.Library()

@register.filter
def percentage_of_day(value):
    """Calculate what percentage of a day the given seconds represent"""
    try:
        return float(value) / 86400 * 100
    except (ValueError, TypeError):
        return 0


from django import template

register = template.Library()

@register.filter
def user_display_name(user):
    """
    Returns the display name for a user, handling None values and missing get_full_name method
    """
    if not user:
        return "Unknown User"

    if hasattr(user, 'get_full_name') and callable(getattr(user, 'get_full_name')):
        full_name = user.get_full_name()
        if full_name and full_name.strip():
            return full_name.strip()

    if hasattr(user, 'first_name') and hasattr(user, 'last_name'):
        if user.first_name and user.last_name:
            return f"{user.first_name} {user.last_name}".strip()
        elif user.first_name:
            return user.first_name.strip()
        elif user.last_name:
            return user.last_name.strip()

    if hasattr(user, 'username') and user.username:
        return user.username

    return f"User #{user.pk}" if hasattr(user, 'pk') else "Unknown User"

@register.filter
def safe_user_initial(user):
    """
    Returns the first letter of user's name safely
    """
    if not user:
        return "?"

    display_name = user_display_name(user)
    return display_name[0].upper() if display_name else "?"
