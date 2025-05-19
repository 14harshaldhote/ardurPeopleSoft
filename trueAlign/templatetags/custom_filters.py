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