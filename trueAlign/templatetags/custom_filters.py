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