from django import template
from django.template.defaultfilters import floatformat

register = template.Library()

@register.filter
def get_username(users_list, user_id):
    """Get username from users list by user ID"""
    try:
        user_id = int(user_id)
        for user in users_list:
            if user.id == user_id:
                return user.username
    except (ValueError, AttributeError):
        pass
    return "Unknown User"

@register.filter
def duration_format(minutes):
    """Format duration in minutes to hours and minutes"""
    try:
        minutes = float(minutes)
        hours = int(minutes // 60)
        mins = int(minutes % 60)
        if hours > 0:
            return f"{hours}h {mins}m"
        return f"{mins}m"
    except (ValueError, TypeError):
        return "0m"

@register.filter
def percentage_color(value):
    """Return appropriate color class based on percentage value"""
    try:
        value = float(value)
        if value >= 80:
            return "text-emerald-600"
        elif value >= 60:
            return "text-blue-600"
        elif value >= 40:
            return "text-yellow-600"
        else:
            return "text-red-600"
    except (ValueError, TypeError):
        return "text-gray-600"
