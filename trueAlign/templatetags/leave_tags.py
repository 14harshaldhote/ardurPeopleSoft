from django import template
from django.contrib.auth.models import Group

register = template.Library()

@register.filter
def has_group(user, group_name):
    """
    Template filter to check if a user belongs to a specific group

    Usage:
    {% if user|has_group:"Manager" %}
        Manager content here
    {% endif %}
    """
    return user.groups.filter(name=group_name).exists()

@register.simple_tag
def get_leave_status_color(status):
    """
    Returns CSS classes for styling leave status

    Usage:
    <span class="{% get_leave_status_color leave.status %}">{{ leave.status }}</span>
    """
    colors = {
        'Pending': 'bg-amber-100 text-amber-800',
        'Approved': 'bg-emerald-100 text-emerald-800',
        'Rejected': 'bg-rose-100 text-rose-800',
        'Cancelled': 'bg-slate-100 text-slate-800'
    }
    return colors.get(status, '')

@register.filter
def decimal_days(value):
    """
    Format decimal days to show half days properly

    Usage:
    {{ leave.days|decimal_days }}
    """
    if not value:
        return "0"

    value = float(value)
    if value.is_integer():
        return str(int(value))
    elif value * 2 == int(value * 2):
        # It's a half day
        return f"{int(value)}.5" if value > 1 else "0.5"
    else:
        # Other decimal value
        return f"{value:.1f}"

@register.simple_tag
def leave_progress(used, total):
    """
    Calculate percentage for progress bars

    Usage:
    {% leave_progress used_days total_days as percentage %}
    """
    if not total or total == 0:
        return 0

    percentage = (float(used) / float(total)) * 100
    return min(100, max(0, percentage))  # Ensure it's between 0 and 100
