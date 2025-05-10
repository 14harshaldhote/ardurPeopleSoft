from django import template

register = template.Library()

@register.filter(name='get_item')
def get_item(dictionary, key):
    """
    Custom template filter to get an item from a dictionary by key
    Usage: {{ my_dict|get_item:key_var }}
    """
    return dictionary.get(key)

@register.filter(name='filter_by_user')
def filter_by_user(items, user_id):
    """
    Custom template filter to filter a list of items by user ID
    Usage: {{ items|filter_by_user:user_id }}
    """
    return [item for item in items if item.user_id == user_id]

@register.filter(name='status_color')
def status_color(status):
    """
    Custom template filter to convert status to a color
    Usage: {{ status|status_color }}
    """
    colors = {
        'Present': 'green',
        'Absent': 'red',
        'Late': 'yellow',
        'Leave': 'blue',
    }
    return colors.get(status, 'gray')

