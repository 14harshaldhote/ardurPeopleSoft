from django import template

register = template.Library()

@register.filter
def get_item(dictionary, key):
    """Get an item from a dictionary by key"""
    return dictionary.get(key)

@register.filter
def calculate_due_status(invoice):
    """Calculate if an invoice is overdue based on due date"""
    from django.utils import timezone
    if invoice.status == 'paid':
        return 'paid'
    elif invoice.due_date < timezone.now().date():
        return 'overdue'
    return invoice.status