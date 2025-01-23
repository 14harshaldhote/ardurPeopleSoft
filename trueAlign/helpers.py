# helpers.py

from django.contrib.auth.models import Group

# Helper function to check if the user belongs to a specific group
def is_user_in_group(user, group_name):
    """
    Check if the user belongs to a specific group using Group model.
    Args:
    - user: The current user object.
    - group_name: The name of the group (e.g. 'Admin', 'Employee', etc.).
    
    Returns:
    - True if the user belongs to the group, otherwise False.
    """
    return user.groups.filter(name=group_name).exists()
