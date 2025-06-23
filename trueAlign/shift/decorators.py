from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import redirect
from django.contrib import messages

def group_required(group_names):
    """
    Decorator for views that checks that the user is in a certain group.
    Usage: @group_required(group_names=['Manager', 'Admin'])
    """
    def check_groups(user):
        if user.is_authenticated:
            # Check if the user is in any of the required groups
            if bool(user.groups.filter(name__in=group_names)) or user.is_superuser:
                return True
        # If user is not in the group or not authenticated,
        # show an error message and redirect.
        return False

    def decorator(view_func):
        def wrapper_func(request, *args, **kwargs):
            if not check_groups(request.user):
                messages.error(request, "You do not have permission to access this page.")
                # Redirect to a safe page, like the shift list or dashboard
                return redirect('shift:list') 
            return view_func(request, *args, **kwargs)
        return wrapper_func
    return decorator