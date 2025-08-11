"""
Role-based Access Control Decorators
====================================
"""

from functools import wraps
from django.http import HttpResponseRedirect, HttpResponseForbidden
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib import messages


def role_required(role_name, redirect_url='leave_management:dashboard'):
    """
    Decorator to require specific role for view access
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            user = request.user

            # Check if user has the required role via groups
            if user.groups.filter(name=role_name).exists():
                return view_func(request, *args, **kwargs)

            # Check if user has the role via UserDetails model
            try:
                from trueAlign.models import UserDetails
                user_details = UserDetails.objects.get(user=user)
                if user_details.role == role_name:
                    return view_func(request, *args, **kwargs)
            except (UserDetails.DoesNotExist, AttributeError):
                pass

            # User doesn't have required role
            messages.error(request, f"Access denied. {role_name} role required.")
            return HttpResponseRedirect(reverse(redirect_url))

        return _wrapped_view
    return decorator


def employee_required(view_func):
    """Decorator for employee-only views"""
    return role_required('Employee')(view_func)


def manager_required(view_func):
    """Decorator for manager-only views"""
    return role_required('Manager')(view_func)


def hr_required(view_func):
    """Decorator for HR-only views"""
    return role_required('HR')(view_func)


def multiple_roles_required(roles, redirect_url='leave_management:dashboard'):
    """
    Decorator to require any of multiple roles
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            user = request.user

            # Check if user has any of the required roles via groups
            if user.groups.filter(name__in=roles).exists():
                return view_func(request, *args, **kwargs)

            # Check via UserDetails model
            try:
                from trueAlign.models import UserDetails
                user_details = UserDetails.objects.get(user=user)
                if user_details.role in roles:
                    return view_func(request, *args, **kwargs)
            except (UserDetails.DoesNotExist, AttributeError):
                pass

            # User doesn't have any required role
            messages.error(request, f"Access denied. One of these roles required: {', '.join(roles)}")
            return HttpResponseRedirect(reverse(redirect_url))

        return _wrapped_view
    return decorator
