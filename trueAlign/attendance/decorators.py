from django.contrib.auth.decorators import user_passes_test
from django.shortcuts import redirect
from django.contrib import messages
from django.http import HttpResponseForbidden
from django.template import loader
from functools import wraps
import logging

logger = logging.getLogger('shift')

def group_required(group_names, redirect_url='shift:list', raise_exception=False):
    """
    Decorator for views that checks that the user is in a certain group.

    Args:
        group_names (list): List of group names that have access
        redirect_url (str): URL to redirect to if access is denied (default: 'shift:list')
        raise_exception (bool): If True, raise Http403 instead of redirecting

    Usage:
        @group_required(group_names=['Manager', 'Admin'])
        @group_required(group_names=['Manager'], redirect_url='shift:dashboard')
        @group_required(group_names=['Admin'], raise_exception=True)
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper_func(request, *args, **kwargs):
            user = request.user
            view_name = getattr(view_func, '__name__', 'unknown_view')

            # Log access attempt
            logger.debug(f"User {user.username if user.is_authenticated else 'anonymous'} "
                        f"attempting to access {view_name}")

            # Check authentication
            if not user.is_authenticated:
                logger.warning(f"Unauthenticated user attempted to access {view_name}")
                messages.error(request, "You must be logged in to access this page.")
                return redirect('login')

            # Check if user is superuser (always has access)
            if user.is_superuser:
                logger.debug(f"Superuser {user.username} granted access to {view_name}")
                return view_func(request, *args, **kwargs)

            # Check group membership
            user_groups = user.groups.values_list('name', flat=True)
            has_access = any(group in user_groups for group in group_names)

            if has_access:
                logger.debug(f"User {user.username} granted access to {view_name} "
                           f"(groups: {list(user_groups)})")
                return view_func(request, *args, **kwargs)

            # Access denied
            logger.warning(f"User {user.username} denied access to {view_name}. "
                         f"Required groups: {group_names}, User groups: {list(user_groups)}")

            error_message = (f"You do not have permission to access this page. "
                           f"Required role(s): {', '.join(group_names)}")

            if raise_exception:
                # Return 403 Forbidden response
                template = loader.get_template('403.html')
                context = {
                    'required_groups': group_names,
                    'user_groups': list(user_groups),
                    'error_message': error_message
                }
                return HttpResponseForbidden(template.render(context, request))
            else:
                # Redirect with error message
                messages.error(request, error_message)
                logger.info(f"Redirecting {user.username} to {redirect_url}")
                return redirect(redirect_url)

        return wrapper_func
    return decorator

def superuser_required(redirect_url='shift:list', raise_exception=False):
    """
    Decorator that requires superuser status.

    Args:
        redirect_url (str): URL to redirect to if access is denied
        raise_exception (bool): If True, raise Http403 instead of redirecting

    Usage:
        @superuser_required()
        @superuser_required(redirect_url='admin:index')
    """
    def decorator(view_func):
        @wraps(view_func)
        def wrapper_func(request, *args, **kwargs):
            user = request.user
            view_name = getattr(view_func, '__name__', 'unknown_view')

            logger.debug(f"User {user.username if user.is_authenticated else 'anonymous'} "
                        f"attempting superuser access to {view_name}")

            if not user.is_authenticated:
                logger.warning(f"Unauthenticated user attempted superuser access to {view_name}")
                messages.error(request, "You must be logged in to access this page.")
                return redirect('login')

            if user.is_superuser:
                logger.debug(f"Superuser {user.username} granted access to {view_name}")
                return view_func(request, *args, **kwargs)

            # Access denied
            logger.warning(f"Non-superuser {user.username} denied access to {view_name}")
            error_message = "You must be a superuser to access this page."

            if raise_exception:
                template = loader.get_template('403.html')
                context = {'error_message': error_message}
                return HttpResponseForbidden(template.render(context, request))
            else:
                messages.error(request, error_message)
                return redirect(redirect_url)

        return wrapper_func
    return decorator
