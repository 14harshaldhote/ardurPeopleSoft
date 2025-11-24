"""
Decorators for Finance Module
Provides permission and role-based access control decorators
"""

from functools import wraps
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from django.contrib import messages
from django.conf import settings


def finance_permission_required(permission_codename):
    """
    Decorator to check if user has specific finance permission
    """
    def decorator(view_func):
        @wraps(view_func)
        @login_required
        def _wrapped_view(request, *args, **kwargs):
            if request.user.has_perm(f'finance.{permission_codename}'):
                return view_func(request, *args, **kwargs)
            messages.error(request, "You don't have permission to access this page.")
            raise PermissionDenied
        return _wrapped_view
    return decorator


def finance_manager_required(view_func):
    """
    Decorator that checks if the user belongs to the Finance group
    """
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect(f"{settings.LOGIN_URL}?next={request.path}")
        
        if not (request.user.groups.filter(name='Finance').exists() or request.user.is_superuser):
            messages.error(request, "You don't have permission to access this page. Finance role required.")
            return redirect('core:home')
        
        return view_func(request, *args, **kwargs)
    
    return wrapper


def department_head_required(view_func):
    """
    Decorator to check if user is a department head
    """
    @wraps(view_func)
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        if request.user.groups.filter(name='Manager').exists() or request.user.is_superuser:
            return view_func(request, *args, **kwargs)
        messages.error(request, "Only department heads/managers can access this page.")
        raise PermissionDenied
    return _wrapped_view


def can_approve_expense(view_func):
    """
    Decorator to check if user can approve expenses (Finance and Manager groups)
    """
    @wraps(view_func)
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        can_approve = (
            request.user.groups.filter(name__in=['Manager', 'Finance']).exists() 
            or request.user.is_superuser
        )
        if can_approve:
            return view_func(request, *args, **kwargs)
        messages.error(request, "You don't have permission to approve expenses.")
        raise PermissionDenied
    return _wrapped_view


def can_approve_voucher(view_func):
    """
    Decorator to check if user can approve vouchers
    """
    @wraps(view_func)
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        can_approve = (
            request.user.groups.filter(name__in=['Manager', 'Finance']).exists() 
            or request.user.is_superuser
        )
        if can_approve:
            return view_func(request, *args, **kwargs)
        messages.error(request, "You don't have permission to approve vouchers.")
        raise PermissionDenied
    return _wrapped_view


def can_approve_payment(view_func):
    """
    Decorator to check if user can approve bank payments (Finance group only)
    """
    @wraps(view_func)
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        can_approve = (
            request.user.groups.filter(name='Finance').exists() 
            or request.user.is_superuser
        )
        if can_approve:
            return view_func(request, *args, **kwargs)
        messages.error(request, "Only finance users can approve payments.")
        raise PermissionDenied
    return _wrapped_view


def ajax_required(view_func):
    """
    Decorator to ensure request is AJAX
    """
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            raise PermissionDenied
        return view_func(request, *args, **kwargs)
    return _wrapped_view