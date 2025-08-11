"""
Role-based security utilities for leave management system
"""
from django.contrib.auth.models import Group, User
from django.core.exceptions import PermissionDenied
from functools import wraps
from typing import List, Optional
from django.utils import timezone
from datetime import datetime, date, time
import pytz


# Role constants
class Roles:
    EMPLOYEE = 'Employee'
    MANAGER = 'Manager'
    HR = 'HR'
    ADMIN = 'Admin'
    FINANCE = 'Finance'

    ALL_ROLES = [EMPLOYEE, MANAGER, HR, ADMIN, FINANCE]


# Timezone utilities for consistent date handling
def get_local_timezone():
    """Get the configured local timezone (Asia/Kolkata)"""
    return pytz.timezone('Asia/Kolkata')


def get_current_date():
    """Get current date in local timezone"""
    return timezone.localtime().date()


def get_current_datetime():
    """Get current datetime in local timezone"""
    return timezone.localtime()


def parse_date_safely(date_string, default_date=None):
    """
    Parse date string safely with timezone awareness
    Returns date object or default_date if parsing fails
    """
    if not date_string:
        return default_date or get_current_date()

    try:
        if isinstance(date_string, str):
            # Try common date formats
            for fmt in ['%Y-%m-%d', '%d/%m/%Y', '%d-%m-%Y']:
                try:
                    return datetime.strptime(date_string, fmt).date()
                except ValueError:
                    continue
        elif isinstance(date_string, datetime):
            return timezone.localtime(date_string).date()
        elif isinstance(date_string, date):
            return date_string
    except (ValueError, TypeError):
        pass

    return default_date or get_current_date()


def make_timezone_aware(dt):
    """Make a datetime timezone-aware using local timezone"""
    if dt is None:
        return None

    if timezone.is_aware(dt):
        return timezone.localtime(dt)

    # Assume naive datetime is in local timezone
    local_tz = get_local_timezone()
    return local_tz.localize(dt)


def get_date_range_for_period(period, reference_date=None):
    """
    Get start and end dates for common periods
    Returns (start_date, end_date) tuple
    """
    if reference_date is None:
        reference_date = get_current_date()

    if period == 'today':
        return reference_date, reference_date
    elif period == 'this_week':
        start = reference_date - timezone.timedelta(days=reference_date.weekday())
        end = start + timezone.timedelta(days=6)
        return start, end
    elif period == 'this_month':
        start = reference_date.replace(day=1)
        if reference_date.month == 12:
            end = reference_date.replace(year=reference_date.year + 1, month=1, day=1) - timezone.timedelta(days=1)
        else:
            end = reference_date.replace(month=reference_date.month + 1, day=1) - timezone.timedelta(days=1)
        return start, end
    elif period == 'this_year':
        start = reference_date.replace(month=1, day=1)
        end = reference_date.replace(month=12, day=31)
        return start, end

    return reference_date, reference_date


def is_working_day(date_obj, exclude_weekends=True):
    """
    Check if a date is a working day
    Can be extended to include holiday calendar
    """
    if exclude_weekends and date_obj.weekday() >= 5:  # Saturday = 5, Sunday = 6
        return False

    # TODO: Add holiday calendar integration
    return True


def calculate_working_days(start_date, end_date, exclude_weekends=True):
    """
    Calculate number of working days between two dates
    """
    if start_date > end_date:
        return 0

    working_days = 0
    current_date = start_date

    while current_date <= end_date:
        if is_working_day(current_date, exclude_weekends):
            working_days += 1
        current_date += timezone.timedelta(days=1)

    return working_days


# Safe input parsing utilities
def safe_int_parse(value, default=None, min_value=None, max_value=None):
    """
    Safely parse integer from various input types
    Returns default if parsing fails or value is out of range
    """
    if value is None:
        return default

    try:
        result = int(value)

        if min_value is not None and result < min_value:
            return default
        if max_value is not None and result > max_value:
            return default

        return result
    except (ValueError, TypeError):
        return default


def safe_year_parse(year_input, default_current_year=True):
    """
    Safely parse year input with reasonable bounds
    Returns current year if parsing fails and default_current_year is True
    """
    current_year = get_current_date().year
    default = current_year if default_current_year else None

    return safe_int_parse(
        year_input,
        default=default,
        min_value=current_year - 10,
        max_value=current_year + 5
    )


def safe_user_id_parse(user_id_input):
    """
    Safely parse user ID input
    Returns None if invalid
    """
    return safe_int_parse(user_id_input, default=None, min_value=1)


def validate_request_params(request, param_configs):
    """
    Validate multiple request parameters at once

    param_configs = {
        'user_id': {'parser': safe_user_id_parse, 'required': False},
        'year': {'parser': safe_year_parse, 'required': False},
    }

    Returns dict of validated parameters and list of validation errors
    """
    validated_params = {}
    errors = []

    for param_name, config in param_configs.items():
        raw_value = request.GET.get(param_name) or request.POST.get(param_name)
        parser = config.get('parser')
        required = config.get('required', False)

        if required and not raw_value:
            errors.append(f"Parameter '{param_name}' is required")
            continue

        if parser and raw_value:
            parsed_value = parser(raw_value)
            if parsed_value is None and required:
                errors.append(f"Invalid value for parameter '{param_name}'")
            else:
                validated_params[param_name] = parsed_value
        elif raw_value:
            validated_params[param_name] = raw_value

    return validated_params, errors


def get_user_roles(user: User) -> List[str]:
    """Get all roles/groups for a user"""
    if not user.is_authenticated:
        return []
    return list(user.groups.values_list('name', flat=True))


def has_role(user: User, role: str) -> bool:
    """Check if user has a specific role"""
    if not user.is_authenticated:
        return False
    return user.groups.filter(name=role).exists()


def is_employee(user: User) -> bool:
    """Check if user is an Employee"""
    return has_role(user, Roles.EMPLOYEE)


def is_manager(user: User) -> bool:
    """Check if user is a Manager"""
    return has_role(user, Roles.MANAGER)


def is_hr(user: User) -> bool:
    """Check if user is HR"""
    return has_role(user, Roles.HR)


def is_admin(user: User) -> bool:
    """Check if user is Admin"""
    return has_role(user, Roles.ADMIN)


def is_finance(user: User) -> bool:
    """Check if user is Finance"""
    return has_role(user, Roles.FINANCE)


def get_user_hierarchy_level(user: User) -> int:
    """Get user's hierarchy level (higher number = higher authority)"""
    if is_admin(user):
        return 4
    elif is_hr(user):
        return 3
    elif is_manager(user):
        return 2
    elif is_employee(user):
        return 1
    else:
        return 0


def can_approve_leave(approver: User, requestor: User) -> bool:
    """
    Check if approver can approve requestor's leave based on hierarchy

    Approval hierarchy:
    - Employee -> Manager or HR
    - Manager -> HR or Admin
    - HR -> Admin
    - Admin -> HR (special case)
    """
    if not approver.is_authenticated or not requestor.is_authenticated:
        return False

    # Same user cannot approve their own leave
    if approver.id == requestor.id:
        return False

    requestor_roles = get_user_roles(requestor)
    approver_roles = get_user_roles(approver)

    # Employee leave approval
    if Roles.EMPLOYEE in requestor_roles:
        return (Roles.MANAGER in approver_roles or
                Roles.HR in approver_roles or
                Roles.ADMIN in approver_roles)

    # Manager leave approval
    elif Roles.MANAGER in requestor_roles:
        return (Roles.HR in approver_roles or
                Roles.ADMIN in approver_roles)

    # HR leave approval
    elif Roles.HR in requestor_roles:
        return Roles.ADMIN in approver_roles

    # Admin leave approval (special case - HR can approve)
    elif Roles.ADMIN in requestor_roles:
        return Roles.HR in approver_roles

    return False


def get_potential_approvers(requestor: User) -> List[User]:
    """Get list of users who can approve requestor's leave"""
    if not requestor.is_authenticated:
        return []

    requestor_roles = get_user_roles(requestor)
    potential_approvers = []

    # Employee leave - can be approved by Manager, HR, or Admin
    if Roles.EMPLOYEE in requestor_roles:
        managers = User.objects.filter(groups__name=Roles.MANAGER, is_active=True)
        hrs = User.objects.filter(groups__name=Roles.HR, is_active=True)
        admins = User.objects.filter(groups__name=Roles.ADMIN, is_active=True)
        potential_approvers = list(managers) + list(hrs) + list(admins)

    # Manager leave - can be approved by HR or Admin
    elif Roles.MANAGER in requestor_roles:
        hrs = User.objects.filter(groups__name=Roles.HR, is_active=True)
        admins = User.objects.filter(groups__name=Roles.ADMIN, is_active=True)
        potential_approvers = list(hrs) + list(admins)

    # HR leave - can be approved by Admin
    elif Roles.HR in requestor_roles:
        potential_approvers = list(User.objects.filter(groups__name=Roles.ADMIN, is_active=True))

    # Admin leave - can be approved by HR
    elif Roles.ADMIN in requestor_roles:
        potential_approvers = list(User.objects.filter(groups__name=Roles.HR, is_active=True))

    # Remove the requestor from potential approvers
    potential_approvers = [user for user in potential_approvers if user.id != requestor.id]

    return potential_approvers


def get_auto_approver(requestor: User) -> Optional[User]:
    """Get the first available auto-approver for a user"""
    potential_approvers = get_potential_approvers(requestor)
    return potential_approvers[0] if potential_approvers else None


def can_view_leave_request(user: User, leave_request) -> bool:
    """Check if user can view a specific leave request"""
    if not user.is_authenticated:
        return False

    # Users can always view their own requests
    if leave_request.user.id == user.id:
        return True

    # HR and Admin can view all requests
    if is_hr(user) or is_admin(user):
        return True

    # Managers can view requests from their subordinates (employees)
    if is_manager(user) and is_employee(leave_request.user):
        return True

    # Finance can view all requests for reporting
    if is_finance(user):
        return True

    return False


def can_edit_leave_request(user: User, leave_request) -> bool:
    """Check if user can edit a leave request"""
    if not user.is_authenticated:
        return False

    # Only pending requests can be edited
    if leave_request.status != 'Pending':
        return False

    # Users can edit their own pending requests
    if leave_request.user.id == user.id:
        return True

    # HR can edit any pending request
    if is_hr(user):
        return True

    return False


def can_cancel_leave_request(user: User, leave_request) -> bool:
    """Check if user can cancel a leave request"""
    if not user.is_authenticated:
        return False

    # Cannot cancel already cancelled or rejected requests
    if leave_request.status in ['Cancelled', 'Rejected']:
        return False

    # Users can cancel their own requests
    if leave_request.user.id == user.id:
        return True

    # HR can cancel any request
    if is_hr(user):
        return True

    return False


def can_manage_leave_policies(user: User) -> bool:
    """Check if user can manage leave policies"""
    return is_hr(user) or is_admin(user)


def can_manage_leave_types(user: User) -> bool:
    """Check if user can manage leave types"""
    return is_hr(user) or is_admin(user)


def can_view_team_leaves(user: User) -> bool:
    """Check if user can view team leave dashboard"""
    return is_manager(user) or is_hr(user) or is_admin(user)


def can_view_reports(user: User) -> bool:
    """Check if user can view leave reports"""
    return is_hr(user) or is_admin(user) or is_finance(user)


def can_bulk_allocate_leaves(user: User) -> bool:
    """Check if user can perform bulk leave allocation"""
    return is_hr(user) or is_admin(user)


def can_override_approval(user: User) -> bool:
    """Check if user can override leave approvals"""
    return is_hr(user) or is_admin(user)


# Decorators for view protection
def require_role(role: str):
    """Decorator to require specific role for view access"""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            if not has_role(request.user, role):
                raise PermissionDenied(f"Access denied. {role} role required.")
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def require_any_role(*roles):
    """Decorator to require any of the specified roles"""
    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            user_roles = get_user_roles(request.user)
            if not any(role in user_roles for role in roles):
                raise PermissionDenied(f"Access denied. One of these roles required: {', '.join(roles)}")
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def require_hr_or_admin(view_func):
    """Decorator for HR or Admin only views"""
    return require_any_role(Roles.HR, Roles.ADMIN)(view_func)


def require_manager_or_above(view_func):
    """Decorator for Manager, HR, or Admin views"""
    return require_any_role(Roles.MANAGER, Roles.HR, Roles.ADMIN)(view_func)


# Role setup utilities
def setup_default_roles():
    """Create default roles/groups if they don't exist"""
    for role in Roles.ALL_ROLES:
        Group.objects.get_or_create(name=role)


def assign_user_role(user: User, role: str) -> bool:
    """Assign a role to a user"""
    try:
        group = Group.objects.get(name=role)
        user.groups.add(group)
        return True
    except Group.DoesNotExist:
        return False


def remove_user_role(user: User, role: str) -> bool:
    """Remove a role from a user"""
    try:
        group = Group.objects.get(name=role)
        user.groups.remove(group)
        return True
    except Group.DoesNotExist:
        return False


def get_role_color(role: str) -> str:
    """Get color class for role badge display"""
    role_colors = {
        Roles.EMPLOYEE: 'bg-sky-100 text-sky-800',
        Roles.MANAGER: 'bg-amber-100 text-amber-800',
        Roles.HR: 'bg-emerald-100 text-emerald-800',
        Roles.ADMIN: 'bg-rose-100 text-rose-800',
        Roles.FINANCE: 'bg-lime-100 text-lime-800'
    }
    return role_colors.get(role, 'bg-gray-100 text-gray-800')


def validate_approval_hierarchy(leave_request) -> dict:
    """
    Validate if the approval follows correct hierarchy
    Returns validation result with status and message
    """
    if not leave_request.approver:
        return {'valid': True, 'message': 'No approver assigned yet'}

    if can_approve_leave(leave_request.approver, leave_request.user):
        return {'valid': True, 'message': 'Valid approval hierarchy'}
    else:
        return {
            'valid': False,
            'message': f'{leave_request.approver.get_full_name()} cannot approve leave for {leave_request.user.get_full_name()}'
        }
