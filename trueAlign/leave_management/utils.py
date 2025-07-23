"""
Role-based security utilities for leave management system
"""
from django.contrib.auth.models import Group, User
from django.core.exceptions import PermissionDenied
from functools import wraps
from typing import List, Optional


# Role constants
class Roles:
    EMPLOYEE = 'Employee'
    MANAGER = 'Manager'
    HR = 'HR'
    ADMIN = 'Admin'
    FINANCE = 'Finance'

    ALL_ROLES = [EMPLOYEE, MANAGER, HR, ADMIN, FINANCE]


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
