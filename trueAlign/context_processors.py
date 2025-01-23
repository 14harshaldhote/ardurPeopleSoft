from django.contrib.auth.models import Group

def is_admin(request):
    """Check if the user belongs to the 'Admin' group."""
    if hasattr(request, 'user') and request.user.is_authenticated:
        try:
            is_admin = request.user.groups.filter(name="Admin").exists()
        except AttributeError:
            is_admin = False
    else:
        is_admin = False
    return {'is_admin': is_admin}

def is_manager(request):
    """Check if the user belongs to the 'Manager' group."""
    if hasattr(request, 'user') and request.user.is_authenticated:
        try:
            is_manager = request.user.groups.filter(name="Manager").exists()
        except AttributeError:
            is_manager = False
    else:
        is_manager = False
    return {'is_manager': is_manager}

def is_employee(request):
    """Check if the user belongs to the 'Employee' group."""
    if hasattr(request, 'user') and request.user.is_authenticated:
        try:
            is_employee = request.user.groups.filter(name="Employee").exists()
        except AttributeError:
            is_employee = False
    else:
        is_employee = False
    return {'is_employee': is_employee}

def is_hr(request):
    """Check if the user belongs to the 'HR' group."""
    if hasattr(request, 'user') and request.user.is_authenticated:
        try:
            is_hr = request.user.groups.filter(name="HR").exists()
        except AttributeError:
            is_hr = False
    else:
        is_hr = False
    return {'is_hr': is_hr}