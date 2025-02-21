from django.contrib.auth.models import Group

def is_admin(request):
    """Check if the user belongs to the 'Admin' group."""
    return {'is_admin': request.user.groups.filter(name="Admin").exists()} if request.user.is_authenticated else {'is_admin': False}

def is_manager(request):
    """Check if the user belongs to the 'Manager' group."""
    return {'is_manager': request.user.groups.filter(name="Manager").exists()} if request.user.is_authenticated else {'is_manager': False}

def is_employee(request):
    """Check if the user belongs to the 'Employee' group."""
    return {'is_employee': request.user.groups.filter(name="Employee").exists()} if request.user.is_authenticated else {'is_employee': False}

def is_hr(request):
    """Check if the user belongs to the 'HR' group."""
    return {'is_hr': request.user.groups.filter(name="HR").exists()} if request.user.is_authenticated else {'is_hr': False}

def is_backoffice(request):
    """Check if the user belongs to the 'Backoffice' group."""
    return {'is_backoffice': request.user.groups.filter(name="Backoffice").exists()} if request.user.is_authenticated else {'is_backoffice': False}

def is_client(request):
    """Check if the user belongs to the 'Client' group."""
    return {'is_client': request.user.groups.filter(name="Client").exists()} if request.user.is_authenticated else {'is_client': False}

def is_finance(request):
    """Check if the user belongs to the 'Finance' group."""
    return {'is_finance': request.user.groups.filter(name="Finance").exists()} if request.user.is_authenticated else {'is_finance': False}

def is_management(request):
    """Check if the user belongs to the 'Management' group."""
    return {'is_management': request.user.groups.filter(name="Management").exists()} if request.user.is_authenticated else {'is_management': False}
