import logging
from django.contrib.auth.mixins import UserPassesTestMixin, LoginRequiredMixin
from django.shortcuts import redirect
from django.contrib import messages
from django.urls import reverse_lazy

logger = logging.getLogger(__name__)

class RoleRequiredMixin(LoginRequiredMixin, UserPassesTestMixin):
    """
    Base mixin for role-based access control with logging.
    """
    role_name = "User"

    def test_func(self):
        raise NotImplementedError("Subclasses must implement test_func")

    def handle_no_permission(self):
        # Log unauthorized access attempt
        user = self.request.user
        path = self.request.path
        ip = self.request.META.get('REMOTE_ADDR')
        
        logger.warning(
            f"Unauthorized access attempt by user {user} (ID: {user.id}) to {path} from IP {ip}. "
            f"Required role: {self.role_name}"
        )
        
        messages.error(self.request, f"You do not have permission to access this page. Required role: {self.role_name}")
        
        # Redirect to a safe page (e.g., home or dashboard)
        return redirect('leave_management:employee_dashboard')

class AdminRequiredMixin(RoleRequiredMixin):
    role_name = "Admin"
    
    def test_func(self):
        user = self.request.user
        # Logic matching context_processors.py but allowing superuser
        return user.is_authenticated and (user.groups.filter(name="Admin").exists() or user.is_superuser)

class HRRequiredMixin(RoleRequiredMixin):
    role_name = "HR"
    
    def test_func(self):
        user = self.request.user
        # Logic matching context_processors.py but allowing Admin/Superuser as per requirements
        return user.is_authenticated and (
            user.groups.filter(name="HR").exists() or 
            user.groups.filter(name="Admin").exists() or 
            user.is_superuser
        )

class ManagerRequiredMixin(RoleRequiredMixin):
    role_name = "Manager"
    
    def test_func(self):
        user = self.request.user
        # Logic matching context_processors.py
        return user.is_authenticated and user.groups.filter(name="Manager").exists()

class EmployeeRequiredMixin(RoleRequiredMixin):
    role_name = "Employee"
    
    def test_func(self):
        user = self.request.user
        # Allow all authenticated users - Admin, HR, Manager, and Employee can all apply for leave
        # This allows everyone to use employee features (apply leave, view own leaves)
        return user.is_authenticated and (
            user.groups.filter(name__in=["Employee", "Manager", "HR", "Admin"]).exists() or
            user.is_superuser
        )
