"""
Base Test Infrastructure

Provides base classes and utilities for integration tests including
authentication helpers, test data factories, and common assertion methods.
"""

from django.test import TestCase, Client
from django.contrib.auth.models import User
from django.urls import reverse
from datetime import datetime, timedelta
import time

from .fixtures import MasterDataFixtures
from .logger import get_test_logger


class TestUserFactory:
    """
    Factory for creating test users with specific roles.
    """
    
    @staticmethod
    def create_user(username, role, email=None, password='testpass123', **kwargs):
        """
        Create a test user with the specified role.
        
        Args:
            username: Username for the user
            role: Role name ('Admin', 'HR', 'Manager', 'Employee', 'Management')
            email: Email address (auto-generated if not provided)
            password: Password (default: 'testpass123')
            **kwargs: Additional user fields (first_name, last_name, etc.)
        
        Returns:
            User object
        """
        from django.contrib.auth.models import Group
        
        if email is None:
            email = f"{username}@test.com"
        
        # Create user
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                'email': email,
                'first_name': kwargs.get('first_name', username.title()),
                'last_name': kwargs.get('last_name', 'Test'),
                'is_active': True,
                'is_staff': role.lower() in ['admin', 'hr']
            }
        )
        
        if created:
            user.set_password(password)
            user.save()
        
        # Assign role (group)
        group = Group.objects.get(name=role)
        user.groups.clear()
        user.groups.add(group)
        
        # Note: UserProfile creation skipped for integration tests
        # Tests focus on authentication, sessions, and RBAC
        # Profile fields would require complex model dependencies
        
        return user
    
    @classmethod
    def create_test_users(cls, fixtures):
        """
        Create all standard test users (simplified for testing).
        
        Args:
            fixtures: Dictionary with groups
        
        Returns:
            Dictionary of created users
        """
        users = {}
        
        # Admin user
        users['admin'] = cls.create_user(
            username='admin_01',
            role='Admin'
        )
        
        # HR user
        users['hr'] = cls.create_user(
            username='hr_01',
            role='HR'
        )
        
        # Manager user
        users['manager'] = cls.create_user(
            username='manager_01',
            role='Manager'
        )
        
        # Employee users
        users['employee_01'] = cls.create_user(
            username='employee_01',
            role='Employee'
        )
        
        users['employee_02'] = cls.create_user(
            username='employee_02',
            role='Employee'
        )
        
        # Management (read-only) user
        users['management'] = cls.create_user(
            username='management_01',
            role='Management'
        )
        
        return users


class IntegrationTestCase(TestCase):
    """
    Base class for all integration tests.
    Provides common setup, utilities, and helper methods.
    """
    
    @classmethod
    def setUpClass(cls):
        """Setup test class - runs once before all tests in the class."""
        super().setUpClass()
        cls.logger = get_test_logger()
        cls.test_start_time = None
    
    def setUp(self):
        """Setup before each test method."""
        # Create HTTP client
        self.client = Client()
        
        # Setup master data fixtures
        self.fixtures = MasterDataFixtures.setup_all_fixtures()
        
        # Create test users
        self.users = TestUserFactory.create_test_users(self.fixtures)
        
        # Track test start time
        self.test_start_time = time.time()
        
        # Default test user (employee)
        self.current_user = self.users['employee_01']
    
    def tearDown(self):
        """Cleanup after each test method."""
        # Calculate test duration
        if self.test_start_time:
            duration = time.time() - self.test_start_time
        else:
            duration = 0
        
        # Log test completion (will be called by individual tests)
        # self.test_start_time = None
    
    # ===== Authentication Helpers =====
    
    def login_as(self, user):
        """
        Login as a specific user.
        
        Args:
            user: User object or username string
        
        Returns:
            Boolean indicating login success
        """
        if isinstance(user, str):
            user = self.users.get(user)
        
        if user is None:
            self.logger.log_error(f"User not found for login")
            return False
        
        success = self.client.login(username=user.username, password='testpass123')
        if success:
            self.current_user = user
            self.logger.log_step(0, f"Logged in as {user.username} ({self.get_user_role(user)})")
        else:
            self.logger.log_error(f"Failed to login as {user.username}")
        
        return success
    
    def logout(self):
        """Logout current user."""
        self.client.logout()
        self.logger.log_step(0, f"Logged out")
        self.current_user = None
    
    def get_user_role(self, user):
        """Get the role (group) name of a user."""
        group = user.groups.first()
        return group.name if group else "No Role"
    
    # ===== HTTP Request Helpers =====
    
    def get(self, url_name, *args, **kwargs):
        """
        Make a GET request.
        
        Args:
            url_name: URL name or full path
            *args: URL args
            **kwargs: URL kwargs or query params
        
        Returns:
            Response object
        """
        if url_name.startswith('/'):
            url = url_name
        else:
            url_kwargs = {k: v for k, v in kwargs.items() if not k.startswith('_')}
            url = reverse(url_name, args=args, kwargs=url_kwargs)
        
        query_params = kwargs.get('_query_params', {})
        
        self.logger.log_api_request('GET', url, query_params)
        response = self.client.get(url, data=query_params)
        self.logger.log_api_response(response.status_code)
        
        return response
    
    def post(self, url_name, data=None, *args, **kwargs):
        """
        Make a POST request.
        
        Args:
            url_name: URL name or full path
            data: POST data
            *args: URL args
            **kwargs: URL kwargs
        
        Returns:
            Response object
        """
        if url_name.startswith('/'):
            url = url_name
        else:
            url = reverse(url_name, args=args, kwargs=kwargs)
        
        self.logger.log_api_request('POST', url, data)
        response = self.client.post(url, data=data)
        self.logger.log_api_response(response.status_code, response.content[:200] if hasattr(response, 'content') else None)
        
        return response
    
    # ===== Database Helpers =====
    
    def create_object(self, model_class, **kwargs):
        """
        Create a database object and log it.
        
        Args:
            model_class: Model class
            **kwargs: Field values
        
        Returns:
            Created object
        """
        obj = model_class.objects.create(**kwargs)
        self.logger.log_database_change(
            model_class.__name__,
            'CREATE',
            obj.pk,
            str(kwargs)
        )
        return obj
    
    def update_object(self, obj, **kwargs):
        """
        Update a database object and log it.
        
        Args:
            obj: Object to update
            **kwargs: Fields to update
        
        Returns:
            Updated object
        """
        # Use QuerySet.update() to bypass model validation
        model_class = obj.__class__
        model_class.objects.filter(pk=obj.pk).update(**kwargs)
        obj.refresh_from_db()
        
        self.logger.log_database_change(
            obj.__class__.__name__,
            'UPDATE',
            obj.pk,
            str(kwargs)
        )
        return obj
    
    # ===== Assertion Helpers =====
    
    def assert_status_code(self, response, expected_code, message=None):
        """Assert HTTP status code."""
        passed = response.status_code == expected_code
        self.logger.log_assertion(
            'HTTP Status Code',
            expected_code,
            response.status_code,
            passed
        )
        
        if not passed and message:
            self.logger.log_error(message)
        
        self.assertEqual(response.status_code, expected_code, message)
    
    def assert_database_count(self, model_class, expected_count, filters=None):
        """Assert database record count."""
        if filters:
            actual_count = model_class.objects.filter(**filters).count()
        else:
            actual_count = model_class.objects.count()
        
        passed = actual_count == expected_count
        self.logger.log_assertion(
            f'{model_class.__name__} Count',
            expected_count,
            actual_count,
            passed
        )
        
        self.assertEqual(actual_count, expected_count)
    
    def assert_object_exists(self, model_class, **filters):
        """Assert that an object exists in database."""
        exists = model_class.objects.filter(**filters).exists()
        self.logger.log_assertion(
            f'{model_class.__name__} Exists',
            True,
            exists,
            exists
        )
        
        self.assertTrue(exists, f"{model_class.__name__} with filters {filters} does not exist")
    
    def assert_object_field(self, obj, field_name, expected_value):
        """Assert object field value."""
        obj.refresh_from_db()  # Refresh to get latest DB value
        actual_value = getattr(obj, field_name)
        passed = actual_value == expected_value
        
        self.logger.log_assertion(
            f'{obj.__class__.__name__}.{field_name}',
            expected_value,
            actual_value,
            passed
        )
        
        self.assertEqual(actual_value, expected_value)
    
    def assert_notification_sent(self, recipient, notification_type, module):
        """Assert that a notification was sent."""
        from trueAlign.models import Notification
        
        exists = Notification.objects.filter(
            user=recipient,
            notification_type=notification_type
        ).exists()
        
        if exists:
            self.logger.log_notification_triggered(notification_type, recipient.username, module)
        
        self.logger.log_assertion(
            f'Notification Sent to {recipient.username}',
            True,
            exists,
            exists
        )
        
        self.assertTrue(exists, f"Notification '{notification_type}' not sent to {recipient.username}")
    
    def assert_access_denied(self, response, message=None):
        """Assert that access was denied (403, redirect to login, or 404)."""
        # Accept 404 for URLs that don't exist for unauthorized users
        passed = response.status_code in [403, 302, 404]
        
        self.logger.log_assertion(
            'Access Denied',
            '403, 302, or 404',
            response.status_code,
            passed
        )
        
        self.assertIn(response.status_code, [403, 302, 404], message or "Access should be denied")
    
    def assert_cross_module_integration(self, module_from, module_to, interaction_type, validation_func):
        """
        Assert cross-module integration.
        
        Args:
            module_from: Source module name
            module_to: Target module name
            interaction_type: Type of interaction
            validation_func: Function that returns True if integration works
        """
        result = validation_func()
        
        self.logger.log_cross_module_interaction(
            module_from,
            module_to,
            interaction_type,
            f"Validation: {result}"
        )
        
        self.assertTrue(result, f"Cross-module integration failed: {module_from} → {module_to}")
    
    # ===== Security Helpers =====
    
    def assert_role_can_access(self, role, url_name, *args, **kwargs):
        """Assert that a role can access a URL."""
        user = self.users.get(role.lower())
        if not user:
            self.fail(f"User with role {role} not found")
        
        self.login_as(user)
        response = self.get(url_name, *args, **kwargs)
        
        allowed = response.status_code == 200
        self.logger.log_security_check('URL Access', role, url_name, allowed)
        
        self.assert_status_code(response, 200, f"{role} should have access to {url_name}")
        self.logout()
    
    def assert_role_cannot_access(self, role, url_name, *args, **kwargs):
        """Assert that a role cannot access a URL."""
        user = self.users.get(role.lower())
        if not user:
            self.fail(f"User with role {role} not found")
        
        self.login_as(user)
        response = self.get(url_name, *args, **kwargs)
        
        denied = response.status_code in [403, 302, 404]
        self.logger.log_security_check('URL Access Denied', role, url_name, not denied)
        
        self.assert_access_denied(response, f"{role} should NOT have access to {url_name}")
        self.logout()
    
    # ===== Test Lifecycle Helpers =====
    
    def log_test_start(self, test_case_id, module_name, roles, description):
        """Log the start of a test case."""
        self.logger.log_test_start(test_case_id, module_name, roles, description)
    
    def log_test_end(self, test_case_id, passed=True):
        """Log the end of a test case."""
        duration = time.time() - self.test_start_time if self.test_start_time else 0
        self.logger.log_test_end(test_case_id, passed, duration)
