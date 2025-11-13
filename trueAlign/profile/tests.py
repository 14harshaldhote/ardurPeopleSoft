"""
Comprehensive test suite for the profile module
Tests all views, forms, utilities, and validations
"""
import json
from datetime import datetime, timedelta
from django.test import TestCase, Client
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.utils import timezone
from unittest.mock import patch, MagicMock
from trueAlign.models import UserDetails, OfficeLocation, UserActionLog, LayoutPreference
from trueAlign.profile.forms import UserDetailsCreateForm, UserDetailsUpdateForm, CSVImportForm, UserProfileForm
from trueAlign.profile.utilities import generate_employee_id, send_welcome_email


class ProfileUtilitiesTestCase(TestCase):
    """Test utility functions"""
    
    def setUp(self):
        self.office_location = OfficeLocation.objects.create(
            name="Test Office",
            city="Test City",
            state="Test State",
            is_active=True
        )
        self.group = Group.objects.create(name="Employee")
        self.finance_group = Group.objects.create(name="Finance")
        
    def test_generate_employee_id_betul_location(self):
        """Test employee ID generation for Betul location"""
        employee_id = generate_employee_id(work_location="Betul", group_id="1")
        current_year = str(datetime.now().year)[2:]
        self.assertTrue(employee_id.startswith(f"ATS{current_year}-"))
        
    def test_generate_employee_id_pune_location(self):
        """Test employee ID generation for Pune location"""
        employee_id = generate_employee_id(work_location="Pune", group_id="1")
        current_year = str(datetime.now().year)[2:]
        self.assertTrue(employee_id.startswith(f"AT{current_year}-"))
        
    def test_generate_employee_id_reserved_role(self):
        """Test employee ID generation for reserved roles (Finance/Management)"""
        employee_id = generate_employee_id(work_location="Betul", group_id="7")  # Finance group
        # Should get ID in range 1-15 or 301-400
        id_num = int(employee_id.split('-')[-1])
        self.assertTrue((1 <= id_num <= 15) or (301 <= id_num <= 400))
        
    @patch('trueAlign.profile.utilities.EmailMultiAlternatives')
    def test_send_welcome_email_success(self, mock_email):
        """Test successful welcome email sending"""
        user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            first_name="Test",
            last_name="User"
        )
        
        mock_email_instance = MagicMock()
        mock_email.return_value = mock_email_instance
        
        result = send_welcome_email(user, "password123")
        
        self.assertTrue(result)
        mock_email.assert_called_once()
        mock_email_instance.send.assert_called_once()


class ProfileFormsTestCase(TestCase):
    """Test all form validations and functionality"""
    
    def setUp(self):
        self.office_location = OfficeLocation.objects.create(
            name="Test Office",
            city="Test City", 
            state="Test State",
            is_active=True
        )
        self.group = Group.objects.create(name="Employee")
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )
        
    def test_user_details_create_form_valid(self):
        """Test UserDetailsCreateForm with valid data"""
        form_data = {
            'first_name': 'John',
            'last_name': 'Doe',
            'email': 'john.doe@example.com',
            'password': 'Welcome@123',
            'group': self.group.id,
            'role': 'employee',
            'dob': '1990-01-01',
            'gender': 'Male',
            'contact_number_primary': '1234567890',
            'employee_type': 'full_time',
            'employment_status': 'active',
            'office_location': self.office_location.id,
            'hire_date': '2023-01-01'
        }
        
        form = UserDetailsCreateForm(data=form_data)
        self.assertTrue(form.is_valid(), f"Form errors: {form.errors}")
        
    def test_user_details_create_form_duplicate_email(self):
        """Test UserDetailsCreateForm with duplicate email"""
        form_data = {
            'first_name': 'John',
            'last_name': 'Doe', 
            'email': 'test@example.com',  # Same as existing user
            'password': 'Welcome@123',
            'group': self.group.id,
            'role': 'employee'
        }
        
        form = UserDetailsCreateForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)
        
    def test_user_profile_form_valid(self):
        """Test UserProfileForm with valid data"""
        user_details, created = UserDetails.objects.get_or_create(user=self.user)
        
        form_data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'dob': '1990-01-01',
            'gender': 'Male',
            'contact_number_primary': '9876543210'
        }
        
        form = UserProfileForm(data=form_data, instance=user_details, user=self.user)
        self.assertTrue(form.is_valid())
        
    def test_csv_import_form_invalid_file(self):
        """Test CSVImportForm with invalid file type"""
        from django.core.files.uploadedfile import SimpleUploadedFile
        
        invalid_file = SimpleUploadedFile("test.txt", b"invalid content", content_type="text/plain")
        
        form_data = {
            'group': self.group.id,
            'office_location': self.office_location.id
        }
        
        form = CSVImportForm(data=form_data, files={'csv_file': invalid_file})
        self.assertFalse(form.is_valid())
        self.assertIn('csv_file', form.errors)


class ProfileViewsTestCase(TestCase):
    """Test all view functions and class-based views"""
    
    def setUp(self):
        self.client = Client()
        self.office_location = OfficeLocation.objects.create(
            name="Test Office",
            city="Test City",
            state="Test State", 
            is_active=True
        )
        self.group = Group.objects.create(name="Employee")
        self.hr_group = Group.objects.create(name="HR")
        
        # Create regular user
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )
        # Use get_or_create to avoid duplicate entries
        self.user_details, created = UserDetails.objects.get_or_create(
            user=self.user,
            defaults={
                'office_location': self.office_location,
                'employment_status': 'active'
            }
        )
        
        # Create HR user
        self.hr_user = User.objects.create_user(
            username="hruser",
            email="hr@example.com", 
            password="hrpass123"
        )
        self.hr_user.groups.add(self.hr_group)
        self.hr_details, created = UserDetails.objects.get_or_create(
            user=self.hr_user,
            defaults={
                'employee_type': 'hr',
                'employment_status': 'active'
            }
        )
        
    def test_hr_dashboard_access_hr_user(self):
        """Test HR dashboard access for HR user"""
        self.client.login(username="hruser", password="hrpass123")
        response = self.client.get(reverse('profile:dashboard'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "HR Dashboard")
        
    def test_hr_dashboard_access_regular_user(self):
        """Test HR dashboard access denied for regular user"""
        self.client.login(username="testuser", password="testpass123")
        response = self.client.get(reverse('profile:dashboard'))
        self.assertEqual(response.status_code, 302)  # Redirect
        
    def test_user_list_view(self):
        """Test user list view"""
        self.client.login(username="hruser", password="hrpass123")
        response = self.client.get(reverse('profile:user-list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "User Management")
        
    def test_user_detail_view(self):
        """Test user detail view"""
        self.client.login(username="hruser", password="hrpass123")
        response = self.client.get(reverse('profile:user-detail', kwargs={'pk': self.user.id}))
        self.assertEqual(response.status_code, 200)
        
    def test_user_create_view_get(self):
        """Test user create view GET request"""
        self.client.login(username="hruser", password="hrpass123")
        response = self.client.get(reverse('profile:user-create'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create New User")
        
    def test_user_create_view_post_valid(self):
        """Test user create view POST with valid data"""
        self.client.login(username="hruser", password="hrpass123")
        
        post_data = {
            'first_name': 'New',
            'last_name': 'User',
            'email': 'newuser@example.com',
            'password': 'Welcome@123',
            'group': self.group.id,
            'role': 'employee',
            'dob': '1990-01-01',
            'gender': 'Male',
            'employee_type': 'full_time',
            'employment_status': 'probation',
            'office_location': self.office_location.id,
            'hire_date': '2023-01-01'
        }
        
        response = self.client.post(reverse('profile:user-create'), data=post_data)
        self.assertEqual(response.status_code, 302)  # Redirect on success
        
        # Verify user was created
        new_user = User.objects.get(email='newuser@example.com')
        self.assertEqual(new_user.first_name, 'New')
        
    def test_user_update_view(self):
        """Test user update view"""
        self.client.login(username="hruser", password="hrpass123")
        
        post_data = {
            'first_name': 'Updated',
            'last_name': 'Name',
            'email': 'updated@example.com',
            'group': self.group.id,
            'role': 'employee',
            'employment_status': 'active'
        }
        
        response = self.client.post(
            reverse('profile:user-update', kwargs={'pk': self.user.id}),
            data=post_data
        )
        self.assertEqual(response.status_code, 302)
        
    def test_change_user_status(self):
        """Test changing user employment status"""
        self.client.login(username="hruser", password="hrpass123")
        
        response = self.client.post(
            reverse('profile:change-status', kwargs={'pk': self.user.id}),
            data={'status': 'inactive'}
        )
        self.assertEqual(response.status_code, 302)
        
        # Verify status changed
        self.user_details.refresh_from_db()
        self.assertEqual(self.user_details.employment_status, 'inactive')
        
    def test_reset_user_password(self):
        """Test password reset functionality"""
        self.client.login(username="hruser", password="hrpass123")
        
        response = self.client.post(
            reverse('profile:reset-password', kwargs={'pk': self.user.id}),
            data={'new_password': 'NewPassword123'}
        )
        self.assertEqual(response.status_code, 302)
        
    def test_my_profile_view(self):
        """Test my profile view"""
        self.client.login(username="testuser", password="testpass123")
        response = self.client.get(reverse('profile:my-profile'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "My Profile")
        
    def test_export_users_csv(self):
        """Test CSV export functionality"""
        self.client.login(username="hruser", password="hrpass123")
        response = self.client.get(reverse('profile:export-csv'))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')
        
    def test_dashboard_analytics_api(self):
        """Test dashboard analytics API"""
        self.client.login(username="hruser", password="hrpass123")
        response = self.client.get(reverse('profile:dashboard-analytics-api'))
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.content)
        self.assertIn('status_distribution', data)
        self.assertIn('location_distribution', data)
        
    def test_dashboard_stats_api(self):
        """Test dashboard stats API"""
        self.client.login(username="hruser", password="hrpass123")
        response = self.client.get(reverse('profile:dashboard-stats-api'))
        self.assertEqual(response.status_code, 200)
        
        data = json.loads(response.content)
        self.assertIn('total_users', data)
        self.assertIn('active_users', data)


class ProfileModelValidationTestCase(TestCase):
    """Test model validations and constraints"""
    
    def setUp(self):
        self.user = User.objects.create_user(
            username="testuser",
            email="test@example.com",
            password="testpass123"
        )
        self.office_location = OfficeLocation.objects.create(
            name="Test Office",
            city="Test City",
            state="Test State",
            is_active=True
        )
        
    def test_user_details_creation(self):
        """Test UserDetails model creation"""
        user_details, created = UserDetails.objects.get_or_create(
            user=self.user,
            defaults={
                'dob': datetime(1990, 1, 1).date(),
                'gender': 'Male',
                'contact_number_primary': '1234567890',
                'employee_type': 'full_time',
                'employment_status': 'active',
                'office_location': self.office_location
            }
        )
        
        self.assertEqual(user_details.user, self.user)
        self.assertEqual(user_details.gender, 'Male')
        self.assertEqual(user_details.employment_status, 'active')
        
    def test_user_action_log_creation(self):
        """Test UserActionLog model creation"""
        action_log = UserActionLog.objects.create(
            user=self.user,
            action_type='create',
            action_by=self.user,
            details='Test action'
        )
        
        self.assertEqual(action_log.user, self.user)
        self.assertEqual(action_log.action_type, 'create')
        self.assertIsNotNone(action_log.timestamp)


class ProfilePermissionTestCase(TestCase):
    """Test permission and access control"""
    
    def setUp(self):
        self.client = Client()
        
        # Create users with different roles
        self.regular_user = User.objects.create_user(
            username="regular",
            email="regular@example.com",
            password="pass123"
        )
        
        self.hr_user = User.objects.create_user(
            username="hruser", 
            email="hr@example.com",
            password="pass123"
        )
        
        self.admin_user = User.objects.create_superuser(
            username="admin",
            email="admin@example.com", 
            password="pass123"
        )
        
        # Create HR group and add HR user
        hr_group = Group.objects.create(name="HR")
        self.hr_user.groups.add(hr_group)
        
    def test_hr_only_views_regular_user_denied(self):
        """Test HR-only views deny access to regular users"""
        self.client.login(username="regular", password="pass123")
        
        hr_only_urls = [
            'profile:dashboard',
            'profile:user-create', 
            'profile:bulk-upload',
            'profile:audit-logs'
        ]
        
        for url_name in hr_only_urls:
            response = self.client.get(reverse(url_name))
            self.assertIn(response.status_code, [302, 403])  # Redirect or forbidden
            
    def test_hr_views_hr_user_allowed(self):
        """Test HR views allow access to HR users"""
        self.client.login(username="hruser", password="pass123")
        
        response = self.client.get(reverse('profile:dashboard'))
        self.assertEqual(response.status_code, 200)
        
    def test_admin_user_access(self):
        """Test admin user has access to all views"""
        self.client.login(username="admin", password="pass123")
        
        response = self.client.get(reverse('profile:dashboard'))
        self.assertEqual(response.status_code, 200)


class ProfileIntegrationTestCase(TestCase):
    """Integration tests for complete workflows"""
    
    def setUp(self):
        self.client = Client()
        self.office_location = OfficeLocation.objects.create(
            name="Test Office",
            city="Test City",
            state="Test State",
            is_active=True
        )
        self.group = Group.objects.create(name="Employee")
        
        # Create HR user
        self.hr_user = User.objects.create_user(
            username="hruser",
            email="hr@example.com",
            password="hrpass123"
        )
        hr_group = Group.objects.create(name="HR")
        self.hr_user.groups.add(hr_group)
        
    def test_complete_user_creation_workflow(self):
        """Test complete user creation workflow"""
        self.client.login(username="hruser", password="hrpass123")
        
        # Step 1: Access user creation form
        response = self.client.get(reverse('profile:user-create'))
        self.assertEqual(response.status_code, 200)
        
        # Step 2: Submit user creation form
        post_data = {
            'first_name': 'Integration',
            'last_name': 'Test',
            'email': 'integration@example.com',
            'password': 'Welcome@123',
            'group': self.group.id,
            'role': 'employee',
            'dob': '1990-01-01',
            'gender': 'Male',
            'employee_type': 'full_time',
            'employment_status': 'probation',
            'office_location': self.office_location.id,
            'hire_date': '2023-01-01'
        }
        
        response = self.client.post(reverse('profile:user-create'), data=post_data)
        self.assertEqual(response.status_code, 302)
        
        # Step 3: Verify user was created
        new_user = User.objects.get(email='integration@example.com')
        self.assertEqual(new_user.first_name, 'Integration')
        
        # Step 4: Verify UserDetails was created
        user_details = UserDetails.objects.get(user=new_user)
        self.assertEqual(user_details.employment_status, 'probation')
        
        # Step 5: Verify user appears in user list
        response = self.client.get(reverse('profile:user-list'))
        self.assertContains(response, 'Integration Test')
        
    def test_user_profile_update_workflow(self):
        """Test user profile update workflow"""
        # Create a user first
        user = User.objects.create_user(
            username="updatetest",
            email="update@example.com",
            password="pass123"
        )
        user_details, created = UserDetails.objects.get_or_create(
            user=user,
            defaults={'employment_status': 'active'}
        )
        
        self.client.login(username="hruser", password="hrpass123")
        
        # Update user profile
        post_data = {
            'first_name': 'Updated',
            'last_name': 'User',
            'email': 'updated@example.com',
            'group': self.group.id,
            'role': 'employee',
            'employment_status': 'active',
            'contact_number_primary': '9876543210'
        }
        
        response = self.client.post(
            reverse('profile:user-update', kwargs={'pk': user.id}),
            data=post_data
        )
        self.assertEqual(response.status_code, 302)
        
        # Verify updates
        user.refresh_from_db()
        self.assertEqual(user.first_name, 'Updated')
        self.assertEqual(user.email, 'updated@example.com')
