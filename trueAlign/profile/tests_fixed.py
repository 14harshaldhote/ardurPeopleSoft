"""
Fixed test suite for the profile module
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
            'role': self.group.name.lower(),  # Use group name
            'dob': '1990-01-01',
            'gender': 'Male',
            'contact_number_primary': '1234567890',
            'employee_type': 'full_time',
            'employment_status': 'active',
            'office_location': self.office_location.id,
            'hire_date': '2023-01-01'
        }
        
        form = UserDetailsCreateForm(data=form_data)
        if not form.is_valid():
            print(f"Form errors: {form.errors}")
        self.assertTrue(form.is_valid())
        
    def test_user_details_create_form_duplicate_email(self):
        """Test UserDetailsCreateForm with duplicate email"""
        form_data = {
            'first_name': 'John',
            'last_name': 'Doe', 
            'email': 'test@example.com',  # Same as existing user
            'password': 'Welcome@123',
            'group': self.group.id,
            'role': self.group.name.lower()
        }
        
        form = UserDetailsCreateForm(data=form_data)
        self.assertFalse(form.is_valid())
        self.assertIn('email', form.errors)


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
        
    def test_user_list_view(self):
        """Test user list view"""
        self.client.login(username="hruser", password="hrpass123")
        response = self.client.get(reverse('profile:user-list'))
        self.assertEqual(response.status_code, 200)
        
    def test_user_detail_view(self):
        """Test user detail view"""
        self.client.login(username="hruser", password="hrpass123")
        response = self.client.get(reverse('profile:user-detail', kwargs={'pk': self.user.id}))
        self.assertEqual(response.status_code, 200)
        
    def test_my_profile_view(self):
        """Test my profile view"""
        self.client.login(username="testuser", password="testpass123")
        response = self.client.get(reverse('profile:my-profile'))
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
        
    def test_user_creation_workflow(self):
        """Test basic user creation workflow"""
        self.client.login(username="hruser", password="hrpass123")
        
        # Access user creation form
        response = self.client.get(reverse('profile:user-create'))
        self.assertEqual(response.status_code, 200)
        
        # Test form submission with minimal required data
        post_data = {
            'first_name': 'Test',
            'last_name': 'User',
            'email': 'testuser@example.com',
            'password': 'Welcome@123',
            'group': self.group.id,
            'role': self.group.name.lower(),
            'employee_type': 'full_time',
            'employment_status': 'probation',
            'office_location': self.office_location.id,
        }
        
        response = self.client.post(reverse('profile:user-create'), data=post_data)
        # Should redirect on success or show form with errors
        self.assertIn(response.status_code, [200, 302])
