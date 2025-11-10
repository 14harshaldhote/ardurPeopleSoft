"""
Test cases for Appraisal Views
Tests all views, forms, permissions, and user interactions
"""
import json
from datetime import date
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.files.uploadedfile import SimpleUploadedFile

from trueAlign.models import (
    Appraisal, AppraisalItem, AppraisalAttachment, AppraisalWorkflow
)

User = get_user_model()


class AppraisalListViewTest(TestCase):
    """Test appraisal list view"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.url = reverse('appraisal:appraisal_list')
        
        # Create groups
        self.manager_group = Group.objects.create(name='Manager')
        self.hr_group = Group.objects.create(name='HR')
        
        # Create users
        self.employee = User.objects.create_user(
            username='employee', password='test123'
        )
        self.manager = User.objects.create_user(
            username='manager', password='test123'
        )
        self.manager.groups.add(self.manager_group)
        
        self.hr_user = User.objects.create_user(
            username='hr_user', password='test123'
        )
        self.hr_user.groups.add(self.hr_group)
        
        # Create appraisals
        self.employee_appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='Employee Appraisal',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status='draft'
        )
        
        self.submitted_appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='Submitted Appraisal',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status='submitted'
        )
    
    def test_list_view_requires_login(self):
        """Test that list view requires authentication"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)  # Redirect to login
    
    def test_employee_sees_own_appraisals(self):
        """Test employee sees only their appraisals"""
        self.client.login(username='employee', password='test123')
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Employee Appraisal')
        self.assertContains(response, 'Submitted Appraisal')
    
    def test_manager_sees_submitted_appraisals(self):
        """Test manager sees appraisals assigned to them with submitted status"""
        self.client.login(username='manager', password='test123')
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Submitted Appraisal')
        self.assertNotContains(response, 'Employee Appraisal')  # Draft not shown
    
    def test_hr_sees_hr_review_appraisals(self):
        """Test HR sees appraisals in HR review status"""
        hr_appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='HR Review Appraisal',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status='hr_review'
        )
        
        self.client.login(username='hr_user', password='test123')
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'HR Review Appraisal')


class AppraisalDetailViewTest(TestCase):
    """Test appraisal detail view"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        self.employee = User.objects.create_user(
            username='employee', password='test123'
        )
        self.manager = User.objects.create_user(
            username='manager', password='test123'
        )
        self.other_user = User.objects.create_user(
            username='other', password='test123'
        )
        
        self.appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='Test Appraisal',
            overview='Test overview',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status='draft'
        )
        
        self.item = AppraisalItem.objects.create(
            appraisal=self.appraisal,
            category='achievement',
            title='Test Achievement',
            description='Test description',
            employee_rating=4
        )
        
        self.url = reverse('appraisal:appraisal_detail', kwargs={'pk': self.appraisal.pk})
    
    def test_detail_view_requires_login(self):
        """Test that detail view requires authentication"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
    
    def test_employee_can_view_own_appraisal(self):
        """Test employee can view their own appraisal"""
        self.client.login(username='employee', password='test123')
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Appraisal')
        self.assertContains(response, 'Test Achievement')
    
    def test_manager_can_view_assigned_appraisal(self):
        """Test manager can view appraisals assigned to them"""
        self.client.login(username='manager', password='test123')
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Appraisal')
    
    def test_other_user_cannot_view_appraisal(self):
        """Test other users cannot view appraisal"""
        self.client.login(username='other', password='test123')
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 302)  # Redirected
    
    def test_detail_shows_workflow_history(self):
        """Test detail shows workflow history"""
        AppraisalWorkflow.objects.create(
            appraisal=self.appraisal,
            from_status=None,
            to_status='draft',
            action_by=self.employee,
            comments='Created'
        )
        
        self.client.login(username='employee', password='test123')
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Workflow History')


class AppraisalCreateViewTest(TestCase):
    """Test appraisal create view"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.url = reverse('appraisal:appraisal_create')
        
        self.manager_group = Group.objects.create(name='Manager')
        
        self.employee = User.objects.create_user(
            username='employee', password='test123'
        )
        self.manager = User.objects.create_user(
            username='manager', password='test123'
        )
        self.manager.groups.add(self.manager_group)
    
    def test_create_view_requires_login(self):
        """Test that create view requires authentication"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
    
    def test_create_form_displays(self):
        """Test create form displays correctly"""
        self.client.login(username='employee', password='test123')
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create New Appraisal')
        self.assertContains(response, 'title')
        self.assertContains(response, 'overview')
        self.assertContains(response, 'manager')
    
    def test_create_appraisal_success(self):
        """Test successful appraisal creation"""
        self.client.login(username='employee', password='test123')
        
        items_data = json.dumps([
            {
                'category': 'achievement',
                'title': 'Major Project',
                'description': 'Completed successfully',
                'date': '2024-11-15',
                'employee_rating': 5
            }
        ])
        
        response = self.client.post(self.url, {
            'title': 'Q4 2024 Review',
            'overview': 'Great performance',
            'period_start': '2024-10-01',
            'period_end': '2024-12-31',
            'manager': self.manager.id,
            'items': items_data
        })
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['success'])
        
        # Verify appraisal was created
        appraisal = Appraisal.objects.get(title='Q4 2024 Review')
        self.assertEqual(appraisal.user, self.employee)
        self.assertEqual(appraisal.manager, self.manager)
        self.assertEqual(appraisal.items.count(), 1)
    
    def test_create_appraisal_missing_required_fields(self):
        """Test creation with missing required fields"""
        self.client.login(username='employee', password='test123')
        
        response = self.client.post(self.url, {
            'title': '',  # Missing title
            'overview': 'Test',
            'period_start': '2024-10-01',
            'period_end': '2024-12-31',
            'manager': self.manager.id,
            'items': json.dumps([])
        })
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertFalse(data['success'])
        self.assertIn('error', data)
    
    def test_create_appraisal_no_items(self):
        """Test creation without items fails"""
        self.client.login(username='employee', password='test123')
        
        response = self.client.post(self.url, {
            'title': 'Test Appraisal',
            'overview': 'Test',
            'period_start': '2024-10-01',
            'period_end': '2024-12-31',
            'manager': self.manager.id,
            'items': json.dumps([])
        })
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertFalse(data['success'])


class AppraisalSubmitViewTest(TestCase):
    """Test appraisal submit view"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        self.manager_group = Group.objects.create(name='Manager')
        
        self.employee = User.objects.create_user(
            username='employee', password='test123'
        )
        self.manager = User.objects.create_user(
            username='manager', password='test123'
        )
        self.manager.groups.add(self.manager_group)
        
        self.appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='Test Appraisal',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status='draft'
        )
        
        self.item = AppraisalItem.objects.create(
            appraisal=self.appraisal,
            category='achievement',
            title='Test',
            description='Test',
            employee_rating=4
        )
        
        self.url = reverse('appraisal:appraisal_submit', kwargs={'pk': self.appraisal.pk})
    
    def test_submit_requires_login(self):
        """Test submit requires authentication"""
        response = self.client.post(self.url)
        self.assertEqual(response.status_code, 302)
    
    def test_submit_requires_post(self):
        """Test submit requires POST method"""
        self.client.login(username='employee', password='test123')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)  # Redirects
    
    def test_submit_success(self):
        """Test successful submission"""
        self.client.login(username='employee', password='test123')
        response = self.client.post(self.url)
        
        self.assertEqual(response.status_code, 302)  # Redirects to detail
        
        self.appraisal.refresh_from_db()
        self.assertEqual(self.appraisal.status, 'submitted')
        self.assertIsNotNone(self.appraisal.submitted_at)
    
    def test_submit_without_items_fails(self):
        """Test submission without items fails"""
        self.appraisal.items.all().delete()
        
        self.client.login(username='employee', password='test123')
        response = self.client.post(self.url)
        
        self.appraisal.refresh_from_db()
        self.assertEqual(self.appraisal.status, 'draft')  # Still draft
    
    def test_other_user_cannot_submit(self):
        """Test other user cannot submit appraisal"""
        other_user = User.objects.create_user(
            username='other', password='test123'
        )
        
        self.client.login(username='other', password='test123')
        response = self.client.post(self.url)
        
        self.appraisal.refresh_from_db()
        self.assertEqual(self.appraisal.status, 'draft')


class AppraisalReviewViewTest(TestCase):
    """Test appraisal review view"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        
        # Create groups
        self.manager_group = Group.objects.create(name='Manager')
        self.hr_group = Group.objects.create(name='HR')
        self.finance_group = Group.objects.create(name='Finance')
        
        # Create users
        self.employee = User.objects.create_user(
            username='employee', password='test123'
        )
        self.manager = User.objects.create_user(
            username='manager', password='test123'
        )
        self.manager.groups.add(self.manager_group)
        
        self.hr_user = User.objects.create_user(
            username='hr_user', password='test123'
        )
        self.hr_user.groups.add(self.hr_group)
        
        self.finance_user = User.objects.create_user(
            username='finance_user', password='test123'
        )
        self.finance_user.groups.add(self.finance_group)
        
        # Create appraisal
        self.appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='Test Appraisal',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status='submitted'
        )
        
        self.item = AppraisalItem.objects.create(
            appraisal=self.appraisal,
            category='achievement',
            title='Test Achievement',
            description='Test description',
            employee_rating=4
        )
        
        self.url = reverse('appraisal:appraisal_review', kwargs={'pk': self.appraisal.pk})
    
    def test_review_requires_login(self):
        """Test review requires authentication"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
    
    def test_employee_cannot_access_review(self):
        """Test employee cannot access review page"""
        self.client.login(username='employee', password='test123')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)  # Redirected
    
    def test_manager_can_review_form(self):
        """Test manager can access review form"""
        self.client.login(username='manager', password='test123')
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Review Appraisal')
        self.assertContains(response, 'Test Achievement')
    
    def test_manager_approve(self):
        """Test manager approval"""
        self.client.login(username='manager', password='test123')
        
        response = self.client.post(self.url, {
            'action': 'approve',
            'comments': 'Good work',
            f'items[{self.item.id}][manager_rating]': '5',
            f'items[{self.item.id}][manager_comments]': 'Excellent'
        })
        
        self.assertEqual(response.status_code, 302)
        
        self.appraisal.refresh_from_db()
        self.assertEqual(self.appraisal.status, 'hr_review')
        
        self.item.refresh_from_db()
        self.assertEqual(self.item.manager_rating, 5)
        self.assertEqual(self.item.manager_comments, 'Excellent')
    
    def test_manager_reject(self):
        """Test manager rejection"""
        self.client.login(username='manager', password='test123')
        
        response = self.client.post(self.url, {
            'action': 'reject',
            'comments': 'Insufficient detail'
        })
        
        self.assertEqual(response.status_code, 302)
        
        self.appraisal.refresh_from_db()
        self.assertEqual(self.appraisal.status, 'rejected')
    
    def test_hr_review(self):
        """Test HR review"""
        self.appraisal.status = 'hr_review'
        self.appraisal.save()
        
        self.client.login(username='hr_user', password='test123')
        
        response = self.client.post(self.url, {
            'action': 'approve',
            'comments': 'Approved'
        })
        
        self.assertEqual(response.status_code, 302)
        
        self.appraisal.refresh_from_db()
        self.assertEqual(self.appraisal.status, 'finance_review')
    
    def test_finance_final_approval(self):
        """Test Finance final approval"""
        self.appraisal.status = 'finance_review'
        self.appraisal.save()
        
        self.client.login(username='finance_user', password='test123')
        
        response = self.client.post(self.url, {
            'action': 'approve',
            'comments': 'Final approval'
        })
        
        self.assertEqual(response.status_code, 302)
        
        self.appraisal.refresh_from_db()
        self.assertEqual(self.appraisal.status, 'approved')
        self.assertIsNotNone(self.appraisal.approved_at)


class AppraisalDashboardViewTest(TestCase):
    """Test appraisal dashboard view"""
    
    def setUp(self):
        """Set up test data"""
        self.client = Client()
        self.url = reverse('appraisal:appraisal_dashboard')
        
        self.hr_group = Group.objects.create(name='HR')
        self.management_group = Group.objects.create(name='Management')
        
        self.employee = User.objects.create_user(
            username='employee', password='test123'
        )
        self.hr_user = User.objects.create_user(
            username='hr_user', password='test123'
        )
        self.hr_user.groups.add(self.hr_group)
        
        self.management_user = User.objects.create_user(
            username='management', password='test123'
        )
        self.management_user.groups.add(self.management_group)
    
    def test_dashboard_requires_login(self):
        """Test dashboard requires authentication"""
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)
    
    def test_employee_cannot_access_dashboard(self):
        """Test regular employee cannot access dashboard"""
        self.client.login(username='employee', password='test123')
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 302)  # Redirected
    
    def test_hr_can_access_dashboard(self):
        """Test HR can access dashboard"""
        self.client.login(username='hr_user', password='test123')
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Appraisal Dashboard')
    
    def test_management_can_access_dashboard(self):
        """Test Management can access dashboard"""
        self.client.login(username='management', password='test123')
        response = self.client.get(self.url)
        
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Appraisal Dashboard')
