"""
Integration Tests for Complete Appraisal Workflows
Tests end-to-end scenarios across all components
"""
import json
from datetime import date
from django.test import TestCase, Client
from django.urls import reverse
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils import timezone

from trueAlign.models import (
    Appraisal, AppraisalItem, AppraisalWorkflow, Notification
)

User = get_user_model()


class CompleteAppraisalWorkflowTest(TestCase):
    """Test complete appraisal workflow from creation to approval"""
    
    def setUp(self):
        """Set up test environment"""
        self.client = Client()
        
        # Create groups
        Group.objects.create(name='Manager')
        Group.objects.create(name='HR')
        Group.objects.create(name='Finance')
        Group.objects.create(name='Management')
        
        # Create users
        self.employee = User.objects.create_user(
            username='john_employee',
            email='john@example.com',
            password='test123',
            first_name='John',
            last_name='Doe'
        )
        
        self.manager = User.objects.create_user(
            username='jane_manager',
            email='jane@example.com',
            password='test123',
            first_name='Jane',
            last_name='Smith'
        )
        self.manager.groups.add(Group.objects.get(name='Manager'))
        
        self.hr_user = User.objects.create_user(
            username='hr_admin',
            email='hr@example.com',
            password='test123',
            first_name='HR',
            last_name='Admin'
        )
        self.hr_user.groups.add(Group.objects.get(name='HR'))
        
        self.finance_user = User.objects.create_user(
            username='finance_admin',
            email='finance@example.com',
            password='test123',
            first_name='Finance',
            last_name='Admin'
        )
        self.finance_user.groups.add(Group.objects.get(name='Finance'))
    
    def test_complete_workflow_happy_path(self):
        """Test complete workflow from creation to final approval"""
        
        # Step 1: Employee creates appraisal
        self.client.login(username='john_employee', password='test123')
        
        create_url = reverse('appraisal:appraisal_create')
        items_data = json.dumps([
            {
                'category': 'achievement',
                'title': 'Completed Major Project',
                'description': 'Successfully delivered Project X on time and under budget',
                'date': '2024-11-15',
                'employee_rating': 5
            },
            {
                'category': 'skill',
                'title': 'Learned New Technology',
                'description': 'Mastered Python and Django framework',
                'employee_rating': 4
            },
            {
                'category': 'teamwork',
                'title': 'Team Collaboration',
                'description': 'Excellent collaboration with team members',
                'employee_rating': 5
            }
        ])
        
        response = self.client.post(create_url, {
            'title': 'Q4 2024 Performance Review',
            'overview': 'Outstanding performance this quarter with significant contributions',
            'period_start': '2024-10-01',
            'period_end': '2024-12-31',
            'manager': self.manager.id,
            'items': items_data
        })
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['success'], f"Failed: {data.get('error')}")
        
        appraisal_id = data['appraisal_id']
        appraisal = Appraisal.objects.get(id=appraisal_id)
        
        # Verify appraisal created correctly
        self.assertEqual(appraisal.status, 'draft')
        self.assertEqual(appraisal.items.count(), 3)
        
        # Step 2: Employee submits appraisal
        submit_url = reverse('appraisal:appraisal_submit', kwargs={'pk': appraisal_id})
        response = self.client.post(submit_url)
        
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'submitted')
        self.assertIsNotNone(appraisal.submitted_at)
        
        # Verify workflow history
        workflow_entries = AppraisalWorkflow.objects.filter(appraisal=appraisal).count()
        self.assertGreaterEqual(workflow_entries, 2)  # Created + Submitted
        
        self.client.logout()
        
        # Step 3: Manager reviews and approves
        self.client.login(username='jane_manager', password='test123')
        
        review_url = reverse('appraisal:appraisal_review', kwargs={'pk': appraisal_id})
        
        # Manager rates all items
        items = appraisal.items.all()
        post_data = {
            'action': 'approve',
            'comments': 'Excellent work! All objectives exceeded expectations.',
        }
        
        for item in items:
            post_data[f'items[{item.id}][manager_rating]'] = '5'
            post_data[f'items[{item.id}][manager_comments]'] = f'Outstanding performance on {item.title}'
        
        response = self.client.post(review_url, post_data)
        self.assertEqual(response.status_code, 302)  # Redirect after success
        
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'hr_review')
        
        # Verify all items have manager ratings
        for item in appraisal.items.all():
            self.assertIsNotNone(item.manager_rating)
            self.assertEqual(item.manager_rating, 5)
        
        self.client.logout()
        
        # Step 4: HR reviews and approves
        self.client.login(username='hr_admin', password='test123')
        
        response = self.client.post(review_url, {
            'action': 'approve',
            'comments': 'HR approved. Meets all criteria.'
        })
        
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'finance_review')
        
        self.client.logout()
        
        # Step 5: Finance gives final approval
        self.client.login(username='finance_admin', password='test123')
        
        response = self.client.post(review_url, {
            'action': 'approve',
            'comments': 'Finance approved. All financial implications reviewed.'
        })
        
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'approved')
        self.assertIsNotNone(appraisal.approved_at)
        
        # Verify complete workflow history
        workflow_entries = AppraisalWorkflow.objects.filter(appraisal=appraisal)
        self.assertGreaterEqual(workflow_entries.count(), 5)
        
        # Verify all status transitions
        statuses = list(workflow_entries.values_list('to_status', flat=True).order_by('-timestamp'))
        self.assertIn('draft', statuses)
        self.assertIn('submitted', statuses)
        self.assertIn('hr_review', statuses)
        self.assertIn('finance_review', statuses)
        self.assertIn('approved', statuses)
    
    def test_complete_workflow_rejection_at_manager_level(self):
        """Test workflow with rejection at manager stage"""
        
        # Employee creates and submits
        self.client.login(username='john_employee', password='test123')
        
        create_url = reverse('appraisal:appraisal_create')
        items_data = json.dumps([
            {
                'category': 'achievement',
                'title': 'Test Achievement',
                'description': 'Test description',
                'employee_rating': 3
            }
        ])
        
        response = self.client.post(create_url, {
            'title': 'Test Appraisal',
            'overview': 'Test overview',
            'period_start': '2024-10-01',
            'period_end': '2024-12-31',
            'manager': self.manager.id,
            'items': items_data
        })
        
        data = json.loads(response.content)
        appraisal_id = data['appraisal_id']
        
        # Submit
        submit_url = reverse('appraisal:appraisal_submit', kwargs={'pk': appraisal_id})
        self.client.post(submit_url)
        
        self.client.logout()
        
        # Manager rejects
        self.client.login(username='jane_manager', password='test123')
        
        review_url = reverse('appraisal:appraisal_review', kwargs={'pk': appraisal_id})
        response = self.client.post(review_url, {
            'action': 'reject',
            'comments': 'Insufficient detail. Please provide more specific examples.'
        })
        
        appraisal = Appraisal.objects.get(id=appraisal_id)
        self.assertEqual(appraisal.status, 'rejected')
        
        # Verify rejection workflow entry exists
        rejection_entry = AppraisalWorkflow.objects.filter(
            appraisal=appraisal,
            to_status='rejected'
        ).first()
        self.assertIsNotNone(rejection_entry)
        self.assertIn('Insufficient detail', rejection_entry.comments)
    
    def test_complete_workflow_rejection_at_hr_level(self):
        """Test workflow with rejection at HR stage"""
        
        # Create and get to HR review stage
        appraisal = self._create_and_submit_appraisal()
        self._manager_approve(appraisal)
        
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'hr_review')
        
        # HR rejects
        self.client.login(username='hr_admin', password='test123')
        
        review_url = reverse('appraisal:appraisal_review', kwargs={'pk': appraisal.id})
        response = self.client.post(review_url, {
            'action': 'reject',
            'comments': 'Does not meet HR policy requirements'
        })
        
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'rejected')
    
    def test_complete_workflow_rejection_at_finance_level(self):
        """Test workflow with rejection at Finance stage"""
        
        # Create and get to Finance review stage
        appraisal = self._create_and_submit_appraisal()
        self._manager_approve(appraisal)
        self._hr_approve(appraisal)
        
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'finance_review')
        
        # Finance rejects
        self.client.login(username='finance_admin', password='test123')
        
        review_url = reverse('appraisal:appraisal_review', kwargs={'pk': appraisal.id})
        response = self.client.post(review_url, {
            'action': 'reject',
            'comments': 'Financial implications not properly documented'
        })
        
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'rejected')
    
    def test_edit_and_resubmit_draft(self):
        """Test editing a draft appraisal and resubmitting"""
        
        # Create draft
        appraisal = self._create_draft_appraisal()
        
        # Edit the appraisal
        self.client.login(username='john_employee', password='test123')
        
        update_url = reverse('appraisal:appraisal_update', kwargs={'pk': appraisal.id})
        new_items = json.dumps([
            {
                'category': 'achievement',
                'title': 'Updated Achievement',
                'description': 'Updated description with more details',
                'employee_rating': 5
            },
            {
                'category': 'project',
                'title': 'New Project',
                'description': 'Added new project',
                'employee_rating': 4
            }
        ])
        
        response = self.client.post(update_url, {
            'title': 'Updated Title',
            'overview': 'Updated overview',
            'items': new_items
        })
        
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['success'])
        
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.title, 'Updated Title')
        self.assertEqual(appraisal.items.count(), 2)
        
        # Now submit
        submit_url = reverse('appraisal:appraisal_submit', kwargs={'pk': appraisal.id})
        response = self.client.post(submit_url)
        
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'submitted')
    
    def test_permission_boundaries(self):
        """Test that permission boundaries are enforced"""
        
        appraisal = self._create_and_submit_appraisal()
        
        # Employee tries to review their own appraisal
        self.client.login(username='john_employee', password='test123')
        review_url = reverse('appraisal:appraisal_review', kwargs={'pk': appraisal.id})
        response = self.client.get(review_url)
        self.assertEqual(response.status_code, 302)  # Redirected, no access
        
        # Create another employee
        other_employee = User.objects.create_user(
            username='other_employee',
            password='test123'
        )
        
        # Other employee tries to view appraisal
        self.client.login(username='other_employee', password='test123')
        detail_url = reverse('appraisal:appraisal_detail', kwargs={'pk': appraisal.id})
        response = self.client.get(detail_url)
        self.assertEqual(response.status_code, 302)  # Redirected, no access
    
    def test_workflow_audit_trail(self):
        """Test that complete audit trail is maintained"""
        
        appraisal = self._create_and_submit_appraisal()
        self._manager_approve(appraisal)
        self._hr_approve(appraisal)
        self._finance_approve(appraisal)
        
        # Get workflow history
        workflow = AppraisalWorkflow.objects.filter(
            appraisal=appraisal
        ).order_by('timestamp')
        
        # Verify all transitions are logged
        transitions = list(workflow.values_list('from_status', 'to_status'))
        
        # Should have: created, submitted, manager approved, HR approved, Finance approved
        self.assertGreaterEqual(len(transitions), 5)
        
        # Verify each action has an action_by user
        for entry in workflow:
            self.assertIsNotNone(entry.action_by)
            self.assertIsNotNone(entry.timestamp)
    
    # Helper methods
    def _create_draft_appraisal(self):
        """Helper to create a draft appraisal"""
        self.client.login(username='john_employee', password='test123')
        
        create_url = reverse('appraisal:appraisal_create')
        items_data = json.dumps([
            {
                'category': 'achievement',
                'title': 'Test Achievement',
                'description': 'Test description',
                'employee_rating': 4
            }
        ])
        
        response = self.client.post(create_url, {
            'title': 'Test Appraisal',
            'overview': 'Test overview',
            'period_start': '2024-10-01',
            'period_end': '2024-12-31',
            'manager': self.manager.id,
            'items': items_data
        })
        
        data = json.loads(response.content)
        return Appraisal.objects.get(id=data['appraisal_id'])
    
    def _create_and_submit_appraisal(self):
        """Helper to create and submit an appraisal"""
        appraisal = self._create_draft_appraisal()
        
        submit_url = reverse('appraisal:appraisal_submit', kwargs={'pk': appraisal.id})
        self.client.post(submit_url)
        
        self.client.logout()
        return appraisal
    
    def _manager_approve(self, appraisal):
        """Helper for manager approval"""
        self.client.login(username='jane_manager', password='test123')
        
        review_url = reverse('appraisal:appraisal_review', kwargs={'pk': appraisal.id})
        post_data = {'action': 'approve', 'comments': 'Approved'}
        
        for item in appraisal.items.all():
            post_data[f'items[{item.id}][manager_rating]'] = '4'
        
        self.client.post(review_url, post_data)
        self.client.logout()
    
    def _hr_approve(self, appraisal):
        """Helper for HR approval"""
        self.client.login(username='hr_admin', password='test123')
        
        review_url = reverse('appraisal:appraisal_review', kwargs={'pk': appraisal.id})
        self.client.post(review_url, {
            'action': 'approve',
            'comments': 'HR approved'
        })
        self.client.logout()
    
    def _finance_approve(self, appraisal):
        """Helper for Finance approval"""
        self.client.login(username='finance_admin', password='test123')
        
        review_url = reverse('appraisal:appraisal_review', kwargs={'pk': appraisal.id})
        self.client.post(review_url, {
            'action': 'approve',
            'comments': 'Finance approved'
        })
        self.client.logout()


class MultiUserScenarioTest(TestCase):
    """Test scenarios with multiple users and appraisals"""
    
    def setUp(self):
        """Set up multiple users and appraisals"""
        # Create groups
        self.manager_group = Group.objects.create(name='Manager')
        
        # Create manager
        self.manager = User.objects.create_user(
            username='manager', password='test123'
        )
        self.manager.groups.add(self.manager_group)
        
        # Create multiple employees
        self.employees = []
        for i in range(5):
            employee = User.objects.create_user(
                username=f'employee{i}',
                password='test123'
            )
            self.employees.append(employee)
            
            # Create appraisal for each
            appraisal = Appraisal.objects.create(
                user=employee,
                manager=self.manager,
                title=f'Appraisal {i}',
                overview='Test',
                period_start=date(2024, 10, 1),
                period_end=date(2024, 12, 31),
                status='submitted' if i % 2 == 0 else 'draft'
            )
            
            AppraisalItem.objects.create(
                appraisal=appraisal,
                category='achievement',
                title='Test',
                description='Test',
                employee_rating=4
            )
    
    def test_manager_sees_only_assigned_appraisals(self):
        """Test manager sees only appraisals assigned to them"""
        self.client.login(username='manager', password='test123')
        
        url = reverse('appraisal:appraisal_list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        
        # Manager should see submitted appraisals (3 out of 5)
        appraisals = response.context['appraisals']
        self.assertEqual(appraisals.count(), 3)
        
        # All should be in submitted status
        for appraisal in appraisals:
            self.assertEqual(appraisal.status, 'submitted')
    
    def test_employee_sees_only_own_appraisals(self):
        """Test employee sees only their own appraisals"""
        self.client.login(username='employee0', password='test123')
        
        url = reverse('appraisal:appraisal_list')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, 200)
        
        appraisals = response.context['appraisals']
        self.assertEqual(appraisals.count(), 1)
        self.assertEqual(appraisals.first().user, self.employees[0])
