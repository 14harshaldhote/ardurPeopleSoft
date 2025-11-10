"""
Comprehensive Scenario Tests for Appraisal System
Tests every possible workflow, rejection, approval, comments, and notifications
"""
from datetime import date
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils import timezone

from trueAlign.models import (
    Appraisal, AppraisalItem, AppraisalWorkflow, Notification
)
from trueAlign.apprisal.service import appraisal_service

User = get_user_model()


class ScenarioTestBase(TestCase):
    """Base class with common setup for scenario tests"""
    
    def setUp(self):
        """Set up test environment with all necessary users and groups"""
        # Create groups
        self.manager_group = Group.objects.create(name='Manager')
        self.hr_group = Group.objects.create(name='HR')
        self.finance_group = Group.objects.create(name='Finance')
        
        # Create users
        self.employee = User.objects.create_user(
            username='john_employee', password='test123', first_name='John', last_name='Doe'
        )
        
        self.manager = User.objects.create_user(
            username='sarah_manager', password='test123', first_name='Sarah', last_name='Manager'
        )
        self.manager.groups.add(self.manager_group)
        
        self.other_manager = User.objects.create_user(
            username='bob_manager', password='test123'
        )
        self.other_manager.groups.add(self.manager_group)
        
        self.hr_user = User.objects.create_user(
            username='alice_hr', password='test123'
        )
        self.hr_user.groups.add(self.hr_group)
        
        self.finance_user = User.objects.create_user(
            username='david_finance', password='test123'
        )
        self.finance_user.groups.add(self.finance_group)
    
    def create_sample_appraisal(self, status='draft'):
        """Helper to create a sample appraisal"""
        appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='Q4 2024 Performance Review',
            overview='Outstanding performance',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status=status
        )
        
        AppraisalItem.objects.create(
            appraisal=appraisal,
            category='achievement',
            title='Major Project',
            description='Delivered successfully',
            employee_rating=5
        )
        
        AppraisalItem.objects.create(
            appraisal=appraisal,
            category='skill',
            title='Technical Skills',
            description='Mastered new tech',
            employee_rating=4
        )
        
        return appraisal


class Scenario01_CompleteHappyPath(ScenarioTestBase):
    """Complete workflow: Create → Submit → Manager → HR → Finance → Approved"""
    
    def test_complete_happy_path(self):
        """Test complete workflow from creation to final approval"""
        
        # Step 1: Create appraisal
        success, message, appraisal = appraisal_service.create_appraisal(
            user=self.employee,
            manager=self.manager,
            title='Q4 2024 Performance Review',
            overview='Excellent quarter',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            items_data=[
                {
                    'category': 'achievement',
                    'title': 'Led Major Initiative',
                    'description': 'Led digital transformation',
                    'employee_rating': 5
                },
                {
                    'category': 'teamwork',
                    'title': 'Team Collaboration',
                    'description': 'Mentored 3 developers',
                    'employee_rating': 5
                }
            ]
        )
        
        self.assertTrue(success)
        self.assertEqual(appraisal.status, 'draft')
        
        # Step 2: Submit
        success, _ = appraisal_service.submit_appraisal(self.employee, appraisal)
        self.assertTrue(success)
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'submitted')
        
        # Step 3: Manager approves
        items = appraisal.items.all()
        item_ratings = {str(item.id): 5 for item in items}
        item_comments = {str(item.id): f'Excellent work on {item.title}' for item in items}
        
        success, _ = appraisal_service.review_appraisal(
            user=self.manager,
            appraisal=appraisal,
            action='approve',
            comments='Exceptional performance!',
            item_ratings=item_ratings,
            item_comments=item_comments
        )
        
        self.assertTrue(success)
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'hr_review')
        
        # Verify manager ratings saved
        for item in appraisal.items.all():
            self.assertEqual(item.manager_rating, 5)
            self.assertIsNotNone(item.manager_comments)
        
        # Step 4: HR approves
        success, _ = appraisal_service.review_appraisal(
            user=self.hr_user,
            appraisal=appraisal,
            action='approve',
            comments='HR approved - Meets all policies'
        )
        
        self.assertTrue(success)
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'finance_review')
        
        # Step 5: Finance final approval
        success, _ = appraisal_service.review_appraisal(
            user=self.finance_user,
            appraisal=appraisal,
            action='approve',
            comments='Finance approved - Budget allocated'
        )
        
        self.assertTrue(success)
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'approved')
        self.assertIsNotNone(appraisal.approved_at)
        
        # Verify complete workflow history
        workflow_count = AppraisalWorkflow.objects.filter(appraisal=appraisal).count()
        self.assertGreaterEqual(workflow_count, 5)


class Scenario02_ManagerRejection(ScenarioTestBase):
    """Manager rejection with detailed comments"""
    
    def test_manager_rejects_with_comments(self):
        """Test manager rejection with detailed feedback"""
        
        appraisal = self.create_sample_appraisal()
        appraisal_service.submit_appraisal(self.employee, appraisal)
        
        rejection_comment = "Insufficient detail. Please add quantifiable metrics."
        
        success, _ = appraisal_service.review_appraisal(
            user=self.manager,
            appraisal=appraisal,
            action='reject',
            comments=rejection_comment
        )
        
        self.assertTrue(success)
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'rejected')
        
        # Verify workflow entry
        workflow = AppraisalWorkflow.objects.filter(
            appraisal=appraisal,
            to_status='rejected',
            action_by=self.manager
        ).first()
        
        self.assertIsNotNone(workflow)
        self.assertIn('Insufficient', workflow.comments)


class Scenario03_HRRejection(ScenarioTestBase):
    """HR rejection after manager approval"""
    
    def test_hr_rejects_policy_violation(self):
        """Test HR rejection for policy violation"""
        
        appraisal = self.create_sample_appraisal()
        appraisal_service.submit_appraisal(self.employee, appraisal)
        
        # Manager approves
        items = appraisal.items.all()
        item_ratings = {str(item.id): 4 for item in items}
        appraisal_service.review_appraisal(
            user=self.manager,
            appraisal=appraisal,
            action='approve',
            item_ratings=item_ratings
        )
        
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'hr_review')
        
        # HR rejects
        success, _ = appraisal_service.review_appraisal(
            user=self.hr_user,
            appraisal=appraisal,
            action='reject',
            comments='Policy violation: Missing required training certificates'
        )
        
        self.assertTrue(success)
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'rejected')


class Scenario04_FinanceRejection(ScenarioTestBase):
    """Finance rejection at final stage"""
    
    def test_finance_rejects_budget_issue(self):
        """Test finance rejection for budget constraints"""
        
        appraisal = self.create_sample_appraisal()
        appraisal_service.submit_appraisal(self.employee, appraisal)
        
        # Manager approves
        items = appraisal.items.all()
        item_ratings = {str(item.id): 5 for item in items}
        appraisal_service.review_appraisal(
            user=self.manager, appraisal=appraisal, action='approve', item_ratings=item_ratings
        )
        
        # HR approves
        appraisal.refresh_from_db()
        appraisal_service.review_appraisal(
            user=self.hr_user, appraisal=appraisal, action='approve'
        )
        
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'finance_review')
        
        # Finance rejects
        success, _ = appraisal_service.review_appraisal(
            user=self.finance_user,
            appraisal=appraisal,
            action='reject',
            comments='Budget exceeded - Defer to next quarter'
        )
        
        self.assertTrue(success)
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'rejected')


class Scenario05_PermissionChecks(ScenarioTestBase):
    """Permission violation scenarios"""
    
    def test_wrong_manager_cannot_review(self):
        """Test non-assigned manager cannot review"""
        
        appraisal = self.create_sample_appraisal()
        appraisal_service.submit_appraisal(self.employee, appraisal)
        
        can_review = appraisal_service.can_user_review_appraisal(
            self.other_manager, appraisal
        )
        self.assertFalse(can_review)
    
    def test_employee_cannot_review_own(self):
        """Test employee cannot review own appraisal"""
        
        appraisal = self.create_sample_appraisal()
        appraisal_service.submit_appraisal(self.employee, appraisal)
        
        can_review = appraisal_service.can_user_review_appraisal(
            self.employee, appraisal
        )
        self.assertFalse(can_review)


class Scenario06_NotificationFlow(ScenarioTestBase):
    """Notification generation at each stage"""
    
    def test_notifications_sent_at_each_stage(self):
        """Test notifications are created at each workflow stage"""
        
        appraisal = self.create_sample_appraisal()
        
        # Submit - notification to manager
        appraisal_service.submit_appraisal(self.employee, appraisal)
        manager_notif = Notification.objects.filter(
            recipient=self.manager,
            reference_id=str(appraisal.id)
        )
        self.assertGreater(manager_notif.count(), 0)
        
        # Manager approves - notifications to employee and HR
        items = appraisal.items.all()
        item_ratings = {str(item.id): 4 for item in items}
        appraisal_service.review_appraisal(
            user=self.manager, appraisal=appraisal,
            action='approve', item_ratings=item_ratings
        )
        
        employee_notif = Notification.objects.filter(
            recipient=self.employee,
            reference_id=str(appraisal.id)
        )
        self.assertGreater(employee_notif.count(), 0)
        
        hr_notif = Notification.objects.filter(
            recipient=self.hr_user,
            reference_id=str(appraisal.id)
        )
        self.assertGreater(hr_notif.count(), 0)


class Scenario07_EdgeCases(ScenarioTestBase):
    """Edge cases and error conditions"""
    
    def test_submit_without_items_fails(self):
        """Test submitting without items fails"""
        
        appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='Empty',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31)
        )
        
        success, message = appraisal_service.submit_appraisal(self.employee, appraisal)
        self.assertFalse(success)
        self.assertIn('item', message.lower())
    
    def test_manager_must_rate_all_items(self):
        """Test manager must rate all items to approve"""
        
        appraisal = self.create_sample_appraisal()
        appraisal_service.submit_appraisal(self.employee, appraisal)
        
        items = list(appraisal.items.all())
        # Only rate first item
        item_ratings = {str(items[0].id): 4}
        
        success, message = appraisal_service.review_appraisal(
            user=self.manager,
            appraisal=appraisal,
            action='approve',
            item_ratings=item_ratings
        )
        
        self.assertFalse(success)
        self.assertIn('rate all', message.lower())
    
    def test_cannot_edit_after_submit(self):
        """Test cannot edit after submission"""
        
        appraisal = self.create_sample_appraisal()
        appraisal_service.submit_appraisal(self.employee, appraisal)
        
        can_edit = appraisal_service.can_user_edit_appraisal(self.employee, appraisal)
        self.assertFalse(can_edit)
