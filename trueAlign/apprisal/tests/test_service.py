"""
Test cases for Appraisal Service Layer
Tests business logic, permissions, workflow transitions, and validation
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.utils import timezone
from datetime import date

from trueAlign.models import (
    Appraisal, AppraisalItem, AppraisalWorkflow
)
from trueAlign.apprisal.service import appraisal_service

User = get_user_model()


class AppraisalServicePermissionTest(TestCase):
    """Test permission checking methods"""
    
    def setUp(self):
        """Set up test users and groups"""
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
            status='draft'
        )
        
        # Add an item so appraisal can be submitted
        AppraisalItem.objects.create(
            appraisal=self.appraisal,
            category='achievement',
            title='Test',
            description='Test',
            employee_rating=4
        )
    
    def test_can_user_create_appraisal(self):
        """Test create permission"""
        # Active user can create
        self.assertTrue(appraisal_service.can_user_create_appraisal(self.employee))
        
        # Inactive user cannot create
        inactive_user = User.objects.create_user(
            username='inactive', password='test123', is_active=False
        )
        self.assertFalse(appraisal_service.can_user_create_appraisal(inactive_user))
    
    def test_can_user_edit_appraisal(self):
        """Test edit permission"""
        # Owner can edit draft
        self.assertTrue(appraisal_service.can_user_edit_appraisal(
            self.employee, self.appraisal
        ))
        
        # Other user cannot edit
        other_user = User.objects.create_user(
            username='other', password='test123'
        )
        self.assertFalse(appraisal_service.can_user_edit_appraisal(
            other_user, self.appraisal
        ))
        
        # Owner cannot edit submitted appraisal
        self.appraisal.status = 'submitted'
        self.appraisal.save()
        self.assertFalse(appraisal_service.can_user_edit_appraisal(
            self.employee, self.appraisal
        ))
    
    def test_can_user_submit_appraisal(self):
        """Test submit permission"""
        # Owner can submit draft with items
        self.assertTrue(appraisal_service.can_user_submit_appraisal(
            self.employee, self.appraisal
        ))
        
        # Other user cannot submit
        other_user = User.objects.create_user(
            username='other', password='test123'
        )
        self.assertFalse(appraisal_service.can_user_submit_appraisal(
            other_user, self.appraisal
        ))
        
        # Cannot submit already submitted
        self.appraisal.status = 'submitted'
        self.appraisal.save()
        self.assertFalse(appraisal_service.can_user_submit_appraisal(
            self.employee, self.appraisal
        ))
    
    def test_can_user_review_appraisal_manager(self):
        """Test manager review permission"""
        self.appraisal.status = 'submitted'
        self.appraisal.save()
        
        # Assigned manager can review
        self.assertTrue(appraisal_service.can_user_review_appraisal(
            self.manager, self.appraisal
        ))
        
        # Other manager cannot review
        other_manager = User.objects.create_user(
            username='other_manager', password='test123'
        )
        other_manager.groups.add(self.manager_group)
        self.assertFalse(appraisal_service.can_user_review_appraisal(
            other_manager, self.appraisal
        ))
        
        # Employee cannot review
        self.assertFalse(appraisal_service.can_user_review_appraisal(
            self.employee, self.appraisal
        ))
    
    def test_can_user_review_appraisal_hr(self):
        """Test HR review permission"""
        self.appraisal.status = 'hr_review'
        self.appraisal.save()
        
        # HR can review
        self.assertTrue(appraisal_service.can_user_review_appraisal(
            self.hr_user, self.appraisal
        ))
        
        # Manager cannot review HR stage
        self.assertFalse(appraisal_service.can_user_review_appraisal(
            self.manager, self.appraisal
        ))
    
    def test_can_user_review_appraisal_finance(self):
        """Test Finance review permission"""
        self.appraisal.status = 'finance_review'
        self.appraisal.save()
        
        # Finance can review
        self.assertTrue(appraisal_service.can_user_review_appraisal(
            self.finance_user, self.appraisal
        ))
        
        # HR cannot review Finance stage
        self.assertFalse(appraisal_service.can_user_review_appraisal(
            self.hr_user, self.appraisal
        ))


class AppraisalServiceWorkflowTest(TestCase):
    """Test workflow and status transitions"""
    
    def setUp(self):
        """Set up test data"""
        self.manager_group = Group.objects.create(name='Manager')
        
        self.employee = User.objects.create_user(
            username='employee', password='test123'
        )
        self.manager = User.objects.create_user(
            username='manager', password='test123'
        )
        self.manager.groups.add(self.manager_group)
    
    def test_valid_status_transitions(self):
        """Test valid status transitions"""
        # draft -> submitted
        self.assertTrue(appraisal_service.is_valid_transition('draft', 'submitted'))
        
        # submitted -> hr_review
        self.assertTrue(appraisal_service.is_valid_transition('submitted', 'hr_review'))
        
        # submitted -> rejected
        self.assertTrue(appraisal_service.is_valid_transition('submitted', 'rejected'))
        
        # hr_review -> finance_review
        self.assertTrue(appraisal_service.is_valid_transition('hr_review', 'finance_review'))
        
        # hr_review -> rejected
        self.assertTrue(appraisal_service.is_valid_transition('hr_review', 'rejected'))
        
        # finance_review -> approved
        self.assertTrue(appraisal_service.is_valid_transition('finance_review', 'approved'))
        
        # finance_review -> rejected
        self.assertTrue(appraisal_service.is_valid_transition('finance_review', 'rejected'))
    
    def test_invalid_status_transitions(self):
        """Test invalid status transitions"""
        # draft -> hr_review (skip submitted)
        self.assertFalse(appraisal_service.is_valid_transition('draft', 'hr_review'))
        
        # draft -> approved (skip all)
        self.assertFalse(appraisal_service.is_valid_transition('draft', 'approved'))
        
        # submitted -> approved (skip stages)
        self.assertFalse(appraisal_service.is_valid_transition('submitted', 'approved'))
        
        # hr_review -> submitted (backward)
        self.assertFalse(appraisal_service.is_valid_transition('hr_review', 'submitted'))
        
        # approved -> anything (final state)
        self.assertFalse(appraisal_service.is_valid_transition('approved', 'draft'))
        self.assertFalse(appraisal_service.is_valid_transition('approved', 'rejected'))
        
        # rejected -> anything (final state)
        self.assertFalse(appraisal_service.is_valid_transition('rejected', 'draft'))
        self.assertFalse(appraisal_service.is_valid_transition('rejected', 'approved'))
    
    def test_create_appraisal_success(self):
        """Test successful appraisal creation"""
        items_data = [
            {
                'category': 'achievement',
                'title': 'Major Project',
                'description': 'Completed successfully',
                'date': date(2024, 11, 15),
                'employee_rating': 5
            },
            {
                'category': 'skill',
                'title': 'New Technology',
                'description': 'Learned Python',
                'employee_rating': 4
            }
        ]
        
        success, message, appraisal = appraisal_service.create_appraisal(
            user=self.employee,
            manager=self.manager,
            title='Q4 2024 Review',
            overview='Great performance',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            items_data=items_data
        )
        
        self.assertTrue(success)
        self.assertIsNotNone(appraisal)
        self.assertEqual(appraisal.user, self.employee)
        self.assertEqual(appraisal.manager, self.manager)
        self.assertEqual(appraisal.status, 'draft')
        self.assertEqual(appraisal.items.count(), 2)
        
        # Check workflow history
        workflow = AppraisalWorkflow.objects.filter(appraisal=appraisal).first()
        self.assertIsNotNone(workflow)
        self.assertEqual(workflow.to_status, 'draft')
    
    def test_create_appraisal_validation_failures(self):
        """Test appraisal creation validation"""
        # Missing title
        success, message, appraisal = appraisal_service.create_appraisal(
            user=self.employee,
            manager=self.manager,
            title='',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            items_data=[{'category': 'achievement', 'title': 'Test', 'description': 'Test', 'employee_rating': 4}]
        )
        self.assertFalse(success)
        self.assertIn('required', message.lower())
        
        # Missing manager
        success, message, appraisal = appraisal_service.create_appraisal(
            user=self.employee,
            manager=None,
            title='Test',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            items_data=[{'category': 'achievement', 'title': 'Test', 'description': 'Test', 'employee_rating': 4}]
        )
        self.assertFalse(success)
        self.assertIn('manager', message.lower())
        
        # No items
        success, message, appraisal = appraisal_service.create_appraisal(
            user=self.employee,
            manager=self.manager,
            title='Test',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            items_data=[]
        )
        self.assertFalse(success)
        self.assertIn('item', message.lower())
    
    def test_submit_appraisal_success(self):
        """Test successful appraisal submission"""
        appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='Test',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status='draft'
        )
        
        AppraisalItem.objects.create(
            appraisal=appraisal,
            category='achievement',
            title='Test',
            description='Test',
            employee_rating=4
        )
        
        success, message = appraisal_service.submit_appraisal(
            self.employee, appraisal
        )
        
        self.assertTrue(success)
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'submitted')
        self.assertIsNotNone(appraisal.submitted_at)
        
        # Check workflow history
        workflow = AppraisalWorkflow.objects.filter(
            appraisal=appraisal,
            to_status='submitted'
        ).first()
        self.assertIsNotNone(workflow)
    
    def test_submit_appraisal_validation(self):
        """Test submission validation"""
        appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='Test',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status='draft'
        )
        
        # Add item without rating
        AppraisalItem.objects.create(
            appraisal=appraisal,
            category='achievement',
            title='Test',
            description='Test',
            employee_rating=None  # No rating
        )
        
        success, message = appraisal_service.submit_appraisal(
            self.employee, appraisal
        )
        
        self.assertFalse(success)
        self.assertIn('rating', message.lower())
    
    def test_review_appraisal_manager_approve(self):
        """Test manager approval"""
        appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='Test',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status='submitted',
            submitted_at=timezone.now()
        )
        
        item = AppraisalItem.objects.create(
            appraisal=appraisal,
            category='achievement',
            title='Test',
            description='Test',
            employee_rating=4
        )
        
        success, message = appraisal_service.review_appraisal(
            user=self.manager,
            appraisal=appraisal,
            action='approve',
            comments='Good work',
            item_ratings={str(item.id): 5},
            item_comments={str(item.id): 'Excellent'}
        )
        
        self.assertTrue(success)
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'hr_review')
        
        item.refresh_from_db()
        self.assertEqual(item.manager_rating, 5)
        self.assertEqual(item.manager_comments, 'Excellent')
    
    def test_review_appraisal_manager_reject(self):
        """Test manager rejection"""
        appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='Test',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status='submitted',
            submitted_at=timezone.now()
        )
        
        AppraisalItem.objects.create(
            appraisal=appraisal,
            category='achievement',
            title='Test',
            description='Test',
            employee_rating=4
        )
        
        success, message = appraisal_service.review_appraisal(
            user=self.manager,
            appraisal=appraisal,
            action='reject',
            comments='Insufficient detail'
        )
        
        self.assertTrue(success)
        appraisal.refresh_from_db()
        self.assertEqual(appraisal.status, 'rejected')


class AppraisalServiceQueryTest(TestCase):
    """Test query methods"""
    
    def setUp(self):
        """Set up test data"""
        self.manager_group = Group.objects.create(name='Manager')
        self.hr_group = Group.objects.create(name='HR')
        
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
        
        # Create test appraisals
        for i in range(15):
            Appraisal.objects.create(
                user=self.employee,
                manager=self.manager,
                title=f'Appraisal {i}',
                overview='Test',
                period_start=date(2024, 10, 1),
                period_end=date(2024, 12, 31),
                status='draft' if i < 5 else 'submitted'
            )
    
    def test_get_user_appraisals(self):
        """Test getting user's appraisals"""
        result = appraisal_service.get_user_appraisals(
            user=self.employee
        )
        
        self.assertEqual(result['total_count'], 15)
        self.assertEqual(len(result['results']), 10)  # Default page size
        self.assertEqual(result['page'], 1)
        self.assertEqual(result['total_pages'], 2)
    
    def test_get_user_appraisals_with_filter(self):
        """Test getting user's appraisals with status filter"""
        result = appraisal_service.get_user_appraisals(
            user=self.employee,
            status='draft'
        )
        
        self.assertEqual(result['total_count'], 5)
        self.assertTrue(all(
            a.status == 'draft' for a in result['results']
        ))
    
    def test_get_user_appraisals_pagination(self):
        """Test pagination"""
        # Page 1
        result = appraisal_service.get_user_appraisals(
            user=self.employee,
            page=1,
            page_size=5
        )
        self.assertEqual(len(result['results']), 5)
        self.assertEqual(result['page'], 1)
        
        # Page 2
        result = appraisal_service.get_user_appraisals(
            user=self.employee,
            page=2,
            page_size=5
        )
        self.assertEqual(len(result['results']), 5)
        self.assertEqual(result['page'], 2)
    
    def test_get_managed_appraisals_manager(self):
        """Test getting appraisals for manager"""
        result = appraisal_service.get_managed_appraisals(
            user=self.manager
        )
        
        # Manager should see submitted appraisals
        self.assertEqual(result['total_count'], 10)
        self.assertTrue(all(
            a.status in ['submitted', 'hr_review', 'finance_review', 'approved', 'rejected']
            for a in result['results']
        ))
    
    def test_get_managed_appraisals_hr(self):
        """Test getting appraisals for HR"""
        # Create HR review appraisals
        for i in range(5):
            Appraisal.objects.create(
                user=self.employee,
                manager=self.manager,
                title=f'HR Appraisal {i}',
                overview='Test',
                period_start=date(2024, 10, 1),
                period_end=date(2024, 12, 31),
                status='hr_review'
            )
        
        result = appraisal_service.get_managed_appraisals(
            user=self.hr_user
        )
        
        # HR should see hr_review and later stages
        self.assertGreaterEqual(result['total_count'], 5)
