"""
Test cases for Appraisal Models
Tests model validation, properties, and relationships
"""
from django.test import TestCase
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.utils import timezone
from datetime import date, timedelta

from trueAlign.models import (
    Appraisal, AppraisalItem, AppraisalAttachment, AppraisalWorkflow
)

User = get_user_model()


class AppraisalModelTest(TestCase):
    """Test Appraisal model"""
    
    def setUp(self):
        """Set up test data"""
        self.employee = User.objects.create_user(
            username='employee_test',
            email='employee@test.com',
            password='testpass123'
        )
        self.manager = User.objects.create_user(
            username='manager_test',
            email='manager@test.com',
            password='testpass123'
        )
        
        self.appraisal = Appraisal.objects.create(
            user=self.employee,
            manager=self.manager,
            title='Q4 2024 Performance Review',
            overview='Test overview',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status='draft'
        )
    
    def test_appraisal_creation(self):
        """Test appraisal is created correctly"""
        self.assertEqual(self.appraisal.user, self.employee)
        self.assertEqual(self.appraisal.manager, self.manager)
        self.assertEqual(self.appraisal.status, 'draft')
        self.assertIsNone(self.appraisal.submitted_at)
        self.assertIsNone(self.appraisal.approved_at)
    
    def test_appraisal_str_representation(self):
        """Test string representation"""
        expected = f"{self.appraisal.title} - {self.employee.get_full_name()} (draft)"
        self.assertEqual(str(self.appraisal), expected)
    
    def test_is_editable_property(self):
        """Test is_editable property"""
        # Draft is editable
        self.assertTrue(self.appraisal.is_editable)
        
        # Submitted is not editable
        self.appraisal.status = 'submitted'
        self.appraisal.save()
        self.assertFalse(self.appraisal.is_editable)
        
        # Approved is not editable
        self.appraisal.status = 'approved'
        self.appraisal.save()
        self.assertFalse(self.appraisal.is_editable)
    
    def test_can_be_submitted_property(self):
        """Test can_be_submitted property"""
        # Without items, cannot be submitted
        self.assertFalse(self.appraisal.can_be_submitted)
        
        # With items, can be submitted
        AppraisalItem.objects.create(
            appraisal=self.appraisal,
            category='achievement',
            title='Test Achievement',
            description='Test description',
            employee_rating=4
        )
        self.assertTrue(self.appraisal.can_be_submitted)
        
        # After submission, cannot be submitted again
        self.appraisal.status = 'submitted'
        self.appraisal.save()
        self.assertFalse(self.appraisal.can_be_submitted)
    
    def test_period_validation(self):
        """Test period date validation"""
        appraisal = Appraisal(
            user=self.employee,
            manager=self.manager,
            title='Invalid Period Test',
            overview='Test',
            period_start=date(2024, 12, 31),
            period_end=date(2024, 10, 1),  # End before start
            status='draft'
        )
        
        with self.assertRaises(ValidationError):
            appraisal.clean()
    
    def test_submitted_without_manager_validation(self):
        """Test validation when submitting without manager"""
        appraisal = Appraisal(
            user=self.employee,
            manager=None,
            title='No Manager Test',
            overview='Test',
            period_start=date(2024, 10, 1),
            period_end=date(2024, 12, 31),
            status='submitted'
        )
        
        with self.assertRaises(ValidationError):
            appraisal.clean()
    
    def test_average_employee_rating(self):
        """Test average employee rating calculation"""
        # No items
        self.assertIsNone(self.appraisal.average_employee_rating)
        
        # Add items with ratings
        AppraisalItem.objects.create(
            appraisal=self.appraisal,
            category='achievement',
            title='Item 1',
            description='Test',
            employee_rating=5
        )
        AppraisalItem.objects.create(
            appraisal=self.appraisal,
            category='project',
            title='Item 2',
            description='Test',
            employee_rating=3
        )
        
        # Average should be (5+3)/2 = 4.0
        self.assertEqual(self.appraisal.average_employee_rating, 4.0)
    
    def test_average_manager_rating(self):
        """Test average manager rating calculation"""
        # No ratings
        self.assertIsNone(self.appraisal.average_manager_rating)
        
        # Add items with manager ratings
        AppraisalItem.objects.create(
            appraisal=self.appraisal,
            category='achievement',
            title='Item 1',
            description='Test',
            employee_rating=4,
            manager_rating=5
        )
        AppraisalItem.objects.create(
            appraisal=self.appraisal,
            category='project',
            title='Item 2',
            description='Test',
            employee_rating=3,
            manager_rating=4
        )
        
        # Average should be (5+4)/2 = 4.5
        self.assertEqual(self.appraisal.average_manager_rating, 4.5)


class AppraisalItemModelTest(TestCase):
    """Test AppraisalItem model"""
    
    def setUp(self):
        """Set up test data"""
        self.employee = User.objects.create_user(
            username='employee_test',
            email='employee@test.com',
            password='testpass123'
        )
        self.manager = User.objects.create_user(
            username='manager_test',
            email='manager@test.com',
            password='testpass123'
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
            title='Major Achievement',
            description='Completed project successfully',
            date=date(2024, 11, 15),
            employee_rating=5
        )
    
    def test_item_creation(self):
        """Test item is created correctly"""
        self.assertEqual(self.item.appraisal, self.appraisal)
        self.assertEqual(self.item.category, 'achievement')
        self.assertEqual(self.item.employee_rating, 5)
        self.assertIsNone(self.item.manager_rating)
    
    def test_item_str_representation(self):
        """Test string representation"""
        expected = f"{self.item.category}: {self.item.title}"
        self.assertEqual(str(self.item), expected)
    
    def test_rating_display_properties(self):
        """Test rating display properties"""
        # Employee rating display
        self.assertEqual(self.item.employee_rating_display, 'Outstanding')
        
        # Manager rating display (not yet rated)
        self.assertEqual(self.item.manager_rating_display, 'Not Rated')
        
        # Add manager rating
        self.item.manager_rating = 4
        self.item.save()
        self.assertEqual(self.item.manager_rating_display, 'Exceeds Expectations')
    
    def test_all_rating_choices(self):
        """Test all rating choice displays"""
        ratings = {
            1: 'Needs Improvement',
            2: 'Below Expectations',
            3: 'Meets Expectations',
            4: 'Exceeds Expectations',
            5: 'Outstanding'
        }
        
        for rating, expected in ratings.items():
            self.item.employee_rating = rating
            self.item.save()
            self.assertEqual(self.item.employee_rating_display, expected)
    
    def test_all_categories(self):
        """Test all category choices"""
        categories = [
            'achievement', 'project', 'skill', 'initiative',
            'teamwork', 'leadership', 'other'
        ]
        
        for category in categories:
            item = AppraisalItem.objects.create(
                appraisal=self.appraisal,
                category=category,
                title=f'Test {category}',
                description='Test description',
                employee_rating=3
            )
            self.assertEqual(item.category, category)


class AppraisalWorkflowModelTest(TestCase):
    """Test AppraisalWorkflow model"""
    
    def setUp(self):
        """Set up test data"""
        self.employee = User.objects.create_user(
            username='employee_test',
            email='employee@test.com',
            password='testpass123'
        )
        self.manager = User.objects.create_user(
            username='manager_test',
            email='manager@test.com',
            password='testpass123'
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
    
    def test_workflow_creation(self):
        """Test workflow entry creation"""
        workflow = AppraisalWorkflow.objects.create(
            appraisal=self.appraisal,
            from_status=None,
            to_status='draft',
            action_by=self.employee,
            comments='Initial creation'
        )
        
        self.assertEqual(workflow.appraisal, self.appraisal)
        self.assertIsNone(workflow.from_status)
        self.assertEqual(workflow.to_status, 'draft')
        self.assertEqual(workflow.action_by, self.employee)
    
    def test_workflow_str_representation(self):
        """Test string representation"""
        workflow = AppraisalWorkflow.objects.create(
            appraisal=self.appraisal,
            from_status='draft',
            to_status='submitted',
            action_by=self.employee,
            comments='Submitted for review'
        )
        
        expected = f"{self.appraisal} - draft → submitted"
        self.assertEqual(str(workflow), expected)
    
    def test_action_display_property(self):
        """Test action display property"""
        # Created
        workflow = AppraisalWorkflow.objects.create(
            appraisal=self.appraisal,
            from_status=None,
            to_status='draft',
            action_by=self.employee
        )
        self.assertEqual(workflow.action_display, 'Created')
        
        # Rejected
        workflow.from_status = 'submitted'
        workflow.to_status = 'rejected'
        workflow.save()
        self.assertEqual(workflow.action_display, 'Rejected')
        
        # Approved
        workflow.from_status = 'finance_review'
        workflow.to_status = 'approved'
        workflow.save()
        self.assertEqual(workflow.action_display, 'Approved')
        
        # Status change
        workflow.from_status = 'submitted'
        workflow.to_status = 'hr_review'
        workflow.save()
        self.assertEqual(workflow.action_display, 'Moved to Hr Review')
    
    def test_workflow_ordering(self):
        """Test workflow entries are ordered by timestamp"""
        # Create multiple workflow entries
        workflow1 = AppraisalWorkflow.objects.create(
            appraisal=self.appraisal,
            from_status=None,
            to_status='draft',
            action_by=self.employee
        )
        
        workflow2 = AppraisalWorkflow.objects.create(
            appraisal=self.appraisal,
            from_status='draft',
            to_status='submitted',
            action_by=self.employee
        )
        
        workflow3 = AppraisalWorkflow.objects.create(
            appraisal=self.appraisal,
            from_status='submitted',
            to_status='hr_review',
            action_by=self.manager
        )
        
        # Get workflow entries
        workflows = AppraisalWorkflow.objects.filter(appraisal=self.appraisal)
        
        # Should be in reverse chronological order
        self.assertEqual(workflows[0], workflow3)
        self.assertEqual(workflows[1], workflow2)
        self.assertEqual(workflows[2], workflow1)


class AppraisalAttachmentModelTest(TestCase):
    """Test AppraisalAttachment model"""
    
    def setUp(self):
        """Set up test data"""
        self.employee = User.objects.create_user(
            username='employee_test',
            email='employee@test.com',
            password='testpass123'
        )
        self.manager = User.objects.create_user(
            username='manager_test',
            email='manager@test.com',
            password='testpass123'
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
    
    def test_attachment_str_representation(self):
        """Test string representation"""
        from django.core.files.uploadedfile import SimpleUploadedFile
        
        file = SimpleUploadedFile("test.pdf", b"file_content", content_type="application/pdf")
        
        attachment = AppraisalAttachment.objects.create(
            appraisal=self.appraisal,
            file=file,
            title='Test Certificate',
            uploaded_by=self.employee
        )
        
        expected = f"{attachment.title} - {self.appraisal}"
        self.assertEqual(str(attachment), expected)
