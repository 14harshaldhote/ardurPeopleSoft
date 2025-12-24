"""
Appraisal Module Integration Tests

Tests for appraisal access and dashboard views.
"""

from datetime import datetime, timedelta
from django.utils import timezone
from trueAlign.models import Appraisal
from .base import IntegrationTestCase


class AppraisalIntegrationTests(IntegrationTestCase):
    """Integration tests for Appraisal Module."""
    
    def test_view_appraisal_list(self):
        """
        TEST CASE: APPRAISAL-001
        Employee can view their appraisal list.
        """
        self.log_test_start(
            'APPRAISAL-001',
            'Appraisal Module',
            ['Employee'],
            'View Appraisal List'
        )
        
        try:
            employee = self.users['employee_01']
            
            # Step 1: Login
            self.logger.log_step(1, "Employee logs in")
            self.login_as(employee)
            
            # Step 2: Access appraisal list
            self.logger.log_step(2, "Access appraisal list")
            response = self.get('/appraisal/')
            
            self.assert_status_code(response, 200, "Employee should view appraisals")
            
            self.log_test_end('APPRAISAL-001', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('APPRAISAL-001', passed=False)
            raise

    def test_create_appraisal(self):
        """
        TEST CASE: APPRAISAL-002
        Create an appraisal for an employee.
        """
        self.log_test_start(
            'APPRAISAL-002',
            'Appraisal Module',
            ['Employee'],
            'Create Appraisal'
        )
        
        try:
            employee = self.users['employee_01']
            manager = self.users['manager']
            today = timezone.now().date()
            
            # Step 1: Create appraisal with all required fields
            self.logger.log_step(1, "Create appraisal")
            appraisal = self.create_object(
                Appraisal,
                user=employee,
                manager=manager,
                title='Annual Performance Review 2025',
                overview='Employee performance overview for 2025',
                period_start=today - timedelta(days=365),
                period_end=today,
                status='draft'
            )
            
            # Step 2: Verify created
            self.logger.log_step(2, "Verify appraisal created")
            self.assert_object_exists(
                Appraisal,
                user=employee,
                status='draft'
            )
            
            self.log_test_end('APPRAISAL-002', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('APPRAISAL-002', passed=False)
            raise

    def test_appraisal_workflow(self):
        """
        TEST CASE: APPRAISAL-003
        Appraisal workflow: Draft → Submitted → Manager Review → Approved.
        """
        self.log_test_start(
            'APPRAISAL-003',
            'Appraisal Module',
            ['Employee', 'Manager'],
            'Appraisal Workflow'
        )
        
        try:
            employee = self.users['employee_01']
            manager = self.users['manager']
            today = timezone.now().date()
            
            # Step 1: Create draft appraisal with all required fields
            self.logger.log_step(1, "Create draft appraisal")
            appraisal = self.create_object(
                Appraisal,
                user=employee,
                manager=manager,
                title='Mid-Year Review',
                overview='Mid-year performance assessment',
                period_start=today - timedelta(days=180),
                period_end=today,
                status='draft'
            )
            
            self.assertEqual(appraisal.status, 'draft')
            
            # Step 2: Submit for review
            self.logger.log_step(2, "Submit for review")
            self.update_object(appraisal, status='submitted')
            self.assert_object_field(appraisal, 'status', 'submitted')
            
            # Step 3: Manager review
            self.logger.log_step(3, "Manager reviews")
            self.update_object(appraisal, status='manager_review')
            self.assert_object_field(appraisal, 'status', 'manager_review')
            
            # Step 4: Approve
            self.logger.log_step(4, "Approve appraisal")
            self.update_object(appraisal, status='approved')
            self.assert_object_field(appraisal, 'status', 'approved')
            
            self.logger.log_cross_module_interaction(
                'Appraisal',
                'Workflow',
                'Status Transition',
                'draft → submitted → manager_review → approved'
            )
            
            self.log_test_end('APPRAISAL-003', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('APPRAISAL-003', passed=False)
            raise

    def test_manager_can_view_team_appraisals(self):
        """
        TEST CASE: APPRAISAL-004
        Manager can view team appraisals.
        """
        self.log_test_start(
            'APPRAISAL-004',
            'Appraisal Module',
            ['Manager'],
            'Manager Team View'
        )
        
        try:
            manager = self.users['manager']
            
            # Step 1: Login as manager
            self.logger.log_step(1, "Manager logs in")
            self.login_as(manager)
            
            # Step 2: Access dashboard
            self.logger.log_step(2, "Access appraisal dashboard")
            response = self.get('/appraisal/dashboard/')
            
            self.assert_status_code(response, 200, "Manager should access dashboard")
            
            self.logger.log_security_check(
                'Appraisal Dashboard Access',
                'Manager',
                '/appraisal/dashboard/',
                True
            )
            
            self.log_test_end('APPRAISAL-004', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('APPRAISAL-004', passed=False)
            raise

    def test_hr_can_export_appraisals(self):
        """
        TEST CASE: APPRAISAL-005
        HR can export appraisals.
        """
        self.log_test_start(
            'APPRAISAL-005',
            'Appraisal Module',
            ['HR'],
            'HR Export Appraisals'
        )
        
        try:
            hr = self.users['hr']
            
            # Step 1: Login as HR
            self.logger.log_step(1, "HR logs in")
            self.login_as(hr)
            
            # Step 2: Access export
            self.logger.log_step(2, "Access appraisal export")
            response = self.get('/appraisal/export/')
            
            self.assert_status_code(response, 200, "HR should export appraisals")
            
            self.logger.log_security_check(
                'Appraisal Export Access',
                'HR',
                '/appraisal/export/',
                True
            )
            
            self.log_test_end('APPRAISAL-005', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('APPRAISAL-005', passed=False)
            raise
