"""
Shift Management Module Integration Tests

Tests for shift creation, assignment, approval workflows,
conflict detection, and schedule management.
"""

from datetime import datetime, time, timedelta
from django.utils import timezone
from trueAlign.models import ShiftMaster, ShiftAssignment
from .base import IntegrationTestCase


class ShiftManagementIntegrationTests(IntegrationTestCase):
    """Integration tests for Shift Management Module."""
    
    def test_hr_can_access_shift_dashboard(self):
        """
        TEST CASE: SHIFT-001
        HR can access shift management dashboard.
        """
        self.log_test_start(
            'SHIFT-001',
            'Shift Module',
            ['HR'],
            'HR Dashboard Access'
        )
        
        try:
            hr = self.users['hr']
            
            # Step 1: HR logs in
            self.logger.log_step(1, "HR logs in")
            self.login_as(hr)
            
            # Step 2: Access shift dashboard
            self.logger.log_step(2, "Access shift dashboard")
            response = self.get('/shift/')
            
            self.assert_status_code(response, 200, "HR should access shift dashboard")
            
            self.logger.log_security_check(
                'Shift Dashboard Access',
                'HR',
                '/shift/',
                True
            )
            
            self.log_test_end('SHIFT-001', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('SHIFT-001', passed=False)
            raise

    def test_create_shift_assignment(self):
        """
        TEST CASE: SHIFT-002
        Create shift assignment for employee.
        """
        self.log_test_start(
            'SHIFT-002',
            'Shift Module',
            ['HR', 'Employee'],
            'Create Shift Assignment'
        )
        
        try:
            employee = self.users['employee_01']
            today = timezone.now().date()
            shift = self.fixtures['shifts']['morning']
            
            # Step 1: Create assignment
            self.logger.log_step(1, "Create shift assignment")
            assignment = self.create_object(
                ShiftAssignment,
                user=employee,
                shift=shift,
                effective_from=today,
                is_current=True,
                status='ACTIVE'
            )
            
            # Step 2: Verify assignment created
            self.logger.log_step(2, "Verify assignment exists")
            self.assert_object_exists(
                ShiftAssignment,
                user=employee,
                shift=shift,
                is_current=True
            )
            
            self.assertEqual(assignment.status, 'ACTIVE')
            
            self.log_test_end('SHIFT-002', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('SHIFT-002', passed=False)
            raise

    def test_shift_assignment_workflow(self):
        """
        TEST CASE: SHIFT-003
        Shift assignment approval workflow.
        """
        self.log_test_start(
            'SHIFT-003',
            'Shift Module',
            ['HR', 'Employee'],
            'Shift Assignment Workflow'
        )
        
        try:
            employee = self.users['employee_01']
            hr = self.users['hr']
            today = timezone.now().date()
            shift = self.fixtures['shifts']['evening']
            
            # Step 1: Create pending assignment
            self.logger.log_step(1, "Create pending assignment")
            assignment = self.create_object(
                ShiftAssignment,
                user=employee,
                shift=shift,
                effective_from=today + timedelta(days=7),
                is_current=False,
                status='PENDING'
            )
            
            # Step 2: HR approves
            self.logger.log_step(2, "HR approves assignment")
            self.update_object(assignment, status='ACTIVE')
            
            self.assert_object_field(assignment, 'status', 'ACTIVE')
            
            self.logger.log_cross_module_interaction(
                'ShiftAssignment',
                'Workflow',
                'Approval',
                f'Assignment approved by HR'
            )
            
            self.log_test_end('SHIFT-003', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('SHIFT-003', passed=False)
            raise

    def test_view_shift_list(self):
        """
        TEST CASE: SHIFT-004
        View list of all shifts.
        """
        self.log_test_start(
            'SHIFT-004',
            'Shift Module',
            ['HR'],
            'View Shift List'
        )
        
        try:
            hr = self.users['hr']
            
            # Step 1: Login
            self.logger.log_step(1, "HR logs in")
            self.login_as(hr)
            
            # Step 2: Access shift list
            self.logger.log_step(2, "Access shift list")
            response = self.get('/shift/shifts/')
            
            self.assert_status_code(response, 200, "HR should view shift list")
            
            # Step 3: Verify fixtures shifts exist
            self.logger.log_step(3, "Verify fixtures exist")
            self.assert_object_exists(ShiftMaster, name='Morning Shift')
            self.assert_object_exists(ShiftMaster, name='Evening Shift')
            
            self.log_test_end('SHIFT-004', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('SHIFT-004', passed=False)
            raise

    def test_employee_cannot_access_shift_management(self):
        """
        TEST CASE: SHIFT-005
        Employee cannot access shift management.
        """
        self.log_test_start(
            'SHIFT-005',
            'Shift Module',
            ['Employee'],
            'Employee Access Restriction'
        )
        
        try:
            employee = self.users['employee_01']
            
            # Step 1: Login
            self.logger.log_step(1, "Employee logs in")
            self.login_as(employee)
            
            # Step 2: Try to access shift create
            self.logger.log_step(2, "Try to create shift")
            response = self.get('/shift/shifts/create/')
            
            # Should be denied or redirected
            self.assert_access_denied(response, "Employee should not create shifts")
            
            self.logger.log_security_check(
                'Shift Create Access',
                'Employee',
                '/shift/shifts/create/',
                False
            )
            
            self.log_test_end('SHIFT-005', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('SHIFT-005', passed=False)
            raise

    def test_shift_integrates_with_attendance(self):
        """
        TEST CASE: SHIFT-006
        Shift assignment integrates with attendance.
        """
        self.log_test_start(
            'SHIFT-006',
            'Shift Module',
            ['Employee'],
            'Shift-Attendance Integration'
        )
        
        try:
            from trueAlign.models import Attendance
            
            employee = self.users['employee_01']
            today = timezone.now().date()
            shift = self.fixtures['shifts']['morning']
            
            # Step 1: Create active shift assignment
            self.logger.log_step(1, "Create shift assignment")
            self.create_object(
                ShiftAssignment,
                user=employee,
                shift=shift,
                effective_from=today - timedelta(days=7),
                is_current=True,
                status='ACTIVE'
            )
            
            # Step 2: Login creates attendance
            self.logger.log_step(2, "Employee logs in")
            self.login_as(employee)
            
            # Step 3: Verify attendance created
            self.logger.log_step(3, "Verify attendance exists")
            self.assert_object_exists(Attendance, user=employee, date=today)
            
            self.logger.log_cross_module_interaction(
                'ShiftAssignment',
                'Attendance',
                'Shift Applied',
                f'Morning Shift applied to attendance'
            )
            
            self.log_test_end('SHIFT-006', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('SHIFT-006', passed=False)
            raise
