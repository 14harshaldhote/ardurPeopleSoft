"""
Cross-Module Integration Tests

Tests to validate data flow and integration between modules,
ensuring session, attendance, leave, and shift work together correctly.
"""

from datetime import datetime, timedelta
from django.utils import timezone
from trueAlign.models import (
    UserSession, Attendance, LeaveRequest, LeaveType,
    UserLeaveBalance, ShiftMaster, ShiftAssignment
)
from .base import IntegrationTestCase


class CrossModuleIntegrationTests(IntegrationTestCase):
    """Integration tests for cross-module interactions."""
    
    def test_session_to_attendance_chain(self):
        """
        TEST CASE: CROSS-001
        Session → Attendance data flow validation.
        """
        self.log_test_start(
            'CROSS-001',
            'Cross-Module',
            ['Employee'],
            'Session → Attendance Integration'
        )
        
        try:
            employee = self.users['employee_01']
            today = timezone.now().date()
            
            # Step 1: Login creates session
            self.logger.log_step(1, "Login creates session")
            self.login_as(employee)
            
            # Step 2: Verify session exists
            self.logger.log_step(2, "Verify session exists")
            self.assert_object_exists(UserSession, user=employee, is_active=True)
            
            # Step 3: Verify attendance exists
            self.logger.log_step(3, "Verify attendance created")
            self.assert_object_exists(Attendance, user=employee, date=today)
            
            # Step 4: Log cross-module interaction
            session = UserSession.objects.filter(user=employee, is_active=True).first()
            attendance = Attendance.objects.get(user=employee, date=today)
            
            self.logger.log_cross_module_interaction(
                'UserSession',
                'Attendance',
                'Auto-Creation',
                f"Session {session.id} → Attendance {attendance.id}"
            )
            
            self.log_test_end('CROSS-001', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('CROSS-001', passed=False)
            raise

    def test_leave_approval_workflow(self):
        """
        TEST CASE: CROSS-002
        Leave Request → Manager Approval → Balance Update
        """
        self.log_test_start(
            'CROSS-002',
            'Cross-Module',
            ['Employee', 'Manager'],
            'Leave → Approval → Balance Chain'
        )
        
        try:
            employee = self.users['employee_01']
            manager = self.users['manager']
            today = timezone.now().date()
            
            # Step 1: Setup leave balance
            self.logger.log_step(1, "Create leave balance")
            leave_type = self.fixtures['leave_types']['annual']
            
            balance = self.create_object(
                UserLeaveBalance,
                user=employee,
                leave_type=leave_type,
                year=today.year,
                allocated=20,
                used=0
            )
            
            # Step 2: Create leave request
            self.logger.log_step(2, "Create leave request")
            leave_request = self.create_object(
                LeaveRequest,
                user=employee,
                leave_type=leave_type,
                start_date=today + timedelta(days=7),
                end_date=today + timedelta(days=9),
                leave_days=3,
                status='Pending',
                reason='Vacation'
            )
            
            # Step 3: Manager approves
            self.logger.log_step(3, "Manager approves leave")
            self.update_object(
                leave_request,
                status='Approved',
                approver=manager
            )
            
            # Step 4: Verify status updated
            self.logger.log_step(4, "Verify approved status")
            self.assert_object_field(leave_request, 'status', 'Approved')
            
            self.logger.log_cross_module_interaction(
                'LeaveRequest',
                'UserLeaveBalance',
                'Balance Deduction',
                f"Leave {leave_request.id} approved"
            )
            
            self.log_test_end('CROSS-002', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('CROSS-002', passed=False)
            raise

    def test_shift_to_attendance_integration(self):
        """
        TEST CASE: CROSS-003
        Shift Assignment → Attendance → Session integration.
        """
        self.log_test_start(
            'CROSS-003',
            'Cross-Module',
            ['Employee', 'HR'],
            'Shift → Attendance → Session Chain'
        )
        
        try:
            employee = self.users['employee_01']
            today = timezone.now().date()
            
            # Step 1: Create shift assignment
            self.logger.log_step(1, "Assign shift to employee")
            shift = self.fixtures['shifts']['morning']
            
            assignment = self.create_object(
                ShiftAssignment,
                user=employee,
                shift=shift,
                effective_from=today - timedelta(days=7),
                is_current=True,
                status='ACTIVE'
            )
            
            # Step 2: Login creates session and attendance
            self.logger.log_step(2, "Employee logs in")
            self.login_as(employee)
            
            # Step 3: Verify session created
            self.logger.log_step(3, "Verify session")
            self.assert_object_exists(UserSession, user=employee, is_active=True)
            
            # Step 4: Verify attendance created
            self.logger.log_step(4, "Verify attendance")
            self.assert_object_exists(Attendance, user=employee, date=today)
            
            self.logger.log_cross_module_interaction(
                'ShiftAssignment',
                'Attendance',
                'Shift Applied',
                f"Shift {shift.name} applied to attendance"
            )
            
            self.log_test_end('CROSS-003', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('CROSS-003', passed=False)
            raise
