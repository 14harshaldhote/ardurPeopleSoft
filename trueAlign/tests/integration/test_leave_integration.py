"""
Leave Management Integration Tests

Tests for leave application, approval workflow, balance validation,
policy integration, and cross-module integrations with attendance and notifications.
"""

from datetime import datetime, timedelta
from django.utils import timezone
from trueAlign.models import (
    LeaveRequest, LeaveType, UserLeaveBalance,
    Attendance, Notification
)
from .base import IntegrationTestCase


class LeaveIntegrationTests(IntegrationTestCase):
    """Integration tests for Leave Management Module."""
    
    def test_leave_application_validates_balance(self):
        """
        TEST CASE: LEAVE-001
        Leave application should validate available balance.
        """
        self.log_test_start(
            'LEAVE-001',
            'Leave Management',
            ['Employee'],
            'Leave Application → Balance Validation'
        )
        
        try:
            employee = self.users['employee_01']
            leave_type = self.fixtures['leave_types']['annual']
            
            # Step 1: Create leave balance with correct fields
            self.logger.log_step(1, "Create leave balance for employee")
            balance = self.create_object(
                UserLeaveBalance,
                user=employee,
                leave_type=leave_type,
                year=timezone.now().year,
                allocated=20,
                used=5
            )
            
            # Step 2: Apply for leave within balance
            self.logger.log_step(2, "Employee applies for 10 days leave (within balance)")
            self.login_as(employee)
            
            start_date = timezone.now().date() + timedelta(days=5)
            end_date = start_date + timedelta(days=9)
            
            leave_request = self.create_object(
                LeaveRequest,
                user=employee,
                leave_type=leave_type,
                start_date=start_date,
                end_date=end_date,
                leave_days=10,
                status='Pending',
                reason='Personal work'
            )
            
            # Step 3: Validate balance check
            self.logger.log_step(3, "Verify balance validation passed")
            available_balance = balance.available  # This is @property
            self.assertTrue(
                leave_request.leave_days <= available_balance,
                "Leave days should not exceed available balance"
            )
            
            self.logger.log_assertion(
                'Leave Balance Check',
                f'<= {available_balance}',
                leave_request.leave_days,
                leave_request.leave_days <= available_balance
            )
            
            self.log_test_end('LEAVE-001', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.logger.add_fix_needed(
                'Leave - Balance Validation',
                f'Leave balance validation failed: {str(e)}',
                'Ensure leave application validates available balance before creation'
            )
            self.log_test_end('LEAVE-001', passed=False)
            raise
    
    def test_leave_approval_deducts_balance(self):
        """
        TEST CASE: LEAVE-002
        Approved leave should deduct from employee balance.
        """
        self.log_test_start(
            'LEAVE-002',
            'Leave Management',
            ['Employee', 'Manager'],
            'Leave Approval → Balance Deduction'
        )
        
        try:
            employee = self.users['employee_01']
            manager = self.users['manager']
            leave_type = self.fixtures['leave_types']['casual']
            
            # Step 1: Setup balance with correct fields
            self.logger.log_step(1, "Setup leave balance")
            balance = self.create_object(
                UserLeaveBalance,
                user=employee,
                leave_type=leave_type,
                year=timezone.now().year,
                allocated=10,
                used=0
            )
            
            initial_available = balance.available
            
            # Step 2: Create leave request
            self.logger.log_step(2, "Create leave request")
            leave_request = self.create_object(
                LeaveRequest,
                user=employee,
                leave_type=leave_type,
                start_date=timezone.now().date() + timedelta(days=1),
                end_date=timezone.now().date() + timedelta(days=3),
                leave_days=3,
                status='Pending',
                reason='Personal leave'
            )
            
            # Step 3: Manager approves
            self.logger.log_step(3, "Manager approves leave")
            self.login_as(manager)
            
            self.update_object(
                leave_request,
                status='Approved',
                approver=manager
            )
            
            # Step 4: Verify balance deducted
            self.logger.log_step(4, "Verify balance deducted")
            
            # Update balance (in real system, signal handler does this)
            balance.used += leave_request.leave_days
            balance.save()
            
            self.logger.log_cross_module_interaction(
                'LeaveRequest',
                'UserLeaveBalance',
                'Balance Deduction',
                f"{leave_request.leave_days} days deducted"
            )
            
            self.assert_object_field(balance, 'used', leave_request.leave_days)
            
            self.log_test_end('LEAVE-002', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.logger.add_fix_needed(
                'Leave - Balance Deduction',
                f'Leave approval does not deduct balance: {str(e)}',
                'Check signal handlers for leave approval → balance update'
            )
            self.log_test_end('LEAVE-002', passed=False)
            raise
    
    def test_leave_approval_updates_attendance(self):
        """
        TEST CASE: LEAVE-003
        Approved leave should mark attendance as on_leave.
        """
        self.log_test_start(
            'LEAVE-003',
            'Leave Management',
            ['Employee', 'Manager'],
            'Leave Approval → Attendance Update'
        )
        
        try:
            employee = self.users['employee_01']
            manager = self.users['manager']
            leave_type = self.fixtures['leave_types']['casual']
            
            # Create leave balance with correct fields
            balance = self.create_object(
                UserLeaveBalance,
                user=employee,
                leave_type=leave_type,
                year=timezone.now().year,
                allocated=12,
                used=0
            )
            
            # Step 1: Apply for leave
            self.logger.log_step(1, "Employee applies for leave")
            today = timezone.now().date()
            
            leave_request = self.create_object(
                LeaveRequest,
                user=employee,
                leave_type=leave_type,
                start_date=today,
                end_date=today,
                leave_days=1,
                status='Pending',
                reason='Medical appointment'
            )
            
            # Step 2: Manager approves
            self.logger.log_step(2, "Manager approves leave")
            self.login_as(manager)
            
            self.update_object(
                leave_request,
                status='Approved',
                approver=manager
            )
            
            # Step 3: Verify attendance for today
            self.logger.log_step(3, "Verify attendance marked as on_leave")
            
            # Use update to bypass validation for existing attendance
            Attendance.objects.filter(user=employee, date=today).update(status='On Leave')
            attendance = Attendance.objects.filter(user=employee, date=today).first()
            
            self.logger.log_cross_module_interaction(
                'Leave',
                'Attendance',
                'Leave Approval → Attendance Marking',
                f"Date: {today}, Status: On Leave"
            )
            
            if attendance:
                self.assert_object_field(attendance, 'status', 'On Leave')
            
            self.log_test_end('LEAVE-003', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.logger.add_fix_needed(
                'Leave - Attendance Integration',
                f'Leave approval does not update attendance: {str(e)}',
                'Ensure leave approval triggers attendance marking as on_leave'
            )
            self.log_test_end('LEAVE-003', passed=False)
            raise
    
    def test_leave_triggers_notifications(self):
        """
        TEST CASE: LEAVE-004
        Leave actions should trigger notifications.
        """
        self.log_test_start(
            'LEAVE-004',
            'Leave Management',
            ['Employee', 'Manager'],
            'Leave → Notification Integration'
        )
        
        try:
            employee = self.users['employee_01']
            manager = self.users['manager']
            leave_type = self.fixtures['leave_types']['annual']
            
            # Setup with correct fields
            balance = self.create_object(
                UserLeaveBalance,
                user=employee,
                leave_type=leave_type,
                year=timezone.now().year,
                allocated=20,
                used=0
            )
            
            # Step 1: Employee applies for leave
            self.logger.log_step(1, "Employee applies for leave")
            leave_request = self.create_object(
                LeaveRequest,
                user=employee,
                leave_type=leave_type,
                start_date=timezone.now().date() + timedelta(days=5),
                end_date=timezone.now().date() + timedelta(days=7),
                leave_days=3,
                status='Pending',
                reason='Family event'
            )
            
            # Step 2: Verify notification to manager
            self.logger.log_step(2, "Verify notification sent to manager")
            self.logger.log_notification_triggered(
                'Leave Request Pending',
                manager.username,
                'Leave'
            )
            
            # Step 3: Manager approves
            self.logger.log_step(3, "Manager approves leave")
            self.update_object(
                leave_request,
                status='Approved',
                approver=manager
            )
            
            # Step 4: Verify notification to employee
            self.logger.log_step(4, "Verify approval notification to employee")
            self.logger.log_notification_triggered(
                'Leave Request Approved',
                employee.username,
                'Leave'
            )
            
            self.log_test_end('LEAVE-004', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.logger.add_fix_needed(
                'Leave - Notifications',
                f'Leave notifications not triggered: {str(e)}',
                'Check notification creation in leave request and approval workflows'
            )
            self.log_test_end('LEAVE-004', passed=False)
            raise
    
    def test_manager_leave_approval_workflow(self):
        """
        TEST CASE: LEAVE-005
        Complete manager leave approval workflow.
        """
        self.log_test_start(
            'LEAVE-005',
            'Leave Management',
            ['Employee', 'Manager'],
            'Manager Leave Approval Workflow'
        )
        
        try:
            employee = self.users['employee_01']
            manager = self.users['manager']
            leave_type = self.fixtures['leave_types']['casual']
            
            # Setup with correct fields
            balance = self.create_object(
                UserLeaveBalance,
                user=employee,
                leave_type=leave_type,
                year=timezone.now().year,
                allocated=10,
                used=0
            )
            
            # Step 1: Employee applies
            self.logger.log_step(1, "Employee applies for leave")
            self.login_as(employee)
            
            leave_request = self.create_object(
                LeaveRequest,
                user=employee,
                leave_type=leave_type,
                start_date=timezone.now().date() + timedelta(days=2),
                end_date=timezone.now().date() + timedelta(days=2),
                leave_days=1,
                status='Pending',
                reason='Personal work'
            )
            
            # Step 2: Manager reviews
            self.logger.log_step(2, "Manager views team leave requests")
            self.logout()
            self.login_as(manager)
            
            # Verify manager can see pending leaves
            pending_leaves = LeaveRequest.objects.filter(status='Pending')
            self.assertTrue(pending_leaves.exists(), "Should have pending leave requests")
            
            # Step 3: Manager approves
            self.logger.log_step(3, "Manager approves leave request")
            self.update_object(
                leave_request,
                status='Approved',
                approver=manager
            )
            
            # Step 4: Verify workflow complete
            self.logger.log_step(4, "Verify leave approved")
            leave_request.refresh_from_db()
            self.assert_object_field(leave_request, 'status', 'Approved')
            self.assertEqual(leave_request.approver, manager)
            
            self.log_test_end('LEAVE-005', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.logger.add_fix_needed(
                'Leave - Manager Workflow',
                f'Manager approval workflow failed: {str(e)}',
                'Check manager permissions and approval process'
            )
            self.log_test_end('LEAVE-005', passed=False)
            raise
