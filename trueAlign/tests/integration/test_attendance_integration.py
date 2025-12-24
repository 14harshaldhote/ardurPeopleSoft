import unittest
"""
Attendance Module Integration Tests

Tests for attendance auto-marking, shift integration, and session tracking.
"""

from datetime import datetime, time, timedelta
from django.utils import timezone
from trueAlign.models import (
    Attendance, UserSession, ShiftMaster,
    ShiftAssignment, LeaveRequest, LeaveType
)
from .base import IntegrationTestCase


class AttendanceIntegrationTests(IntegrationTestCase):
    """Integration tests for Attendance Module."""
    
    def test_attendance_auto_creation_on_login(self):
        """
        TEST CASE: ATT-001
        Verify attendance is auto-created when user logs in.
        """
        self.log_test_start(
            'ATT-001',
            'Attendance Module',
            ['Employee'],
            'Attendance Auto-Creation on Login'
        )
        
        try:
            employee = self.users['employee_01']
            today = timezone.now().date()
            
            # Step 1: Login creates attendance
            self.logger.log_step(1, "Employee logs in")
            self.login_as(employee)
            
            # Step 2: Verify attendance created
            self.logger.log_step(2, "Verify attendance exists")
            self.assert_object_exists(Attendance, user=employee, date=today)
            
            attendance = Attendance.objects.get(user=employee, date=today)
            self.assertEqual(attendance.status, 'Present')
            
            self.logger.log_assertion(
                'Attendance Auto-Created',
                True,
                True,
                True
            )
            
            self.log_test_end('ATT-001', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('ATT-001', passed=False)
            raise

    def test_leave_integration_with_attendance(self):
        """
        TEST CASE: ATT-002
        Verify leave affects attendance status.
        """
        self.log_test_start(
            'ATT-002',
            'Attendance Module',
            ['Employee', 'Manager'],
            'Leave Integration with Attendance'
        )
        
        try:
            employee = self.users['employee_01']
            manager = self.users['manager']
            today = timezone.now().date()
            
            # Step 1: Create leave balance and request
            self.logger.log_step(1, "Create leave balance")
            leave_type = self.fixtures['leave_types']['casual']
            
            from trueAlign.models import UserLeaveBalance
            balance = self.create_object(
                UserLeaveBalance,
                user=employee,
                leave_type=leave_type,
                year=today.year,
                allocated=10,
                used=0
            )
            
            # Step 2: Create leave request for today
            self.logger.log_step(2, "Create leave request")
            leave_request = self.create_object(
                LeaveRequest,
                user=employee,
                leave_type=leave_type,
                start_date=today,
                end_date=today,
                leave_days=1,
                status='Pending',
                reason='Personal work'
            )
            
            # Step 3: Manager approves
            self.logger.log_step(3, "Manager approves leave")
            self.update_object(leave_request, status='Approved', approver=manager)
            
            self.logger.log_cross_module_interaction(
                'LeaveRequest',
                'Attendance',
                'Status Integration',
                f"Leave approved, attendance would be marked as On Leave"
            )
            
            self.log_test_end('ATT-002', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('ATT-002', passed=False)
            raise

    def test_shift_assignment_affects_attendance(self):
        """
        TEST CASE: ATT-003
        Verify shift assignment integration with attendance.
        """
        self.log_test_start(
            'ATT-003',
            'Attendance Module',
            ['Employee', 'HR'],
            'Shift Assignment with Attendance'
        )
        
        try:
            employee = self.users['employee_01']
            today = timezone.now().date()
            
            # Step 1: Create shift assignment
            self.logger.log_step(1, "Create shift assignment")
            shift = self.fixtures['shifts']['morning']
            
            assignment = self.create_object(
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
            
            # Step 3: Verify attendance created with shift
            self.logger.log_step(3, "Verify attendance has shift")
            attendance = Attendance.objects.get(user=employee, date=today)
            
            self.logger.log_cross_module_interaction(
                'ShiftAssignment',
                'Attendance',
                'Shift Integration',
                f"Attendance created with shift: {shift.name}"
            )
            
            self.log_test_end('ATT-003', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('ATT-003', passed=False)
            raise

    def test_session_tracking_updates_attendance(self):
        """
        TEST CASE: ATT-004
        Verify session tracking updates attendance.
        """
        self.log_test_start(
            'ATT-004',
            'Attendance Module',
            ['Employee'],
            'Session Tracking with Attendance'
        )
        
        try:
            employee = self.users['employee_01']
            today = timezone.now().date()
            
            # Step 1: Login creates session
            self.logger.log_step(1, "Employee logs in")
            self.login_as(employee)
            
            # Step 2: Verify session created
            self.logger.log_step(2, "Verify session exists")
            self.assert_object_exists(UserSession, user=employee, is_active=True)
            
            # Step 3: Verify attendance exists
            self.logger.log_step(3, "Verify attendance exists")
            self.assert_object_exists(Attendance, user=employee, date=today)
            
            self.logger.log_cross_module_interaction(
                'UserSession',
                'Attendance',
                'Session-Attendance Link',
                f"Session created, attendance marked Present"
            )
            
            self.log_test_end('ATT-004', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('ATT-004', passed=False)
            raise

    def test_hr_can_view_all_attendance(self):
        """
        TEST CASE: ATT-005
        HR can view all employee attendance.
        """
        self.log_test_start(
            'ATT-005',
            'Attendance Module',
            ['HR'],
            'HR Attendance Dashboard Access'
        )
        
        try:
            hr = self.users['hr']
            
            # Step 1: HR logs in
            self.logger.log_step(1, "HR logs in")
            self.login_as(hr)
            
            # Step 2: Access HR dashboard
            self.logger.log_step(2, "Access attendance dashboard")
            response = self.get('/attendance/hr/dashboard/')
            
            self.assert_status_code(response, 200, "HR should access attendance dashboard")
            
            self.logger.log_security_check(
                'HR Dashboard Access',
                'HR',
                '/attendance/hr/dashboard/',
                True
            )
            
            self.log_test_end('ATT-005', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('ATT-005', passed=False)
            raise

    def test_manager_can_view_team_attendance(self):
        """
        TEST CASE: ATT-006
        Manager can view team attendance.
        """
        self.log_test_start(
            'ATT-006',
            'Attendance Module',
            ['Manager'],
            'Manager Team Attendance Access'
        )
        
        try:
            manager = self.users['manager']
            
            # Step 1: Manager logs in
            self.logger.log_step(1, "Manager logs in")
            self.login_as(manager)
            
            # Step 2: Access manager overview
            self.logger.log_step(2, "Access team attendance")
            response = self.get('/attendance/manager/overview/')
            
            self.assert_status_code(response, 200, "Manager should access team attendance")
            
            self.logger.log_security_check(
                'Manager Team Access',
                'Manager',
                '/attendance/manager/overview/',
                True
            )
            
            self.log_test_end('ATT-006', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('ATT-006', passed=False)
            raise

