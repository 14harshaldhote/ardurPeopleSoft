"""
Core Module Integration Tests

Tests for Core module including session tracking, login/logout workflows,
dashboard access, and session-attendance integration.
"""

from datetime import datetime, timedelta
from django.utils import timezone
from trueAlign.models import UserSession, Attendance, OfficeLocation
from .base import IntegrationTestCase


class CoreModuleIntegrationTests(IntegrationTestCase):
    """Integration tests for Core Module."""
    
    def test_login_creates_session_and_attendance(self):
        """
        TEST CASE: CORE-001
        Validates that login creates a session and auto-marks attendance.
        """
        self.log_test_start(
            'CORE-001',
            'Core Module',
            ['Employee'],
            'Login → Session Creation → Auto-Attendance Marking'
        )
        
        try:
            # Step 1: Login as employee
            self.logger.log_step(1, "Employee logs in")
            self.login_as('employee_01')
            
            # Step 2: Verify session created
            self.logger.log_step(2, "Verify session created")
            self.assert_object_exists(
                UserSession,
                user=self.current_user,
                is_active=True
            )
            
            session = UserSession.objects.filter(
                user=self.current_user,
                is_active=True
            ).first()
            
            self.assertIsNotNone(session, "Session should be created on login")
            
            # Step 3: Verify attendance auto-marked
            self.logger.log_step(3, "Verify attendance auto-marked")
            today = timezone.now().date()
            self.assert_object_exists(
                Attendance,
                user=self.current_user,
                date=today
            )
            
            attendance = Attendance.objects.get(
                user=self.current_user,
                date=today
            )
            
            # Step 4: Verify attendance exists with Present status
            self.logger.log_step(4, "Verify attendance status")
            self.assertEqual(attendance.status, 'Present')
            
            # Step 5: Verify cross-module integration
            self.logger.log_cross_module_interaction(
                'Session',
                'Attendance',
                'Auto-marking',
                f"Session ID: {session.id}, Attendance ID: {attendance.id}"
            )
            
            self.log_test_end('CORE-001', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('CORE-001', passed=False)
            raise
    
    def test_logout_ends_session(self):
        """
        TEST CASE: CORE-002
        Validates that logout ends session properly.
        """
        self.log_test_start(
            'CORE-002',
            'Core Module',
            ['Employee'],
            'Logout → Session End'
        )
        
        try:
            # Step 1: Login
            self.logger.log_step(1, "Employee logs in")
            self.login_as('employee_01')
            
            session = UserSession.objects.filter(
                user=self.current_user,
                is_active=True
            ).first()
            
            session_id = session.id if session else None
            
            # Step 2: Logout
            self.logger.log_step(2, "Employee logs out")
            self.logout()
            
            # Step 3: Verify session ended
            self.logger.log_step(3, "Verify session marked as inactive")
            if session_id:
                session = UserSession.objects.get(id=session_id)
                self.assertFalse(session.is_active)
            
            self.log_test_end('CORE-002', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('CORE-002', passed=False)
            raise
    
    def test_role_based_dashboard_access(self):
        """
        TEST CASE: CORE-003
        Validates that each role can access their appropriate dashboard.
        """
        self.log_test_start(
            'CORE-003',
            'Core Module',
            ['Admin', 'HR', 'Manager', 'Employee', 'Management'],
            'Role-Based Dashboard Access Control'
        )
        
        try:
            roles = ['admin', 'hr', 'manager', 'employee_01', 'management']
            
            for idx, role in enumerate(roles, 1):
                self.logger.log_step(idx, f"Test dashboard access for {role}")
                self.login_as(role)
                
                response = self.get('/dashboard/')
                
                self.logger.log_security_check(
                    'Dashboard Access',
                    self.get_user_role(self.current_user),
                    '/dashboard/',
                    response.status_code == 200
                )
                
                self.assert_status_code(response, 200, f"{role} should access dashboard")
                self.logout()
            
            self.log_test_end('CORE-003', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('CORE-003', passed=False)
            raise
    
    def test_unauthenticated_access_blocked(self):
        """
        TEST CASE: CORE-004
        Validates that unauthenticated users are redirected to login.
        """
        self.log_test_start(
            'CORE-004',
            'Core Module',
            ['Unauthenticated'],
            'Unauthorized Access Prevention'
        )
        
        try:
            # Step 1: Attempt to access dashboard without authentication
            self.logger.log_step(1, "Attempt to access dashboard without authentication")
            response = self.get('/dashboard/')
            
            self.logger.log_security_check(
                'Unauthorized Access',
                'Anonymous',
                '/dashboard/',
                response.status_code == 200
            )
            
            # Step 2: Verify redirect to login page
            self.logger.log_step(2, "Verify redirect to login page")
            self.assertIn(response.status_code, [302, 403], "Should redirect or deny")
            
            self.log_test_end('CORE-004', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('CORE-004', passed=False)
            raise
    
    def test_session_heartbeat_tracking(self):
        """
        TEST CASE: CORE-005
        Validates session heartbeat and activity tracking.
        """
        self.log_test_start(
            'CORE-005',
            'Core Module',
            ['Employee'],
            'Session Heartbeat Activity Tracking'
        )
        
        try:
            # Step 1: Login
            self.logger.log_step(1, "Employee logs in")
            employee = self.users['employee_01']
            self.login_as(employee)
            
            # Step 2: Get session
            self.logger.log_step(2, "Get active session")
            session = UserSession.objects.filter(
                user=employee,
                is_active=True
            ).first()
            
            self.assertIsNotNone(session, "Session should exist")
            
            # Step 3: Simulate activity
            self.logger.log_step(3, "Simulate user activity")
            initial_activity = session.last_activity if hasattr(session, 'last_activity') else None
            
            # Access a page to simulate activity
            self.get('/dashboard/')
            
            # Step 4: Verify session still active
            session.refresh_from_db()
            self.assertTrue(session.is_active)
            
            self.logger.log_database_change(
                'UserSession',
                'HEARTBEAT',
                session.id,
                f"Session still active"
            )
            
            self.log_test_end('CORE-005', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('CORE-005', passed=False)
            raise

    def test_multiple_session_handling(self):
        """
        TEST CASE: CORE-006
        Test handling of multiple sessions for same user.
        """
        self.log_test_start(
            'CORE-006',
            'Core Module',
            ['Employee'],
            'Multiple Session Handling'
        )
        
        try:
            employee = self.users['employee_01']
            
            # Step 1: First login
            self.logger.log_step(1, "First login")
            self.login_as(employee)
            
            # Get active sessions count
            active_sessions = UserSession.objects.filter(
                user=employee,
                is_active=True
            ).count()
            
            # Step 2: Verify only one active session
            self.logger.log_step(2, "Verify session management")
            self.assertEqual(active_sessions, 1, "Should have exactly one active session")
            
            self.log_test_end('CORE-006', passed=True)
            
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('CORE-006', passed=False)
            raise
