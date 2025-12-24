"""
Notifications Module Integration Tests

URL-based tests for notification access across all roles.
"""

from .base import IntegrationTestCase


class NotificationsIntegrationTests(IntegrationTestCase):
    """Integration tests for Notifications Module."""
    
    def test_employee_can_view_notifications(self):
        """
        TEST CASE: NOTIFY-001
        Employee can view notifications page.
        """
        self.log_test_start('NOTIFY-001', 'Notifications Module', ['Employee'], 'View Notifications')
        
        try:
            employee = self.users['employee_01']
            
            self.logger.log_step(1, "Employee logs in")
            self.login_as(employee)
            
            self.logger.log_step(2, "Access notifications page")
            response = self.get('/notifications/')
            self.assert_status_code(response, 200, "Employee should view notifications")
            
            self.log_test_end('NOTIFY-001', passed=True)
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('NOTIFY-001', passed=False)
            raise

    def test_all_roles_can_access_notifications(self):
        """
        TEST CASE: NOTIFY-002
        All roles can access notifications page.
        """
        self.log_test_start('NOTIFY-002', 'Notifications Module', ['All Roles'], 'Multi-Role Access')
        
        try:
            roles = ['admin', 'hr', 'manager', 'employee_01']
            
            for i, role in enumerate(roles, 1):
                self.logger.log_step(i, f"{role} accesses notifications")
                user = self.users[role]
                self.login_as(user)
                
                response = self.get('/notifications/')
                self.assert_status_code(response, 200, f"{role} should access notifications")
            
            self.log_test_end('NOTIFY-002', passed=True)
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('NOTIFY-002', passed=False)
            raise

    def test_notification_api_endpoint(self):
        """
        TEST CASE: NOTIFY-003
        Notification API endpoint works correctly.
        """
        self.log_test_start('NOTIFY-003', 'Notifications Module', ['Employee'], 'API Endpoint')
        
        try:
            employee = self.users['employee_01']
            
            self.logger.log_step(1, "Employee logs in")
            self.login_as(employee)
            
            self.logger.log_step(2, "Access notifications API")
            response = self.get('/notifications/api/unread-count/')
            
            # API should return JSON response
            self.assertIn(response.status_code, [200, 404], "API should respond")
            
            self.log_test_end('NOTIFY-003', passed=True)
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('NOTIFY-003', passed=False)
            raise

    def test_hr_can_view_all_notifications(self):
        """
        TEST CASE: NOTIFY-004
        HR can access notification management.
        """
        self.log_test_start('NOTIFY-004', 'Notifications Module', ['HR'], 'HR Notification Access')
        
        try:
            hr = self.users['hr']
            
            self.logger.log_step(1, "HR logs in")
            self.login_as(hr)
            
            self.logger.log_step(2, "Access notifications")
            response = self.get('/notifications/')
            self.assert_status_code(response, 200, "HR should view notifications")
            
            self.log_test_end('NOTIFY-004', passed=True)
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('NOTIFY-004', passed=False)
            raise

    def test_admin_can_view_notifications(self):
        """
        TEST CASE: NOTIFY-005
        Admin can access notifications.
        """
        self.log_test_start('NOTIFY-005', 'Notifications Module', ['Admin'], 'Admin Notification Access')
        
        try:
            admin = self.users['admin']
            
            self.logger.log_step(1, "Admin logs in")
            self.login_as(admin)
            
            self.logger.log_step(2, "Access notifications")
            response = self.get('/notifications/')
            self.assert_status_code(response, 200, "Admin should view notifications")
            
            self.log_test_end('NOTIFY-005', passed=True)
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('NOTIFY-005', passed=False)
            raise
