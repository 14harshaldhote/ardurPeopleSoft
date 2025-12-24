"""
Support Ticket Module Integration Tests

URL-based tests for support ticket access across all roles.
"""

from .base import IntegrationTestCase


class SupportIntegrationTests(IntegrationTestCase):
    """Integration tests for Support Ticket Module."""
    
    def test_hr_can_access_support_dashboard(self):
        """
        TEST CASE: SUPPORT-001
        HR can access the support dashboard.
        """
        self.log_test_start('SUPPORT-001', 'Support Module', ['HR'], 'HR Dashboard Access')
        
        try:
            hr = self.users['hr']
            
            self.logger.log_step(1, "HR logs in")
            self.login_as(hr)
            
            self.logger.log_step(2, "Access support dashboard")
            response = self.get('/support/')
            self.assert_status_code(response, 200, "HR should access support dashboard")
            
            self.log_test_end('SUPPORT-001', passed=True)
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('SUPPORT-001', passed=False)
            raise

    def test_employee_can_view_my_tickets(self):
        """
        TEST CASE: SUPPORT-002
        Employee can view their own tickets.
        """
        self.log_test_start('SUPPORT-002', 'Support Module', ['Employee'], 'My Tickets View')
        
        try:
            employee = self.users['employee_01']
            
            self.logger.log_step(1, "Employee logs in")
            self.login_as(employee)
            
            self.logger.log_step(2, "Access my tickets page")
            response = self.get('/support/my-tickets/')
            self.assert_status_code(response, 200, "Employee should view my tickets")
            
            self.log_test_end('SUPPORT-002', passed=True)
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('SUPPORT-002', passed=False)
            raise

    def test_employee_can_access_ticket_create_page(self):
        """
        TEST CASE: SUPPORT-003
        Employee can access ticket creation page.
        """
        self.log_test_start('SUPPORT-003', 'Support Module', ['Employee'], 'Ticket Create Page')
        
        try:
            employee = self.users['employee_01']
            
            self.logger.log_step(1, "Employee logs in")
            self.login_as(employee)
            
            self.logger.log_step(2, "Access create ticket page")
            response = self.get('/support/create/')
            self.assert_status_code(response, 200, "Employee should access create page")
            
            self.log_test_end('SUPPORT-003', passed=True)
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('SUPPORT-003', passed=False)
            raise

    def test_manager_can_access_support(self):
        """
        TEST CASE: SUPPORT-004
        Manager can access support tickets.
        """
        self.log_test_start('SUPPORT-004', 'Support Module', ['Manager'], 'Manager Access')
        
        try:
            manager = self.users['manager']
            
            self.logger.log_step(1, "Manager logs in")
            self.login_as(manager)
            
            self.logger.log_step(2, "Access my tickets")
            response = self.get('/support/my-tickets/')
            self.assert_status_code(response, 200, "Manager should access support")
            
            self.log_test_end('SUPPORT-004', passed=True)
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('SUPPORT-004', passed=False)
            raise

    def test_admin_can_access_support(self):
        """
        TEST CASE: SUPPORT-005
        Admin can access support module.
        """
        self.log_test_start('SUPPORT-005', 'Support Module', ['Admin'], 'Admin Access')
        
        try:
            admin = self.users['admin']
            
            self.logger.log_step(1, "Admin logs in")
            self.login_as(admin)
            
            self.logger.log_step(2, "Access support dashboard")
            response = self.get('/support/')
            self.assert_status_code(response, 200, "Admin should access support")
            
            self.log_test_end('SUPPORT-005', passed=True)
        except Exception as e:
            self.logger.log_error(f"Test failed: {str(e)}", e)
            self.log_test_end('SUPPORT-005', passed=False)
            raise
