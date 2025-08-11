#!/usr/bin/env python
"""
Manual Frontend Testing Checklist
=================================

Interactive testing script for final validation of the Leave Management System frontend.
This script guides testers through comprehensive manual testing scenarios.

Usage: python manual_frontend_test_checklist.py

Author: Ardur Technology
Date: 2025-08-10
"""

import os
import sys
from datetime import datetime
import json

class ManualTestingChecklist:
    def __init__(self):
        self.test_results = {
            'timestamp': datetime.now().isoformat(),
            'tester': '',
            'categories': {},
            'overall_status': 'PENDING',
            'issues_found': [],
            'recommendations': []
        }
        self.current_category = None

    def print_header(self):
        print("=" * 80)
        print("🧪 LEAVE MANAGEMENT SYSTEM - MANUAL TESTING CHECKLIST")
        print("=" * 80)
        print("This interactive script will guide you through comprehensive manual testing")
        print("of all key frontend features and workflows.\n")

        tester_name = input("👤 Enter tester name: ").strip()
        self.test_results['tester'] = tester_name

        print(f"\nWelcome, {tester_name}!")
        print("Please follow each test step carefully and report results accurately.\n")

    def get_user_input(self, prompt, valid_options=['y', 'n']):
        """Get validated user input"""
        while True:
            response = input(f"{prompt} ({'/'.join(valid_options)}): ").strip().lower()
            if response in valid_options:
                return response
            print(f"Please enter one of: {', '.join(valid_options)}")

    def record_test_result(self, test_name, status, notes=""):
        """Record individual test result"""
        if self.current_category not in self.test_results['categories']:
            self.test_results['categories'][self.current_category] = {
                'tests': {},
                'passed': 0,
                'failed': 0,
                'total': 0
            }

        self.test_results['categories'][self.current_category]['tests'][test_name] = {
            'status': status,
            'notes': notes,
            'timestamp': datetime.now().isoformat()
        }

        self.test_results['categories'][self.current_category]['total'] += 1

        if status == 'PASS':
            self.test_results['categories'][self.current_category]['passed'] += 1
            icon = "✅"
        else:
            self.test_results['categories'][self.current_category]['failed'] += 1
            icon = "❌"
            if notes:
                self.test_results['issues_found'].append(f"{test_name}: {notes}")

        print(f"{icon} {test_name}: {status}")
        if notes:
            print(f"   📝 Notes: {notes}")

    def test_authentication_flow(self):
        """Test 1: Authentication and Login Flow"""
        self.current_category = "Authentication Flow"
        print("\n" + "=" * 60)
        print("🔑 TEST CATEGORY 1: AUTHENTICATION FLOW")
        print("=" * 60)

        print("\n📋 Instructions:")
        print("1. Open your web browser")
        print("2. Navigate to: http://127.0.0.1:8000/login/")
        print("3. Test the following scenarios:\n")

        # Test 1.1: Login page accessibility
        print("🧪 TEST 1.1: Login Page Access")
        print("- Verify the login page loads without errors")
        print("- Check that the page displays properly on desktop and mobile")
        result = self.get_user_input("Does the login page load correctly?")
        notes = input("Any issues or notes: ").strip() if result == 'n' else ""
        self.record_test_result("Login Page Access", "PASS" if result == 'y' else "FAIL", notes)

        # Test 1.2: Form elements present
        print("\n🧪 TEST 1.2: Login Form Elements")
        print("- Verify username/employee ID field is present")
        print("- Verify password field is present")
        print("- Verify submit button is present and clickable")
        result = self.get_user_input("Are all login form elements present and functional?")
        notes = input("Any missing elements: ").strip() if result == 'n' else ""
        self.record_test_result("Login Form Elements", "PASS" if result == 'y' else "FAIL", notes)

        # Test 1.3: Invalid login
        print("\n🧪 TEST 1.3: Invalid Login Handling")
        print("- Try logging in with incorrect credentials")
        print("- Verify appropriate error message is shown")
        result = self.get_user_input("Does invalid login show proper error message?")
        notes = input("Error message details: ").strip() if result == 'n' else ""
        self.record_test_result("Invalid Login Handling", "PASS" if result == 'y' else "FAIL", notes)

        # Test 1.4: Valid login
        print("\n🧪 TEST 1.4: Valid Login")
        print("- Log in with valid credentials (testEmployee/testpass123)")
        print("- Verify successful redirect to dashboard")
        result = self.get_user_input("Does valid login redirect to dashboard successfully?")
        notes = input("Any redirect issues: ").strip() if result == 'n' else ""
        self.record_test_result("Valid Login Success", "PASS" if result == 'y' else "FAIL", notes)

    def test_dashboard_functionality(self):
        """Test 2: Dashboard Functionality"""
        self.current_category = "Dashboard Functionality"
        print("\n" + "=" * 60)
        print("📊 TEST CATEGORY 2: DASHBOARD FUNCTIONALITY")
        print("=" * 60)

        print("\n📋 Instructions:")
        print("Ensure you're logged in and test the following dashboards:\n")

        # Test 2.1: Main dashboard
        print("🧪 TEST 2.1: Main Dashboard")
        print("- Navigate to main dashboard")
        print("- Verify role-based dashboard selection is shown")
        print("- Check notifications section displays")
        result = self.get_user_input("Is the main dashboard functional with all sections?")
        notes = input("Any missing sections: ").strip() if result == 'n' else ""
        self.record_test_result("Main Dashboard Display", "PASS" if result == 'y' else "FAIL", notes)

        # Test 2.2: Employee dashboard
        print("\n🧪 TEST 2.2: Employee Dashboard")
        print("- Click on Employee Dashboard")
        print("- Verify leave statistics are shown")
        print("- Check leave balance information displays")
        print("- Verify navigation links work")
        result = self.get_user_input("Is the employee dashboard fully functional?")
        notes = input("Any display issues: ").strip() if result == 'n' else ""
        self.record_test_result("Employee Dashboard", "PASS" if result == 'y' else "FAIL", notes)

        # Test 2.3: Manager dashboard (if applicable)
        manager_test = self.get_user_input("Do you have manager access to test?", ['y', 'n', 'skip'])
        if manager_test == 'y':
            print("\n🧪 TEST 2.3: Manager Dashboard")
            print("- Access manager dashboard")
            print("- Verify team leave requests are shown")
            print("- Check pending approvals section")
            result = self.get_user_input("Is the manager dashboard functional?")
            notes = input("Any issues: ").strip() if result == 'n' else ""
            self.record_test_result("Manager Dashboard", "PASS" if result == 'y' else "FAIL", notes)
        elif manager_test == 'skip':
            self.record_test_result("Manager Dashboard", "SKIP", "Tester doesn't have manager access")

        # Test 2.4: HR dashboard (if applicable)
        hr_test = self.get_user_input("Do you have HR access to test?", ['y', 'n', 'skip'])
        if hr_test == 'y':
            print("\n🧪 TEST 2.4: HR Dashboard")
            print("- Access HR dashboard")
            print("- Verify company-wide statistics")
            print("- Check employee management features")
            result = self.get_user_input("Is the HR dashboard functional?")
            notes = input("Any issues: ").strip() if result == 'n' else ""
            self.record_test_result("HR Dashboard", "PASS" if result == 'y' else "FAIL", notes)
        elif hr_test == 'skip':
            self.record_test_result("HR Dashboard", "SKIP", "Tester doesn't have HR access")

    def test_leave_application_workflow(self):
        """Test 3: Leave Application Workflow"""
        self.current_category = "Leave Application Workflow"
        print("\n" + "=" * 60)
        print("📋 TEST CATEGORY 3: LEAVE APPLICATION WORKFLOW")
        print("=" * 60)

        print("\n📋 Instructions:")
        print("Test the complete leave application process:\n")

        # Test 3.1: Apply leave form access
        print("🧪 TEST 3.1: Apply Leave Form Access")
        print("- Navigate to Apply Leave page")
        print("- Verify form loads without errors")
        print("- Check leave balance panel is visible")
        result = self.get_user_input("Does the apply leave form load correctly?")
        notes = input("Any loading issues: ").strip() if result == 'n' else ""
        self.record_test_result("Apply Leave Form Access", "PASS" if result == 'y' else "FAIL", notes)

        # Test 3.2: Form elements
        print("\n🧪 TEST 3.2: Form Elements Validation")
        print("- Verify leave type dropdown has options")
        print("- Check start date and end date pickers work")
        print("- Verify reason text area is present")
        print("- Check submit button is enabled")
        result = self.get_user_input("Are all form elements present and functional?")
        notes = input("Missing elements: ").strip() if result == 'n' else ""
        self.record_test_result("Form Elements Complete", "PASS" if result == 'y' else "FAIL", notes)

        # Test 3.3: Date validation
        print("\n🧪 TEST 3.3: Date Validation")
        print("- Try entering end date before start date")
        print("- Try entering past dates")
        print("- Verify validation messages appear")
        result = self.get_user_input("Does date validation work properly?")
        notes = input("Validation issues: ").strip() if result == 'n' else ""
        self.record_test_result("Date Validation", "PASS" if result == 'y' else "FAIL", notes)

        # Test 3.4: Successful submission
        print("\n🧪 TEST 3.4: Leave Request Submission")
        print("- Fill out form with valid data:")
        print("  * Select a leave type")
        print("  * Choose future start and end dates")
        print("  * Add a reason")
        print("- Submit the form")
        print("- Verify success message or redirect")
        result = self.get_user_input("Does leave submission work successfully?")
        notes = input("Submission issues: ").strip() if result == 'n' else ""
        self.record_test_result("Leave Request Submission", "PASS" if result == 'y' else "FAIL", notes)

    def test_leave_management_pages(self):
        """Test 4: Leave Management Pages"""
        self.current_category = "Leave Management Pages"
        print("\n" + "=" * 60)
        print("📑 TEST CATEGORY 4: LEAVE MANAGEMENT PAGES")
        print("=" * 60)

        print("\n📋 Instructions:")
        print("Test all leave management list pages:\n")

        # Test 4.1: My Leaves page
        print("🧪 TEST 4.1: My Leaves Page")
        print("- Navigate to My Leaves page")
        print("- Verify leave requests are displayed")
        print("- Check status filters work")
        print("- Test pagination if multiple requests exist")
        result = self.get_user_input("Is the My Leaves page fully functional?")
        notes = input("Any display/filter issues: ").strip() if result == 'n' else ""
        self.record_test_result("My Leaves Page", "PASS" if result == 'y' else "FAIL", notes)

        # Test 4.2: Leave Balance page
        print("\n🧪 TEST 4.2: Leave Balance Page")
        print("- Navigate to Leave Balance page")
        print("- Verify all leave types are shown")
        print("- Check balance calculations are correct")
        print("- Verify progress bars display properly")
        result = self.get_user_input("Is the Leave Balance page accurate?")
        notes = input("Balance/display issues: ").strip() if result == 'n' else ""
        self.record_test_result("Leave Balance Page", "PASS" if result == 'y' else "FAIL", notes)

        # Test 4.3: Comp Off page
        print("\n🧪 TEST 4.3: Comp Off Page")
        print("- Navigate to Comp Off page")
        print("- Verify comp off requests are listed")
        print("- Check apply comp off functionality")
        result = self.get_user_input("Is the Comp Off page working correctly?")
        notes = input("Comp off issues: ").strip() if result == 'n' else ""
        self.record_test_result("Comp Off Page", "PASS" if result == 'y' else "FAIL", notes)

    def test_api_functionality(self):
        """Test 5: API and AJAX Functionality"""
        self.current_category = "API Functionality"
        print("\n" + "=" * 60)
        print("📡 TEST CATEGORY 5: API AND AJAX FUNCTIONALITY")
        print("=" * 60)

        print("\n📋 Instructions:")
        print("Test API endpoints and dynamic functionality:\n")

        # Test 5.1: Dynamic form behavior
        print("🧪 TEST 5.1: Dynamic Form Behavior")
        print("- Go to Apply Leave form")
        print("- Change leave type and verify balance updates")
        print("- Change dates and verify day calculation")
        result = self.get_user_input("Do forms update dynamically (AJAX working)?")
        notes = input("Dynamic issues: ").strip() if result == 'n' else ""
        self.record_test_result("Dynamic Form Updates", "PASS" if result == 'y' else "FAIL", notes)

        # Test 5.2: Real-time validation
        print("\n🧪 TEST 5.2: Real-time Validation")
        print("- Test form validation as you type")
        print("- Verify error messages appear/disappear dynamically")
        result = self.get_user_input("Does real-time validation work properly?")
        notes = input("Validation issues: ").strip() if result == 'n' else ""
        self.record_test_result("Real-time Validation", "PASS" if result == 'y' else "FAIL", notes)

    def test_responsive_design(self):
        """Test 6: Responsive Design"""
        self.current_category = "Responsive Design"
        print("\n" + "=" * 60)
        print("📱 TEST CATEGORY 6: RESPONSIVE DESIGN")
        print("=" * 60)

        print("\n📋 Instructions:")
        print("Test mobile and tablet responsiveness:\n")

        # Test 6.1: Mobile layout
        print("🧪 TEST 6.1: Mobile Layout")
        print("- Resize browser to mobile width (320px-768px)")
        print("- Or test on actual mobile device")
        print("- Verify all pages adapt properly")
        print("- Check navigation menu works on mobile")
        result = self.get_user_input("Does the system work well on mobile?")
        notes = input("Mobile issues: ").strip() if result == 'n' else ""
        self.record_test_result("Mobile Responsiveness", "PASS" if result == 'y' else "FAIL", notes)

        # Test 6.2: Tablet layout
        print("\n🧪 TEST 6.2: Tablet Layout")
        print("- Resize browser to tablet width (768px-1024px)")
        print("- Verify layout adapts appropriately")
        print("- Check touch interactions work")
        result = self.get_user_input("Does the system work well on tablet?")
        notes = input("Tablet issues: ").strip() if result == 'n' else ""
        self.record_test_result("Tablet Responsiveness", "PASS" if result == 'y' else "FAIL", notes)

    def test_role_based_security(self):
        """Test 7: Role-based Security"""
        self.current_category = "Security Testing"
        print("\n" + "=" * 60)
        print("🔐 TEST CATEGORY 7: ROLE-BASED SECURITY")
        print("=" * 60)

        print("\n📋 Instructions:")
        print("Test access control and security:\n")

        # Test 7.1: Unauthorized access
        print("🧪 TEST 7.1: Unauthorized Access Prevention")
        print("- Try accessing pages without login")
        print("- Verify redirect to login page")
        result = self.get_user_input("Are protected pages properly secured?")
        notes = input("Security issues: ").strip() if result == 'n' else ""
        self.record_test_result("Unauthorized Access Prevention", "PASS" if result == 'y' else "FAIL", notes)

        # Test 7.2: Cross-role access
        print("\n🧪 TEST 7.2: Cross-role Access Restrictions")
        print("- As employee, try accessing manager URLs directly")
        print("- Verify proper access denial or redirect")
        result = self.get_user_input("Are role restrictions properly enforced?")
        notes = input("Role access issues: ").strip() if result == 'n' else ""
        self.record_test_result("Role Access Restrictions", "PASS" if result == 'y' else "FAIL", notes)

    def test_error_handling(self):
        """Test 8: Error Handling"""
        self.current_category = "Error Handling"
        print("\n" + "=" * 60)
        print("❗ TEST CATEGORY 8: ERROR HANDLING")
        print("=" * 60)

        print("\n📋 Instructions:")
        print("Test error scenarios and recovery:\n")

        # Test 8.1: Network errors
        print("🧪 TEST 8.1: Network Error Handling")
        print("- Temporarily disconnect internet/network")
        print("- Try submitting forms")
        print("- Verify graceful error messages")
        result = self.get_user_input("Are network errors handled gracefully?")
        notes = input("Error handling issues: ").strip() if result == 'n' else ""
        self.record_test_result("Network Error Handling", "PASS" if result == 'y' else "FAIL", notes)

        # Test 8.2: Invalid data submission
        print("\n🧪 TEST 8.2: Invalid Data Handling")
        print("- Submit forms with invalid data")
        print("- Verify clear error messages")
        print("- Check form doesn't break")
        result = self.get_user_input("Are invalid data errors handled well?")
        notes = input("Data error issues: ").strip() if result == 'n' else ""
        self.record_test_result("Invalid Data Handling", "PASS" if result == 'y' else "FAIL", notes)

    def generate_final_report(self):
        """Generate final testing report"""
        print("\n" + "=" * 80)
        print("📊 MANUAL TESTING COMPLETE - GENERATING REPORT")
        print("=" * 80)

        total_tests = 0
        total_passed = 0
        total_failed = 0
        total_skipped = 0

        for category, data in self.test_results['categories'].items():
            total_tests += data['total']
            total_passed += data['passed']
            total_failed += data['failed']

            # Count skipped tests
            for test_name, test_data in data['tests'].items():
                if test_data['status'] == 'SKIP':
                    total_skipped += 1

        success_rate = (total_passed / total_tests * 100) if total_tests > 0 else 0

        # Determine overall status
        if total_failed == 0:
            if success_rate >= 90:
                self.test_results['overall_status'] = 'EXCELLENT'
                status_icon = '🌟'
            else:
                self.test_results['overall_status'] = 'GOOD'
                status_icon = '✅'
        elif total_failed <= 2:
            self.test_results['overall_status'] = 'MODERATE'
            status_icon = '⚠️'
        else:
            self.test_results['overall_status'] = 'POOR'
            status_icon = '❌'

        # Print summary
        print(f"\n{status_icon} OVERALL STATUS: {self.test_results['overall_status']}")
        print(f"🎯 SUCCESS RATE: {success_rate:.1f}% ({total_passed}/{total_tests})")
        print(f"\n📈 TEST SUMMARY:")
        print(f"   ✅ Passed: {total_passed}")
        print(f"   ❌ Failed: {total_failed}")
        print(f"   ⏭️ Skipped: {total_skipped}")
        print(f"   📋 Total: {total_tests}")

        # Print category breakdown
        print(f"\n📊 CATEGORY BREAKDOWN:")
        for category, data in self.test_results['categories'].items():
            category_success = (data['passed'] / data['total'] * 100) if data['total'] > 0 else 0
            status = '✅' if data['failed'] == 0 else '❌'
            print(f"   {status} {category}: {category_success:.0f}% ({data['passed']}/{data['total']})")

        # Print issues found
        if self.test_results['issues_found']:
            print(f"\n🚨 ISSUES FOUND:")
            for i, issue in enumerate(self.test_results['issues_found'], 1):
                print(f"   {i}. {issue}")

        # Generate recommendations
        if total_failed == 0:
            self.test_results['recommendations'].append("🎉 Excellent! System is ready for production")
        elif total_failed <= 2:
            self.test_results['recommendations'].append("⚠️ Address minor issues before production")
        else:
            self.test_results['recommendations'].append("❌ Critical issues must be fixed")

        if success_rate < 80:
            self.test_results['recommendations'].append("🔧 Comprehensive fixes needed")
        elif success_rate < 95:
            self.test_results['recommendations'].append("✨ Minor improvements recommended")

        print(f"\n💡 RECOMMENDATIONS:")
        for rec in self.test_results['recommendations']:
            print(f"   • {rec}")

        # Save report
        report_filename = f"manual_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w') as f:
            json.dump(self.test_results, f, indent=2, default=str)

        print(f"\n💾 Detailed report saved to: {report_filename}")

        # Final verdict
        if self.test_results['overall_status'] in ['EXCELLENT', 'GOOD']:
            print(f"\n🚀 PRODUCTION DEPLOYMENT: ✅ APPROVED")
            print("The system has passed manual testing and is ready for production.")
        else:
            print(f"\n🚫 PRODUCTION DEPLOYMENT: ❌ NOT RECOMMENDED")
            print("Please address the identified issues before deploying to production.")

    def run_complete_test_suite(self):
        """Run the complete manual testing suite"""
        self.print_header()

        try:
            self.test_authentication_flow()
            self.test_dashboard_functionality()
            self.test_leave_application_workflow()
            self.test_leave_management_pages()
            self.test_api_functionality()
            self.test_responsive_design()
            self.test_role_based_security()
            self.test_error_handling()

            self.generate_final_report()

        except KeyboardInterrupt:
            print("\n\n⚠️ Testing interrupted by user.")
            print("Partial results have been recorded.")
        except Exception as e:
            print(f"\n❌ Error during testing: {str(e)}")
            print("Please report this issue to the development team.")

def main():
    """Main execution function"""
    print("🧪 Leave Management System - Manual Testing Suite")
    print("=" * 80)

    proceed = input("\nThis will guide you through comprehensive manual testing.\nProceed? (y/n): ").strip().lower()

    if proceed == 'y':
        tester = ManualTestingChecklist()
        tester.run_complete_test_suite()
    else:
        print("Testing cancelled.")

if __name__ == "__main__":
    main()
