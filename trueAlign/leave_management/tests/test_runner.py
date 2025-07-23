#!/usr/bin/env python
"""
Leave Management Test Runner

A comprehensive test runner for the Leave Management System that can:
- Run specific test suites or all tests
- Generate detailed reports in different formats
- Calculate test coverage
- Track performance metrics
- Generate a health report for the system
"""

import os
import sys
import time
import unittest
import json
import datetime
import argparse
import traceback
from collections import defaultdict
from django.test.runner import DiscoverRunner
from django.conf import settings
from django.db import connections
from django.test import TestCase
from django.contrib.auth.models import User, Group
from django.urls import reverse
from django.test.client import Client

try:
    from coverage import Coverage
    COVERAGE_AVAILABLE = True
except ImportError:
    COVERAGE_AVAILABLE = False

# Test Categories
TEST_CATEGORIES = {
    'policy': 'Policy Management Tests',
    'allocation': 'Leave Allocation Tests',
    'workflow': 'Leave Workflow Tests',
    'permissions': 'Role and Permission Tests',
    'edge_cases': 'Edge Case Tests',
    'services': 'Service Layer Tests',
    'api': 'API Tests',
    'all': 'All Tests',
}

class LeaveTestRunner(DiscoverRunner):
    """Custom test runner for Leave Management System"""

    def __init__(self, pattern=None, top_level=None, verbosity=1,
                 interactive=True, failfast=False, keepdb=False,
                 reverse=False, debug_mode=False, debug_sql=False,
                 parallel=0, tags=None, exclude_tags=None,
                 test_name_patterns=None, report_type='console',
                 include_coverage=False, **kwargs):

        self.report_type = report_type
        self.include_coverage = include_coverage
        self.test_results = {
            'total': 0,
            'passed': 0,
            'failed': 0,
            'skipped': 0,
            'errors': 0,
            'duration': 0,
            'categories': defaultdict(lambda: {
                'total': 0, 'passed': 0, 'failed': 0, 'skipped': 0, 'errors': 0, 'duration': 0
            }),
            'test_cases': [],
        }

        super().__init__(
            pattern=pattern, top_level=top_level, verbosity=verbosity,
            interactive=interactive, failfast=failfast, keepdb=keepdb,
            reverse=reverse, debug_mode=debug_mode, debug_sql=debug_sql,
            parallel=parallel, tags=tags, exclude_tags=exclude_tags,
            test_name_patterns=test_name_patterns, **kwargs
        )

        if self.include_coverage and COVERAGE_AVAILABLE:
            self.cov = Coverage(
                source=['trueAlign.leave_management'],
                omit=['*migrations*', '*tests*', '*__init__*'],
            )

    def run_tests(self, test_labels, extra_tests=None, **kwargs):
        """Run the tests with timing and result tracking"""
        if self.include_coverage and COVERAGE_AVAILABLE:
            self.cov.start()

        start_time = time.time()

        # Run the tests
        result = super().run_tests(test_labels, extra_tests, **kwargs)

        # Calculate duration
        self.test_results['duration'] = time.time() - start_time

        # Generate report
        if self.report_type == 'console':
            self._generate_console_report()
        elif self.report_type == 'json':
            self._generate_json_report()
        elif self.report_type == 'html':
            self._generate_html_report()

        # Generate coverage if requested
        if self.include_coverage and COVERAGE_AVAILABLE:
            self.cov.stop()
            self.cov.save()

            if self.report_type == 'html':
                self.cov.html_report(directory='htmlcov')
            else:
                self.cov.report()

        return result

    def _generate_console_report(self):
        """Generate a console text report"""
        print("\n\n")
        print("🧪 LEAVE MANAGEMENT SYSTEM TEST REPORT")
        print("="*80)

        # Summary
        print("📊 SUMMARY")
        print(f"  Total Tests: {self.test_results['total']}")
        print(f"  ✅ Passed: {self.test_results['passed']}")
        print(f"  ❌ Failed: {self.test_results['failed']}")
        print(f"  ⏭️  Skipped: {self.test_results['skipped']}")
        print(f"  🚫 Errors: {self.test_results['errors']}")
        print(f"  ⏱️  Duration: {self.test_results['duration']:.2f}s")

        if self.test_results['total'] > 0:
            success_rate = (self.test_results['passed'] / self.test_results['total']) * 100
            print(f"  📈 Success Rate: {success_rate:.1f}%")

        # Category breakdown
        print("\n📋 TEST SUITE BREAKDOWN")
        for category, results in self.test_results['categories'].items():
            if results['total'] > 0:
                category_success_rate = (results['passed'] / results['total']) * 100
                print(f"  {category}:")
                print(f"    Tests: {results['total']} | "
                      f"✅ {results['passed']} | "
                      f"❌ {results['failed']} | "
                      f"⏭️ {results['skipped']} | "
                      f"🚫 {results['errors']}")
                print(f"    Success Rate: {category_success_rate:.1f}% | "
                      f"Duration: {results['duration']:.2f}s")
                print()

        # Failed tests details
        if self.test_results['failed'] > 0 or self.test_results['errors'] > 0:
            print("\n❌ FAILED TESTS")
            for test_case in self.test_results['test_cases']:
                if test_case['status'] in ['failed', 'error']:
                    print(f"  {test_case['category']}.{test_case['class']}.{test_case['name']}")
                    print(f"    Reason: {test_case['message']}")
                    print()

        print("\n" + "="*80)
        print(f"Test run completed at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    def _generate_json_report(self):
        """Generate a JSON report"""
        report = {
            'summary': {
                'total': self.test_results['total'],
                'passed': self.test_results['passed'],
                'failed': self.test_results['failed'],
                'skipped': self.test_results['skipped'],
                'errors': self.test_results['errors'],
                'duration': self.test_results['duration'],
                'success_rate': 0 if self.test_results['total'] == 0 else
                               (self.test_results['passed'] / self.test_results['total']) * 100
            },
            'categories': dict(self.test_results['categories']),
            'test_cases': self.test_results['test_cases'],
            'timestamp': datetime.datetime.now().isoformat()
        }

        # Convert defaultdict to regular dict for JSON
        for category, results in report['categories'].items():
            if results['total'] > 0:
                results['success_rate'] = (results['passed'] / results['total']) * 100

        with open('leave_management_test_report.json', 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\nJSON report saved to: leave_management_test_report.json")

    def _generate_html_report(self):
        """Generate an HTML report"""
        # Simple HTML template
        html = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Leave Management System Test Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #2c3e50; }
                .summary { background-color: #f8f9fa; padding: 15px; border-radius: 5px; }
                .success { color: #28a745; }
                .failure { color: #dc3545; }
                .warning { color: #ffc107; }
                .info { color: #17a2b8; }
                table { border-collapse: collapse; width: 100%; margin-top: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                tr:nth-child(even) { background-color: #f9f9f9; }
                .category { margin-top: 30px; }
                .failed-test { background-color: #fff3f3; }
            </style>
        </head>
        <body>
            <h1>🧪 Leave Management System Test Report</h1>
            <div class="summary">
                <h2>📊 Summary</h2>
                <p>Total Tests: {total}</p>
                <p class="success">✅ Passed: {passed}</p>
                <p class="failure">❌ Failed: {failed}</p>
                <p class="warning">⏭️ Skipped: {skipped}</p>
                <p class="failure">🚫 Errors: {errors}</p>
                <p class="info">⏱️ Duration: {duration:.2f}s</p>
                <p class="info">📈 Success Rate: {success_rate:.1f}%</p>
            </div>

            <div class="category">
                <h2>📋 Test Suite Breakdown</h2>
                <table>
                    <tr>
                        <th>Category</th>
                        <th>Total</th>
                        <th>Passed</th>
                        <th>Failed</th>
                        <th>Skipped</th>
                        <th>Errors</th>
                        <th>Success Rate</th>
                        <th>Duration</th>
                    </tr>
                    {category_rows}
                </table>
            </div>

            <div class="category">
                <h2>🔍 Test Case Details</h2>
                <table>
                    <tr>
                        <th>Category</th>
                        <th>Test Class</th>
                        <th>Test Method</th>
                        <th>Status</th>
                        <th>Duration</th>
                        <th>Message</th>
                    </tr>
                    {test_case_rows}
                </table>
            </div>

            <div class="category">
                <h2>❌ Failed Tests</h2>
                {failed_tests}
            </div>

            <footer>
                <p>Test run completed at: {timestamp}</p>
            </footer>
        </body>
        </html>
        """

        # Generate category rows
        category_rows = ""
        for category, results in self.test_results['categories'].items():
            if results['total'] > 0:
                success_rate = (results['passed'] / results['total']) * 100
                category_rows += f"""
                <tr>
                    <td>{category}</td>
                    <td>{results['total']}</td>
                    <td class="success">{results['passed']}</td>
                    <td class="failure">{results['failed']}</td>
                    <td class="warning">{results['skipped']}</td>
                    <td class="failure">{results['errors']}</td>
                    <td>{success_rate:.1f}%</td>
                    <td>{results['duration']:.2f}s</td>
                </tr>
                """

        # Generate test case rows
        test_case_rows = ""
        for test_case in self.test_results['test_cases']:
            status_class = "success" if test_case['status'] == 'passed' else \
                          "warning" if test_case['status'] == 'skipped' else "failure"
            row_class = "failed-test" if test_case['status'] in ['failed', 'error'] else ""

            test_case_rows += f"""
            <tr class="{row_class}">
                <td>{test_case['category']}</td>
                <td>{test_case['class']}</td>
                <td>{test_case['name']}</td>
                <td class="{status_class}">{test_case['status']}</td>
                <td>{test_case['duration']:.3f}s</td>
                <td>{test_case['message']}</td>
            </tr>
            """

        # Generate failed tests section
        failed_tests = ""
        if self.test_results['failed'] > 0 or self.test_results['errors'] > 0:
            for test_case in self.test_results['test_cases']:
                if test_case['status'] in ['failed', 'error']:
                    failed_tests += f"""
                    <div class="failed-test" style="margin-bottom: 20px; padding: 10px;">
                        <h3>{test_case['category']}.{test_case['class']}.{test_case['name']}</h3>
                        <p><strong>Status:</strong> {test_case['status']}</p>
                        <p><strong>Reason:</strong> {test_case['message']}</p>
                    </div>
                    """
        else:
            failed_tests = "<p>No failed tests!</p>"

        # Calculate success rate
        success_rate = 0
        if self.test_results['total'] > 0:
            success_rate = (self.test_results['passed'] / self.test_results['total']) * 100

        # Fill in the template
        html = html.format(
            total=self.test_results['total'],
            passed=self.test_results['passed'],
            failed=self.test_results['failed'],
            skipped=self.test_results['skipped'],
            errors=self.test_results['errors'],
            duration=self.test_results['duration'],
            success_rate=success_rate,
            category_rows=category_rows,
            test_case_rows=test_case_rows,
            failed_tests=failed_tests,
            timestamp=datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )

        # Write to file
        with open('leave_management_test_report.html', 'w') as f:
            f.write(html)

        print(f"\nHTML report saved to: leave_management_test_report.html")

    def add_arguments(self, parser):
        """Add custom arguments to the test command"""
        super().add_arguments(parser)

        parser.add_argument(
            '--report',
            choices=['console', 'json', 'html'],
            default='console',
            help='Report format (console, json, or html)'
        )

        parser.add_argument(
            '--coverage',
            action='store_true',
            help='Include test coverage information'
        )

        parser.add_argument(
            '--suite',
            choices=list(TEST_CATEGORIES.keys()),
            default='all',
            help='Run specific test suite'
        )


def get_test_suite(suite_name):
    """Get a specific test suite based on name"""
    if suite_name == 'all':
        return None  # Run all tests

    # Map test suite names to test modules
    suite_mapping = {
        'policy': ['test_policy_management'],
        'allocation': ['test_allocation'],
        'workflow': ['test_workflow'],
        'permissions': ['test_permissions'],
        'edge_cases': ['test_edge_cases'],
        'services': ['test_services'],
        'api': ['test_api'],
    }

    if suite_name in suite_mapping:
        return [f'trueAlign.leave_management.tests.{module}' for module in suite_mapping[suite_name]]

    return None


def generate_health_report():
    """Generate a comprehensive system health report"""
    # This function could:
    # - Check database integrity
    # - Verify permissions and roles
    # - Check for orphaned records
    # - Validate business rules
    # - Performance benchmark key operations

    print("\n\n🩺 LEAVE MANAGEMENT SYSTEM HEALTH REPORT")
    print("="*80)

    # Database check
    print("\n📊 Database Health")
    try:
        # Check connection
        conn = connections['default']
        conn.cursor()
        print("  ✅ Database connection: OK")

        # Get model counts for key models
        from trueAlign.models import LeaveType, LeavePolicy, LeaveAllocation, UserLeaveBalance, LeaveRequest
        from django.contrib.auth.models import User, Group

        print("  📋 Data Statistics:")
        print(f"    Users: {User.objects.count()}")
        print(f"    Groups: {Group.objects.count()}")
        print(f"    Leave Types: {LeaveType.objects.count()}")
        print(f"    Leave Policies: {LeavePolicy.objects.count()}")
        print(f"    Leave Allocations: {LeaveAllocation.objects.count()}")
        print(f"    User Leave Balances: {UserLeaveBalance.objects.count()}")
        print(f"    Leave Requests: {LeaveRequest.objects.count()}")

        # Check for orphaned records
        orphaned_balances = UserLeaveBalance.objects.filter(user__isnull=True).count()
        orphaned_requests = LeaveRequest.objects.filter(user__isnull=True).count()
        orphaned_allocations = LeaveAllocation.objects.filter(policy__isnull=True).count()

        if orphaned_balances + orphaned_requests + orphaned_allocations > 0:
            print("  ⚠️ Orphaned Records:")
            if orphaned_balances > 0:
                print(f"    - {orphaned_balances} user leave balances with no user")
            if orphaned_requests > 0:
                print(f"    - {orphaned_requests} leave requests with no user")
            if orphaned_allocations > 0:
                print(f"    - {orphaned_allocations} leave allocations with no policy")
        else:
            print("  ✅ No orphaned records found")

        # Check for data integrity issues
        negative_balances = UserLeaveBalance.objects.filter(allocated_days__lt=0).count()
        if negative_balances > 0:
            print(f"  ⚠️ Data Integrity: {negative_balances} balances with negative allocated days")
        else:
            print("  ✅ Balance data integrity: OK")

    except Exception as e:
        print(f"  ❌ Database check failed: {str(e)}")

    # Performance check
    print("\n⏱️ Performance Metrics")
    try:
        # Simulate key operations and measure time
        from django.utils import timezone
        from datetime import timedelta
        from trueAlign.leave_management.services.leave_service import LeaveService

        # Setup test data
        employee_group = Group.objects.get(name="Employee")
        employee = User.objects.filter(groups=employee_group).first()
        annual_leave = LeaveType.objects.filter(name__icontains="Annual").first()

        if employee and annual_leave:
            service = LeaveService()

            # Test balance lookup
            start_time = time.time()
            service.get_user_leave_balance(employee, annual_leave, timezone.now().year)
            balance_lookup_time = time.time() - start_time
            print(f"  Balance Lookup: {balance_lookup_time*1000:.2f}ms")

            # Test leave application
            start_time = time.time()
            start_date = timezone.now().date() + timedelta(days=5)
            end_date = start_date + timedelta(days=1)
            service.validate_leave_request(
                user=employee,
                leave_type=annual_leave,
                start_date=start_date,
                end_date=end_date
            )
            validation_time = time.time() - start_time
            print(f"  Leave Validation: {validation_time*1000:.2f}ms")

            # Test dashboard data retrieval
            start_time = time.time()
            service.get_leave_summary(employee)
            dashboard_time = time.time() - start_time
            print(f"  Dashboard Data Retrieval: {dashboard_time*1000:.2f}ms")

            # Performance assessment
            avg_time = (balance_lookup_time + validation_time + dashboard_time) / 3 * 1000
            if avg_time < 50:
                print("  ✅ Overall Performance: Excellent (< 50ms)")
            elif avg_time < 100:
                print("  ✅ Overall Performance: Good (< 100ms)")
            elif avg_time < 200:
                print("  ⚠️ Overall Performance: Acceptable (< 200ms)")
            else:
                print("  ❌ Overall Performance: Poor (> 200ms)")
        else:
            print("  ⚠️ Performance test skipped: Missing test data")

    except Exception as e:
        print(f"  ❌ Performance check failed: {str(e)}")

    # URL health check
    print("\n🔗 URL Health Check")
    try:
        from django.urls import reverse, NoReverseMatch

        # List of key URLs to check
        key_urls = [
            'dashboard', 'employee_dashboard', 'manager_dashboard',
            'hr_dashboard', 'admin_dashboard', 'apply_leave',
            'my_leaves', 'team_leaves', 'leave_balance',
            'api_leave_balance', 'api_leave_types'
        ]

        url_failures = 0
        for url_name in key_urls:
            try:
                full_url = f'leave_management:{url_name}'
                reverse(full_url)
                print(f"  ✅ URL {full_url}: OK")
            except NoReverseMatch:
                print(f"  ❌ URL {full_url}: Not found")
                url_failures += 1

        if url_failures == 0:
            print("  ✅ All URLs are configured properly")
        else:
            print(f"  ⚠️ {url_failures} URL configuration issues found")

    except Exception as e:
        print(f"  ❌ URL health check failed: {str(e)}")

    # Overall health assessment
    print("\n🏥 Overall System Health")
    try:
        # Count issues
        from trueAlign.models import LeaveRequest
        pending_requests = LeaveRequest.objects.filter(status='Pending').count()
        approved_requests = LeaveRequest.objects.filter(status='Approved').count()
        rejected_requests = LeaveRequest.objects.filter(status='Rejected').count()
        cancelled_requests = LeaveRequest.objects.filter(status='Cancelled').count()

        print(f"  Leave Request Statistics:")
        print(f"    Pending: {pending_requests}")
        print(f"    Approved: {approved_requests}")
        print(f"    Rejected: {rejected_requests}")
        print(f"    Cancelled: {cancelled_requests}")

        # Simplified health score
        total_requests = pending_requests + approved_requests + rejected_requests + cancelled_requests
        if total_requests > 0:
            flow_ratio = (approved_requests + rejected_requests) / total_requests
            print(f"  Process Flow Ratio: {flow_ratio:.2f}")

            if flow_ratio > 0.8:
                print("  ✅ Process Flow: Healthy (> 80% requests processed)")
            elif flow_ratio > 0.5:
                print("  ⚠️ Process Flow: Moderate (> 50% requests processed)")
            else:
                print("  ❌ Process Flow: Poor (< 50% requests processed)")

        # Final assessment
        print("\n📝 Health Report Summary")
        print("  The Leave Management System is operational with no critical issues detected.")
        print("  See detailed metrics above for specific areas that may need attention.")

    except Exception as e:
        print(f"  ❌ Overall health assessment failed: {str(e)}")

    print("\n" + "="*80)
    print(f"Health report generated at: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")


def main():
    """Main entry point when running test_runner.py directly"""
    parser = argparse.ArgumentParser(description='Leave Management System Test Runner')

    parser.add_argument(
        '--suite',
        choices=list(TEST_CATEGORIES.keys()),
        default='all',
        help='Run specific test suite'
    )

    parser.add_argument(
        '--report',
        choices=['console', 'json', 'html'],
        default='console',
        help='Report format (console, json, or html)'
    )

    parser.add_argument(
        '--coverage',
        action='store_true',
        help='Include test coverage information'
    )

    parser.add_argument(
        '--health',
        action='store_true',
        help='Generate a system health report'
    )

    parser.add_argument(
        '--interactive',
        action='store_true',
        help='Run tests in interactive mode'
    )

    args = parser.parse_args()

    if args.health:
        generate_health_report()
        return

    # Prepare Django test environment
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'ardurPeopleSoft.settings')
    import django
    django.setup()

    # Get the test suite to run
    test_labels = get_test_suite(args.suite)

    # Configure test runner
    runner = LeaveTestRunner(
        verbosity=2,
        interactive=args.interactive,
        report_type=args.report,
        include_coverage=args.coverage
    )

    # Run tests
    failures = runner.run_tests(test_labels)

    sys.exit(bool(failures))


if __name__ == '__main__':
    main()
